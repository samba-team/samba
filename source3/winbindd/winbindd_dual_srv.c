/*
   Unix SMB/CIFS implementation.

   In-Child server implementation of the routines defined in wbint.idl

   Copyright (C) Volker Lendecke 2009
   Copyright (C) Guenther Deschner 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "winbindd/winbindd.h"
#include "winbindd/winbindd_proto.h"
#include "rpc_client/cli_pipe.h"
#include "ntdomain.h"
#include "librpc/gen_ndr/ndr_winbind.h"
#include "librpc/gen_ndr/ndr_winbind_scompat.h"
#include "../librpc/gen_ndr/ndr_netlogon_c.h"
#include "../librpc/gen_ndr/ndr_lsa_c.h"
#include "idmap.h"
#include "../libcli/security/security.h"
#include "../libcli/auth/netlogon_creds_cli.h"
#include "passdb.h"
#include "../source4/dsdb/samdb/samdb.h"
#include "rpc_client/cli_netlogon.h"
#include "rpc_client/util_netlogon.h"
#include "libsmb/dsgetdcname.h"

void _wbint_Ping(struct pipes_struct *p, struct wbint_Ping *r)
{
	*r->out.out_data = r->in.in_data;
}

bool reset_cm_connection_on_error(struct winbindd_domain *domain,
				  struct dcerpc_binding_handle *b,
				  NTSTATUS status)
{
	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_RPC_SEC_PKG_ERROR) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_ACCESS_DENIED)) {
		invalidate_cm_connection(domain);
		domain->conn.netlogon_force_reauth = true;
		return true;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_IO_DEVICE_ERROR))
	{
		invalidate_cm_connection(domain);
		/* We invalidated the connection. */
		return true;
	}

	if (b != NULL && !dcerpc_binding_handle_is_connected(b)) {
		invalidate_cm_connection(domain);
		return true;
	}

	return false;
}

NTSTATUS _wbint_LookupSid(struct pipes_struct *p, struct wbint_LookupSid *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	char *dom_name;
	char *name;
	enum lsa_SidType type;
	NTSTATUS status;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = wb_cache_sid_to_name(domain, p->mem_ctx, r->in.sid,
				      &dom_name, &name, &type);
	reset_cm_connection_on_error(domain, NULL, status);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*r->out.domain = dom_name;
	*r->out.name = name;
	*r->out.type = type;
	return NT_STATUS_OK;
}

NTSTATUS _wbint_LookupSids(struct pipes_struct *p, struct wbint_LookupSids *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	struct lsa_RefDomainList *domains = r->out.domains;
	NTSTATUS status;
	bool retry = false;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	/*
	 * This breaks the winbindd_domain->methods abstraction: This
	 * is only called for remote domains, and both winbindd_msrpc
	 * and winbindd_ad call into lsa_lookupsids anyway. Caching is
	 * done at the wbint RPC layer.
	 */
again:
	status = rpc_lookup_sids(p->mem_ctx, domain, r->in.sids,
				 &domains, &r->out.names);

	if (domains != NULL) {
		r->out.domains = domains;
	}

	if (!retry && reset_cm_connection_on_error(domain, NULL, status)) {
		retry = true;
		goto again;
	}

	return status;
}

NTSTATUS _wbint_LookupName(struct pipes_struct *p, struct wbint_LookupName *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	NTSTATUS status;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = wb_cache_name_to_sid(domain, p->mem_ctx, r->in.domain,
				      r->in.name, r->in.flags,
				      r->out.sid, r->out.type);
	reset_cm_connection_on_error(domain, NULL, status);
	return status;
}

NTSTATUS _wbint_Sids2UnixIDs(struct pipes_struct *p,
			     struct wbint_Sids2UnixIDs *r)
{
	uint32_t i;

	struct lsa_DomainInfo *d;
	struct wbint_TransID *ids;
	uint32_t num_ids;

	struct id_map **id_map_ptrs = NULL;
	struct idmap_domain *dom;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	if (r->in.domains->count != 1) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	d = &r->in.domains->domains[0];
	ids = r->in.ids->ids;
	num_ids = r->in.ids->num_ids;

	dom = idmap_find_domain_with_sid(d->name.string, d->sid);
	if (dom == NULL) {
		struct dom_sid_buf buf;
		DEBUG(10, ("idmap domain %s:%s not found\n",
			   d->name.string,
			   dom_sid_str_buf(d->sid, &buf)));

		for (i=0; i<num_ids; i++) {

			ids[i].xid = (struct unixid) {
				.id = UINT32_MAX,
				.type = ID_TYPE_NOT_SPECIFIED
			};
		}

		return NT_STATUS_OK;
	}

	id_map_ptrs = id_map_ptrs_init(talloc_tos(), num_ids);
	if (id_map_ptrs == NULL) {
		goto nomem;
	}

	/*
	 * Convert the input data into a list of id_map structs
	 * suitable for handing in to the idmap sids_to_unixids
	 * method.
	 */

	for (i=0; i<num_ids; i++) {
		struct id_map *m = id_map_ptrs[i];

		sid_compose(m->sid, d->sid, ids[i].rid);
		m->status = ID_UNKNOWN;
		m->xid = (struct unixid) { .type = ids[i].type };
	}

	status = dom->methods->sids_to_unixids(dom, id_map_ptrs);

	if (NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		/*
		 * This is okay. We need to transfer the mapped ones
		 * up to our caller. The individual mappings carry the
		 * information whether they are mapped or not.
		 */
		status = NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("sids_to_unixids returned %s\n",
			   nt_errstr(status)));
		goto done;
	}

	/*
	 * Extract the results for handing them back to the caller.
	 */

	for (i=0; i<num_ids; i++) {
		struct id_map *m = id_map_ptrs[i];

		if (!idmap_unix_id_is_in_range(m->xid.id, dom)) {
			DBG_DEBUG("id %"PRIu32" is out of range "
				  "%"PRIu32"-%"PRIu32" for domain %s\n",
				  m->xid.id, dom->low_id, dom->high_id,
				  dom->name);
			m->status = ID_UNMAPPED;
		}

		if (m->status == ID_MAPPED) {
			ids[i].xid = m->xid;
		} else {
			ids[i].xid.id = UINT32_MAX;
			ids[i].xid.type = ID_TYPE_NOT_SPECIFIED;
		}
	}

	goto done;
nomem:
	status = NT_STATUS_NO_MEMORY;
done:
	TALLOC_FREE(id_map_ptrs);
	return status;
}

NTSTATUS _wbint_UnixIDs2Sids(struct pipes_struct *p,
			     struct wbint_UnixIDs2Sids *r)
{
	struct id_map **maps;
	NTSTATUS status;
	uint32_t i;

	maps = id_map_ptrs_init(talloc_tos(), r->in.num_ids);
	if (maps == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<r->in.num_ids; i++) {
		maps[i]->status = ID_UNKNOWN;
		maps[i]->xid = r->in.xids[i];
	}

	status = idmap_backend_unixids_to_sids(maps, r->in.domain_name,
					       r->in.domain_sid);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(maps);
		return status;
	}

	for (i=0; i<r->in.num_ids; i++) {
		if (maps[i]->status == ID_MAPPED) {
			r->out.xids[i] = maps[i]->xid;
			sid_copy(&r->out.sids[i], maps[i]->sid);
		} else {
			r->out.sids[i] = (struct dom_sid) { 0 };
		}
	}

	TALLOC_FREE(maps);

	return NT_STATUS_OK;
}

NTSTATUS _wbint_AllocateUid(struct pipes_struct *p, struct wbint_AllocateUid *r)
{
	struct unixid xid;
	NTSTATUS status;

	status = idmap_allocate_uid(&xid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	*r->out.uid = xid.id;
	return NT_STATUS_OK;
}

NTSTATUS _wbint_AllocateGid(struct pipes_struct *p, struct wbint_AllocateGid *r)
{
	struct unixid xid;
	NTSTATUS status;

	status = idmap_allocate_gid(&xid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	*r->out.gid = xid.id;
	return NT_STATUS_OK;
}

NTSTATUS _wbint_GetNssInfo(struct pipes_struct *p, struct wbint_GetNssInfo *r)
{
	struct idmap_domain *domain;
	NTSTATUS status;

	domain = idmap_find_domain(r->in.info->domain_name);
	if ((domain == NULL) || (domain->query_user == NULL)) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = domain->query_user(domain, r->in.info);
	return status;
}

NTSTATUS _wbint_LookupUserAliases(struct pipes_struct *p,
				  struct wbint_LookupUserAliases *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	NTSTATUS status;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = wb_cache_lookup_useraliases(domain, p->mem_ctx,
					     r->in.sids->num_sids,
					     r->in.sids->sids,
					     &r->out.rids->num_rids,
					     &r->out.rids->rids);
	reset_cm_connection_on_error(domain, NULL, status);
	return status;
}

NTSTATUS _wbint_LookupUserGroups(struct pipes_struct *p,
				 struct wbint_LookupUserGroups *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	NTSTATUS status;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = wb_cache_lookup_usergroups(domain, p->mem_ctx, r->in.sid,
					    &r->out.sids->num_sids,
					    &r->out.sids->sids);
	reset_cm_connection_on_error(domain, NULL, status);
	return status;
}

NTSTATUS _wbint_QuerySequenceNumber(struct pipes_struct *p,
				    struct wbint_QuerySequenceNumber *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	NTSTATUS status;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = wb_cache_sequence_number(domain, r->out.sequence);
	reset_cm_connection_on_error(domain, NULL, status);
	return status;
}

NTSTATUS _wbint_LookupGroupMembers(struct pipes_struct *p,
				   struct wbint_LookupGroupMembers *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	uint32_t i, num_names;
	struct dom_sid *sid_mem;
	char **names;
	uint32_t *name_types;
	NTSTATUS status;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = wb_cache_lookup_groupmem(domain, p->mem_ctx, r->in.sid,
					  r->in.type, &num_names, &sid_mem,
					  &names, &name_types);
	reset_cm_connection_on_error(domain, NULL, status);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	r->out.members->num_principals = num_names;
	r->out.members->principals = talloc_array(
		r->out.members, struct wbint_Principal, num_names);
	if (r->out.members->principals == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<num_names; i++) {
		struct wbint_Principal *m = &r->out.members->principals[i];
		sid_copy(&m->sid, &sid_mem[i]);
		m->name = talloc_move(r->out.members->principals, &names[i]);
		m->type = (enum lsa_SidType)name_types[i];
	}

	return NT_STATUS_OK;
}

NTSTATUS _wbint_QueryGroupList(struct pipes_struct *p,
			       struct wbint_QueryGroupList *r)
{
	TALLOC_CTX *frame = NULL;
	struct winbindd_domain *domain = wb_child_domain();
	uint32_t i;
	uint32_t num_local_groups = 0;
	struct wb_acct_info *local_groups = NULL;
	uint32_t num_dom_groups = 0;
	struct wb_acct_info *dom_groups = NULL;
	uint32_t ti = 0;
	uint64_t num_total = 0;
	struct wbint_Principal *result;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	bool include_local_groups = false;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	frame = talloc_stackframe();

	switch (lp_server_role()) {
	case ROLE_ACTIVE_DIRECTORY_DC:
		if (domain->internal) {
			/*
			 * we want to include local groups
			 * for BUILTIN and WORKGROUP
			 */
			include_local_groups = true;
		}
		break;
	default:
		/*
		 * We might include local groups in more
		 * setups later, but that requires more work
		 * elsewhere.
		 */
		break;
	}

	if (include_local_groups) {
		status = wb_cache_enum_local_groups(domain, frame,
						    &num_local_groups,
						    &local_groups);
		reset_cm_connection_on_error(domain, NULL, status);
		if (!NT_STATUS_IS_OK(status)) {
			goto out;
		}
	}

	status = wb_cache_enum_dom_groups(domain, frame,
					  &num_dom_groups,
					  &dom_groups);
	reset_cm_connection_on_error(domain, NULL, status);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	num_total = num_local_groups + num_dom_groups;
	if (num_total > UINT32_MAX) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto out;
	}

	result = talloc_array(frame, struct wbint_Principal, num_total);
	if (result == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto out;
	}

	for (i = 0; i < num_local_groups; i++) {
		struct wb_acct_info *lg = &local_groups[i];
		struct wbint_Principal *rg = &result[ti++];

		sid_compose(&rg->sid, &domain->sid, lg->rid);
		rg->type = SID_NAME_ALIAS;
		rg->name = talloc_strdup(result, lg->acct_name);
		if (rg->name == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}
	num_local_groups = 0;

	for (i = 0; i < num_dom_groups; i++) {
		struct wb_acct_info *dg = &dom_groups[i];
		struct wbint_Principal *rg = &result[ti++];

		sid_compose(&rg->sid, &domain->sid, dg->rid);
		rg->type = SID_NAME_DOM_GRP;
		rg->name = talloc_strdup(result, dg->acct_name);
		if (rg->name == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto out;
		}
	}
	num_dom_groups = 0;

	r->out.groups->num_principals = ti;
	r->out.groups->principals = talloc_move(r->out.groups, &result);

	status = NT_STATUS_OK;
out:
	TALLOC_FREE(frame);
	return status;
}

NTSTATUS _wbint_QueryUserRidList(struct pipes_struct *p,
				 struct wbint_QueryUserRidList *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	NTSTATUS status;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	/*
	 * Right now this is overkill. We should add a backend call
	 * just querying the rids.
	 */

	status = wb_cache_query_user_list(domain, p->mem_ctx,
					  &r->out.rids->rids);
	reset_cm_connection_on_error(domain, NULL, status);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	r->out.rids->num_rids = talloc_array_length(r->out.rids->rids);

	return NT_STATUS_OK;
}

NTSTATUS _wbint_DsGetDcName(struct pipes_struct *p, struct wbint_DsGetDcName *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	struct rpc_pipe_client *netlogon_pipe;
	struct netr_DsRGetDCNameInfo *dc_info;
	NTSTATUS status;
	WERROR werr;
	unsigned int orig_timeout;
	struct dcerpc_binding_handle *b;
	bool retry = false;
	bool try_dsrgetdcname = false;

	if (domain == NULL) {
		return dsgetdcname(p->mem_ctx, global_messaging_context(),
				   r->in.domain_name, r->in.domain_guid,
				   r->in.site_name ? r->in.site_name : "",
				   r->in.flags,
				   r->out.dc_info);
	}

	if (domain->active_directory) {
		try_dsrgetdcname = true;
	}

reconnect:
	status = cm_connect_netlogon(domain, &netlogon_pipe);

	reset_cm_connection_on_error(domain, NULL, status);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("Can't contact the NETLOGON pipe\n"));
		return status;
	}

	b = netlogon_pipe->binding_handle;

	/* This call can take a long time - allow the server to time out.
	   35 seconds should do it. */

	orig_timeout = rpccli_set_timeout(netlogon_pipe, 35000);

	if (try_dsrgetdcname) {
		status = dcerpc_netr_DsRGetDCName(b,
			p->mem_ctx, domain->dcname,
			r->in.domain_name, NULL, r->in.domain_guid,
			r->in.flags, r->out.dc_info, &werr);
		if (NT_STATUS_IS_OK(status) && W_ERROR_IS_OK(werr)) {
			goto done;
		}
		if (!retry &&
		    reset_cm_connection_on_error(domain, NULL, status))
		{
			retry = true;
			goto reconnect;
		}
		try_dsrgetdcname = false;
		retry = false;
	}

	/*
	 * Fallback to less capable methods
	 */

	dc_info = talloc_zero(r->out.dc_info, struct netr_DsRGetDCNameInfo);
	if (dc_info == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	if (r->in.flags & DS_PDC_REQUIRED) {
		status = dcerpc_netr_GetDcName(b,
			p->mem_ctx, domain->dcname,
			r->in.domain_name, &dc_info->dc_unc, &werr);
	} else {
		status = dcerpc_netr_GetAnyDCName(b,
			p->mem_ctx, domain->dcname,
			r->in.domain_name, &dc_info->dc_unc, &werr);
	}

	if (!retry && reset_cm_connection_on_error(domain, b, status)) {
		retry = true;
		goto reconnect;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("dcerpc_netr_Get[Any]DCName failed: %s\n",
			   nt_errstr(status)));
		goto done;
	}
	if (!W_ERROR_IS_OK(werr)) {
		DEBUG(10, ("dcerpc_netr_Get[Any]DCName failed: %s\n",
			   win_errstr(werr)));
		status = werror_to_ntstatus(werr);
		goto done;
	}

	*r->out.dc_info = dc_info;
	status = NT_STATUS_OK;

done:
	/* And restore our original timeout. */
	rpccli_set_timeout(netlogon_pipe, orig_timeout);

	return status;
}

NTSTATUS _wbint_LookupRids(struct pipes_struct *p, struct wbint_LookupRids *r)
{
	struct winbindd_domain *domain = wb_child_domain();
	char *domain_name;
	char **names;
	enum lsa_SidType *types;
	struct wbint_Principal *result;
	NTSTATUS status;
	uint32_t i;

	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = wb_cache_rids_to_names(domain, talloc_tos(), r->in.domain_sid,
					r->in.rids->rids, r->in.rids->num_rids,
					&domain_name, &names, &types);
	reset_cm_connection_on_error(domain, NULL, status);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, STATUS_SOME_UNMAPPED)) {
		return status;
	}

	*r->out.domain_name = talloc_move(r->out.domain_name, &domain_name);

	result = talloc_array(p->mem_ctx, struct wbint_Principal,
			      r->in.rids->num_rids);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i<r->in.rids->num_rids; i++) {
		sid_compose(&result[i].sid, r->in.domain_sid,
			    r->in.rids->rids[i]);
		result[i].type = types[i];
		result[i].name = talloc_move(result, &names[i]);
	}
	TALLOC_FREE(types);
	TALLOC_FREE(names);

	r->out.names->num_principals = r->in.rids->num_rids;
	r->out.names->principals = result;
	return NT_STATUS_OK;
}

NTSTATUS _wbint_CheckMachineAccount(struct pipes_struct *p,
				    struct wbint_CheckMachineAccount *r)
{
	struct winbindd_domain *domain;
	int num_retries = 0;
	NTSTATUS status;

	domain = wb_child_domain();
	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

again:
	invalidate_cm_connection(domain);
	domain->conn.netlogon_force_reauth = true;

	{
		struct rpc_pipe_client *netlogon_pipe = NULL;
		struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;
		status = cm_connect_netlogon_secure(domain,
						    &netlogon_pipe,
						    &netlogon_creds_ctx);
	}

        /* There is a race condition between fetching the trust account
           password and the periodic machine password change.  So it's
	   possible that the trust account password has been changed on us.
	   We are returned NT_STATUS_ACCESS_DENIED if this happens. */

#define MAX_RETRIES 3

        if ((num_retries < MAX_RETRIES)
	    && NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
                num_retries++;
                goto again;
        }

        if (!NT_STATUS_IS_OK(status)) {
                DEBUG(3, ("could not open handle to NETLOGON pipe\n"));
                goto done;
        }

	/* Pass back result code - zero for success, other values for
	   specific failures. */

	DEBUG(3,("domain %s secret is %s\n", domain->name,
		NT_STATUS_IS_OK(status) ? "good" : "bad"));

 done:
	DEBUG(NT_STATUS_IS_OK(status) ? 5 : 2,
	      ("Checking the trust account password for domain %s returned %s\n",
	       domain->name, nt_errstr(status)));

	return status;
}

NTSTATUS _wbint_ChangeMachineAccount(struct pipes_struct *p,
				     struct wbint_ChangeMachineAccount *r)
{
	struct messaging_context *msg_ctx = global_messaging_context();
	struct winbindd_domain *domain;
	NTSTATUS status;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;

	domain = wb_child_domain();
	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = cm_connect_netlogon_secure(domain,
					    &netlogon_pipe,
					    &netlogon_creds_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("could not open handle to NETLOGON pipe\n"));
		goto done;
	}

	status = trust_pw_change(netlogon_creds_ctx,
				 msg_ctx,
				 netlogon_pipe->binding_handle,
				 domain->name,
				 domain->dcname,
				 true); /* force */

	/* Pass back result code - zero for success, other values for
	   specific failures. */

	DEBUG(3,("domain %s secret %s\n", domain->name,
		NT_STATUS_IS_OK(status) ? "changed" : "unchanged"));

 done:
	DEBUG(NT_STATUS_IS_OK(status) ? 5 : 2,
	      ("Changing the trust account password for domain %s returned %s\n",
	       domain->name, nt_errstr(status)));

	return status;
}

NTSTATUS _wbint_PingDc(struct pipes_struct *p, struct wbint_PingDc *r)
{
	NTSTATUS status;
	struct winbindd_domain *domain;
	struct rpc_pipe_client *netlogon_pipe;
	union netr_CONTROL_QUERY_INFORMATION info;
	WERROR werr;
	fstring logon_server;
	struct dcerpc_binding_handle *b;
	bool retry = false;

	domain = wb_child_domain();
	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

reconnect:
	status = cm_connect_netlogon(domain, &netlogon_pipe);
	reset_cm_connection_on_error(domain, NULL, status);
        if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("could not open handle to NETLOGON pipe: %s\n",
			  nt_errstr(status)));
		return status;
        }

	b = netlogon_pipe->binding_handle;

	fstr_sprintf(logon_server, "\\\\%s", domain->dcname);
	*r->out.dcname = talloc_strdup(p->mem_ctx, domain->dcname);
	if (*r->out.dcname == NULL) {
		DEBUG(2, ("Could not allocate memory\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * This provokes a WERR_NOT_SUPPORTED error message. This is
	 * documented in the wspp docs. I could not get a successful
	 * call to work, but the main point here is testing that the
	 * netlogon pipe works.
	 */
	status = dcerpc_netr_LogonControl(b, p->mem_ctx,
					  logon_server, NETLOGON_CONTROL_QUERY,
					  2, &info, &werr);

	if (!retry && reset_cm_connection_on_error(domain, b, status)) {
		retry = true;
		goto reconnect;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("dcerpc_netr_LogonControl failed: %s\n",
			nt_errstr(status)));
		return status;
	}

	if (!W_ERROR_EQUAL(werr, WERR_NOT_SUPPORTED)) {
		DEBUG(2, ("dcerpc_netr_LogonControl returned %s, expected "
			  "WERR_NOT_SUPPORTED\n",
			  win_errstr(werr)));
		return werror_to_ntstatus(werr);
	}

	DEBUG(5, ("winbindd_dual_ping_dc succeeded\n"));
	return NT_STATUS_OK;
}

NTSTATUS _winbind_DsrUpdateReadOnlyServerDnsRecords(struct pipes_struct *p,
						    struct winbind_DsrUpdateReadOnlyServerDnsRecords *r)
{
	struct winbindd_domain *domain;
	NTSTATUS status;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;
	struct dcerpc_binding_handle *b = NULL;
	bool retry = false;

	domain = wb_child_domain();
	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

reconnect:
	status = cm_connect_netlogon_secure(domain,
					    &netlogon_pipe,
					    &netlogon_creds_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("could not open handle to NETLOGON pipe\n"));
		goto done;
	}

	b = netlogon_pipe->binding_handle;

	status = netlogon_creds_cli_DsrUpdateReadOnlyServerDnsRecords(netlogon_creds_ctx,
								      netlogon_pipe->binding_handle,
								      r->in.site_name,
								      r->in.dns_ttl,
								      r->in.dns_names);

	if (!retry && reset_cm_connection_on_error(domain, b, status)) {
		retry = true;
		goto reconnect;
	}

	/* Pass back result code - zero for success, other values for
	   specific failures. */

	DEBUG(3,("DNS records for domain %s %s\n", domain->name,
		NT_STATUS_IS_OK(status) ? "changed" : "unchanged"));

 done:
	DEBUG(NT_STATUS_IS_OK(status) ? 5 : 2,
	      ("Update of DNS records via RW DC %s returned %s\n",
	       domain->name, nt_errstr(status)));

	return status;
}

NTSTATUS _winbind_SamLogon(struct pipes_struct *p,
			struct winbind_SamLogon *r)
{
	struct winbindd_domain *domain;
	NTSTATUS status;
	struct netr_IdentityInfo *identity_info = NULL;
	const uint8_t chal_zero[8] = {0, };
	const uint8_t *challenge = chal_zero;
	DATA_BLOB lm_response, nt_response;
	uint32_t flags = 0;
	uint16_t validation_level;
	union netr_Validation *validation = NULL;
	bool interactive = false;

	domain = wb_child_domain();
	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	switch (r->in.validation_level) {
	case 3:
	case 6:
		break;
	default:
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	switch (r->in.logon_level) {
	case NetlogonInteractiveInformation:
	case NetlogonServiceInformation:
	case NetlogonInteractiveTransitiveInformation:
	case NetlogonServiceTransitiveInformation:
		if (r->in.logon.password == NULL) {
			return NT_STATUS_REQUEST_NOT_ACCEPTED;
		}

		interactive = true;
		identity_info = &r->in.logon.password->identity_info;

		challenge = chal_zero;
		lm_response = data_blob_talloc(p->mem_ctx,
					r->in.logon.password->lmpassword.hash,
					sizeof(r->in.logon.password->lmpassword.hash));
		nt_response = data_blob_talloc(p->mem_ctx,
					r->in.logon.password->ntpassword.hash,
					sizeof(r->in.logon.password->ntpassword.hash));
		break;

	case NetlogonNetworkInformation:
	case NetlogonNetworkTransitiveInformation:
		if (r->in.logon.network == NULL) {
			return NT_STATUS_REQUEST_NOT_ACCEPTED;
		}

		interactive = false;
		identity_info = &r->in.logon.network->identity_info;

		challenge = r->in.logon.network->challenge;
		lm_response = data_blob_talloc(p->mem_ctx,
					r->in.logon.network->lm.data,
					r->in.logon.network->lm.length);
		nt_response = data_blob_talloc(p->mem_ctx,
					r->in.logon.network->nt.data,
					r->in.logon.network->nt.length);
		break;

	case NetlogonGenericInformation:
		if (r->in.logon.generic == NULL) {
			return NT_STATUS_REQUEST_NOT_ACCEPTED;
		}

		identity_info = &r->in.logon.generic->identity_info;
		/*
		 * Not implemented here...
		 */
		return NT_STATUS_REQUEST_NOT_ACCEPTED;

	default:
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

	status = winbind_dual_SamLogon(domain, p->mem_ctx,
				       interactive,
				       identity_info->parameter_control,
				       identity_info->account_name.string,
				       identity_info->domain_name.string,
				       identity_info->workstation.string,
				       identity_info->logon_id,
				       "SamLogon",
				       0,
				       challenge,
				       lm_response, nt_response,
				       p->remote_address,
				       p->local_address,
				       &r->out.authoritative,
				       true, /* skip_sam */
				       &flags,
				       &validation_level,
				       &validation);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	switch (r->in.validation_level) {
	case 3:
		status = map_validation_to_info3(p->mem_ctx,
						 validation_level,
						 validation,
						 &r->out.validation.sam3);
		TALLOC_FREE(validation);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		return NT_STATUS_OK;
	case 6:
		status = map_validation_to_info6(p->mem_ctx,
						 validation_level,
						 validation,
						 &r->out.validation.sam6);
		TALLOC_FREE(validation);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		return NT_STATUS_OK;
	}

	smb_panic(__location__);
	return NT_STATUS_INTERNAL_ERROR;
}

static WERROR _winbind_LogonControl_REDISCOVER(struct pipes_struct *p,
			     struct winbindd_domain *domain,
			     struct winbind_LogonControl *r)
{
	NTSTATUS status;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;
	struct netr_NETLOGON_INFO_2 *info2 = NULL;
	WERROR check_result = WERR_INTERNAL_ERROR;

	info2 = talloc_zero(p->mem_ctx, struct netr_NETLOGON_INFO_2);
	if (info2 == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (domain->internal) {
		check_result = WERR_OK;
		goto check_return;
	}

	/*
	 * For now we just force a reconnect
	 *
	 * TODO: take care of the optional '\dcname'
	 */
	invalidate_cm_connection(domain);
	domain->conn.netlogon_force_reauth = true;
	status = cm_connect_netlogon_secure(domain,
					    &netlogon_pipe,
					    &netlogon_creds_ctx);
	reset_cm_connection_on_error(domain, NULL, status);
	if (NT_STATUS_EQUAL(status, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND)) {
		status = NT_STATUS_NO_LOGON_SERVERS;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("%s: domain[%s/%s] cm_connect_netlogon() returned %s\n",
			  __func__, domain->name, domain->alt_name,
			  nt_errstr(status)));
		/*
		 * Here we return a top level error!
		 * This is different than TC_QUERY or TC_VERIFY.
		 */
		return ntstatus_to_werror(status);
	}
	check_result = WERR_OK;

check_return:
	info2->pdc_connection_status = WERR_OK;
	if (domain->dcname != NULL) {
		info2->flags |= NETLOGON_HAS_IP;
		info2->flags |= NETLOGON_HAS_TIMESERV;
		info2->trusted_dc_name = talloc_asprintf(info2, "\\\\%s",
							 domain->dcname);
		if (info2->trusted_dc_name == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	} else {
		info2->trusted_dc_name = talloc_strdup(info2, "");
		if (info2->trusted_dc_name == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}
	info2->tc_connection_status = check_result;

	if (!W_ERROR_IS_OK(info2->pdc_connection_status)) {
		DEBUG(2, ("%s: domain[%s/%s] dcname[%s] "
			  "pdc_connection[%s] tc_connection[%s]\n",
			  __func__, domain->name, domain->alt_name,
			  domain->dcname,
			  win_errstr(info2->pdc_connection_status),
			  win_errstr(info2->tc_connection_status)));
	}

	r->out.query->info2 = info2;

	DEBUG(5, ("%s: succeeded.\n", __func__));
	return WERR_OK;
}

static WERROR _winbind_LogonControl_TC_QUERY(struct pipes_struct *p,
			     struct winbindd_domain *domain,
			     struct winbind_LogonControl *r)
{
	NTSTATUS status;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;
	struct netr_NETLOGON_INFO_2 *info2 = NULL;
	WERROR check_result = WERR_INTERNAL_ERROR;

	info2 = talloc_zero(p->mem_ctx, struct netr_NETLOGON_INFO_2);
	if (info2 == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (domain->internal) {
		check_result = WERR_OK;
		goto check_return;
	}

	status = cm_connect_netlogon_secure(domain,
					    &netlogon_pipe,
					    &netlogon_creds_ctx);
	reset_cm_connection_on_error(domain, NULL, status);
	if (NT_STATUS_EQUAL(status, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND)) {
		status = NT_STATUS_NO_LOGON_SERVERS;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("could not open handle to NETLOGON pipe: %s\n",
			  nt_errstr(status)));
		check_result = ntstatus_to_werror(status);
		goto check_return;
	}
	check_result = WERR_OK;

check_return:
	info2->pdc_connection_status = WERR_OK;
	if (domain->dcname != NULL) {
		info2->flags |= NETLOGON_HAS_IP;
		info2->flags |= NETLOGON_HAS_TIMESERV;
		info2->trusted_dc_name = talloc_asprintf(info2, "\\\\%s",
							 domain->dcname);
		if (info2->trusted_dc_name == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	} else {
		info2->trusted_dc_name = talloc_strdup(info2, "");
		if (info2->trusted_dc_name == NULL) {
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}
	info2->tc_connection_status = check_result;

	if (!W_ERROR_IS_OK(info2->pdc_connection_status)) {
		DEBUG(2, ("%s: domain[%s/%s] dcname[%s] "
			  "pdc_connection[%s] tc_connection[%s]\n",
			  __func__, domain->name, domain->alt_name,
			  domain->dcname,
			  win_errstr(info2->pdc_connection_status),
			  win_errstr(info2->tc_connection_status)));
	}

	r->out.query->info2 = info2;

	DEBUG(5, ("%s: succeeded.\n", __func__));
	return WERR_OK;
}

static WERROR _winbind_LogonControl_TC_VERIFY(struct pipes_struct *p,
			     struct winbindd_domain *domain,
			     struct winbind_LogonControl *r)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	NTSTATUS result;
	struct lsa_String trusted_domain_name = {};
	struct lsa_StringLarge trusted_domain_name_l = {};
	struct rpc_pipe_client *local_lsa_pipe = NULL;
	struct policy_handle local_lsa_policy = {};
	struct dcerpc_binding_handle *local_lsa = NULL;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;
	struct cli_credentials *creds = NULL;
	struct samr_Password *cur_nt_hash = NULL;
	uint32_t trust_attributes = 0;
	struct samr_Password new_owf_password = {};
	int cmp_new = -1;
	struct samr_Password old_owf_password = {};
	int cmp_old = -1;
	const struct lsa_TrustDomainInfoInfoEx *local_tdo = NULL;
	bool fetch_fti = false;
	struct lsa_ForestTrustInformation *new_fti = NULL;
	struct netr_TrustInfo *trust_info = NULL;
	struct netr_NETLOGON_INFO_2 *info2 = NULL;
	struct dcerpc_binding_handle *b = NULL;
	WERROR check_result = WERR_INTERNAL_ERROR;
	WERROR verify_result = WERR_INTERNAL_ERROR;
	bool retry = false;

	trusted_domain_name.string = domain->name;
	trusted_domain_name_l.string = domain->name;

	info2 = talloc_zero(p->mem_ctx, struct netr_NETLOGON_INFO_2);
	if (info2 == NULL) {
		TALLOC_FREE(frame);
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (domain->internal) {
		check_result = WERR_OK;
		goto check_return;
	}

	status = pdb_get_trust_credentials(domain->name,
					   domain->alt_name,
					   frame,
					   &creds);
	if (NT_STATUS_IS_OK(status)) {
		cur_nt_hash = cli_credentials_get_nt_hash(creds, frame);
		TALLOC_FREE(creds);
	}

	if (!domain->primary) {
		union lsa_TrustedDomainInfo *tdi = NULL;

		status = open_internal_lsa_conn(frame, &local_lsa_pipe,
						&local_lsa_policy);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("%s:%s: open_internal_lsa_conn() failed - %s\n",
				 __location__, __func__, nt_errstr(status)));
			TALLOC_FREE(frame);
			return WERR_INTERNAL_ERROR;
		}
		local_lsa = local_lsa_pipe->binding_handle;

		status = dcerpc_lsa_QueryTrustedDomainInfoByName(local_lsa, frame,
							&local_lsa_policy,
							&trusted_domain_name,
							LSA_TRUSTED_DOMAIN_INFO_INFO_EX,
							&tdi, &result);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("%s:%s: local_lsa.QueryTrustedDomainInfoByName(%s) failed - %s\n",
				 __location__, __func__, domain->name, nt_errstr(status)));
			TALLOC_FREE(frame);
			return WERR_INTERNAL_ERROR;
		}
		if (NT_STATUS_EQUAL(result, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			DEBUG(1,("%s:%s: domain[%s] not found via LSA, might be removed already.\n",
				 __location__, __func__, domain->name));
			TALLOC_FREE(frame);
			return WERR_NO_SUCH_DOMAIN;
		}
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(0,("%s:%s: local_lsa.QueryTrustedDomainInfoByName(%s) returned %s\n",
				 __location__, __func__, domain->name, nt_errstr(result)));
			TALLOC_FREE(frame);
			return WERR_INTERNAL_ERROR;
		}
		if (tdi == NULL) {
			DEBUG(0,("%s:%s: local_lsa.QueryTrustedDomainInfoByName() "
				 "returned no trusted domain information\n",
				 __location__, __func__));
			TALLOC_FREE(frame);
			return WERR_INTERNAL_ERROR;
		}

		local_tdo = &tdi->info_ex;
		trust_attributes = local_tdo->trust_attributes;
	}

	if (trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
		struct lsa_ForestTrustInformation *old_fti = NULL;

		status = dcerpc_lsa_lsaRQueryForestTrustInformation(local_lsa, frame,
							&local_lsa_policy,
							&trusted_domain_name,
							LSA_FOREST_TRUST_DOMAIN_INFO,
							&old_fti, &result);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("%s:%s: local_lsa.lsaRQueryForestTrustInformation(%s) failed %s\n",
				 __location__, __func__, domain->name, nt_errstr(status)));
			TALLOC_FREE(frame);
			return WERR_INTERNAL_ERROR;
		}
		if (NT_STATUS_EQUAL(result, NT_STATUS_NOT_FOUND)) {
			DEBUG(2,("%s: no forest trust information available for domain[%s] yet.\n",
				  __func__, domain->name));
			old_fti = NULL;
			fetch_fti = true;
			result = NT_STATUS_OK;
		}
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(0,("%s:%s: local_lsa.lsaRQueryForestTrustInformation(%s) returned %s\n",
				 __location__, __func__, domain->name, nt_errstr(result)));
			TALLOC_FREE(frame);
			return WERR_INTERNAL_ERROR;
		}

		TALLOC_FREE(old_fti);
	}

reconnect:
	status = cm_connect_netlogon_secure(domain,
					    &netlogon_pipe,
					    &netlogon_creds_ctx);
	reset_cm_connection_on_error(domain, NULL, status);
	if (NT_STATUS_EQUAL(status, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND)) {
		status = NT_STATUS_NO_LOGON_SERVERS;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("could not open handle to NETLOGON pipe: %s\n",
			  nt_errstr(status)));
		check_result = ntstatus_to_werror(status);
		goto check_return;
	}
	check_result = WERR_OK;
	b = netlogon_pipe->binding_handle;

	if (cur_nt_hash == NULL) {
		verify_result = WERR_NO_TRUST_LSA_SECRET;
		goto verify_return;
	}

	if (fetch_fti) {
		status = netlogon_creds_cli_GetForestTrustInformation(netlogon_creds_ctx,
								      b, frame,
								      &new_fti);
		if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
			status = NT_STATUS_NOT_SUPPORTED;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
			new_fti = NULL;
			status = NT_STATUS_OK;
		}
		if (!NT_STATUS_IS_OK(status)) {
			if (!retry &&
			    reset_cm_connection_on_error(domain, b, status))
			{
				retry = true;
				goto reconnect;
			}
			DEBUG(2, ("netlogon_creds_cli_GetForestTrustInformation(%s)"
				  "failed: %s\n",
				  domain->name, nt_errstr(status)));
			check_result = ntstatus_to_werror(status);
			goto check_return;
		}
	}

	if (new_fti != NULL) {
		struct lsa_ForestTrustInformation old_fti = {};
		struct lsa_ForestTrustInformation *merged_fti = NULL;
		struct lsa_ForestTrustCollisionInfo *collision_info = NULL;

		status = dsdb_trust_merge_forest_info(frame, local_tdo,
						      &old_fti, new_fti,
						      &merged_fti);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("%s:%s: dsdb_trust_merge_forest_info(%s) failed %s\n",
				 __location__, __func__,
				 domain->name, nt_errstr(status)));
			TALLOC_FREE(frame);
			return ntstatus_to_werror(status);
		}

		status = dcerpc_lsa_lsaRSetForestTrustInformation(local_lsa, frame,
						&local_lsa_policy,
						&trusted_domain_name_l,
						LSA_FOREST_TRUST_DOMAIN_INFO,
						merged_fti,
						0, /* check_only=0 => store it! */
						&collision_info,
						&result);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("%s:%s: local_lsa.lsaRSetForestTrustInformation(%s) failed %s\n",
				 __location__, __func__, domain->name, nt_errstr(status)));
			TALLOC_FREE(frame);
			return WERR_INTERNAL_ERROR;
		}
		if (!NT_STATUS_IS_OK(result)) {
			DEBUG(0,("%s:%s: local_lsa.lsaRSetForestTrustInformation(%s) returned %s\n",
				 __location__, __func__, domain->name, nt_errstr(result)));
			TALLOC_FREE(frame);
			return ntstatus_to_werror(result);
		}
	}

	status = netlogon_creds_cli_ServerGetTrustInfo(netlogon_creds_ctx,
						       b, frame,
						       &new_owf_password,
						       &old_owf_password,
						       &trust_info);
	if (NT_STATUS_EQUAL(status, NT_STATUS_RPC_PROCNUM_OUT_OF_RANGE)) {
		status = NT_STATUS_NOT_SUPPORTED;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		DEBUG(5, ("netlogon_creds_cli_ServerGetTrustInfo failed: %s\n",
			nt_errstr(status)));
		verify_result = WERR_OK;
		goto verify_return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		if (!retry && reset_cm_connection_on_error(domain, b, status)) {
			retry = true;
			goto reconnect;
		}
		DEBUG(2, ("netlogon_creds_cli_ServerGetTrustInfo failed: %s\n",
			nt_errstr(status)));

		if (!dcerpc_binding_handle_is_connected(b)) {
			check_result = ntstatus_to_werror(status);
			goto check_return;
		} else {
			verify_result = ntstatus_to_werror(status);
			goto verify_return;
		}
	}

	if (trust_info != NULL && trust_info->count >= 1) {
		uint32_t diff = trust_info->data[0] ^ trust_attributes;

		if (diff & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE) {
			verify_result = WERR_DOMAIN_TRUST_INCONSISTENT;
			goto verify_return;
		}
	}

	cmp_new = memcmp(new_owf_password.hash,
			 cur_nt_hash->hash,
			 sizeof(cur_nt_hash->hash));
	cmp_old = memcmp(old_owf_password.hash,
			 cur_nt_hash->hash,
			 sizeof(cur_nt_hash->hash));
	if (cmp_new != 0 && cmp_old != 0) {
		DEBUG(1,("%s:Error: credentials for domain[%s/%s] doesn't match "
			 "any password known to dcname[%s]\n",
			 __func__, domain->name, domain->alt_name,
			 domain->dcname));
		verify_result = WERR_WRONG_PASSWORD;
		goto verify_return;
	}

	if (cmp_new != 0) {
		DEBUG(2,("%s:Warning: credentials for domain[%s/%s] only match "
			 "against the old password known to dcname[%s]\n",
			 __func__, domain->name, domain->alt_name,
			 domain->dcname));
	}

	verify_result = WERR_OK;
	goto verify_return;

check_return:
	verify_result = check_result;
verify_return:
	info2->flags |= NETLOGON_VERIFY_STATUS_RETURNED;
	info2->pdc_connection_status = verify_result;
	if (domain->dcname != NULL) {
		info2->flags |= NETLOGON_HAS_IP;
		info2->flags |= NETLOGON_HAS_TIMESERV;
		info2->trusted_dc_name = talloc_asprintf(info2, "\\\\%s",
							 domain->dcname);
		if (info2->trusted_dc_name == NULL) {
			TALLOC_FREE(frame);
			return WERR_NOT_ENOUGH_MEMORY;
		}
	} else {
		info2->trusted_dc_name = talloc_strdup(info2, "");
		if (info2->trusted_dc_name == NULL) {
			TALLOC_FREE(frame);
			return WERR_NOT_ENOUGH_MEMORY;
		}
	}
	info2->tc_connection_status = check_result;

	if (!W_ERROR_IS_OK(info2->pdc_connection_status)) {
		DEBUG(2, ("%s: domain[%s/%s] dcname[%s] "
			  "pdc_connection[%s] tc_connection[%s]\n",
			  __func__, domain->name, domain->alt_name,
			  domain->dcname,
			  win_errstr(info2->pdc_connection_status),
			  win_errstr(info2->tc_connection_status)));
	}

	r->out.query->info2 = info2;

	DEBUG(5, ("%s: succeeded.\n", __func__));
	TALLOC_FREE(frame);
	return WERR_OK;
}

static WERROR _winbind_LogonControl_CHANGE_PASSWORD(struct pipes_struct *p,
			     struct winbindd_domain *domain,
			     struct winbind_LogonControl *r)
{
	struct messaging_context *msg_ctx = global_messaging_context();
	NTSTATUS status;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;
	struct cli_credentials *creds = NULL;
	struct samr_Password *cur_nt_hash = NULL;
	struct netr_NETLOGON_INFO_1 *info1 = NULL;
	struct dcerpc_binding_handle *b;
	WERROR change_result = WERR_OK;
	bool retry = false;

	info1 = talloc_zero(p->mem_ctx, struct netr_NETLOGON_INFO_1);
	if (info1 == NULL) {
		return WERR_NOT_ENOUGH_MEMORY;
	}

	if (domain->internal) {
		return WERR_NOT_SUPPORTED;
	}

	status = pdb_get_trust_credentials(domain->name,
					   domain->alt_name,
					   p->mem_ctx,
					   &creds);
	if (NT_STATUS_IS_OK(status)) {
		cur_nt_hash = cli_credentials_get_nt_hash(creds, p->mem_ctx);
		TALLOC_FREE(creds);
	}

reconnect:
	status = cm_connect_netlogon_secure(domain,
					    &netlogon_pipe,
					    &netlogon_creds_ctx);
	reset_cm_connection_on_error(domain, NULL, status);
	if (NT_STATUS_EQUAL(status, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND)) {
		status = NT_STATUS_NO_LOGON_SERVERS;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("%s: domain[%s/%s] cm_connect_netlogon() returned %s\n",
			  __func__, domain->name, domain->alt_name,
			  nt_errstr(status)));
		/*
		 * Here we return a top level error!
		 * This is different than TC_QUERY or TC_VERIFY.
		 */
		return ntstatus_to_werror(status);
	}
	b = netlogon_pipe->binding_handle;

	if (cur_nt_hash == NULL) {
		change_result = WERR_NO_TRUST_LSA_SECRET;
		goto change_return;
	}
	TALLOC_FREE(cur_nt_hash);

	status = trust_pw_change(netlogon_creds_ctx,
				 msg_ctx, b, domain->name,
				 domain->dcname,
				 true); /* force */
	if (!NT_STATUS_IS_OK(status)) {
		if (!retry && reset_cm_connection_on_error(domain, b, status)) {
			retry = true;
			goto reconnect;
		}

		DEBUG(1, ("trust_pw_change(%s): %s\n",
			  domain->name, nt_errstr(status)));

		change_result = ntstatus_to_werror(status);
		goto change_return;
	}

	change_result = WERR_OK;

change_return:
	info1->pdc_connection_status = change_result;

	if (!W_ERROR_IS_OK(info1->pdc_connection_status)) {
		DEBUG(2, ("%s: domain[%s/%s] dcname[%s] "
			  "pdc_connection[%s]\n",
			  __func__, domain->name, domain->alt_name,
			  domain->dcname,
			  win_errstr(info1->pdc_connection_status)));
	}

	r->out.query->info1 = info1;

	DEBUG(5, ("%s: succeeded.\n", __func__));
	return WERR_OK;
}

WERROR _winbind_LogonControl(struct pipes_struct *p,
			     struct winbind_LogonControl *r)
{
	struct winbindd_domain *domain;

	domain = wb_child_domain();
	if (domain == NULL) {
		return WERR_NO_SUCH_DOMAIN;
	}

	switch (r->in.function_code) {
	case NETLOGON_CONTROL_REDISCOVER:
		if (r->in.level != 2) {
			return WERR_INVALID_PARAMETER;
		}
		return _winbind_LogonControl_REDISCOVER(p, domain, r);
	case NETLOGON_CONTROL_TC_QUERY:
		if (r->in.level != 2) {
			return WERR_INVALID_PARAMETER;
		}
		return _winbind_LogonControl_TC_QUERY(p, domain, r);
	case NETLOGON_CONTROL_TC_VERIFY:
		if (r->in.level != 2) {
			return WERR_INVALID_PARAMETER;
		}
		return _winbind_LogonControl_TC_VERIFY(p, domain, r);
	case NETLOGON_CONTROL_CHANGE_PASSWORD:
		if (r->in.level != 1) {
			return WERR_INVALID_PARAMETER;
		}
		return _winbind_LogonControl_CHANGE_PASSWORD(p, domain, r);
	default:
		break;
	}

	DEBUG(4, ("%s: function_code[0x%x] not supported\n",
		  __func__, r->in.function_code));
	return WERR_NOT_SUPPORTED;
}

WERROR _winbind_GetForestTrustInformation(struct pipes_struct *p,
			     struct winbind_GetForestTrustInformation *r)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status, result;
	struct winbindd_domain *domain;
	struct rpc_pipe_client *netlogon_pipe = NULL;
	struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;
	struct dcerpc_binding_handle *b;
	bool retry = false;
	struct lsa_String trusted_domain_name = {};
	struct lsa_StringLarge trusted_domain_name_l = {};
	union lsa_TrustedDomainInfo *tdi = NULL;
	const struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	struct lsa_ForestTrustInformation _old_fti = {};
	struct lsa_ForestTrustInformation *old_fti = NULL;
	struct lsa_ForestTrustInformation *new_fti = NULL;
	struct lsa_ForestTrustInformation *merged_fti = NULL;
	struct lsa_ForestTrustCollisionInfo *collision_info = NULL;
	bool update_fti = false;
	struct rpc_pipe_client *local_lsa_pipe;
	struct policy_handle local_lsa_policy;
	struct dcerpc_binding_handle *local_lsa = NULL;

	domain = wb_child_domain();
	if (domain == NULL) {
		TALLOC_FREE(frame);
		return WERR_NO_SUCH_DOMAIN;
	}

	/*
	 * checking for domain->internal and domain->primary
	 * makes sure we only do some work when running as DC.
	 */

	if (domain->internal) {
		TALLOC_FREE(frame);
		return WERR_NO_SUCH_DOMAIN;
	}

	if (domain->primary) {
		TALLOC_FREE(frame);
		return WERR_NO_SUCH_DOMAIN;
	}

	trusted_domain_name.string = domain->name;
	trusted_domain_name_l.string = domain->name;

	status = open_internal_lsa_conn(frame, &local_lsa_pipe,
					&local_lsa_policy);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("%s:%s: open_internal_lsa_conn() failed - %s\n",
			 __location__, __func__, nt_errstr(status)));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}
	local_lsa = local_lsa_pipe->binding_handle;

	status = dcerpc_lsa_QueryTrustedDomainInfoByName(local_lsa, frame,
						&local_lsa_policy,
						&trusted_domain_name,
						LSA_TRUSTED_DOMAIN_INFO_INFO_EX,
						&tdi, &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("%s:%s: local_lsa.QueryTrustedDomainInfoByName(%s) failed - %s\n",
			 __location__, __func__, domain->name, nt_errstr(status)));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}
	if (NT_STATUS_EQUAL(result, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		DEBUG(1,("%s:%s: domain[%s] not found via LSA, might be removed already.\n",
			 __location__, __func__, domain->name));
		TALLOC_FREE(frame);
		return WERR_NO_SUCH_DOMAIN;
	}
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("%s:%s: local_lsa.QueryTrustedDomainInfoByName(%s) returned %s\n",
			 __location__, __func__, domain->name, nt_errstr(result)));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}
	if (tdi == NULL) {
		DEBUG(0,("%s:%s: local_lsa.QueryTrustedDomainInfoByName() "
			 "returned no trusted domain information\n",
			 __location__, __func__));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}

	tdo = &tdi->info_ex;

	if (!(tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_FOREST_TRANSITIVE)) {
		DEBUG(2,("%s: tdo[%s/%s] is no forest trust attributes[0x%08X]\n",
			 __func__, tdo->netbios_name.string,
			 tdo->domain_name.string,
			 (unsigned)tdo->trust_attributes));
		TALLOC_FREE(frame);
		return WERR_NO_SUCH_DOMAIN;
	}

	if (r->in.flags & ~DS_GFTI_UPDATE_TDO) {
		TALLOC_FREE(frame);
		return WERR_INVALID_FLAGS;
	}

reconnect:
	status = cm_connect_netlogon_secure(domain,
					    &netlogon_pipe,
					    &netlogon_creds_ctx);
	reset_cm_connection_on_error(domain, NULL, status);
	if (NT_STATUS_EQUAL(status, NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND)) {
		status = NT_STATUS_NO_LOGON_SERVERS;
	}
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("could not open handle to NETLOGON pipe: %s\n",
			  nt_errstr(status)));
		TALLOC_FREE(frame);
		return ntstatus_to_werror(status);
	}
	b = netlogon_pipe->binding_handle;

	status = netlogon_creds_cli_GetForestTrustInformation(netlogon_creds_ctx,
							      b, p->mem_ctx,
							      &new_fti);
	if (!NT_STATUS_IS_OK(status)) {
		if (!retry && reset_cm_connection_on_error(domain, b, status)) {
			retry = true;
			goto reconnect;
		}
		DEBUG(2, ("netlogon_creds_cli_GetForestTrustInformation(%s) failed: %s\n",
			  domain->name, nt_errstr(status)));
		TALLOC_FREE(frame);
		return ntstatus_to_werror(status);
	}

	*r->out.forest_trust_info = new_fti;

	if (r->in.flags & DS_GFTI_UPDATE_TDO) {
		update_fti = true;
	}

	status = dcerpc_lsa_lsaRQueryForestTrustInformation(local_lsa, frame,
						&local_lsa_policy,
						&trusted_domain_name,
						LSA_FOREST_TRUST_DOMAIN_INFO,
						&old_fti, &result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("%s:%s: local_lsa.lsaRQueryForestTrustInformation(%s) failed %s\n",
			 __location__, __func__, domain->name, nt_errstr(status)));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}
	if (NT_STATUS_EQUAL(result, NT_STATUS_NOT_FOUND)) {
		DEBUG(2,("%s: no forest trust information available for domain[%s] yet.\n",
			  __func__, domain->name));
		update_fti = true;
		old_fti = &_old_fti;
		result = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("%s:%s: local_lsa.lsaRQueryForestTrustInformation(%s) returned %s\n",
			 __location__, __func__, domain->name, nt_errstr(result)));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}

	if (old_fti == NULL) {
		DEBUG(0,("%s:%s: local_lsa.lsaRQueryForestTrustInformation() "
			 "returned success without returning forest trust information\n",
			 __location__, __func__));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}

	if (!update_fti) {
		goto done;
	}

	status = dsdb_trust_merge_forest_info(frame, tdo, old_fti, new_fti,
					      &merged_fti);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("%s:%s: dsdb_trust_merge_forest_info(%s) failed %s\n",
			 __location__, __func__, domain->name, nt_errstr(status)));
		TALLOC_FREE(frame);
		return ntstatus_to_werror(status);
	}

	status = dcerpc_lsa_lsaRSetForestTrustInformation(local_lsa, frame,
						&local_lsa_policy,
						&trusted_domain_name_l,
						LSA_FOREST_TRUST_DOMAIN_INFO,
						merged_fti,
						0, /* check_only=0 => store it! */
						&collision_info,
						&result);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("%s:%s: local_lsa.lsaRSetForestTrustInformation(%s) failed %s\n",
			 __location__, __func__, domain->name, nt_errstr(status)));
		TALLOC_FREE(frame);
		return WERR_INTERNAL_ERROR;
	}
	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(0,("%s:%s: local_lsa.lsaRSetForestTrustInformation(%s) returned %s\n",
			 __location__, __func__, domain->name, nt_errstr(result)));
		TALLOC_FREE(frame);
		return ntstatus_to_werror(result);
	}

done:
	DEBUG(5, ("_winbind_GetForestTrustInformation succeeded\n"));
	TALLOC_FREE(frame);
	return WERR_OK;
}

NTSTATUS _winbind_SendToSam(struct pipes_struct *p, struct winbind_SendToSam *r)
{
	struct winbindd_domain *domain;
	NTSTATUS status;
	struct rpc_pipe_client *netlogon_pipe;
	struct netlogon_creds_cli_context *netlogon_creds_ctx = NULL;
	struct dcerpc_binding_handle *b = NULL;
	bool retry = false;

	DEBUG(5, ("_winbind_SendToSam received\n"));
	domain = wb_child_domain();
	if (domain == NULL) {
		return NT_STATUS_REQUEST_NOT_ACCEPTED;
	}

reconnect:
	status = cm_connect_netlogon_secure(domain,
					    &netlogon_pipe,
					    &netlogon_creds_ctx);
	reset_cm_connection_on_error(domain, NULL, status);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(3, ("could not open handle to NETLOGON pipe\n"));
		return status;
	}

	b = netlogon_pipe->binding_handle;

	status = netlogon_creds_cli_SendToSam(netlogon_creds_ctx,
					      b,
					      &r->in.message);
	if (!retry && reset_cm_connection_on_error(domain, b, status)) {
		retry = true;
		goto reconnect;
	}

	return status;
}

#include "librpc/gen_ndr/ndr_winbind_scompat.c"
