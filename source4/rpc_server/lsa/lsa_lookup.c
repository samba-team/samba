/* 
   Unix SMB/CIFS implementation.

   endpoint server for the lsarpc pipe

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2007
   
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

#include "rpc_server/lsa/lsa.h"
#include "libds/common/roles.h"
#include "libds/common/flag_mapping.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_lsa_c.h"

struct dcesrv_lsa_TranslatedItem {
	enum lsa_SidType type;
	const struct dom_sid *sid;
	const char *name;
	const char *authority_name;
	const struct dom_sid *authority_sid;
	uint32_t flags;
	uint32_t wb_idx;
	bool done;
	struct {
		const char *domain; /* only $DOMAIN\ */
		const char *namespace; /* $NAMESPACE\ or @$NAMESPACE */
		const char *principal; /* \$PRINCIPAL or $PRIN@IPAL */
		const char *sid; /* "S-1-5-21-9000-8000-7000-6000" */
		const char *rid; /* "00001770" */
	} hints;
};

struct dcesrv_lsa_LookupSids_base_state;
struct dcesrv_lsa_LookupNames_base_state;

struct dcesrv_lsa_Lookup_view {
	const char *name;
	NTSTATUS (*lookup_sid)(struct dcesrv_lsa_LookupSids_base_state *state,
			       struct dcesrv_lsa_TranslatedItem *item);
	NTSTATUS (*lookup_name)(struct dcesrv_lsa_LookupNames_base_state *state,
				struct dcesrv_lsa_TranslatedItem *item);
};

struct dcesrv_lsa_Lookup_view_table {
	const char *name;
	size_t count;
	const struct dcesrv_lsa_Lookup_view **array;
};

static const struct dcesrv_lsa_Lookup_view_table *dcesrv_lsa_view_table(
	enum lsa_LookupNamesLevel level);

/*
  lookup a SID for 1 name
*/
static NTSTATUS dcesrv_lsa_lookup_name(struct lsa_policy_state *state,
				       TALLOC_CTX *mem_ctx,
				       const char *domain_name,
				       const struct dom_sid *domain_sid,
				       struct ldb_dn *domain_dn,
				       const char *principal,
				       const struct dom_sid **p_sid,
				       enum lsa_SidType *p_type)
{
	const char * const attrs[] = { "objectSid", "sAMAccountType", NULL};
	struct ldb_message **res = NULL;
	const char *nt4_account = NULL;
	char *encoded_account = NULL;
	const char *at = NULL;
	NTSTATUS status;
	const struct dom_sid *sid = NULL;
	uint32_t atype;
	enum lsa_SidType type;
	bool match = false;
	int ret;

	if ((principal == NULL) || (principal[0] == '\0')) {
		return NT_STATUS_NONE_MAPPED;
	}

	at = strchr(principal, '@');
	if (at != NULL) {
		const char *nt4_domain = NULL;

		status = crack_name_to_nt4_name(mem_ctx,
						state->sam_ldb,
						DRSUAPI_DS_NAME_FORMAT_USER_PRINCIPAL,
						principal,
						&nt4_domain,
						&nt4_account);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(3, ("Failed to crack name %s into an NT4 name: %s\n",
				  principal, nt_errstr(status)));
			return status;
		}

		match = strequal(nt4_domain, domain_name);
		if (!match) {
			/*
			 * TODO: handle multiple domains in a forest.
			 */
			return NT_STATUS_NONE_MAPPED;
		}
	} else {
		nt4_account = principal;
	}

	encoded_account = ldb_binary_encode_string(mem_ctx, nt4_account);
	if (encoded_account == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = gendb_search(state->sam_ldb, mem_ctx, domain_dn, &res, attrs, 
			   "(&(sAMAccountName=%s)(objectSid=*))", 
			   encoded_account);
	TALLOC_FREE(encoded_account);
	if (ret < 0) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}
	if (ret == 0) {
		return NT_STATUS_NONE_MAPPED;
	}
	if (ret > 1) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		DBG_ERR("nt4_account[%s] found %d times (principal[%s]) - %s\n",
			nt4_account, ret, principal, nt_errstr(status));
		return status;
	}

	sid = samdb_result_dom_sid(mem_ctx, res[0], "objectSid");
	if (sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Check that this is in the domain */
	match = dom_sid_in_domain(domain_sid, sid);
	if (!match) {
		return NT_STATUS_NONE_MAPPED;
	}

	atype = ldb_msg_find_attr_as_uint(res[0], "sAMAccountType", 0);
	type = ds_atype_map(atype);
	if (type == SID_NAME_UNKNOWN) {
		return NT_STATUS_NONE_MAPPED;
	}

	*p_sid = sid;
	*p_type = type;
	return NT_STATUS_OK;
}


/*
  add to the lsa_RefDomainList for LookupSids and LookupNames
*/
static NTSTATUS dcesrv_lsa_authority_list(const char *authority_name,
					  const struct dom_sid *authority_sid,
					  struct lsa_RefDomainList *domains,
					  uint32_t *sid_index)
{
	uint32_t i;

	*sid_index = UINT32_MAX;

	if (authority_name == NULL) {
		return NT_STATUS_OK;
	}

	/* see if we've already done this authority name */
	for (i=0;i<domains->count;i++) {
		if (strcasecmp_m(authority_name, domains->domains[i].name.string) == 0) {
			*sid_index = i;
			return NT_STATUS_OK;
		}
	}

	domains->domains = talloc_realloc(domains, 
					  domains->domains,
					  struct lsa_DomainInfo,
					  domains->count+1);
	if (domains->domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	domains->domains[i].name.string = talloc_strdup(domains->domains,
							authority_name);
	if (domains->domains[i].name.string == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	domains->domains[i].sid         = dom_sid_dup(domains->domains,
						      authority_sid);
	if (domains->domains[i].sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	domains->count++;
	domains->max_size = LSA_REF_DOMAIN_LIST_MULTIPLIER * domains->count;
	*sid_index = i;

	return NT_STATUS_OK;
}

/*
  lookup a name for 1 SID
*/
static NTSTATUS dcesrv_lsa_lookup_sid(struct lsa_policy_state *state,
				      TALLOC_CTX *mem_ctx,
				      const char *domain_name,
				      const struct dom_sid *domain_sid,
				      struct ldb_dn *domain_dn,
				      const struct dom_sid *sid,
				      const char **p_name,
				      enum lsa_SidType *p_type)
{
	const char * const attrs[] = { "sAMAccountName", "sAMAccountType", NULL};
	struct ldb_message **res = NULL;
	char *encoded_sid = NULL;
	const char *name = NULL;
	uint32_t atype;
	enum lsa_SidType type;
	int ret;

	encoded_sid = ldap_encode_ndr_dom_sid(mem_ctx, sid);
	if (encoded_sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = gendb_search(state->sam_ldb, mem_ctx, domain_dn, &res, attrs, 
			   "(&(objectSid=%s)(sAMAccountName=*))", encoded_sid);
	TALLOC_FREE(encoded_sid);
	if (ret < 0) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}
	if (ret == 0) {
		return NT_STATUS_NONE_MAPPED;
	}
	if (ret > 1) {
		NTSTATUS status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		DBG_ERR("sid[%s] found %d times - %s\n",
			dom_sid_string(mem_ctx, sid), ret, nt_errstr(status));
		return status;
	}

	name = ldb_msg_find_attr_as_string(res[0], "sAMAccountName", NULL);
	if (name == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	atype = ldb_msg_find_attr_as_uint(res[0], "sAMAccountType", 0);
	type = ds_atype_map(atype);
	if (type == SID_NAME_UNKNOWN) {
		return NT_STATUS_NONE_MAPPED;
	}

	*p_name = name;
	*p_type = type;
	return NT_STATUS_OK;
}

struct dcesrv_lsa_LookupSids_base_state {
	struct dcesrv_call_state *dce_call;

	TALLOC_CTX *mem_ctx;

	struct lsa_policy_state *policy_state;

	struct lsa_LookupSids3 r;

	const struct dcesrv_lsa_Lookup_view_table *view_table;
	struct dcesrv_lsa_TranslatedItem *items;

	struct dsdb_trust_routing_table *routing_table;

	struct {
		struct dcerpc_binding_handle *irpc_handle;
		struct lsa_SidArray sids;
		struct lsa_RefDomainList *domains;
		struct lsa_TransNameArray2 names;
		uint32_t count;
		NTSTATUS result;
	} wb;

	struct {
		struct lsa_LookupSids *l;
		struct lsa_LookupSids2 *l2;
		struct lsa_LookupSids3 *l3;
	} _r;
};

static NTSTATUS dcesrv_lsa_LookupSids_base_finish(
	struct dcesrv_lsa_LookupSids_base_state *state);
static void dcesrv_lsa_LookupSids_base_map(
	struct dcesrv_lsa_LookupSids_base_state *state);
static void dcesrv_lsa_LookupSids_base_done(struct tevent_req *subreq);

static NTSTATUS dcesrv_lsa_LookupSids_base_call(struct dcesrv_lsa_LookupSids_base_state *state)
{
	struct lsa_LookupSids3 *r = &state->r;
	struct tevent_req *subreq = NULL;
	uint32_t v;
	uint32_t i;

	*r->out.domains = NULL;
	r->out.names->count = 0;
	r->out.names->names = NULL;
	*r->out.count = 0;

	state->view_table = dcesrv_lsa_view_table(r->in.level);
	if (state->view_table == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*r->out.domains = talloc_zero(r->out.domains, struct lsa_RefDomainList);
	if (*r->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.names->names = talloc_zero_array(r->out.names,
						struct lsa_TranslatedName2,
						r->in.sids->num_sids);
	if (r->out.names->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->items = talloc_zero_array(state,
					 struct dcesrv_lsa_TranslatedItem,
					 r->in.sids->num_sids);
	if (state->items == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<r->in.sids->num_sids;i++) {
		struct dcesrv_lsa_TranslatedItem *item = &state->items[i];
		uint32_t rid = 0;

		if (r->in.sids->sids[i].sid == NULL) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		item->type = SID_NAME_UNKNOWN;
		item->sid = r->in.sids->sids[i].sid;

		item->hints.sid = dom_sid_string(state->items, item->sid);
		if (item->hints.sid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		dom_sid_split_rid(state->items, item->sid, NULL, &rid);
		item->hints.rid = talloc_asprintf(state->items,
						  "%08X", (unsigned)rid);
		if (item->hints.rid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	for (v=0; v < state->view_table->count; v++) {
		const struct dcesrv_lsa_Lookup_view *view =
			state->view_table->array[v];

		for (i=0; i < r->in.sids->num_sids; i++) {
			struct dcesrv_lsa_TranslatedItem *item = &state->items[i];
			NTSTATUS status;

			if (item->done) {
				continue;
			}

			status = view->lookup_sid(state, item);
			if (NT_STATUS_IS_OK(status)) {
				item->done = true;
			} else if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
				status = NT_STATUS_OK;
			} else if (NT_STATUS_EQUAL(status, NT_STATUS_SOME_NOT_MAPPED)) {
				status = NT_STATUS_OK;
			}
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}

	if (state->wb.irpc_handle == NULL) {
		return dcesrv_lsa_LookupSids_base_finish(state);
	}

	state->wb.sids.sids = talloc_zero_array(state, struct lsa_SidPtr,
						r->in.sids->num_sids);
	if (state->wb.sids.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0; i < r->in.sids->num_sids; i++) {
		struct dcesrv_lsa_TranslatedItem *item = &state->items[i];

		if (item->done) {
			continue;
		}

		item->wb_idx = state->wb.sids.num_sids;
		state->wb.sids.sids[item->wb_idx] = r->in.sids->sids[i];
		state->wb.sids.num_sids++;
	}

	subreq = dcerpc_lsa_LookupSids3_send(state,
					     state->dce_call->event_ctx,
					     state->wb.irpc_handle,
					     &state->wb.sids,
					     &state->wb.domains,
					     &state->wb.names,
					     state->r.in.level,
					     &state->wb.count,
					     state->r.in.lookup_options,
					     state->r.in.client_revision);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;;
	}
	state->dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;
	tevent_req_set_callback(subreq,
				dcesrv_lsa_LookupSids_base_done,
				state);

	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_lsa_LookupSids_base_finish(
	struct dcesrv_lsa_LookupSids_base_state *state)
{
	struct lsa_LookupSids3 *r = &state->r;
	uint32_t i;

	for (i=0;i<r->in.sids->num_sids;i++) {
		struct dcesrv_lsa_TranslatedItem *item = &state->items[i];
		NTSTATUS status;
		uint32_t sid_index = UINT32_MAX;

		status = dcesrv_lsa_authority_list(item->authority_name,
						   item->authority_sid,
						   *r->out.domains,
						   &sid_index);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (item->name == NULL && r->in.level == LSA_LOOKUP_NAMES_ALL) {
			if (sid_index == UINT32_MAX) {
				item->name = item->hints.sid;
			} else {
				item->name = item->hints.rid;
			}
		}

		r->out.names->names[i].sid_type    = item->type;
		r->out.names->names[i].name.string = item->name;
		r->out.names->names[i].sid_index   = sid_index;
		r->out.names->names[i].unknown     = item->flags;

		r->out.names->count++;
		if (item->type != SID_NAME_UNKNOWN) {
			(*r->out.count)++;
		}
	}

	if (*r->out.count == 0) {
		return NT_STATUS_NONE_MAPPED;
	}
	if (*r->out.count != r->in.sids->num_sids) {
		return STATUS_SOME_UNMAPPED;
	}

	return NT_STATUS_OK;
}

static void dcesrv_lsa_LookupSids_base_map(
	struct dcesrv_lsa_LookupSids_base_state *state)
{
	if (state->_r.l3 != NULL) {
		struct lsa_LookupSids3 *r = state->_r.l3;

		r->out.result = state->r.out.result;
		return;
	}

	if (state->_r.l2 != NULL) {
		struct lsa_LookupSids2 *r = state->_r.l2;

		r->out.result = state->r.out.result;
		return;
	}

	if (state->_r.l != NULL) {
		struct lsa_LookupSids *r = state->_r.l;
		uint32_t i;

		r->out.result = state->r.out.result;

		SMB_ASSERT(state->r.out.names->count <= r->in.sids->num_sids);
		for (i = 0; i < state->r.out.names->count; i++) {
			struct lsa_TranslatedName2 *n2 =
				&state->r.out.names->names[i];
			struct lsa_TranslatedName *n =
				&r->out.names->names[i];

			n->sid_type = n2->sid_type;
			n->name = n2->name;
			n->sid_index = n2->sid_index;
		}
		r->out.names->count = state->r.out.names->count;
		return;
	}
}

static void dcesrv_lsa_LookupSids_base_done(struct tevent_req *subreq)
{
	struct dcesrv_lsa_LookupSids_base_state *state =
		tevent_req_callback_data(subreq,
		struct dcesrv_lsa_LookupSids_base_state);
	struct dcesrv_call_state *dce_call = state->dce_call;
	NTSTATUS status;
	uint32_t i;

	status = dcerpc_lsa_LookupSids3_recv(subreq, state->mem_ctx,
					     &state->wb.result);
	TALLOC_FREE(subreq);
	TALLOC_FREE(state->wb.irpc_handle);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		DEBUG(0,(__location__ ": IRPC callback failed %s\n",
			 nt_errstr(status)));
		goto finished;
	} else if (!NT_STATUS_IS_OK(status)) {
		state->dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
		DEBUG(0,(__location__ ": IRPC callback failed %s\n",
			 nt_errstr(status)));
		goto finished;
	}

	status = state->wb.result;
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		status = NT_STATUS_OK;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_SOME_NOT_MAPPED)) {
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		goto finished;
	}

	for (i=0; i < state->r.in.sids->num_sids; i++) {
		struct dcesrv_lsa_TranslatedItem *item = &state->items[i];
		struct lsa_TranslatedName2 *s2 = NULL;
		struct lsa_DomainInfo *d = NULL;

		if (item->done) {
			continue;
		}

		if (item->wb_idx >= state->wb.names.count) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto finished;
		}

		s2 = &state->wb.names.names[item->wb_idx];

		item->type = s2->sid_type;
		item->name = s2->name.string;
		item->flags = s2->unknown;

		if (s2->sid_index == UINT32_MAX) {
			continue;
		}

		if (state->wb.domains == NULL) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto finished;
		}

		if (s2->sid_index >= state->wb.domains->count) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto finished;
		}

		d = &state->wb.domains->domains[s2->sid_index];

		item->authority_name = d->name.string;
		item->authority_sid = d->sid;
	}

	status = dcesrv_lsa_LookupSids_base_finish(state);
 finished:
	state->r.out.result = status;
	dcesrv_lsa_LookupSids_base_map(state);

	status = dcesrv_reply(dce_call);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": dcesrv_reply() failed - %s\n", nt_errstr(status)));
	}
}

/*
  lsa_LookupSids2
*/
NTSTATUS dcesrv_lsa_LookupSids2(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx,
				struct lsa_LookupSids2 *r)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	struct dcesrv_lsa_LookupSids_base_state *state = NULL;
	struct dcesrv_handle *policy_handle = NULL;
	NTSTATUS status;

	if (transport != NCACN_NP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	*r->out.domains = NULL;
	r->out.names->count = 0;
	r->out.names->names = NULL;
	*r->out.count = 0;

	state = talloc_zero(mem_ctx, struct dcesrv_lsa_LookupSids_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->policy_state = policy_handle->data;

	state->r.in.sids = r->in.sids;
	state->r.in.level = r->in.level;
	state->r.in.lookup_options = r->in.lookup_options;
	state->r.in.client_revision = r->in.client_revision;
	state->r.in.names = r->in.names;
	state->r.in.count = r->in.count;
	state->r.out.domains = r->out.domains;
	state->r.out.names = r->out.names;
	state->r.out.count = r->out.count;

	state->_r.l2 = r;

	status = dcesrv_lsa_LookupSids_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return status;
	}

	state->r.out.result = status;
	dcesrv_lsa_LookupSids_base_map(state);
	return status;
}

/* A random hexidecimal number (honest!) */
#define LSA_SERVER_IMPLICIT_POLICY_STATE_MAGIC 0xc0c99e00

/*
  Ensure we're operating on an schannel connection,
  and use a lsa_policy_state cache on the connection.
*/
static NTSTATUS schannel_call_setup(struct dcesrv_call_state *dce_call,
				    struct lsa_policy_state **_policy_state)
{
	struct lsa_policy_state *policy_state = NULL;
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	enum dcerpc_AuthType auth_type = DCERPC_AUTH_TYPE_NONE;
	if (transport != NCACN_IP_TCP) {
		/* We can't call DCESRV_FAULT() in the sub-function */
		dce_call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * We don't have policy handles on this call. So this must be restricted
	 * to crypto connections only.
	 *
	 * NB. gensec requires schannel connections to
	 * have at least DCERPC_AUTH_LEVEL_INTEGRITY.
	 */
	dcesrv_call_auth_info(dce_call, &auth_type, NULL);
	if (auth_type != DCERPC_AUTH_TYPE_SCHANNEL) {
		/* We can't call DCESRV_FAULT() in the sub-function */
		dce_call->fault_code = DCERPC_FAULT_ACCESS_DENIED;
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * We don't have a policy handle on this call, so we want to
	 * make a policy state and cache it for the life of the
	 * connection, to avoid re-opening the DB each call.
	 */
	policy_state
		= dcesrv_iface_state_find_conn(dce_call,
					       LSA_SERVER_IMPLICIT_POLICY_STATE_MAGIC,
					       struct lsa_policy_state);

	if (policy_state == NULL) {
		NTSTATUS status
			= dcesrv_lsa_get_policy_state(dce_call,
						      dce_call /* mem_ctx */,
						      0, /* we skip access checks */
						      &policy_state);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/*
		 * This will talloc_steal() policy_state onto the
		 * connection, which has longer lifetime than the
		 * immidiate caller requires
		 */
		status = dcesrv_iface_state_store_conn(dce_call,
						       LSA_SERVER_IMPLICIT_POLICY_STATE_MAGIC,
						       policy_state);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	*_policy_state = policy_state;
	return NT_STATUS_OK;
}

/*
  lsa_LookupSids3

  Identical to LookupSids2, but doesn't take a policy handle

*/
NTSTATUS dcesrv_lsa_LookupSids3(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx,
				struct lsa_LookupSids3 *r)
{
	struct dcesrv_lsa_LookupSids_base_state *state = NULL;
	NTSTATUS status;

	*r->out.domains = NULL;
	r->out.names->count = 0;
	r->out.names->names = NULL;
	*r->out.count = 0;

	state = talloc_zero(mem_ctx, struct dcesrv_lsa_LookupSids_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * We don't have a policy handle on this call, so we want to
	 * make a policy state and cache it for the life of the
	 * connection, to avoid re-opening the DB each call.
	 *
	 * This also enforces that this is only available over
	 * ncacn_ip_tcp and with SCHANNEL.
	 *
	 * schannel_call_setup may also set the fault state.
	 *
	 * state->policy_state is shared between all calls on this
	 * connection and is moved with talloc_steal() under the
	 * connection, not dce_call or state.
	 */
	status = schannel_call_setup(dce_call, &state->policy_state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;
	state->r.in.sids = r->in.sids;
	state->r.in.level = r->in.level;
	state->r.in.lookup_options = r->in.lookup_options;
	state->r.in.client_revision = r->in.client_revision;
	state->r.in.names = r->in.names;
	state->r.in.count = r->in.count;
	state->r.out.domains = r->out.domains;
	state->r.out.names = r->out.names;
	state->r.out.count = r->out.count;

	state->_r.l3 = r;

	status = dcesrv_lsa_LookupSids_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return status;
	}

	state->r.out.result = status;
	dcesrv_lsa_LookupSids_base_map(state);
	return status;
}


/* 
  lsa_LookupSids 
*/
NTSTATUS dcesrv_lsa_LookupSids(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct lsa_LookupSids *r)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	struct dcesrv_lsa_LookupSids_base_state *state = NULL;
	struct dcesrv_handle *policy_handle = NULL;
	NTSTATUS status;

	if (transport != NCACN_NP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	*r->out.domains = NULL;
	r->out.names->count = 0;
	r->out.names->names = NULL;
	*r->out.count = 0;

	r->out.names->names = talloc_zero_array(r->out.names,
						struct lsa_TranslatedName,
						r->in.sids->num_sids);
	if (r->out.names->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_zero(mem_ctx, struct dcesrv_lsa_LookupSids_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->policy_state = policy_handle->data;

	state->r.in.sids = r->in.sids;
	state->r.in.level = r->in.level;
	state->r.in.lookup_options = LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES;
	state->r.in.client_revision = LSA_CLIENT_REVISION_1;
	state->r.in.names = talloc_zero(state, struct lsa_TransNameArray2);
	if (state->r.in.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->r.in.count = r->in.count;
	state->r.out.domains = r->out.domains;
	state->r.out.names = talloc_zero(state, struct lsa_TransNameArray2);
	if (state->r.out.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->r.out.count = r->out.count;

	state->_r.l = r;

	status = dcesrv_lsa_LookupSids_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return status;
	}

	state->r.out.result = status;
	dcesrv_lsa_LookupSids_base_map(state);
	return status;
}

struct dcesrv_lsa_LookupNames_base_state {
	struct dcesrv_call_state *dce_call;

	TALLOC_CTX *mem_ctx;

	struct lsa_policy_state *policy_state;

	struct lsa_LookupNames4 r;

	const struct dcesrv_lsa_Lookup_view_table *view_table;
	struct dcesrv_lsa_TranslatedItem *items;

	struct dsdb_trust_routing_table *routing_table;

	struct {
		struct dcerpc_binding_handle *irpc_handle;
		uint32_t num_names;
		struct lsa_String *names;
		struct lsa_RefDomainList *domains;
		struct lsa_TransSidArray3 sids;
		uint32_t count;
		NTSTATUS result;
	} wb;

	struct {
		struct lsa_LookupNames *l;
		struct lsa_LookupNames2 *l2;
		struct lsa_LookupNames3 *l3;
		struct lsa_LookupNames4 *l4;
	} _r;
};

static NTSTATUS dcesrv_lsa_LookupNames_base_finish(
	struct dcesrv_lsa_LookupNames_base_state *state);
static void dcesrv_lsa_LookupNames_base_map(
	struct dcesrv_lsa_LookupNames_base_state *state);
static void dcesrv_lsa_LookupNames_base_done(struct tevent_req *subreq);

static NTSTATUS dcesrv_lsa_LookupNames_base_call(struct dcesrv_lsa_LookupNames_base_state *state)
{
	struct lsa_LookupNames4 *r = &state->r;
	enum lsa_LookupOptions invalid_lookup_options = 0;
	struct tevent_req *subreq = NULL;
	uint32_t v;
	uint32_t i;

	*r->out.domains = NULL;
	r->out.sids->count = 0;
	r->out.sids->sids = NULL;
	*r->out.count = 0;

	if (r->in.level != LSA_LOOKUP_NAMES_ALL) {
		invalid_lookup_options |=
			LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES_LOCAL;
	}
	if (r->in.lookup_options & invalid_lookup_options) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	state->view_table = dcesrv_lsa_view_table(r->in.level);
	if (state->view_table == NULL) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	*r->out.domains = talloc_zero(r->out.domains, struct lsa_RefDomainList);
	if (*r->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.sids->sids = talloc_zero_array(r->out.sids,
					      struct lsa_TranslatedSid3,
					      r->in.num_names);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->items = talloc_zero_array(state,
					 struct dcesrv_lsa_TranslatedItem,
					 r->in.num_names);
	if (state->items == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<r->in.num_names;i++) {
		struct dcesrv_lsa_TranslatedItem *item = &state->items[i];
		char *p = NULL;

		item->type = SID_NAME_UNKNOWN;
		item->name = r->in.names[i].string;
		/*
		 * Note: that item->name can be NULL!
		 *
		 * See test_LookupNames_NULL() in
		 * source4/torture/rpc/lsa.c
		 *
		 * nt4 returns NT_STATUS_NONE_MAPPED with sid_type
		 * SID_NAME_UNKNOWN, rid 0, and sid_index -1;
		 *
		 * w2k3/w2k8 return NT_STATUS_OK with sid_type
		 * SID_NAME_DOMAIN, rid -1 and sid_index 0 and BUILTIN domain
		 */
		if (item->name == NULL) {
			continue;
		}

		item->hints.principal = item->name;
		p = strchr(item->name, '\\');
		if (p != NULL && p != item->name) {
			item->hints.domain = talloc_strndup(state->items,
							    item->name,
							    p - item->name);
			if (item->hints.domain == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			item->hints.namespace = item->hints.domain;
			p++;
			if (p[0] == '\0') {
				/*
				 * This is just 'BUILTIN\'.
				 */
				item->hints.principal = NULL;
			} else {
				item->hints.principal = p;
			}
		}
		if (item->hints.domain == NULL) {
			p = strchr(item->name, '@');
			if (p != NULL && p != item->name && p[1] != '\0') {
				item->hints.namespace = p + 1;
			}
		}
	}

	for (v=0; v < state->view_table->count; v++) {
		const struct dcesrv_lsa_Lookup_view *view =
			state->view_table->array[v];

		for (i=0; i < r->in.num_names; i++) {
			struct dcesrv_lsa_TranslatedItem *item = &state->items[i];
			NTSTATUS status;

			if (item->done) {
				continue;
			}

			status = view->lookup_name(state, item);
			if (NT_STATUS_IS_OK(status)) {
				item->done = true;
			} else if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
				status = NT_STATUS_OK;
			} else if (NT_STATUS_EQUAL(status, NT_STATUS_SOME_NOT_MAPPED)) {
				status = NT_STATUS_OK;
			}
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}
	}

	if (state->wb.irpc_handle == NULL) {
		return dcesrv_lsa_LookupNames_base_finish(state);
	}

	state->wb.names = talloc_zero_array(state, struct lsa_String,
					    r->in.num_names);
	if (state->wb.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<r->in.num_names;i++) {
		struct dcesrv_lsa_TranslatedItem *item = &state->items[i];

		if (item->done) {
			continue;
		}

		item->wb_idx = state->wb.num_names;
		state->wb.names[item->wb_idx] = r->in.names[i];
		state->wb.num_names++;
	}

	subreq = dcerpc_lsa_LookupNames4_send(state,
					      state->dce_call->event_ctx,
					      state->wb.irpc_handle,
					      state->wb.num_names,
					      state->wb.names,
					      &state->wb.domains,
					      &state->wb.sids,
					      state->r.in.level,
					      &state->wb.count,
					      state->r.in.lookup_options,
					      state->r.in.client_revision);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->dce_call->state_flags |= DCESRV_CALL_STATE_FLAG_ASYNC;
	tevent_req_set_callback(subreq,
				dcesrv_lsa_LookupNames_base_done,
				state);

	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_lsa_LookupNames_base_finish(
	struct dcesrv_lsa_LookupNames_base_state *state)
{
	struct lsa_LookupNames4 *r = &state->r;
	uint32_t i;

	for (i=0;i<r->in.num_names;i++) {
		struct dcesrv_lsa_TranslatedItem *item = &state->items[i];
		NTSTATUS status;
		uint32_t sid_index = UINT32_MAX;

		status = dcesrv_lsa_authority_list(item->authority_name,
						   item->authority_sid,
						   *r->out.domains,
						   &sid_index);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		r->out.sids->sids[i].sid_type  = item->type;
		r->out.sids->sids[i].sid       = discard_const_p(struct dom_sid,
								 item->sid);
		r->out.sids->sids[i].sid_index = sid_index;
		r->out.sids->sids[i].flags     = item->flags;

		r->out.sids->count++;
		if (item->type != SID_NAME_UNKNOWN) {
			(*r->out.count)++;
		}
	}

	if (*r->out.count == 0) {
		return NT_STATUS_NONE_MAPPED;
	}
	if (*r->out.count != r->in.num_names) {
		return STATUS_SOME_UNMAPPED;
	}

	return NT_STATUS_OK;
}

static void dcesrv_lsa_LookupNames_base_map(
	struct dcesrv_lsa_LookupNames_base_state *state)
{
	if (state->_r.l4 != NULL) {
		struct lsa_LookupNames4 *r = state->_r.l4;

		r->out.result = state->r.out.result;
		return;
	}

	if (state->_r.l3 != NULL) {
		struct lsa_LookupNames3 *r = state->_r.l3;

		r->out.result = state->r.out.result;
		return;
	}

	if (state->_r.l2 != NULL) {
		struct lsa_LookupNames2 *r = state->_r.l2;
		uint32_t i;

		r->out.result = state->r.out.result;

		SMB_ASSERT(state->r.out.sids->count <= r->in.num_names);
		for (i = 0; i < state->r.out.sids->count; i++) {
			const struct lsa_TranslatedSid3 *s3 =
				&state->r.out.sids->sids[i];
			struct lsa_TranslatedSid2 *s2 =
				&r->out.sids->sids[i];

			s2->sid_type = s3->sid_type;
			if (s3->sid_type == SID_NAME_DOMAIN) {
				s2->rid = UINT32_MAX;
			} else if (s3->flags & 0x00000004) {
				s2->rid = UINT32_MAX;
			} else if (s3->sid == NULL) {
				/*
				 * MS-LSAT 3.1.4.7 - rid zero is considered
				 * equivalent to sid NULL - so we should return
				 * 0 rid for unmapped entries
				 */
				s2->rid = 0;
			} else {
				s2->rid = 0;
				dom_sid_split_rid(NULL, s3->sid,
						  NULL, &s2->rid);
			}
			s2->sid_index = s3->sid_index;
			s2->unknown = s3->flags;
		}
		r->out.sids->count = state->r.out.sids->count;
		return;
	}

	if (state->_r.l != NULL) {
		struct lsa_LookupNames *r = state->_r.l;
		uint32_t i;

		r->out.result = state->r.out.result;

		SMB_ASSERT(state->r.out.sids->count <= r->in.num_names);
		for (i = 0; i < state->r.out.sids->count; i++) {
			struct lsa_TranslatedSid3 *s3 =
				&state->r.out.sids->sids[i];
			struct lsa_TranslatedSid *s =
				&r->out.sids->sids[i];

			s->sid_type = s3->sid_type;
			if (s3->sid_type == SID_NAME_DOMAIN) {
				s->rid = UINT32_MAX;
			} else if (s3->flags & 0x00000004) {
				s->rid = UINT32_MAX;
			} else if (s3->sid == NULL) {
				/*
				 * MS-LSAT 3.1.4.7 - rid zero is considered
				 * equivalent to sid NULL - so we should return
				 * 0 rid for unmapped entries
				 */
				s->rid = 0;
			} else {
				s->rid = 0;
				dom_sid_split_rid(NULL, s3->sid,
						  NULL, &s->rid);
			}
			s->sid_index = s3->sid_index;
		}
		r->out.sids->count = state->r.out.sids->count;
		return;
	}
}

static void dcesrv_lsa_LookupNames_base_done(struct tevent_req *subreq)
{
	struct dcesrv_lsa_LookupNames_base_state *state =
		tevent_req_callback_data(subreq,
		struct dcesrv_lsa_LookupNames_base_state);
	struct dcesrv_call_state *dce_call = state->dce_call;
	NTSTATUS status;
	uint32_t i;

	status = dcerpc_lsa_LookupNames4_recv(subreq, state->mem_ctx,
					      &state->wb.result);
	TALLOC_FREE(subreq);
	TALLOC_FREE(state->wb.irpc_handle);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		DEBUG(0,(__location__ ": IRPC callback failed %s\n",
			 nt_errstr(status)));
		goto finished;
	} else if (!NT_STATUS_IS_OK(status)) {
		state->dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
		DEBUG(0,(__location__ ": IRPC callback failed %s\n",
			 nt_errstr(status)));
		goto finished;
	}

	status = state->wb.result;
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		status = NT_STATUS_OK;
	} else if (NT_STATUS_EQUAL(status, NT_STATUS_SOME_NOT_MAPPED)) {
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		goto finished;
	}

	for (i=0; i < state->r.in.num_names;i++) {
		struct dcesrv_lsa_TranslatedItem *item = &state->items[i];
		struct lsa_TranslatedSid3 *s3 = NULL;
		struct lsa_DomainInfo *d = NULL;

		if (item->done) {
			continue;
		}

		if (item->wb_idx >= state->wb.sids.count) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto finished;
		}

		s3 = &state->wb.sids.sids[item->wb_idx];

		item->type = s3->sid_type;
		item->sid = s3->sid;
		item->flags = s3->flags;

		if (s3->sid_index == UINT32_MAX) {
			continue;
		}

		if (state->wb.domains == NULL) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto finished;
		}

		if (s3->sid_index >= state->wb.domains->count) {
			status = NT_STATUS_INTERNAL_ERROR;
			goto finished;
		}

		d = &state->wb.domains->domains[s3->sid_index];

		item->authority_name = d->name.string;
		item->authority_sid = d->sid;
	}

	status = dcesrv_lsa_LookupNames_base_finish(state);
 finished:
	state->r.out.result = status;
	dcesrv_lsa_LookupNames_base_map(state);

	status = dcesrv_reply(dce_call);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,(__location__ ": dcesrv_reply() failed - %s\n", nt_errstr(status)));
	}
}

/*
  lsa_LookupNames3
*/
NTSTATUS dcesrv_lsa_LookupNames3(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx,
				 struct lsa_LookupNames3 *r)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	struct dcesrv_lsa_LookupNames_base_state *state = NULL;
	struct dcesrv_handle *policy_handle = NULL;
	NTSTATUS status;

	if (transport != NCACN_NP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	*r->out.domains = NULL;
	r->out.sids->count = 0;
	r->out.sids->sids = NULL;
	*r->out.count = 0;

	state = talloc_zero(mem_ctx, struct dcesrv_lsa_LookupNames_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->policy_state = policy_handle->data;

	state->r.in.num_names = r->in.num_names;
	state->r.in.names = r->in.names;
	state->r.in.level = r->in.level;
	state->r.in.lookup_options = r->in.lookup_options;
	state->r.in.client_revision = r->in.client_revision;
	state->r.in.sids = r->in.sids;
	state->r.in.count = r->in.count;
	state->r.out.domains = r->out.domains;
	state->r.out.sids = r->out.sids;
	state->r.out.count = r->out.count;

	state->_r.l3 = r;

	status = dcesrv_lsa_LookupNames_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return status;
	}

	state->r.out.result = status;
	dcesrv_lsa_LookupNames_base_map(state);
	return status;
}

/* 
  lsa_LookupNames4

  Identical to LookupNames3, but doesn't take a policy handle
  
*/
NTSTATUS dcesrv_lsa_LookupNames4(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct lsa_LookupNames4 *r)
{
	struct dcesrv_lsa_LookupNames_base_state *state = NULL;
	NTSTATUS status;

	*r->out.domains = NULL;
	r->out.sids->count = 0;
	r->out.sids->sids = NULL;
	*r->out.count = 0;

	state = talloc_zero(mem_ctx, struct dcesrv_lsa_LookupNames_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	/*
	 * We don't have a policy handle on this call, so we want to
	 * make a policy state and cache it for the life of the
	 * connection, to avoid re-opening the DB each call.
	 *
	 * This also enforces that this is only available over
	 * ncacn_ip_tcp and with SCHANNEL.
	 *
	 * schannel_call_setup may also set the fault state.
	 *
	 * state->policy_state is shared between all calls on this
	 * connection and is moved with talloc_steal() under the
	 * connection, not dce_call or state.
	 */
	status = schannel_call_setup(dce_call, &state->policy_state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	state->r.in.num_names = r->in.num_names;
	state->r.in.names = r->in.names;
	state->r.in.level = r->in.level;
	state->r.in.lookup_options = r->in.lookup_options;
	state->r.in.client_revision = r->in.client_revision;
	state->r.in.sids = r->in.sids;
	state->r.in.count = r->in.count;
	state->r.out.domains = r->out.domains;
	state->r.out.sids = r->out.sids;
	state->r.out.count = r->out.count;

	state->_r.l4 = r;

	status = dcesrv_lsa_LookupNames_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return status;
	}

	state->r.out.result = status;
	dcesrv_lsa_LookupNames_base_map(state);
	return status;
}

/*
  lsa_LookupNames2
*/
NTSTATUS dcesrv_lsa_LookupNames2(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx,
				 struct lsa_LookupNames2 *r)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	struct dcesrv_lsa_LookupNames_base_state *state = NULL;
	struct dcesrv_handle *policy_handle = NULL;
	NTSTATUS status;

	if (transport != NCACN_NP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	*r->out.domains = NULL;
	r->out.sids->count = 0;
	r->out.sids->sids = NULL;
	*r->out.count = 0;

	r->out.sids->sids = talloc_zero_array(r->out.sids,
					      struct lsa_TranslatedSid2,
					      r->in.num_names);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_zero(mem_ctx, struct dcesrv_lsa_LookupNames_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->policy_state = policy_handle->data;

	state->r.in.num_names = r->in.num_names;
	state->r.in.names = r->in.names;
	state->r.in.level = r->in.level;
	/*
	 * MS-LSAT 3.1.4.7:
	 *
	 * The LookupOptions and ClientRevision parameters MUST be ignored.
	 * Message processing MUST happen as if LookupOptions is set to
	 * 0x00000000 and ClientRevision is set to 0x00000002.
	 */
	state->r.in.lookup_options = LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES;
	state->r.in.client_revision = LSA_CLIENT_REVISION_2;
	state->r.in.sids = talloc_zero(state, struct lsa_TransSidArray3);
	if (state->r.in.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->r.in.count = r->in.count;
	state->r.out.domains = r->out.domains;
	state->r.out.sids = talloc_zero(state, struct lsa_TransSidArray3);
	if (state->r.out.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->r.out.count = r->out.count;

	state->_r.l2 = r;

	status = dcesrv_lsa_LookupNames_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return status;
	}

	state->r.out.result = status;
	dcesrv_lsa_LookupNames_base_map(state);
	return status;
}

/* 
  lsa_LookupNames 
*/
NTSTATUS dcesrv_lsa_LookupNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LookupNames *r)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	struct dcesrv_lsa_LookupNames_base_state *state = NULL;
	struct dcesrv_handle *policy_handle = NULL;
	NTSTATUS status;

	if (transport != NCACN_NP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	*r->out.domains = NULL;
	r->out.sids->count = 0;
	r->out.sids->sids = NULL;
	*r->out.count = 0;

	r->out.sids->sids = talloc_zero_array(r->out.sids,
					      struct lsa_TranslatedSid,
					      r->in.num_names);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_zero(mem_ctx, struct dcesrv_lsa_LookupNames_base_state);
	if (state == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->dce_call = dce_call;
	state->mem_ctx = mem_ctx;

	state->policy_state = policy_handle->data;

	state->r.in.num_names = r->in.num_names;
	state->r.in.names = r->in.names;
	state->r.in.level = r->in.level;
	state->r.in.lookup_options = LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES;
	state->r.in.client_revision = LSA_CLIENT_REVISION_1;
	state->r.in.sids = talloc_zero(state, struct lsa_TransSidArray3);
	if (state->r.in.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->r.in.count = r->in.count;
	state->r.out.domains = r->out.domains;
	state->r.out.sids = talloc_zero(state, struct lsa_TransSidArray3);
	if (state->r.out.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->r.out.count = r->out.count;

	state->_r.l = r;

	status = dcesrv_lsa_LookupNames_base_call(state);

	if (dce_call->state_flags & DCESRV_CALL_STATE_FLAG_ASYNC) {
		return status;
	}

	state->r.out.result = status;
	dcesrv_lsa_LookupNames_base_map(state);
	return status;
}

static NTSTATUS dcesrv_lsa_lookup_name_predefined(
		struct dcesrv_lsa_LookupNames_base_state *state,
		struct dcesrv_lsa_TranslatedItem *item)
{
	NTSTATUS status;

	status = dom_sid_lookup_predefined_name(item->name,
						&item->sid,
						&item->type,
						&item->authority_sid,
						&item->authority_name);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		return status;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_lsa_lookup_sid_predefined(
		struct dcesrv_lsa_LookupSids_base_state *state,
		struct dcesrv_lsa_TranslatedItem *item)
{
	NTSTATUS status;

	status = dom_sid_lookup_predefined_sid(item->sid,
					       &item->name,
					       &item->type,
					       &item->authority_sid,
					       &item->authority_name);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		return status;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

static const struct dcesrv_lsa_Lookup_view view_predefined = {
	.name = "Predefined",
	.lookup_sid = dcesrv_lsa_lookup_sid_predefined,
	.lookup_name = dcesrv_lsa_lookup_name_predefined,
};

static NTSTATUS dcesrv_lsa_lookup_name_builtin(
		struct dcesrv_lsa_LookupNames_base_state *state,
		struct dcesrv_lsa_TranslatedItem *item)
{
	struct lsa_policy_state *policy_state = state->policy_state;
	NTSTATUS status;
	bool is_builtin = false;

	if (item->name == NULL) {
		/*
		 * This should not be mapped.
		 */
		return NT_STATUS_OK;
	}

	/*
	 * The predefined view already handled the BUILTIN domain.
	 *
	 * Now we just need to find the principal.
	 *
	 * We only allow 'BUILTIN\something' and
	 * not 'something@BUILTIN.
	 *
	 * And we try out best for just 'something'.
	 */
	is_builtin = strequal(item->hints.domain, NAME_BUILTIN);
	if (!is_builtin && item->hints.domain != NULL) {
		return NT_STATUS_NONE_MAPPED;
	}

	status = dcesrv_lsa_lookup_name(state->policy_state,
					state->mem_ctx,
					NAME_BUILTIN,
					policy_state->builtin_sid,
					policy_state->builtin_dn,
					item->hints.principal,
					&item->sid,
					&item->type);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		if (!is_builtin) {
			return NT_STATUS_NONE_MAPPED;
		}
		/*
		 * We know we're authoritative
		 */
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	item->authority_name = NAME_BUILTIN;
	item->authority_sid = policy_state->builtin_sid;
	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_lsa_lookup_sid_builtin(
		struct dcesrv_lsa_LookupSids_base_state *state,
		struct dcesrv_lsa_TranslatedItem *item)
{
	struct lsa_policy_state *policy_state = state->policy_state;
	NTSTATUS status;
	bool is_builtin = false;

	/*
	 * The predefined view already handled the BUILTIN domain.
	 *
	 * Now we just need to find the principal.
	 */
	is_builtin = dom_sid_in_domain(policy_state->builtin_sid, item->sid);
	if (!is_builtin) {
		return NT_STATUS_NONE_MAPPED;
	}

	status = dcesrv_lsa_lookup_sid(state->policy_state,
				       state->mem_ctx,
				       NAME_BUILTIN,
				       policy_state->builtin_sid,
				       policy_state->builtin_dn,
				       item->sid,
				       &item->name,
				       &item->type);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		/*
		 * We know we're authoritative
		 */
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	item->authority_name = NAME_BUILTIN;
	item->authority_sid = policy_state->builtin_sid;
	return NT_STATUS_OK;
}

static const struct dcesrv_lsa_Lookup_view view_builtin = {
	.name = "Builtin",
	.lookup_sid = dcesrv_lsa_lookup_sid_builtin,
	.lookup_name = dcesrv_lsa_lookup_name_builtin,
};

static NTSTATUS dcesrv_lsa_lookup_name_account(
		struct dcesrv_lsa_LookupNames_base_state *state,
		struct dcesrv_lsa_TranslatedItem *item)
{
	struct lsa_policy_state *policy_state = state->policy_state;
	struct loadparm_context *lp_ctx = state->dce_call->conn->dce_ctx->lp_ctx;
	struct lsa_LookupNames4 *r = &state->r;
	NTSTATUS status;
	int role;
	bool (*is_local_match_fn)(struct loadparm_context *, const char *) = NULL;
	bool is_domain = false;
	bool try_lookup = false;
	const char *check_domain_name = NULL;

	role = lpcfg_server_role(lp_ctx);
	if (role == ROLE_ACTIVE_DIRECTORY_DC) {
		is_local_match_fn = lpcfg_is_my_domain_or_realm;
	} else {
		is_local_match_fn = lpcfg_is_myname;
	}

	if (item->name == NULL) {
		/*
		 * This should not be mapped.
		 */
		return NT_STATUS_OK;
	}

	if (item->hints.domain != NULL && item->hints.principal == NULL) {
		/*
		 * This is 'DOMAIN\'.
		 */
		check_domain_name = item->hints.domain;
	} else {
		/*
		 * This is just 'DOMAIN'.
		 */
		check_domain_name = item->name;
	}
	is_domain = is_local_match_fn(lp_ctx, check_domain_name);
	if (is_domain) {
		item->type = SID_NAME_DOMAIN;
		item->sid = policy_state->domain_sid;
		item->authority_name = policy_state->domain_name;
		item->authority_sid = policy_state->domain_sid;
		return NT_STATUS_OK;
	}

	if (r->in.lookup_options & LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES_LOCAL) {
		if (item->hints.domain != item->hints.namespace) {
			/*
			 * This means the client asked for an UPN,
			 * and it should not be mapped.
			 */
			return NT_STATUS_OK;
		}
	}

	if (item->hints.namespace != NULL) {
		is_domain = is_local_match_fn(lp_ctx, item->hints.namespace);
		try_lookup = is_domain;
	} else {
		try_lookup = true;
	}

	if (!try_lookup) {
		struct dcesrv_lsa_TranslatedItem tmp;

		tmp = *item;
		status = dom_sid_lookup_predefined_name(item->hints.namespace,
							&tmp.sid,
							&tmp.type,
							&tmp.authority_sid,
							&tmp.authority_name);
		if (NT_STATUS_IS_OK(status)) {
			/*
			 * It should not be handled by us.
			 */
			return NT_STATUS_NONE_MAPPED;
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
			return status;
		}
	}

	if (!try_lookup) {
		const struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
		const struct lsa_ForestTrustDomainInfo *di = NULL;

		if (state->routing_table == NULL) {
			status = dsdb_trust_routing_table_load(policy_state->sam_ldb,
							       state,
							       &state->routing_table);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}

		tdo = dsdb_trust_domain_by_name(state->routing_table,
						item->hints.namespace,
						&di);
		if (tdo == NULL) {
			/*
			 * The name is not resolvable at all...
			 */
			return NT_STATUS_OK;
		}

		if (!(tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST)) {
			/*
			 * The name is not resolvable here
			 */
			return NT_STATUS_NONE_MAPPED;
		}

		/*
		 * TODO: handle multiple domains in a forest together with
		 * LSA_LOOKUP_NAMES_PRIMARY_DOMAIN_ONLY
		 */
		is_domain = true;
		try_lookup = true;
	}

	if (!try_lookup) {
		/*
		 * It should not be handled by us.
		 */
		return NT_STATUS_NONE_MAPPED;
	}

	/*
	 * TODO: handle multiple domains in our forest.
	 */

	status = dcesrv_lsa_lookup_name(state->policy_state,
					state->mem_ctx,
					policy_state->domain_name,
					policy_state->domain_sid,
					policy_state->domain_dn,
					item->hints.principal,
					&item->sid,
					&item->type);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		if (!is_domain) {
			return NT_STATUS_NONE_MAPPED;
		}
		/*
		 * We know we're authoritative
		 */
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	item->authority_name = policy_state->domain_name;
	item->authority_sid = policy_state->domain_sid;
	return NT_STATUS_OK;
}

static NTSTATUS dcesrv_lsa_lookup_sid_account(
		struct dcesrv_lsa_LookupSids_base_state *state,
		struct dcesrv_lsa_TranslatedItem *item)
{
	struct lsa_policy_state *policy_state = state->policy_state;
	NTSTATUS status;
	bool is_domain;

	is_domain = dom_sid_equal(policy_state->domain_sid, item->sid);
	if (is_domain) {
		item->type = SID_NAME_DOMAIN;
		item->name = policy_state->domain_name;
		item->authority_name = policy_state->domain_name;
		item->authority_sid = policy_state->domain_sid;
		return NT_STATUS_OK;
	}
	is_domain = dom_sid_in_domain(policy_state->domain_sid, item->sid);
	if (!is_domain) {
		return NT_STATUS_NONE_MAPPED;
	}

	status = dcesrv_lsa_lookup_sid(state->policy_state,
				       state->mem_ctx,
				       policy_state->domain_name,
				       policy_state->domain_sid,
				       policy_state->domain_dn,
				       item->sid,
				       &item->name,
				       &item->type);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		/*
		 * We know we're authoritative
		 */
		status = NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	item->authority_name = policy_state->domain_name;
	item->authority_sid = policy_state->domain_sid;
	return NT_STATUS_OK;
}

static const struct dcesrv_lsa_Lookup_view view_account = {
	.name = "Account",
	.lookup_sid = dcesrv_lsa_lookup_sid_account,
	.lookup_name = dcesrv_lsa_lookup_name_account,
};

static NTSTATUS dcesrv_lsa_lookup_name_winbind(
		struct dcesrv_lsa_LookupNames_base_state *state,
		struct dcesrv_lsa_TranslatedItem *item)
{
	struct lsa_LookupNames4 *r = &state->r;
	const struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	const struct lsa_ForestTrustDomainInfo *di = NULL;
	NTSTATUS status;
	const char *check_domain_name = NULL;
	bool expect_domain = false;
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(state->dce_call->conn);

	if (item->name == NULL) {
		/*
		 * This should not be mapped.
		 */
		return NT_STATUS_OK;
	}

	if (item->hints.domain != NULL && item->hints.principal == NULL) {
		/*
		 * This is 'DOMAIN\'.
		 */
		check_domain_name = item->hints.domain;
		expect_domain = true;
	} else if (item->hints.namespace != NULL) {
		/*
		 * This is 'DOMAIN\someone'
		 * or 'someone@DOMAIN'
		 */
		check_domain_name = item->hints.namespace;
	} else {
		/*
		 * This is just 'DOMAIN'.
		 */
		check_domain_name = item->name;
		expect_domain = true;
	}

	if (state->routing_table == NULL) {
		struct lsa_policy_state *policy_state = state->policy_state;

		status = dsdb_trust_routing_table_load(policy_state->sam_ldb,
						       state,
						       &state->routing_table);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	tdo = dsdb_trust_domain_by_name(state->routing_table,
					check_domain_name,
					&di);
	if (tdo == NULL) {
		/*
		 * The name is not resolvable at all...
		 *
		 * And for now we don't send unqualified names
		 * to winbindd, as we don't handle them
		 * there yet.
		 *
		 * TODO: how should that work within
		 * winbindd?
		 */
		return NT_STATUS_OK;
	}

	if (tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
		/*
		 * The name should have been resolved in the account view.
		 *
		 * TODO: handle multiple domains in a forest...
		 */
		return NT_STATUS_OK;
	}

	if (expect_domain) {
		const char *name = NULL;
		const struct dom_sid *sid = NULL;

		name = talloc_strdup(state->mem_ctx,
				     di->netbios_domain_name.string);
		if (name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		sid = dom_sid_dup(state->mem_ctx,
				  di->domain_sid);
		if (sid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		item->type = SID_NAME_DOMAIN;
		item->sid = sid;
		item->authority_name = name;
		item->authority_sid = sid;
		return NT_STATUS_OK;
	}

	if (r->in.lookup_options & LSA_LOOKUP_OPTION_SEARCH_ISOLATED_NAMES_LOCAL) {
		if (item->hints.namespace == NULL) {
			/*
			 * We should not try to resolve isolated names
			 * remotely.
			 */
			return NT_STATUS_OK;
		}
	}

	/*
	 * We know at least the domain part of the name exists.
	 *
	 * For now the rest handled within winbindd.
	 *
	 * In future we can optimize it based on
	 * r->in.level.
	 *
	 * We can also try to resolve SID_NAME_DOMAIN
	 * just based on the routing table.
	 */

	if (state->wb.irpc_handle != NULL) {
		/*
		 * already called...
		 */
		return NT_STATUS_NONE_MAPPED;
	}

	state->wb.irpc_handle = irpc_binding_handle_by_name(state,
							    imsg_ctx,
							    "winbind_server",
							    &ndr_table_lsarpc);
	if (state->wb.irpc_handle == NULL) {
		DEBUG(0,("Failed to get binding_handle for winbind_server task\n"));
		state->dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/*
	 * 60 seconds timeout should be enough
	 */
	dcerpc_binding_handle_set_timeout(state->wb.irpc_handle, 60);

	return NT_STATUS_NONE_MAPPED;
}

static NTSTATUS dcesrv_lsa_lookup_sid_winbind(
		struct dcesrv_lsa_LookupSids_base_state *state,
		struct dcesrv_lsa_TranslatedItem *item)
{
	const struct lsa_TrustDomainInfoInfoEx *tdo = NULL;
	const struct lsa_ForestTrustDomainInfo *di = NULL;
	struct dcesrv_lsa_TranslatedItem tmp;
	struct dom_sid domain_sid = {0,};
	NTSTATUS status;
	bool match;
	struct imessaging_context *imsg_ctx =
		dcesrv_imessaging_context(state->dce_call->conn);

	/*
	 * Verify the sid is not INVALID.
	 */
	tmp = *item;
	status = dom_sid_lookup_predefined_sid(tmp.sid,
					       &tmp.name,
					       &tmp.type,
					       &tmp.authority_sid,
					       &tmp.authority_name);
	if (NT_STATUS_IS_OK(status)) {
		status = NT_STATUS_NONE_MAPPED;
	}
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NONE_MAPPED)) {
		/*
		 * Typically INVALID_SID
		 */
		return status;
	}

	if (state->routing_table == NULL) {
		struct lsa_policy_state *policy_state = state->policy_state;

		status = dsdb_trust_routing_table_load(policy_state->sam_ldb,
						       state,
						       &state->routing_table);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	domain_sid = *item->sid;
	if (domain_sid.num_auths == 5) {
		sid_split_rid(&domain_sid, NULL);
	}

	tdo = dsdb_trust_domain_by_sid(state->routing_table,
				       &domain_sid, &di);
	if (tdo == NULL) {
		/*
		 * The sid is not resolvable at all...
		 */
		return NT_STATUS_OK;
	}

	if (tdo->trust_attributes & LSA_TRUST_ATTRIBUTE_WITHIN_FOREST) {
		/*
		 * The name should have been resolved in the account view.
		 *
		 * TODO: handle multiple domains in a forest...
		 */
		return NT_STATUS_OK;
	}

	match = dom_sid_equal(di->domain_sid, item->sid);
	if (match) {
		const char *name = NULL;

		name = talloc_strdup(state->mem_ctx,
				     di->netbios_domain_name.string);
		if (name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		item->type = SID_NAME_DOMAIN;
		item->name = name;
		item->authority_name = name;
		item->authority_sid = item->sid;
		return NT_STATUS_OK;
	}

	/*
	 * We know at least the domain part of the sid exists.
	 *
	 * For now the rest handled within winbindd.
	 *
	 * In future we can optimize it based on
	 * r->in.level.
	 *
	 * We can also try to resolve SID_NAME_DOMAIN
	 * just based on the routing table.
	 */
	if (state->wb.irpc_handle != NULL) {
		/*
		 * already called...
		 */
		return NT_STATUS_NONE_MAPPED;
	}

	state->wb.irpc_handle = irpc_binding_handle_by_name(state,
							    imsg_ctx,
							    "winbind_server",
							    &ndr_table_lsarpc);
	if (state->wb.irpc_handle == NULL) {
		DEBUG(0,("Failed to get binding_handle for winbind_server task\n"));
		state->dce_call->fault_code = DCERPC_FAULT_CANT_PERFORM;
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/*
	 * 60 seconds timeout should be enough
	 */
	dcerpc_binding_handle_set_timeout(state->wb.irpc_handle, 60);

	return NT_STATUS_NONE_MAPPED;
}

static const struct dcesrv_lsa_Lookup_view view_winbind = {
	.name = "Winbind",
	.lookup_sid = dcesrv_lsa_lookup_sid_winbind,
	.lookup_name = dcesrv_lsa_lookup_name_winbind,
};

static const struct dcesrv_lsa_Lookup_view *table_all_views[] = {
	&view_predefined,
	&view_builtin,
	&view_account,
	&view_winbind,
};

static const struct dcesrv_lsa_Lookup_view_table table_all = {
	.name = "LSA_LOOKUP_NAMES_ALL",
	.count = ARRAY_SIZE(table_all_views),
	.array = table_all_views,
};

static const struct dcesrv_lsa_Lookup_view *table_domains_views[] = {
	&view_account,
	&view_winbind,
};

static const struct dcesrv_lsa_Lookup_view_table table_domains = {
	.name = "LSA_LOOKUP_NAMES_DOMAINS_ONLY",
	.count = ARRAY_SIZE(table_domains_views),
	.array = table_domains_views,
};

static const struct dcesrv_lsa_Lookup_view *table_primary_views[] = {
	&view_account,
};

static const struct dcesrv_lsa_Lookup_view_table table_primary = {
	.name = "LSA_LOOKUP_NAMES_PRIMARY_DOMAIN_ONLY",
	.count = ARRAY_SIZE(table_primary_views),
	.array = table_primary_views,
};

static const struct dcesrv_lsa_Lookup_view *table_remote_views[] = {
	&view_winbind,
};

static const struct dcesrv_lsa_Lookup_view_table table_gc = {
	.name = "LSA_LOOKUP_NAMES_UPLEVEL_TRUSTS_ONLY",
	.count = ARRAY_SIZE(table_domains_views),
	.array = table_domains_views,
};

static const struct dcesrv_lsa_Lookup_view_table table_xreferral = {
	.name = "LSA_LOOKUP_NAMES_FOREST_TRUSTS_ONLY",
	.count = ARRAY_SIZE(table_remote_views),
	.array = table_remote_views,
};

static const struct dcesrv_lsa_Lookup_view_table table_xresolve = {
	.name = "LSA_LOOKUP_NAMES_UPLEVEL_TRUSTS_ONLY2",
	.count = ARRAY_SIZE(table_domains_views),
	.array = table_domains_views,
};

static const struct dcesrv_lsa_Lookup_view_table table_rodc = {
	.name = "LSA_LOOKUP_NAMES_RODC_REFERRAL_TO_FULL_DC",
	.count = ARRAY_SIZE(table_remote_views),
	.array = table_remote_views,
};

static const struct dcesrv_lsa_Lookup_view_table *dcesrv_lsa_view_table(
	enum lsa_LookupNamesLevel level)
{
	switch (level) {
	case LSA_LOOKUP_NAMES_ALL:
		return &table_all;
	case LSA_LOOKUP_NAMES_DOMAINS_ONLY:
		return &table_domains;
	case LSA_LOOKUP_NAMES_PRIMARY_DOMAIN_ONLY:
		return &table_primary;
	case LSA_LOOKUP_NAMES_UPLEVEL_TRUSTS_ONLY:
		return &table_gc;
	case LSA_LOOKUP_NAMES_FOREST_TRUSTS_ONLY:
		return &table_xreferral;
	case LSA_LOOKUP_NAMES_UPLEVEL_TRUSTS_ONLY2:
		return &table_xresolve;
	case LSA_LOOKUP_NAMES_RODC_REFERRAL_TO_FULL_DC:
		return &table_rodc;
	}

	return NULL;
}
