/*
 * Unix SMB/CIFS implementation.
 *
 * Winbind rpc backend functions
 *
 * Copyright (c) 2000-2003 Tim Potter
 * Copyright (c) 2001      Andrew Tridgell
 * Copyright (c) 2005      Volker Lendecke
 * Copyright (c) 2008      Guenther Deschner (pidl conversion)
 * Copyright (c) 2010      Andreas Schneider <asn@samba.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "winbindd.h"
#include "winbindd_rpc.h"
#include "lib/util_unixsids.h"
#include "rpc_client/rpc_client.h"
#include "rpc_client/cli_pipe.h"
#include "../librpc/gen_ndr/ndr_samr_c.h"
#include "rpc_client/cli_samr.h"
#include "../librpc/gen_ndr/ndr_lsa_c.h"
#include "rpc_client/cli_lsarpc.h"
#include "rpc_server/rpc_ncacn_np.h"
#include "../libcli/security/security.h"
#include "passdb/machine_sid.h"
#include "auth.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND

/*
 * The other end of this won't go away easily, so we can trust it
 *
 * It is either a long-lived process with the same lifetime as
 * winbindd or a part of this process
 */
struct winbind_internal_pipes {
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle samr_domain_hnd;
	struct rpc_pipe_client *lsa_pipe;
	struct policy_handle lsa_hnd;
};


NTSTATUS open_internal_samr_conn(TALLOC_CTX *mem_ctx,
				 struct winbindd_domain *domain,
				 struct rpc_pipe_client **samr_pipe,
				 struct policy_handle *samr_domain_hnd)
{
	NTSTATUS status, result;
	struct policy_handle samr_connect_hnd;
	struct dcerpc_binding_handle *b;

	status = wb_open_internal_pipe(mem_ctx, &ndr_table_samr, samr_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	b = (*samr_pipe)->binding_handle;

	status = dcerpc_samr_Connect2(b, mem_ctx,
				      (*samr_pipe)->desthost,
				      SEC_FLAG_MAXIMUM_ALLOWED,
				      &samr_connect_hnd,
				      &result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (!NT_STATUS_IS_OK(result)) {
		return result;
	}

	status = dcerpc_samr_OpenDomain(b, mem_ctx,
					&samr_connect_hnd,
					SEC_FLAG_MAXIMUM_ALLOWED,
					&domain->sid,
					samr_domain_hnd,
					&result);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return result;
}

NTSTATUS open_internal_lsa_conn(TALLOC_CTX *mem_ctx,
				struct rpc_pipe_client **lsa_pipe,
				struct policy_handle *lsa_hnd)
{
	NTSTATUS status;

	status = wb_open_internal_pipe(mem_ctx, &ndr_table_lsarpc, lsa_pipe);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = rpccli_lsa_open_policy((*lsa_pipe),
					mem_ctx,
					true,
					SEC_FLAG_MAXIMUM_ALLOWED,
					lsa_hnd);

	return status;
}


static NTSTATUS open_cached_internal_pipe_conn(
	struct winbindd_domain *domain,
	struct rpc_pipe_client **samr_pipe,
	struct policy_handle *samr_domain_hnd,
	struct rpc_pipe_client **lsa_pipe,
	struct policy_handle *lsa_hnd)
{
	struct winbind_internal_pipes *internal_pipes = NULL;

	if (domain->private_data == NULL) {
		TALLOC_CTX *frame = talloc_stackframe();
		NTSTATUS status;

		internal_pipes = talloc_zero(frame,
					     struct winbind_internal_pipes);

		status = open_internal_samr_conn(
			internal_pipes,
			domain,
			&internal_pipes->samr_pipe,
			&internal_pipes->samr_domain_hnd);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}

		status = open_internal_lsa_conn(internal_pipes,
						&internal_pipes->lsa_pipe,
						&internal_pipes->lsa_hnd);

		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}

		domain->private_data = talloc_move(domain, &internal_pipes);

		TALLOC_FREE(frame);

	}

	internal_pipes = talloc_get_type_abort(
		domain->private_data, struct winbind_internal_pipes);

	if (samr_domain_hnd) {
		*samr_domain_hnd = internal_pipes->samr_domain_hnd;
	}

	if (samr_pipe) {
		*samr_pipe = internal_pipes->samr_pipe;
	}

	if (lsa_hnd) {
		*lsa_hnd = internal_pipes->lsa_hnd;
	}

	if (lsa_pipe) {
		*lsa_pipe = internal_pipes->lsa_pipe;
	}

	return NT_STATUS_OK;
}

static bool reset_connection_on_error(struct winbindd_domain *domain,
				      struct rpc_pipe_client *p,
				      NTSTATUS status)
{
	struct winbind_internal_pipes *internal_pipes = NULL;

	internal_pipes = talloc_get_type_abort(
		domain->private_data, struct winbind_internal_pipes);

	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT) ||
	    NT_STATUS_EQUAL(status, NT_STATUS_IO_DEVICE_ERROR))
	{
		TALLOC_FREE(internal_pipes);
		domain->private_data = NULL;
		return true;
	}

	if (!rpccli_is_connected(p)) {
		TALLOC_FREE(internal_pipes);
		domain->private_data = NULL;
		return true;
	}

	return false;
}

/*********************************************************************
 SAM specific functions.
*********************************************************************/

/* List all domain groups */
static NTSTATUS sam_enum_dom_groups(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32_t *pnum_info,
				    struct wb_acct_info **pinfo)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol = { 0 };
	struct wb_acct_info *info = NULL;
	uint32_t num_info = 0;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("sam_enum_dom_groups\n"));

	if (pnum_info) {
		*pnum_info = 0;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						&samr_pipe,
						&dom_pol,
						NULL,
						NULL);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	status = rpc_enum_dom_groups(tmp_ctx,
				     samr_pipe,
				     &dom_pol,
				     &num_info,
				     &info);

	if (!retry && reset_connection_on_error(domain, samr_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tmp_ctx);
		return status;
	}

	if (pnum_info) {
		*pnum_info = num_info;
	}

	if (pinfo) {
		*pinfo = talloc_move(mem_ctx, &info);
	}

	TALLOC_FREE(tmp_ctx);
	return status;
}

/* Query display info for a domain */
static NTSTATUS sam_query_user_list(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    uint32_t **prids)
{
	struct rpc_pipe_client *samr_pipe = NULL;
	struct policy_handle dom_pol = { 0 };
	uint32_t *rids = NULL;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("samr_query_user_list\n"));

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						&samr_pipe,
						&dom_pol,
						NULL,
						NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_query_user_list(tmp_ctx,
				     samr_pipe,
				     &dom_pol,
				     &domain->sid,
				     &rids);
	if (!retry && reset_connection_on_error(domain, samr_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (prids != NULL) {
		*prids = talloc_move(mem_ctx, &rids);
	}

done:
	TALLOC_FREE(rids);
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* get a list of trusted domains - builtin domain */
static NTSTATUS sam_trusted_domains(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    struct netr_DomainTrustList *ptrust_list)
{
	struct rpc_pipe_client *lsa_pipe;
	struct policy_handle lsa_policy = { 0 };
	struct netr_DomainTrust *trusts = NULL;
	uint32_t num_trusts = 0;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("samr: trusted domains\n"));

	if (ptrust_list) {
		ZERO_STRUCTP(ptrust_list);
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						NULL,
						NULL,
						&lsa_pipe,
						&lsa_policy);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_trusted_domains(tmp_ctx,
				     lsa_pipe,
				     &lsa_policy,
				     &num_trusts,
				     &trusts);

	if (!retry && reset_connection_on_error(domain, lsa_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (ptrust_list) {
		ptrust_list->count = num_trusts;
		ptrust_list->array = talloc_move(mem_ctx, &trusts);
	}

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* Lookup group membership given a rid.   */
static NTSTATUS sam_lookup_groupmem(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    const struct dom_sid *group_sid,
				    enum lsa_SidType type,
				    uint32_t *pnum_names,
				    struct dom_sid **psid_mem,
				    char ***pnames,
				    uint32_t **pname_types)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol = { 0 };

	uint32_t num_names = 0;
	struct dom_sid *sid_mem = NULL;
	char **names = NULL;
	uint32_t *name_types = NULL;

	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("sam_lookup_groupmem\n"));

	/* Paranoia check */
	if (sid_check_is_in_builtin(group_sid) && (type != SID_NAME_ALIAS)) {
		/* There's no groups, only aliases in BUILTIN */
		return NT_STATUS_NO_SUCH_GROUP;
	}

	if (pnum_names) {
		*pnum_names = 0;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						&samr_pipe,
						&dom_pol,
						NULL,
						NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_lookup_groupmem(tmp_ctx,
				     samr_pipe,
				     &dom_pol,
				     domain->name,
				     &domain->sid,
				     group_sid,
				     type,
				     &num_names,
				     &sid_mem,
				     &names,
				     &name_types);

	if (!retry && reset_connection_on_error(domain, samr_pipe, status)) {
		retry = true;
		goto again;
	}

	if (pnum_names) {
		*pnum_names = num_names;
	}

	if (pnames) {
		*pnames = talloc_move(mem_ctx, &names);
	}

	if (pname_types) {
		*pname_types = talloc_move(mem_ctx, &name_types);
	}

	if (psid_mem) {
		*psid_mem = talloc_move(mem_ctx, &sid_mem);
	}

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/*********************************************************************
 BUILTIN specific functions.
*********************************************************************/

/* List all domain groups */
static NTSTATUS builtin_enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32_t *num_entries,
				struct wb_acct_info **info)
{
	/* BUILTIN doesn't have domain groups */
	*num_entries = 0;
	*info = NULL;
	return NT_STATUS_OK;
}

/* Query display info for a domain */
static NTSTATUS builtin_query_user_list(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32_t **rids)
{
	/* We don't have users */
	*rids = NULL;
	return NT_STATUS_OK;
}

/* get a list of trusted domains - builtin domain */
static NTSTATUS builtin_trusted_domains(struct winbindd_domain *domain,
					TALLOC_CTX *mem_ctx,
					struct netr_DomainTrustList *trusts)
{
	ZERO_STRUCTP(trusts);
	return NT_STATUS_OK;
}

/*********************************************************************
 COMMON functions.
*********************************************************************/

/* List all local groups (aliases) */
static NTSTATUS sam_enum_local_groups(struct winbindd_domain *domain,
				      TALLOC_CTX *mem_ctx,
				      uint32_t *pnum_info,
				      struct wb_acct_info **pinfo)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol = { 0 };
	struct wb_acct_info *info = NULL;
	uint32_t num_info = 0;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("samr: enum local groups\n"));

	if (pnum_info) {
		*pnum_info = 0;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						&samr_pipe,
						&dom_pol,
						NULL,
						NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_enum_local_groups(mem_ctx,
				       samr_pipe,
				       &dom_pol,
				       &num_info,

				       &info);
	if (!retry && reset_connection_on_error(domain, samr_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (pnum_info) {
		*pnum_info = num_info;
	}

	if (pinfo) {
		*pinfo = talloc_move(mem_ctx, &info);
	}

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* convert a single name to a sid in a domain */
static NTSTATUS sam_name_to_sid(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   const char *domain_name,
				   const char *name,
				   uint32_t flags,
				   const char **pdom_name,
				   struct dom_sid *psid,
				   enum lsa_SidType *ptype)
{
	struct rpc_pipe_client *lsa_pipe;
	struct policy_handle lsa_policy = { 0 };
	struct dom_sid sid;
	const char *dom_name;
	enum lsa_SidType type;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("sam_name_to_sid\n"));

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						NULL,
						NULL,
						&lsa_pipe,
						&lsa_policy);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_name_to_sid(tmp_ctx,
				 lsa_pipe,
				 &lsa_policy,
				 domain_name,
				 name,
				 flags,
				 &dom_name,
				 &sid,
				 &type);

	if (!retry && reset_connection_on_error(domain, lsa_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (pdom_name != NULL) {
		*pdom_name = talloc_strdup(mem_ctx, dom_name);
		if (*pdom_name == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto done;
		}
	}

	if (psid) {
		sid_copy(psid, &sid);
	}
	if (ptype) {
		*ptype = type;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* convert a domain SID to a user or group name */
static NTSTATUS sam_sid_to_name(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const struct dom_sid *sid,
				char **pdomain_name,
				char **pname,
				enum lsa_SidType *ptype)
{
	struct rpc_pipe_client *lsa_pipe;
	struct policy_handle lsa_policy = { 0 };
	char *domain_name = NULL;
	char *name = NULL;
	enum lsa_SidType type;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("sam_sid_to_name\n"));

	/* Paranoia check */
	if (!sid_check_is_in_builtin(sid) &&
	    !sid_check_is_builtin(sid) &&
	    !sid_check_is_in_our_sam(sid) &&
	    !sid_check_is_our_sam(sid) &&
	    !sid_check_is_in_unix_users(sid) &&
	    !sid_check_is_unix_users(sid) &&
	    !sid_check_is_in_unix_groups(sid) &&
	    !sid_check_is_unix_groups(sid) &&
	    !sid_check_is_in_wellknown_domain(sid)) {
		struct dom_sid_buf buf;
		DEBUG(0, ("sam_sid_to_name: possible deadlock - trying to "
			  "lookup SID %s\n",
			  dom_sid_str_buf(sid, &buf)));
		return NT_STATUS_NONE_MAPPED;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						NULL,
						NULL,
						&lsa_pipe,
						&lsa_policy);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_sid_to_name(tmp_ctx,
				 lsa_pipe,
				 &lsa_policy,
				 domain,
				 sid,
				 &domain_name,
				 &name,
				 &type);

	if (!retry && reset_connection_on_error(domain, lsa_pipe, status)) {
		retry = true;
		goto again;
	}

	if (ptype) {
		*ptype = type;
	}

	if (pname) {
		*pname = talloc_move(mem_ctx, &name);
	}

	if (pdomain_name) {
		*pdomain_name = talloc_move(mem_ctx, &domain_name);
	}

done:

	TALLOC_FREE(tmp_ctx);
	return status;
}

static NTSTATUS sam_rids_to_names(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const struct dom_sid *domain_sid,
				  uint32_t *rids,
				  size_t num_rids,
				  char **pdomain_name,
				  char ***pnames,
				  enum lsa_SidType **ptypes)
{
	struct rpc_pipe_client *lsa_pipe;
	struct policy_handle lsa_policy = { 0 };
	enum lsa_SidType *types = NULL;
	char *domain_name = NULL;
	char **names = NULL;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("sam_rids_to_names for %s\n", domain->name));

	/* Paranoia check */
	if (!sid_check_is_builtin(domain_sid) &&
	    !sid_check_is_our_sam(domain_sid) &&
	    !sid_check_is_unix_users(domain_sid) &&
	    !sid_check_is_unix_groups(domain_sid) &&
	    !sid_check_is_in_wellknown_domain(domain_sid)) {
		struct dom_sid_buf buf;
		DEBUG(0, ("sam_rids_to_names: possible deadlock - trying to "
			  "lookup SID %s\n",
			  dom_sid_str_buf(domain_sid, &buf)));
		return NT_STATUS_NONE_MAPPED;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						NULL,
						NULL,
						&lsa_pipe,
						&lsa_policy);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_rids_to_names(tmp_ctx,
				   lsa_pipe,
				   &lsa_policy,
				   domain,
				   domain_sid,
				   rids,
				   num_rids,
				   &domain_name,
				   &names,
				   &types);

	if (!retry && reset_connection_on_error(domain, lsa_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (pdomain_name) {
		*pdomain_name = talloc_move(mem_ctx, &domain_name);
	}

	if (ptypes) {
		*ptypes = talloc_move(mem_ctx, &types);
	}

	if (pnames) {
		*pnames = talloc_move(mem_ctx, &names);
	}

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

static NTSTATUS sam_lockout_policy(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   struct samr_DomInfo12 *lockout_policy)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol = { 0 };
	union samr_DomainInfo *info = NULL;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status, result;
	struct dcerpc_binding_handle *b = NULL;
	bool retry = false;

	DEBUG(3,("sam_lockout_policy\n"));

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						&samr_pipe,
						&dom_pol,
						NULL,
						NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	b = samr_pipe->binding_handle;

	status = dcerpc_samr_QueryDomainInfo(b,
					     mem_ctx,
					     &dom_pol,
					     DomainLockoutInformation,
					     &info,
					     &result);

	if (!retry && reset_connection_on_error(domain, samr_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto error;
	}

	*lockout_policy = info->info12;

error:
	TALLOC_FREE(tmp_ctx);
	return status;
}

static NTSTATUS sam_password_policy(struct winbindd_domain *domain,
				    TALLOC_CTX *mem_ctx,
				    struct samr_DomInfo1 *passwd_policy)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol = { 0 };
	union samr_DomainInfo *info = NULL;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status, result;
	struct dcerpc_binding_handle *b = NULL;
	bool retry = false;

	DEBUG(3,("sam_password_policy\n"));

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						&samr_pipe,
						&dom_pol,
						NULL,
						NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}

	b = samr_pipe->binding_handle;

	status = dcerpc_samr_QueryDomainInfo(b,
					     mem_ctx,
					     &dom_pol,
					     DomainPasswordInformation,
					     &info,
					     &result);

	if (!retry && reset_connection_on_error(domain, samr_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto error;
	}
	if (!NT_STATUS_IS_OK(result)) {
		status = result;
		goto error;
	}

	*passwd_policy = info->info1;

error:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* Lookup groups a user is a member of. */
static NTSTATUS sam_lookup_usergroups(struct winbindd_domain *domain,
				      TALLOC_CTX *mem_ctx,
				      const struct dom_sid *user_sid,
				      uint32_t *pnum_groups,
				      struct dom_sid **puser_grpsids)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol;
	struct dom_sid *user_grpsids = NULL;
	uint32_t num_groups = 0;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("sam_lookup_usergroups\n"));

	ZERO_STRUCT(dom_pol);

	if (pnum_groups) {
		*pnum_groups = 0;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						&samr_pipe,
						&dom_pol,
						NULL,
						NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_lookup_usergroups(tmp_ctx,
				       samr_pipe,
				       &dom_pol,
				       &domain->sid,
				       user_sid,
				       &num_groups,
				       &user_grpsids);

	if (!retry && reset_connection_on_error(domain, samr_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (pnum_groups) {
		*pnum_groups = num_groups;
	}

	if (puser_grpsids) {
		*puser_grpsids = talloc_move(mem_ctx, &user_grpsids);
	}

done:

	TALLOC_FREE(tmp_ctx);
	return status;
}

static NTSTATUS sam_lookup_useraliases(struct winbindd_domain *domain,
				       TALLOC_CTX *mem_ctx,
				       uint32_t num_sids,
				       const struct dom_sid *sids,
				       uint32_t *pnum_aliases,
				       uint32_t **palias_rids)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol = { 0 };
	uint32_t num_aliases = 0;
	uint32_t *alias_rids = NULL;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("sam_lookup_useraliases\n"));

	if (pnum_aliases) {
		*pnum_aliases = 0;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						&samr_pipe,
						&dom_pol,
						NULL,
						NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_lookup_useraliases(tmp_ctx,
					samr_pipe,
					&dom_pol,
					num_sids,
					sids,
					&num_aliases,
					&alias_rids);

	if (!retry && reset_connection_on_error(domain, samr_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (pnum_aliases) {
		*pnum_aliases = num_aliases;
	}

	if (palias_rids) {
		*palias_rids = talloc_move(mem_ctx, &alias_rids);
	}

done:

	TALLOC_FREE(tmp_ctx);
	return status;
}

/* find the sequence number for a domain */
static NTSTATUS sam_sequence_number(struct winbindd_domain *domain,
				    uint32_t *pseq)
{
	struct rpc_pipe_client *samr_pipe;
	struct policy_handle dom_pol = { 0 };
	uint32_t seq = DOM_SEQUENCE_NONE;
	TALLOC_CTX *tmp_ctx;
	NTSTATUS status;
	bool retry = false;

	DEBUG(3,("samr: sequence number\n"));

	if (pseq) {
		*pseq = DOM_SEQUENCE_NONE;
	}

	tmp_ctx = talloc_stackframe();
	if (tmp_ctx == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	status = open_cached_internal_pipe_conn(domain,
						&samr_pipe,
						&dom_pol,
						NULL,
						NULL);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = rpc_sequence_number(tmp_ctx,
				     samr_pipe,
				     &dom_pol,
				     domain->name,
				     &seq);

	if (!retry && reset_connection_on_error(domain, samr_pipe, status)) {
		retry = true;
		goto again;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (pseq) {
		*pseq = seq;
	}

done:
	TALLOC_FREE(tmp_ctx);
	return status;
}

/* the rpc backend methods are exposed via this structure */
struct winbindd_methods builtin_passdb_methods = {
	.consistent            = false,

	.query_user_list       = builtin_query_user_list,
	.enum_dom_groups       = builtin_enum_dom_groups,
	.enum_local_groups     = sam_enum_local_groups,
	.name_to_sid           = sam_name_to_sid,
	.sid_to_name           = sam_sid_to_name,
	.rids_to_names         = sam_rids_to_names,
	.lookup_usergroups     = sam_lookup_usergroups,
	.lookup_useraliases    = sam_lookup_useraliases,
	.lookup_groupmem       = sam_lookup_groupmem,
	.sequence_number       = sam_sequence_number,
	.lockout_policy        = sam_lockout_policy,
	.password_policy       = sam_password_policy,
	.trusted_domains       = builtin_trusted_domains
};

/* the rpc backend methods are exposed via this structure */
struct winbindd_methods sam_passdb_methods = {
	.consistent            = false,

	.query_user_list       = sam_query_user_list,
	.enum_dom_groups       = sam_enum_dom_groups,
	.enum_local_groups     = sam_enum_local_groups,
	.name_to_sid           = sam_name_to_sid,
	.sid_to_name           = sam_sid_to_name,
	.rids_to_names         = sam_rids_to_names,
	.lookup_usergroups     = sam_lookup_usergroups,
	.lookup_useraliases    = sam_lookup_useraliases,
	.lookup_groupmem       = sam_lookup_groupmem,
	.sequence_number       = sam_sequence_number,
	.lockout_policy        = sam_lockout_policy,
	.password_policy       = sam_password_policy,
	.trusted_domains       = sam_trusted_domains
};
