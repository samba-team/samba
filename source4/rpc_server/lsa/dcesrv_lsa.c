/* 
   Unix SMB/CIFS implementation.

   endpoint server for the lsarpc pipe

   Copyright (C) Andrew Tridgell 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "lib/ldb/include/ldb.h"

/*
  this type allows us to distinguish handle types
*/
enum lsa_handle {
	LSA_HANDLE_POLICY,
	LSA_HANDLE_ACCOUNT,
	LSA_HANDLE_SECRET
};

/*
  state associated with a lsa_OpenPolicy() operation
*/
struct lsa_policy_state {
	void *sam_ctx;
	struct sidmap_context *sidmap;
	uint32_t access_mask;
	const char *domain_dn;
	const char *domain_name;
	struct dom_sid *domain_sid;
	struct dom_sid *builtin_sid;
};


/*
  destroy an open policy. This closes the database connection
*/
static void lsa_Policy_destroy(struct dcesrv_connection *conn, struct dcesrv_handle *h)
{
	struct lsa_policy_state *state = h->data;
	talloc_free(state);
}

/* 
  lsa_Close 
*/
static NTSTATUS lsa_Close(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			  struct lsa_Close *r)
{
	struct dcesrv_handle *h;

	*r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	/* this causes the callback samr_XXX_destroy() to be called by
	   the handle destroy code which destroys the state associated
	   with the handle */
	dcesrv_handle_destroy(dce_call->conn, h);

	ZERO_STRUCTP(r->out.handle);

	return NT_STATUS_OK;
}


/* 
  lsa_Delete 
*/
static NTSTATUS lsa_Delete(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			   struct lsa_Delete *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_EnumPrivs 
*/
static NTSTATUS lsa_EnumPrivs(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct lsa_EnumPrivs *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	int i;
	const char *privname;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	i = *r->in.resume_handle;
	if (i == 0) i = 1;

	while ((privname = sec_privilege_name(i)) &&
	       r->out.privs->count < r->in.max_count) {
		struct lsa_PrivEntry *e;

		r->out.privs->privs = talloc_realloc_p(r->out.privs,
						       r->out.privs->privs, 
						       struct lsa_PrivEntry, 
						       r->out.privs->count+1);
		if (r->out.privs->privs == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		e = &r->out.privs->privs[r->out.privs->count];
		e->luid.low = i;
		e->luid.high = 0;
		e->name.string = privname;
		r->out.privs->count++;
		i++;
	}

	*r->in.resume_handle = i;

	return NT_STATUS_OK;
}


/* 
  lsa_QuerySecObj 
*/
static NTSTATUS lsa_QuerySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_QuerySecurity *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_SetSecObj 
*/
static NTSTATUS lsa_SetSecObj(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct lsa_SetSecObj *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_ChangePassword 
*/
static NTSTATUS lsa_ChangePassword(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct lsa_ChangePassword *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_OpenPolicy2
*/
static NTSTATUS lsa_OpenPolicy2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct lsa_OpenPolicy2 *r)
{
	struct lsa_policy_state *state;
	struct dcesrv_handle *handle;
	const char *sid_str;

	ZERO_STRUCTP(r->out.handle);

	state = talloc_p(dce_call->conn, struct lsa_policy_state);
	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}

	/* make sure the sam database is accessible */
	state->sam_ctx = samdb_connect(state);
	if (state->sam_ctx == NULL) {
		talloc_free(state);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	state->sidmap = sidmap_open(state);
	if (state->sidmap == NULL) {
		talloc_free(state);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* work out the domain_dn - useful for so many calls its worth
	   fetching here */
	state->domain_dn = samdb_search_string(state->sam_ctx, state, NULL,
					       "dn", "(&(objectClass=domain)(!(objectclass=builtinDomain)))");
	if (!state->domain_dn) {
		talloc_free(state);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	sid_str = samdb_search_string(state->sam_ctx, state, NULL,
				      "objectSid", "dn=%s", state->domain_dn);
	if (!sid_str) {
		talloc_free(state);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->domain_sid = dom_sid_parse_talloc(state, sid_str);
	if (!state->domain_sid) {
		talloc_free(state);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->builtin_sid = dom_sid_parse_talloc(state, SID_BUILTIN);
	if (!state->builtin_sid) {
		talloc_free(state);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->domain_name = samdb_search_string(state->sam_ctx, state, NULL,
						 "name", "dn=%s", state->domain_dn);
	if (!state->domain_name) {
		talloc_free(state);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}
	

	handle = dcesrv_handle_new(dce_call->conn, LSA_HANDLE_POLICY);
	if (!handle) {
		talloc_free(state);
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = state;
	handle->destroy = lsa_Policy_destroy;

	state->access_mask = r->in.access_mask;
	*r->out.handle = handle->wire_handle;

	/* note that we have completely ignored the attr element of
	   the OpenPolicy. As far as I can tell, this is what w2k3
	   does */

	return NT_STATUS_OK;
}

/* 
  lsa_OpenPolicy
  a wrapper around lsa_OpenPolicy2
*/
static NTSTATUS lsa_OpenPolicy(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_OpenPolicy *r)
{
	struct lsa_OpenPolicy2 r2;

	r2.in.system_name = NULL;
	r2.in.attr = r->in.attr;
	r2.in.access_mask = r->in.access_mask;
	r2.out.handle = r->out.handle;

	return lsa_OpenPolicy2(dce_call, mem_ctx, &r2);
}




/*
  fill in the AccountDomain info
*/
static NTSTATUS lsa_info_AccountDomain(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
				       struct lsa_DomainInfo *info)
{
	const char * const attrs[] = { "objectSid", "name", NULL};
	int ret;
	struct ldb_message **res;

	ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, attrs, 
			   "dn=%s", state->domain_dn);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	info->name.string = samdb_result_string(res[0], "name", NULL);
	info->sid         = samdb_result_dom_sid(mem_ctx, res[0], "objectSid");

	return NT_STATUS_OK;
}

/*
  fill in the DNS domain info
*/
static NTSTATUS lsa_info_DNS(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
			     struct lsa_DnsDomainInfo *info)
{
	const char * const attrs[] = { "name", "dnsDomain", "objectGUID", "objectSid", NULL };
	int ret;
	struct ldb_message **res;

	ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, attrs, 
			   "dn=%s", state->domain_dn);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	info->name.string       = samdb_result_string(res[0],           "name", NULL);
	info->dns_domain.string = samdb_result_string(res[0],           "dnsDomain", NULL);
	info->dns_forest.string = samdb_result_string(res[0],           "dnsDomain", NULL);
	info->domain_guid       = samdb_result_guid(res[0],             "objectGUID");
	info->sid               = samdb_result_dom_sid(mem_ctx, res[0], "objectSid");

	return NT_STATUS_OK;
}

/* 
  lsa_QueryInfoPolicy2
*/
static NTSTATUS lsa_QueryInfoPolicy2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct lsa_QueryInfoPolicy2 *r)
{
	struct lsa_policy_state *state;
	struct dcesrv_handle *h;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	r->out.info = talloc_p(mem_ctx, union lsa_PolicyInformation);
	if (!r->out.info) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(r->out.info);

	switch (r->in.level) {
	case LSA_POLICY_INFO_DOMAIN:
	case LSA_POLICY_INFO_ACCOUNT_DOMAIN:
		return lsa_info_AccountDomain(state, mem_ctx, &r->out.info->account_domain);

	case LSA_POLICY_INFO_DNS:
		return lsa_info_DNS(state, mem_ctx, &r->out.info->dns);
	}

	return NT_STATUS_INVALID_INFO_CLASS;
}

/* 
  lsa_QueryInfoPolicy 
*/
static NTSTATUS lsa_QueryInfoPolicy(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				    struct lsa_QueryInfoPolicy *r)
{
	struct lsa_QueryInfoPolicy2 r2;
	NTSTATUS status;

	r2.in.handle = r->in.handle;
	r2.in.level = r->in.level;
	
	status = lsa_QueryInfoPolicy2(dce_call, mem_ctx, &r2);

	r->out.info = r2.out.info;

	return status;
}

/* 
  lsa_SetInfoPolicy 
*/
static NTSTATUS lsa_SetInfoPolicy(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_SetInfoPolicy *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_ClearAuditLog 
*/
static NTSTATUS lsa_ClearAuditLog(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_ClearAuditLog *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CreateAccount 
*/
static NTSTATUS lsa_CreateAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_CreateAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_EnumAccounts 
*/
static NTSTATUS lsa_EnumAccounts(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct lsa_EnumAccounts *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CreateTrustedDomain 
*/
static NTSTATUS lsa_CreateTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct lsa_CreateTrustedDomain *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_EnumTrustDom 
*/
static NTSTATUS lsa_EnumTrustDom(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_EnumTrustDom *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/*
  return the authority name and authority sid, given a sid
*/
static NTSTATUS lsa_authority_name(struct lsa_policy_state *state,
				   TALLOC_CTX *mem_ctx, struct dom_sid *sid,
				   const char **authority_name,
				   struct dom_sid **authority_sid)
{
	if (dom_sid_in_domain(state->domain_sid, sid)) {
		*authority_name = state->domain_name;
		*authority_sid = state->domain_sid;
		return NT_STATUS_OK;
	}

	if (dom_sid_in_domain(state->builtin_sid, sid)) {
		*authority_name = "BUILTIN";
		*authority_sid = state->builtin_sid;
		return NT_STATUS_OK;
	}

	*authority_sid = dom_sid_dup(mem_ctx, sid);
	if (*authority_sid == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	(*authority_sid)->num_auths = 0;
	*authority_name = dom_sid_string(mem_ctx, *authority_sid);
	if (*authority_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/*
  add to the lsa_RefDomainList for LookupSids and LookupNames
*/
static NTSTATUS lsa_authority_list(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx, 
				   struct dom_sid *sid, 
				   struct lsa_RefDomainList *domains,
				   uint32_t *sid_index)
{
	NTSTATUS status;
	const char *authority_name;
	struct dom_sid *authority_sid;
	int i;

	/* work out the authority name */
	status = lsa_authority_name(state, mem_ctx, sid, 
				    &authority_name, &authority_sid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	/* see if we've already done this authority name */
	for (i=0;i<domains->count;i++) {
		if (strcmp(authority_name, domains->domains[i].name.string) == 0) {
			*sid_index = i;
			return NT_STATUS_OK;
		}
	}

	domains->domains = talloc_realloc_p(domains, 
					    domains->domains,
					    struct lsa_TrustInformation,
					    domains->count+1);
	if (domains->domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	domains->domains[i].name.string = authority_name;
	domains->domains[i].sid         = authority_sid;
	domains->count++;
	*sid_index = i;
	
	return NT_STATUS_OK;
}

/*
  lookup a name for 1 SID
*/
static NTSTATUS lsa_lookup_sid(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
			       struct dom_sid *sid, const char *sid_str,
			       const char **name, uint32_t *atype)
{
	int ret;
	struct ldb_message **res;
	const char * const attrs[] = { "sAMAccountName", "sAMAccountType", NULL};
	NTSTATUS status;

	ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, attrs, 
			   "objectSid=%s", sid_str);
	if (ret == 1) {
		*name = ldb_msg_find_string(res[0], "sAMAccountName", NULL);
		if (*name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	
		*atype = samdb_result_uint(res[0], "sAMAccountType", 0);

		return NT_STATUS_OK;
	}

	status = sidmap_allocated_sid_lookup(state->sidmap, mem_ctx, sid, name, atype);

	return status;
}


/*
  lsa_LookupSids2
*/
static NTSTATUS lsa_LookupSids2(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx,
				struct lsa_LookupSids2 *r)
{
	struct lsa_policy_state *state;
	struct dcesrv_handle *h;
	int i;
	NTSTATUS status = NT_STATUS_OK;

	r->out.domains = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	r->out.domains = talloc_zero_p(mem_ctx,  struct lsa_RefDomainList);
	if (r->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.names = talloc_zero_p(mem_ctx,  struct lsa_TransNameArray2);
	if (r->out.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*r->out.count = 0;

	r->out.names->names = talloc_array_p(r->out.names, struct lsa_TranslatedName2, 
					     r->in.sids->num_sids);
	if (r->out.names->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<r->in.sids->num_sids;i++) {
		struct dom_sid *sid = r->in.sids->sids[i].sid;
		char *sid_str = dom_sid_string(mem_ctx, sid);
		const char *name;
		uint32_t atype, rtype, sid_index;
		NTSTATUS status2;

		r->out.names->count++;
		(*r->out.count)++;

		r->out.names->names[i].sid_type    = SID_NAME_UNKNOWN;
		r->out.names->names[i].name.string = sid_str;
		r->out.names->names[i].sid_index   = 0xFFFFFFFF;
		r->out.names->names[i].unknown     = 0;

		if (sid_str == NULL) {
			r->out.names->names[i].name.string = "(SIDERROR)";
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		/* work out the authority name */
		status2 = lsa_authority_list(state, mem_ctx, sid, r->out.domains, &sid_index);
		if (!NT_STATUS_IS_OK(status2)) {
			return status2;
		}

		status2 = lsa_lookup_sid(state, mem_ctx, sid, sid_str, 
					 &name, &atype);
		if (!NT_STATUS_IS_OK(status2)) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		rtype = samdb_atype_map(atype);
		if (rtype == SID_NAME_UNKNOWN) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		r->out.names->names[i].sid_type    = rtype;
		r->out.names->names[i].name.string = name;
		r->out.names->names[i].sid_index   = sid_index;
		r->out.names->names[i].unknown     = 0;
	}
	
	return status;
}


/* 
  lsa_LookupSids 
*/
static NTSTATUS lsa_LookupSids(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct lsa_LookupSids *r)
{
	struct lsa_LookupSids2 r2;
	NTSTATUS status;
	int i;

	r2.in.handle   = r->in.handle;
	r2.in.sids     = r->in.sids;
	r2.in.names    = NULL;
	r2.in.level    = r->in.level;
	r2.in.count    = r->in.count;
	r2.in.unknown1 = 0;
	r2.in.unknown2 = 0;
	r2.out.count   = r->out.count;

	status = lsa_LookupSids2(dce_call, mem_ctx, &r2);
	if (dce_call->fault_code != 0) {
		return status;
	}

	r->out.domains = r2.out.domains;
	r->out.names = talloc_p(mem_ctx, struct lsa_TransNameArray);
	if (r->out.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.names->count = r2.out.names->count;
	r->out.names->names = talloc_array_p(r->out.names, struct lsa_TranslatedName, 
					     r->out.names->count);
	if (r->out.names->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<r->out.names->count;i++) {
		r->out.names->names[i].sid_type    = r2.out.names->names[i].sid_type;
		r->out.names->names[i].name.string = r2.out.names->names[i].name.string;
		r->out.names->names[i].sid_index   = r2.out.names->names[i].sid_index;
	}

	return status;
}


/* 
  lsa_CreateSecret 
*/
static NTSTATUS lsa_CreateSecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CreateSecret *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_OpenAccount 
*/
static NTSTATUS lsa_OpenAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_OpenAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_EnumPrivsAccount 
*/
static NTSTATUS lsa_EnumPrivsAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_EnumPrivsAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_AddPrivilegesToAccount
*/
static NTSTATUS lsa_AddPrivilegesToAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_AddPrivilegesToAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_RemovePrivilegesFromAccount
*/
static NTSTATUS lsa_RemovePrivilegesFromAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_RemovePrivilegesFromAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_GetQuotasForAccount
*/
static NTSTATUS lsa_GetQuotasForAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_GetQuotasForAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_SetQuotasForAccount
*/
static NTSTATUS lsa_SetQuotasForAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_SetQuotasForAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_GetSystemAccessAccount
*/
static NTSTATUS lsa_GetSystemAccessAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_GetSystemAccessAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_SetSystemAccessAccount
*/
static NTSTATUS lsa_SetSystemAccessAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_SetSystemAccessAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_OpenTrustedDomain
*/
static NTSTATUS lsa_OpenTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_OpenTrustedDomain *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_QueryTrustedDomainInfo
*/
static NTSTATUS lsa_QueryTrustedDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_QueryTrustedDomainInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_SetInformationTrustedDomain
*/
static NTSTATUS lsa_SetInformationTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_SetInformationTrustedDomain *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_OpenSecret 
*/
static NTSTATUS lsa_OpenSecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_OpenSecret *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_SetSecret 
*/
static NTSTATUS lsa_SetSecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_SetSecret *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_QuerySecret 
*/
static NTSTATUS lsa_QuerySecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_QuerySecret *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LookupPrivValue
*/
static NTSTATUS lsa_LookupPrivValue(struct dcesrv_call_state *dce_call, 
				    TALLOC_CTX *mem_ctx,
				    struct lsa_LookupPrivValue *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	int id;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	id = sec_privilege_id(r->in.name->string);
	if (id == -1) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	r->out.luid->low = id;
	r->out.luid->high = 0;

	return NT_STATUS_OK;	
}


/* 
  lsa_LookupPrivName 
*/
static NTSTATUS lsa_LookupPrivName(struct dcesrv_call_state *dce_call, 
				   TALLOC_CTX *mem_ctx,
				   struct lsa_LookupPrivName *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	const char *privname;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	if (r->in.luid->high != 0) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	privname = sec_privilege_name(r->in.luid->low);
	if (privname == NULL) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	r->out.name = talloc_p(mem_ctx, struct lsa_String);
	if (r->out.name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.name->string = privname;

	return NT_STATUS_OK;	
}


/* 
  lsa_LookupPrivDisplayName
*/
static NTSTATUS lsa_LookupPrivDisplayName(struct dcesrv_call_state *dce_call, 
					  TALLOC_CTX *mem_ctx,
					  struct lsa_LookupPrivDisplayName *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	int id;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	id = sec_privilege_id(r->in.name->string);
	if (id == -1) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}
	
	r->out.disp_name = talloc_p(mem_ctx, struct lsa_String);
	if (r->out.disp_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.disp_name->string = sec_privilege_display_name(id, r->in.language_id);
	if (r->out.disp_name->string == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	return NT_STATUS_OK;
}


/* 
  lsa_DeleteObject
*/
static NTSTATUS lsa_DeleteObject(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_DeleteObject *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_EnumAccountsWithUserRight
*/
static NTSTATUS lsa_EnumAccountsWithUserRight(struct dcesrv_call_state *dce_call, 
					      TALLOC_CTX *mem_ctx,
					      struct lsa_EnumAccountsWithUserRight *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	int ret, i;
	struct ldb_message **res;
	const char * const attrs[] = { "objectSid", NULL};
	const char *privname;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	if (r->in.name == NULL) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	} 

	privname = r->in.name->string;
	if (sec_privilege_id(privname) == -1) {
		return NT_STATUS_NO_SUCH_PRIVILEGE;
	}

	ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, attrs, 
			   "privilege=%s", privname);
	if (ret <= 0) {
		return NT_STATUS_NO_SUCH_USER;
	}

	r->out.sids->sids = talloc_array_p(r->out.sids, struct lsa_SidPtr, ret);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<ret;i++) {
		const char *sidstr;
		sidstr = samdb_result_string(res[i], "objectSid", NULL);
		if (sidstr == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		r->out.sids->sids[i].sid = dom_sid_parse_talloc(r->out.sids->sids,
								sidstr);
		if (r->out.sids->sids[i].sid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	r->out.sids->num_sids = ret;

	return NT_STATUS_OK;
}


/* 
  lsa_EnumAccountRights 
*/
static NTSTATUS lsa_EnumAccountRights(struct dcesrv_call_state *dce_call, 
				      TALLOC_CTX *mem_ctx,
				      struct lsa_EnumAccountRights *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	int ret, i;
	struct ldb_message **res;
	const char * const attrs[] = { "privilege", NULL};
	const char *sidstr;
	struct ldb_message_element *el;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	sidstr = dom_sid_string(mem_ctx, r->in.sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, attrs, 
			   "objectSid=%s", sidstr);
	if (ret != 1) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	el = ldb_msg_find_element(res[0], "privilege");
	if (el == NULL || el->num_values == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	r->out.rights->count = el->num_values;
	r->out.rights->names = talloc_array_p(r->out.rights, 
					      struct lsa_String, r->out.rights->count);
	if (r->out.rights->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<el->num_values;i++) {
		r->out.rights->names[i].string = el->values[i].data;
	}

	return NT_STATUS_OK;
}


/* 
  lsa_AddAccountRights
*/
static NTSTATUS lsa_AddAccountRights(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_AddAccountRights *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_RemoveAccountRights
*/
static NTSTATUS lsa_RemoveAccountRights(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_RemoveAccountRights *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_QueryTrustedDomainInfoBySid
*/
static NTSTATUS lsa_QueryTrustedDomainInfoBySid(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct lsa_QueryTrustedDomainInfoBySid *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_SetTrustDomainInfo
*/
static NTSTATUS lsa_SetTrustDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_SetTrustDomainInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_DeleteTrustDomain
*/
static NTSTATUS lsa_DeleteTrustDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_DeleteTrustDomain *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_StorePrivateData
*/
static NTSTATUS lsa_StorePrivateData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_StorePrivateData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_RetrievePrivateData
*/
static NTSTATUS lsa_RetrievePrivateData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_RetrievePrivateData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_GetUserName
*/
static NTSTATUS lsa_GetUserName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_GetUserName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_SetInfoPolicy2
*/
static NTSTATUS lsa_SetInfoPolicy2(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx,
				   struct lsa_SetInfoPolicy2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_QueryTrustedDomainInfoByName
*/
static NTSTATUS lsa_QueryTrustedDomainInfoByName(struct dcesrv_call_state *dce_call,
						 TALLOC_CTX *mem_ctx,
						 struct lsa_QueryTrustedDomainInfoByName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_SetTrustedDomainInfoByName
*/
static NTSTATUS lsa_SetTrustedDomainInfoByName(struct dcesrv_call_state *dce_call,
					       TALLOC_CTX *mem_ctx,
					       struct lsa_SetTrustedDomainInfoByName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_EnumTrustedDomainsEx
*/
static NTSTATUS lsa_EnumTrustedDomainsEx(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct lsa_EnumTrustedDomainsEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_CreateTrustedDomainEx
*/
static NTSTATUS lsa_CreateTrustedDomainEx(struct dcesrv_call_state *dce_call,
					  TALLOC_CTX *mem_ctx,
					  struct lsa_CreateTrustedDomainEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_CloseTrustedDomainEx
*/
static NTSTATUS lsa_CloseTrustedDomainEx(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct lsa_CloseTrustedDomainEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_QueryDomainInformationPolicy
*/
static NTSTATUS lsa_QueryDomainInformationPolicy(struct dcesrv_call_state *dce_call,
						 TALLOC_CTX *mem_ctx,
						 struct lsa_QueryDomainInformationPolicy *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_SetDomInfoPolicy
*/
static NTSTATUS lsa_SetDomInfoPolicy(struct dcesrv_call_state *dce_call,
				     TALLOC_CTX *mem_ctx,
				     struct lsa_SetDomInfoPolicy *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_OpenTrustedDomainByName
*/
static NTSTATUS lsa_OpenTrustedDomainByName(struct dcesrv_call_state *dce_call,
					    TALLOC_CTX *mem_ctx,
					    struct lsa_OpenTrustedDomainByName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_TestCall
*/
static NTSTATUS lsa_TestCall(struct dcesrv_call_state *dce_call,
			     TALLOC_CTX *mem_ctx,
			     struct lsa_TestCall *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lookup a SID for 1 name
*/
static NTSTATUS lsa_lookup_name(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
				const char *name, struct dom_sid **sid, uint32_t *atype)
{
	int ret;
	struct ldb_message **res;
	const char * const attrs[] = { "objectSid", "sAMAccountType", NULL};

	ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, attrs, "sAMAccountName=%s", name);
	if (ret == 1) {
		const char *sid_str = ldb_msg_find_string(res[0], "objectSid", NULL);
		if (sid_str == NULL) {
			return NT_STATUS_INVALID_SID;
		}

		*sid = dom_sid_parse_talloc(mem_ctx, sid_str);
		if (*sid == NULL) {
			return NT_STATUS_INVALID_SID;
		}

		*atype = samdb_result_uint(res[0], "sAMAccountType", 0);

		return NT_STATUS_OK;
	}

	/* need to add a call into sidmap to check for a allocated sid */

	return NT_STATUS_INVALID_SID;
}

/*
  lsa_LookupNames2
*/
static NTSTATUS lsa_LookupNames2(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx,
				 struct lsa_LookupNames2 *r)
{
	struct lsa_policy_state *state;
	struct dcesrv_handle *h;
	int i;
	NTSTATUS status = NT_STATUS_OK;

	r->out.domains = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	r->out.domains = talloc_zero_p(mem_ctx,  struct lsa_RefDomainList);
	if (r->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.sids = talloc_zero_p(mem_ctx,  struct lsa_TransSidArray2);
	if (r->out.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*r->out.count = 0;

	r->out.sids->sids = talloc_array_p(r->out.sids, struct lsa_TranslatedSid2, 
					   r->in.num_names);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<r->in.num_names;i++) {
		const char *name = r->in.names[i].string;
		struct dom_sid *sid;
		uint32_t atype, rtype, sid_index;
		NTSTATUS status2;

		r->out.sids->count++;
		(*r->out.count)++;

		r->out.sids->sids[i].sid_type    = SID_NAME_UNKNOWN;
		r->out.sids->sids[i].rid         = 0xFFFFFFFF;
		r->out.sids->sids[i].sid_index   = 0xFFFFFFFF;
		r->out.sids->sids[i].unknown     = 0;

		status2 = lsa_lookup_name(state, mem_ctx, name, &sid, &atype);
		if (!NT_STATUS_IS_OK(status) || sid->num_auths == 0) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		rtype = samdb_atype_map(atype);
		if (rtype == SID_NAME_UNKNOWN) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		status2 = lsa_authority_list(state, mem_ctx, sid, r->out.domains, &sid_index);
		if (!NT_STATUS_IS_OK(status2)) {
			return status2;
		}

		r->out.sids->sids[i].sid_type    = rtype;
		r->out.sids->sids[i].rid         = sid->sub_auths[sid->num_auths-1];
		r->out.sids->sids[i].sid_index   = sid_index;
		r->out.sids->sids[i].unknown     = 0;
	}
	
	return status;
}

/* 
  lsa_LookupNames 
*/
static NTSTATUS lsa_LookupNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LookupNames *r)
{
	struct lsa_LookupNames2 r2;
	NTSTATUS status;
	int i;

	r2.in.handle    = r->in.handle;
	r2.in.num_names = r->in.num_names;
	r2.in.names     = r->in.names;
	r2.in.sids      = NULL;
	r2.in.level     = r->in.level;
	r2.in.count     = r->in.count;
	r2.in.unknown1  = 0;
	r2.in.unknown2  = 0;
	r2.out.count    = r->out.count;

	status = lsa_LookupNames2(dce_call, mem_ctx, &r2);
	if (dce_call->fault_code != 0) {
		return status;
	}

	r->out.domains = r2.out.domains;
	r->out.sids = talloc_p(mem_ctx, struct lsa_TransSidArray);
	if (r->out.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.sids->count = r2.out.sids->count;
	r->out.sids->sids = talloc_array_p(r->out.sids, struct lsa_TranslatedSid, 
					   r->out.sids->count);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<r->out.sids->count;i++) {
		r->out.sids->sids[i].sid_type    = r2.out.sids->sids[i].sid_type;
		r->out.sids->sids[i].rid         = r2.out.sids->sids[i].rid;
		r->out.sids->sids[i].sid_index   = r2.out.sids->sids[i].sid_index;
	}

	return status;
}



/*
  lsa_CreateTrustedDomainEx2
*/
static NTSTATUS lsa_CreateTrustedDomainEx2(struct dcesrv_call_state *dce_call,
					   TALLOC_CTX *mem_ctx,
					   struct lsa_CreateTrustedDomainEx2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_lsa_s.c"
