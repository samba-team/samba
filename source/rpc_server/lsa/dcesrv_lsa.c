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
	int reference_count;
	void *sam_ctx;
	uint32_t access_mask;
	const char *domain_dn;
};


/*
  destroy policy state
*/
static void lsa_Policy_close(struct lsa_policy_state *state)
{
	state->reference_count--;
	if (state->reference_count == 0) {
		talloc_free(state);
	}
}

/*
  destroy an open policy. This closes the database connection
*/
static void lsa_Policy_destroy(struct dcesrv_connection *conn, struct dcesrv_handle *h)
{
	struct lsa_policy_state *state = h->data;
	lsa_Policy_close(state);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_QuerySecObj 
*/
static NTSTATUS lsa_QuerySecObj(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_QuerySecObj *r)
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

	/* work out the domain_dn - useful for so many calls its worth
	   fetching here */
	state->domain_dn = samdb_search_string(state->sam_ctx, state, NULL,
					       "dn", "(&(objectClass=domain)(!(objectclass=builtinDomain)))");
	if (!state->domain_dn) {
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

	state->reference_count = 1;
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

	info->name.name = samdb_result_string(res[0], "name", NULL);
	info->sid       = samdb_result_dom_sid(mem_ctx, res[0], "objectSid");

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

	info->name.name       = samdb_result_string(res[0],           "name", NULL);
	info->dns_domain.name = samdb_result_string(res[0],           "dnsDomain", NULL);
	info->dns_forest.name = samdb_result_string(res[0],           "dnsDomain", NULL);
	info->domain_guid     = samdb_result_guid(res[0],             "objectGUID");
	info->sid             = samdb_result_dom_sid(mem_ctx, res[0], "objectSid");

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
  lsa_LookupNames 
*/
static NTSTATUS lsa_LookupNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LookupNames *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LookupSids 
*/
static NTSTATUS lsa_LookupSids(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct lsa_LookupSids *r)
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

	r->out.names = talloc_zero_p(mem_ctx,  struct lsa_TransNameArray);
	if (r->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*r->out.count = 0;

	r->out.names->names = talloc_array_p(r->out.names, struct lsa_TranslatedName, 
					     r->in.sids->num_sids);
	if (r->out.names->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<r->in.sids->num_sids;i++) {
		const char * const attrs[] = { "sAMAccountName", "sAMAccountType", NULL};
		struct dom_sid *sid = r->in.sids->sids[i].sid;
		char *sid_str = dom_sid_string(mem_ctx, sid);
		int ret, j;
		struct ldb_message **res;
		const char *name, *authority_name;
		struct dom_sid *authority_sid;
		uint32_t atype, rtype;
		const struct {
			const char *sid_prefix;
			const char *authority_name;
		} authority_names[] = {
			{ "S-1-5", "NT AUTHORITY" }
		};

		r->out.names->count++;
		(*r->out.count)++;

		r->out.names->names[i].sid_type = SID_NAME_UNKNOWN;
		r->out.names->names[i].name.name = sid_str;
		r->out.names->names[i].sid_index = 0xFFFFFFFF;

		if (sid_str == NULL) {
			r->out.names->names[i].name.name = "(SIDERROR)";
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		/* work out the authority name */
		authority_name = talloc_strndup(mem_ctx, sid_str, 5);
		authority_sid = dom_sid_parse_talloc(mem_ctx, authority_name);
		if (!authority_name || !authority_sid) {
			return NT_STATUS_NO_MEMORY;
		}
		for (j=0;j<ARRAY_SIZE(authority_names);j++) {
			if (strncmp(sid_str, authority_names[j].sid_prefix, 
				    strlen(authority_names[j].sid_prefix)) == 0) {
				authority_name = authority_names[j].authority_name;
				break;
			}
		}

		/* see if we've already done this authority name */
		for (j=0;j<r->out.domains->count;j++) {
			if (strcmp(authority_name, r->out.domains->domains[j].name.name) == 0) {
				break;
			}
		}
		if (j == r->out.domains->count) {
			r->out.domains->domains = talloc_realloc_p(r->out.domains, 
								   r->out.domains->domains,
								   struct lsa_TrustInformation,
								   r->out.domains->count+1);
			if (r->out.domains == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			r->out.domains->domains[j].name.name = authority_name;
			r->out.domains->domains[j].sid = authority_sid;
			r->out.domains->count++;
		}

		ret = samdb_search(state->sam_ctx, mem_ctx, NULL, &res, attrs, "objectSid=%s", sid_str);
		if (ret != 1) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		name = ldb_msg_find_string(res[0], "sAMAccountName", NULL);
		if (name == NULL) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		atype = samdb_result_uint(res[0], "sAMAccountType", 0);
		if (atype == 0) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		rtype = samdb_atype_map(atype);
		if (rtype == SID_NAME_UNKNOWN) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		r->out.names->names[i].sid_type = rtype;
		r->out.names->names[i].name.name = name;
		r->out.names->names[i].sid_index = 0;
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
  lsa_QueryInfoTrustedDomain
*/
static NTSTATUS lsa_QueryInfoTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_QueryInfoTrustedDomain *r)
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
static NTSTATUS lsa_LookupPrivValue(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LookupPrivValue *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LookupPrivName 
*/
static NTSTATUS lsa_LookupPrivName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LookupPrivName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LookupPrivDisplayName
*/
static NTSTATUS lsa_LookupPrivDisplayName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LookupPrivDisplayName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
static NTSTATUS lsa_EnumAccountsWithUserRight(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_EnumAccountsWithUserRight *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_EnumAccountRights 
*/
static NTSTATUS lsa_EnumAccountRights(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_EnumAccountRights *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
  lsa_QueryTrustDomainInfo
*/
static NTSTATUS lsa_QueryTrustDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_QueryTrustDomainInfo *r)
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
  lsa_LookupSids2
*/
static NTSTATUS lsa_LookupSids2(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx,
				struct lsa_LookupSids2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_LookupNames2
*/
static NTSTATUS lsa_LookupNames2(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx,
				 struct lsa_LookupNames2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
