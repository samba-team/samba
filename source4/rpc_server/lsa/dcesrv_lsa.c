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
#include "rpc_server/common/common.h"

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
	TALLOC_CTX *mem_ctx;
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
		samdb_close(state->sam_ctx);
		talloc_destroy(state->mem_ctx);
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
	TALLOC_CTX *lsa_mem_ctx;

	ZERO_STRUCTP(r->out.handle);

	lsa_mem_ctx = talloc_init("lsa_OpenPolicy");
	if (!lsa_mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	state = talloc_p(lsa_mem_ctx, struct lsa_policy_state);
	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}
	state->mem_ctx = lsa_mem_ctx;

	/* make sure the sam database is accessible */
	state->sam_ctx = samdb_connect();
	if (state->sam_ctx == NULL) {
		talloc_destroy(state->mem_ctx);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* work out the domain_dn - useful for so many calls its worth
	   fetching here */
	state->domain_dn = samdb_search_string(state->sam_ctx, state->mem_ctx, NULL,
					       "dn", "(&(objectClass=domain)(!(objectclass=builtinDomain)))");
	if (!state->domain_dn) {
		samdb_close(state->sam_ctx);
		talloc_destroy(state->mem_ctx);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	handle = dcesrv_handle_new(dce_call->conn, LSA_HANDLE_POLICY);
	if (!handle) {
		talloc_destroy(state->mem_ctx);
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
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
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
  ADDPRIVS 
*/
static NTSTATUS ADDPRIVS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct ADDPRIVS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  REMOVEPRIVS 
*/
static NTSTATUS REMOVEPRIVS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct REMOVEPRIVS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  GETQUOTAS 
*/
static NTSTATUS GETQUOTAS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct GETQUOTAS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  SETQUOTAS 
*/
static NTSTATUS SETQUOTAS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct SETQUOTAS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  GETSYSTEMACCOUNT 
*/
static NTSTATUS GETSYSTEMACCOUNT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct GETSYSTEMACCOUNT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  SETSYSTEMACCOUNT 
*/
static NTSTATUS SETSYSTEMACCOUNT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct SETSYSTEMACCOUNT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  OPENTRUSTDOM 
*/
static NTSTATUS OPENTRUSTDOM(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct OPENTRUSTDOM *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  QUERYTRUSTDOM 
*/
static NTSTATUS QUERYTRUSTDOM(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct QUERYTRUSTDOM *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  SETINFOTRUSTDOM 
*/
static NTSTATUS SETINFOTRUSTDOM(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct SETINFOTRUSTDOM *r)
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
  LOOKUPPRIVVALUE 
*/
static NTSTATUS LOOKUPPRIVVALUE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct LOOKUPPRIVVALUE *r)
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
  PRIV_GET_DISPNAME 
*/
static NTSTATUS PRIV_GET_DISPNAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct PRIV_GET_DISPNAME *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DELETEOBJECT 
*/
static NTSTATUS DELETEOBJECT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DELETEOBJECT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  ENUMACCTWITHRIGHT 
*/
static NTSTATUS ENUMACCTWITHRIGHT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct ENUMACCTWITHRIGHT *r)
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
  ADDACCTRIGHTS 
*/
static NTSTATUS ADDACCTRIGHTS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct ADDACCTRIGHTS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  REMOVEACCTRIGHTS 
*/
static NTSTATUS REMOVEACCTRIGHTS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct REMOVEACCTRIGHTS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  QUERYTRUSTDOMINFO 
*/
static NTSTATUS QUERYTRUSTDOMINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct QUERYTRUSTDOMINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  SETTRUSTDOMINFO 
*/
static NTSTATUS SETTRUSTDOMINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct SETTRUSTDOMINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  DELETETRUSTDOM 
*/
static NTSTATUS DELETETRUSTDOM(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct DELETETRUSTDOM *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  STOREPRIVDATA 
*/
static NTSTATUS STOREPRIVDATA(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct STOREPRIVDATA *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  RETRPRIVDATA 
*/
static NTSTATUS RETRPRIVDATA(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct RETRPRIVDATA *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  UNK_GET_CONNUSER 
*/
static NTSTATUS UNK_GET_CONNUSER(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct UNK_GET_CONNUSER *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_lsa_s.c"
