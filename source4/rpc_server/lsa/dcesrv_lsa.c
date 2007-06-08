/* 
   Unix SMB/CIFS implementation.

   endpoint server for the lsarpc pipe

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   
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
#include "rpc_server/dcerpc_server.h"
#include "rpc_server/common/common.h"
#include "auth/auth.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/ldap/ldap.h"
#include "lib/ldb/include/ldb_errors.h"
#include "libcli/security/security.h"
#include "libcli/auth/libcli_auth.h"
#include "param/secrets.h"
#include "db_wrap.h"
#include "librpc/gen_ndr/ndr_dssetup.h"

/*
  this type allows us to distinguish handle types
*/
enum lsa_handle {
	LSA_HANDLE_POLICY,
	LSA_HANDLE_ACCOUNT,
	LSA_HANDLE_SECRET,
	LSA_HANDLE_TRUSTED_DOMAIN
};

/*
  state associated with a lsa_OpenPolicy() operation
*/
struct lsa_policy_state {
	struct dcesrv_handle *handle;
	struct ldb_context *sam_ldb;
	struct sidmap_context *sidmap;
	uint32_t access_mask;
	struct ldb_dn *domain_dn;
	struct ldb_dn *forest_dn;
	struct ldb_dn *builtin_dn;
	struct ldb_dn *system_dn;
	const char *domain_name;
	const char *domain_dns;
	const char *forest_dns;
	struct dom_sid *domain_sid;
	struct GUID domain_guid;
	struct dom_sid *builtin_sid;
	int mixed_domain;
};


/*
  state associated with a lsa_OpenAccount() operation
*/
struct lsa_account_state {
	struct lsa_policy_state *policy;
	uint32_t access_mask;
	struct dom_sid *account_sid;
};


/*
  state associated with a lsa_OpenSecret() operation
*/
struct lsa_secret_state {
	struct lsa_policy_state *policy;
	uint32_t access_mask;
	struct ldb_dn *secret_dn;
	struct ldb_context *sam_ldb;
	BOOL global;
};

/*
  state associated with a lsa_OpenTrustedDomain() operation
*/
struct lsa_trusted_domain_state {
	struct lsa_policy_state *policy;
	uint32_t access_mask;
	struct ldb_dn *trusted_domain_dn;
};

static NTSTATUS dcesrv_lsa_EnumAccountRights(struct dcesrv_call_state *dce_call, 
				      TALLOC_CTX *mem_ctx,
				      struct lsa_EnumAccountRights *r);

static NTSTATUS dcesrv_lsa_AddRemoveAccountRights(struct dcesrv_call_state *dce_call, 
					   TALLOC_CTX *mem_ctx,
					   struct lsa_policy_state *state,
					   int ldb_flag,
					   struct dom_sid *sid,
					   const struct lsa_RightSet *rights);

/* 
  lsa_Close 
*/
static NTSTATUS dcesrv_lsa_Close(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			  struct lsa_Close *r)
{
	struct dcesrv_handle *h;

	*r->out.handle = *r->in.handle;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);

	talloc_free(h);

	ZERO_STRUCTP(r->out.handle);

	return NT_STATUS_OK;
}


/* 
  lsa_Delete 
*/
static NTSTATUS dcesrv_lsa_Delete(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			   struct lsa_Delete *r)
{
	struct dcesrv_handle *h;
	int ret;

	DCESRV_PULL_HANDLE(h, r->in.handle, DCESRV_HANDLE_ANY);
	if (h->wire_handle.handle_type == LSA_HANDLE_SECRET) {
		struct lsa_secret_state *secret_state = h->data;
		ret = samdb_delete(secret_state->sam_ldb, mem_ctx, secret_state->secret_dn);
		talloc_free(h);
		if (ret != 0) {
			return NT_STATUS_INVALID_HANDLE;
		}

		return NT_STATUS_OK;
	} else if (h->wire_handle.handle_type == LSA_HANDLE_TRUSTED_DOMAIN) {
		struct lsa_trusted_domain_state *trusted_domain_state = h->data;
		ret = samdb_delete(trusted_domain_state->policy->sam_ldb, mem_ctx, 
				   trusted_domain_state->trusted_domain_dn);
		talloc_free(h);
		if (ret != 0) {
			return NT_STATUS_INVALID_HANDLE;
		}

		return NT_STATUS_OK;
	} else if (h->wire_handle.handle_type == LSA_HANDLE_ACCOUNT) {
		struct lsa_RightSet *rights;
		struct lsa_account_state *astate;
		struct lsa_EnumAccountRights r2;
		NTSTATUS status;

		rights = talloc(mem_ctx, struct lsa_RightSet);

		DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_ACCOUNT);
		
		astate = h->data;

		r2.in.handle = &astate->policy->handle->wire_handle;
		r2.in.sid = astate->account_sid;
		r2.out.rights = rights;

		status = dcesrv_lsa_EnumAccountRights(dce_call, mem_ctx, &r2);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			return NT_STATUS_OK;
		}

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, astate->policy, 
						    LDB_FLAG_MOD_DELETE, astate->account_sid,
						    r2.out.rights);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			return NT_STATUS_OK;
		}

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} 
	
	return NT_STATUS_INVALID_HANDLE;
}


/* 
  lsa_EnumPrivs 
*/
static NTSTATUS dcesrv_lsa_EnumPrivs(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
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

		r->out.privs->privs = talloc_realloc(r->out.privs,
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

	*r->out.resume_handle = i;

	return NT_STATUS_OK;
}


/* 
  lsa_QuerySecObj 
*/
static NTSTATUS dcesrv_lsa_QuerySecurity(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_QuerySecurity *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_SetSecObj 
*/
static NTSTATUS dcesrv_lsa_SetSecObj(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct lsa_SetSecObj *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_ChangePassword 
*/
static NTSTATUS dcesrv_lsa_ChangePassword(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				   struct lsa_ChangePassword *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

static NTSTATUS dcesrv_lsa_get_policy_state(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct lsa_policy_state **_state)
{
	struct lsa_policy_state *state;
	struct ldb_dn *partitions_basedn;
	struct ldb_result *dom_res;
	const char *dom_attrs[] = {
		"objectSid", 
		"objectGUID", 
		"nTMixedDomain",
		"fSMORoleOwner",
		NULL
	};
	struct ldb_result *ref_res;
	struct ldb_result *forest_ref_res;
	const char *ref_attrs[] = {
		"nETBIOSName",
		"dnsRoot",
		NULL
	};
	int ret;

	state = talloc(mem_ctx, struct lsa_policy_state);
	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}

	/* make sure the sam database is accessible */
	state->sam_ldb = samdb_connect(state, dce_call->conn->auth_state.session_info); 
	if (state->sam_ldb == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	partitions_basedn = samdb_partitions_dn(state->sam_ldb, mem_ctx);

	state->sidmap = sidmap_open(state);
	if (state->sidmap == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* work out the domain_dn - useful for so many calls its worth
	   fetching here */
	state->domain_dn = samdb_base_dn(state->sam_ldb);
	if (!state->domain_dn) {
		return NT_STATUS_NO_MEMORY;		
	}

	/* work out the forest root_dn - useful for so many calls its worth
	   fetching here */
	state->forest_dn = samdb_root_dn(state->sam_ldb);
	if (!state->forest_dn) {
		return NT_STATUS_NO_MEMORY;		
	}

	ret = ldb_search(state->sam_ldb, state->domain_dn, LDB_SCOPE_BASE, NULL, dom_attrs, &dom_res);
	
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}
	talloc_steal(mem_ctx, dom_res);
	if (dom_res->count != 1) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->domain_sid = samdb_result_dom_sid(state, dom_res->msgs[0], "objectSid");
	if (!state->domain_sid) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->domain_guid = samdb_result_guid(dom_res->msgs[0], "objectGUID");
	if (!state->domain_sid) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->mixed_domain = ldb_msg_find_attr_as_uint(dom_res->msgs[0], "nTMixedDomain", 0);
	
	talloc_free(dom_res);

	ret = ldb_search_exp_fmt(state->sam_ldb, state, &ref_res,
				 partitions_basedn, LDB_SCOPE_SUBTREE, ref_attrs,
				 "(&(objectclass=crossRef)(ncName=%s))",
				 ldb_dn_get_linearized(state->domain_dn));
	
	if (ret != LDB_SUCCESS) {
		talloc_free(ref_res);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}
	if (ref_res->count != 1) {
		talloc_free(ref_res);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->domain_name = ldb_msg_find_attr_as_string(ref_res->msgs[0], "nETBIOSName", NULL);
	if (!state->domain_name) {
		talloc_free(ref_res);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}
	talloc_steal(state, state->domain_name);

	state->domain_dns = ldb_msg_find_attr_as_string(ref_res->msgs[0], "dnsRoot", NULL);
	if (!state->domain_dns) {
		talloc_free(ref_res);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}
	talloc_steal(state, state->domain_dns);

	talloc_free(ref_res);

	ret = ldb_search_exp_fmt(state->sam_ldb, state, &forest_ref_res,
				 partitions_basedn, LDB_SCOPE_SUBTREE, ref_attrs,
				 "(&(objectclass=crossRef)(ncName=%s))",
				 ldb_dn_get_linearized(state->forest_dn));
	
	if (ret != LDB_SUCCESS) {
		talloc_free(forest_ref_res);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}
	if (forest_ref_res->count != 1) {
		talloc_free(forest_ref_res);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->forest_dns = ldb_msg_find_attr_as_string(forest_ref_res->msgs[0], "dnsRoot", NULL);
	if (!state->forest_dns) {
		talloc_free(forest_ref_res);
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}
	talloc_steal(state, state->forest_dns);

	talloc_free(forest_ref_res);

	/* work out the builtin_dn - useful for so many calls its worth
	   fetching here */
	state->builtin_dn = samdb_search_dn(state->sam_ldb, state, state->domain_dn, "(objectClass=builtinDomain)");
	if (!state->builtin_dn) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	/* work out the system_dn - useful for so many calls its worth
	   fetching here */
	state->system_dn = samdb_search_dn(state->sam_ldb, state,
					   state->domain_dn, "(&(objectClass=container)(cn=System))");
	if (!state->system_dn) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->builtin_sid = dom_sid_parse_talloc(state, SID_BUILTIN);
	if (!state->builtin_sid) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	*_state = state;

	return NT_STATUS_OK;
}

/* 
  dssetup_DsRoleGetPrimaryDomainInformation 

  This is not an LSA call, but is the only call left on the DSSETUP
  pipe (after the pipe was truncated), and needs lsa_get_policy_state
*/
static WERROR dcesrv_dssetup_DsRoleGetPrimaryDomainInformation(struct dcesrv_call_state *dce_call, 
						 TALLOC_CTX *mem_ctx,
						 struct dssetup_DsRoleGetPrimaryDomainInformation *r)
{
	union dssetup_DsRoleInfo *info;

	info = talloc(mem_ctx, union dssetup_DsRoleInfo);
	W_ERROR_HAVE_NO_MEMORY(info);

	switch (r->in.level) {
	case DS_ROLE_BASIC_INFORMATION:
	{
		enum dssetup_DsRole role = DS_ROLE_STANDALONE_SERVER;
		uint32_t flags = 0;
		const char *domain = NULL;
		const char *dns_domain = NULL;
		const char *forest = NULL;
		struct GUID domain_guid;
		struct lsa_policy_state *state;

		NTSTATUS status = dcesrv_lsa_get_policy_state(dce_call, mem_ctx, &state);
		if (!NT_STATUS_IS_OK(status)) {
			return ntstatus_to_werror(status);
		}

		ZERO_STRUCT(domain_guid);

		switch (lp_server_role()) {
		case ROLE_STANDALONE:
			role		= DS_ROLE_STANDALONE_SERVER;
			break;
		case ROLE_DOMAIN_MEMBER:
			role		= DS_ROLE_MEMBER_SERVER;
			break;
		case ROLE_DOMAIN_CONTROLLER:
			if (samdb_is_pdc(state->sam_ldb)) {
				role	= DS_ROLE_PRIMARY_DC;
			} else {
				role    = DS_ROLE_BACKUP_DC;
			}
			break;
		}

		switch (lp_server_role()) {
		case ROLE_STANDALONE:
			domain		= talloc_strdup(mem_ctx, lp_workgroup());
			W_ERROR_HAVE_NO_MEMORY(domain);
			break;
		case ROLE_DOMAIN_MEMBER:
			domain		= talloc_strdup(mem_ctx, lp_workgroup());
			W_ERROR_HAVE_NO_MEMORY(domain);
			/* TODO: what is with dns_domain and forest and guid? */
			break;
		case ROLE_DOMAIN_CONTROLLER:
			flags		= DS_ROLE_PRIMARY_DS_RUNNING;

			if (state->mixed_domain == 1) {
				flags	|= DS_ROLE_PRIMARY_DS_MIXED_MODE;
			}
			
			domain		= state->domain_name;
			dns_domain	= state->domain_dns;
			forest		= state->forest_dns;

			domain_guid	= state->domain_guid;
			flags	|= DS_ROLE_PRIMARY_DOMAIN_GUID_PRESENT;
			break;
		}

		info->basic.role        = role; 
		info->basic.flags       = flags;
		info->basic.domain      = domain;
		info->basic.dns_domain  = dns_domain;
		info->basic.forest      = forest;
		info->basic.domain_guid = domain_guid;

		r->out.info = info;
		return WERR_OK;
	}
	case DS_ROLE_UPGRADE_STATUS:
	{
		info->upgrade.upgrading     = DS_ROLE_NOT_UPGRADING;
		info->upgrade.previous_role = DS_ROLE_PREVIOUS_UNKNOWN;

		r->out.info = info;
		return WERR_OK;
	}
	case DS_ROLE_OP_STATUS:
	{
		info->opstatus.status = DS_ROLE_OP_IDLE;

		r->out.info = info;
		return WERR_OK;
	}
	default:
		return WERR_INVALID_PARAM;
	}

	return WERR_INVALID_PARAM;
}

/* 
  lsa_OpenPolicy2
*/
static NTSTATUS dcesrv_lsa_OpenPolicy2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct lsa_OpenPolicy2 *r)
{
	NTSTATUS status;
	struct lsa_policy_state *state;
	struct dcesrv_handle *handle;

	ZERO_STRUCTP(r->out.handle);

	status = dcesrv_lsa_get_policy_state(dce_call, mem_ctx, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_POLICY);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = talloc_steal(handle, state);

	state->access_mask = r->in.access_mask;
	state->handle = handle;
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
static NTSTATUS dcesrv_lsa_OpenPolicy(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_OpenPolicy *r)
{
	struct lsa_OpenPolicy2 r2;

	r2.in.system_name = NULL;
	r2.in.attr = r->in.attr;
	r2.in.access_mask = r->in.access_mask;
	r2.out.handle = r->out.handle;

	return dcesrv_lsa_OpenPolicy2(dce_call, mem_ctx, &r2);
}




/*
  fill in the AccountDomain info
*/
static NTSTATUS dcesrv_lsa_info_AccountDomain(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
				       struct lsa_DomainInfo *info)
{
	info->name.string = state->domain_name;
	info->sid         = state->domain_sid;

	return NT_STATUS_OK;
}

/*
  fill in the DNS domain info
*/
static NTSTATUS dcesrv_lsa_info_DNS(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
			     struct lsa_DnsDomainInfo *info)
{
	info->name.string = state->domain_name;
	info->sid         = state->domain_sid;
	info->dns_domain.string = state->domain_dns;
	info->dns_forest.string = state->forest_dns;
	info->domain_guid       = state->domain_guid;

	return NT_STATUS_OK;
}

/* 
  lsa_QueryInfoPolicy2
*/
static NTSTATUS dcesrv_lsa_QueryInfoPolicy2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				     struct lsa_QueryInfoPolicy2 *r)
{
	struct lsa_policy_state *state;
	struct dcesrv_handle *h;

	r->out.info = NULL;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	r->out.info = talloc(mem_ctx, union lsa_PolicyInformation);
	if (!r->out.info) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCTP(r->out.info);

	switch (r->in.level) {
	case LSA_POLICY_INFO_DOMAIN:
	case LSA_POLICY_INFO_ACCOUNT_DOMAIN:
		return dcesrv_lsa_info_AccountDomain(state, mem_ctx, &r->out.info->account_domain);

	case LSA_POLICY_INFO_DNS:
		return dcesrv_lsa_info_DNS(state, mem_ctx, &r->out.info->dns);
	}

	return NT_STATUS_INVALID_INFO_CLASS;
}

/* 
  lsa_QueryInfoPolicy 
*/
static NTSTATUS dcesrv_lsa_QueryInfoPolicy(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				    struct lsa_QueryInfoPolicy *r)
{
	struct lsa_QueryInfoPolicy2 r2;
	NTSTATUS status;

	r2.in.handle = r->in.handle;
	r2.in.level = r->in.level;
	
	status = dcesrv_lsa_QueryInfoPolicy2(dce_call, mem_ctx, &r2);

	r->out.info = r2.out.info;

	return status;
}

/* 
  lsa_SetInfoPolicy 
*/
static NTSTATUS dcesrv_lsa_SetInfoPolicy(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_SetInfoPolicy *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_ClearAuditLog 
*/
static NTSTATUS dcesrv_lsa_ClearAuditLog(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_ClearAuditLog *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CreateAccount 
*/
static NTSTATUS dcesrv_lsa_CreateAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct lsa_CreateAccount *r)
{
	struct lsa_account_state *astate;

	struct lsa_policy_state *state;
	struct dcesrv_handle *h, *ah;

	ZERO_STRUCTP(r->out.acct_handle);

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	astate = talloc(dce_call->conn, struct lsa_account_state);
	if (astate == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	astate->account_sid = dom_sid_dup(astate, r->in.sid);
	if (astate->account_sid == NULL) {
		talloc_free(astate);
		return NT_STATUS_NO_MEMORY;
	}
	
	astate->policy = talloc_reference(astate, state);
	astate->access_mask = r->in.access_mask;

	ah = dcesrv_handle_new(dce_call->context, LSA_HANDLE_ACCOUNT);
	if (!ah) {
		talloc_free(astate);
		return NT_STATUS_NO_MEMORY;
	}

	ah->data = talloc_steal(ah, astate);

	*r->out.acct_handle = ah->wire_handle;

	return NT_STATUS_OK;
}


/* 
  lsa_EnumAccounts 
*/
static NTSTATUS dcesrv_lsa_EnumAccounts(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct lsa_EnumAccounts *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;
	int ret, i;
	struct ldb_message **res;
	const char * const attrs[] = { "objectSid", NULL};
	uint32_t count;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	/* NOTE: This call must only return accounts that have at least
	   one privilege set 
	*/
	ret = gendb_search(state->sam_ldb, mem_ctx, NULL, &res, attrs, 
			   "(&(objectSid=*)(privilege=*))");
	if (ret < 0) {
		return NT_STATUS_NO_SUCH_USER;
	}

	if (*r->in.resume_handle >= ret) {
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	count = ret - *r->in.resume_handle;
	if (count > r->in.num_entries) {
		count = r->in.num_entries;
	}

	if (count == 0) {
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	r->out.sids->sids = talloc_array(r->out.sids, struct lsa_SidPtr, count);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<count;i++) {
		r->out.sids->sids[i].sid = 
			samdb_result_dom_sid(r->out.sids->sids, 
					     res[i + *r->in.resume_handle],
					     "objectSid");
		NT_STATUS_HAVE_NO_MEMORY(r->out.sids->sids[i].sid);
	}

	r->out.sids->num_sids = count;
	*r->out.resume_handle = count + *r->in.resume_handle;

	return NT_STATUS_OK;
	
}


/*
  lsa_CreateTrustedDomainEx2
*/
static NTSTATUS dcesrv_lsa_CreateTrustedDomainEx2(struct dcesrv_call_state *dce_call,
					   TALLOC_CTX *mem_ctx,
					   struct lsa_CreateTrustedDomainEx2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_CreateTrustedDomainEx
*/
static NTSTATUS dcesrv_lsa_CreateTrustedDomainEx(struct dcesrv_call_state *dce_call,
					  TALLOC_CTX *mem_ctx,
					  struct lsa_CreateTrustedDomainEx *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/* 
  lsa_CreateTrustedDomain 
*/
static NTSTATUS dcesrv_lsa_CreateTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct lsa_CreateTrustedDomain *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_policy_state *policy_state;
	struct lsa_trusted_domain_state *trusted_domain_state;
	struct dcesrv_handle *handle;
	struct ldb_message **msgs, *msg;
	const char *attrs[] = {
		NULL
	};
	const char *name;
	int ret;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.trustdom_handle);
	
	policy_state = policy_handle->data;

	if (!r->in.info->name.string) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	name = r->in.info->name.string;
	
	trusted_domain_state = talloc(mem_ctx, struct lsa_trusted_domain_state);
	if (!trusted_domain_state) {
		return NT_STATUS_NO_MEMORY;
	}
	trusted_domain_state->policy = policy_state;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* search for the trusted_domain record */
	ret = gendb_search(trusted_domain_state->policy->sam_ldb,
			   mem_ctx, policy_state->system_dn, &msgs, attrs,
			   "(&(cn=%s)(objectclass=trustedDomain))", 
			   ldb_binary_encode_string(mem_ctx, r->in.info->name.string));
	if (ret > 0) {
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}
	
	if (ret < 0 || ret > 1) {
		DEBUG(0,("Found %d records matching DN %s\n", ret,
			 ldb_dn_get_linearized(policy_state->system_dn)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	
	msg->dn = ldb_dn_copy(mem_ctx, policy_state->system_dn);
	if ( ! ldb_dn_add_child_fmt(msg->dn, "cn=%s", name)) {
		return NT_STATUS_NO_MEMORY;
	}
	
	samdb_msg_add_string(trusted_domain_state->policy->sam_ldb, mem_ctx, msg, "flatname", name);

	if (r->in.info->sid) {
		const char *sid_string = dom_sid_string(mem_ctx, r->in.info->sid);
		if (!sid_string) {
			return NT_STATUS_NO_MEMORY;
		}
			
		samdb_msg_add_string(trusted_domain_state->policy->sam_ldb, mem_ctx, msg, "securityIdentifier", sid_string);
	}

	samdb_msg_add_string(trusted_domain_state->policy->sam_ldb, mem_ctx, msg, "objectClass", "trustedDomain");
	
	trusted_domain_state->trusted_domain_dn = talloc_reference(trusted_domain_state, msg->dn);

	/* create the trusted_domain */
	ret = ldb_add(trusted_domain_state->policy->sam_ldb, msg);
	if (ret != LDB_SUCCESS) {
		DEBUG(0,("Failed to create trusted_domain record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn), ldb_errstring(trusted_domain_state->policy->sam_ldb)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_TRUSTED_DOMAIN);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}
	
	handle->data = talloc_steal(handle, trusted_domain_state);
	
	trusted_domain_state->access_mask = r->in.access_mask;
	trusted_domain_state->policy = talloc_reference(trusted_domain_state, policy_state);
	
	*r->out.trustdom_handle = handle->wire_handle;
	
	return NT_STATUS_OK;
}

/* 
  lsa_OpenTrustedDomain
*/
static NTSTATUS dcesrv_lsa_OpenTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct lsa_OpenTrustedDomain *r)
{
	struct dcesrv_handle *policy_handle;
	
	struct lsa_policy_state *policy_state;
	struct lsa_trusted_domain_state *trusted_domain_state;
	struct dcesrv_handle *handle;
	struct ldb_message **msgs;
	const char *attrs[] = {
		NULL
	};

	const char *sid_string;
	int ret;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.trustdom_handle);
	policy_state = policy_handle->data;

	trusted_domain_state = talloc(mem_ctx, struct lsa_trusted_domain_state);
	if (!trusted_domain_state) {
		return NT_STATUS_NO_MEMORY;
	}
	trusted_domain_state->policy = policy_state;

	sid_string = dom_sid_string(mem_ctx, r->in.sid);
	if (!sid_string) {
		return NT_STATUS_NO_MEMORY;
	}

	/* search for the trusted_domain record */
	ret = gendb_search(trusted_domain_state->policy->sam_ldb,
			   mem_ctx, policy_state->system_dn, &msgs, attrs,
			   "(&(securityIdentifier=%s)(objectclass=trustedDomain))", 
			   sid_string);
	if (ret == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	
	if (ret != 1) {
		DEBUG(0,("Found %d records matching DN %s\n", ret,
			 ldb_dn_get_linearized(policy_state->system_dn)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	trusted_domain_state->trusted_domain_dn = talloc_reference(trusted_domain_state, msgs[0]->dn);
	
	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_TRUSTED_DOMAIN);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}
	
	handle->data = talloc_steal(handle, trusted_domain_state);
	
	trusted_domain_state->access_mask = r->in.access_mask;
	trusted_domain_state->policy = talloc_reference(trusted_domain_state, policy_state);
	
	*r->out.trustdom_handle = handle->wire_handle;
	
	return NT_STATUS_OK;
}


/*
  lsa_OpenTrustedDomainByName
*/
static NTSTATUS dcesrv_lsa_OpenTrustedDomainByName(struct dcesrv_call_state *dce_call,
					    TALLOC_CTX *mem_ctx,
					    struct lsa_OpenTrustedDomainByName *r)
{
	struct dcesrv_handle *policy_handle;
	
	struct lsa_policy_state *policy_state;
	struct lsa_trusted_domain_state *trusted_domain_state;
	struct dcesrv_handle *handle;
	struct ldb_message **msgs;
	const char *attrs[] = {
		NULL
	};

	int ret;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.trustdom_handle);
	policy_state = policy_handle->data;

	if (!r->in.name.string) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	trusted_domain_state = talloc(mem_ctx, struct lsa_trusted_domain_state);
	if (!trusted_domain_state) {
		return NT_STATUS_NO_MEMORY;
	}
	trusted_domain_state->policy = policy_state;

	/* search for the trusted_domain record */
	ret = gendb_search(trusted_domain_state->policy->sam_ldb,
			   mem_ctx, policy_state->system_dn, &msgs, attrs,
			   "(&(flatname=%s)(objectclass=trustedDomain))", 
			   ldb_binary_encode_string(mem_ctx, r->in.name.string));
	if (ret == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	
	if (ret != 1) {
		DEBUG(0,("Found %d records matching DN %s\n", ret,
			 ldb_dn_get_linearized(policy_state->system_dn)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	trusted_domain_state->trusted_domain_dn = talloc_reference(trusted_domain_state, msgs[0]->dn);
	
	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_TRUSTED_DOMAIN);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}
	
	handle->data = talloc_steal(handle, trusted_domain_state);
	
	trusted_domain_state->access_mask = r->in.access_mask;
	trusted_domain_state->policy = talloc_reference(trusted_domain_state, policy_state);
	
	*r->out.trustdom_handle = handle->wire_handle;
	
	return NT_STATUS_OK;
}



/* 
  lsa_SetTrustedDomainInfo
*/
static NTSTATUS dcesrv_lsa_SetTrustedDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					 struct lsa_SetTrustedDomainInfo *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}



/* 
  lsa_SetInfomrationTrustedDomain
*/
static NTSTATUS dcesrv_lsa_SetInformationTrustedDomain(struct dcesrv_call_state *dce_call, 
						TALLOC_CTX *mem_ctx,
						struct lsa_SetInformationTrustedDomain *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_DeleteTrustedDomain
*/
static NTSTATUS dcesrv_lsa_DeleteTrustedDomain(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				      struct lsa_DeleteTrustedDomain *r)
{
	NTSTATUS status;
	struct lsa_OpenTrustedDomain open;
	struct lsa_Delete delete;
	struct dcesrv_handle *h;

	open.in.handle = r->in.handle;
	open.in.sid = r->in.dom_sid;
	open.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	open.out.trustdom_handle = talloc(mem_ctx, struct policy_handle);
	if (!open.out.trustdom_handle) {
		return NT_STATUS_NO_MEMORY;
	}
	status = dcesrv_lsa_OpenTrustedDomain(dce_call, mem_ctx, &open);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	DCESRV_PULL_HANDLE(h, open.out.trustdom_handle, DCESRV_HANDLE_ANY);
	talloc_steal(mem_ctx, h);

	delete.in.handle = open.out.trustdom_handle;
	status = dcesrv_lsa_Delete(dce_call, mem_ctx, &delete);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return NT_STATUS_OK;
}

static NTSTATUS fill_trust_domain_ex(TALLOC_CTX *mem_ctx, 
				     struct ldb_message *msg, 
				     struct lsa_TrustDomainInfoInfoEx *info_ex) 
{
	info_ex->domain_name.string
		= ldb_msg_find_attr_as_string(msg, "trustPartner", NULL);
	info_ex->netbios_name.string
		= ldb_msg_find_attr_as_string(msg, "flatname", NULL);
	info_ex->sid 
		= samdb_result_dom_sid(mem_ctx, msg, "securityIdentifier");
	info_ex->trust_direction
		= ldb_msg_find_attr_as_int(msg, "trustDirection", 0);
	info_ex->trust_type
		= ldb_msg_find_attr_as_int(msg, "trustType", 0);
	info_ex->trust_attributes
		= ldb_msg_find_attr_as_int(msg, "trustAttributes", 0);	
	return NT_STATUS_OK;
}

/* 
  lsa_QueryTrustedDomainInfo
*/
static NTSTATUS dcesrv_lsa_QueryTrustedDomainInfo(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					   struct lsa_QueryTrustedDomainInfo *r)
{
	struct dcesrv_handle *h;
	struct lsa_trusted_domain_state *trusted_domain_state;
	struct ldb_message *msg;
	int ret;
	struct ldb_message **res;
	const char *attrs[] = {
		"flatname", 
		"trustPartner",
		"securityIdentifier",
		"trustDirection",
		"trustType",
		"trustAttributes", 
		NULL
	};

	DCESRV_PULL_HANDLE(h, r->in.trustdom_handle, LSA_HANDLE_TRUSTED_DOMAIN);

	trusted_domain_state = h->data;

	/* pull all the user attributes */
	ret = gendb_search_dn(trusted_domain_state->policy->sam_ldb, mem_ctx,
			      trusted_domain_state->trusted_domain_dn, &res, attrs);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];
	
	r->out.info = talloc(mem_ctx, union lsa_TrustedDomainInfo);
	if (!r->out.info) {
		return NT_STATUS_NO_MEMORY;
	}
	switch (r->in.level) {
	case LSA_TRUSTED_DOMAIN_INFO_NAME:
		r->out.info->name.netbios_name.string
			= samdb_result_string(msg, "flatname", NULL);					   
		break;
	case LSA_TRUSTED_DOMAIN_INFO_POSIX_OFFSET:
		r->out.info->posix_offset.posix_offset
			= samdb_result_uint(msg, "posixOffset", 0);					   
		break;
#if 0  /* Win2k3 doesn't implement this */
	case LSA_TRUSTED_DOMAIN_INFO_BASIC:
		r->out.info->info_basic.netbios_name.string 
			= ldb_msg_find_attr_as_string(msg, "flatname", NULL);
		r->out.info->info_basic.sid
			= samdb_result_dom_sid(mem_ctx, msg, "securityIdentifier");
		break;
#endif
	case LSA_TRUSTED_DOMAIN_INFO_INFO_EX:
		return fill_trust_domain_ex(mem_ctx, msg, &r->out.info->info_ex);

	case LSA_TRUSTED_DOMAIN_INFO_FULL_INFO:
		ZERO_STRUCT(r->out.info->full_info);
		return fill_trust_domain_ex(mem_ctx, msg, &r->out.info->full_info.info_ex);

	case LSA_TRUSTED_DOMAIN_INFO_INFO_ALL:
		ZERO_STRUCT(r->out.info->info_all);
		return fill_trust_domain_ex(mem_ctx, msg, &r->out.info->info_all.info_ex);

	case LSA_TRUSTED_DOMAIN_INFO_CONTROLLERS_INFO:
	case LSA_TRUSTED_DOMAIN_INFO_11:
		/* oops, we don't want to return the info after all */
		talloc_free(r->out.info);
		r->out.info = NULL;
		return NT_STATUS_INVALID_PARAMETER;
	default:
		/* oops, we don't want to return the info after all */
		talloc_free(r->out.info);
		r->out.info = NULL;
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	return NT_STATUS_OK;
}


/* 
  lsa_QueryTrustedDomainInfoBySid
*/
static NTSTATUS dcesrv_lsa_QueryTrustedDomainInfoBySid(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct lsa_QueryTrustedDomainInfoBySid *r)
{
	NTSTATUS status;
	struct lsa_OpenTrustedDomain open;
	struct lsa_QueryTrustedDomainInfo query;
	struct dcesrv_handle *h;
	open.in.handle = r->in.handle;
	open.in.sid = r->in.dom_sid;
	open.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	open.out.trustdom_handle = talloc(mem_ctx, struct policy_handle);
	if (!open.out.trustdom_handle) {
		return NT_STATUS_NO_MEMORY;
	}
	status = dcesrv_lsa_OpenTrustedDomain(dce_call, mem_ctx, &open);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Ensure this handle goes away at the end of this call */
	DCESRV_PULL_HANDLE(h, open.out.trustdom_handle, DCESRV_HANDLE_ANY);
	talloc_steal(mem_ctx, h);
	
	query.in.trustdom_handle = open.out.trustdom_handle;
	query.in.level = r->in.level;
	status = dcesrv_lsa_QueryTrustedDomainInfo(dce_call, mem_ctx, &query);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	r->out.info = query.out.info;
	return NT_STATUS_OK;
}

/*
  lsa_SetTrustedDomainInfoByName
*/
static NTSTATUS dcesrv_lsa_SetTrustedDomainInfoByName(struct dcesrv_call_state *dce_call,
					       TALLOC_CTX *mem_ctx,
					       struct lsa_SetTrustedDomainInfoByName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/* 
   lsa_QueryTrustedDomainInfoByName
*/
static NTSTATUS dcesrv_lsa_QueryTrustedDomainInfoByName(struct dcesrv_call_state *dce_call,
						 TALLOC_CTX *mem_ctx,
						 struct lsa_QueryTrustedDomainInfoByName *r)
{
	NTSTATUS status;
	struct lsa_OpenTrustedDomainByName open;
	struct lsa_QueryTrustedDomainInfo query;
	struct dcesrv_handle *h;
	open.in.handle = r->in.handle;
	open.in.name = r->in.trusted_domain;
	open.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	open.out.trustdom_handle = talloc(mem_ctx, struct policy_handle);
	if (!open.out.trustdom_handle) {
		return NT_STATUS_NO_MEMORY;
	}
	status = dcesrv_lsa_OpenTrustedDomainByName(dce_call, mem_ctx, &open);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	/* Ensure this handle goes away at the end of this call */
	DCESRV_PULL_HANDLE(h, open.out.trustdom_handle, DCESRV_HANDLE_ANY);
	talloc_steal(mem_ctx, h);

	query.in.trustdom_handle = open.out.trustdom_handle;
	query.in.level = r->in.level;
	status = dcesrv_lsa_QueryTrustedDomainInfo(dce_call, mem_ctx, &query);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	r->out.info = query.out.info;
	return NT_STATUS_OK;
}

/*
  lsa_CloseTrustedDomainEx 
*/
static NTSTATUS dcesrv_lsa_CloseTrustedDomainEx(struct dcesrv_call_state *dce_call,
					 TALLOC_CTX *mem_ctx,
					 struct lsa_CloseTrustedDomainEx *r)
{
	/* The result of a bad hair day from an IDL programmer?  Not
	 * implmented in Win2k3.  You should always just lsa_Close
	 * anyway. */
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  comparison function for sorting lsa_DomainInformation array
*/
static int compare_DomainInfo(struct lsa_DomainInfo *e1, struct lsa_DomainInfo *e2)
{
	return strcasecmp_m(e1->name.string, e2->name.string);
}

/* 
  lsa_EnumTrustDom 
*/
static NTSTATUS dcesrv_lsa_EnumTrustDom(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct lsa_EnumTrustDom *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_DomainInfo *entries;
	struct lsa_policy_state *policy_state;
	struct ldb_message **domains;
	const char *attrs[] = {
		"flatname", 
		"securityIdentifier",
		NULL
	};


	int count, i;

	*r->out.resume_handle = 0;

	r->out.domains->domains = NULL;
	r->out.domains->count = 0;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	policy_state = policy_handle->data;

	/* search for all users in this domain. This could possibly be cached and 
	   resumed based on resume_key */
	count = gendb_search(policy_state->sam_ldb, mem_ctx, policy_state->system_dn, &domains, attrs, 
			     "objectclass=trustedDomain");
	if (count == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (count == 0 || r->in.max_size == 0) {
		return NT_STATUS_OK;
	}

	/* convert to lsa_TrustInformation format */
	entries = talloc_array(mem_ctx, struct lsa_DomainInfo, count);
	if (!entries) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<count;i++) {
		entries[i].sid = samdb_result_dom_sid(mem_ctx, domains[i], "securityIdentifier");
		entries[i].name.string = samdb_result_string(domains[i], "flatname", NULL);
	}

	/* sort the results by name */
	qsort(entries, count, sizeof(*entries), 
	      (comparison_fn_t)compare_DomainInfo);

	if (*r->in.resume_handle >= count) {
		*r->out.resume_handle = -1;

		return NT_STATUS_NO_MORE_ENTRIES;
	}

	/* return the rest, limit by max_size. Note that we 
	   use the w2k3 element size value of 60 */
	r->out.domains->count = count - *r->in.resume_handle;
	r->out.domains->count = MIN(r->out.domains->count, 
				 1+(r->in.max_size/LSA_ENUM_TRUST_DOMAIN_MULTIPLIER));

	r->out.domains->domains = entries + *r->in.resume_handle;
	r->out.domains->count = r->out.domains->count;

	if (r->out.domains->count < count - *r->in.resume_handle) {
		*r->out.resume_handle = *r->in.resume_handle + r->out.domains->count;
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}

/*
  comparison function for sorting lsa_DomainInformation array
*/
static int compare_TrustDomainInfoInfoEx(struct lsa_TrustDomainInfoInfoEx *e1, struct lsa_TrustDomainInfoInfoEx *e2)
{
	return strcasecmp_m(e1->netbios_name.string, e2->netbios_name.string);
}

/* 
  lsa_EnumTrustedDomainsEx 
*/
static NTSTATUS dcesrv_lsa_EnumTrustedDomainsEx(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct lsa_EnumTrustedDomainsEx *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_TrustDomainInfoInfoEx *entries;
	struct lsa_policy_state *policy_state;
	struct ldb_message **domains;
	const char *attrs[] = {
		"flatname", 
		"trustPartner",
		"securityIdentifier",
		"trustDirection",
		"trustType",
		"trustAttributes", 
		NULL
	};
	NTSTATUS nt_status;

	int count, i;

	*r->out.resume_handle = 0;

	r->out.domains->domains = NULL;
	r->out.domains->count = 0;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	policy_state = policy_handle->data;

	/* search for all users in this domain. This could possibly be cached and 
	   resumed based on resume_key */
	count = gendb_search(policy_state->sam_ldb, mem_ctx, policy_state->system_dn, &domains, attrs, 
			     "objectclass=trustedDomain");
	if (count == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (count == 0 || r->in.max_size == 0) {
		return NT_STATUS_OK;
	}

	/* convert to lsa_DomainInformation format */
	entries = talloc_array(mem_ctx, struct lsa_TrustDomainInfoInfoEx, count);
	if (!entries) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<count;i++) {
		nt_status = fill_trust_domain_ex(mem_ctx, domains[i], &entries[i]);
		if (!NT_STATUS_IS_OK(nt_status)) {
			return nt_status;
		}
	}

	/* sort the results by name */
	qsort(entries, count, sizeof(*entries), 
	      (comparison_fn_t)compare_TrustDomainInfoInfoEx);

	if (*r->in.resume_handle >= count) {
		*r->out.resume_handle = -1;

		return NT_STATUS_NO_MORE_ENTRIES;
	}

	/* return the rest, limit by max_size. Note that we 
	   use the w2k3 element size value of 60 */
	r->out.domains->count = count - *r->in.resume_handle;
	r->out.domains->count = MIN(r->out.domains->count, 
				 1+(r->in.max_size/LSA_ENUM_TRUST_DOMAIN_EX_MULTIPLIER));

	r->out.domains->domains = entries + *r->in.resume_handle;
	r->out.domains->count = r->out.domains->count;

	if (r->out.domains->count < count - *r->in.resume_handle) {
		*r->out.resume_handle = *r->in.resume_handle + r->out.domains->count;
		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}


/*
  return the authority name and authority sid, given a sid
*/
static NTSTATUS dcesrv_lsa_authority_name(struct lsa_policy_state *state,
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
static NTSTATUS dcesrv_lsa_authority_list(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx, 
				   struct dom_sid *sid, 
				   struct lsa_RefDomainList *domains,
				   uint32_t *sid_index)
{
	NTSTATUS status;
	const char *authority_name;
	struct dom_sid *authority_sid;
	int i;

	/* work out the authority name */
	status = dcesrv_lsa_authority_name(state, mem_ctx, sid, 
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

	domains->domains = talloc_realloc(domains, 
					  domains->domains,
					  struct lsa_DomainInfo,
					  domains->count+1);
	if (domains->domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	domains->domains[i].name.string = authority_name;
	domains->domains[i].sid         = authority_sid;
	domains->count++;
	domains->max_size = LSA_REF_DOMAIN_LIST_MULTIPLIER * domains->count;
	*sid_index = i;
	
	return NT_STATUS_OK;
}

/*
  lookup a name for 1 SID
*/
static NTSTATUS dcesrv_lsa_lookup_sid(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
			       struct dom_sid *sid, const char *sid_str,
			       const char **name, uint32_t *atype)
{
	int ret;
	struct ldb_message **res;
	const char * const attrs[] = { "sAMAccountName", "sAMAccountType", "name", NULL};
	NTSTATUS status;

	ret = gendb_search(state->sam_ldb, mem_ctx, NULL, &res, attrs, 
			   "objectSid=%s", ldap_encode_ndr_dom_sid(mem_ctx, sid));
	if (ret == 1) {
		*name = ldb_msg_find_attr_as_string(res[0], "sAMAccountName", NULL);
		if (!*name) {
			*name = ldb_msg_find_attr_as_string(res[0], "name", NULL);
			if (!*name) {
				*name = talloc_strdup(mem_ctx, sid_str);
				NT_STATUS_HAVE_NO_MEMORY(*name);
			}
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
static NTSTATUS dcesrv_lsa_LookupSids2(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx,
				struct lsa_LookupSids2 *r)
{
	struct lsa_policy_state *state;
	int i;
	NTSTATUS status = NT_STATUS_OK;

	r->out.domains = NULL;

	status = dcesrv_lsa_get_policy_state(dce_call, mem_ctx, &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	r->out.domains = talloc_zero(mem_ctx,  struct lsa_RefDomainList);
	if (r->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.names = talloc_zero(mem_ctx,  struct lsa_TransNameArray2);
	if (r->out.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*r->out.count = 0;

	r->out.names->names = talloc_array(r->out.names, struct lsa_TranslatedName2, 
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
		status2 = dcesrv_lsa_authority_list(state, mem_ctx, sid, r->out.domains, &sid_index);
		if (!NT_STATUS_IS_OK(status2)) {
			return status2;
		}

		status2 = dcesrv_lsa_lookup_sid(state, mem_ctx, sid, sid_str, 
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
  lsa_LookupSids3

  Identical to LookupSids2, but doesn't take a policy handle
  
*/
static NTSTATUS dcesrv_lsa_LookupSids3(struct dcesrv_call_state *dce_call,
				TALLOC_CTX *mem_ctx,
				struct lsa_LookupSids3 *r)
{
	struct lsa_LookupSids2 r2;
	struct lsa_OpenPolicy2 pol;
	NTSTATUS status;
	struct dcesrv_handle *h;

	/* No policy handle on the wire, so make one up here */
	r2.in.handle = talloc(mem_ctx, struct policy_handle);
	if (!r2.in.handle) {
		return NT_STATUS_NO_MEMORY;
	}

	pol.out.handle = r2.in.handle;
	pol.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	pol.in.attr = NULL;
	pol.in.system_name = NULL;
	status = dcesrv_lsa_OpenPolicy2(dce_call, mem_ctx, &pol);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* ensure this handle goes away at the end of this call */
	DCESRV_PULL_HANDLE(h, r2.in.handle, LSA_HANDLE_POLICY);
	talloc_steal(mem_ctx, h);

	r2.in.sids     = r->in.sids;
	r2.in.names    = r->in.names;
	r2.in.level    = r->in.level;
	r2.in.count    = r->in.count;
	r2.in.unknown1 = r->in.unknown1;
	r2.in.unknown2 = r->in.unknown2;
	r2.out.count   = r->out.count;
	r2.out.names   = r->out.names;

	status = dcesrv_lsa_LookupSids2(dce_call, mem_ctx, &r2);
	if (dce_call->fault_code != 0) {
		return status;
	}

	r->out.domains = r2.out.domains;
	r->out.names   = r2.out.names;
	r->out.count   = r2.out.count;

	return status;
}


/* 
  lsa_LookupSids 
*/
static NTSTATUS dcesrv_lsa_LookupSids(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
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
	r2.out.names   = NULL;

	status = dcesrv_lsa_LookupSids2(dce_call, mem_ctx, &r2);
	if (dce_call->fault_code != 0) {
		return status;
	}

	r->out.domains = r2.out.domains;
	if (!r2.out.names) {
		r->out.names = NULL;
		return status;
	}

	r->out.names = talloc(mem_ctx, struct lsa_TransNameArray);
	if (r->out.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.names->count = r2.out.names->count;
	r->out.names->names = talloc_array(r->out.names, struct lsa_TranslatedName, 
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
  lsa_OpenAccount 
*/
static NTSTATUS dcesrv_lsa_OpenAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_OpenAccount *r)
{
	struct dcesrv_handle *h, *ah;
	struct lsa_policy_state *state;
	struct lsa_account_state *astate;

	ZERO_STRUCTP(r->out.acct_handle);

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	astate = talloc(dce_call->conn, struct lsa_account_state);
	if (astate == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	astate->account_sid = dom_sid_dup(astate, r->in.sid);
	if (astate->account_sid == NULL) {
		talloc_free(astate);
		return NT_STATUS_NO_MEMORY;
	}
	
	astate->policy = talloc_reference(astate, state);
	astate->access_mask = r->in.access_mask;

	ah = dcesrv_handle_new(dce_call->context, LSA_HANDLE_ACCOUNT);
	if (!ah) {
		talloc_free(astate);
		return NT_STATUS_NO_MEMORY;
	}

	ah->data = talloc_steal(ah, astate);

	*r->out.acct_handle = ah->wire_handle;

	return NT_STATUS_OK;
}


/* 
  lsa_EnumPrivsAccount 
*/
static NTSTATUS dcesrv_lsa_EnumPrivsAccount(struct dcesrv_call_state *dce_call, 
				     TALLOC_CTX *mem_ctx,
				     struct lsa_EnumPrivsAccount *r)
{
	struct dcesrv_handle *h;
	struct lsa_account_state *astate;
	int ret, i;
	struct ldb_message **res;
	const char * const attrs[] = { "privilege", NULL};
	struct ldb_message_element *el;
	const char *sidstr;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_ACCOUNT);

	astate = h->data;

	r->out.privs = talloc(mem_ctx, struct lsa_PrivilegeSet);
	r->out.privs->count = 0;
	r->out.privs->unknown = 0;
	r->out.privs->set = NULL;

	sidstr = ldap_encode_ndr_dom_sid(mem_ctx, astate->account_sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = gendb_search(astate->policy->sam_ldb, mem_ctx, NULL, &res, attrs, 
			   "objectSid=%s", sidstr);
	if (ret != 1) {
		return NT_STATUS_OK;
	}

	el = ldb_msg_find_element(res[0], "privilege");
	if (el == NULL || el->num_values == 0) {
		return NT_STATUS_OK;
	}

	r->out.privs->set = talloc_array(r->out.privs, 
					 struct lsa_LUIDAttribute, el->num_values);
	if (r->out.privs->set == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<el->num_values;i++) {
		int id = sec_privilege_id((const char *)el->values[i].data);
		if (id == -1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		r->out.privs->set[i].attribute = 0;
		r->out.privs->set[i].luid.low = id;
		r->out.privs->set[i].luid.high = 0;
	}

	r->out.privs->count = el->num_values;

	return NT_STATUS_OK;
}

/* 
  lsa_EnumAccountRights 
*/
static NTSTATUS dcesrv_lsa_EnumAccountRights(struct dcesrv_call_state *dce_call, 
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

	sidstr = ldap_encode_ndr_dom_sid(mem_ctx, r->in.sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	ret = gendb_search(state->sam_ldb, mem_ctx, NULL, &res, attrs, 
			   "(&(objectSid=%s)(privilege=*))", sidstr);
	if (ret == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (ret > 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (ret == -1) {
		DEBUG(3, ("searching for account rights for SID: %s failed: %s", 
			  dom_sid_string(mem_ctx, r->in.sid),
			  ldb_errstring(state->sam_ldb)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	el = ldb_msg_find_element(res[0], "privilege");
	if (el == NULL || el->num_values == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	r->out.rights->count = el->num_values;
	r->out.rights->names = talloc_array(r->out.rights, 
					    struct lsa_StringLarge, r->out.rights->count);
	if (r->out.rights->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<el->num_values;i++) {
		r->out.rights->names[i].string = (const char *)el->values[i].data;
	}

	return NT_STATUS_OK;
}



/* 
  helper for lsa_AddAccountRights and lsa_RemoveAccountRights
*/
static NTSTATUS dcesrv_lsa_AddRemoveAccountRights(struct dcesrv_call_state *dce_call, 
					   TALLOC_CTX *mem_ctx,
					   struct lsa_policy_state *state,
					   int ldb_flag,
					   struct dom_sid *sid,
					   const struct lsa_RightSet *rights)
{
	const char *sidstr;
	struct ldb_message *msg;
	struct ldb_message_element *el;
	int i, ret;
	struct lsa_EnumAccountRights r2;

	sidstr = ldap_encode_ndr_dom_sid(mem_ctx, sid);
	if (sidstr == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = samdb_search_dn(state->sam_ldb, mem_ctx, 
				  NULL, "objectSid=%s", sidstr);
	if (msg->dn == NULL) {
		NTSTATUS status;
		if (ldb_flag == LDB_FLAG_MOD_DELETE) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		status = samdb_create_foreign_security_principal(state->sam_ldb, mem_ctx, 
								 sid, &msg->dn);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		return NT_STATUS_NO_SUCH_USER;
	}

	if (ldb_msg_add_empty(msg, "privilege", ldb_flag, NULL)) {
		return NT_STATUS_NO_MEMORY;
	}

	if (ldb_flag == LDB_FLAG_MOD_ADD) {
		NTSTATUS status;

		r2.in.handle = &state->handle->wire_handle;
		r2.in.sid = sid;
		r2.out.rights = talloc(mem_ctx, struct lsa_RightSet);

		status = dcesrv_lsa_EnumAccountRights(dce_call, mem_ctx, &r2);
		if (!NT_STATUS_IS_OK(status)) {
			ZERO_STRUCTP(r2.out.rights);
		}
	}

	for (i=0;i<rights->count;i++) {
		if (sec_privilege_id(rights->names[i].string) == -1) {
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}

		if (ldb_flag == LDB_FLAG_MOD_ADD) {
			int j;
			for (j=0;j<r2.out.rights->count;j++) {
				if (strcasecmp_m(r2.out.rights->names[j].string, 
					       rights->names[i].string) == 0) {
					break;
				}
			}
			if (j != r2.out.rights->count) continue;
		}

		ret = ldb_msg_add_string(msg, "privilege", rights->names[i].string);
		if (ret != LDB_SUCCESS) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	el = ldb_msg_find_element(msg, "privilege");
	if (!el) {
		return NT_STATUS_OK;
	}

	ret = samdb_modify(state->sam_ldb, mem_ctx, msg);
	if (ret != 0) {
		if (ldb_flag == LDB_FLAG_MOD_DELETE && ret == LDB_ERR_NO_SUCH_ATTRIBUTE) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		DEBUG(3, ("Could not %s attributes from %s: %s", 
			  ldb_flag == LDB_FLAG_MOD_DELETE ? "delete" : "add",
			  ldb_dn_get_linearized(msg->dn), ldb_errstring(state->sam_ldb)));
		return NT_STATUS_UNEXPECTED_IO_ERROR;
	}

	return NT_STATUS_OK;
}

/* 
  lsa_AddPrivilegesToAccount
*/
static NTSTATUS dcesrv_lsa_AddPrivilegesToAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					   struct lsa_AddPrivilegesToAccount *r)
{
	struct lsa_RightSet rights;
	struct dcesrv_handle *h;
	struct lsa_account_state *astate;
	int i;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_ACCOUNT);

	astate = h->data;

	rights.count = r->in.privs->count;
	rights.names = talloc_array(mem_ctx, struct lsa_StringLarge, rights.count);
	if (rights.names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<rights.count;i++) {
		int id = r->in.privs->set[i].luid.low;
		if (r->in.privs->set[i].luid.high) {
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
		rights.names[i].string = sec_privilege_name(id);
		if (rights.names[i].string == NULL) {
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
	}

	return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, astate->policy, 
					  LDB_FLAG_MOD_ADD, astate->account_sid,
					  &rights);
}


/* 
  lsa_RemovePrivilegesFromAccount
*/
static NTSTATUS dcesrv_lsa_RemovePrivilegesFromAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct lsa_RemovePrivilegesFromAccount *r)
{
	struct lsa_RightSet *rights;
	struct dcesrv_handle *h;
	struct lsa_account_state *astate;
	int i;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_ACCOUNT);

	astate = h->data;

	rights = talloc(mem_ctx, struct lsa_RightSet);

	if (r->in.remove_all == 1 && 
	    r->in.privs == NULL) {
		struct lsa_EnumAccountRights r2;
		NTSTATUS status;

		r2.in.handle = &astate->policy->handle->wire_handle;
		r2.in.sid = astate->account_sid;
		r2.out.rights = rights;

		status = dcesrv_lsa_EnumAccountRights(dce_call, mem_ctx, &r2);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, astate->policy, 
						  LDB_FLAG_MOD_DELETE, astate->account_sid,
						  r2.out.rights);
	}

	if (r->in.remove_all != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	rights->count = r->in.privs->count;
	rights->names = talloc_array(mem_ctx, struct lsa_StringLarge, rights->count);
	if (rights->names == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<rights->count;i++) {
		int id = r->in.privs->set[i].luid.low;
		if (r->in.privs->set[i].luid.high) {
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
		rights->names[i].string = sec_privilege_name(id);
		if (rights->names[i].string == NULL) {
			return NT_STATUS_NO_SUCH_PRIVILEGE;
		}
	}

	return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, astate->policy, 
					  LDB_FLAG_MOD_DELETE, astate->account_sid,
					  rights);
}


/* 
  lsa_GetQuotasForAccount
*/
static NTSTATUS dcesrv_lsa_GetQuotasForAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_GetQuotasForAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_SetQuotasForAccount
*/
static NTSTATUS dcesrv_lsa_SetQuotasForAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_SetQuotasForAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_GetSystemAccessAccount
*/
static NTSTATUS dcesrv_lsa_GetSystemAccessAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_GetSystemAccessAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_SetSystemAccessAccount
*/
static NTSTATUS dcesrv_lsa_SetSystemAccessAccount(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_SetSystemAccessAccount *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CreateSecret 
*/
static NTSTATUS dcesrv_lsa_CreateSecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct lsa_CreateSecret *r)
{
	struct dcesrv_handle *policy_handle;
	struct lsa_policy_state *policy_state;
	struct lsa_secret_state *secret_state;
	struct dcesrv_handle *handle;
	struct ldb_message **msgs, *msg;
	const char *errstr;
	const char *attrs[] = {
		NULL
	};

	const char *name;

	int ret;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.sec_handle);
	
	policy_state = policy_handle->data;

	if (!r->in.name.string) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	secret_state = talloc(mem_ctx, struct lsa_secret_state);
	if (!secret_state) {
		return NT_STATUS_NO_MEMORY;
	}
	secret_state->policy = policy_state;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (strncmp("G$", r->in.name.string, 2) == 0) {
		const char *name2;
		name = &r->in.name.string[2];
		secret_state->sam_ldb = talloc_reference(secret_state, policy_state->sam_ldb);
		secret_state->global = True;

		if (strlen(name) < 1) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		name2 = talloc_asprintf(mem_ctx, "%s Secret", ldb_binary_encode_string(mem_ctx, name));
		/* search for the secret record */
		ret = gendb_search(secret_state->sam_ldb,
				   mem_ctx, policy_state->system_dn, &msgs, attrs,
				   "(&(cn=%s)(objectclass=secret))", 
				   name2);
		if (ret > 0) {
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
		
		if (ret == -1) {
			DEBUG(0,("Failure searching for CN=%s: %s\n", 
				 name2, ldb_errstring(secret_state->sam_ldb)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		msg->dn = ldb_dn_copy(mem_ctx, policy_state->system_dn);
		if (!name2 || ! ldb_dn_add_child_fmt(msg->dn, "cn=%s", name2)) {
			return NT_STATUS_NO_MEMORY;
		}
		
		samdb_msg_add_string(secret_state->sam_ldb, mem_ctx, msg, "cn", name2);
	
	} else {
		secret_state->global = False;

		name = r->in.name.string;
		if (strlen(name) < 1) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		secret_state->sam_ldb = talloc_reference(secret_state, secrets_db_connect(mem_ctx));
		/* search for the secret record */
		ret = gendb_search(secret_state->sam_ldb, mem_ctx,
				   ldb_dn_new(mem_ctx, secret_state->sam_ldb, "cn=LSA Secrets"),
				   &msgs, attrs,
				   "(&(cn=%s)(objectclass=secret))", 
				   ldb_binary_encode_string(mem_ctx, name));
		if (ret > 0) {
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
		
		if (ret == -1) {
			DEBUG(0,("Failure searching for CN=%s: %s\n", 
				 name, ldb_errstring(secret_state->sam_ldb)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		msg->dn = ldb_dn_new_fmt(mem_ctx, secret_state->sam_ldb, "cn=%s,cn=LSA Secrets", name);
		samdb_msg_add_string(secret_state->sam_ldb, mem_ctx, msg, "cn", name);
	} 

	/* pull in all the template attributes.  Note this is always from the global samdb */
	ret = samdb_copy_template(secret_state->policy->sam_ldb, msg, 
				  "(&(cn=TemplateSecret)(objectclass=secretTemplate))", &errstr);
	if (ret != 0) {
		DEBUG(0,("Failed to load TemplateSecret from samdb: %s\n",
			 errstr));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	samdb_msg_add_string(secret_state->sam_ldb, mem_ctx, msg, "objectClass", "secret");
	
	secret_state->secret_dn = talloc_reference(secret_state, msg->dn);

	/* create the secret */
	ret = samdb_add(secret_state->sam_ldb, mem_ctx, msg);
	if (ret != 0) {
		DEBUG(0,("Failed to create secret record %s: %s\n",
			 ldb_dn_get_linearized(msg->dn), 
			 ldb_errstring(secret_state->sam_ldb)));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_SECRET);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}
	
	handle->data = talloc_steal(handle, secret_state);
	
	secret_state->access_mask = r->in.access_mask;
	secret_state->policy = talloc_reference(secret_state, policy_state);
	
	*r->out.sec_handle = handle->wire_handle;
	
	return NT_STATUS_OK;
}


/* 
  lsa_OpenSecret 
*/
static NTSTATUS dcesrv_lsa_OpenSecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct lsa_OpenSecret *r)
{
	struct dcesrv_handle *policy_handle;
	
	struct lsa_policy_state *policy_state;
	struct lsa_secret_state *secret_state;
	struct dcesrv_handle *handle;
	struct ldb_message **msgs;
	const char *attrs[] = {
		NULL
	};

	const char *name;

	int ret;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);
	ZERO_STRUCTP(r->out.sec_handle);
	policy_state = policy_handle->data;

	if (!r->in.name.string) {
		return NT_STATUS_INVALID_PARAMETER;
	}
	
	secret_state = talloc(mem_ctx, struct lsa_secret_state);
	if (!secret_state) {
		return NT_STATUS_NO_MEMORY;
	}
	secret_state->policy = policy_state;

	if (strncmp("G$", r->in.name.string, 2) == 0) {
		name = &r->in.name.string[2];
		secret_state->sam_ldb = talloc_reference(secret_state, policy_state->sam_ldb);
		secret_state->global = True;

		if (strlen(name) < 1) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* search for the secret record */
		ret = gendb_search(secret_state->sam_ldb,
				   mem_ctx, policy_state->system_dn, &msgs, attrs,
				   "(&(cn=%s Secret)(objectclass=secret))", 
				   ldb_binary_encode_string(mem_ctx, name));
		if (ret == 0) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		
		if (ret != 1) {
			DEBUG(0,("Found %d records matching DN %s\n", ret,
				 ldb_dn_get_linearized(policy_state->system_dn)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	
	} else {
		secret_state->sam_ldb = talloc_reference(secret_state, secrets_db_connect(mem_ctx));

		secret_state->global = False;
		name = r->in.name.string;
		if (strlen(name) < 1) {
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* search for the secret record */
		ret = gendb_search(secret_state->sam_ldb, mem_ctx,
				   ldb_dn_new(mem_ctx, secret_state->sam_ldb, "cn=LSA Secrets"),
				   &msgs, attrs,
				   "(&(cn=%s)(objectclass=secret))", 
				   ldb_binary_encode_string(mem_ctx, name));
		if (ret == 0) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		
		if (ret != 1) {
			DEBUG(0,("Found %d records matching DN %s\n", ret,
				 ldb_dn_get_linearized(policy_state->system_dn)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} 

	secret_state->secret_dn = talloc_reference(secret_state, msgs[0]->dn);
	
	handle = dcesrv_handle_new(dce_call->context, LSA_HANDLE_SECRET);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}
	
	handle->data = talloc_steal(handle, secret_state);
	
	secret_state->access_mask = r->in.access_mask;
	secret_state->policy = talloc_reference(secret_state, policy_state);
	
	*r->out.sec_handle = handle->wire_handle;
	
	return NT_STATUS_OK;
}


/* 
  lsa_SetSecret 
*/
static NTSTATUS dcesrv_lsa_SetSecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			      struct lsa_SetSecret *r)
{

	struct dcesrv_handle *h;
	struct lsa_secret_state *secret_state;
	struct ldb_message *msg;
	DATA_BLOB session_key;
	DATA_BLOB crypt_secret, secret;
	struct ldb_val val;
	int ret;
	NTSTATUS status = NT_STATUS_OK;

	struct timeval now = timeval_current();
	NTTIME nt_now = timeval_to_nttime(&now);

	DCESRV_PULL_HANDLE(h, r->in.sec_handle, LSA_HANDLE_SECRET);

	secret_state = h->data;

	msg = ldb_msg_new(mem_ctx);
	if (msg == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = talloc_reference(mem_ctx, secret_state->secret_dn);
	if (!msg->dn) {
		return NT_STATUS_NO_MEMORY;
	}
	status = dcesrv_fetch_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (r->in.old_val) {
		/* Decrypt */
		crypt_secret.data = r->in.old_val->data;
		crypt_secret.length = r->in.old_val->size;
		
		status = sess_decrypt_blob(mem_ctx, &crypt_secret, &session_key, &secret);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		
		val.data = secret.data;
		val.length = secret.length;
		
		/* set value */
		if (samdb_msg_add_value(secret_state->sam_ldb, 
					mem_ctx, msg, "priorValue", &val) != 0) {
			return NT_STATUS_NO_MEMORY; 
		}
		
		/* set old value mtime */
		if (samdb_msg_add_uint64(secret_state->sam_ldb, 
					 mem_ctx, msg, "priorSetTime", nt_now) != 0) { 
			return NT_STATUS_NO_MEMORY; 
		}

		if (!r->in.new_val) {
			/* This behaviour varies depending of if this is a local, or a global secret... */
			if (secret_state->global) {
				/* set old value mtime */
				if (samdb_msg_add_uint64(secret_state->sam_ldb, 
							 mem_ctx, msg, "lastSetTime", nt_now) != 0) { 
					return NT_STATUS_NO_MEMORY; 
				}
			} else {
				if (samdb_msg_add_delete(secret_state->sam_ldb, 
							 mem_ctx, msg, "currentValue")) {
					return NT_STATUS_NO_MEMORY;
				}
				if (samdb_msg_add_delete(secret_state->sam_ldb, 
							 mem_ctx, msg, "lastSetTime")) {
					return NT_STATUS_NO_MEMORY;
				}
			}
		}
	}

	if (r->in.new_val) {
		/* Decrypt */
		crypt_secret.data = r->in.new_val->data;
		crypt_secret.length = r->in.new_val->size;
		
		status = sess_decrypt_blob(mem_ctx, &crypt_secret, &session_key, &secret);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		
		val.data = secret.data;
		val.length = secret.length;
		
		/* set value */
		if (samdb_msg_add_value(secret_state->sam_ldb, 
					mem_ctx, msg, "currentValue", &val) != 0) {
			return NT_STATUS_NO_MEMORY; 
		}
		
		/* set new value mtime */
		if (samdb_msg_add_uint64(secret_state->sam_ldb, 
					 mem_ctx, msg, "lastSetTime", nt_now) != 0) { 
			return NT_STATUS_NO_MEMORY; 
		}
		
		/* If the old value is not set, then migrate the
		 * current value to the old value */
		if (!r->in.old_val) {
			const struct ldb_val *new_val;
			NTTIME last_set_time;
			struct ldb_message **res;
			const char *attrs[] = {
				"currentValue",
				"lastSetTime",
				NULL
			};
			
			/* search for the secret record */
			ret = gendb_search_dn(secret_state->sam_ldb,mem_ctx,
					      secret_state->secret_dn, &res, attrs);
			if (ret == 0) {
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
			}
			
			if (ret != 1) {
				DEBUG(0,("Found %d records matching dn=%s\n", ret,
					 ldb_dn_get_linearized(secret_state->secret_dn)));
				return NT_STATUS_INTERNAL_DB_CORRUPTION;
			}

			new_val = ldb_msg_find_ldb_val(res[0], "currentValue");
			last_set_time = ldb_msg_find_attr_as_uint64(res[0], "lastSetTime", 0);
			
			if (new_val) {
				/* set value */
				if (samdb_msg_add_value(secret_state->sam_ldb, 
							mem_ctx, msg, "priorValue", 
							new_val) != 0) {
					return NT_STATUS_NO_MEMORY; 
				}
			}
			
			/* set new value mtime */
			if (ldb_msg_find_ldb_val(res[0], "lastSetTime")) {
				if (samdb_msg_add_uint64(secret_state->sam_ldb, 
							 mem_ctx, msg, "priorSetTime", last_set_time) != 0) { 
					return NT_STATUS_NO_MEMORY; 
				}
			}
		}
	}

	/* modify the samdb record */
	ret = samdb_replace(secret_state->sam_ldb, mem_ctx, msg);
	if (ret != 0) {
		/* we really need samdb.c to return NTSTATUS */
		return NT_STATUS_UNSUCCESSFUL;
	}

	return NT_STATUS_OK;
}


/* 
  lsa_QuerySecret 
*/
static NTSTATUS dcesrv_lsa_QuerySecret(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_QuerySecret *r)
{
	struct dcesrv_handle *h;
	struct lsa_secret_state *secret_state;
	struct ldb_message *msg;
	DATA_BLOB session_key;
	DATA_BLOB crypt_secret, secret;
	int ret;
	struct ldb_message **res;
	const char *attrs[] = {
		"currentValue",
		"priorValue",
		"lastSetTime",
		"priorSetTime", 
		NULL
	};

	NTSTATUS nt_status;

	DCESRV_PULL_HANDLE(h, r->in.sec_handle, LSA_HANDLE_SECRET);

	secret_state = h->data;

	/* pull all the user attributes */
	ret = gendb_search_dn(secret_state->sam_ldb, mem_ctx,
			      secret_state->secret_dn, &res, attrs);
	if (ret != 1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	msg = res[0];
	
	nt_status = dcesrv_fetch_session_key(dce_call->conn, &session_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}
	
	if (r->in.old_val) {
		const struct ldb_val *prior_val;
		r->out.old_val = talloc_zero(mem_ctx, struct lsa_DATA_BUF_PTR);
		if (!r->out.old_val) {
			return NT_STATUS_NO_MEMORY;
		}
		prior_val = ldb_msg_find_ldb_val(res[0], "priorValue");
		
		if (prior_val && prior_val->length) {
			secret.data = prior_val->data;
			secret.length = prior_val->length;
		
			/* Encrypt */
			crypt_secret = sess_encrypt_blob(mem_ctx, &secret, &session_key);
			if (!crypt_secret.length) {
				return NT_STATUS_NO_MEMORY;
			}
			r->out.old_val->buf = talloc(mem_ctx, struct lsa_DATA_BUF);
			if (!r->out.old_val->buf) {
				return NT_STATUS_NO_MEMORY;
			}
			r->out.old_val->buf->size = crypt_secret.length;
			r->out.old_val->buf->length = crypt_secret.length;
			r->out.old_val->buf->data = crypt_secret.data;
		}
	}
	
	if (r->in.old_mtime) {
		r->out.old_mtime = talloc(mem_ctx, NTTIME);
		if (!r->out.old_mtime) {
			return NT_STATUS_NO_MEMORY;
		}
		*r->out.old_mtime = ldb_msg_find_attr_as_uint64(res[0], "priorSetTime", 0);
	}
	
	if (r->in.new_val) {
		const struct ldb_val *new_val;
		r->out.new_val = talloc_zero(mem_ctx, struct lsa_DATA_BUF_PTR);
		if (!r->out.new_val) {
			return NT_STATUS_NO_MEMORY;
		}

		new_val = ldb_msg_find_ldb_val(res[0], "currentValue");
		
		if (new_val && new_val->length) {
			secret.data = new_val->data;
			secret.length = new_val->length;
		
			/* Encrypt */
			crypt_secret = sess_encrypt_blob(mem_ctx, &secret, &session_key);
			if (!crypt_secret.length) {
				return NT_STATUS_NO_MEMORY;
			}
			r->out.new_val->buf = talloc(mem_ctx, struct lsa_DATA_BUF);
			if (!r->out.new_val->buf) {
				return NT_STATUS_NO_MEMORY;
			}
			r->out.new_val->buf->length = crypt_secret.length;
			r->out.new_val->buf->size = crypt_secret.length;
			r->out.new_val->buf->data = crypt_secret.data;
		}
	}
	
	if (r->in.new_mtime) {
		r->out.new_mtime = talloc(mem_ctx, NTTIME);
		if (!r->out.new_mtime) {
			return NT_STATUS_NO_MEMORY;
		}
		*r->out.new_mtime = ldb_msg_find_attr_as_uint64(res[0], "lastSetTime", 0);
	}
	
	return NT_STATUS_OK;
}


/* 
  lsa_LookupPrivValue
*/
static NTSTATUS dcesrv_lsa_LookupPrivValue(struct dcesrv_call_state *dce_call, 
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
static NTSTATUS dcesrv_lsa_LookupPrivName(struct dcesrv_call_state *dce_call, 
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

	r->out.name = talloc(mem_ctx, struct lsa_StringLarge);
	if (r->out.name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.name->string = privname;

	return NT_STATUS_OK;	
}


/* 
  lsa_LookupPrivDisplayName
*/
static NTSTATUS dcesrv_lsa_LookupPrivDisplayName(struct dcesrv_call_state *dce_call, 
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
	
	r->out.disp_name = talloc(mem_ctx, struct lsa_StringLarge);
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
static NTSTATUS dcesrv_lsa_DeleteObject(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_DeleteObject *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_EnumAccountsWithUserRight
*/
static NTSTATUS dcesrv_lsa_EnumAccountsWithUserRight(struct dcesrv_call_state *dce_call, 
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

	ret = gendb_search(state->sam_ldb, mem_ctx, NULL, &res, attrs, 
			   "privilege=%s", privname);
	if (ret == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	if (ret == 0) {
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	r->out.sids->sids = talloc_array(r->out.sids, struct lsa_SidPtr, ret);
	if (r->out.sids->sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	for (i=0;i<ret;i++) {
		r->out.sids->sids[i].sid = samdb_result_dom_sid(r->out.sids->sids,
								res[i], "objectSid");
		NT_STATUS_HAVE_NO_MEMORY(r->out.sids->sids[i].sid);
	}
	r->out.sids->num_sids = ret;

	return NT_STATUS_OK;
}


/* 
  lsa_AddAccountRights
*/
static NTSTATUS dcesrv_lsa_AddAccountRights(struct dcesrv_call_state *dce_call, 
				     TALLOC_CTX *mem_ctx,
				     struct lsa_AddAccountRights *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, state, 
					  LDB_FLAG_MOD_ADD,
					  r->in.sid, r->in.rights);
}


/* 
  lsa_RemoveAccountRights
*/
static NTSTATUS dcesrv_lsa_RemoveAccountRights(struct dcesrv_call_state *dce_call, 
					TALLOC_CTX *mem_ctx,
					struct lsa_RemoveAccountRights *r)
{
	struct dcesrv_handle *h;
	struct lsa_policy_state *state;

	DCESRV_PULL_HANDLE(h, r->in.handle, LSA_HANDLE_POLICY);

	state = h->data;

	return dcesrv_lsa_AddRemoveAccountRights(dce_call, mem_ctx, state, 
					  LDB_FLAG_MOD_DELETE,
					  r->in.sid, r->in.rights);
}


/* 
  lsa_StorePrivateData
*/
static NTSTATUS dcesrv_lsa_StorePrivateData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_StorePrivateData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_RetrievePrivateData
*/
static NTSTATUS dcesrv_lsa_RetrievePrivateData(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_RetrievePrivateData *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_GetUserName
*/
static NTSTATUS dcesrv_lsa_GetUserName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_GetUserName *r)
{
	NTSTATUS status = NT_STATUS_OK;
	const char *account_name;
	const char *authority_name;
	struct lsa_String *_account_name;
	struct lsa_StringPointer *_authority_name = NULL;

	/* this is what w2k3 does */
	r->out.account_name = r->in.account_name;
	r->out.authority_name = r->in.authority_name;

	if (r->in.account_name && r->in.account_name->string) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (r->in.authority_name &&
	    r->in.authority_name->string &&
	    r->in.authority_name->string->string) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	account_name = talloc_reference(mem_ctx, dce_call->conn->auth_state.session_info->server_info->account_name);
	authority_name = talloc_reference(mem_ctx, dce_call->conn->auth_state.session_info->server_info->domain_name);

	_account_name = talloc(mem_ctx, struct lsa_String);
	NT_STATUS_HAVE_NO_MEMORY(_account_name);
	_account_name->string = account_name;

	if (r->in.authority_name) {
		_authority_name = talloc(mem_ctx, struct lsa_StringPointer);
		NT_STATUS_HAVE_NO_MEMORY(_authority_name);
		_authority_name->string = talloc(mem_ctx, struct lsa_String);
		NT_STATUS_HAVE_NO_MEMORY(_authority_name->string);
		_authority_name->string->string = authority_name;
	}

	r->out.account_name = _account_name;
	r->out.authority_name = _authority_name;

	return status;
}

/*
  lsa_SetInfoPolicy2
*/
static NTSTATUS dcesrv_lsa_SetInfoPolicy2(struct dcesrv_call_state *dce_call,
				   TALLOC_CTX *mem_ctx,
				   struct lsa_SetInfoPolicy2 *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_QueryDomainInformationPolicy
*/
static NTSTATUS dcesrv_lsa_QueryDomainInformationPolicy(struct dcesrv_call_state *dce_call,
						 TALLOC_CTX *mem_ctx,
						 struct lsa_QueryDomainInformationPolicy *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_SetDomInfoPolicy
*/
static NTSTATUS dcesrv_lsa_SetDomainInformationPolicy(struct dcesrv_call_state *dce_call,
					      TALLOC_CTX *mem_ctx,
					      struct lsa_SetDomainInformationPolicy *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lsa_TestCall
*/
static NTSTATUS dcesrv_lsa_TestCall(struct dcesrv_call_state *dce_call,
			     TALLOC_CTX *mem_ctx,
			     struct lsa_TestCall *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}

/*
  lookup a SID for 1 name
*/
static NTSTATUS dcesrv_lsa_lookup_name(struct lsa_policy_state *state, TALLOC_CTX *mem_ctx,
				const char *name, struct dom_sid **sid, uint32_t *atype)
{
	int ret;
	struct ldb_message **res;
	const char * const attrs[] = { "objectSid", "sAMAccountType", NULL};
	const char *p;

	p = strchr_m(name, '\\');
	if (p != NULL) {
		/* TODO: properly parse the domain prefix here, and use it to 
		   limit the search */
		name = p + 1;
	}

	ret = gendb_search(state->sam_ldb, mem_ctx, NULL, &res, attrs, "sAMAccountName=%s", ldb_binary_encode_string(mem_ctx, name));
	if (ret == 1) {
		*sid = samdb_result_dom_sid(mem_ctx, res[0], "objectSid");
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
  lsa_LookupNames3
*/
static NTSTATUS dcesrv_lsa_LookupNames3(struct dcesrv_call_state *dce_call,
				 TALLOC_CTX *mem_ctx,
				 struct lsa_LookupNames3 *r)
{
	struct lsa_policy_state *policy_state;
	struct dcesrv_handle *policy_handle;
	int i;
	NTSTATUS status = NT_STATUS_OK;

	DCESRV_PULL_HANDLE(policy_handle, r->in.handle, LSA_HANDLE_POLICY);

	policy_state = policy_handle->data;

	r->out.domains = NULL;

	r->out.domains = talloc_zero(mem_ctx,  struct lsa_RefDomainList);
	if (r->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.sids = talloc_zero(mem_ctx,  struct lsa_TransSidArray3);
	if (r->out.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*r->out.count = 0;

	r->out.sids->sids = talloc_array(r->out.sids, struct lsa_TranslatedSid3, 
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
		r->out.sids->sids[i].sid         = NULL;
		r->out.sids->sids[i].sid_index   = 0xFFFFFFFF;
		r->out.sids->sids[i].unknown     = 0;

		status2 = dcesrv_lsa_lookup_name(policy_state, mem_ctx, name, &sid, &atype);
		if (!NT_STATUS_IS_OK(status2) || sid->num_auths == 0) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		rtype = samdb_atype_map(atype);
		if (rtype == SID_NAME_UNKNOWN) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		status2 = dcesrv_lsa_authority_list(policy_state, mem_ctx, sid, r->out.domains, &sid_index);
		if (!NT_STATUS_IS_OK(status2)) {
			return status2;
		}

		r->out.sids->sids[i].sid_type    = rtype;
		r->out.sids->sids[i].sid         = sid;
		r->out.sids->sids[i].sid_index   = sid_index;
		r->out.sids->sids[i].unknown     = 0;
	}
	
	return status;
}

/* 
  lsa_LookupNames4

  Identical to LookupNames3, but doesn't take a policy handle
  
*/
static NTSTATUS dcesrv_lsa_LookupNames4(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				 struct lsa_LookupNames4 *r)
{
	struct lsa_LookupNames3 r2;
	struct lsa_OpenPolicy2 pol;
	NTSTATUS status;
	struct dcesrv_handle *h;

	/* No policy handle on the wire, so make one up here */
	r2.in.handle = talloc(mem_ctx, struct policy_handle);
	if (!r2.in.handle) {
		return NT_STATUS_NO_MEMORY;
	}

	pol.out.handle = r2.in.handle;
	pol.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	pol.in.attr = NULL;
	pol.in.system_name = NULL;
	status = dcesrv_lsa_OpenPolicy2(dce_call, mem_ctx, &pol);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* ensure this handle goes away at the end of this call */
	DCESRV_PULL_HANDLE(h, r2.in.handle, LSA_HANDLE_POLICY);
	talloc_steal(mem_ctx, h);

	r2.in.num_names = r->in.num_names;
	r2.in.names = r->in.names;
	r2.in.sids = r->in.sids;
	r2.in.count = r->in.count;
	r2.in.unknown1 = r->in.unknown1;
	r2.in.unknown2 = r->in.unknown2;
	r2.out.domains = r->out.domains;
	r2.out.sids = r->out.sids;
	r2.out.count = r->out.count;
	
	status = dcesrv_lsa_LookupNames3(dce_call, mem_ctx, &r2);
	if (dce_call->fault_code != 0) {
		return status;
	}
	
	r->out.domains = r2.out.domains;
	r->out.sids = r2.out.sids;
	r->out.count = r2.out.count;
	return status;
}

/*
  lsa_LookupNames2
*/
static NTSTATUS dcesrv_lsa_LookupNames2(struct dcesrv_call_state *dce_call,
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

	r->out.domains = talloc_zero(mem_ctx,  struct lsa_RefDomainList);
	if (r->out.domains == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.sids = talloc_zero(mem_ctx,  struct lsa_TransSidArray2);
	if (r->out.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*r->out.count = 0;

	r->out.sids->sids = talloc_array(r->out.sids, struct lsa_TranslatedSid2, 
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

		status2 = dcesrv_lsa_lookup_name(state, mem_ctx, name, &sid, &atype);
		if (!NT_STATUS_IS_OK(status2) || sid->num_auths == 0) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		rtype = samdb_atype_map(atype);
		if (rtype == SID_NAME_UNKNOWN) {
			status = STATUS_SOME_UNMAPPED;
			continue;
		}

		status2 = dcesrv_lsa_authority_list(state, mem_ctx, sid, r->out.domains, &sid_index);
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
static NTSTATUS dcesrv_lsa_LookupNames(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
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

	status = dcesrv_lsa_LookupNames2(dce_call, mem_ctx, &r2);
	if (dce_call->fault_code != 0) {
		return status;
	}

	r->out.domains = r2.out.domains;
	r->out.sids = talloc(mem_ctx, struct lsa_TransSidArray);
	if (r->out.sids == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	r->out.sids->count = r2.out.sids->count;
	r->out.sids->sids = talloc_array(r->out.sids, struct lsa_TranslatedSid, 
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
  lsa_CREDRWRITE 
*/
static NTSTATUS dcesrv_lsa_CREDRWRITE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRWRITE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CREDRREAD 
*/
static NTSTATUS dcesrv_lsa_CREDRREAD(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRREAD *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CREDRENUMERATE 
*/
static NTSTATUS dcesrv_lsa_CREDRENUMERATE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRENUMERATE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CREDRWRITEDOMAINCREDENTIALS 
*/
static NTSTATUS dcesrv_lsa_CREDRWRITEDOMAINCREDENTIALS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRWRITEDOMAINCREDENTIALS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CREDRREADDOMAINCREDENTIALS 
*/
static NTSTATUS dcesrv_lsa_CREDRREADDOMAINCREDENTIALS(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRREADDOMAINCREDENTIALS *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CREDRDELETE 
*/
static NTSTATUS dcesrv_lsa_CREDRDELETE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRDELETE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CREDRGETTARGETINFO 
*/
static NTSTATUS dcesrv_lsa_CREDRGETTARGETINFO(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRGETTARGETINFO *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CREDRPROFILELOADED 
*/
static NTSTATUS dcesrv_lsa_CREDRPROFILELOADED(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRPROFILELOADED *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CREDRGETSESSIONTYPES 
*/
static NTSTATUS dcesrv_lsa_CREDRGETSESSIONTYPES(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRGETSESSIONTYPES *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LSARREGISTERAUDITEVENT 
*/
static NTSTATUS dcesrv_lsa_LSARREGISTERAUDITEVENT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARREGISTERAUDITEVENT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LSARGENAUDITEVENT 
*/
static NTSTATUS dcesrv_lsa_LSARGENAUDITEVENT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARGENAUDITEVENT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LSARUNREGISTERAUDITEVENT 
*/
static NTSTATUS dcesrv_lsa_LSARUNREGISTERAUDITEVENT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARUNREGISTERAUDITEVENT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_lsaRQueryForestTrustInformation 
*/
static NTSTATUS dcesrv_lsa_lsaRQueryForestTrustInformation(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_lsaRQueryForestTrustInformation *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LSARSETFORESTTRUSTINFORMATION 
*/
static NTSTATUS dcesrv_lsa_LSARSETFORESTTRUSTINFORMATION(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARSETFORESTTRUSTINFORMATION *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_CREDRRENAME 
*/
static NTSTATUS dcesrv_lsa_CREDRRENAME(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_CREDRRENAME *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}



/* 
  lsa_LSAROPENPOLICYSCE 
*/
static NTSTATUS dcesrv_lsa_LSAROPENPOLICYSCE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSAROPENPOLICYSCE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LSARADTREGISTERSECURITYEVENTSOURCE 
*/
static NTSTATUS dcesrv_lsa_LSARADTREGISTERSECURITYEVENTSOURCE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARADTREGISTERSECURITYEVENTSOURCE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE 
*/
static NTSTATUS dcesrv_lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARADTUNREGISTERSECURITYEVENTSOURCE *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  lsa_LSARADTREPORTSECURITYEVENT 
*/
static NTSTATUS dcesrv_lsa_LSARADTREPORTSECURITYEVENT(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
		       struct lsa_LSARADTREPORTSECURITYEVENT *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_lsa_s.c"



/*****************************************
NOTE! The remaining calls below were
removed in w2k3, so the DCESRV_FAULT()
replies are the correct implementation. Do
not try and fill these in with anything else
******************************************/

/* 
  dssetup_DsRoleDnsNameToFlatName 
*/
static WERROR dcesrv_dssetup_DsRoleDnsNameToFlatName(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					struct dssetup_DsRoleDnsNameToFlatName *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleDcAsDc 
*/
static WERROR dcesrv_dssetup_DsRoleDcAsDc(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct dssetup_DsRoleDcAsDc *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleDcAsReplica 
*/
static WERROR dcesrv_dssetup_DsRoleDcAsReplica(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				  struct dssetup_DsRoleDcAsReplica *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleDemoteDc 
*/
static WERROR dcesrv_dssetup_DsRoleDemoteDc(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			       struct dssetup_DsRoleDemoteDc *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleGetDcOperationProgress 
*/
static WERROR dcesrv_dssetup_DsRoleGetDcOperationProgress(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					     struct dssetup_DsRoleGetDcOperationProgress *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleGetDcOperationResults 
*/
static WERROR dcesrv_dssetup_DsRoleGetDcOperationResults(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					    struct dssetup_DsRoleGetDcOperationResults *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleCancel 
*/
static WERROR dcesrv_dssetup_DsRoleCancel(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
			     struct dssetup_DsRoleCancel *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleServerSaveStateForUpgrade 
*/
static WERROR dcesrv_dssetup_DsRoleServerSaveStateForUpgrade(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						struct dssetup_DsRoleServerSaveStateForUpgrade *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleUpgradeDownlevelServer 
*/
static WERROR dcesrv_dssetup_DsRoleUpgradeDownlevelServer(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
					     struct dssetup_DsRoleUpgradeDownlevelServer *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* 
  dssetup_DsRoleAbortDownlevelServerUpgrade 
*/
static WERROR dcesrv_dssetup_DsRoleAbortDownlevelServerUpgrade(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
						  struct dssetup_DsRoleAbortDownlevelServerUpgrade *r)
{
	DCESRV_FAULT(DCERPC_FAULT_OP_RNG_ERROR);
}


/* include the generated boilerplate */
#include "librpc/gen_ndr/ndr_dssetup_s.c"

NTSTATUS dcerpc_server_lsa_init(void)
{
	NTSTATUS ret;
	
	ret = dcerpc_server_dssetup_init();
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}
	ret = dcerpc_server_lsarpc_init();
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}
	return ret;
}
