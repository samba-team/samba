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

/*
 * This matches a Windows 2012R2 dc in
 * a domain with function level 2012R2.
 */
#define DCESRV_LSA_POLICY_SD_SDDL \
	"O:BAG:SY" \
	"D:" \
	"(D;;0x00000800;;;AN)" \
	"(A;;GA;;;BA)" \
	"(A;;GX;;;WD)" \
	"(A;;0x00000801;;;AN)" \
	"(A;;0x00001000;;;LS)" \
	"(A;;0x00001000;;;NS)" \
	"(A;;0x00001000;;;IS)" \
	"(A;;0x00000801;;;S-1-15-2-1)"

static const struct generic_mapping dcesrv_lsa_policy_mapping = {
	LSA_POLICY_READ,
	LSA_POLICY_WRITE,
	LSA_POLICY_EXECUTE,
	LSA_POLICY_ALL_ACCESS
};

NTSTATUS dcesrv_lsa_get_policy_state(struct dcesrv_call_state *dce_call,
				     TALLOC_CTX *mem_ctx,
				     uint32_t access_desired,
				     struct lsa_policy_state **_state)
{
	struct auth_session_info *session_info =
		dcesrv_call_session_info(dce_call);
	enum security_user_level security_level;
	struct lsa_policy_state *state;
	struct ldb_result *dom_res;
	const char *dom_attrs[] = {
		"objectSid", 
		"objectGUID", 
		"nTMixedDomain",
		"fSMORoleOwner",
		NULL
	};
	char *p;
	int ret;

	state = talloc_zero(mem_ctx, struct lsa_policy_state);
	if (!state) {
		return NT_STATUS_NO_MEMORY;
	}

	/* make sure the sam database is accessible */
	state->sam_ldb = dcesrv_samdb_connect_as_user(state, dce_call);
	if (state->sam_ldb == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* and the privilege database */
	state->pdb = privilege_connect(state, dce_call->conn->dce_ctx->lp_ctx);
	if (state->pdb == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	/* work out the domain_dn - useful for so many calls its worth
	   fetching here */
	state->domain_dn = ldb_get_default_basedn(state->sam_ldb);
	if (!state->domain_dn) {
		return NT_STATUS_NO_MEMORY;		
	}

	/* work out the forest root_dn - useful for so many calls its worth
	   fetching here */
	state->forest_dn = ldb_get_root_basedn(state->sam_ldb);
	if (!state->forest_dn) {
		return NT_STATUS_NO_MEMORY;		
	}

	ret = ldb_search(state->sam_ldb, mem_ctx, &dom_res,
			 state->domain_dn, LDB_SCOPE_BASE, dom_attrs, NULL);
	if (ret != LDB_SUCCESS) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}
	if (dom_res->count != 1) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->domain_sid = samdb_result_dom_sid(state, dom_res->msgs[0], "objectSid");
	if (!state->domain_sid) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->domain_guid = samdb_result_guid(dom_res->msgs[0], "objectGUID");

	state->mixed_domain = ldb_msg_find_attr_as_uint(dom_res->msgs[0], "nTMixedDomain", 0);
	
	talloc_free(dom_res);

	state->domain_name = lpcfg_sam_name(dce_call->conn->dce_ctx->lp_ctx);

	state->domain_dns = ldb_dn_canonical_string(state, state->domain_dn);
	if (!state->domain_dns) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}
	p = strchr(state->domain_dns, '/');
	if (p) {
		*p = '\0';
	}

	state->forest_dns = ldb_dn_canonical_string(state, state->forest_dn);
	if (!state->forest_dns) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}
	p = strchr(state->forest_dns, '/');
	if (p) {
		*p = '\0';
	}

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

	state->nt_authority_sid = dom_sid_parse_talloc(state, SID_NT_AUTHORITY);
	if (!state->nt_authority_sid) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->creator_owner_domain_sid = dom_sid_parse_talloc(state, SID_CREATOR_OWNER_DOMAIN);
	if (!state->creator_owner_domain_sid) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->world_domain_sid = dom_sid_parse_talloc(state, SID_WORLD_DOMAIN);
	if (!state->world_domain_sid) {
		return NT_STATUS_NO_SUCH_DOMAIN;		
	}

	state->sd = sddl_decode(state, DCESRV_LSA_POLICY_SD_SDDL,
				state->domain_sid);
	if (state->sd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	state->sd->dacl->revision = SECURITY_ACL_REVISION_NT4;

	se_map_generic(&access_desired, &dcesrv_lsa_policy_mapping);
	security_acl_map_generic(state->sd->dacl, &dcesrv_lsa_policy_mapping);

	security_level = security_session_user_level(session_info, NULL);
	if (security_level >= SECURITY_SYSTEM) {
		/*
		 * The security descriptor doesn't allow system,
		 * but we want to allow system via ncalrpc as root.
		 */
		state->access_mask = access_desired;
		if (state->access_mask & SEC_FLAG_MAXIMUM_ALLOWED) {
			state->access_mask &= ~SEC_FLAG_MAXIMUM_ALLOWED;
			state->access_mask |= LSA_POLICY_ALL_ACCESS;
		}
	} else {
		NTSTATUS status;

		status = se_access_check(state->sd,
					 session_info->security_token,
					 access_desired,
					 &state->access_mask);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(2,("%s: access desired[0x%08X] rejected[0x%08X] - %s\n",
				 __func__,
				 (unsigned)access_desired,
				 (unsigned)state->access_mask,
				 nt_errstr(status)));
			return status;
		}
	}

	DEBUG(10,("%s: access desired[0x%08X] granted[0x%08X] - success.\n",
		  __func__,
		 (unsigned)access_desired,
		 (unsigned)state->access_mask));

	*_state = state;

	return NT_STATUS_OK;
}

/* 
  lsa_OpenPolicy2
*/
NTSTATUS dcesrv_lsa_OpenPolicy2(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_OpenPolicy2 *r)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	NTSTATUS status;
	struct lsa_policy_state *state;
	struct dcesrv_handle *handle;

	if (transport != NCACN_NP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	ZERO_STRUCTP(r->out.handle);

	if (r->in.attr != NULL &&
	    r->in.attr->root_dir != NULL) {
		/* MS-LSAD 3.1.4.4.1 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	status = dcesrv_lsa_get_policy_state(dce_call, mem_ctx,
					     r->in.access_mask,
					     &state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	handle = dcesrv_handle_create(dce_call, LSA_HANDLE_POLICY);
	if (!handle) {
		return NT_STATUS_NO_MEMORY;
	}

	handle->data = talloc_steal(handle, state);

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
NTSTATUS dcesrv_lsa_OpenPolicy(struct dcesrv_call_state *dce_call, TALLOC_CTX *mem_ctx,
				struct lsa_OpenPolicy *r)
{
	enum dcerpc_transport_t transport =
		dcerpc_binding_get_transport(dce_call->conn->endpoint->ep_description);
	struct lsa_OpenPolicy2 r2;

	if (transport != NCACN_NP && transport != NCALRPC) {
		DCESRV_FAULT(DCERPC_FAULT_ACCESS_DENIED);
	}

	r2.in.system_name = NULL;
	r2.in.attr = r->in.attr;
	r2.in.access_mask = r->in.access_mask;
	r2.out.handle = r->out.handle;

	return dcesrv_lsa_OpenPolicy2(dce_call, mem_ctx, &r2);
}


