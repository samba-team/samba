/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
 
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
#include "libnet/libnet.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "librpc/gen_ndr/ndr_lsa.h"
#include "librpc/gen_ndr/ndr_drsuapi.h"
#include "lib/ldb/include/ldb.h"
#include "include/secrets.h"

/*
 * do a domain join using DCERPC/SAMR calls
 * 1. connect to the SAMR pipe of users domain PDC (maybe a standalone server or workstation)
 *    is it correct to contact the the pdc of the domain of the user who's password should be set?
 * 2. do a samr_Connect to get a policy handle
 * 3. do a samr_LookupDomain to get the domain sid
 * 4. do a samr_OpenDomain to get a domain handle
 * 5. do a samr_CreateAccount to try and get a new account 
 * 
 * If that fails, do:
 * 5.1. do a samr_LookupNames to get the users rid
 * 5.2. do a samr_OpenUser to get a user handle
 * 
 * 6. call libnet_SetPassword_samr_handle to set the password
 *
 * 7. do a samrSetUserInfo to set the account flags
 */
NTSTATUS libnet_JoinDomain(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_JoinDomain *r)
{
	TALLOC_CTX *tmp_ctx;

	NTSTATUS status;
	struct libnet_RpcConnect c;
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 lsa_open_policy;
	struct policy_handle lsa_p_handle;
	struct lsa_QueryInfoPolicy2 lsa_query_info2;
	struct lsa_QueryInfoPolicy lsa_query_info;

	struct dcerpc_binding *samr_binding;
	struct dcerpc_pipe *samr_pipe;
	struct samr_Connect sc;
	struct policy_handle p_handle;
	struct samr_OpenDomain od;
	struct policy_handle d_handle;
	struct samr_LookupNames ln;
	struct samr_OpenUser ou;
	struct samr_CreateUser2 cu;
	struct policy_handle u_handle;
	struct samr_QueryUserInfo qui;
	struct samr_SetUserInfo sui;
	union samr_UserInfo u_info;
	union libnet_SetPassword r2;
	struct samr_GetUserPwInfo pwp;
	struct lsa_String samr_account_name;

	struct dcerpc_pipe *drsuapi_pipe;
	struct dcerpc_binding *drsuapi_binding;
	struct drsuapi_DsBind r_drsuapi_bind;
	struct drsuapi_DsCrackNames r_crack_names;
	struct drsuapi_DsNameString names[1];
	struct policy_handle drsuapi_bind_handle;
	struct GUID drsuapi_bind_guid;

	uint32_t acct_flags;
	uint32_t rid, access_granted;
	int policy_min_pw_len = 0;

	struct dom_sid *domain_sid;
	const char *domain_name;
	const char *realm = NULL; /* Also flag for remote being AD */
	const char *account_dn;

	tmp_ctx = talloc_named(mem_ctx, 0, "libnet_Join temp context");
	if (!tmp_ctx) {
		r->out.error_string = NULL;
		return NT_STATUS_NO_MEMORY;
	}


	/* prepare connect to the LSA pipe of PDC */
	c.level                     = LIBNET_RPC_CONNECT_PDC;
	c.in.domain_name            = r->in.domain_name;
	c.in.dcerpc_iface_name      = DCERPC_LSARPC_NAME;
	c.in.dcerpc_iface_uuid      = DCERPC_LSARPC_UUID;
	c.in.dcerpc_iface_version   = DCERPC_LSARPC_VERSION;

	/* connect to the LSA pipe of the PDC */
	status = libnet_RpcConnect(ctx, tmp_ctx, &c);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"Connection to LSA pipe of PDC of domain '%s' failed: %s",
						r->in.domain_name, nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	
	/* Get an LSA policy handle */

	ZERO_STRUCT(lsa_p_handle);
	qos.len = 0;
	qos.impersonation_level = 2;
	qos.context_mode = 1;
	qos.effective_only = 0;

	attr.len = 0;
	attr.root_dir = NULL;
	attr.object_name = NULL;
	attr.attributes = 0;
	attr.sec_desc = NULL;
	attr.sec_qos = &qos;

	lsa_open_policy.in.attr = &attr;
	lsa_open_policy.in.system_name = talloc_asprintf(tmp_ctx, "\\%s", lp_netbios_name());
	lsa_open_policy.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	lsa_open_policy.out.handle = &lsa_p_handle;

	status = dcerpc_lsa_OpenPolicy2(c.out.dcerpc_pipe, tmp_ctx, &lsa_open_policy);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"lsa_OpenPolicy2 failed: %s",
						nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	lsa_query_info2.in.handle = &lsa_p_handle;
	lsa_query_info2.in.level = LSA_POLICY_INFO_DNS;

	status = dcerpc_lsa_QueryInfoPolicy2(c.out.dcerpc_pipe, tmp_ctx, 
					     &lsa_query_info2);
	
	if (!NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
		if (!NT_STATUS_IS_OK(status)) {
			r->out.error_string = talloc_asprintf(mem_ctx,
							      "lsa_QueryInfoPolicy2 failed: %s",
							      nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
		realm = lsa_query_info2.out.info->dns.dns_domain.string;
	}

	lsa_query_info.in.handle = &lsa_p_handle;
	lsa_query_info.in.level = LSA_POLICY_INFO_DOMAIN;

	status = dcerpc_lsa_QueryInfoPolicy(c.out.dcerpc_pipe, tmp_ctx, 
					     &lsa_query_info);
	
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "lsa_QueryInfoPolicy2 failed: %s",
						      nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}
	domain_sid = lsa_query_info.out.info->domain.sid;
	domain_name = lsa_query_info.out.info->domain.name.string;
	
	r->out.domain_sid = talloc_steal(mem_ctx, domain_sid);
	r->out.domain_name = talloc_steal(mem_ctx, domain_name);
	r->out.realm = talloc_steal(mem_ctx, realm);

	/*
	  step 1 - establish a SAMR connection, on the same CIFS transport
	*/

	/* Find the original binding string */
	status = dcerpc_parse_binding(tmp_ctx, c.out.dcerpc_pipe->conn->binding_string, &samr_binding);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string
			= talloc_asprintf(mem_ctx,
					  "Failed to parse dcerpc binding '%s'", 
					  c.out.dcerpc_pipe->conn->binding_string);
		talloc_free(tmp_ctx);
		return status;
	}

	/* Make binding string for samr, not the other pipe */
	status = dcerpc_epm_map_binding(tmp_ctx, samr_binding, 
					DCERPC_SAMR_UUID, DCERPC_SAMR_VERSION,
					c.out.dcerpc_pipe->conn->event_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string
			= talloc_asprintf(mem_ctx,
					  "Failed to map DCERPC/TCP NCACN_NP pipe for '%s' - %s", 
					  DCERPC_NETLOGON_UUID, nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	/* Setup a SAMR connection */
	status = dcerpc_secondary_connection(c.out.dcerpc_pipe, &samr_pipe, samr_binding);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "SAMR secondary connection failed: %s",
						      nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	status = dcerpc_pipe_auth(samr_pipe, samr_binding, DCERPC_SAMR_UUID, 
				  DCERPC_SAMR_VERSION, ctx->cred);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "SAMR bind failed: %s",
						      nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
        }

	/* prepare samr_Connect */
	ZERO_STRUCT(p_handle);
	sc.in.system_name = NULL;
	sc.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	sc.out.connect_handle = &p_handle;

	/* 2. do a samr_Connect to get a policy handle */
	status = dcerpc_samr_Connect(samr_pipe, tmp_ctx, &sc);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"samr_Connect failed: %s\n",
						nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	/* check result of samr_Connect */
	if (!NT_STATUS_IS_OK(sc.out.result)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"samr_Connect failed: %s\n", 
						nt_errstr(sc.out.result));
		status = sc.out.result;
		talloc_free(tmp_ctx);
		return status;
	}

	/* prepare samr_OpenDomain */
	ZERO_STRUCT(d_handle);
	od.in.connect_handle = &p_handle;
	od.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	od.in.sid = domain_sid;
	od.out.domain_handle = &d_handle;

	/* 4. do a samr_OpenDomain to get a domain handle */
	status = dcerpc_samr_OpenDomain(samr_pipe, tmp_ctx, &od);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"samr_OpenDomain for [%s] failed: %s\n",
						r->in.domain_name, nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	/* prepare samr_CreateUser2 */
	ZERO_STRUCT(u_handle);
	cu.in.domain_handle  = &d_handle;
	cu.in.access_mask     = SEC_FLAG_MAXIMUM_ALLOWED;
	samr_account_name.string = r->in.account_name;
	cu.in.account_name    = &samr_account_name;
	cu.in.acct_flags      = r->in.acct_type;
	cu.out.user_handle    = &u_handle;
	cu.out.rid            = &rid;
	cu.out.access_granted = &access_granted;

	/* 4. do a samr_CreateUser2 to get an account handle, or an error */
	status = dcerpc_samr_CreateUser2(samr_pipe, tmp_ctx, &cu);
	if (!NT_STATUS_IS_OK(status) && !NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
			r->out.error_string = talloc_asprintf(mem_ctx,
								   "samr_CreateUser2 for [%s] failed: %s\n",
								   r->in.domain_name, nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;

	} else if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
		/* prepare samr_LookupNames */
		ln.in.domain_handle = &d_handle;
		ln.in.num_names = 1;
		ln.in.names = talloc_array(tmp_ctx, struct lsa_String, 1);
		if (!ln.in.names) {
			r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		ln.in.names[0].string = r->in.account_name;
		
		/* 5. do a samr_LookupNames to get the users rid */
		status = dcerpc_samr_LookupNames(samr_pipe, tmp_ctx, &ln);
		if (!NT_STATUS_IS_OK(status)) {
			r->out.error_string = talloc_asprintf(mem_ctx,
							      "samr_LookupNames for [%s] failed: %s\n",
						r->in.account_name, nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
		
		
		/* check if we got one RID for the user */
		if (ln.out.rids.count != 1) {
			r->out.error_string = talloc_asprintf(mem_ctx,
							      "samr_LookupNames for [%s] returns %d RIDs\n",
							      r->in.account_name, ln.out.rids.count);
			status = NT_STATUS_INVALID_PARAMETER;
			talloc_free(tmp_ctx);
			return status;	
		}
		
		/* prepare samr_OpenUser */
		ZERO_STRUCT(u_handle);
		ou.in.domain_handle = &d_handle;
		ou.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		ou.in.rid = ln.out.rids.ids[0];
		ou.out.user_handle = &u_handle;
		
		/* 6. do a samr_OpenUser to get a user handle */
		status = dcerpc_samr_OpenUser(samr_pipe, tmp_ctx, &ou);
		if (!NT_STATUS_IS_OK(status)) {
			r->out.error_string = talloc_asprintf(mem_ctx,
							      "samr_OpenUser for [%s] failed: %s\n",
							      r->in.account_name, nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
	}

	pwp.in.user_handle = &u_handle;

	status = dcerpc_samr_GetUserPwInfo(samr_pipe, tmp_ctx, &pwp);
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_password_length;
	}

	r->out.join_password = generate_random_str(mem_ctx, MAX(8, policy_min_pw_len));

	r2.samr_handle.level		= LIBNET_SET_PASSWORD_SAMR_HANDLE;
	r2.samr_handle.in.account_name	= r->in.account_name;
	r2.samr_handle.in.newpassword	= r->out.join_password;
	r2.samr_handle.in.user_handle   = &u_handle;
	r2.samr_handle.in.dcerpc_pipe   = samr_pipe;

	status = libnet_SetPassword(ctx, tmp_ctx, &r2);

	r->out.error_string = r2.samr_handle.out.error_string;

	if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
		return status;
	}

	/* prepare samr_QueryUserInfo (get flags) */
	qui.in.user_handle = &u_handle;
	qui.in.level = 16;
	
	status = dcerpc_samr_QueryUserInfo(samr_pipe, tmp_ctx, &qui);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string
			= talloc_asprintf(mem_ctx,
					  "samr_QueryUserInfo for [%s] failed: %s\n",
					  r->in.account_name, nt_errstr(status));
			talloc_free(tmp_ctx);
		return status;
	}
	if (!qui.out.info) {
		status = NT_STATUS_INVALID_PARAMETER;
		r->out.error_string
			= talloc_asprintf(mem_ctx,
					  "samr_QueryUserInfo failed to return qui.out.info for [%s]: %s\n",
					  r->in.account_name, nt_errstr(status));
			talloc_free(tmp_ctx);
		return status;
	}

	/* Possibly change account type */
	if ((qui.out.info->info16.acct_flags & (ACB_WSTRUST | ACB_SVRTRUST | ACB_DOMTRUST)) 
	    != r->in.acct_type) {
		acct_flags = (qui.out.info->info16.acct_flags & ~(ACB_WSTRUST | ACB_SVRTRUST | ACB_DOMTRUST))
			      | r->in.acct_type;
	} else {
		acct_flags = qui.out.info->info16.acct_flags;
	}
	
	acct_flags = (acct_flags & ~ACB_DISABLED);

	/* reset flags (if required) */
	if (acct_flags != qui.out.info->info16.acct_flags) {
		ZERO_STRUCT(u_info);
		u_info.info16.acct_flags = acct_flags;

		sui.in.user_handle = &u_handle;
		sui.in.info = &u_info;
		sui.in.level = 16;
		
		dcerpc_samr_SetUserInfo(samr_pipe, tmp_ctx, &sui);
		if (!NT_STATUS_IS_OK(status)) {
			r->out.error_string
				= talloc_asprintf(mem_ctx,
						  "samr_SetUserInfo for [%s] failed to remove ACB_DISABLED flag: %s\n",
						  r->in.account_name, nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
	}

	/* Now, if it was AD, then we want to start looking changing a
	 * few more things */
	if (!realm) {
		talloc_free(tmp_ctx);
		return NT_STATUS_OK;
	}

	drsuapi_binding = talloc(tmp_ctx, struct dcerpc_binding);
	*drsuapi_binding = *samr_binding;
	drsuapi_binding->transport = NCACN_IP_TCP;
	drsuapi_binding->endpoint = NULL;
	drsuapi_binding->flags |= DCERPC_SEAL;
	
	status = dcerpc_pipe_connect_b(tmp_ctx, 
				       &drsuapi_pipe,
				       drsuapi_binding,
				       DCERPC_DRSUAPI_UUID,
				       DCERPC_DRSUAPI_VERSION, 
				       ctx->cred, 
				       ctx->event_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"Connection to DRSUAPI pipe of PDC of domain '%s' failed: %s",
						r->in.domain_name, nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}
	
	GUID_from_string(DRSUAPI_DS_BIND_GUID, &drsuapi_bind_guid);

	r_drsuapi_bind.in.bind_guid = &drsuapi_bind_guid;
	r_drsuapi_bind.in.bind_info = NULL;
	r_drsuapi_bind.out.bind_handle = &drsuapi_bind_handle;

	status = dcerpc_drsuapi_DsBind(drsuapi_pipe, tmp_ctx, &r_drsuapi_bind);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			r->out.error_string
				= talloc_asprintf(mem_ctx,
						  "dcerpc_drsuapi_DsBind for [%s\\%s] failed - %s\n", 
						  domain_name, r->in.account_name, 
						  dcerpc_errstr(tmp_ctx, drsuapi_pipe->last_fault_code));
			talloc_free(tmp_ctx);
			return status;
		} else {
			r->out.error_string
				= talloc_asprintf(mem_ctx,
						  "dcerpc_drsuapi_DsBind for [%s\\%s] failed - %s\n", 
						  domain_name, r->in.account_name, 
						  nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
	} else if (!W_ERROR_IS_OK(r_crack_names.out.result)) {
		r->out.error_string
				= talloc_asprintf(mem_ctx,
						  "DsBind failed - %s\n", win_errstr(r_drsuapi_bind.out.result));
			talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	ZERO_STRUCT(r_crack_names);
	r_crack_names.in.bind_handle		= &drsuapi_bind_handle;
	r_crack_names.in.level			= 1;
	r_crack_names.in.req.req1.unknown1		= 0x000004e4;
	r_crack_names.in.req.req1.unknown2		= 0x00000407;
	r_crack_names.in.req.req1.count		= 1;
	r_crack_names.in.req.req1.names		= names;
	r_crack_names.in.req.req1.format_flags	= DRSUAPI_DS_NAME_FLAG_NO_FLAGS;
	r_crack_names.in.req.req1.format_offered	= DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT;
	r_crack_names.in.req.req1.format_desired	= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = talloc_asprintf(tmp_ctx, "%s\\%s", domain_name, r->in.account_name);

	status = dcerpc_drsuapi_DsCrackNames(drsuapi_pipe, tmp_ctx, &r_crack_names);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			r->out.error_string
				= talloc_asprintf(mem_ctx,
						  "dcerpc_drsuapi_DsCrackNames for [%s\\%s] failed - %s\n", 
						  domain_name, r->in.account_name, 
						  dcerpc_errstr(tmp_ctx, drsuapi_pipe->last_fault_code));
			talloc_free(tmp_ctx);
			return status;
		} else {
			r->out.error_string
				= talloc_asprintf(mem_ctx,
						  "dcerpc_drsuapi_DsCrackNames for [%s\\%s] failed - %s\n", 
						  domain_name, r->in.account_name, 
						  nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
	} else if (!W_ERROR_IS_OK(r_crack_names.out.result)) {
		r->out.error_string
				= talloc_asprintf(mem_ctx,
						  "DsCrackNames failed - %s\n", win_errstr(r_crack_names.out.result));
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	account_dn = r_crack_names.out.ctr.ctr1->array[0].result_name;

	printf("Account DN is: %s\n", account_dn);
	
	/* close connection */
	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS libnet_Join_primary_domain(struct libnet_context *ctx, 
					   TALLOC_CTX *mem_ctx, 
					   struct libnet_Join *r)
{
	NTSTATUS status;
	int ret;

	struct ldb_context *ldb;
	struct libnet_JoinDomain r2;
	const char *base_dn = "cn=Primary Domains";
	const struct ldb_val *prior_secret;
	const struct ldb_val *prior_modified_time;
	struct ldb_message **msgs, *msg;
	char *sct;
	const char *attrs[] = {
		"whenChanged",
		"secret",
		"priorSecret"
		"priorChanged",
		NULL
	};

	if (r->in.secure_channel_type == SEC_CHAN_BDC) {
		r2.in.acct_type = ACB_SVRTRUST;
	} else if (r->in.secure_channel_type == SEC_CHAN_WKSTA) {
		r2.in.acct_type = ACB_WSTRUST;
	}
	r2.in.domain_name  = r->in.domain_name;

	r2.in.account_name = talloc_asprintf(mem_ctx, "%s$", lp_netbios_name());

	/* Local secrets are stored in secrets.ldb */
	ldb = secrets_db_connect(mem_ctx);
	if (!ldb) {
		r->out.error_string
			= talloc_asprintf(mem_ctx, 
					  "Could not open secrets database\n");
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/* join domain */
	status = libnet_JoinDomain(ctx, mem_ctx, &r2);

	r->out.error_string = r2.out.error_string;
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	sct = talloc_asprintf(mem_ctx, "%d", r->in.secure_channel_type);
	msg = ldb_msg_new(mem_ctx);

	/* search for the secret record */
	ret = gendb_search(ldb,
			   mem_ctx, base_dn, &msgs, attrs,
			   "(|" SECRETS_PRIMARY_DOMAIN_FILTER "(realm=%s))",
			   r2.out.domain_name, r2.out.realm);

	msg->dn = talloc_asprintf(mem_ctx, "flatname=%s,%s", 
				  r2.out.domain_name,
				  base_dn);
	
	samdb_msg_add_string(ldb, mem_ctx, msg, "flatname", r2.out.domain_name);
	if (r2.out.realm) {
		samdb_msg_add_string(ldb, mem_ctx, msg, "realm", r2.out.realm);
	}
	samdb_msg_add_string(ldb, mem_ctx, msg, "objectClass", "primaryDomain");
	samdb_msg_add_string(ldb, mem_ctx, msg, "secret", r2.out.join_password);
	
	samdb_msg_add_string(ldb, mem_ctx, msg, "samAccountName", r2.in.account_name);
	
	samdb_msg_add_string(ldb, mem_ctx, msg, "secureChannelType", sct);
	

	if (ret == 0) {
	} else if (ret == -1) {
		r->out.error_string
			= talloc_asprintf(mem_ctx, 
					  "Search for domain: %s and realm: %s failed: %s", 
					  r2.out.domain_name, r2.out.realm, ldb_errstring(ldb));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else {
		int i;
		for (i = 0; i < ret; i++) {
			ldb_delete(ldb, msgs[i]->dn);
		}

		prior_secret = ldb_msg_find_ldb_val(msgs[0], "secret");
		if (prior_secret) {
			samdb_msg_set_value(ldb, mem_ctx, msg, "priorSecret", prior_secret);
		}
		samdb_msg_set_string(ldb, mem_ctx, msg, "secret", r2.out.join_password);
		
		prior_modified_time = ldb_msg_find_ldb_val(msgs[0], 
							   "whenChanged");
		if (prior_modified_time) {
			samdb_msg_set_value(ldb, mem_ctx, msg, "priorWhenChanged", 
					    prior_modified_time);
		}
		
		samdb_msg_set_string(ldb, mem_ctx, msg, "samAccountName", r2.in.account_name);
		samdb_msg_set_string(ldb, mem_ctx, msg, "secureChannelType", sct);
	}

	/* create the secret */
	ret = samdb_add(ldb, mem_ctx, msg);
	if (ret != 0) {
		r->out.error_string
			= talloc_asprintf(mem_ctx, 
					  "Failed to create secret record %s\n", 
					  msg->dn);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	return NT_STATUS_OK;
}

NTSTATUS libnet_Join(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_Join *r)
{
	NTSTATUS nt_status;
	struct libnet_Join r2;
	r2.in.secure_channel_type = r->in.secure_channel_type;
	r2.in.domain_name = r->in.domain_name;
	
	if ((r->in.secure_channel_type == SEC_CHAN_WKSTA)
	    || (r->in.secure_channel_type == SEC_CHAN_BDC)) {
		nt_status = libnet_Join_primary_domain(ctx, mem_ctx, &r2);
	} else {
		r->out.error_string
			= talloc_asprintf(mem_ctx, "Invalid secure channel type specified (%08X) attempting to join domain %s",
					 r->in.secure_channel_type, r->in.domain_name);
		return NT_STATUS_INVALID_PARAMETER;
	}
	r->out.error_string = r2.out.error_string;
	return nt_status;
}


