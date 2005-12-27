/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Brad Henry 2005
 
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
#include "lib/ldb/include/ldb_errors.h"
#include "libcli/cldap/cldap.h"
#include "include/secrets.h"
#include "librpc/gen_ndr/drsuapi.h"

/*
 * find out Site specific stuff:
 * 1.) setup an CLDAP socket
 * 2.) lookup the Site name
 * 3.) Add entry CN=<netbios name>,CN=Servers,CN=<site name>,CN=Sites,CN=Configuration,<domain dn>.
 * TODO: 4.) use DsAddEntry() to create CN=NTDS Settings,CN=<netbios name>,CN=Servers,CN=<site name>...
 */
static NTSTATUS libnet_JoinSite(struct libnet_context *ctx,
				struct dcerpc_pipe *drsuapi_pipe,
				struct policy_handle drsuapi_bind_handle,
				struct ldb_context *remote_ldb,
				struct libnet_JoinDomain *libnet_r)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;

	struct cldap_socket *cldap = NULL;
	struct cldap_netlogon search;

	struct ldb_dn *server_dn;
	struct ldb_message *msg;
	int rtn;

	const char *site_name;
	const char *server_dn_str;
	const char *config_dn_str;

	tmp_ctx = talloc_named(libnet_r, 0, "libnet_JoinSite temp context");
	if (!tmp_ctx) {
		libnet_r->out.error_string = NULL;
		return NT_STATUS_NO_MEMORY;
	}

	/* Resolve the site name. */

	ZERO_STRUCT(search);
	search.in.dest_address = libnet_r->out.samr_binding->host;
	search.in.acct_control = -1;
	search.in.version = 6;

	cldap = cldap_socket_init(tmp_ctx, NULL);
	status = cldap_netlogon(cldap, tmp_ctx, &search);
	if (!NT_STATUS_IS_OK(status)) {
		/* Default to using Default-First-Site-Name rather than returning status at this point. */
		site_name = talloc_asprintf(tmp_ctx, "%s", "Default-First-Site-Name");
		if (!site_name) {
			libnet_r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		site_name = search.out.netlogon.logon5.site_name;
	}

	config_dn_str = talloc_asprintf(tmp_ctx, "CN=Configuration,%s", libnet_r->out.domain_dn_str);
	if (!config_dn_str) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	server_dn_str = talloc_asprintf(tmp_ctx, "CN=%s,CN=Servers,CN=%s,CN=Sites,%s",
						 libnet_r->in.netbios_name, site_name, config_dn_str);
	if (!server_dn_str) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 Add entry CN=<netbios name>,CN=Servers,CN=<site name>,CN=Sites,CN=Configuration,<domain dn>.
	*/
	msg = ldb_msg_new(tmp_ctx);
	if (!msg) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	rtn = ldb_msg_add_string(msg, "objectClass", "server");
	if (rtn != 0) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	rtn = ldb_msg_add_string(msg, "systemFlags", "50000000");
	if (rtn != 0) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	rtn = ldb_msg_add_string(msg, "serverReference",libnet_r->out.account_dn_str);
	if (rtn != 0) {
		libnet_r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	server_dn = ldb_dn_explode(tmp_ctx, server_dn_str);
	if (server_dn == NULL) {
		libnet_r->out.error_string = talloc_asprintf(libnet_r, 
					"Invalid server dn: %s",
					server_dn_str);
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	msg->dn = server_dn; 

	rtn = ldb_add(remote_ldb, msg);
	if (rtn == LDB_ERR_ENTRY_ALREADY_EXISTS) {
		int i;
		
		/* make a 'modify' msg, and only for serverReference */
		msg = ldb_msg_new(tmp_ctx);
		if (!msg) {
			libnet_r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		msg->dn = server_dn; 

		rtn = ldb_msg_add_string(msg, "serverReference",libnet_r->out.account_dn_str);
		if (rtn != 0) {
			libnet_r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}
		
		/* mark all the message elements (should be just one)
		   as LDB_FLAG_MOD_REPLACE */
		for (i=0;i<msg->num_elements;i++) {
			msg->elements[i].flags = LDB_FLAG_MOD_REPLACE;
		}

		rtn = ldb_modify(remote_ldb, msg);
		if (rtn != 0) {
			libnet_r->out.error_string
				= talloc_asprintf(libnet_r,
						  "Failed to modify server entry %s: %s: %d",
						  server_dn_str,
						  ldb_errstring(remote_ldb), rtn);
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else if (rtn != 0) {
		libnet_r->out.error_string
			= talloc_asprintf(libnet_r,
				"Failed to add server entry %s: %s: %d",
				server_dn_str,
					  ldb_errstring(remote_ldb), rtn);
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	DEBUG(0, ("We still need to perform a DsAddEntry() so that we can create the CN=NTDS Settings container.\n"));

	/* Store the server DN in libnet_r */
	libnet_r->out.server_dn_str = server_dn_str;
	talloc_steal(libnet_r, server_dn_str);
	
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/*
 * complete a domain join, when joining to a AD domain:
 * 1.) connect and bind to the DRSUAPI pipe
 * 2.) do a DsCrackNames() to find the machine account dn
 * 3.) connect to LDAP
 * 4.) do an ldap search to find the "msDS-KeyVersionNumber" of the machine account
 * 5.) set the servicePrincipalName's of the machine account via LDAP, (maybe we should use DsWriteAccountSpn()...)
 * 6.) do a DsCrackNames() to find the domain dn
 * 7.) find out Site specific stuff, look at libnet_JoinSite() for details
 */
static NTSTATUS libnet_JoinADSDomain(struct libnet_context *ctx, struct libnet_JoinDomain *r)
{
	NTSTATUS status;

	TALLOC_CTX *tmp_ctx;

	const char *realm = r->out.realm;

	struct dcerpc_binding *samr_binding = r->out.samr_binding;

	struct dcerpc_pipe *drsuapi_pipe;
	struct dcerpc_binding *drsuapi_binding;
	struct drsuapi_DsBind r_drsuapi_bind;
	struct drsuapi_DsCrackNames r_crack_names;
	struct drsuapi_DsNameString names[1];
	struct policy_handle drsuapi_bind_handle;
	struct GUID drsuapi_bind_guid;

	struct ldb_context *remote_ldb;
	const struct ldb_dn *account_dn;
	const char *account_dn_str;
	const char *remote_ldb_url;
	struct ldb_result *res;
	struct ldb_message *msg;

	int ret, rtn;

	unsigned int kvno;
	
	const char * const attrs[] = {
		"msDS-KeyVersionNumber",
		"servicePrincipalName",
		"dNSHostName",
		NULL,
	};

	r->out.error_string = NULL;
	
	/* We need to convert between a samAccountName and domain to a
	 * DN in the directory.  The correct way to do this is with
	 * DRSUAPI CrackNames */

	/* Fiddle with the bindings, so get to DRSUAPI on
	 * NCACN_IP_TCP, sealed */
	tmp_ctx = talloc_named(r, 0, "libnet_JoinADSDomain temp context");  
	if (!tmp_ctx) {
		r->out.error_string = NULL;
		return NT_STATUS_NO_MEMORY;
	}
	                                           
	drsuapi_binding = talloc(tmp_ctx, struct dcerpc_binding);
	if (!drsuapi_binding) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	
	*drsuapi_binding = *samr_binding;

	/* DRSUAPI is only available on IP_TCP, and locally on NCALRPC */
	if (drsuapi_binding->transport != NCALRPC) {
		drsuapi_binding->transport = NCACN_IP_TCP;
	}
	drsuapi_binding->endpoint = NULL;
	drsuapi_binding->flags |= DCERPC_SEAL;

	status = dcerpc_pipe_connect_b(tmp_ctx, 
				       &drsuapi_pipe,
				       drsuapi_binding,
					   &dcerpc_table_drsuapi,
				       ctx->cred, 
				       ctx->event_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(r,
					"Connection to DRSUAPI pipe of PDC of domain '%s' failed: %s",
					r->in.domain_name,
					nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	/* get a DRSUAPI pipe handle */
	GUID_from_string(DRSUAPI_DS_BIND_GUID, &drsuapi_bind_guid);

	r_drsuapi_bind.in.bind_guid = &drsuapi_bind_guid;
	r_drsuapi_bind.in.bind_info = NULL;
	r_drsuapi_bind.out.bind_handle = &drsuapi_bind_handle;

	status = dcerpc_drsuapi_DsBind(drsuapi_pipe, tmp_ctx, &r_drsuapi_bind);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			r->out.error_string
				= talloc_asprintf(r,
						  "dcerpc_drsuapi_DsBind for [%s\\%s] failed - %s\n", 
						  r->in.domain_name, r->in.account_name, 
						  dcerpc_errstr(tmp_ctx, drsuapi_pipe->last_fault_code));
			talloc_free(tmp_ctx);
			return status;
		} else {
			r->out.error_string
				= talloc_asprintf(r,
						  "dcerpc_drsuapi_DsBind for [%s\\%s] failed - %s\n", 
						  r->in.domain_name, r->in.account_name, 
						  nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
	} else if (!W_ERROR_IS_OK(r_drsuapi_bind.out.result)) {
		r->out.error_string
				= talloc_asprintf(r,
						  "DsBind failed - %s\n", 
						  win_errstr(r_drsuapi_bind.out.result));
			talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Actually 'crack' the names */
	ZERO_STRUCT(r_crack_names);
	r_crack_names.in.bind_handle		= &drsuapi_bind_handle;
	r_crack_names.in.level			= 1;
	r_crack_names.in.req.req1.unknown1	= 0x000004e4;
	r_crack_names.in.req.req1.unknown2	= 0x00000407;
	r_crack_names.in.req.req1.count		= 1;
	r_crack_names.in.req.req1.names		= names;
	r_crack_names.in.req.req1.format_flags	= DRSUAPI_DS_NAME_FLAG_NO_FLAGS;
	r_crack_names.in.req.req1.format_offered= DRSUAPI_DS_NAME_FORMAT_SID_OR_SID_HISTORY;
	r_crack_names.in.req.req1.format_desired= DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = dom_sid_string(tmp_ctx, r->out.account_sid);
	if (!names[0].str) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_drsuapi_DsCrackNames(drsuapi_pipe, tmp_ctx, &r_crack_names);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			r->out.error_string
				= talloc_asprintf(r,
						  "dcerpc_drsuapi_DsCrackNames for [%s] failed - %s\n", 
						  names[0].str,
						  dcerpc_errstr(tmp_ctx, drsuapi_pipe->last_fault_code));
			talloc_free(tmp_ctx);
			return status;
		} else {
			r->out.error_string
				= talloc_asprintf(r,
						  "dcerpc_drsuapi_DsCrackNames for [%s] failed - %s\n", 
						  names[0].str,
						  nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
	} else if (!W_ERROR_IS_OK(r_crack_names.out.result)) {
		r->out.error_string
				= talloc_asprintf(r,
						  "DsCrackNames failed - %s\n", win_errstr(r_crack_names.out.result));
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	} else if (r_crack_names.out.level != 1 
		   || !r_crack_names.out.ctr.ctr1 
		   || r_crack_names.out.ctr.ctr1->count != 1 
		   || !r_crack_names.out.ctr.ctr1->array[0].result_name
		   || r_crack_names.out.ctr.ctr1->array[0].status != DRSUAPI_DS_NAME_STATUS_OK) {
		r->out.error_string = talloc_asprintf(r, "DsCrackNames failed\n");
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Store the DN of our machine account. */
	account_dn_str = r_crack_names.out.ctr.ctr1->array[0].result_name;

	account_dn = ldb_dn_explode(tmp_ctx, account_dn_str);
	if (!account_dn) {
		r->out.error_string = talloc_asprintf(r, "Invalid account dn: %s",
						      account_dn_str);
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Now we know the user's DN, open with LDAP, read and modify a few things */

	remote_ldb_url = talloc_asprintf(tmp_ctx, "ldap://%s", 
					 drsuapi_binding->host);
	if (!remote_ldb_url) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	remote_ldb = ldb_wrap_connect(tmp_ctx, remote_ldb_url, 
				      NULL, ctx->cred, 0, NULL);
	if (!remote_ldb) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* search for the user's record */
	ret = ldb_search(remote_ldb, account_dn, LDB_SCOPE_BASE, 
			     NULL, attrs, &res);
	if (ret != LDB_SUCCESS || res->count != 1) {
		r->out.error_string = talloc_asprintf(r, "ldb_search for %s failed - %s\n",
						      account_dn_str, ldb_errstring(remote_ldb));
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* If we have a kvno recorded in AD, we need it locally as well */
	kvno = ldb_msg_find_uint(res->msgs[0], "msDS-KeyVersionNumber", 0);

	/* Prepare a new message, for the modify */
	msg = ldb_msg_new(tmp_ctx);
	if (!msg) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	msg->dn = res->msgs[0]->dn;

	{
		int i;
		const char *service_principal_name[6];
		const char *dns_host_name = strlower_talloc(tmp_ctx, 
							    talloc_asprintf(tmp_ctx, 
									    "%s.%s", 
									    r->in.netbios_name, 
									    realm));

		if (!dns_host_name) {
			r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		service_principal_name[0] = talloc_asprintf(tmp_ctx, "host/%s", dns_host_name);
		service_principal_name[1] = talloc_asprintf(tmp_ctx, "host/%s", strlower_talloc(tmp_ctx, r->in.netbios_name));
		service_principal_name[2] = talloc_asprintf(tmp_ctx, "host/%s/%s", dns_host_name, realm);
		service_principal_name[3] = talloc_asprintf(tmp_ctx, "host/%s/%s", strlower_talloc(tmp_ctx, r->in.netbios_name), realm);
		service_principal_name[4] = talloc_asprintf(tmp_ctx, "host/%s/%s", dns_host_name, r->out.domain_name);
		service_principal_name[5] = talloc_asprintf(tmp_ctx, "host/%s/%s", strlower_talloc(tmp_ctx, r->in.netbios_name), r->out.domain_name);
		
		for (i=0; i < ARRAY_SIZE(service_principal_name); i++) {
			if (!service_principal_name[i]) {
				r->out.error_string = NULL;
				talloc_free(tmp_ctx);
				return NT_STATUS_NO_MEMORY;
			}
			rtn = samdb_msg_add_string(remote_ldb, tmp_ctx, msg, "servicePrincipalName", service_principal_name[i]);
			if (rtn == -1) {
				r->out.error_string = NULL;
				talloc_free(tmp_ctx);
				return NT_STATUS_NO_MEMORY;
			}
		}

		rtn = samdb_msg_add_string(remote_ldb, tmp_ctx, msg, "dNSHostName", dns_host_name);
		if (rtn == -1) {
			r->out.error_string = NULL;
			talloc_free(tmp_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		rtn = samdb_replace(remote_ldb, tmp_ctx, msg);
		if (rtn != 0) {
			r->out.error_string
				= talloc_asprintf(r, 
						  "Failed to replace entries on %s\n", 
						  ldb_dn_linearize(tmp_ctx, msg->dn));
			talloc_free(tmp_ctx);
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}
				
	/* DsCrackNames to find out the DN of the domain. */
	r_crack_names.in.req.req1.format_offered = DRSUAPI_DS_NAME_FORMAT_NT4_ACCOUNT;
	r_crack_names.in.req.req1.format_desired = DRSUAPI_DS_NAME_FORMAT_FQDN_1779;
	names[0].str = talloc_asprintf(tmp_ctx, "%s\\", r->out.domain_name);
	if (!names[0].str) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_drsuapi_DsCrackNames(drsuapi_pipe, tmp_ctx, &r_crack_names);
	if (!NT_STATUS_IS_OK(status)) {
		if (NT_STATUS_EQUAL(status, NT_STATUS_NET_WRITE_FAULT)) {
			r->out.error_string
				= talloc_asprintf(r,
						  "dcerpc_drsuapi_DsCrackNames for [%s] failed - %s\n", 
						  r->in.domain_name, 
						  dcerpc_errstr(tmp_ctx, drsuapi_pipe->last_fault_code));
			talloc_free(tmp_ctx);
			return status;
		} else {
			r->out.error_string
				= talloc_asprintf(r,
						  "dcerpc_drsuapi_DsCrackNames for [%s] failed - %s\n", 
						  r->in.domain_name, 
						  nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
	} else if (!W_ERROR_IS_OK(r_crack_names.out.result)) {
		r->out.error_string
			= talloc_asprintf(r,
					  "DsCrackNames failed - %s\n", win_errstr(r_crack_names.out.result));
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	} else if (r_crack_names.out.level != 1 
		   || !r_crack_names.out.ctr.ctr1 
		   || r_crack_names.out.ctr.ctr1->count != 1
		   || !r_crack_names.out.ctr.ctr1->array[0].result_name		  
		   || r_crack_names.out.ctr.ctr1->array[0].status != DRSUAPI_DS_NAME_STATUS_OK) {
		r->out.error_string = talloc_asprintf(r, "DsCrackNames failed\n");
		talloc_free(tmp_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Store the account DN. */
	r->out.account_dn_str = account_dn_str;
	talloc_steal(r, account_dn_str);

	/* Store the domain DN. */
	r->out.domain_dn_str = r_crack_names.out.ctr.ctr1->array[0].result_name;
	talloc_steal(r, r_crack_names.out.ctr.ctr1->array[0].result_name);

	r->out.kvno = kvno;

	if (r->in.acct_type ==  ACB_SVRTRUST) {
		status = libnet_JoinSite(ctx,
					 drsuapi_pipe, drsuapi_bind_handle,
					 remote_ldb, r);
	}
	talloc_free(tmp_ctx);

	return status;
}

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
 * 8. do some ADS specific things when we join as Domain Controller,
 *    look at libnet_joinADSDomain() for the details
 */
NTSTATUS libnet_JoinDomain(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_JoinDomain *r)
{
	TALLOC_CTX *tmp_ctx;

	NTSTATUS status, cu_status;
	struct libnet_RpcConnect *c;
	struct lsa_ObjectAttribute attr;
	struct lsa_QosInfo qos;
	struct lsa_OpenPolicy2 lsa_open_policy;
	struct policy_handle lsa_p_handle;
	struct lsa_QueryInfoPolicy2 lsa_query_info2;
	struct lsa_QueryInfoPolicy lsa_query_info;

	struct dcerpc_binding *samr_binding;
	struct dcerpc_pipe *samr_pipe;
	struct dcerpc_pipe *lsa_pipe;
	struct samr_Connect sc;
	struct policy_handle p_handle;
	struct samr_OpenDomain od;
	struct policy_handle d_handle;
	struct samr_LookupNames ln;
	struct samr_OpenUser ou;
	struct samr_CreateUser2 cu;
	struct policy_handle *u_handle = NULL;
	struct samr_QueryUserInfo qui;
	struct samr_SetUserInfo sui;
	union samr_UserInfo u_info;
	union libnet_SetPassword r2;
	struct samr_GetUserPwInfo pwp;
	struct lsa_String samr_account_name;
	
	uint32_t acct_flags, old_acct_flags;
	uint32_t rid, access_granted;
	int policy_min_pw_len = 0;

	struct dom_sid *domain_sid = NULL;
	struct dom_sid *account_sid = NULL;
	const char *domain_name = NULL;
	const char *password_str = NULL;
	const char *realm = NULL; /* Also flag for remote being AD */
	
	
	r->out.error_string = NULL;
	r2.samr_handle.out.error_string = NULL;
	
	tmp_ctx = talloc_named(mem_ctx, 0, "libnet_Join temp context");
	if (!tmp_ctx) {
		r->out.error_string = NULL;
		return NT_STATUS_NO_MEMORY;
	}
	
	u_handle = talloc(tmp_ctx, struct policy_handle);
	if (!u_handle) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	
	samr_pipe = talloc(tmp_ctx, struct dcerpc_pipe);
	if (!samr_pipe) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	
	c = talloc(tmp_ctx, struct libnet_RpcConnect);
	if (!c) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}
	
	/* prepare connect to the LSA pipe of PDC */
	if (r->in.level == LIBNET_JOINDOMAIN_AUTOMATIC) {
		c->level             = LIBNET_RPC_CONNECT_PDC;
		c->in.domain_name    = r->in.domain_name;
	} else {
		c->level             = LIBNET_RPC_CONNECT_BINDING;
		c->in.binding        = r->in.binding;
	}
	c->in.dcerpc_iface      = &dcerpc_table_lsarpc;
	
	/* connect to the LSA pipe of the PDC */

	status = libnet_RpcConnect(ctx, c, c);
	if (!NT_STATUS_IS_OK(status)) {
		if (r->in.level == LIBNET_JOINDOMAIN_AUTOMATIC) {
			r->out.error_string = talloc_asprintf(mem_ctx,
							      "Connection to LSA pipe of PDC of domain '%s' failed: %s",
							      r->in.domain_name, nt_errstr(status));
		} else {
			r->out.error_string = talloc_asprintf(mem_ctx,
							      "Connection to LSA pipe with binding '%s' failed: %s",
							      r->in.binding, nt_errstr(status));
		}
		talloc_free(tmp_ctx);
		return status;
	}			
	lsa_pipe = c->out.dcerpc_pipe;
	
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
	
	lsa_open_policy.in.system_name = talloc_asprintf(tmp_ctx, "\\"); 
	if (!lsa_open_policy.in.system_name) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	lsa_open_policy.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	lsa_open_policy.out.handle = &lsa_p_handle;

	status = dcerpc_lsa_OpenPolicy2(lsa_pipe, tmp_ctx, &lsa_open_policy); 

	/* This now fails on ncacn_ip_tcp against Win2k3 SP1 */
	if (NT_STATUS_IS_OK(status)) {
		/* Look to see if this is ADS (a fault indicates NT4 or Samba 3.0) */
		
		lsa_query_info2.in.handle = &lsa_p_handle;
		lsa_query_info2.in.level = LSA_POLICY_INFO_DNS;
		
		status = dcerpc_lsa_QueryInfoPolicy2(lsa_pipe, tmp_ctx, 		
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
		
		/* Grab the domain SID (regardless of the result of the previous call */
		
		lsa_query_info.in.handle = &lsa_p_handle;
		lsa_query_info.in.level = LSA_POLICY_INFO_DOMAIN;
		
		status = dcerpc_lsa_QueryInfoPolicy(lsa_pipe, tmp_ctx, 
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
	} else {
		/* Cause the code further down to try this with just SAMR */
		domain_sid = NULL;
		if (r->in.level == LIBNET_JOINDOMAIN_AUTOMATIC) {
			domain_name = talloc_strdup(tmp_ctx, r->in.domain_name);
		} else {
			/* Bugger, we just lost our way to automaticly find the domain name */
			domain_name = talloc_strdup(tmp_ctx, lp_workgroup());
		}
	}

	/*
	  establish a SAMR connection, on the same CIFS transport
	*/

	/* Find the original binding string */
	status = dcerpc_parse_binding(tmp_ctx, lsa_pipe->conn->binding_string, &samr_binding);	
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"Failed to parse lsa binding '%s'",
						lsa_pipe->conn->binding_string);
		talloc_free(tmp_ctx);
		return status;
	}

	/* Make binding string for samr, not the other pipe */
	status = dcerpc_epm_map_binding(tmp_ctx, samr_binding, 					
					&dcerpc_table_samr,
					lsa_pipe->conn->event_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"Failed to map DCERPC/TCP NCACN_NP pipe for '%s' - %s",
						DCERPC_NETLOGON_UUID,
						nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	/* Setup a SAMR connection */
	status = dcerpc_secondary_connection(lsa_pipe, &samr_pipe, samr_binding);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"SAMR secondary connection failed: %s",
						nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	status = dcerpc_pipe_auth(samr_pipe, samr_binding, &dcerpc_table_samr, ctx->cred);
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
						"samr_Connect failed: %s",
						nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	/* Perhaps we didn't get a SID above, because we are against ncacn_ip_tcp */
	if (!domain_sid) {
		struct lsa_String name;
		struct samr_LookupDomain l;
		name.string = domain_name;
		l.in.connect_handle = &p_handle;
		l.in.domain_name = &name;
		
		status = dcerpc_samr_LookupDomain(samr_pipe, tmp_ctx, &l);
		if (!NT_STATUS_IS_OK(status)) {
			r->out.error_string = talloc_asprintf(mem_ctx,
							      "SAMR LookupDomain failed: %s",
							      nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
		domain_sid = l.out.sid;
	}

	/* prepare samr_OpenDomain */
	ZERO_STRUCT(d_handle);
	od.in.connect_handle = &p_handle;
	od.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
	od.in.sid = domain_sid;
	od.out.domain_handle = &d_handle;

	/* do a samr_OpenDomain to get a domain handle */
	status = dcerpc_samr_OpenDomain(samr_pipe, tmp_ctx, &od);			
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
					"samr_OpenDomain for [%s] failed: %s",
					r->in.domain_name,
					nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}
	
	/* prepare samr_CreateUser2 */
	ZERO_STRUCTP(u_handle);
	cu.in.domain_handle  = &d_handle;
	cu.in.access_mask     = SEC_FLAG_MAXIMUM_ALLOWED;
	samr_account_name.string = r->in.account_name;
	cu.in.account_name    = &samr_account_name;
	cu.in.acct_flags      = r->in.acct_type;
	cu.out.user_handle    = u_handle;
	cu.out.rid            = &rid;
	cu.out.access_granted = &access_granted;

	/* do a samr_CreateUser2 to get an account handle, or an error */
	cu_status = dcerpc_samr_CreateUser2(samr_pipe, tmp_ctx, &cu);			
	status = cu_status;
	if (NT_STATUS_EQUAL(status, NT_STATUS_USER_EXISTS)) {
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
						"samr_LookupNames for [%s] failed: %s",
						r->in.account_name,
						nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
		
		/* check if we got one RID for the user */
		if (ln.out.rids.count != 1) {
			r->out.error_string = talloc_asprintf(mem_ctx,
							      "samr_LookupNames for [%s] returns %d RIDs\n",
							      r->in.account_name, ln.out.rids.count);
			talloc_free(tmp_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		}
		
		/* prepare samr_OpenUser */
		ZERO_STRUCTP(u_handle);
		ou.in.domain_handle = &d_handle;
		ou.in.access_mask = SEC_FLAG_MAXIMUM_ALLOWED;
		ou.in.rid = ln.out.rids.ids[0];
		rid = ou.in.rid;
		ou.out.user_handle = u_handle;
		
		/* 6. do a samr_OpenUser to get a user handle */
		status = dcerpc_samr_OpenUser(samr_pipe, tmp_ctx, &ou); 
		if (!NT_STATUS_IS_OK(status)) {
			r->out.error_string = talloc_asprintf(mem_ctx,
							"samr_OpenUser for [%s] failed: %s",
							r->in.account_name,
							nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}

		if (r->in.recreate_account) {
			struct samr_DeleteUser d;
			d.in.user_handle = u_handle;
			d.out.user_handle = u_handle;
			status = dcerpc_samr_DeleteUser(samr_pipe, mem_ctx, &d);
			if (!NT_STATUS_IS_OK(status)) {
				r->out.error_string = talloc_asprintf(mem_ctx,
								      "samr_DeleteUser (for recreate) of [%s] failed: %s",
								      r->in.account_name,
								      nt_errstr(status));
				talloc_free(tmp_ctx);
				return status;
			}

			/* We want to recreate, so delete and another samr_CreateUser2 */
			
			/* &cu filled in above */
			status = dcerpc_samr_CreateUser2(samr_pipe, tmp_ctx, &cu);			
			if (!NT_STATUS_IS_OK(status)) {
				r->out.error_string = talloc_asprintf(mem_ctx,
								      "samr_CreateUser2 (recreate) for [%s] failed: %s\n",
								      r->in.domain_name, nt_errstr(status));
				talloc_free(tmp_ctx);
				return status;
			}
		}
	} else if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						      "samr_CreateUser2 for [%s] failed: %s\n",
						      r->in.domain_name, nt_errstr(status));
		talloc_free(tmp_ctx);
		return status;
	}

	/* prepare samr_QueryUserInfo (get flags) */
	qui.in.user_handle = u_handle;
	qui.in.level = 16;
	
	status = dcerpc_samr_QueryUserInfo(samr_pipe, tmp_ctx, &qui);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_asprintf(mem_ctx,
						"samr_QueryUserInfo for [%s] failed: %s",
						r->in.account_name,
						nt_errstr(status));
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

	old_acct_flags = (qui.out.info->info16.acct_flags & (ACB_WSTRUST | ACB_SVRTRUST | ACB_DOMTRUST));
	/* Possibly bail if the account is of the wrong type */
	if (old_acct_flags
	    != r->in.acct_type) {
		const char *old_account_type, *new_account_type;
		switch (old_acct_flags) {
		case ACB_WSTRUST:
			old_account_type = "domain member (member)";
			break;
		case ACB_SVRTRUST:
			old_account_type = "domain controller (bdc)";
			break;
		case ACB_DOMTRUST:
			old_account_type = "trusted domain";
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
		}
		switch (r->in.acct_type) {
		case ACB_WSTRUST:
			new_account_type = "domain member (member)";
			break;
		case ACB_SVRTRUST:
			new_account_type = "domain controller (bdc)";
			break;
		case ACB_DOMTRUST:
			new_account_type = "trusted domain";
			break;
		default:
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (!NT_STATUS_EQUAL(cu_status, NT_STATUS_USER_EXISTS)) {
			/* We created a new user, but they didn't come out the right type?!? */
			r->out.error_string
				= talloc_asprintf(mem_ctx,
						  "We asked to create a new machine account (%s) of type %s, but we got an account of type %s.  This is unexpected.  Perhaps delete the account and try again.\n",
						  r->in.account_name, new_account_type, old_account_type);
			talloc_free(tmp_ctx);
			return NT_STATUS_INVALID_PARAMETER;
		} else {
			/* The account is of the wrong type, so bail */

			/* TODO: We should allow a --force option to override, and redo this from the top setting r.in.recreate_account */
			r->out.error_string
				= talloc_asprintf(mem_ctx,
						  "The machine account (%s) already exists in the domain %s, but is a %s.  You asked to join as a %s.  Please delete the account and try again.\n",
						  r->in.account_name, domain_name, old_account_type, new_account_type);
			talloc_free(tmp_ctx);
			return NT_STATUS_USER_EXISTS;
		}
	} else {
		acct_flags = qui.out.info->info16.acct_flags;
	}
	
	acct_flags = (acct_flags & ~ACB_DISABLED);

	/* Find out what password policy this user has */
	pwp.in.user_handle = u_handle;

	status = dcerpc_samr_GetUserPwInfo(samr_pipe, tmp_ctx, &pwp);				
	if (NT_STATUS_IS_OK(status)) {
		policy_min_pw_len = pwp.out.info.min_password_length;
	}
	
	/* Grab a password of that minimum length */
	
	password_str = generate_random_str(tmp_ctx, MAX(8, policy_min_pw_len));	

	r2.samr_handle.level		= LIBNET_SET_PASSWORD_SAMR_HANDLE;
	r2.samr_handle.in.account_name	= r->in.account_name;
	r2.samr_handle.in.newpassword	= password_str;
	r2.samr_handle.in.user_handle   = u_handle;
	r2.samr_handle.in.dcerpc_pipe   = samr_pipe;

	status = libnet_SetPassword(ctx, tmp_ctx, &r2);	
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_steal(mem_ctx, r2.samr_handle.out.error_string);
		talloc_free(tmp_ctx);
		return status;
	}

	/* reset flags (if required) */
	if (acct_flags != qui.out.info->info16.acct_flags) {	
		ZERO_STRUCT(u_info);
		u_info.info16.acct_flags = acct_flags;

		sui.in.user_handle = u_handle;
		sui.in.info = &u_info;
		sui.in.level = 16;
		
		dcerpc_samr_SetUserInfo(samr_pipe, tmp_ctx, &sui);
		if (!NT_STATUS_IS_OK(status)) {
			r->out.error_string = talloc_asprintf(mem_ctx,
							"samr_SetUserInfo for [%s] failed to remove ACB_DISABLED flag: %s",
							r->in.account_name,
							nt_errstr(status));
			talloc_free(tmp_ctx);
			return status;
		}
	}

	account_sid = dom_sid_add_rid(mem_ctx, domain_sid, rid);
	if (!account_sid) {
		r->out.error_string = NULL;
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* Finish out by pushing various bits of status data out for the caller to use */
	r->out.join_password = password_str;
	talloc_steal(mem_ctx, password_str);

	r->out.domain_sid = domain_sid;
	talloc_steal(mem_ctx, domain_sid);

	r->out.account_sid = account_sid;
	talloc_steal(mem_ctx, account_sid);

	r->out.domain_name = domain_name;
	talloc_steal(mem_ctx, domain_name);
	r->out.realm = realm;
	talloc_steal(mem_ctx, realm);
	r->out.lsa_pipe = lsa_pipe;
	talloc_steal(mem_ctx, lsa_pipe);
	r->out.samr_pipe = samr_pipe;
	talloc_steal(mem_ctx, samr_pipe);
	r->out.samr_binding = samr_binding;
	talloc_steal(mem_ctx, samr_binding);
	r->out.user_handle = u_handle;
	talloc_steal(mem_ctx, u_handle);
	r->out.error_string = r2.samr_handle.out.error_string;
	talloc_steal(mem_ctx, r2.samr_handle.out.error_string);
	r->out.kvno = 0;
	r->out.server_dn_str = NULL;
	talloc_free(tmp_ctx); 

	/* Now, if it was AD, then we want to start looking changing a
	 * few more things.  Otherwise, we are done. */
	if (realm) {
		status = libnet_JoinADSDomain(ctx, r);
		return status;
	}

	return status;
}

static NTSTATUS libnet_Join_primary_domain(struct libnet_context *ctx, 
					   TALLOC_CTX *mem_ctx, 
					   struct libnet_Join *r)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_mem;
	struct libnet_JoinDomain *r2;
	int ret, rtn;
	struct ldb_context *ldb;
	const struct ldb_dn *base_dn;
	struct ldb_message **msgs, *msg;
	const char *sct;
	const char * const attrs[] = {
		"whenChanged",
		"secret",
		"priorSecret",
		"priorChanged",
		NULL
	};
	uint32_t acct_type = 0;
	const char *account_name;
	const char *netbios_name;
	char *filter;
	
	r->out.error_string = NULL;

	tmp_mem = talloc_new(mem_ctx);
	if (!tmp_mem) {
		return NT_STATUS_NO_MEMORY;
	}

	r2 = talloc(tmp_mem, struct libnet_JoinDomain);
	if (!r2) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}
	
	if (r->in.secure_channel_type == SEC_CHAN_BDC) {
		acct_type = ACB_SVRTRUST;
	} else if (r->in.secure_channel_type == SEC_CHAN_WKSTA) {
		acct_type = ACB_WSTRUST;
	} else {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);	
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((r->in.netbios_name != NULL) && (r->in.level != LIBNET_JOIN_AUTOMATIC)) {
		netbios_name = r->in.netbios_name;
	} else {
		netbios_name = talloc_asprintf(tmp_mem, "%s", lp_netbios_name());
		if (!netbios_name) {
			r->out.error_string = NULL;
			talloc_free(tmp_mem);
			return NT_STATUS_NO_MEMORY;
		}
	}

	account_name = talloc_asprintf(tmp_mem, "%s$", netbios_name);
	if (!account_name) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}
	
	/*
	 * Local secrets are stored in secrets.ldb 
	 * open it to make sure we can write the info into it after the join
	 */
	ldb = secrets_db_connect(tmp_mem);
	if (!ldb) {
		r->out.error_string
			= talloc_asprintf(mem_ctx, 
					  "Could not open secrets database\n");
		talloc_free(tmp_mem);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	/*
	 * join the domain
	 */
	ZERO_STRUCTP(r2);
	r2->in.domain_name	= r->in.domain_name;
	r2->in.account_name	= account_name;
	r2->in.netbios_name	= netbios_name;
	r2->in.level		= LIBNET_JOINDOMAIN_AUTOMATIC;
	r2->in.acct_type	= acct_type;
	r2->in.recreate_account = False;
	status = libnet_JoinDomain(ctx, r2, r2);
	if (!NT_STATUS_IS_OK(status)) {
		r->out.error_string = talloc_steal(mem_ctx, r2->out.error_string);
		talloc_free(tmp_mem);
		return status;
	}
	
	/*
	 * now prepare the record for secrets.ldb
	 */
	sct = talloc_asprintf(tmp_mem, "%d", r->in.secure_channel_type); 
	if (!sct) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}
	
	msg = ldb_msg_new(tmp_mem);
	if (!msg) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}

	base_dn = ldb_dn_explode(tmp_mem, "cn=Primary Domains");
	if (!base_dn) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}

	msg->dn = ldb_dn_build_child(tmp_mem, "flatname", r2->out.domain_name, base_dn);
	if (!msg->dn) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}
	
	rtn = samdb_msg_add_string(ldb, tmp_mem, msg, "flatname", r2->out.domain_name);
	if (rtn == -1) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}

	if (r2->out.realm) {
		rtn = samdb_msg_add_string(ldb, tmp_mem, msg, "realm", r2->out.realm);
		if (rtn == -1) {
			r->out.error_string = NULL;
			talloc_free(tmp_mem);
			return NT_STATUS_NO_MEMORY;
		}

		rtn = samdb_msg_add_string(ldb, tmp_mem, msg, "objectClass", "primaryDomain");
		if (rtn == -1) {
			r->out.error_string = NULL;
			talloc_free(tmp_mem);
			return NT_STATUS_NO_MEMORY;
		}
	}

	rtn = samdb_msg_add_string(ldb, tmp_mem, msg, "objectClass", "primaryDomain");
	if (rtn == -1) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}

	rtn = samdb_msg_add_string(ldb, tmp_mem, msg, "secret", r2->out.join_password);
	if (rtn == -1) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}

	rtn = samdb_msg_add_string(ldb, tmp_mem, msg, "samAccountName", r2->in.account_name);
	if (rtn == -1) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}

	rtn = samdb_msg_add_string(ldb, tmp_mem, msg, "secureChannelType", sct);
	if (rtn == -1) {
		r->out.error_string = NULL;
		talloc_free(tmp_mem);
		return NT_STATUS_NO_MEMORY;
	}

	if (r2->out.kvno) {
		rtn = samdb_msg_add_uint(ldb, tmp_mem, msg, "msDS-KeyVersionNumber",
					 r2->out.kvno);
		if (rtn == -1) {
			r->out.error_string = NULL;
			talloc_free(tmp_mem);
			return NT_STATUS_NO_MEMORY;
		}
	}

	if (r2->out.domain_sid) {
		rtn = samdb_msg_add_dom_sid(ldb, tmp_mem, msg, "objectSid",
					    r2->out.domain_sid);
		if (rtn == -1) {
			r->out.error_string = NULL;
			talloc_free(tmp_mem);
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* 
	 * search for the secret record
	 * - remove the records we find
	 * - and fetch the old secret and store it under priorSecret
	 */
	ret = gendb_search(ldb,
			   tmp_mem, base_dn,
			   &msgs, attrs,
			   "(|" SECRETS_PRIMARY_DOMAIN_FILTER "(realm=%s))",
			   r2->out.domain_name, r2->out.realm);
	if (ret == 0) {
	} else if (ret == -1) {
		r->out.error_string
			= talloc_asprintf(mem_ctx, 
					  "Search for domain: %s and realm: %s failed: %s", 
					  r2->out.domain_name, r2->out.realm, ldb_errstring(ldb));
		talloc_free(tmp_mem);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else {
		const struct ldb_val *prior_secret;
		const struct ldb_val *prior_modified_time;
		int i;

		for (i = 0; i < ret; i++) {
			ldb_delete(ldb, msgs[i]->dn);
		}

		prior_secret = ldb_msg_find_ldb_val(msgs[0], "secret");
		if (prior_secret) {
			rtn = samdb_msg_set_value(ldb, tmp_mem, msg, "priorSecret", prior_secret);
			if (rtn == -1) {
				r->out.error_string = NULL;
				talloc_free(tmp_mem);
				return NT_STATUS_NO_MEMORY;
			}
		}
		rtn = samdb_msg_set_string(ldb, tmp_mem, msg, "secret", r2->out.join_password);
		if (rtn == -1) {
			r->out.error_string = NULL;
			talloc_free(tmp_mem);
			return NT_STATUS_NO_MEMORY;
		}

		prior_modified_time = ldb_msg_find_ldb_val(msgs[0], 
							   "whenChanged");
		if (prior_modified_time) {
			rtn = samdb_msg_set_value(ldb, tmp_mem, msg, "priorWhenChanged", 
						  prior_modified_time);
			if (rtn == -1) {
				r->out.error_string = NULL;
				talloc_free(tmp_mem);
				return NT_STATUS_NO_MEMORY;
			}
		}

		rtn = samdb_msg_set_string(ldb, tmp_mem, msg, "samAccountName", r2->in.account_name);
		if (rtn == -1) {
			r->out.error_string = NULL;
			talloc_free(tmp_mem);
			return NT_STATUS_NO_MEMORY;
		}

		rtn = samdb_msg_set_string(ldb, tmp_mem, msg, "secureChannelType", sct);
		if (rtn == -1) {
			r->out.error_string = NULL;
			talloc_free(tmp_mem);
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* create the secret */
	ret = samdb_add(ldb, tmp_mem, msg);
	if (ret != 0) {
		r->out.error_string = talloc_asprintf(mem_ctx, "Failed to create secret record %s\n", 
						      ldb_dn_linearize(ldb, msg->dn));
		talloc_free(tmp_mem);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (r2->out.realm) {
		struct cli_credentials *creds;
		/* Make a credentials structure from it */
		creds = cli_credentials_init(mem_ctx);
		if (!creds) {
			r->out.error_string = NULL;
			talloc_free(tmp_mem);
			return NT_STATUS_NO_MEMORY;
		}
		cli_credentials_set_conf(creds);
		filter = talloc_asprintf(mem_ctx, "dn=%s", ldb_dn_linearize(mem_ctx, msg->dn));
		status = cli_credentials_set_secrets(creds, NULL, filter);
		if (!NT_STATUS_IS_OK(status)) {
			r->out.error_string = talloc_asprintf(mem_ctx, "Failed to read secrets for keytab update for %s\n", 
							      filter);
			talloc_free(tmp_mem);
			return status;
		} 
		ret = cli_credentials_update_keytab(creds);
		if (ret != 0) {
			r->out.error_string = talloc_asprintf(mem_ctx, "Failed to update keytab for %s\n", 
							      filter);
			talloc_free(tmp_mem);
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	/* move all out parameter to the callers TALLOC_CTX */
	r->out.error_string	= NULL;
	r->out.join_password	= r2->out.join_password;
	talloc_steal(mem_ctx, r2->out.join_password);
	r->out.domain_sid	= r2->out.domain_sid;
	talloc_steal(mem_ctx, r2->out.domain_sid);
	r->out.domain_name      = r2->out.domain_name;
	talloc_steal(mem_ctx, r2->out.domain_name);
	talloc_free(tmp_mem);
	return NT_STATUS_OK;
}

NTSTATUS libnet_Join(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_Join *r)
{
	switch (r->in.secure_channel_type) {
		case SEC_CHAN_WKSTA:
			return libnet_Join_primary_domain(ctx, mem_ctx, r);
		case SEC_CHAN_BDC:
			return libnet_Join_primary_domain(ctx, mem_ctx, r);
		case SEC_CHAN_DOMAIN:
			break;
	}

	r->out.error_string = talloc_asprintf(mem_ctx,
				"Invalid secure channel type specified (%08X) attempting to join domain %s",
				r->in.secure_channel_type, r->in.domain_name);
	return NT_STATUS_INVALID_PARAMETER;
}


