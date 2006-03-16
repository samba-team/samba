/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2004
   Copyright (C) Gerald Carter                             2003
   Copyright (C) Stefan Metzmacher                         2005
   
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
#include "system/time.h"
#include "auth/auth.h"
#include "db_wrap.h"
#include "dsdb/samdb/samdb.h"
#include "libcli/security/proto.h"
#include "libcli/ldap/ldap.h"
#include "librpc/gen_ndr/ndr_security.h"

static const char *user_attrs[] = {
	/* requried for the krb5 kdc*/
	"objectClass",
	"sAMAccountName",
	"userPrincipalName",
	"servicePrincipalName",
	"msDS-KeyVersionNumber",
	"krb5Key",

	/* passwords */
	"lmPwdHash", 
	"ntPwdHash",

	"userAccountControl",

	"pwdLastSet",
	"accountExpires",
	
	"objectSid",

	/* check 'allowed workstations' */
	"userWorkstations",
		       
	/* required for server_info, not access control: */
	"displayName",
	"scriptPath",
	"profilePath",
	"homeDirectory",
	"homeDrive",
	"lastLogon",
	"lastLogoff",
	"accountExpires",
	"badPwdCount",
	"logonCount",
	"primaryGroupID",
	NULL,
};

static const char *domain_ref_attrs[] =  {"nETBIOSName", "nCName", 
					  "dnsRoot", "objectClass", NULL};

/****************************************************************************
 Do a specific test for an smb password being correct, given a smb_password and
 the lanman and NT responses.
****************************************************************************/
static NTSTATUS authsam_password_ok(struct auth_context *auth_context,
				    TALLOC_CTX *mem_ctx,
				    uint16_t acct_flags,
				    const struct samr_Password *lm_pwd, 
				    const struct samr_Password *nt_pwd,
				    const struct auth_usersupplied_info *user_info, 
				    DATA_BLOB *user_sess_key, 
				    DATA_BLOB *lm_sess_key)
{
	NTSTATUS status;

	if (acct_flags & ACB_PWNOTREQ) {
		if (lp_null_passwords()) {
			DEBUG(3,("Account for user '%s' has no password and null passwords are allowed.\n", 
				 user_info->mapped.account_name));
			return NT_STATUS_OK;
		} else {
			DEBUG(3,("Account for user '%s' has no password and null passwords are NOT allowed.\n", 
				 user_info->mapped.account_name));
			return NT_STATUS_LOGON_FAILURE;
		}		
	}

	switch (user_info->password_state) {
	case AUTH_PASSWORD_PLAIN: 
	{
		const struct auth_usersupplied_info *user_info_temp;	
		status = encrypt_user_info(mem_ctx, auth_context, 
					   AUTH_PASSWORD_HASH, 
					   user_info, &user_info_temp);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to convert plaintext password to password HASH: %s\n", nt_errstr(status)));
			return status;
		}
		user_info = user_info_temp;

		/* NO break */
	}
	case AUTH_PASSWORD_HASH:
		*lm_sess_key = data_blob(NULL, 0);
		*user_sess_key = data_blob(NULL, 0);
		status = hash_password_check(mem_ctx, 
					     user_info->password.hash.lanman,
					     user_info->password.hash.nt,
					     user_info->mapped.account_name,
					     lm_pwd, nt_pwd);
		NT_STATUS_NOT_OK_RETURN(status);
		break;
		
	case AUTH_PASSWORD_RESPONSE:
		status = ntlm_password_check(mem_ctx, user_info->logon_parameters, 
					     &auth_context->challenge.data, 
					     &user_info->password.response.lanman, 
					     &user_info->password.response.nt,
					     user_info->mapped.account_name,
					     user_info->client.account_name, 
					     user_info->client.domain_name, 
					     lm_pwd, nt_pwd,
					     user_sess_key, lm_sess_key);
		NT_STATUS_NOT_OK_RETURN(status);
		break;
	}

	if (user_sess_key && user_sess_key->data) {
		talloc_steal(auth_context, user_sess_key->data);
	}
	if (lm_sess_key && lm_sess_key->data) {
		talloc_steal(auth_context, lm_sess_key->data);
	}

	return NT_STATUS_OK;
}


/****************************************************************************
 Do a specific test for a SAM_ACCOUNT being vaild for this connection 
 (ie not disabled, expired and the like).
****************************************************************************/
NTSTATUS authsam_account_ok(TALLOC_CTX *mem_ctx,
			    struct ldb_context *sam_ctx,
			    uint32_t logon_parameters,
			    struct ldb_message *msg,
			    struct ldb_message *msg_domain_ref,
			    const char *logon_workstation,
			    const char *name_for_logs)
{
	uint16_t acct_flags;
	const char *workstation_list;
	NTTIME acct_expiry;
	NTTIME must_change_time;
	NTTIME last_set_time;

	struct ldb_dn *domain_dn = samdb_result_dn(mem_ctx, msg_domain_ref, "nCName", ldb_dn_new(mem_ctx));

	NTTIME now;
	DEBUG(4,("authsam_account_ok: Checking SMB password for user %s\n", name_for_logs));

	acct_flags = samdb_result_acct_flags(msg, "userAccountControl");
	
	acct_expiry = samdb_result_nttime(msg, "accountExpires", 0);
	must_change_time = samdb_result_force_password_change(sam_ctx, mem_ctx, 
							      domain_dn, msg);
	last_set_time = samdb_result_nttime(msg, "pwdLastSet", 0);

	workstation_list = samdb_result_string(msg, "userWorkstations", NULL);

	/* Quit if the account was disabled. */
	if (acct_flags & ACB_DISABLED) {
		DEBUG(1,("authsam_account_ok: Account for user '%s' was disabled.\n", name_for_logs));
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	/* Quit if the account was locked out. */
	if (acct_flags & ACB_AUTOLOCK) {
		DEBUG(1,("authsam_account_ok: Account for user %s was locked out.\n", name_for_logs));
		return NT_STATUS_ACCOUNT_LOCKED_OUT;
	}

	/* Test account expire time */
	unix_to_nt_time(&now, time(NULL));
	if (now > acct_expiry) {
		DEBUG(1,("authsam_account_ok: Account for user '%s' has expired.\n", name_for_logs));
		DEBUG(3,("authsam_account_ok: Account expired at '%s'.\n", 
			 nt_time_string(mem_ctx, acct_expiry)));
		return NT_STATUS_ACCOUNT_EXPIRED;
	}

	if (!(acct_flags & ACB_PWNOEXP)) {
		/* check for immediate expiry "must change at next logon" */
		if (must_change_time == 0 && last_set_time != 0) {
			DEBUG(1,("sam_account_ok: Account for user '%s' password must change!.\n", 
				 name_for_logs));
			return NT_STATUS_PASSWORD_MUST_CHANGE;
		}

		/* check for expired password */
		if ((must_change_time != 0) && (must_change_time < now)) {
			DEBUG(1,("sam_account_ok: Account for user '%s' password expired!.\n", 
				 name_for_logs));
			DEBUG(1,("sam_account_ok: Password expired at '%s' unix time.\n", 
				 nt_time_string(mem_ctx, must_change_time)));
			return NT_STATUS_PASSWORD_EXPIRED;
		}
	}

	/* Test workstation. Workstation list is comma separated. */
	if (logon_workstation && workstation_list && *workstation_list) {
		BOOL invalid_ws = True;
		int i;
		const char **workstations = str_list_make(mem_ctx, workstation_list, ",");
		
		for (i = 0; workstations && workstations[i]; i++) {
			DEBUG(10,("sam_account_ok: checking for workstation match '%s' and '%s'\n",
				  workstations[i], logon_workstation));

			if (strequal(workstations[i], logon_workstation)) {
				invalid_ws = False;
				break;
			}
		}

		talloc_free(workstations);

		if (invalid_ws) {
			return NT_STATUS_INVALID_WORKSTATION;
		}
	}
	
	if (acct_flags & ACB_DOMTRUST) {
		DEBUG(2,("sam_account_ok: Domain trust account %s denied by server\n", name_for_logs));
		return NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT;
	}
	
	if (!(logon_parameters & MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT)) {
		if (acct_flags & ACB_SVRTRUST) {
			DEBUG(2,("sam_account_ok: Server trust account %s denied by server\n", name_for_logs));
			return NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT;
		}
	}
	if (!(logon_parameters & MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT)) {
		if (acct_flags & ACB_WSTRUST) {
			DEBUG(4,("sam_account_ok: Wksta trust account %s denied by server\n", name_for_logs));
			return NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
		}
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Look for the specified user in the sam, return ldb result structures
****************************************************************************/

static NTSTATUS authsam_search_account(TALLOC_CTX *mem_ctx, struct ldb_context *sam_ctx,
				       const char *account_name,
				       const char *domain_name,
				       struct ldb_message ***ret_msgs,
				       struct ldb_message ***ret_msgs_domain_ref)
{
	struct ldb_message **msgs_tmp;
	struct ldb_message **msgs;
	struct ldb_message **msgs_domain_ref;

	int ret;
	int ret_domain;

	const struct ldb_dn *domain_dn = NULL;

	if (domain_name) {
		char *escaped_domain = ldb_binary_encode_string(mem_ctx, domain_name);
		/* find the domain's DN */
		ret_domain = gendb_search(sam_ctx, mem_ctx, NULL, &msgs_domain_ref, domain_ref_attrs,
					  "(&(&(|(&(dnsRoot=%s)(nETBIOSName=*))(nETBIOSName=%s))(objectclass=crossRef))(ncName=*))", 
					  escaped_domain, escaped_domain);
		if (ret_domain == -1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		if (ret_domain == 0) {
			DEBUG(3,("sam_search_user: Couldn't find domain [%s] in samdb.\n", 
				 domain_name));
			return NT_STATUS_NO_SUCH_USER;
		}

		if (ret_domain > 1) {
			DEBUG(0,("Found %d records matching domain [%s]\n", 
				 ret_domain, domain_name));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		domain_dn = samdb_result_dn(mem_ctx, msgs_domain_ref[0], "nCName", NULL);
	}

	/* pull the user attributes */
	ret = gendb_search(sam_ctx, mem_ctx, domain_dn, &msgs, user_attrs,
			   "(&(sAMAccountName=%s)(objectclass=user))", 
			   ldb_binary_encode_string(mem_ctx, account_name));
	if (ret == -1) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (ret == 0) {
		DEBUG(3,("sam_search_user: Couldn't find user [%s] in samdb.\n", 
			 account_name));
		return NT_STATUS_NO_SUCH_USER;
	}

	if (ret > 1) {
		DEBUG(0,("Found %d records matching user [%s]\n", ret, account_name));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (!domain_name) {
		struct dom_sid *domain_sid;

		domain_sid = samdb_result_sid_prefix(mem_ctx, msgs[0], "objectSid");
		if (!domain_sid) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		/* find the domain's DN */
		ret = gendb_search(sam_ctx, mem_ctx, NULL, &msgs_tmp, NULL,
				   "(&(objectSid=%s)(objectclass=domain))", 
				   ldap_encode_ndr_dom_sid(mem_ctx, domain_sid));
		if (ret == -1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		
		if (ret == 0) {
			DEBUG(3,("check_sam_security: Couldn't find domain_sid [%s] in passdb file.\n",
				 dom_sid_string(mem_ctx, domain_sid)));
			return NT_STATUS_NO_SUCH_USER;
		}
		
		if (ret > 1) {
			DEBUG(0,("Found %d records matching domain_sid [%s]\n", 
				 ret, dom_sid_string(mem_ctx, domain_sid)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		ret_domain = gendb_search(sam_ctx, mem_ctx, NULL, &msgs_domain_ref, domain_ref_attrs,
					  "(nCName=%s)", ldb_dn_linearize(msgs_tmp, msgs_tmp[0]->dn));

		if (ret_domain == -1) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		
		if (ret_domain == 0) {
			DEBUG(3,("check_sam_security: Couldn't find domain [%s] in passdb file.\n",
				 ldb_dn_linearize(msgs_tmp, msgs_tmp[0]->dn)));
			return NT_STATUS_NO_SUCH_USER;
		}
		
		if (ret_domain > 1) {
			DEBUG(0,("Found %d records matching domain [%s]\n", 
				 ret_domain, ldb_dn_linearize(msgs_tmp, msgs_tmp[0]->dn)));
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

	}

	*ret_msgs = msgs;
	*ret_msgs_domain_ref = msgs_domain_ref;
	
	return NT_STATUS_OK;
}

static NTSTATUS authsam_authenticate(struct auth_context *auth_context, 
				     TALLOC_CTX *mem_ctx, struct ldb_context *sam_ctx, 
				     struct ldb_message **msgs,
				     struct ldb_message **msgs_domain_ref,
				     const struct auth_usersupplied_info *user_info, 
				     DATA_BLOB *user_sess_key, DATA_BLOB *lm_sess_key) 
{
	struct samr_Password *lm_pwd, *nt_pwd;
	NTSTATUS nt_status;
	uint16_t acct_flags = samdb_result_acct_flags(msgs[0], "userAccountControl");
	
	/* Quit if the account was locked out. */
	if (acct_flags & ACB_AUTOLOCK) {
		DEBUG(3,("check_sam_security: Account for user %s was locked out.\n", 
			 user_info->mapped.account_name));
		return NT_STATUS_ACCOUNT_LOCKED_OUT;
	}

	/* You can only do an interactive login to normal accounts */
	if (user_info->flags & USER_INFO_INTERACTIVE_LOGON) {
		if (!(acct_flags & ACB_NORMAL)) {
			return NT_STATUS_NO_SUCH_USER;
		}
	}

	nt_status = samdb_result_passwords(mem_ctx, msgs[0], &lm_pwd, &nt_pwd);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	nt_status = authsam_password_ok(auth_context, mem_ctx, 
					acct_flags, lm_pwd, nt_pwd,
					user_info, user_sess_key, lm_sess_key);
	NT_STATUS_NOT_OK_RETURN(nt_status);

	nt_status = authsam_account_ok(mem_ctx, sam_ctx, 
				       user_info->logon_parameters,
				       msgs[0],
				       msgs_domain_ref[0],
				       user_info->workstation_name,
				       user_info->mapped.account_name);

	return nt_status;
}

NTSTATUS authsam_make_server_info(TALLOC_CTX *mem_ctx, struct ldb_context *sam_ctx,
				  struct ldb_message *msg,
				  struct ldb_message *msg_domain_ref,
				  DATA_BLOB user_sess_key, DATA_BLOB lm_sess_key,
				  struct auth_serversupplied_info **_server_info)
{
	struct auth_serversupplied_info *server_info;
	struct ldb_message **group_msgs;
	int group_ret;
	const char *group_attrs[3] = { "sAMAccountType", "objectSid", NULL }; 
	/* find list of sids */
	struct dom_sid **groupSIDs = NULL;
	struct dom_sid *account_sid;
	struct dom_sid *primary_group_sid;
	const char *str;
	struct ldb_dn *ncname;
	int i;
	uint_t rid;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);

	group_ret = gendb_search(sam_ctx,
				 tmp_ctx, NULL, &group_msgs, group_attrs,
				 "(&(member=%s)(sAMAccountType=*))", 
				 ldb_dn_linearize(tmp_ctx, msg->dn));
	if (group_ret == -1) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	server_info = talloc(mem_ctx, struct auth_serversupplied_info);
	NT_STATUS_HAVE_NO_MEMORY(server_info);
	
	if (group_ret > 0) {
		groupSIDs = talloc_array(server_info, struct dom_sid *, group_ret);
		NT_STATUS_HAVE_NO_MEMORY(groupSIDs);
	}

	/* Need to unroll some nested groups, but not aliases */
	for (i = 0; i < group_ret; i++) {
		groupSIDs[i] = samdb_result_dom_sid(groupSIDs, 
						    group_msgs[i], "objectSid");
		NT_STATUS_HAVE_NO_MEMORY(groupSIDs[i]);
	}

	talloc_free(tmp_ctx);

	account_sid = samdb_result_dom_sid(server_info, msg, "objectSid");
	NT_STATUS_HAVE_NO_MEMORY(account_sid);

	primary_group_sid = dom_sid_dup(server_info, account_sid);
	NT_STATUS_HAVE_NO_MEMORY(primary_group_sid);

	rid = samdb_result_uint(msg, "primaryGroupID", ~0);
	if (rid == ~0) {
		if (group_ret > 0) {
			primary_group_sid = groupSIDs[0];
		} else {
			primary_group_sid = NULL;
		}
	} else {
		primary_group_sid->sub_auths[primary_group_sid->num_auths-1] = rid;
	}

	server_info->account_sid = account_sid;
	server_info->primary_group_sid = primary_group_sid;
	
	server_info->n_domain_groups = group_ret;
	server_info->domain_groups = groupSIDs;

	server_info->account_name = talloc_steal(server_info, samdb_result_string(msg, "sAMAccountName", NULL));

	server_info->domain_name = talloc_steal(server_info, samdb_result_string(msg_domain_ref, "nETBIOSName", NULL));

	str = samdb_result_string(msg, "displayName", "");
	server_info->full_name = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->full_name);

	str = samdb_result_string(msg, "scriptPath", "");
	server_info->logon_script = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->logon_script);

	str = samdb_result_string(msg, "profilePath", "");
	server_info->profile_path = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->profile_path);

	str = samdb_result_string(msg, "homeDirectory", "");
	server_info->home_directory = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_directory);

	str = samdb_result_string(msg, "homeDrive", "");
	server_info->home_drive = talloc_strdup(server_info, str);
	NT_STATUS_HAVE_NO_MEMORY(server_info->home_drive);

	server_info->logon_server = talloc_strdup(server_info, lp_netbios_name());
	NT_STATUS_HAVE_NO_MEMORY(server_info->logon_server);

	server_info->last_logon = samdb_result_nttime(msg, "lastLogon", 0);
	server_info->last_logoff = samdb_result_nttime(msg, "lastLogoff", 0);
	server_info->acct_expiry = samdb_result_nttime(msg, "accountExpires", 0);
	server_info->last_password_change = samdb_result_nttime(msg, "pwdLastSet", 0);

	ncname = samdb_result_dn(mem_ctx, msg_domain_ref, "nCName", NULL);
	if (!ncname) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	server_info->allow_password_change
		= samdb_result_allow_password_change(sam_ctx, mem_ctx, 
						     ncname, msg, "pwdLastSet");
	server_info->force_password_change
		= samdb_result_force_password_change(sam_ctx, mem_ctx, 
						     ncname, msg);
	
	server_info->logon_count = samdb_result_uint(msg, "logonCount", 0);
	server_info->bad_password_count = samdb_result_uint(msg, "badPwdCount", 0);

	server_info->acct_flags = samdb_result_acct_flags(msg, "userAccountControl");

	server_info->user_session_key = user_sess_key;
	server_info->lm_session_key = lm_sess_key;

	server_info->authenticated = True;

	*_server_info = server_info;

	return NT_STATUS_OK;
}

NTSTATUS sam_get_results_principal(struct ldb_context *sam_ctx,
				   TALLOC_CTX *mem_ctx, const char *principal,
				   struct ldb_message ***msgs,
				   struct ldb_message ***msgs_domain_ref)
{			   
	struct ldb_dn *user_dn, *domain_dn;
	NTSTATUS nt_status;
	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	int ret;

	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	nt_status = crack_user_principal_name(sam_ctx, tmp_ctx, principal, &user_dn, &domain_dn);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}
	
	/* grab domain info from the reference */
	ret = gendb_search(sam_ctx, tmp_ctx, NULL, msgs_domain_ref, domain_ref_attrs,
			   "(ncName=%s)", ldb_dn_linearize(tmp_ctx, domain_dn));

	if (ret != 1) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	
	/* pull the user attributes */
	ret = gendb_search_dn(sam_ctx, tmp_ctx, 
			      user_dn, msgs, user_attrs);
	if (ret != 1) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	talloc_steal(mem_ctx, *msgs);
	talloc_steal(mem_ctx, *msgs_domain_ref);
	talloc_free(tmp_ctx);
	
	return NT_STATUS_OK;
}
				   
/* Used in the gensec_gssapi and gensec_krb5 server-side code, where the PAC isn't available */
NTSTATUS sam_get_server_info_principal(TALLOC_CTX *mem_ctx, const char *principal,
				       struct auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status;
	DATA_BLOB user_sess_key = data_blob(NULL, 0);
	DATA_BLOB lm_sess_key = data_blob(NULL, 0);

	struct ldb_message **msgs;
	struct ldb_message **msgs_domain_ref;
	struct ldb_context *sam_ctx;

	TALLOC_CTX *tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	sam_ctx = samdb_connect(tmp_ctx, system_session(tmp_ctx));
	if (sam_ctx == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	nt_status = sam_get_results_principal(sam_ctx, tmp_ctx, principal, 
					      &msgs, &msgs_domain_ref);
	if (!NT_STATUS_IS_OK(nt_status)) {
		return nt_status;
	}

	nt_status = authsam_make_server_info(tmp_ctx, sam_ctx, msgs[0], msgs_domain_ref[0],
					     user_sess_key, lm_sess_key,
					     server_info);
	if (NT_STATUS_IS_OK(nt_status)) {
		talloc_steal(mem_ctx, *server_info);
	}
	talloc_free(tmp_ctx);
	return nt_status;
}

static NTSTATUS authsam_check_password_internals(struct auth_method_context *ctx,
						 TALLOC_CTX *mem_ctx,
						 const char *domain,
						 const struct auth_usersupplied_info *user_info, 
						 struct auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status;
	const char *account_name = user_info->mapped.account_name;
	struct ldb_message **msgs;
	struct ldb_message **domain_ref_msgs;
	struct ldb_context *sam_ctx;
	DATA_BLOB user_sess_key, lm_sess_key;
	TALLOC_CTX *tmp_ctx;

	if (!account_name || !*account_name) {
		/* 'not for me' */
		return NT_STATUS_NOT_IMPLEMENTED;
	}

	tmp_ctx = talloc_new(mem_ctx);
	if (!tmp_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	sam_ctx = samdb_connect(tmp_ctx, system_session(mem_ctx));
	if (sam_ctx == NULL) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}

	nt_status = authsam_search_account(tmp_ctx, sam_ctx, account_name, domain, &msgs, &domain_ref_msgs);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	nt_status = authsam_authenticate(ctx->auth_ctx, tmp_ctx, sam_ctx, msgs, domain_ref_msgs, user_info,
					 &user_sess_key, &lm_sess_key);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	nt_status = authsam_make_server_info(tmp_ctx, sam_ctx, msgs[0], domain_ref_msgs[0],
					     user_sess_key, lm_sess_key,
					     server_info);
	if (!NT_STATUS_IS_OK(nt_status)) {
		talloc_free(tmp_ctx);
		return nt_status;
	}

	talloc_steal(mem_ctx, *server_info);
	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

static NTSTATUS authsam_ignoredomain_check_password(struct auth_method_context *ctx,
						    TALLOC_CTX *mem_ctx,
						    const struct auth_usersupplied_info *user_info, 
						    struct auth_serversupplied_info **server_info)
{
	return authsam_check_password_internals(ctx, mem_ctx, NULL, user_info, server_info);
}

/****************************************************************************
Check SAM security (above) but with a few extra checks.
****************************************************************************/
static NTSTATUS authsam_check_password(struct auth_method_context *ctx,
				       TALLOC_CTX *mem_ctx,
				       const struct auth_usersupplied_info *user_info, 
				       struct auth_serversupplied_info **server_info)
{
	const char *domain;
	BOOL is_local_name, is_my_domain;

	is_local_name = is_myname(user_info->mapped.domain_name);
	is_my_domain  = strequal(user_info->mapped.domain_name, lp_workgroup());

	/* check whether or not we service this domain/workgroup name */
	switch (lp_server_role()) {
		case ROLE_STANDALONE:
			domain = lp_netbios_name();
			break;
		case ROLE_DOMAIN_MEMBER:
			if (!is_local_name) {
				DEBUG(6,("authsam_check_password: %s is not one of my local names (%s)\n",
					user_info->mapped.domain_name, (lp_server_role() == ROLE_DOMAIN_MEMBER 
					? "ROLE_DOMAIN_MEMBER" : "ROLE_STANDALONE") ));
				return NT_STATUS_NOT_IMPLEMENTED;
			}
			domain = lp_netbios_name();
			break;
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
			if (!is_local_name && !is_my_domain) {
				DEBUG(6,("authsam_check_password: %s is not one of my local names or domain name (DC)\n",
					user_info->mapped.domain_name));
				return NT_STATUS_NOT_IMPLEMENTED;
			}
			domain = lp_workgroup();
			break;
		default:
			DEBUG(6,("authsam_check_password: lp_server_role() has an undefined value\n"));
			return NT_STATUS_NOT_IMPLEMENTED;
	}

	return authsam_check_password_internals(ctx, mem_ctx, domain, user_info, server_info);
}

static const struct auth_operations sam_ignoredomain_ops = {
	.name		= "sam_ignoredomain",
	.get_challenge	= auth_get_challenge_not_implemented,
	.check_password	= authsam_ignoredomain_check_password
};

static const struct auth_operations sam_ops = {
	.name		= "sam",
	.get_challenge	= auth_get_challenge_not_implemented,
	.check_password	= authsam_check_password
};

NTSTATUS auth_sam_init(void)
{
	NTSTATUS ret;

	ret = auth_register(&sam_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'sam' auth backend!\n"));
		return ret;
	}

	ret = auth_register(&sam_ignoredomain_ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register 'sam_ignoredomain' auth backend!\n"));
		return ret;
	}

	return ret;
}
