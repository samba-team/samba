/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2001-2004
   Copyright (C) Gerald Carter                             2003
   
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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_AUTH

/****************************************************************************
 Do a specific test for an smb password being correct, given a smb_password and
 the lanman and NT responses.
****************************************************************************/

static NTSTATUS sam_password_ok(const struct auth_context *auth_context,
				TALLOC_CTX *mem_ctx,
				const char *username,
				uint16_t acct_flags,
				const struct samr_Password *lm_pwd, 
				const struct samr_Password *nt_pwd,
				const struct auth_usersupplied_info *user_info, 
				DATA_BLOB *user_sess_key, 
				DATA_BLOB *lm_sess_key)
{
	if (acct_flags & ACB_PWNOTREQ) {
		if (lp_null_passwords()) {
			DEBUG(3,("Account for user '%s' has no password and null passwords are allowed.\n", 
				 username));
			return NT_STATUS_OK;
		} else {
			DEBUG(3,("Account for user '%s' has no password and null passwords are NOT allowed.\n", 
				 username));
			return NT_STATUS_LOGON_FAILURE;
		}		
	}

	return ntlm_password_check(mem_ctx, &auth_context->challenge, 
				   &user_info->lm_resp, &user_info->nt_resp, 
				   &user_info->lm_interactive_password, 
				   &user_info->nt_interactive_password,
				   username, 
				   user_info->smb_name.str, 
				   user_info->client_domain.str, 
				   lm_pwd->hash, nt_pwd->hash, user_sess_key, lm_sess_key);
}


/****************************************************************************
 Do a specific test for a SAM_ACCOUNT being vaild for this connection 
 (ie not disabled, expired and the like).
****************************************************************************/

static NTSTATUS sam_account_ok(TALLOC_CTX *mem_ctx,
			       const char *username,
			       uint16_t acct_flags,
			       NTTIME *acct_expiry,
			       NTTIME *must_change_time,
			       NTTIME *last_set_time,
			       const char *workstation_list,
			       const struct auth_usersupplied_info *user_info)
{
	DEBUG(4,("sam_account_ok: Checking SMB password for user %s\n", username));

	/* Quit if the account was disabled. */
	if (acct_flags & ACB_DISABLED) {
		DEBUG(1,("sam_account_ok: Account for user '%s' was disabled.\n", username));
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	/* Quit if the account was locked out. */
	if (acct_flags & ACB_AUTOLOCK) {
		DEBUG(1,("sam_account_ok: Account for user %s was locked out.\n", username));
		return NT_STATUS_ACCOUNT_LOCKED_OUT;
	}

	/* Test account expire time */
	if ((*acct_expiry) != -1 && time(NULL) > nt_time_to_unix(*acct_expiry)) {
		DEBUG(1,("sam_account_ok: Account for user '%s' has expired.\n", username));
		DEBUG(3,("sam_account_ok: Account expired at '%s'.\n", 
			 nt_time_string(mem_ctx, *acct_expiry)));
		return NT_STATUS_ACCOUNT_EXPIRED;
	}

	if (!(acct_flags & ACB_PWNOEXP)) {

		/* check for immediate expiry "must change at next logon" */
		if (*must_change_time == 0 && *last_set_time != 0) {
			DEBUG(1,("sam_account_ok: Account for user '%s' password must change!.\n", 
				 username));
			return NT_STATUS_PASSWORD_MUST_CHANGE;
		}

		/* check for expired password */
		if ((*must_change_time) != 0 && nt_time_to_unix(*must_change_time) < time(NULL)) {
			DEBUG(1,("sam_account_ok: Account for user '%s' password expired!.\n", 
				 username));
			DEBUG(1,("sam_account_ok: Password expired at '%s' unix time.\n", 
				 nt_time_string(mem_ctx, *must_change_time)));
			return NT_STATUS_PASSWORD_EXPIRED;
		}
	}

	/* Test workstation. Workstation list is comma separated. */

	if (workstation_list && *workstation_list) {
		BOOL invalid_ws = True;
		const char *s = workstation_list;
			
		fstring tok;
			
		while (next_token(&s, tok, ",", sizeof(tok))) {
			DEBUG(10,("sam_account_ok: checking for workstation match %s and %s (len=%d)\n",
				  tok, user_info->wksta_name.str, user_info->wksta_name.len));
			
			if(strequal(tok, user_info->wksta_name.str)) {
				invalid_ws = False;
				break;
			}
		}
		
		if (invalid_ws) 
			return NT_STATUS_INVALID_WORKSTATION;
	}

	if (acct_flags & ACB_DOMTRUST) {
		DEBUG(2,("sam_account_ok: Domain trust account %s denied by server\n", username));
		return NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT;
	}
	
	if (acct_flags & ACB_SVRTRUST) {
		DEBUG(2,("sam_account_ok: Server trust account %s denied by server\n", username));
		return NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT;
	}
	
	if (acct_flags & ACB_WSTRUST) {
		DEBUG(4,("sam_account_ok: Wksta trust account %s denied by server\n", username));
		return NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
	}
	
	return NT_STATUS_OK;
}

/****************************************************************************
check if a username/password is OK assuming the password is a 24 byte
SMB hash supplied in the user_info structure
return an NT_STATUS constant.
****************************************************************************/

static NTSTATUS check_sam_security(const struct auth_context *auth_context,
				   void *my_private_data, 
				   TALLOC_CTX *mem_ctx,
				   const struct auth_usersupplied_info *user_info, 
				   struct auth_serversupplied_info **server_info)
{
	struct ldb_message **msgs;
	struct ldb_message **msgs_domain;
	void *sam_ctx;
	char *username = user_info->internal_username.str;
	uint16_t acct_flags;
	const char *workstation_list;
	NTTIME acct_expiry;
	NTTIME must_change_time;
	NTTIME last_set_time;

	uint_t ret;
	uint_t ret_domain;

	const char *domain_dn;
	const char *domain_sid;

	NTSTATUS nt_status;
	DATA_BLOB user_sess_key = data_blob(NULL, 0);
	DATA_BLOB lm_sess_key = data_blob(NULL, 0);
	struct samr_Password *lm_pwd, *nt_pwd;

	const char *attrs[] = {"unicodePwd", "lmPwdHash", "ntPwdHash", 
			       "userAccountControl",
			       "pwdLastSet",
			       "accountExpires",
			       "objectSid",
			       "userWorkstations",
			       
			       /* required for server_info, not access control: */
			       "sAMAccountName",
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
			       NULL,
	};

	const char *domain_attrs[] =  {"name"};

	if (!user_info || !auth_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	sam_ctx = samdb_connect();
	if (sam_ctx == NULL) {
		return NT_STATUS_INVALID_SYSTEM_SERVICE;
	}
	/* pull the user attributes */
	ret = samdb_search(sam_ctx, mem_ctx, NULL, &msgs, attrs,
			   "(&(sAMAccountName=%s)(objectclass=user))", 
			   username);

	if (ret == 0) {
		DEBUG(3,("check_sam_security: Couldn't find user [%s] in passdb file.\n", 
			 username));
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	if (ret > 1) {
		DEBUG(1,("Found %d records matching user [%s]\n", ret, username));
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}
	
	domain_sid = samdb_result_sid_prefix(mem_ctx, msgs[0], "objectSid");
	if (!domain_sid) {
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* find the domain's DN */
	ret_domain = samdb_search(sam_ctx, mem_ctx, NULL, &msgs_domain, domain_attrs,
			   "(&(objectSid=%s)(objectclass=domain))", 
			   domain_sid);

	if (ret_domain == 0) {
		DEBUG(3,("check_sam_security: Couldn't find domain [%s] in passdb file.\n", 
			 domain_sid));
		samdb_close(sam_ctx);
		return NT_STATUS_NO_SUCH_USER;
	}

	if (ret_domain > 1) {
		DEBUG(1,("Found %d records matching domain [%s]\n", 
			 ret_domain, domain_sid));
		samdb_close(sam_ctx);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	domain_dn = msgs_domain[0]->dn;
	
	acct_flags = samdb_result_acct_flags(msgs[0], "sAMAcctFlags");
	
	/* Quit if the account was locked out. */
	if (acct_flags & ACB_AUTOLOCK) {
		DEBUG(3,("check_sam_security: Account for user %s was locked out.\n", 
			 username));
		samdb_close(sam_ctx);
		return NT_STATUS_ACCOUNT_LOCKED_OUT;
	}

	if (!NT_STATUS_IS_OK(nt_status = samdb_result_passwords(mem_ctx, msgs[0], 
								&lm_pwd, &nt_pwd))) {
		return nt_status;
	}

	nt_status = sam_password_ok(auth_context, mem_ctx, 
				    username, acct_flags, 
				    lm_pwd, nt_pwd,
				    user_info, &user_sess_key, &lm_sess_key);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		samdb_close(sam_ctx);
		return nt_status;
	}

	acct_expiry = samdb_result_nttime(msgs[0], "accountExpires", 0);
	must_change_time = samdb_result_force_password_change(sam_ctx, mem_ctx, 
							      domain_dn, msgs[0], 
							      "pwdLastSet");
	last_set_time = samdb_result_nttime(msgs[0], "pwdLastSet", 0);

	workstation_list = samdb_result_string(msgs[0], "userWorkstations", NULL);

	nt_status = sam_account_ok(mem_ctx, username, acct_flags, 
				   &acct_expiry, 
				   &must_change_time, 
				   &last_set_time, 
				   workstation_list,
				   user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		samdb_close(sam_ctx);
		return nt_status;
	}

	if (!NT_STATUS_IS_OK(nt_status = make_server_info(server_info, username))) {		
		DEBUG(0,("check_sam_security: make_server_info_sam() failed with '%s'\n", nt_errstr(nt_status)));
		samdb_close(sam_ctx);
		return nt_status;
	}

	{
		struct ldb_message **group_msgs;
		char *dn = msgs[0]->dn;
		int group_ret;
		const char *group_attrs[3] = { "sAMAccountType", "objectSid", NULL }; 
		/* find list of sids */
		struct dom_sid **groupSIDs = NULL;
		struct dom_sid *user_sid;
		struct dom_sid *primary_group_sid;
		const char *sidstr;
		int i;

		group_ret = samdb_search(sam_ctx,
					 mem_ctx, NULL, &group_msgs, group_attrs,
					 "(&(member=%s)(sAMAccountType=*))", 
					 dn);
		
		if (group_ret > 0 && 
		    !(groupSIDs = talloc_realloc_p((*server_info)->mem_ctx, groupSIDs, 
						   struct dom_sid *, group_ret))) {
			talloc_destroy((*server_info)->mem_ctx);
			samdb_close(sam_ctx);
			return NT_STATUS_NO_MEMORY;
		}

		/* Need to unroll some nested groups, but not aliases */
		for (i = 0; i < group_ret; i++) {
			sidstr = ldb_msg_find_string(group_msgs[i], "objectSid", NULL);
			groupSIDs[i] = dom_sid_parse_talloc((*server_info)->mem_ctx, sidstr);
		}
		
		sidstr = ldb_msg_find_string(msgs[0], "objectSid", NULL);
		user_sid = dom_sid_parse_talloc((*server_info)->mem_ctx, sidstr);
		primary_group_sid = dom_sid_parse_talloc((*server_info)->mem_ctx, sidstr);
		primary_group_sid->sub_auths[primary_group_sid->num_auths-1] 
			= samdb_result_uint(msgs[0], "primaryGroupID", 0);

		(*server_info)->user_sid = user_sid;
		(*server_info)->primary_group_sid = primary_group_sid;
		
		(*server_info)->n_domain_groups = group_ret;
		(*server_info)->domain_groups = groupSIDs;
	}

	(*server_info)->account_name 
		= talloc_strdup((*server_info)->mem_ctx, 
				samdb_result_string(msgs[0], "sAMAccountName", ""));

	(*server_info)->domain
		= talloc_strdup((*server_info)->mem_ctx, 
				samdb_result_string(msgs_domain[0], "name", ""));

	(*server_info)->full_name 
		= talloc_strdup((*server_info)->mem_ctx, 
				samdb_result_string(msgs[0], "displayName", ""));

	(*server_info)->logon_script 
		= talloc_strdup((*server_info)->mem_ctx, 
				samdb_result_string(msgs[0], "scriptPath", ""));
	(*server_info)->profile_path 
		= talloc_strdup((*server_info)->mem_ctx, 
				samdb_result_string(msgs[0], "profilePath", ""));
	(*server_info)->home_directory 
		= talloc_strdup((*server_info)->mem_ctx, 
				samdb_result_string(msgs[0], "homeDirectory", ""));

	(*server_info)->home_drive 
		= talloc_strdup((*server_info)->mem_ctx, 
				samdb_result_string(msgs[0], "homeDrive", ""));

	(*server_info)->last_logon = samdb_result_nttime(msgs[0], "lastLogon", 0);
	(*server_info)->last_logoff = samdb_result_nttime(msgs[0], "lastLogoff", 0);
	(*server_info)->acct_expiry = samdb_result_nttime(msgs[0], "accountExpires", 0);
	(*server_info)->last_password_change = samdb_result_nttime(msgs[0], "pwdLastSet", 0);
	(*server_info)->allow_password_change
		= samdb_result_allow_password_change(sam_ctx, mem_ctx, 
						     domain_dn, msgs[0], "pwdLastSet");
	(*server_info)->force_password_change
		= samdb_result_force_password_change(sam_ctx, mem_ctx, 
						     domain_dn, msgs[0], "pwdLastSet");

	(*server_info)->logon_count = samdb_result_uint(msgs[0], "logonCount", 0);
	(*server_info)->bad_password_count = samdb_result_uint(msgs[0], "badPwdCount", 0);

	(*server_info)->acct_flags = samdb_result_acct_flags(msgs[0], "userAccountControl");

	(*server_info)->guest = False;

	(*server_info)->user_session_key = user_sess_key;
	(*server_info)->lm_session_key = lm_sess_key;

	if (!(*server_info)->account_name 
	    || !(*server_info)->full_name 
	    || !(*server_info)->logon_script
	    || !(*server_info)->profile_path
	    || !(*server_info)->home_directory
	    || !(*server_info)->home_drive) {
		talloc_destroy((*server_info)->mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	samdb_close(sam_ctx);

	return nt_status;
}

/* module initialisation */
static NTSTATUS auth_init_sam_ignoredomain(struct auth_context *auth_context, 
					   const char *param, 
					   struct auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_context, auth_method)) {
		return NT_STATUS_NO_MEMORY;
	}

	(*auth_method)->auth = check_sam_security;	
	(*auth_method)->name = "sam_ignoredomain";
	return NT_STATUS_OK;
}


/****************************************************************************
Check SAM security (above) but with a few extra checks.
****************************************************************************/

static NTSTATUS check_samstrict_security(const struct auth_context *auth_context,
					 void *my_private_data, 
					 TALLOC_CTX *mem_ctx,
					 const struct auth_usersupplied_info *user_info, 
					 struct auth_serversupplied_info **server_info)
{

	if (!user_info || !auth_context) {
		return NT_STATUS_LOGON_FAILURE;
	}

	/* If we are a domain member, we must not 
	   attempt to check the password locally,
	   unless it is one of our aliases. */
	
	if (!is_myname(user_info->domain.str)) {
		DEBUG(7,("The requested user domain is not the local server name. [%s]\\[%s]\n",
			user_info->domain.str,user_info->internal_username.str));
		return NT_STATUS_NO_SUCH_USER;
	}
	
	return check_sam_security(auth_context, my_private_data, mem_ctx, user_info, server_info);
}

/* module initialisation */
static NTSTATUS auth_init_sam(struct auth_context *auth_context, 
			      const char *param, 
			      struct auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_context, auth_method)) {
		return NT_STATUS_NO_MEMORY;
	}

	(*auth_method)->auth = check_samstrict_security;
	(*auth_method)->name = "sam";
	return NT_STATUS_OK;
}

NTSTATUS auth_sam_init(void)
{
	NTSTATUS ret;
	struct auth_operations ops;

	ops.name = "sam";
	ops.init = auth_init_sam;
	ret = register_backend("auth", &ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' auth backend!\n",
			ops.name));
		return ret;
	}

	ops.name = "sam_ignoredomain";
	ops.init = auth_init_sam_ignoredomain;
	ret = register_backend("auth", &ops);
	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register '%s' auth backend!\n",
			ops.name));
		return ret;
	}

	return ret;
}
