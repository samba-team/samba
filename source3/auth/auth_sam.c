/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Andrew Bartlett              2001
   
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

/****************************************************************************
core of smb password checking routine.
****************************************************************************/
static BOOL smb_pwd_check_ntlmv1(DATA_BLOB nt_response,
				 const uchar *part_passwd,
				 DATA_BLOB sec_blob,
				 uint8 user_sess_key[16])
{
	/* Finish the encryption of part_passwd. */
	uchar p24[24];
	
	if (part_passwd == NULL) {
		DEBUG(10,("No password set - DISALLOWING access\n"));
		/* No password set - always false ! */
		return False;
	}
	
	if (sec_blob.length != 8) {
		DEBUG(0, ("smb_pwd_check_ntlmv1: incorrect challenge size (%d)\n", sec_blob.length));
		return False;
	}
	
	if (nt_response.length != 24) {
		DEBUG(0, ("smb_pwd_check_ntlmv1: incorrect password length (%d)\n", nt_response.length));
		return False;
	}

	SMBOWFencrypt(part_passwd, sec_blob.data, p24);
	if (user_sess_key != NULL)
	{
		SMBsesskeygen_ntv1(part_passwd, NULL, user_sess_key);
	}
	
	
	
#if DEBUG_PASSWORD
	DEBUG(100,("Part password (P16) was |"));
	dump_data(100, part_passwd, 16);
	DEBUG(100,("Password from client was |"));
	dump_data(100, nt_response.data, nt_response.length);
	DEBUG(100,("Given challenge was |"));
	dump_data(100, sec_blob.data, sec_blob.length);
	DEBUG(100,("Value from encryption was |"));
	dump_data(100, p24, 24);
#endif
  return (memcmp(p24, nt_response.data, 24) == 0);
}

/****************************************************************************
core of smb password checking routine.
****************************************************************************/
static BOOL smb_pwd_check_ntlmv2(const DATA_BLOB ntv2_response,
				 const uchar *part_passwd,
				 const DATA_BLOB sec_blob,
				 const char *user, const char *domain,
				 uint8 user_sess_key[16])
{
	/* Finish the encryption of part_passwd. */
	uchar kr[16];
	uchar value_from_encryption[16];
	uchar client_response[16];
	DATA_BLOB client_key_data;

	if (part_passwd == NULL)
	{
		DEBUG(10,("No password set - DISALLOWING access\n"));
		/* No password set - always False */
		return False;
	}

	if (ntv2_response.length < 16) {
		/* We MUST have more than 16 bytes, or the stuff below will go
		   crazy... */
		DEBUG(0, ("smb_pwd_check_ntlmv2: incorrect password length (%d)\n", 
			  ntv2_response.length));
		return False;
	}

	client_key_data = data_blob(ntv2_response.data+16, ntv2_response.length-16);
	memcpy(client_response, ntv2_response.data, sizeof(client_response));

	ntv2_owf_gen(part_passwd, user, domain, kr);
	SMBOWFencrypt_ntv2(kr, sec_blob, client_key_data, (char *)value_from_encryption);
	if (user_sess_key != NULL)
	{
		SMBsesskeygen_ntv2(kr, value_from_encryption, user_sess_key);
	}

#if DEBUG_PASSWORD
	DEBUG(100,("Part password (P16) was |"));
	dump_data(100, part_passwd, 16);
	DEBUG(100,("Password from client was |"));
	dump_data(100, ntv2_response.data, ntv2_response.length);
	DEBUG(100,("Variable data from client was |"));
	dump_data(100, client_key_data.data, client_key_data.length);
	DEBUG(100,("Given challenge was |"));
	dump_data(100, sec_blob.data, sec_blob.length);
	DEBUG(100,("Value from encryption was |"));
	dump_data(100, value_from_encryption, 16);
#endif
	data_blob_clear_free(&client_key_data);
	return (memcmp(value_from_encryption, client_response, 16) == 0);
}


/****************************************************************************
 Do a specific test for an smb password being correct, given a smb_password and
 the lanman and NT responses.
****************************************************************************/
static NTSTATUS sam_password_ok(const struct auth_context *auth_context,
				TALLOC_CTX *mem_ctx,
				SAM_ACCOUNT *sampass, 
				const auth_usersupplied_info *user_info, 
				uint8 user_sess_key[16])
{
	uint16 acct_ctrl;
	const uint8 *nt_pw, *lm_pw;
	uint32 auth_flags;

	acct_ctrl = pdb_get_acct_ctrl(sampass);
	if (acct_ctrl & ACB_PWNOTREQ) 
	{
		if (lp_null_passwords()) 
		{
			DEBUG(3,("Account for user '%s' has no password and null passwords are allowed.\n", pdb_get_username(sampass)));
			return(NT_STATUS_OK);
		} 
		else 
		{
			DEBUG(3,("Account for user '%s' has no password and null passwords are NOT allowed.\n", pdb_get_username(sampass)));
			return(NT_STATUS_LOGON_FAILURE);
		}		
	}

	nt_pw = pdb_get_nt_passwd(sampass);
	lm_pw = pdb_get_lanman_passwd(sampass);
	
	auth_flags = user_info->auth_flags;

	if (nt_pw == NULL) {
		DEBUG(3,("sam_password_ok: NO NT password stored for user %s.\n", 
			 pdb_get_username(sampass)));
		/* No return, we want to check the LM hash below in this case */
		auth_flags &= (~(AUTH_FLAG_NTLMv2_RESP |  AUTH_FLAG_NTLM_RESP));
	}
	
	if (auth_flags & AUTH_FLAG_NTLMv2_RESP) {
		/* We have the NT MD4 hash challenge available - see if we can
		   use it (ie. does it exist in the smbpasswd file).
		*/
		DEBUG(4,("sam_password_ok: Checking NTLMv2 password\n"));
		if (smb_pwd_check_ntlmv2( user_info->nt_resp, 
					  nt_pw, auth_context->challenge, 
					  user_info->smb_name.str, 
					  user_info->client_domain.str,
					  user_sess_key))
		{
			return NT_STATUS_OK;
		} else {
			DEBUG(3,("sam_password_ok: NTLMv2 password check failed\n"));
			return NT_STATUS_WRONG_PASSWORD;
		}
	} else if (auth_flags & AUTH_FLAG_NTLM_RESP) {
		if (lp_ntlm_auth()) {				
			/* We have the NT MD4 hash challenge available - see if we can
			   use it (ie. does it exist in the smbpasswd file).
			*/
			DEBUG(4,("sam_password_ok: Checking NT MD4 password\n"));
			if (smb_pwd_check_ntlmv1(user_info->nt_resp, 
						 nt_pw, auth_context->challenge,
						 user_sess_key)) 
			{
				return NT_STATUS_OK;
			} else {
				DEBUG(3,("sam_password_ok: NT MD4 password check failed for user %s\n",pdb_get_username(sampass)));
				return NT_STATUS_WRONG_PASSWORD;
			}
		} else {
			DEBUG(2,("sam_password_ok: NTLMv1 passwords NOT PERMITTED for user %s\n",pdb_get_username(sampass)));			
				/* No return, we want to check the LM hash below in this case */
		}
	}
	
	if (lm_pw == NULL) {
		DEBUG(3,("sam_password_ok: NO LanMan password set for user %s (and no NT password supplied)\n",pdb_get_username(sampass)));
		auth_flags &= (~AUTH_FLAG_LM_RESP);		
	}
	
	if (auth_flags & AUTH_FLAG_LM_RESP) {
		
		if (user_info->lm_resp.length != 24) {
			DEBUG(2,("sam_password_ok: invalid LanMan password length (%d) for user %s\n", 
				 user_info->nt_resp.length, pdb_get_username(sampass)));		
		}
		
		if (!lp_lanman_auth()) {
			DEBUG(3,("sam_password_ok: Lanman passwords NOT PERMITTED for user %s\n",pdb_get_username(sampass)));			
			return NT_STATUS_LOGON_FAILURE;
		}
		
		DEBUG(4,("sam_password_ok: Checking LM password\n"));
		if (smb_pwd_check_ntlmv1(user_info->lm_resp, 
					 lm_pw, auth_context->challenge,
					 user_sess_key)) 
		{
			return NT_STATUS_OK;
		} else {
			DEBUG(4,("sam_password_ok: LM password check failed for user %s\n",pdb_get_username(sampass)));
			return NT_STATUS_WRONG_PASSWORD;
		} 
	}

	/* Should not be reached, but if they send nothing... */
	DEBUG(3,("sam_password_ok: NEITHER LanMan nor NT password supplied for user %s\n",pdb_get_username(sampass)));
	return NT_STATUS_WRONG_PASSWORD;
}

/****************************************************************************
 Do a specific test for a SAM_ACCOUNT being vaild for this connection 
 (ie not disabled, expired and the like).
****************************************************************************/
static NTSTATUS sam_account_ok(TALLOC_CTX *mem_ctx,
			       SAM_ACCOUNT *sampass, 
			       const auth_usersupplied_info *user_info)
{
	uint16	acct_ctrl = pdb_get_acct_ctrl(sampass);
	char *workstation_list;
	time_t kickoff_time;
	
	DEBUG(4,("sam_account_ok: Checking SMB password for user %s\n",pdb_get_username(sampass)));

	/* Quit if the account was disabled. */
	if (acct_ctrl & ACB_DISABLED) {
		DEBUG(1,("Account for user '%s' was disabled.\n", pdb_get_username(sampass)));
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	/* Test account expire time */
	
	kickoff_time = pdb_get_kickoff_time(sampass);
	if (kickoff_time != 0 && time(NULL) > kickoff_time) {
		DEBUG(1,("Account for user '%s' has expried.\n", pdb_get_username(sampass)));
		DEBUG(3,("Account expired at '%ld' unix time.\n", (long)kickoff_time));
		return NT_STATUS_ACCOUNT_EXPIRED;
	}

	if (!(pdb_get_acct_ctrl(sampass) & ACB_PWNOEXP)) {
		time_t must_change_time = pdb_get_pass_must_change_time(sampass);
		time_t last_set_time = pdb_get_pass_last_set_time(sampass);

		/* check for immediate expiry "must change at next logon" */
		if (must_change_time == 0 && last_set_time != 0) {
			DEBUG(1,("Account for user '%s' password must change!.\n", pdb_get_username(sampass)));
			return NT_STATUS_PASSWORD_MUST_CHANGE;
		}

		/* check for expired password */
		if (must_change_time < time(NULL) && must_change_time != 0) {
			DEBUG(1,("Account for user '%s' password expired!.\n", pdb_get_username(sampass)));
			DEBUG(1,("Password expired at '%s' (%ld) unix time.\n", http_timestring(must_change_time), (long)must_change_time));
			return NT_STATUS_PASSWORD_EXPIRED;
		}
	}

	/* Test workstation. Workstation list is comma separated. */

	workstation_list = talloc_strdup(mem_ctx, pdb_get_workstations(sampass));

	if (!workstation_list) return NT_STATUS_NO_MEMORY;

	if (*workstation_list) {
		BOOL invalid_ws = True;
		char *s = workstation_list;
			
		fstring tok;
			
		while (next_token(&s, tok, ",", sizeof(tok))) {
			DEBUG(10,("checking for workstation match %s and %s (len=%d)\n",
				  tok, user_info->wksta_name.str, user_info->wksta_name.len));
			if(strequal(tok, user_info->wksta_name.str)) {
				invalid_ws = False;
				break;
			}
		}
		
		if (invalid_ws) 
			return NT_STATUS_INVALID_WORKSTATION;
	}

	if (acct_ctrl & ACB_DOMTRUST) {
		DEBUG(2,("sam_account_ok: Domain trust account %s denied by server\n", pdb_get_username(sampass)));
		return NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT;
	}
	
	if (acct_ctrl & ACB_SVRTRUST) {
		DEBUG(2,("sam_account_ok: Server trust account %s denied by server\n", pdb_get_username(sampass)));
		return NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT;
	}
	
	if (acct_ctrl & ACB_WSTRUST) {
		DEBUG(4,("sam_account_ok: Wksta trust account %s denied by server\n", pdb_get_username(sampass)));
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
				   const auth_usersupplied_info *user_info, 
				   auth_serversupplied_info **server_info)
{
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret;
	NTSTATUS nt_status;
	uint8 user_sess_key[16];
	const uint8* lm_hash;

	if (!user_info || !auth_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Can't use the talloc version here, becouse the returned struct gets
	   kept on the server_info */
	if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam(&sampass))) {
		return nt_status;
	}

	/* get the account information */

	become_root();
	ret = pdb_getsampwnam(sampass, user_info->internal_username.str);
	unbecome_root();

	if (ret == False)
	{
		DEBUG(3,("Couldn't find user '%s' in passdb file.\n", user_info->internal_username.str));
		pdb_free_sam(&sampass);
		return NT_STATUS_NO_SUCH_USER;
	}

	nt_status = sam_password_ok(auth_context, mem_ctx, sampass, user_info, user_sess_key);

	if (!NT_STATUS_IS_OK(nt_status)) {
		pdb_free_sam(&sampass);
		return nt_status;
	}

	nt_status = sam_account_ok(mem_ctx, sampass, user_info);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		pdb_free_sam(&sampass);
		return nt_status;
	}

	if (!make_server_info_sam(server_info, sampass)) {		
		DEBUG(0,("failed to malloc memory for server_info\n"));
		return NT_STATUS_NO_MEMORY;
	}

	lm_hash = pdb_get_lanman_passwd((*server_info)->sam_account);
	if (lm_hash) {
		memcpy((*server_info)->first_8_lm_hash, lm_hash, 8);
	}
	
	memcpy((*server_info)->session_key, user_sess_key, sizeof(user_sess_key));

	return nt_status;
}

/* module initialisation */
BOOL auth_init_sam(struct auth_context *auth_context, auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_context, auth_method)) {
		return False;
	}

	(*auth_method)->auth = check_sam_security;
	return True;
}


/****************************************************************************
Check SAM security (above) but with a few extra checks.
****************************************************************************/

static NTSTATUS check_samstrict_security(const struct auth_context *auth_context,
					 void *my_private_data, 
					 TALLOC_CTX *mem_ctx,
					 const auth_usersupplied_info *user_info, 
					 auth_serversupplied_info **server_info)
{

	if (!user_info || !auth_context) {
		return NT_STATUS_LOGON_FAILURE;
	}

	/* If we are a domain member, we must not 
	   attempt to check the password locally,
	   unless it is one of our aliases. */
	
	if (!is_netbios_alias_or_name(user_info->domain.str)) {
		return NT_STATUS_NO_SUCH_USER;
	}
	
	return check_sam_security(auth_context, my_private_data, mem_ctx, user_info, server_info);
}

/* module initialisation */
BOOL auth_init_samstrict(struct auth_context *auth_context, auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_context, auth_method)) {
		return False;
	}

	(*auth_method)->auth = check_samstrict_security;
	return True;
}


