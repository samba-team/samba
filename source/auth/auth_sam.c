/* 
   Unix SMB/CIFS implementation.
   Password and authentication handling
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Andrew Bartlett              2001
   Copyright (C) Gerald Carter                2003
   
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
 Core of smb password checking routine.
****************************************************************************/

static BOOL smb_pwd_check_ntlmv1(const DATA_BLOB *nt_response,
				 const uchar *part_passwd,
				 const DATA_BLOB *sec_blob,
				 DATA_BLOB *user_sess_key)
{
	/* Finish the encryption of part_passwd. */
	uchar p24[24];
	
	if (part_passwd == NULL) {
		DEBUG(10,("No password set - DISALLOWING access\n"));
		/* No password set - always false ! */
		return False;
	}
	
	if (sec_blob->length != 8) {
		DEBUG(0, ("smb_pwd_check_ntlmv1: incorrect challenge size (%lu)\n", (unsigned long)sec_blob->length));
		return False;
	}
	
	if (nt_response->length != 24) {
		DEBUG(0, ("smb_pwd_check_ntlmv1: incorrect password length (%lu)\n", (unsigned long)nt_response->length));
		return False;
	}

	SMBOWFencrypt(part_passwd, sec_blob->data, p24);
	if (user_sess_key != NULL) {
		*user_sess_key = data_blob(NULL, 16);
		SMBsesskeygen_ntv1(part_passwd, NULL, user_sess_key->data);
	}
	
	
	
#if DEBUG_PASSWORD
	DEBUG(100,("Part password (P16) was |\n"));
	dump_data(100, part_passwd, 16);
	DEBUGADD(100,("Password from client was |\n"));
	dump_data(100, nt_response->data, nt_response->length);
	DEBUGADD(100,("Given challenge was |\n"));
	dump_data(100, sec_blob->data, sec_blob->length);
	DEBUGADD(100,("Value from encryption was |\n"));
	dump_data(100, p24, 24);
#endif
  return (memcmp(p24, nt_response->data, 24) == 0);
}

/****************************************************************************
 Core of smb password checking routine. (NTLMv2, LMv2)
 Note:  The same code works with both NTLMv2 and LMv2.
****************************************************************************/

static BOOL smb_pwd_check_ntlmv2(const DATA_BLOB *ntv2_response,
				 const uchar *part_passwd,
				 const DATA_BLOB *sec_blob,
				 const char *user, const char *domain,
				 DATA_BLOB *user_sess_key)
{
	/* Finish the encryption of part_passwd. */
	uchar kr[16];
	uchar value_from_encryption[16];
	uchar client_response[16];
	DATA_BLOB client_key_data;

	if (part_passwd == NULL) {
		DEBUG(10,("No password set - DISALLOWING access\n"));
		/* No password set - always False */
		return False;
	}

	if (ntv2_response->length < 24) {
		/* We MUST have more than 16 bytes, or the stuff below will go
		   crazy.  No known implementation sends less than the 24 bytes
		   for LMv2, let alone NTLMv2. */
		DEBUG(0, ("smb_pwd_check_ntlmv2: incorrect password length (%lu)\n", 
			  (unsigned long)ntv2_response->length));
		return False;
	}

	client_key_data = data_blob(ntv2_response->data+16, ntv2_response->length-16);
	/* 
	   todo:  should we be checking this for anything?  We can't for LMv2, 
	   but for NTLMv2 it is meant to contain the current time etc.
	*/

	memcpy(client_response, ntv2_response->data, sizeof(client_response));

	if (!ntv2_owf_gen(part_passwd, user, domain, kr)) {
		return False;
	}

	SMBOWFencrypt_ntv2(kr, sec_blob, &client_key_data, value_from_encryption);
	if (user_sess_key != NULL) {
		*user_sess_key = data_blob(NULL, 16);
		SMBsesskeygen_ntv2(kr, value_from_encryption, user_sess_key->data);
	}

#if DEBUG_PASSWORD
	DEBUG(100,("Part password (P16) was |\n"));
	dump_data(100, part_passwd, 16);
	DEBUGADD(100,("Password from client was |\n"));
	dump_data(100, ntv2_response->data, ntv2_response->length);
	DEBUGADD(100,("Variable data from client was |\n"));
	dump_data(100, client_key_data.data, client_key_data.length);
	DEBUGADD(100,("Given challenge was |\n"));
	dump_data(100, sec_blob->data, sec_blob->length);
	DEBUGADD(100,("Value from encryption was |\n"));
	dump_data(100, value_from_encryption, 16);
#endif
	data_blob_clear_free(&client_key_data);
	return (memcmp(value_from_encryption, client_response, 16) == 0);
}

/**
 * Check a challenge-response password against the value of the NT or
 * LM password hash.
 *
 * @param mem_ctx talloc context
 * @param challenge 8-byte challenge.  If all zero, forces plaintext comparison
 * @param nt_response 'unicode' NT response to the challenge, or unicode password
 * @param lm_response ASCII or LANMAN response to the challenge, or password in DOS code page
 * @param username internal Samba username, for log messages
 * @param client_username username the client used
 * @param client_domain domain name the client used (may be mapped)
 * @param nt_pw MD4 unicode password from our passdb or similar
 * @param lm_pw LANMAN ASCII password from our passdb or similar
 * @param user_sess_key User session key
 * @param lm_sess_key LM session key (first 8 bytes of the LM hash)
 */

static NTSTATUS ntlm_password_check(TALLOC_CTX *mem_ctx,
				    const DATA_BLOB *challenge,
				    const DATA_BLOB *lm_response,
				    const DATA_BLOB *nt_response,
				    const char *username, 
				    const char *client_username, 
				    const char *client_domain,
				    const uint8 *lm_pw, const uint8 *nt_pw, 
				    DATA_BLOB *user_sess_key, 
				    DATA_BLOB *lm_sess_key)
{
	static const unsigned char zeros[8];
	if (nt_pw == NULL) {
		DEBUG(3,("sam_password_ok: NO NT password stored for user %s.\n", 
			 username));
	}

	/* Check for cleartext netlogon. Used by Exchange 5.5. */
	if (challenge->length == sizeof(zeros) && 
	    (memcmp(challenge->data, zeros, challenge->length) == 0 )) {

		DEBUG(4,("sam_password_ok: checking plaintext passwords for user %s\n",
			 username));
		if (nt_pw && nt_response->length) {
			unsigned char pwhash[16];
			mdfour(pwhash, nt_response->data, nt_response->length);
			if (memcmp(pwhash, nt_pw, sizeof(pwhash)) == 0) {
				return NT_STATUS_OK;
			} else {
				DEBUG(3,("sam_password_ok: NT (Unicode) plaintext password check failed for user %s\n",
					 username));
				return NT_STATUS_WRONG_PASSWORD;
			}

		} else if (!lp_lanman_auth()) {
			DEBUG(3,("sam_password_ok: (plaintext password check) LANMAN passwords NOT PERMITTED for user %s\n",
				 username));

		} else if (lm_pw && lm_response->length) {
			uchar dospwd[14]; 
			uchar p16[16]; 
			ZERO_STRUCT(dospwd);
			
			DEBUG(100, ("DOS password: %s\n"));
			memcpy(dospwd, lm_response->data, MIN(lm_response->length, sizeof(dospwd)));
			/* Only the fisrt 14 chars are considered, password need not be null terminated. */
			E_P16((const unsigned char *)dospwd, p16);

			dump_data_pw("DOS password (first buffer)\n", dospwd, 14);
			dump_data_pw("DOS password (wire DES hash)\n", p16, 16);
			dump_data_pw("DOS password (passdb DES hash)\n", lm_pw, 16);
			if (memcmp(p16, lm_pw, sizeof(p16)) == 0) {
				return NT_STATUS_OK;
			} else {
				DEBUG(3,("sam_password_ok: LANMAN (ASCII) plaintext password check failed for user %s\n",
					 username));
				return NT_STATUS_WRONG_PASSWORD;
			}
		} else {
			DEBUG(3, ("Plaintext authentication for user %s attempted, but neither NT nor LM passwords available\n", username));
			return NT_STATUS_WRONG_PASSWORD;
		}
	}

	if (nt_response->length != 0 && nt_response->length < 24) {
		DEBUG(2,("sam_password_ok: invalid NT password length (%lu) for user %s\n", 
			 (unsigned long)nt_response->length, username));		
	}
	
	if (nt_response->length >= 24 && nt_pw) {
		if (nt_response->length > 24) {
			/* We have the NT MD4 hash challenge available - see if we can
			   use it (ie. does it exist in the smbpasswd file).
			*/
			DEBUG(4,("sam_password_ok: Checking NTLMv2 password with domain [%s]\n", client_domain));
			if (smb_pwd_check_ntlmv2( nt_response, 
						  nt_pw, challenge, 
					  client_username, 
						  client_domain,
						  user_sess_key)) {
				return NT_STATUS_OK;
			}
			
			DEBUG(4,("sam_password_ok: Checking NTLMv2 password without a domain\n"));
			if (smb_pwd_check_ntlmv2( nt_response, 
						  nt_pw, challenge, 
						  client_username, 
						  "",
						  user_sess_key)) {
				return NT_STATUS_OK;
			} else {
				DEBUG(3,("sam_password_ok: NTLMv2 password check failed\n"));
				return NT_STATUS_WRONG_PASSWORD;
			}
		}

		if (lp_ntlm_auth()) {		
			/* We have the NT MD4 hash challenge available - see if we can
			   use it (ie. does it exist in the smbpasswd file).
			*/
			DEBUG(4,("sam_password_ok: Checking NT MD4 password\n"));
			if (smb_pwd_check_ntlmv1(nt_response, 
						 nt_pw, challenge,
						 user_sess_key)) {
				/* The LM session key for this response is not very secure, 
				   so use it only if we otherwise allow LM authentication */

				if (lp_lanman_auth() && lm_pw) {
					uint8 first_8_lm_hash[16];
					memcpy(first_8_lm_hash, lm_pw, 8);
					memset(first_8_lm_hash + 8, '\0', 8);
					*lm_sess_key = data_blob(first_8_lm_hash, 16);
				}
				return NT_STATUS_OK;
			} else {
				DEBUG(3,("sam_password_ok: NT MD4 password check failed for user %s\n",
					 username));
				return NT_STATUS_WRONG_PASSWORD;
			}
		} else {
			DEBUG(2,("sam_password_ok: NTLMv1 passwords NOT PERMITTED for user %s\n",
				 username));			
			/* no return, becouse we might pick up LMv2 in the LM field */
		}
	}
	
	if (lm_response->length == 0) {
		DEBUG(3,("sam_password_ok: NEITHER LanMan nor NT password supplied for user %s\n",
			 username));
		return NT_STATUS_WRONG_PASSWORD;
	}
	
	if (lm_response->length < 24) {
		DEBUG(2,("sam_password_ok: invalid LanMan password length (%lu) for user %s\n", 
			 (unsigned long)nt_response->length, username));		
		return NT_STATUS_WRONG_PASSWORD;
	}
		
	if (!lp_lanman_auth()) {
		DEBUG(3,("sam_password_ok: Lanman passwords NOT PERMITTED for user %s\n",
			 username));
	} else if (!lm_pw) {
		DEBUG(3,("sam_password_ok: NO LanMan password set for user %s (and no NT password supplied)\n",
			 username));
	} else {
		DEBUG(4,("sam_password_ok: Checking LM password\n"));
		if (smb_pwd_check_ntlmv1(lm_response, 
					 lm_pw, challenge,
					 NULL)) {
			uint8 first_8_lm_hash[16];
			memcpy(first_8_lm_hash, lm_pw, 8);
			memset(first_8_lm_hash + 8, '\0', 8);
			*user_sess_key = data_blob(first_8_lm_hash, 16);
			*lm_sess_key = data_blob(first_8_lm_hash, 16);
			return NT_STATUS_OK;
		}
	}
	
	if (!nt_pw) {
		DEBUG(4,("sam_password_ok: LM password check failed for user, no NT password %s\n",username));
		return NT_STATUS_WRONG_PASSWORD;
	}
	
	/* This is for 'LMv2' authentication.  almost NTLMv2 but limited to 24 bytes.
	   - related to Win9X, legacy NAS pass-though authentication
	*/
	DEBUG(4,("sam_password_ok: Checking LMv2 password with domain %s\n", client_domain));
	if (smb_pwd_check_ntlmv2( lm_response, 
				  nt_pw, challenge, 
				  client_username,
				  client_domain,
				  NULL)) {
		return NT_STATUS_OK;
	}
	
	DEBUG(4,("sam_password_ok: Checking LMv2 password without a domain\n"));
	if (smb_pwd_check_ntlmv2( lm_response, 
				  nt_pw, challenge, 
				  client_username,
				  "",
				  NULL)) {
		return NT_STATUS_OK;
	}

	/* Apparently NT accepts NT responses in the LM field
	   - I think this is related to Win9X pass-though authentication
	*/
	DEBUG(4,("sam_password_ok: Checking NT MD4 password in LM field\n"));
	if (lp_ntlm_auth()) {
		if (smb_pwd_check_ntlmv1(lm_response, 
					 nt_pw, challenge,
					 NULL)) {
			/* The session key for this response is still very odd.  
			   It not very secure, so use it only if we otherwise 
			   allow LM authentication */

			if (lp_lanman_auth() && lm_pw) {
				uint8 first_8_lm_hash[16];
				memcpy(first_8_lm_hash, lm_pw, 8);
				memset(first_8_lm_hash + 8, '\0', 8);
				*user_sess_key = data_blob(first_8_lm_hash, 16);
				*lm_sess_key = data_blob(first_8_lm_hash, 16);
			}
			return NT_STATUS_OK;
		}
		DEBUG(3,("sam_password_ok: LM password, NT MD4 password in LM field and LMv2 failed for user %s\n",username));
	} else {
		DEBUG(3,("sam_password_ok: LM password and LMv2 failed for user %s, and NT MD4 password in LM field not permitted\n",username));
	}
	return NT_STATUS_WRONG_PASSWORD;
}

/****************************************************************************
 Do a specific test for an smb password being correct, given a smb_password and
 the lanman and NT responses.
****************************************************************************/

static NTSTATUS sam_password_ok(const struct auth_context *auth_context,
				TALLOC_CTX *mem_ctx,
				SAM_ACCOUNT *sampass, 
				const auth_usersupplied_info *user_info, 
				DATA_BLOB *user_sess_key, 
				DATA_BLOB *lm_sess_key)
{
	uint16 acct_ctrl;
	const uint8 *lm_pw, *nt_pw;
	const char *username = pdb_get_username(sampass);

	acct_ctrl = pdb_get_acct_ctrl(sampass);
	if (acct_ctrl & ACB_PWNOTREQ) {
		if (lp_null_passwords()) {
			DEBUG(3,("Account for user '%s' has no password and null passwords are allowed.\n", username));
			return NT_STATUS_OK;
		} else {
			DEBUG(3,("Account for user '%s' has no password and null passwords are NOT allowed.\n", username));
			return NT_STATUS_LOGON_FAILURE;
		}		
	}

	lm_pw = pdb_get_lanman_passwd(sampass);
	nt_pw = pdb_get_nt_passwd(sampass);

	return ntlm_password_check(mem_ctx, &auth_context->challenge, 
				   &user_info->lm_resp, &user_info->nt_resp,  
				   username, 
				   user_info->smb_name.str, 
				   user_info->client_domain.str, 
				   lm_pw, nt_pw, user_sess_key, lm_sess_key);
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
		DEBUG(1,("sam_account_ok: Account for user '%s' was disabled.\n", pdb_get_username(sampass)));
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	/* Quit if the account was locked out. */
	if (acct_ctrl & ACB_AUTOLOCK) {
		DEBUG(1,("sam_account_ok: Account for user %s was locked out.\n", pdb_get_username(sampass)));
		return NT_STATUS_ACCOUNT_LOCKED_OUT;
	}

	/* Test account expire time */
	
	kickoff_time = pdb_get_kickoff_time(sampass);
	if (kickoff_time != 0 && time(NULL) > kickoff_time) {
		DEBUG(1,("sam_account_ok: Account for user '%s' has expired.\n", pdb_get_username(sampass)));
		DEBUG(3,("sam_account_ok: Account expired at '%ld' unix time.\n", (long)kickoff_time));
		return NT_STATUS_ACCOUNT_EXPIRED;
	}

	if (!(pdb_get_acct_ctrl(sampass) & ACB_PWNOEXP)) {
		time_t must_change_time = pdb_get_pass_must_change_time(sampass);
		time_t last_set_time = pdb_get_pass_last_set_time(sampass);

		/* check for immediate expiry "must change at next logon" */
		if (must_change_time == 0 && last_set_time != 0) {
			DEBUG(1,("sam_account_ok: Account for user '%s' password must change!.\n", pdb_get_username(sampass)));
			return NT_STATUS_PASSWORD_MUST_CHANGE;
		}

		/* check for expired password */
		if (must_change_time < time(NULL) && must_change_time != 0) {
			DEBUG(1,("sam_account_ok: Account for user '%s' password expired!.\n", pdb_get_username(sampass)));
			DEBUG(1,("sam_account_ok: Password expired at '%s' (%ld) unix time.\n", http_timestring(must_change_time), (long)must_change_time));
			return NT_STATUS_PASSWORD_EXPIRED;
		}
	}

	/* Test workstation. Workstation list is comma separated. */

	workstation_list = talloc_strdup(mem_ctx, pdb_get_workstations(sampass));
	if (!workstation_list)
		return NT_STATUS_NO_MEMORY;

	if (*workstation_list) {
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
	DATA_BLOB user_sess_key = data_blob(NULL, 0);
	DATA_BLOB lm_sess_key = data_blob(NULL, 0);

	if (!user_info || !auth_context) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Can't use the talloc version here, because the returned struct gets
	   kept on the server_info */
	if (!NT_STATUS_IS_OK(nt_status = pdb_init_sam(&sampass))) {
		return nt_status;
	}

	/* get the account information */

	become_root();
	ret = pdb_getsampwnam(sampass, user_info->internal_username.str);
	unbecome_root();

	if (ret == False) {
		DEBUG(3,("check_sam_security: Couldn't find user '%s' in passdb file.\n", user_info->internal_username.str));
		pdb_free_sam(&sampass);
		return NT_STATUS_NO_SUCH_USER;
	}

	nt_status = sam_password_ok(auth_context, mem_ctx, sampass, 
				    user_info, &user_sess_key, &lm_sess_key);
	
	if (!NT_STATUS_IS_OK(nt_status)) {
		pdb_free_sam(&sampass);
		return nt_status;
	}

	nt_status = sam_account_ok(mem_ctx, sampass, user_info);

	if (!NT_STATUS_IS_OK(nt_status)) {
		pdb_free_sam(&sampass);
		return nt_status;
	}

	if (!NT_STATUS_IS_OK(nt_status = make_server_info_sam(server_info, sampass))) {		
		DEBUG(0,("check_sam_security: make_server_info_sam() failed with '%s'\n", nt_errstr(nt_status)));
		return nt_status;
	}

	(*server_info)->nt_session_key = user_sess_key;
	(*server_info)->lm_session_key = lm_sess_key;

	return nt_status;
}

/* module initialisation */
static NTSTATUS auth_init_sam_ignoredomain(struct auth_context *auth_context, const char *param, auth_methods **auth_method) 
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
					 const auth_usersupplied_info *user_info, 
					 auth_serversupplied_info **server_info)
{
	BOOL is_local_name, is_my_domain;

	if (!user_info || !auth_context) {
		return NT_STATUS_LOGON_FAILURE;
	}

	is_local_name = is_myname(user_info->domain.str);
	is_my_domain  = strequal(user_info->domain.str, lp_workgroup());

	/* check whether or not we service this domain/workgroup name */
	
	switch ( lp_server_role() ) {
		case ROLE_STANDALONE:
		case ROLE_DOMAIN_MEMBER:
			if ( !is_local_name ) {
				DEBUG(6,("check_samstrict_security: %s is not one of my local names (%s)\n",
					user_info->domain.str, (lp_server_role() == ROLE_DOMAIN_MEMBER 
					? "ROLE_DOMAIN_MEMBER" : "ROLE_STANDALONE") ));
				return NT_STATUS_NOT_IMPLEMENTED;
			}
		case ROLE_DOMAIN_PDC:
		case ROLE_DOMAIN_BDC:
			if ( !is_local_name && !is_my_domain ) {
				DEBUG(6,("check_samstrict_security: %s is not one of my local names or domain name (DC)\n",
					user_info->domain.str));
				return NT_STATUS_NOT_IMPLEMENTED;
			}
		default: /* name is ok */
			break;
	}
	
	return check_sam_security(auth_context, my_private_data, mem_ctx, user_info, server_info);
}

/* module initialisation */
static NTSTATUS auth_init_sam(struct auth_context *auth_context, const char *param, auth_methods **auth_method) 
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
	smb_register_auth(AUTH_INTERFACE_VERSION, "sam", auth_init_sam);
	smb_register_auth(AUTH_INTERFACE_VERSION, "sam_ignoredomain", auth_init_sam_ignoredomain);
	return NT_STATUS_OK;
}
