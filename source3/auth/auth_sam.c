/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
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

extern int DEBUGLEVEL;

/****************************************************************************
core of smb password checking routine.
****************************************************************************/
static BOOL smb_pwd_check_ntlmv1(const uchar *password,
				const uchar *part_passwd,
				const uchar *c8,
				char user_sess_key[16])
{
  /* Finish the encryption of part_passwd. */
  uchar p24[24];

  if (part_passwd == NULL) {
	  DEBUG(10,("No password set - DISALLOWING access\n"));
	  /* No password set - always false ! */
	  return False;
  }

  SMBOWFencrypt(part_passwd, c8, p24);
	if (user_sess_key != NULL)
	{
		SMBsesskeygen_ntv1(part_passwd, NULL, user_sess_key);
	}



#if DEBUG_PASSWORD
	DEBUG(100,("Part password (P16) was |"));
	dump_data(100, part_passwd, 16);
	DEBUG(100,("Password from client was |"));
	dump_data(100, password, 24);
	DEBUG(100,("Given challenge was |"));
	dump_data(100, c8, 8);
	DEBUG(100,("Value from encryption was |"));
	dump_data(100, p24, 24);
#endif
  return (memcmp(p24, password, 24) == 0);
}

/****************************************************************************
core of smb password checking routine.
****************************************************************************/
static BOOL smb_pwd_check_ntlmv2(const uchar *password, size_t pwd_len,
				uchar *part_passwd,
				uchar const *c8,
				const char *user, const char *domain,
				char user_sess_key[16])
{
	/* Finish the encryption of part_passwd. */
	uchar kr[16];
	uchar resp[16];

	if (part_passwd == NULL)
	{
		DEBUG(10,("No password set - DISALLOWING access\n"));
		/* No password set - always False */
		return False;
	}

	ntv2_owf_gen(part_passwd, user, domain, kr);
	SMBOWFencrypt_ntv2(kr, c8, 8, password+16, pwd_len-16, (char *)resp);
	if (user_sess_key != NULL)
	{
		SMBsesskeygen_ntv2(kr, resp, user_sess_key);
	}

#if DEBUG_PASSWORD
	DEBUG(100,("Part password (P16) was |"));
	dump_data(100, part_passwd, 16);
	DEBUG(100,("Password from client was |"));
	dump_data(100, password, pwd_len);
	DEBUG(100,("Given challenge was |"));
	dump_data(100, c8, 8);
	DEBUG(100,("Value from encryption was |"));
	dump_data(100, resp, 16);
#endif

	return (memcmp(resp, password, 16) == 0);
}


/****************************************************************************
 Do a specific test for an smb password being correct, given a smb_password and
 the lanman and NT responses.
****************************************************************************/
NTSTATUS sam_password_ok(SAM_ACCOUNT *sampass, const auth_usersupplied_info *user_info, char user_sess_key[16])
{
	uint8 *nt_pw, *lm_pw;
	uint16	acct_ctrl = pdb_get_acct_ctrl(sampass);
	
	if (!user_info || !sampass) 
		return NT_STATUS_LOGON_FAILURE;

	if (acct_ctrl & ACB_PWNOTREQ) 
	{
		if (lp_null_passwords()) 
		{
			DEBUG(3,("Account for user '%s' has no password and null passwords are allowed.\n", sampass->username));
			return(NT_STATUS_OK);
		} 
		else 
		{
			DEBUG(3,("Account for user '%s' has no password and null passwords are NOT allowed.\n", sampass->username));
			return(NT_STATUS_LOGON_FAILURE);
		}		
	} else {
		nt_pw = pdb_get_nt_passwd(sampass);
		lm_pw = pdb_get_lanman_passwd(sampass);
		
		if (nt_pw != NULL && user_info->nt_resp.len > 0) {
			if ((user_info->nt_resp.len > 24 )) {
				/* We have the NT MD4 hash challenge available - see if we can
				   use it (ie. does it exist in the smbpasswd file).
				*/
				DEBUG(4,("smb_password_ok: Checking NTLMv2 password\n"));
				if (smb_pwd_check_ntlmv2( user_info->nt_resp.buffer, 
							   user_info->nt_resp.len, 
							   nt_pw, 
							   user_info->chal, user_info->smb_username.str, 
							   user_info->requested_domain.str,
							   user_sess_key))
				{
					return NT_STATUS_OK;
				} else {
					DEBUG(4,("smb_password_ok: NTLMv2 password check failed\n"));
					return NT_STATUS_WRONG_PASSWORD;
				}
				
			} else if (lp_ntlm_auth() && (user_info->nt_resp.len == 24)) {
				/* We have the NT MD4 hash challenge available - see if we can
				   use it (ie. does it exist in the smbpasswd file).
				*/
				DEBUG(4,("smb_password_ok: Checking NT MD4 password\n"));
				if (smb_pwd_check_ntlmv1(user_info->nt_resp.buffer, 
							  nt_pw, user_info->chal,
							  user_sess_key)) 
				{
					return NT_STATUS_OK;
				} else {
					DEBUG(4,("smb_password_ok: NT MD4 password check failed\n"));
					return NT_STATUS_WRONG_PASSWORD;
				}
			} else {
				return NT_STATUS_LOGON_FAILURE;
			}
		} else if (lm_pw != NULL && user_info->lm_resp.len == 24) {
			if (lp_lanman_auth()) {
				DEBUG(4,("smb_password_ok: Checking LM password\n"));
				if (smb_pwd_check_ntlmv1(user_info->lm_resp.buffer, 
							 lm_pw, user_info->chal,
							 user_sess_key)) 
				{
					return NT_STATUS_OK;
				} else {
					DEBUG(4,("smb_password_ok: LM password check failed\n"));
					return NT_STATUS_WRONG_PASSWORD;
				}       
			}
		}
	}
	/* Should not be reached */
	return NT_STATUS_LOGON_FAILURE;
}

/****************************************************************************
 Do a specific test for a SAM_ACCOUNT being vaild for this connection 
 (ie not disabled, expired and the like).
****************************************************************************/
NTSTATUS sam_account_ok(SAM_ACCOUNT *sampass, const auth_usersupplied_info *user_info)
{
	uint16	acct_ctrl = pdb_get_acct_ctrl(sampass);
	char *workstation_list;
	time_t kickoff_time;
	
	if (!user_info || !sampass) 
		return NT_STATUS_LOGON_FAILURE;

	DEBUG(4,("smb_password_ok: Checking SMB password for user %s\n",sampass->username));

	/* Quit if the account was disabled. */
	if (acct_ctrl & ACB_DISABLED) {
		DEBUG(1,("Account for user '%s' was disabled.\n", sampass->username));
		return NT_STATUS_ACCOUNT_DISABLED;
	}

	/* Test account expire time */
	
	kickoff_time = pdb_get_kickoff_time(sampass);
	if (kickoff_time != 0 && time(NULL) > kickoff_time) {
		DEBUG(1,("Account for user '%s' has expried.\n", sampass->username));
		DEBUG(3,("Account expired at '%ld' unix time.\n", (long)kickoff_time));
		return NT_STATUS_ACCOUNT_EXPIRED;
	}

	/* Test workstation. Workstation list is comma separated. */

	workstation_list = strdup(pdb_get_workstations(sampass));

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
		
		SAFE_FREE(workstation_list);		
		if (invalid_ws) 
			return NT_STATUS_INVALID_WORKSTATION;
	} else {
		SAFE_FREE(workstation_list);
	}

	
	{
		time_t must_change_time = pdb_get_pass_must_change_time(sampass);
		time_t last_set_time = pdb_get_pass_last_set_time(sampass);

		/* check for immediate expiry "must change at next logon" */
		if (must_change_time == 0 && last_set_time != 0) {
			DEBUG(1,("Account for user '%s' password must change!.\n", sampass->username));
			return NT_STATUS_PASSWORD_MUST_CHANGE;
		}

		/* check for expired password */
		if (must_change_time < time(NULL) && must_change_time != 0) {
			DEBUG(1,("Account for user '%s' password expired!.\n", sampass->username));
			DEBUG(1,("Password expired at '%ld' unix time.\n", (long)must_change_time));
			return NT_STATUS_PASSWORD_EXPIRED;
		}
	}

	if (acct_ctrl & ACB_DOMTRUST) {
		DEBUG(2,("session_trust_account: Domain trust account %s denied by server\n", sampass->username));
		return NT_STATUS_NOLOGON_INTERDOMAIN_TRUST_ACCOUNT;
	}
	
	if (acct_ctrl & ACB_SVRTRUST) {
		DEBUG(2,("session_trust_account: Server trust account %s denied by server\n", sampass->username));
		return NT_STATUS_NOLOGON_SERVER_TRUST_ACCOUNT;
	}
	
	if (acct_ctrl & ACB_WSTRUST) {
		DEBUG(4,("session_trust_account: Wksta trust account %s denied by server\n", sampass->username));
		return NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT;
	}
	
	return NT_STATUS_OK;
}


/****************************************************************************
check if a username/password is OK assuming the password is a 24 byte
SMB hash supplied in the user_info structure
return an NT_STATUS constant.
****************************************************************************/

NTSTATUS check_smbpasswd_security(const auth_usersupplied_info *user_info, auth_serversupplied_info *server_info)
{
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret;
	NTSTATUS nt_status;

	pdb_init_sam(&sampass);

	/* get the account information */

	become_root();
	ret = pdb_getsampwnam(sampass, user_info->unix_username.str);
	unbecome_root();

	if (ret == False)
	{
		DEBUG(1,("Couldn't find user '%s' in passdb file.\n", user_info->unix_username.str));
		pdb_free_sam(&sampass);
		return NT_STATUS_NO_SUCH_USER;
	}

	nt_status = sam_password_ok(sampass, user_info, server_info->session_key);

	if NT_STATUS_IS_OK(nt_status) {
		nt_status = sam_account_ok(sampass, user_info);
	}

	pdb_free_sam(&sampass);
	return nt_status;
}



