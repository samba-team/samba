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
				uchar user_sess_key[16])
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
		SMBsesskeygen_ntv1(part_passwd, NULL, (char *)user_sess_key);
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
				char *user_sess_key)
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
uint32 smb_password_ok(SAM_ACCOUNT *sampass, const auth_usersupplied_info *user_info, auth_serversupplied_info *server_info)
{
	uint8 *nt_pw, *lm_pw;
	uint16	acct_ctrl;

	acct_ctrl = pdb_get_acct_ctrl(sampass);
	
	/* Quit if the account was disabled. */
	if(acct_ctrl & ACB_DISABLED) {
		DEBUG(1,("Account for user '%s' was disabled.\n", user_info->smb_username.str));
		return(NT_STATUS_ACCOUNT_DISABLED);
	}

	if (acct_ctrl & ACB_PWNOTREQ) 
	{
		if (lp_null_passwords()) 
		{
			DEBUG(3,("Account for user '%s' has no password and null passwords are allowed.\n", user_info->smb_username.str));
			return(NT_STATUS_OK);
		} 
		else 
		{
			DEBUG(3,("Account for user '%s' has no password and null passwords are NOT allowed.\n", user_info->smb_username.str));
			return(NT_STATUS_LOGON_FAILURE);
		}		
	}

	if (!user_info || !sampass) 
		return(NT_STATUS_LOGON_FAILURE);

	DEBUG(4,("smb_password_ok: Checking SMB password for user %s\n",user_info->smb_username.str));

	nt_pw = pdb_get_nt_passwd(sampass);

	if (nt_pw != NULL) {
		if ((user_info->nt_resp.len > 24 )) {
			/* We have the NT MD4 hash challenge available - see if we can
			   use it (ie. does it exist in the smbpasswd file).
			*/
			DEBUG(4,("smb_password_ok: Checking NTLMv2 password\n"));
			if (smb_pwd_check_ntlmv2( user_info->nt_resp.buffer, 
						  user_info->nt_resp.len, 
						  nt_pw, 
						  user_info->chal, user_info->requested_username.str, 
						  user_info->requested_domain.str,
						  (char *)server_info->session_key))
			{
				return NT_STATUS_OK;
			}
			DEBUG(4,("smb_password_ok: NTLMv2 password check failed\n"));

		} else if (lp_ntlm_auth() && (user_info->nt_resp.len == 24 )) {
				/* We have the NT MD4 hash challenge available - see if we can
				   use it (ie. does it exist in the smbpasswd file).
				*/
			DEBUG(4,("smb_password_ok: Checking NT MD4 password\n"));
			if (smb_pwd_check_ntlmv1(user_info->nt_resp.buffer, 
						 nt_pw, user_info->chal,
						 server_info->session_key)) {
				DEBUG(4,("smb_password_ok: NT MD4 password check succeeded\n"));
				return NT_STATUS_OK;
			} else { 
				DEBUG(4,("smb_password_ok: NT MD4 password check failed\n"));
				return NT_STATUS_WRONG_PASSWORD;
			}
		}
	}
	
	lm_pw = pdb_get_lanman_passwd(sampass);
	
	if(lp_lanman_auth() && (lm_pw != NULL) && (user_info->lm_resp.len == 24 )) {
		DEBUG(4,("smb_password_ok: Checking LM password\n"));
		if (smb_pwd_check_ntlmv1(user_info->lm_resp.buffer, 
					 lm_pw, user_info->chal,
					 server_info->session_key)) {
			DEBUG(4,("smb_password_ok: LM password check succeeded\n"));
			return NT_STATUS_OK;
		} else {
			DEBUG(4,("smb_password_ok: LM password check failed\n"));
			return NT_STATUS_WRONG_PASSWORD;
		}
	}
	
	return NT_STATUS_LOGON_FAILURE;
}


/****************************************************************************
check if a username/password is OK assuming the password is a 24 byte
SMB hash supplied in the user_info structure
return an NT_STATUS constant.
****************************************************************************/

uint32 check_smbpasswd_security(const auth_usersupplied_info *user_info, auth_serversupplied_info *server_info)
{
	SAM_ACCOUNT *sampass=NULL;
	BOOL ret;
	uint32 nt_status;

	pdb_init_sam(&sampass);

	/* get the account information */

	become_root();
	ret = pdb_getsampwnam(sampass, user_info->smb_username.str);
	unbecome_root();

	if (ret == False)
	{
		DEBUG(1,("Couldn't find user '%s' in passdb file.\n", user_info->smb_username.str));
		pdb_free_sam(sampass);
		return(NT_STATUS_NO_SUCH_USER);
	}

	nt_status = smb_password_ok(sampass, user_info, server_info);
	
	pdb_free_sam(sampass);
	return nt_status;
}


