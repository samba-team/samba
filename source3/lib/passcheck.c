/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Andrew Tridgell 1992-1998
   
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
extern int Protocol;

extern pstring scope;
extern pstring global_myname;
extern fstring global_myworkgroup;



/****************************************************************************
core of smb password checking routine.
****************************************************************************/
static BOOL smb_pwd_check_ntlmv1(char *password, unsigned char *part_passwd,
				unsigned char *c8,
				uchar sess_key[16])
{
  /* Finish the encryption of part_passwd. */
  unsigned char p24[24];

  if (part_passwd == NULL)
    DEBUG(10,("No password set - allowing access\n"));
  /* No password set - always true ! */
  if (part_passwd == NULL)
    return True;

  SMBOWFencrypt(part_passwd, c8, p24);
	if (sess_key != NULL)
	{
		SMBsesskeygen_ntv1(part_passwd, NULL, sess_key);
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
static BOOL smb_pwd_check_ntlmv2(char *password, size_t pwd_len,
				unsigned char *part_passwd,
				unsigned char const *c8,
				const char *user, const char *domain,
				char *sess_key)
{
	/* Finish the encryption of part_passwd. */
	unsigned char kr[16];
	unsigned char resp[16];

	if (part_passwd == NULL)
	{
		DEBUG(10,("No password set - allowing access\n"));
	}
	/* No password set - always true ! */
	if (part_passwd == NULL)
	{
		return True;
	}

	ntv2_owf_gen(part_passwd, user, domain, kr);
	SMBOWFencrypt_ntv2(kr, c8, 8, password+16, pwd_len-16, resp);
	if (sess_key != NULL)
	{
		SMBsesskeygen_ntv2(kr, resp, sess_key);
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
BOOL smb_password_ok(struct smb_passwd *smb_pass, uchar challenge[8],
				const char *user, const char *domain,
				uchar *lm_pass, size_t lm_pwd_len,
				uchar *nt_pass, size_t nt_pwd_len,
				uchar sess_key[16])
{
	if (smb_pass == NULL)
	{
		return False;
	}

	DEBUG(4,("Checking SMB password for user %s\n", 
		 smb_pass->unix_name));

	if (smb_pass->acct_ctrl & ACB_DISABLED)
	{
		DEBUG(3,("account for user %s was disabled.\n", 
			 smb_pass->unix_name));
		return False;
	}

	if (challenge == NULL)
	{
		DEBUG(1,("no challenge available - password failed\n"));
		return False;
	}

	if ((Protocol >= PROTOCOL_NT1) && (smb_pass->smb_nt_passwd != NULL))
	{
		/* We have the NT MD4 hash challenge available - see if we can
		   use it (ie. does it exist in the smbpasswd file).
		*/
		if (lp_server_ntlmv2() != False && nt_pwd_len > 24)
		{
			DEBUG(4,("smb_password_ok: Check NTLMv2 password\n"));
			if (smb_pwd_check_ntlmv2(nt_pass, nt_pwd_len,
				       (uchar *)smb_pass->smb_nt_passwd, 
					challenge, user, domain,
			                sess_key))
			{
				return True;
			}
		}
		if (lp_server_ntlmv2() != True && nt_pwd_len == 24)
		{
			DEBUG(4,("smb_password_ok: Check NT MD4 password\n"));
			if (smb_pwd_check_ntlmv1((char *)nt_pass, 
				       (uchar *)smb_pass->smb_nt_passwd, 
				       challenge,
			               sess_key))
			{
				DEBUG(4,("NT MD4 password check succeeded\n"));
				return True;
			}
		}
		DEBUG(4,("NT MD4 password check failed\n"));
	}

	if (lp_server_ntlmv2() == True)
	{
		DEBUG(4,("Not checking LM MD4 password\n"));
		return False;
	}

	/* Try against the lanman password. smb_pass->smb_passwd == NULL means
	   no password, allow access. */

	DEBUG(4,("Checking LM MD4 password\n"));

	if ((smb_pass->smb_passwd == NULL) && 
	   (smb_pass->acct_ctrl & ACB_PWNOTREQ))
	{
		DEBUG(4,("no password required for user %s\n",
			 smb_pass->unix_name));
		return True;
	}

	if ((smb_pass->smb_passwd != NULL) && 
	   smb_pwd_check_ntlmv1((char *)lm_pass, 
			      (uchar *)smb_pass->smb_passwd,
				challenge, NULL))
	{
		DEBUG(4,("LM MD4 password check succeeded\n"));
		return(True);
	}

	DEBUG(4,("LM MD4 password check failed\n"));

	return False;
}


/****************************************************************************
check if a username/password is OK assuming the password is a 24 byte
SMB hash
return True if the password is correct, False otherwise
****************************************************************************/
BOOL pass_check_smb(struct smb_passwd *smb_pass, char *domain, uchar *chal,
		uchar *lm_pwd, size_t lm_pwd_len,
		uchar *nt_pwd, size_t nt_pwd_len,
		struct passwd *pwd, uchar user_sess_key[16])
{
	const struct passwd *pass;
	struct passwd pw;
	char *user = NULL;

	if (smb_pass == NULL)
	{
		DEBUG(3,("Couldn't find user %s in smb_passwd file.\n", user));
		return False;
	}

	user = smb_pass->unix_name;

	if (lm_pwd == NULL || nt_pwd == NULL)
	{
		return False;
	}

	if (pwd != NULL && user == NULL)
	{
		pass = (struct passwd *) pwd;
		user = pass->pw_name;
	}
	else
	{
		pass = Get_Pwnam(user,True);
		if (pass == NULL)
		{
			DEBUG(3,("Couldn't find user %s\n",user));
			return False;
		}
		memcpy(&pw, pass, sizeof(struct passwd));
		pass = &pw;
	}

	/* Quit if the account was disabled. */
	if (smb_pass->acct_ctrl & ACB_DISABLED) {
		DEBUG(3,("account for user %s was disabled.\n", user));
		return False;
        }

	/* Ensure the uid's match */
	if (smb_pass->unix_uid != pass->pw_uid)
	{
		DEBUG(3,("Error : UNIX (%d) and SMB (%d) uids in password files do not match !\n", pass->pw_uid, smb_pass->unix_uid));
		return False;
	}

	if (lm_pwd[0] == '\0' && IS_BITS_SET_ALL(smb_pass->acct_ctrl, ACB_PWNOTREQ) && lp_null_passwords())
	{
		DEBUG(3,("account for user %s has no password and null passwords are allowed.\n", smb_pass->unix_name));
		return(True);
	}

	if (smb_password_ok(smb_pass, chal, user, domain,
	                                    lm_pwd, lm_pwd_len,
		                            nt_pwd, nt_pwd_len,
	                                    user_sess_key))
	{
		if (user_sess_key != NULL)
		{
#ifdef DEBUG_PASSWORD
		DEBUG(100,("user session key: "));
		dump_data(100, user_sess_key, 16);
#endif
		}
		return(True);
	}
	
	DEBUG(3,("Error pass_check_smb failed\n"));
	return False;
}

