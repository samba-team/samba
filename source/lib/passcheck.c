/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password and authentication handling
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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
static BOOL smb_pwd_check_ntlmv1(const char *password,
				const uchar *part_passwd,
				const uchar *c8,
				uchar user_sess_key[16])
{
  /* Finish the encryption of part_passwd. */
  uchar p24[24];

  if (part_passwd == NULL)
    DEBUG(10,("No password set - allowing access\n"));
  /* No password set - always true ! */
  if (part_passwd == NULL)
    return True;

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
static BOOL smb_pwd_check_ntlmv2(const char *password, size_t pwd_len,
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
		DEBUG(10,("No password set - allowing access\n"));
	}
	/* No password set - always true ! */
	if (part_passwd == NULL)
	{
		return True;
	}

	ntv2_owf_gen(part_passwd, user, domain, kr);
	SMBOWFencrypt_ntv2(kr, c8, 8, password+16, pwd_len-16, resp);
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
BOOL smb_password_ok(uint16 acct_ctrl,
				uchar smb_passwd[16],
				uchar smb_nt_passwd[16],
				const uchar challenge[8],
				const char *user, const char *domain,
				const uchar *lm_pass, size_t lm_pwd_len,
				const uchar *nt_pass, size_t nt_pwd_len,
				uchar user_sess_key[16])
{
	DEBUG(4,("Checking SMB password for user %s\n", user));

	dump_data_pw("lm password:\n", lm_pass, lm_pwd_len);
	dump_data_pw("nt password:\n", nt_pass, nt_pwd_len);

	if (acct_ctrl & ACB_DISABLED)
	{
		DEBUG(3,("account for user %s was disabled.\n", user));
		return False;
	}

	if (challenge == NULL)
	{
		DEBUG(1,("no challenge available - password failed\n"));
		return False;
	}

	if (smb_nt_passwd != NULL)
	{
		/* We have the NT MD4 hash challenge available - see if we can
		   use it (ie. does it exist in the smbpasswd file).
		*/
		if (lp_server_ntlmv2() != False && nt_pwd_len > 24)
		{
			DEBUG(4,("smb_password_ok: Check NTLMv2 password\n"));
			if (smb_pwd_check_ntlmv2(nt_pass, nt_pwd_len,
				       (uchar *)smb_nt_passwd, 
					challenge, user, domain,
			                user_sess_key))
			{
				return True;
			}
		}
		if (lp_server_ntlmv2() != True && nt_pwd_len == 24)
		{
			DEBUG(4,("smb_password_ok: Check NT MD4 password\n"));
			if (smb_pwd_check_ntlmv1((const char *)nt_pass, 
				       (const uchar *)smb_nt_passwd, 
				       challenge,
			               user_sess_key))
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

	/* Try against the lanman password. smb_passwd == NULL means
	   no password, allow access. */

	DEBUG(4,("Checking LM MD4 password\n"));

	if ((smb_passwd == NULL) && 
	   (acct_ctrl & ACB_PWNOTREQ))
	{
		DEBUG(4,("no password required for user %s\n", user));
		return True;
	}

	if ((smb_passwd != NULL) && 
	   smb_pwd_check_ntlmv1((const char *)lm_pass, 
			      (const uchar *)smb_passwd,
				challenge, user_sess_key))
	{
		DEBUG(4,("LM MD4 password check succeeded\n"));
		return(True);
	}

	DEBUG(4,("LM MD4 password check failed\n"));

	return False;
}

