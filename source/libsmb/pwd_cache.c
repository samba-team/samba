/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password cacheing.  
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   
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
initialises a password structure
****************************************************************************/
void pwd_init(struct pwd_info *pwd)
{
	ZERO_STRUCT(pwd->password);
	ZERO_STRUCT(pwd->smb_lm_pwd);
	ZERO_STRUCT(pwd->smb_nt_pwd);
	ZERO_STRUCT(pwd->smb_lm_owf);
	ZERO_STRUCT(pwd->smb_nt_owf);
	pwd->nt_owf_len = 0;

	pwd->null_pwd = True;	/* safest option... */
	pwd->cleartext = False;
	pwd->crypted = False;
}

/****************************************************************************
returns NULL password flag
****************************************************************************/
BOOL pwd_is_nullpwd(const struct pwd_info *pwd)
{
	return pwd->null_pwd;
}


/****************************************************************************
compares two passwords.  hmm, not as trivial as expected.  hmm.
****************************************************************************/
BOOL pwd_compare(const struct pwd_info *pwd1, const struct pwd_info *pwd2)
{
	if (pwd1->crypted || pwd2->crypted)
	{
		DEBUG(0, ("pwd_compare: cannot compare crypted passwords\n"));
		return True;
	}

	if (pwd1->cleartext && pwd2->cleartext)
	{
		if (strequal(pwd1->password, pwd2->password))
		{
			return True;
		}
	}
	if (pwd1->null_pwd && pwd2->null_pwd)
	{
		return True;
	}

	if (!pwd1->null_pwd && !pwd2->null_pwd &&
	    !pwd1->cleartext && !pwd2->cleartext)
	{
		dump_data_pw("pwd compare: nt#1\n", pwd1->smb_nt_pwd, 16);
		dump_data_pw("pwd compare: nt#2\n", pwd2->smb_nt_pwd, 16);

		dump_data_pw("pwd compare: lm#1\n", pwd1->smb_lm_pwd, 16);
		dump_data_pw("pwd compare: lm#2\n", pwd2->smb_lm_pwd, 16);

		if (memcmp(pwd1->smb_nt_pwd, pwd2->smb_nt_pwd, 16) == 0 &&
		    memcmp(pwd1->smb_lm_pwd, pwd2->smb_lm_pwd, 16) == 0)
		{
			return True;
		}
	}

	return False;
}

/****************************************************************************
reads a password
****************************************************************************/
void pwd_read(struct pwd_info *pwd, char *passwd_report, BOOL do_encrypt)
{
	/* grab a password */
	char *user_pass;

	pwd_init(pwd);

	user_pass = (char *)getpass(passwd_report);

	if (user_pass == NULL || user_pass[0] == 0)
	{
		pwd_set_nullpwd(pwd);
	}
	else if (do_encrypt)
	{
		pwd_make_lm_nt_16(pwd, user_pass);
	}
	else
	{
		pwd_set_cleartext(pwd, user_pass);
	}
}

/****************************************************************************
 stores a cleartext password
 ****************************************************************************/
void pwd_set_nullpwd(struct pwd_info *pwd)
{
	pwd_init(pwd);

	pwd->cleartext = False;
	pwd->null_pwd = True;
	pwd->crypted = False;
}

/****************************************************************************
 stores a cleartext password
 ****************************************************************************/
void pwd_set_cleartext(struct pwd_info *pwd, char *clr)
{
	pwd_init(pwd);
	fstrcpy(pwd->password, clr);
	pwd->cleartext = True;
	pwd->null_pwd = False;
	pwd->crypted = False;

}

/****************************************************************************
 gets a cleartext password
 ****************************************************************************/
void pwd_get_cleartext(struct pwd_info *pwd, char *clr)
{
	if (pwd->cleartext)
	{
		fstrcpy(clr, pwd->password);
	}
	else
	{
		clr[0] = 0;
	}
}

/****************************************************************************
 stores lm and nt hashed passwords
 ****************************************************************************/
void pwd_set_lm_nt_16(struct pwd_info *pwd,
		      const uchar lm_pwd[16], const uchar nt_pwd[16])
{
	pwd_init(pwd);

	Memcpy(pwd->smb_lm_pwd, lm_pwd, 16);
	Memcpy(pwd->smb_nt_pwd, nt_pwd, 16);

	pwd->null_pwd = False;
	pwd->cleartext = False;
	pwd->crypted = False;

}

/****************************************************************************
 gets lm and nt hashed passwords
 ****************************************************************************/
void pwd_get_lm_nt_16(const struct pwd_info *pwd, uchar lm_pwd[16],
		      uchar nt_pwd[16])
{
	Memcpy(lm_pwd, pwd->smb_lm_pwd, 16);
	Memcpy(nt_pwd, pwd->smb_nt_pwd, 16);
}

/****************************************************************************
 makes lm and nt hashed passwords
 ****************************************************************************/
void pwd_make_lm_nt_16(struct pwd_info *pwd, char *clr)
{
	pwd_init(pwd);

	nt_lm_owf_gen(clr, pwd->smb_nt_pwd, pwd->smb_lm_pwd);
	pwd->null_pwd = False;
	pwd->cleartext = False;
	pwd->crypted = False;

}

/****************************************************************************
 makes lm and nt OWF crypts
 ****************************************************************************/
void pwd_make_lm_nt_owf2(struct pwd_info *pwd, const uchar srv_key[8],
			 const char *user, const char *server,
			 const char *domain, uchar sess_key[16])
{
	uchar kr[16];

	DEBUG(10, ("pwd_make_lm_nt_owf2: user %s, srv %s, dom %s\n",
		   user, server, domain));


	SMBgenclientchals(pwd->lm_cli_chal,
			  pwd->nt_cli_chal,
			  &pwd->nt_cli_chal_len, server, domain);

	ntv2_owf_gen(pwd->smb_nt_pwd, user, domain, kr);

	/* lm # */
	SMBOWFencrypt_ntv2(kr,
			   srv_key, 8, pwd->lm_cli_chal, 8, pwd->smb_lm_owf);
	memcpy(&pwd->smb_lm_owf[16], pwd->lm_cli_chal, 8);

	/* nt # */
	SMBOWFencrypt_ntv2(kr,
			   srv_key, 8,
			   pwd->nt_cli_chal, pwd->nt_cli_chal_len,
			   pwd->smb_nt_owf);
	memcpy(&pwd->smb_nt_owf[16], pwd->nt_cli_chal, pwd->nt_cli_chal_len);
	pwd->nt_owf_len = pwd->nt_cli_chal_len + 16;

	SMBsesskeygen_ntv2(kr, pwd->smb_nt_owf, sess_key);

#if DEBUG_PASSWORD
#endif

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("server cryptkey: "));
	dump_data(100, srv_key, 8);

	DEBUG(100, ("client lmv2 cryptkey: "));
	dump_data(100, pwd->lm_cli_chal, 8);

	DEBUG(100, ("client ntv2 cryptkey: "));
	dump_data(100, pwd->nt_cli_chal, pwd->nt_cli_chal_len);

	DEBUG(100, ("ntv2_owf_passwd: "));
	dump_data(100, pwd->smb_nt_owf, pwd->nt_owf_len);
	DEBUG(100, ("nt_sess_pwd: "));
	dump_data(100, pwd->smb_nt_pwd, sizeof(pwd->smb_nt_pwd));

	DEBUG(100, ("lmv2_owf_passwd: "));
	dump_data(100, pwd->smb_lm_owf, sizeof(pwd->smb_lm_owf));
	DEBUG(100, ("lm_sess_pwd: "));
	dump_data(100, pwd->smb_lm_pwd, sizeof(pwd->smb_lm_pwd));

	DEBUG(100, ("session key:\n"));
	dump_data(100, sess_key, 16);
#endif
	pwd->crypted = True;

}

/****************************************************************************
 makes lm and nt OWF crypts
 ****************************************************************************/
void pwd_make_lm_nt_owf(struct pwd_info *pwd, uchar cryptkey[8],
			uchar sess_key[16])
{
	if (pwd->null_pwd)
	{
#ifdef DEBUG_PASSWORD
		DEBUG(100, ("pwd_make_lm_nt_owf: NULL password\n"));
#endif
		pwd->nt_owf_len = 0;
		return;
	}

	/* generate 24-byte hashes */
	SMBOWFencrypt(pwd->smb_lm_pwd, cryptkey, pwd->smb_lm_owf);
	SMBOWFencrypt(pwd->smb_nt_pwd, cryptkey, pwd->smb_nt_owf);
	pwd->nt_owf_len = 24;

	SMBsesskeygen_ntv1(pwd->smb_nt_pwd, pwd->smb_nt_owf, sess_key);

#ifdef DEBUG_PASSWORD
	DEBUG(100, ("client cryptkey: "));
	dump_data(100, cryptkey, 8);

	DEBUG(100, ("nt_owf_passwd: "));
	dump_data(100, pwd->smb_nt_owf, pwd->nt_owf_len);
	DEBUG(100, ("nt_sess_pwd: "));
	dump_data(100, pwd->smb_nt_pwd, sizeof(pwd->smb_nt_pwd));

	DEBUG(100, ("lm_owf_passwd: "));
	dump_data(100, pwd->smb_lm_owf, sizeof(pwd->smb_lm_owf));
	DEBUG(100, ("lm_sess_pwd: "));
	dump_data(100, pwd->smb_lm_pwd, sizeof(pwd->smb_lm_pwd));

	DEBUG(100, ("session key:\n"));
	dump_data(100, sess_key, 16);
#endif

	pwd->crypted = True;

}

/****************************************************************************
 gets lm and nt crypts
 ****************************************************************************/
void pwd_get_lm_nt_owf(struct pwd_info *pwd, uchar lm_owf[24],
		       uchar * nt_owf, size_t * nt_owf_len)
{
	if (pwd->null_pwd)
	{
#ifdef DEBUG_PASSWORD
		DEBUG(100, ("pwd_get_lm_nt_owf: NULL password\n"));
#endif
		if (nt_owf_len != NULL)
		{
			*nt_owf_len = 0;
		}
		return;
	}

	Memcpy(lm_owf, pwd->smb_lm_owf, 24);
	Memcpy(nt_owf, pwd->smb_nt_owf, pwd->nt_owf_len);

	if (nt_owf_len != NULL)
	{
		*nt_owf_len = pwd->nt_owf_len;
	}
}
