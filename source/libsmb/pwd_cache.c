/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Password cacheing.  obfuscation is planned
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

/****************************************************************************
 Initialises a password structure.
****************************************************************************/

void pwd_init(struct pwd_info *pwd)
{
	memset((char *)pwd->password  , '\0', sizeof(pwd->password  ));
	memset((char *)pwd->smb_lm_pwd, '\0', sizeof(pwd->smb_lm_pwd));
	memset((char *)pwd->smb_nt_pwd, '\0', sizeof(pwd->smb_nt_pwd));
	memset((char *)pwd->smb_lm_owf, '\0', sizeof(pwd->smb_lm_owf));
	memset((char *)pwd->smb_nt_owf, '\0', sizeof(pwd->smb_nt_owf));

	pwd->null_pwd  = True; /* safest option... */
	pwd->cleartext = False;
	pwd->crypted   = False;
}

/****************************************************************************
 Returns NULL password flag.
****************************************************************************/

BOOL pwd_is_nullpwd(const struct pwd_info *pwd)
{
        return pwd->null_pwd;
}

/****************************************************************************
 Compares two passwords.  hmm, not as trivial as expected.  hmm.
****************************************************************************/

BOOL pwd_compare(struct pwd_info *pwd1, struct pwd_info *pwd2)
{
	if (pwd1->cleartext && pwd2->cleartext) {
		if (strequal(pwd1->password, pwd2->password))
			return True;
	}
	if (pwd1->null_pwd && pwd2->null_pwd)
		return True;

	if (!pwd1->null_pwd  && !pwd2->null_pwd &&
	    !pwd1->cleartext && !pwd2->cleartext) {
#ifdef DEBUG_PASSWORD
		DEBUG(100,("pwd compare: nt#\n"));
		dump_data(100, pwd1->smb_nt_pwd, 16);
		dump_data(100, pwd2->smb_nt_pwd, 16);
#endif
		if (memcmp(pwd1->smb_nt_pwd, pwd2->smb_nt_pwd, 16) == 0)
			return True;
#ifdef DEBUG_PASSWORD
		DEBUG(100,("pwd compare: lm#\n"));
		dump_data(100, pwd1->smb_lm_pwd, 16);
		dump_data(100, pwd2->smb_lm_pwd, 16);
#endif
		if (memcmp(pwd1->smb_lm_pwd, pwd2->smb_lm_pwd, 16) == 0)
			return True;
	}
	return False;
}

/****************************************************************************
 Reads a password.
****************************************************************************/

void pwd_read(struct pwd_info *pwd, char *passwd_report, BOOL do_encrypt)
{
	/* grab a password */
	char *user_pass;

	pwd_init(pwd);

	user_pass = (char*)getpass(passwd_report);

	/*
	 * Do not assume that an empty string is a NULL password.
	 * If you do this will break the session key generation for
	 * and account with an emtpy password.  If you wish to use
	 * a NULL password, use the -N option to smbclient and rpcclient
	 * --jerry
	 */
#if 0
	if (user_pass == NULL || user_pass[0] == 0)
		pwd_set_nullpwd(pwd);
	else if (do_encrypt)
#endif
	if (do_encrypt)
		pwd_make_lm_nt_16(pwd, user_pass);
	else
		pwd_set_cleartext(pwd, user_pass);
}

/****************************************************************************
 Stores a cleartext password.
****************************************************************************/

void pwd_set_nullpwd(struct pwd_info *pwd)
{
	pwd_init(pwd);

	pwd->cleartext = False;
	pwd->null_pwd  = True;
	pwd->crypted   = False;
}

/****************************************************************************
 Stores a cleartext password.
 ****************************************************************************/

void pwd_set_cleartext(struct pwd_info *pwd, const char *clr)
{
	pwd_init(pwd);
	fstrcpy(pwd->password, clr);
	unix_to_dos(pwd->password);
	pwd->cleartext = True;
	pwd->null_pwd  = False;
	pwd->crypted   = False;
}

/****************************************************************************
 Gets a cleartext password.
****************************************************************************/

void pwd_get_cleartext(struct pwd_info *pwd, char *clr)
{
	if (pwd->cleartext) {
		fstrcpy(clr, pwd->password);
		dos_to_unix(clr);
	} else {
		clr[0] = 0;
	}
}

/****************************************************************************
 Stores lm and nt hashed passwords.
****************************************************************************/

void pwd_set_lm_nt_16(struct pwd_info *pwd, uchar lm_pwd[16], uchar nt_pwd[16])
{
	pwd_init(pwd);

	if (lm_pwd)
		memcpy(pwd->smb_lm_pwd, lm_pwd, 16);
	else
		memset((char *)pwd->smb_lm_pwd, '\0', 16);

	if (nt_pwd)
		memcpy(pwd->smb_nt_pwd, nt_pwd, 16);
	else
		memset((char *)pwd->smb_nt_pwd, '\0', 16);

	pwd->null_pwd  = False;
	pwd->cleartext = False;
	pwd->crypted   = False;
}

/****************************************************************************
 Gets lm and nt hashed passwords.
****************************************************************************/

void pwd_get_lm_nt_16(struct pwd_info *pwd, uchar lm_pwd[16], uchar nt_pwd[16])
{
	if (lm_pwd != NULL)
		memcpy(lm_pwd, pwd->smb_lm_pwd, 16);
	if (nt_pwd != NULL)
		memcpy(nt_pwd, pwd->smb_nt_pwd, 16);
}

/****************************************************************************
 Makes lm and nt hashed passwords.
****************************************************************************/

void pwd_make_lm_nt_16(struct pwd_info *pwd, char *clr)
{
	pstring dos_passwd;

	pwd_init(pwd);

	pstrcpy(dos_passwd, clr);
	unix_to_dos(dos_passwd);

	nt_lm_owf_gen(dos_passwd, pwd->smb_nt_pwd, pwd->smb_lm_pwd);
	pwd->null_pwd  = False;
	pwd->cleartext = False;
	pwd->crypted = False;
}

/****************************************************************************
 Makes lm and nt OWF crypts.
****************************************************************************/

void pwd_make_lm_nt_owf(struct pwd_info *pwd, uchar cryptkey[8])
{

#ifdef DEBUG_PASSWORD
	DEBUG(100,("client cryptkey: "));
	dump_data(100, (char *)cryptkey, 8);
#endif

	SMBOWFencrypt(pwd->smb_nt_pwd, cryptkey, pwd->smb_nt_owf);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("nt_owf_passwd: "));
	dump_data(100, (char *)pwd->smb_nt_owf, sizeof(pwd->smb_nt_owf));
	DEBUG(100,("nt_sess_pwd: "));
	dump_data(100, (char *)pwd->smb_nt_pwd, sizeof(pwd->smb_nt_pwd));
#endif

	SMBOWFencrypt(pwd->smb_lm_pwd, cryptkey, pwd->smb_lm_owf);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("lm_owf_passwd: "));
	dump_data(100, (char *)pwd->smb_lm_owf, sizeof(pwd->smb_lm_owf));
	DEBUG(100,("lm_sess_pwd: "));
	dump_data(100, (char *)pwd->smb_lm_pwd, sizeof(pwd->smb_lm_pwd));
#endif

	pwd->crypted = True;
}

/****************************************************************************
 Gets lm and nt crypts.
****************************************************************************/

void pwd_get_lm_nt_owf(struct pwd_info *pwd, uchar lm_owf[24], uchar nt_owf[24])
{
	if (lm_owf != NULL)
		memcpy(lm_owf, pwd->smb_lm_owf, 24);
	if (nt_owf != NULL)
		memcpy(nt_owf, pwd->smb_nt_owf, 24);
}
