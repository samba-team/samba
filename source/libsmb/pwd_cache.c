/* 
   Unix SMB/CIFS implementation.
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

static void pwd_init(struct pwd_info *pwd)
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
 Makes lm and nt hashed passwords.
****************************************************************************/

static void pwd_make_lm_nt_16(struct pwd_info *pwd, const char *clr)
{
	pwd_init(pwd);

	if (!clr) {
		ZERO_STRUCT(pwd->smb_nt_pwd);
		ZERO_STRUCT(pwd->smb_lm_pwd);
		pwd->null_pwd  = True;
	} else {
		nt_lm_owf_gen(clr, pwd->smb_nt_pwd, pwd->smb_lm_pwd);
		pwd->null_pwd  = False;
	}
	pwd->crypted = False;
}

/****************************************************************************
 Stores a cleartext password.
****************************************************************************/

void pwd_set_cleartext(struct pwd_info *pwd, const char *clr)
{
	pwd_make_lm_nt_16(pwd, clr);
	fstrcpy(pwd->password, clr);
	pwd->cleartext = True;
}

/****************************************************************************
 Gets a cleartext password.
****************************************************************************/

void pwd_get_cleartext(struct pwd_info *pwd, fstring clr)
{
	if (pwd->cleartext)
		fstrcpy(clr, pwd->password);
	else
		clr[0] = 0;

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
