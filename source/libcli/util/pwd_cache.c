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
	pstring dos_passwd;

	pwd_init(pwd);

	push_ascii_pstring(dos_passwd, clr);

	nt_lm_owf_gen(dos_passwd, pwd->smb_nt_pwd, pwd->smb_lm_pwd);
	pwd->null_pwd  = False;
	pwd->cleartext = False;
	pwd->crypted = False;
}

/****************************************************************************
 Stores a cleartext password.
****************************************************************************/

void pwd_set_cleartext(struct pwd_info *pwd, const char *clr)
{
	pwd_init(pwd);
	push_ascii_fstring(pwd->password, clr);
	pwd->cleartext = True;
	pwd->null_pwd  = False;
	pwd->crypted   = False;
	pwd_make_lm_nt_16(pwd, clr);
}


