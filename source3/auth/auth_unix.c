/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   Password and authentication handling
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
update the encrypted smbpasswd file from the plaintext username and password

this ugly hack needs to die, but not quite yet...
*****************************************************************************/
static BOOL update_smbpassword_file(char *user, char *password)
{
	SAM_ACCOUNT 	*sampass = NULL;
	BOOL 		ret;
	
	pdb_init_sam(&sampass);
	
	become_root();
	ret = pdb_getsampwnam(sampass, user);
	unbecome_root();

	if(ret == False) {
		DEBUG(0,("pdb_getsampwnam returned NULL\n"));
		pdb_free_sam(sampass);
		return False;
	}

	/*
	 * Remove the account disabled flag - we are updating the
	 * users password from a login.
	 */
	pdb_set_acct_ctrl(sampass, pdb_get_acct_ctrl(sampass) & ~ACB_DISABLED);

	/* Here, the flag is one, because we want to ignore the
           XXXXXXX'd out password */
	ret = change_oem_password( sampass, password, True);
	if (ret == False) {
		DEBUG(3,("change_oem_password returned False\n"));
	}

	pdb_free_sam(sampass);
	return ret;
}


/****************************************************************************
check if a username/password is OK assuming the password 
in PLAIN TEXT
****************************************************************************/

uint32 check_unix_security(const auth_usersupplied_info *user_info, auth_serversupplied_info *server_info)
{
	uint32 nt_status;
	
	become_root();
	nt_status = (pass_check(user_info->smb_username.str, user_info->plaintext_password.str,
				user_info->plaintext_password.len,
				lp_update_encrypted() ? update_smbpassword_file : NULL) 
		     ? NT_STATUS_OK : NT_STATUS_LOGON_FAILURE);
	unbecome_root();

	return nt_status;
}


