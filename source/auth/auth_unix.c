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

/****************************************************************************
update the encrypted smbpasswd file from the plaintext username and password

this ugly hack needs to die, but not quite yet...
*****************************************************************************/
static BOOL update_smbpassword_file(char *user, char *password)
{
	SAM_ACCOUNT 	*sampass = NULL;
	BOOL            ret;
	
	pdb_init_sam(&sampass);
	
	become_root();
	ret = pdb_getsampwnam(sampass, user);
	unbecome_root();

	if(ret == False) {
		DEBUG(0,("pdb_getsampwnam returned NULL\n"));
		pdb_free_sam(&sampass);
		return False;
	}

	/*
	 * Remove the account disabled flag - we are updating the
	 * users password from a login.
	 */
	if (!pdb_set_acct_ctrl(sampass, pdb_get_acct_ctrl(sampass) & ~ACB_DISABLED)) {
		pdb_free_sam(&sampass);
		return False;
	}

	if (!pdb_set_plaintext_passwd (sampass, password)) {
		pdb_free_sam(&sampass);
		return False;
	}

	/* Now write it into the file. */
	become_root();

	/* Here, the override flag is True, because we want to ignore the
           XXXXXXX'd out password */
	ret = pdb_update_sam_account (sampass, True);

	unbecome_root();

	if (ret) {
		DEBUG(3,("pdb_update_sam_account returned %d\n",ret));
	}

	memset(password, '\0', strlen(password));

	pdb_free_sam(&sampass);
	return ret;
}


/****************************************************************************
check if a username/password is OK assuming the password 
in PLAIN TEXT
****************************************************************************/

NTSTATUS check_unix_security(void *my_private_data,
			     const auth_usersupplied_info *user_info, 
			     const auth_authsupplied_info *auth_info,
			     auth_serversupplied_info **server_info)
{
	NTSTATUS nt_status;
	struct passwd *pass = NULL;

	become_root();
	pass = Get_Pwnam(user_info->internal_username.str);

	nt_status = pass_check(pass,
				pass ? pass->pw_name : user_info->internal_username.str, 
				(char *)user_info->plaintext_password.data,
				user_info->plaintext_password.length-1,
				lp_update_encrypted() ? 
				update_smbpassword_file : NULL,
				True);
	
	unbecome_root();

	if NT_STATUS_IS_OK(nt_status) {
		if (pass) {
			make_server_info_pw(server_info, pass);
		} else {
			/* we need to do somthing more useful here */
			nt_status = NT_STATUS_NO_SUCH_USER;
		}
	}

	return nt_status;
}

BOOL auth_init_unix(auth_methods **auth_method) 
{
	if (!make_auth_methods(auth_method)) {
		return False;
	}
	(*auth_method)->auth = check_unix_security;
	return True;
}
