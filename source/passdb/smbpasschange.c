/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   change a password in a local smbpasswd file
   Copyright (C) Andrew Tridgell 1998
   
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


/*************************************************************
add a new user to the local smbpasswd file
*************************************************************/
static BOOL add_new_user(char *user_name, uid_t uid, BOOL trust_account, 
			 BOOL disable_user, BOOL set_no_password,
			 uchar *new_p16, uchar *new_nt_p16)
{
	struct smb_passwd new_smb_pwent;

	pwdb_init_smb(&new_smb_pwent);

	/* Create a new smb passwd entry and set it to the given password. */
	new_smb_pwent.unix_uid = uid;
	new_smb_pwent.nt_name = user_name; 
	new_smb_pwent.smb_passwd = NULL;
	new_smb_pwent.smb_nt_passwd = NULL;
	new_smb_pwent.acct_ctrl = (trust_account ? ACB_WSTRUST : ACB_NORMAL);
	
	if(disable_user) {
		new_smb_pwent.acct_ctrl |= ACB_DISABLED;
	} else if (set_no_password) {
		new_smb_pwent.acct_ctrl |= ACB_PWNOTREQ;
	} else {
		new_smb_pwent.smb_passwd = new_p16;
		new_smb_pwent.smb_nt_passwd = new_nt_p16;
	}
	
	return add_smbpwd_entry(&new_smb_pwent);
}


/*************************************************************
change a password entry in the local smbpasswd file
*************************************************************/
BOOL local_password_change(char *user_name, BOOL trust_account, BOOL add_user,
			   BOOL enable_user, BOOL disable_user, BOOL set_no_password,
			   char *new_passwd, 
			   char *err_str, size_t err_str_len,
			   char *msg_str, size_t msg_str_len)
{
	struct passwd  *pwd;
	struct smb_passwd *smb_pwent;
	uchar           new_p16[16];
	uchar           new_nt_p16[16];
	fstring unix_name;
	uid_t unix_uid;

	*err_str = '\0';
	*msg_str = '\0';

	pwd = getpwnam(user_name);
	
	/*
	 * Check for a machine account.
	 */
	
	if (pwd == NULL)
	{
		if (trust_account)
		{
			slprintf(err_str, err_str_len - 1, "User %s does not \
exist in system password file (usually /etc/passwd).  \
Cannot add machine account without a valid system user.\n", user_name);
		}
		else
		{
			slprintf(err_str, err_str_len - 1, "User %s does not \
exist in system password file (usually /etc/passwd).\n", user_name);
		}
		return False;
	}

	unix_uid = pwd->pw_uid;
	fstrcpy(unix_name, pwd->pw_name);

	/* Calculate the MD4 hash (NT compatible) of the new password. */
	nt_lm_owf_gen(new_passwd, new_nt_p16, new_p16);

	/* Get the smb passwd entry for this user */
	smb_pwent = getsmbpwnam(user_name);
	if (smb_pwent == NULL) {
		if(add_user == False) {
			slprintf(err_str, err_str_len-1,
				"Failed to find entry for user %s.\n", unix_name);
			return False;
		}

		if (add_new_user(user_name, unix_uid, trust_account, disable_user,
				 set_no_password, new_p16, new_nt_p16)) {
			slprintf(msg_str, msg_str_len-1, "Added user %s.\n", user_name);
			return True;
		} else {
			slprintf(err_str, err_str_len-1, "Failed to add entry for user %s.\n", user_name);
			return False;
		}
	} else {
		/* the entry already existed */
		add_user = False;
	}

	/*
	 * We are root - just write the new password
	 * and the valid last change time.
	 */

	if(disable_user) {
		smb_pwent->acct_ctrl |= ACB_DISABLED;
	} else if (enable_user) {
		if(smb_pwent->smb_passwd == NULL) {
			smb_pwent->smb_passwd = new_p16;
			smb_pwent->smb_nt_passwd = new_nt_p16;
		}
		smb_pwent->acct_ctrl &= ~ACB_DISABLED;
	} else if (set_no_password) {
		smb_pwent->acct_ctrl |= ACB_PWNOTREQ;
		/* This is needed to preserve ACB_PWNOTREQ in mod_smbfilepwd_entry */
		smb_pwent->smb_passwd = NULL;
		smb_pwent->smb_nt_passwd = NULL;
	} else {
		smb_pwent->acct_ctrl &= ~ACB_PWNOTREQ;
		smb_pwent->smb_passwd = new_p16;
		smb_pwent->smb_nt_passwd = new_nt_p16;
	}
	
	if(mod_smbpwd_entry(smb_pwent,True) == False) {
		slprintf(err_str, err_str_len-1, "Failed to modify entry for user %s.\n",
			unix_name);
		return False;
	}

	return True;
}
