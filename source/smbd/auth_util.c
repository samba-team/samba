/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Authentication utility functions
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Andrew Bartlett 2001

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

/* Data to do lanman1/2 password challenge. */
static unsigned char saved_challenge[8];
static BOOL challenge_sent=False;

/*******************************************************************
Get the next challenge value - no repeats.
********************************************************************/
void generate_next_challenge(char *challenge)
{
        unsigned char buf[8];

        generate_random_buffer(buf,8,False);
	memcpy(saved_challenge, buf, 8);
	memcpy(challenge,buf,8);
	challenge_sent = True;
}

/*******************************************************************
set the last challenge sent, usually from a password server
********************************************************************/
BOOL set_challenge(unsigned char *challenge)
{
	memcpy(saved_challenge,challenge,8);
	challenge_sent = True;
	return(True);
}

/*******************************************************************
get the last challenge sent
********************************************************************/
BOOL last_challenge(unsigned char *challenge)
{
	if (!challenge_sent) return(False);
	memcpy(challenge,saved_challenge,8);
	return(True);
}


/****************************************************************************
 Create a UNIX user on demand.
****************************************************************************/

static int smb_create_user(char *unix_user, char *homedir)
{
	pstring add_script;
	int ret;

	pstrcpy(add_script, lp_adduser_script());
	if (! *add_script) return -1;
	all_string_sub(add_script, "%u", unix_user, sizeof(pstring));
	if (homedir)
		all_string_sub(add_script, "%H", homedir, sizeof(pstring));
	ret = smbrun(add_script,NULL);
	DEBUG(3,("smb_create_user: Running the command `%s' gave %d\n",add_script,ret));
	return ret;
}

/****************************************************************************
 Delete a UNIX user on demand.
****************************************************************************/

static int smb_delete_user(char *unix_user)
{
	pstring del_script;
	int ret;

	pstrcpy(del_script, lp_deluser_script());
	if (! *del_script) return -1;
	all_string_sub(del_script, "%u", unix_user, sizeof(pstring));
	ret = smbrun(del_script,NULL);
	DEBUG(3,("smb_delete_user: Running the command `%s' gave %d\n",del_script,ret));
	return ret;
}

/****************************************************************************
 Add and Delete UNIX users on demand, based on NTSTATUS codes.
****************************************************************************/

void smb_user_control(char *unix_user, NTSTATUS nt_status) 
{
	struct passwd *pwd=NULL;

	if (NT_STATUS_IS_OK(nt_status)) {
		/*
		 * User validated ok against Domain controller.
		 * If the admin wants us to try and create a UNIX
		 * user on the fly, do so.
		 */
		if(lp_adduser_script() && !(pwd = smb_getpwnam(unix_user,True)))
			smb_create_user(unix_user, NULL);

		if(lp_adduser_script() && pwd) {
			SMB_STRUCT_STAT st;

			/*
			 * Also call smb_create_user if the users home directory
			 * doesn't exist. Used with winbindd to allow the script to
			 * create the home directory for a user mapped with winbindd.
			 */

			if (pwd->pw_dir && (sys_stat(pwd->pw_dir, &st) == -1) && (errno == ENOENT))
				smb_create_user(unix_user, pwd->pw_dir);
		}

	} else if (NT_STATUS_V(nt_status) == NT_STATUS_V(NT_STATUS_NO_SUCH_USER)) {
		/*
		 * User failed to validate ok against Domain controller.
		 * If the failure was "user doesn't exist" and admin 
		 * wants us to try and delete that UNIX user on the fly,
		 * do so.
		 */
		if(lp_deluser_script() && smb_getpwnam(unix_user,True))
			smb_delete_user(unix_user);
	}
}
