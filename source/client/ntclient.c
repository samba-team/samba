/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1997
   
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



#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;


#ifdef NTDOMAIN

/****************************************************************************
experimental nt login.
****************************************************************************/
BOOL do_nt_login_test(struct in_addr dest_ip, char *dest_host, char *myhostname,
				char *username, char *workgroup,
				char *mach_acct)
{
	/* client connection state */
	struct cli_state cli;

	uint16 fnum = 0xffff;

	/* session-chasing junk */
	uchar sess_key[8];
	DOM_CRED clnt_cred;
	DOM_CRED rtn_cred;

	/* user-identification info, for logins */
	DOM_ID_INFO_1 id1;
	LSA_USER_INFO user_info1;

	BOOL res = True;

	/* machine account passwords */
	pstring new_mach_pwd;

	/* initialisation */
	new_mach_pwd[0] = 0;
	bzero(&cli, sizeof(cli));

	DEBUG(5,("do_nt_login_test: %d\n", __LINE__));

	/* open NETLOGON session.  negotiate credentials */
	res = res ? do_nt_session_open(&cli, &fnum,
	                          dest_ip, dest_host, myhostname,
	                          mach_acct,
	                          username, workgroup,
	                          sess_key, &clnt_cred) : False;

	/* check whether the user wants to change their machine password */
	res = res ? trust_account_check(dest_ip, dest_host, myhostname, workgroup,
	                                mach_acct, new_mach_pwd) : False;

	/* change the machine password? */
	if (new_mach_pwd != NULL && new_mach_pwd[0] != 0)
	{
		res = res ? do_nt_srv_pwset(&cli, fnum,
		                   sess_key, &clnt_cred, &rtn_cred,
		                   new_mach_pwd,
		                   dest_host, mach_acct, myhostname) : False;
	}

	/* create the user-identification info */
	make_nt_login_info(&id1,
	                 sess_key,
	                 workgroup, myhostname,
	                 getuid(), username);

	/* do an NT login */
	res = res ? do_nt_login(&cli, fnum,
	                        sess_key, &clnt_cred, &rtn_cred,
	                        &id1, dest_host, myhostname, &user_info1) : False;

	/* ok!  you're logged in!  do anything you like, then... */
	   
	/* do an NT logout */
	res = res ? do_nt_logoff(&cli, fnum,
	                         sess_key, &clnt_cred, &rtn_cred,
	                         &id1, dest_host, myhostname) : False;

	/* close the session */
	do_nt_session_close(&cli, fnum);

	return res;
}

#endif /* NTDOMAIN */

