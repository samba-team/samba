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

#define DEBUG_TESTING

extern struct cli_state *smb_cli;

extern FILE* out_hnd;


/****************************************************************************
experimental nt login.
****************************************************************************/
void cmd_netlogon_login_test(struct client_info *info)
{
	BOOL res = True;

	/* machine account passwords */
	pstring new_mach_pwd;

	/* initialisation */
	new_mach_pwd[0] = 0;

	DEBUG(5,("do_nt_login_test: %d\n", __LINE__));

#if 0
	/* check whether the user wants to change their machine password */
	res = res ? trust_account_check(info->dest_ip, info->dest_host,
	                                info->myhostname, smb_cli->domain,
	                                info->mach_acct, new_mach_pwd) : False;
#endif
	/* open NETLOGON session.  negotiate credentials */
	res = res ? do_nt_session_open(smb_cli, 
	                          info->dest_host, info->myhostname,
	                          info->mach_acct,
	                          smb_cli->user_name, smb_cli->domain,
	                          info->dom.sess_key, &info->dom.clnt_cred) : False;

	/* change the machine password? */
	if (new_mach_pwd != NULL && new_mach_pwd[0] != 0)
	{
		res = res ? do_nt_srv_pwset(smb_cli, info->dom.lsarpc_fnum,
		                   info->dom.sess_key, &info->dom.clnt_cred, &info->dom.rtn_cred,
		                   new_mach_pwd,
		                   info->dest_host, info->mach_acct, info->myhostname) : False;
	}

	/* create the user-identification info */
	make_nt_login_interactive(&info->dom.ctr,
	                 info->dom.sess_key,
	                 smb_cli->domain, info->myhostname,
	                 getuid(), smb_cli->user_name);

	/* do an NT login */
	res = res ? do_nt_login(smb_cli, info->dom.lsarpc_fnum,
	                        info->dom.sess_key, &info->dom.clnt_cred, &info->dom.rtn_cred,
	                        &info->dom.ctr, info->dest_host, info->myhostname, &info->dom.user_info3) : False;

	/* ok!  you're logged in!  do anything you like, then... */
	   
	/* do an NT logout */
	res = res ? do_nt_logoff(smb_cli, info->dom.lsarpc_fnum,
	                         info->dom.sess_key, &info->dom.clnt_cred, &info->dom.rtn_cred,
	                         &info->dom.ctr, info->dest_host, info->myhostname) : False;

	/* close the session */
	cli_nt_session_close(smb_cli);

	if (res)
	{
		DEBUG(5,("cmd_nt_login: login test succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_nt_login: login test failed\n"));
	}
}

