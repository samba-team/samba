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

extern struct user_creds *usr_creds;

extern FILE* out_hnd;


/****************************************************************************
experimental nt login.
****************************************************************************/
void cmd_netlogon_login_test(struct client_info *info, int argc, char *argv[])
{
#if 0
	extern BOOL global_machine_password_needs_changing;
#endif

	fstring nt_user_name;
	BOOL res = True;
	char *nt_password;
	uchar trust_passwd[16];
	uchar nt_pw[16];
	uchar lm_pw[16];
	fstring trust_acct;
	fstring domain;
	char *p;

	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(domain, usr_creds->ntc.domain);

	if (domain[0] == 0)
	{
		fstrcpy(domain, info->dom.level3_dom);
	}
#if 0
	/* trust account passwords */
	pstring new_mach_pwd;

	/* initialisation */
	new_mach_pwd[0] = 0;
#endif

	argc--;
	argv++;

	if (argc < 1)
	{
		fstrcpy(nt_user_name, usr_creds->ntc.user_name);
		if (nt_user_name[0] == 0)
		{
			report(out_hnd,"ntlogin: must specify username with anonymous connection\n");
			report(out_hnd,"ntlogin [[DOMAIN\\]user] [password]\n");
			return;
		}
	}
	else
	{
		fstrcpy(nt_user_name, argv[0]);
	}

	p = strchr(nt_user_name, '\\');
	if (p != NULL)
	{
		fstrcpy(domain, nt_user_name);
		p = strchr(domain, '\\');
		if (p != NULL)
		{
			*p = 0;
			fstrcpy(nt_user_name, p+1);
		}
		
	}

	if (domain[0] == 0)
	{
		report(out_hnd,"no domain specified.\n");
	}

	argc--;
	argv++;

	if (argc > 0)
	{
		nt_password = argv[0];
	}
	else
	{
		nt_password = getpass("Enter NT Login password:");
	}

	nt_lm_owf_gen(nt_password, nt_pw, lm_pw);

	DEBUG(5,("do_nt_login_test: username %s from: %s\n",
	            nt_user_name, info->myhostname));

	fstrcpy(trust_acct, info->myhostname);
	fstrcat(trust_acct, "$");

	res = res ? trust_get_passwd(trust_passwd, domain, info->myhostname) : False;

#if 0
	/* check whether the user wants to change their trust password */
	res = res ? trust_account_check(info->dest_ip, info->dest_host,
	                                info->myhostname, usr_creds->ntc.domain,
	                                info->mach_acct, new_mach_pwd) : False;
#endif

	res = res ? cli_nt_setup_creds(srv_name, info->myhostname,
	                               trust_acct, 
	                               trust_passwd, SEC_CHAN_WKSTA) == 0x0 : False;

#if 0
	/* change the trust password? */
	if (global_machine_password_needs_changing)
	{
		uchar new_trust_passwd[16];
		generate_random_buffer(new_trust_passwd, 16, True);
		res = res ? cli_nt_srv_pwset(srv_name, info->myhostname, new_trust_passwd, SEC_CHAN_WKSTA) : False;

		if (res)
		{
			global_machine_password_needs_changing = !set_trust_account_password(new_trust_passwd);
		}

		memset(new_trust_passwd, 0, 16);
	}
#endif

	memset(trust_passwd, 0, 16);

	/* do an NT login */
	res = res ? (cli_nt_login_interactive(srv_name, info->myhostname,
	                 usr_creds->ntc.domain, nt_user_name,
	                 getuid(), lm_pw, nt_pw,
	                 &info->dom.ctr, &info->dom.user_info3) == 0x0) : False;


#if 0
	/* ok!  you're logged in!  do anything you like, then... */

	/* do an NT logout */
	res = res ? cli_nt_logoff(srv_name, info->myhostname, &info->dom.ctr) : False;
#endif

	report(out_hnd,"cmd_nt_login: login (%s) test succeeded: %s\n",
		nt_user_name, BOOLSTR(res));
}

/****************************************************************************
experimental nt login.
****************************************************************************/
void cmd_netlogon_domain_test(struct client_info *info, int argc, char *argv[])
{
	char *nt_trust_dom;
	BOOL res = True;
	uchar trust_passwd[16];
	fstring inter_dom_acct;

	fstring srv_name;
	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	if (argc < 2)
	{
		report(out_hnd,"domtest: must specify domain name\n");
		return;
	}

	nt_trust_dom = argv[1];

	DEBUG(5,("do_nt_login_test: domain %s\n", nt_trust_dom));

	fstrcpy(inter_dom_acct, nt_trust_dom);
	fstrcat(inter_dom_acct, "$");

	res = res ? trust_get_passwd(trust_passwd, usr_creds->ntc.domain, nt_trust_dom) : False;

	res = res ? cli_nt_setup_creds(srv_name,
	                               info->myhostname, inter_dom_acct,
	                               trust_passwd, 
	                               SEC_CHAN_DOMAIN) == 0x0 : False;

	memset(trust_passwd, 0, 16);

	report(out_hnd,"cmd_nt_login: credentials (%s) test succeeded: %s\n",
		nt_trust_dom, BOOLSTR(res));
}

/****************************************************************************
experimental SAM synchronisation.
****************************************************************************/
void cmd_sam_sync(struct client_info *info, int argc, char *argv[])
{
	SAM_DELTA_HDR hdr_deltas[MAX_SAM_DELTAS];
	SAM_DELTA_CTR deltas[MAX_SAM_DELTAS];
	uint32 num;
	uchar trust_passwd[16];
	fstring srv_name;
	fstring trust_acct;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(trust_acct, info->myhostname);
	fstrcat(trust_acct, "$");

	if (!trust_get_passwd(trust_passwd, usr_creds->ntc.domain, info->myhostname))
	{
		report(out_hnd, "cmd_sam_sync: no trust account password\n");
		return;
	}

	if (net_sam_sync(srv_name, info->myhostname,
		trust_acct, trust_passwd,
	    hdr_deltas, deltas, &num))
	{
		display_sam_sync(out_hnd, ACTION_HEADER   , hdr_deltas, deltas, num);
		display_sam_sync(out_hnd, ACTION_ENUMERATE, hdr_deltas, deltas, num);
		display_sam_sync(out_hnd, ACTION_FOOTER   , hdr_deltas, deltas, num);
	}
}
