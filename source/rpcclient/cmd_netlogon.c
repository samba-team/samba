/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell              1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   
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
#include "rpc_client.h"
#include "rpcclient.h"
#include "nterr.h"

extern int DEBUGLEVEL;

#define DEBUG_TESTING

extern struct user_creds *usr_creds;

extern FILE *out_hnd;

#if 0
/****************************************************************************
experimental nt login trust account change.
****************************************************************************/
void cmd_netlogon_pwset(struct client_info *info, int argc, char *argv[])
{
	fstring domain;
	fstring acct_name;
	fstring name;
	fstring sid;
	DOM_SID sid1;
	uint32 user_rid;
	int opt;
	char *password = NULL;
	pstring upwb;
	int plen = 0;
	int len = 0;
	UNISTR2 upw;
	uchar ntpw[16];
	STRING2 secret;

	BOOL res = True;
	POLICY_HND lsa_pol;

	POLICY_HND pol_sec;
	BOOL res1;
	uint32 res2;

	uchar old_trust_passwd[16];
	char *p;
	uint16 validation_level;

	fstring wks_name;
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(wks_name, "\\\\");
	if (strequal(srv_name, "\\\\.") &&
	    strequal(info->dest_host, info->myhostname))
	{
		fstrcat(wks_name, ".");
	}
	else
	{
		fstrcat(wks_name, info->dest_host);
	}
	strupper(wks_name);

	domain[0] = 0;
	if (usr_creds != NULL)
	{
		fstrcpy(domain, usr_creds->ntc.domain);
	}

	if (domain[0] == 0)
	{
		fstrcpy(domain, info->dom.level3_dom);
	}

	argc--;
	argv++;

	if (domain[0] == 0)
	{
		report(out_hnd, "no domain specified.\n");
	}

	DEBUG(5, ("do_nt_login_test: username %s from: %s\n",
		  nt_user_name, info->myhostname));

	safe_strcpy(acct_name, argv[0], sizeof(acct_name));
	len = strlen(acct_name) - 1;
	if (acct_name[len] == '$')
	{
		safe_strcpy(name, argv[0], sizeof(name));
		name[len] = 0;
	}

	res = res ? cli_nt_setup_creds(srv_name, domain, info->myhostname,
				       trust_acct,
				       old_trust_passwd,
				       SEC_CHAN_WKSTA,
				       &validation_level) == 0x0 : False;

	/*
	 * generate new random password.  unicode string is stored
	 * in secret $MACHINE.ACC; nt owf is sent in net_srv_pwset.
	 */

	upw.uni_str_len = 0xc;
	upw.uni_max_len = 0xc;
	password = (char *)upw.buffer;
	plen = upw.uni_str_len * 2;
	generate_random_buffer(password, plen, True);

	nt_owf_genW(&upw, ntpw);

	/*
	 * ok.  this looks really weird, but if you don't open
	 * the connection to the workstation first, then the
	 * set trust account on the SAM database may get the
	 * local copy-of trust account out-of-sync with the
	 * remote one, and you're stuffed!
	 */
	res = lsa_open_policy(wks_name, &lsa_pol, True, 0x02000000);

	if (!res)
	{
		report(out_hnd, "Connection to %s FAILED\n", wks_name);
		report(out_hnd, "(Do a \"use \\\\%s -U localadmin\")\n",
		       wks_name);

		return;
	}
	res1 = lsa_open_secret(&lsa_pol, "$MACHINE.ACC", 0x020003, &pol_sec);

	if (!res1)
	{
		lsa_close(&lsa_pol);
		report(out_hnd, "Open Secret failed\n");
		return;
	}

	if (!lsa_query_secret(&pol_sec, &secret, NULL) ||
	    !secret_to_nt_owf(&old_trust_passwd, &secret))
	{
		lsa_close(&lsa_pol);
		lsa_close(&pol_sec);
		report(out_hnd,
		       "Query local Trust Account password: Failed\n");
		return;
	}

	if (net_srv_pwset(srv_name, &sid1,
			  acct_name,, password, plen,
			  &user_rid) != NT_STATUS_NOPROBLEMO)
	{
		lsa_close(&lsa_pol);
		lsa_close(&pol_sec);
		report(out_hnd,
		       "Set remote Trust Account password: Failed\n");
		return;
	}

	report(out_hnd, "Set remote Trust Account password: OK\n");

	strupper(domain);
	strupper(name);

	/* valid pol_sec on $MACHINE.ACC, set trust passwd */
	secret_store_data(&secret, password, plen);

	res2 = lsa_set_secret(&pol_sec, &secret);

	if (res2 == NT_STATUS_NOPROBLEMO)
	{
		report(out_hnd, "Set $MACHINE.ACC: OK\n");
	}
	else
	{
		report(out_hnd, "Set $MACHINE.ACC: FAILED\n");
	}

	res1 = res1 ? lsa_close(&pol_sec) : False;
	res = res ? lsa_close(&lsa_pol) : False;

	memset(&upw, 0, sizeof(upw));
	memset(ntpw, 0, sizeof(ntpw));


	report(out_hnd, "cmd_nt_login: login (%s) test succeeded: %s\n",
	       nt_user_name, BOOLSTR(res));
}

#endif


/****************************************************************************
experimental nt trusted domain list.
****************************************************************************/
void cmd_netlogon_dom_list(struct client_info *info, int argc, char *argv[])
{
	uint32 status;
	fstring domains;
	BUFFER2 buf;

	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	status = cli_net_trust_dom_list(srv_name, &buf);
	if (status == 0x0)
	{
		buffer2_to_multistr(domains, &buf, sizeof(domains));
	}
	else
	{
		ZERO_STRUCT(domains);
	}

	report(out_hnd, "cmd_nt_login: login (%s) test succeeded: %s\n",
	       domains, BOOLSTR(status == 0x0));
}

/****************************************************************************
experimental nt login.
****************************************************************************/
void cmd_netlogon_login_test(struct client_info *info, int argc, char *argv[])
{
	fstring nt_user_name;
	BOOL res = True;
	char *nt_password;
	uchar trust_passwd[16];
	uchar nt_pw[16];
	uchar lm_pw[16];
	fstring trust_acct;
	fstring domain;
	char *p;
	uint16 validation_level;

	fstring wks_name;
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(wks_name, "\\\\");
	if (strequal(srv_name, "\\\\.") &&
	    strequal(info->dest_host, info->myhostname))
	{
		fstrcat(wks_name, ".");
	}
	else
	{
		fstrcat(wks_name, info->dest_host);
	}
	strupper(wks_name);

	domain[0] = 0;
	if (usr_creds != NULL)
	{
		fstrcpy(domain, usr_creds->ntc.domain);
	}

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
		nt_user_name[0] = 0;
		if (usr_creds != NULL)
		{
			fstrcpy(nt_user_name, usr_creds->ntc.user_name);
		}
		if (nt_user_name[0] == 0)
		{
			report(out_hnd,
			       "ntlogin: must specify username with anonymous connection\n");
			report(out_hnd,
			       "ntlogin [[DOMAIN\\]user] [password]\n");
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
			fstrcpy(nt_user_name, p + 1);
		}

	}

	if (domain[0] == 0)
	{
		report(out_hnd, "no domain specified.\n");
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

	DEBUG(5, ("do_nt_login_test: username %s from: %s\n",
		  nt_user_name, info->myhostname));

	fstrcpy(trust_acct, info->myhostname);
	fstrcat(trust_acct, "$");

	res = res ? msrpc_lsa_query_trust_passwd(wks_name, "$MACHINE.ACC",
						 trust_passwd, NULL) : False;

	res = res ? cli_nt_setup_creds(srv_name, domain, info->myhostname,
				       trust_acct,
				       trust_passwd,
				       SEC_CHAN_WKSTA,
				       &validation_level) == 0x0 : False;


	memset(trust_passwd, 0, 16);

	/* do an NT login */
	res = res ? (cli_nt_login_interactive(srv_name, info->myhostname,
					      domain, nt_user_name,
					      getuid(), lm_pw, nt_pw,
					      &info->dom.ctr,
					      validation_level,
					      &info->dom.user_info3) ==
		     0x0) : False;


#if 0
	/* ok!  you're logged in!  do anything you like, then... */

	/* do an NT logout */
	res =
		res ? cli_nt_logoff(srv_name, info->myhostname,
				    &info->dom.ctr) : False;
#endif

	report(out_hnd, "cmd_nt_login: login (%s) test succeeded: %s\n",
	       nt_user_name, BOOLSTR(res));
}

/****************************************************************************
experimental nt login.
****************************************************************************/
void cmd_netlogon_domain_test(struct client_info *info, int argc,
			      char *argv[])
{
	char *nt_trust_dom;
	BOOL res = True;
	uchar trust_passwd[16];
	fstring inter_dom_acct;
	fstring trust_sec_name;
	fstring domain;
	uint16 validation_level;

	fstring wks_name;
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(wks_name, "\\\\");
	if (strequal(srv_name, "\\\\.") &&
	    strequal(info->dest_host, info->myhostname))
	{
		fstrcat(wks_name, ".");
	}
	else
	{
		fstrcat(wks_name, info->dest_host);
	}
	strupper(wks_name);

	domain[0] = 0;
	if (usr_creds != NULL)
	{
		fstrcpy(domain, usr_creds->ntc.domain);
	}

	if (domain[0] == 0)
	{
		fstrcpy(domain, info->dom.level3_dom);
	}

	if (argc < 2)
	{
		report(out_hnd, "domtest: must specify domain name\n");
		return;
	}

	nt_trust_dom = argv[1];

	DEBUG(5, ("do_nt_login_test: domain %s\n", nt_trust_dom));

	fstrcpy(trust_sec_name, "G$$");
	fstrcat(trust_sec_name, nt_trust_dom);
	strupper(inter_dom_acct);

	fstrcpy(inter_dom_acct, nt_trust_dom);
	fstrcat(inter_dom_acct, "$");

	res = res ? msrpc_lsa_query_trust_passwd(wks_name, trust_sec_name,
						 trust_passwd, NULL) : False;
	res = res ? cli_nt_setup_creds(srv_name, domain,
				       info->myhostname, inter_dom_acct,
				       trust_passwd,
				       SEC_CHAN_DOMAIN,
				       &validation_level) == 0x0 : False;

	memset(trust_passwd, 0, 16);

	report(out_hnd, "cmd_nt_login: credentials (%s) test succeeded: %s\n",
	       nt_trust_dom, BOOLSTR(res));
}

/****************************************************************************
experimental SAM synchronisation.
****************************************************************************/
uint32 cmd_sam_sync(struct client_info *info, int argc, char *argv[])
{
	SAM_DELTA_HDR hdr_deltas[MAX_SAM_DELTAS];
	SAM_DELTA_CTR deltas[MAX_SAM_DELTAS];
	uint32 num;
	uchar trust_passwd[16];
	fstring trust_acct;
	fstring domain;

	fstring wks_name;
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, info->dest_host);
	strupper(srv_name);

	fstrcpy(domain, info->dom.level5_dom);

	fstrcpy(wks_name, "\\\\");
#if 0
	if (strequal(srv_name, "\\\\."))
#endif
	{
		fstrcat(wks_name, ".");
	}
#if 0
	else
	{
		fstrcat(wks_name, info->myhostname);
	}
#endif
	strupper(wks_name);

	if (!get_dc_name(domain, srv_name, 0x1b))
	{
		report(out_hnd, "could not locate server for domain %s\n",
		       domain);
		return NT_STATUS_DOMAIN_CONTROLLER_NOT_FOUND;
	}

	fstrcpy(trust_acct, info->myhostname);
	fstrcat(trust_acct, "$");

	if (!msrpc_lsa_query_trust_passwd(wks_name, "$MACHINE.ACC",
					  trust_passwd, NULL))
	{
		report(out_hnd, "cmd_sam_sync: no trust account password\n");
		return NT_STATUS_ACCESS_DENIED;
	}

	if (net_sam_sync(srv_name, domain, info->myhostname,
			 trust_acct, trust_passwd, hdr_deltas, deltas, &num))
	{
		display_sam_sync(out_hnd, ACTION_HEADER, hdr_deltas, deltas,
				 num);
		display_sam_sync(out_hnd, ACTION_ENUMERATE, hdr_deltas,
				 deltas, num);
		display_sam_sync(out_hnd, ACTION_FOOTER, hdr_deltas, deltas,
				 num);
	}

	return NT_STATUS_NOPROBLEMO;
}
