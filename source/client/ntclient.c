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
extern int smb_tidx;

extern struct cli_state *ipc_cli;
extern int ipc_tidx;

extern FILE* out_hnd;

/****************************************************************************
nt lsa query

use the anon IPC$ for this one
****************************************************************************/
void cmd_lsa_query_info(struct client_info *info)
{
	fstring srv_name;

	BOOL res = True;

	strcpy(info->dom.level3_dom, "");
	strcpy(info->dom.level3_sid, "");
	strcpy(info->dom.level5_dom, "");
	strcpy(info->dom.level5_sid, "");

	strcpy(srv_name, "\\\\");
	strcat(srv_name, info->myhostname);
	strupper(srv_name);

	DEBUG(4,("cmd_lsa_query_info: server:%s\n", srv_name));

	DEBUG(5, ("cmd_lsa_query_info: ipc_cli->fd:%d\n", ipc_cli->fd));

	/* open LSARPC session. */
	res = res ? do_lsa_session_open(ipc_cli, ipc_tidx, info) : False;

	/* lookup domain controller; receive a policy handle */
	res = res ? do_lsa_open_policy(ipc_cli, ipc_tidx, info->dom.lsarpc_fnum,
				srv_name,
				&info->dom.lsa_info_pol) : False;

	/* send client info query, level 3.  receive domain name and sid */
	res = res ? do_lsa_query_info_pol(ipc_cli, ipc_tidx, info->dom.lsarpc_fnum,
	            &info->dom.lsa_info_pol, 0x03,
				info->dom.level3_dom,
	            info->dom.level3_sid) : False;

	/* send client info query, level 5.  receive domain name and sid */
	res = res ? do_lsa_query_info_pol(ipc_cli, ipc_tidx, info->dom.lsarpc_fnum,
	            &info->dom.lsa_info_pol, 0x05,
				info->dom.level5_dom,
	            info->dom.level5_sid) : False;

	res = res ? do_lsa_close(ipc_cli, ipc_tidx, info->dom.lsarpc_fnum,
				&info->dom.lsa_info_pol) : False;

	/* close the session */
	do_lsa_session_close(ipc_cli, ipc_tidx, info);

	if (res)
	{
		BOOL domain_something = False;
		DEBUG(5,("cmd_lsa_query_info: query succeeded\n"));

		fprintf(out_hnd, "LSA Query Info Policy\n");

		if (info->dom.level3_sid[0] != 0)
		{
			fprintf(out_hnd, "Domain Member     - Domain: %s SID: %s\n",
				info->dom.level3_dom, info->dom.level3_sid);
			domain_something = True;
		}
		if (info->dom.level5_sid[0] != 0)
		{
			fprintf(out_hnd, "Domain Controller - Domain: %s SID: %s\n",
				info->dom.level5_dom, info->dom.level5_sid);
			domain_something = True;
		}
		if (!domain_something)
		{
			fprintf(out_hnd, "%s is not a Domain Member or Controller\n",
			    info->dest_host);
		}
	}
	else
	{
		DEBUG(5,("cmd_lsa_query_info: query succeeded\n"));
	}
}

/****************************************************************************
 display group rid info
 ****************************************************************************/
static void display_group_info(uint32 num_gids, DOM_GID *gid)
{
	int i;

	if (num_gids == 0)
	{
		fprintf(out_hnd, "\tNo Groups\n");
	}
	else
	{
		fprintf(out_hnd, "\tGroup Info\n");
		fprintf(out_hnd, "\t----------\n");

		for (i = 0; i < num_gids; i++)
		{
			fprintf(out_hnd, "\tGroup RID: %8x attr: %x\n",
							  gid[i].g_rid, gid[i].attr);
		}

		fprintf(out_hnd, "\n");
	}
}


/****************************************************************************
 display user_info_15 structure
 ****************************************************************************/
static void display_user_info_15(USER_INFO_15 *usr)
{
	fprintf(out_hnd, "\tUser Info, Level 0x15\n");
	fprintf(out_hnd, "\t---------------------\n");

	fprintf(out_hnd, "\t\tUser Name   : %s\n", unistrn2(usr->uni_user_name   .buffer, usr->uni_user_name   .uni_str_len)); /* username unicode string */
	fprintf(out_hnd, "\t\tFull Name   : %s\n", unistrn2(usr->uni_full_name   .buffer, usr->uni_full_name   .uni_str_len)); /* user's full name unicode string */
	fprintf(out_hnd, "\t\tHome Drive  : %s\n", unistrn2(usr->uni_home_dir    .buffer, usr->uni_home_dir    .uni_str_len)); /* home directory unicode string */
	fprintf(out_hnd, "\t\tDir Drive   : %s\n", unistrn2(usr->uni_dir_drive   .buffer, usr->uni_dir_drive   .uni_str_len)); /* home directory drive unicode string */
	fprintf(out_hnd, "\t\tProfile Path: %s\n", unistrn2(usr->uni_profile_path.buffer, usr->uni_profile_path.uni_str_len)); /* profile path unicode string */
	fprintf(out_hnd, "\t\tLogon Script: %s\n", unistrn2(usr->uni_logon_script.buffer, usr->uni_logon_script.uni_str_len)); /* logon script unicode string */
	fprintf(out_hnd, "\t\tDescription : %s\n", unistrn2(usr->uni_description .buffer, usr->uni_description .uni_str_len)); /* user description unicode string */

	fprintf(out_hnd, "\t\tLogon Time               : %s\n", time_to_string(interpret_nt_time(&(usr->logon_time           ))));
	fprintf(out_hnd, "\t\tLogoff Time              : %s\n", time_to_string(interpret_nt_time(&(usr->logoff_time          ))));
	fprintf(out_hnd, "\t\tKickoff Time             : %s\n", time_to_string(interpret_nt_time(&(usr->kickoff_time         ))));
	fprintf(out_hnd, "\t\tPassword last set Time   : %s\n", time_to_string(interpret_nt_time(&(usr->pass_last_set_time   ))));
	fprintf(out_hnd, "\t\tPassword can change Time : %s\n", time_to_string(interpret_nt_time(&(usr->pass_can_change_time ))));
	fprintf(out_hnd, "\t\tPassword must change Time: %s\n", time_to_string(interpret_nt_time(&(usr->pass_must_change_time))));
	
	fprintf(out_hnd, "\t\tlogon_count : %d\n", usr->logon_count); /* logon count */
	fprintf(out_hnd, "\t\tbad_pw_count: %d\n", usr->bad_pw_count); /* bad password count */
	fprintf(out_hnd, "\t\tunknown_0: %08x\n", usr->unknown_0);
	fprintf(out_hnd, "\t\tunknown_1: %08x\n", usr->unknown_1);

	fprintf(out_hnd, "\t\tunknown_2[0..31]...\n"); /* user passwords? */

	fprintf(out_hnd, "\t\tuser_rid : %x\n"  , usr->user_rid ); /* User ID */
	fprintf(out_hnd, "\t\tgroup_rid: %x\n"  , usr->group_rid); /* Group ID */
	fprintf(out_hnd, "\t\tacb_info : %04x\n", usr->acb_info ); /* Account Control Info */

	fprintf(out_hnd, "\t\tunknown_3: %08x\n", usr->unknown_3); /* 0x00ff ffff */
	fprintf(out_hnd, "\t\tlogon_divs: %d\n", usr->logon_divs); /* 0x0000 00a8 which is 168 which is num hrs in a week */
	fprintf(out_hnd, "\t\tunknown_5: %08x\n", usr->unknown_5); /* 0x0002 0000 */

	fprintf(out_hnd, "\t\tpadding1[0..7]...\n");

	if (usr->ptr_padding2)
	{
		fprintf(out_hnd, "\t\tpadding2[0..31]...\n");
	}

	if (usr->ptr_padding3)
	{
		fprintf(out_hnd, "\t\tpadding3: %x\n", usr->padding3);
	}

	if (usr->ptr_unknown6)
	{
		fprintf(out_hnd, "\t\tunknown_6,pad4: %08x %08x\n", usr->unknown_6, usr->padding4);
	}

	if (usr->ptr_logon_hrs)
	{
		fprintf(out_hnd, "\t\tlogon_hrs[0..%d]...\n", usr->logon_hrs.len);
	}

	fprintf(out_hnd, "\n");
}

/****************************************************************************
experimental SAM user query.

use the nt IPC$ connection for this one.
****************************************************************************/
void cmd_sam_query_users(struct client_info *info)
{
	fstring srv_name;
	fstring sid;
	fstring domain;
	int user_idx;
	BOOL res = True;
	BOOL request_user_info  = False;
	BOOL request_group_info = False;
	uint16 num_entries = 0;
	uint16 unk_0 = 0x0;
	uint16 acb_mask = 0;
	uint16 unk_1 = 0x0;
	uint32 admin_rid = 0x304; /* absolutely no idea. */
	fstring tmp;

	fstrcpy(sid   , info->dom.level5_sid);
	fstrcpy(domain, info->dom.level5_dom);

	if (strlen(sid) == 0)
	{
		fprintf(out_hnd, "please use 'lsaquery' first, to ascertain the SID\n");
		return;
	}

	strcpy(srv_name, "\\\\");
	strcat(srv_name, info->dest_host);
	strupper(srv_name);

	/* a bad way to do token parsing... */
	if (next_token(NULL, tmp, NULL))
	{
		request_user_info  |= strequal(tmp, "-u");
		request_group_info |= strequal(tmp, "-g");
	}

	if (next_token(NULL, tmp, NULL))
	{
		request_user_info  |= strequal(tmp, "-u");
		request_group_info |= strequal(tmp, "-g");
	}

#ifdef DEBUG_TESTING
	if (next_token(NULL, tmp, NULL))
	{
		num_entries = strtoul(tmp, (char**)NULL, 16);
	}

	if (next_token(NULL, tmp, NULL))
	{
		unk_0 = strtoul(tmp, (char**)NULL, 16);
	}

	if (next_token(NULL, tmp, NULL))
	{
		acb_mask = strtoul(tmp, (char**)NULL, 16);
	}

	if (next_token(NULL, tmp, NULL))
	{
		unk_1 = strtoul(tmp, (char**)NULL, 16);
	}
#endif

	fprintf(out_hnd, "SAM Enumerate Users\n");
	fprintf(out_hnd, "From: %s To: %s Domain: %s SID: %s\n",
	                  info->myhostname, srv_name, domain, sid);

#ifdef DEBUG_TESTING
	DEBUG(5,("Number of entries:%d unk_0:%04x acb_mask:%04x unk_1:%04x\n",
	          num_entries, unk_0, acb_mask, unk_1));
#endif

	/* open SAMR session.  negotiate credentials */
	res = res ? do_samr_session_open(smb_cli, smb_tidx, info) : False;

	/* establish a connection. */
	res = res ? do_samr_connect(smb_cli, smb_tidx, info->dom.samr_fnum,
				srv_name, 0x00000020,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? do_samr_open_domain(smb_cli, smb_tidx, info->dom.samr_fnum,
	            &info->dom.samr_pol_connect, admin_rid, sid,
	            &info->dom.samr_pol_open_domain) : False;

	/* read some users */
	res = res ? do_samr_enum_dom_users(smb_cli, smb_tidx, info->dom.samr_fnum,
				&info->dom.samr_pol_open_domain,
	            num_entries, unk_0, acb_mask, unk_1, 0xffff,
				info->dom.sam, &info->dom.num_sam_entries) : False;

	if (res && info->dom.num_sam_entries == 0)
	{
		fprintf(out_hnd, "No users\n");
	}

	if (request_user_info || request_group_info)
	{
		/* query all the users */
		user_idx = 0;

		while (res && user_idx < info->dom.num_sam_entries)
		{
			uint32 user_rid = info->dom.sam[user_idx].smb_userid;
			USER_INFO_15 usr;

			fprintf(out_hnd, "User RID: %8x  User Name: %s\n",
					  user_rid,
					  info->dom.sam[user_idx].acct_name);

			if (request_user_info)
			{
				/* send user info query, level 0x15 */
				if (get_samr_query_userinfo_15(smb_cli, smb_tidx, info->dom.samr_fnum,
							&info->dom.samr_pol_open_domain,
							user_rid, &usr))
				{
					display_user_info_15(&usr);
				}
			}

			if (request_group_info)
			{
				uint32 num_groups;
				DOM_GID gid[LSA_MAX_GROUPS];

				/* send user group query */
				if (get_samr_query_usergroups(smb_cli, smb_tidx, info->dom.samr_fnum,
							&info->dom.samr_pol_open_domain,
							user_rid, &num_groups, gid))
				{
					display_group_info(num_groups, gid);
				}
			}

			user_idx++;
		}
	}

	res = res ? do_samr_close(smb_cli, smb_tidx, info->dom.samr_fnum,
	            &info->dom.samr_pol_connect) : False;

	res = res ? do_samr_close(smb_cli, smb_tidx, info->dom.samr_fnum,
	            &info->dom.samr_pol_open_domain) : False;

	/* close the session */
	do_samr_session_close(smb_cli, smb_tidx, info);

	if (res)
	{
		DEBUG(5,("cmd_sam_query_users: succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_sam_query_users: failed\n"));
	}
}


/****************************************************************************
experimental nt login.

use the anon IPC$ for this one
****************************************************************************/
void cmd_nt_login_test(struct client_info *info)
{
	fstring username;

	BOOL res = True;

	/* machine account passwords */
	pstring new_mach_pwd;

	/* initialisation */
	new_mach_pwd[0] = 0;

	if (!next_token(NULL, username,NULL))
	{
		fprintf(out_hnd, "cmd_nt_login: <username>\n");
		return;
	}

	DEBUG(5,("do_nt_login_test: %d\n", __LINE__));

#if 0
	/* check whether the user wants to change their machine password */
	res = res ? trust_account_check(info->dest_ip, info->dest_host,
	                                info->myhostname, info->workgroup,
	                                info->mach_acct, new_mach_pwd) : False;
#endif
	/* open NETLOGON session.  negotiate credentials */
	res = res ? do_nt_session_open(ipc_cli, ipc_tidx, &info->dom.lsarpc_fnum,
	                          info->dest_host, info->myhostname,
	                          info->mach_acct,
	                          username, info->workgroup,
	                          info->dom.sess_key, &info->dom.clnt_cred) : False;

	/* change the machine password? */
	if (new_mach_pwd != NULL && new_mach_pwd[0] != 0)
	{
		res = res ? do_nt_srv_pwset(ipc_cli, ipc_tidx, info->dom.lsarpc_fnum,
		                   info->dom.sess_key, &info->dom.clnt_cred, &info->dom.rtn_cred,
		                   new_mach_pwd,
		                   info->dest_host, info->mach_acct, info->myhostname) : False;
	}

	/* create the user-identification info */
	make_nt_login_info(&info->dom.id1,
	                 info->dom.sess_key,
	                 info->workgroup, info->myhostname,
	                 getuid(), username);

	/* do an NT login */
	res = res ? do_nt_login(ipc_cli, ipc_tidx, info->dom.lsarpc_fnum,
	                        info->dom.sess_key, &info->dom.clnt_cred, &info->dom.rtn_cred,
	                        &info->dom.id1, info->dest_host, info->myhostname, &info->dom.user_info3) : False;

	/* ok!  you're logged in!  do anything you like, then... */
	   
	/* do an NT logout */
	res = res ? do_nt_logoff(ipc_cli, ipc_tidx, info->dom.lsarpc_fnum,
	                         info->dom.sess_key, &info->dom.clnt_cred, &info->dom.rtn_cred,
	                         &info->dom.id1, info->dest_host, info->myhostname) : False;

	/* close the session */
	do_nt_session_close(ipc_cli, ipc_tidx, info->dom.lsarpc_fnum);

	if (res)
	{
		DEBUG(5,("cmd_nt_login: login test succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_nt_login: login test failed\n"));
	}
}

/****************************************************************************
experimental net login test.

use the nt IPC$ connection for this one.
****************************************************************************/
void cmd_nltest(struct client_info *info)
{
	BOOL res = True;
	fstring username;

	if (!next_token(NULL, username,NULL))
	{
		fprintf(out_hnd, "cmd_nltest: <username>\n");
		return;
	}

	DEBUG(5,("do_nltest: %d\n", __LINE__));

	/* open NETLOGON session.  negotiate credentials */
	res = res ? do_nt_session_open(smb_cli, smb_tidx, &info->dom.lsarpc_fnum,
	                          info->dest_host, info->myhostname,
	                          info->mach_acct,
	                          username, info->workgroup,
	                          info->dom.sess_key, 
	                          &info->dom.clnt_cred) : False;

	/* close the session */
	do_nt_session_close(smb_cli, smb_tidx, info->dom.lsarpc_fnum);

	if (res)
	{
		DEBUG(5,("cmd_nltest: nltest succeeded\n"));
	}
	else
	{
		DEBUG(5,("cmd_nltest: nltest failed\n"));
	}
}

#if 0
/****************************************************************************
initialise nt client structure
****************************************************************************/
 void client_nt_init(void)
{
	bzero(smb_cli, sizeof(nt_cli));
}

/****************************************************************************
make nt client connection 
****************************************************************************/
 void client_nt_connect(struct client_info *info,
				char *username, char *password, char *workgroup)
{
	BOOL anonymous = !username || username[0] == 0;
	BOOL got_pass = password && password[0] == 0;

	if (!cli_establish_connection(smb_cli, &smb_tidx,
			info->dest_host, 0x20, &info->dest_ip,
		     info->myhostname,
		   (got_pass || anonymous) ? NULL : "Enter Password:",
		   username, !anonymous ? password : NULL, workgroup,
	       "IPC$", "IPC",
	       False, True, !anonymous))
	{
		DEBUG(0,("client_nt_connect: connection failed\n"));
		cli_shutdown(smb_cli);
	}
}

/****************************************************************************
stop the nt connection(s?)
****************************************************************************/
 void client_nt_stop(void)
{
	cli_shutdown(smb_cli);
}
#endif /* 0 */

