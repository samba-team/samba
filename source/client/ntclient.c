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

extern struct cli_state *ipc_cli;
extern int ipc_tidx;

extern FILE* out_hnd;


/****************************************************************************
server get info query
****************************************************************************/
void cmd_srv_query_info(struct client_info *info)
{
	fstring dest_srv;
	fstring tmp;
	SRV_INFO_CTR ctr;
	uint32 info_level = 101;

	BOOL res = True;

	bzero(&ctr, sizeof(ctr));

	strcpy(dest_srv, "\\\\");
	strcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	if (next_token(NULL, tmp, NULL))
	{
		info_level = strtoul(tmp, (char**)NULL, 10);
	}

	DEBUG(4,("cmd_srv_query_info: server:%s info level: %D\n",
				dest_srv, info_level));

	DEBUG(5, ("cmd_srv_query_info: ipc_cli->fd:%d\n", ipc_cli->fd));

	/* open LSARPC session. */
	res = res ? do_srv_session_open(ipc_cli, ipc_tidx, info) : False;

	/* lookup domain controller; receive a policy handle */
	res = res ? do_srv_net_srv_get_info(ipc_cli, ipc_tidx, info->dom.srvsvc_fnum,
				dest_srv, info_level, &ctr) : False;

	/* close the session */
	do_srv_session_close(ipc_cli, ipc_tidx, info);

	if (res)
	{
		DEBUG(5,("cmd_srv_query_info: query succeeded\n"));

		display_srv_info_ctr(out_hnd, &ctr);
	}
	else
	{
		DEBUG(5,("cmd_srv_query_info: query failed\n"));
	}
}

/****************************************************************************
server enum connections
****************************************************************************/
void cmd_srv_query_conn(struct client_info *info)
{
	fstring dest_srv;
	fstring qual_srv;
	fstring tmp;
	SRV_CONN_INFO_CTR ctr;
	ENUM_HND hnd;
	uint32 info_level = 0;

	BOOL res = True;

	bzero(&ctr, sizeof(ctr));

	strcpy(qual_srv, "\\\\");
	strcat(qual_srv, info->myhostname);
	strupper(qual_srv);

	strcpy(dest_srv, "\\\\");
	strcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	if (next_token(NULL, tmp, NULL))
	{
		info_level = strtoul(tmp, (char**)NULL, 10);
	}

	DEBUG(4,("cmd_srv_query_conn: server:%s info level: %D\n",
				dest_srv, info_level));

	DEBUG(5, ("cmd_srv_query_conn: ipc_cli->fd:%d\n", ipc_cli->fd));

	/* open srvsvc session. */
	res = res ? do_srv_session_open(ipc_cli, ipc_tidx, info) : False;

	hnd.ptr_hnd = 1;
	hnd.handle = 0;

	/* enumerate files on server */
	res = res ? do_srv_net_srv_conn_enum(ipc_cli, ipc_tidx, info->dom.srvsvc_fnum,
				dest_srv, qual_srv,
	            info_level, &ctr, 0x1000, &hnd) : False;

	/* close the session */
	do_srv_session_close(ipc_cli, ipc_tidx, info);

	if (res)
	{
		DEBUG(5,("cmd_srv_query_conn: query succeeded\n"));

/*
		display_srv_info_ctr(out_hnd, &ctr);
*/
	}
	else
	{
		DEBUG(5,("cmd_srv_query_conn: query failed\n"));
	}
}

/****************************************************************************
server enum sessions
****************************************************************************/
void cmd_srv_query_sess(struct client_info *info)
{
	fstring dest_srv;
	fstring tmp;
	SRV_SESS_INFO_CTR ctr;
	ENUM_HND hnd;
	uint32 info_level = 0;

	BOOL res = True;

	bzero(&ctr, sizeof(ctr));

	strcpy(dest_srv, "\\\\");
	strcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	if (next_token(NULL, tmp, NULL))
	{
		info_level = strtoul(tmp, (char**)NULL, 10);
	}

	DEBUG(4,("cmd_srv_query_sess: server:%s info level: %D\n",
				dest_srv, info_level));

	DEBUG(5, ("cmd_srv_query_sess: ipc_cli->fd:%d\n", ipc_cli->fd));

	/* open srvsvc session. */
	res = res ? do_srv_session_open(ipc_cli, ipc_tidx, info) : False;

	hnd.ptr_hnd = 1;
	hnd.handle = 0;

	/* enumerate files on server */
	res = res ? do_srv_net_srv_sess_enum(ipc_cli, ipc_tidx, info->dom.srvsvc_fnum,
				dest_srv, NULL, info_level, &ctr, 0x1000, &hnd) : False;

	/* close the session */
	do_srv_session_close(ipc_cli, ipc_tidx, info);

	if (res)
	{
		DEBUG(5,("cmd_srv_query_sess: query succeeded\n"));

/*
		display_srv_info_ctr(out_hnd, &ctr);
*/
	}
	else
	{
		DEBUG(5,("cmd_srv_query_sess: query failed\n"));
	}
}

/****************************************************************************
server enum files
****************************************************************************/
void cmd_srv_query_files(struct client_info *info)
{
	fstring dest_srv;
	fstring tmp;
	SRV_FILE_INFO_CTR ctr;
	ENUM_HND hnd;
	uint32 info_level = 3;

	BOOL res = True;

	bzero(&ctr, sizeof(ctr));

	strcpy(dest_srv, "\\\\");
	strcat(dest_srv, info->dest_host);
	strupper(dest_srv);

	if (next_token(NULL, tmp, NULL))
	{
		info_level = strtoul(tmp, (char**)NULL, 10);
	}

	DEBUG(4,("cmd_srv_query_files: server:%s info level: %D\n",
				dest_srv, info_level));

	DEBUG(5, ("cmd_srv_query_files: ipc_cli->fd:%d\n", ipc_cli->fd));

	/* open srvsvc session. */
	res = res ? do_srv_session_open(ipc_cli, ipc_tidx, info) : False;

	hnd.ptr_hnd = 1;
	hnd.handle = 0;

	/* enumerate files on server */
	res = res ? do_srv_net_srv_file_enum(ipc_cli, ipc_tidx, info->dom.srvsvc_fnum,
				dest_srv, NULL, info_level, &ctr, 0x1000, &hnd) : False;

	/* close the session */
	do_srv_session_close(ipc_cli, ipc_tidx, info);

	if (res)
	{
		DEBUG(5,("cmd_srv_query_files: query succeeded\n"));

/*
		display_srv_info_ctr(out_hnd, &ctr);
*/
	}
	else
	{
		DEBUG(5,("cmd_srv_query_files: query failed\n"));
	}
}

/****************************************************************************
nt lsa query
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
experimental SAM user query.
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
	res = res ? do_samr_session_open(ipc_cli, ipc_tidx, info) : False;

	/* establish a connection. */
	res = res ? do_samr_connect(ipc_cli, ipc_tidx, info->dom.samr_fnum,
				srv_name, 0x00000020,
				&info->dom.samr_pol_connect) : False;

	/* connect to the domain */
	res = res ? do_samr_open_domain(ipc_cli, ipc_tidx, info->dom.samr_fnum,
	            &info->dom.samr_pol_connect, admin_rid, sid,
	            &info->dom.samr_pol_open_domain) : False;

	/* read some users */
	res = res ? do_samr_enum_dom_users(ipc_cli, ipc_tidx, info->dom.samr_fnum,
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
			SAM_USER_INFO_15 usr;

			fprintf(out_hnd, "User RID: %8x  User Name: %s\n",
					  user_rid,
					  info->dom.sam[user_idx].acct_name);

			if (request_user_info)
			{
				/* send user info query, level 0x15 */
				if (get_samr_query_userinfo_15(ipc_cli, ipc_tidx, info->dom.samr_fnum,
							&info->dom.samr_pol_open_domain,
							user_rid, &usr))
				{
					display_sam_user_info_15(out_hnd, &usr);
				}
			}

			if (request_group_info)
			{
				uint32 num_groups;
				DOM_GID gid[LSA_MAX_GROUPS];

				/* send user group query */
				if (get_samr_query_usergroups(ipc_cli, ipc_tidx, info->dom.samr_fnum,
							&info->dom.samr_pol_open_domain,
							user_rid, &num_groups, gid))
				{
					display_group_info(out_hnd, num_groups, gid);
				}
			}

			user_idx++;
		}
	}

	res = res ? do_samr_close(ipc_cli, ipc_tidx, info->dom.samr_fnum,
	            &info->dom.samr_pol_connect) : False;

	res = res ? do_samr_close(ipc_cli, ipc_tidx, info->dom.samr_fnum,
	            &info->dom.samr_pol_open_domain) : False;

	/* close the session */
	do_samr_session_close(ipc_cli, ipc_tidx, info);

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
	res = res ? do_nt_session_open(ipc_cli, ipc_tidx, &info->dom.lsarpc_fnum,
	                          info->dest_host, info->myhostname,
	                          info->mach_acct,
	                          username, info->workgroup,
	                          info->dom.sess_key, 
	                          &info->dom.clnt_cred) : False;

	/* close the session */
	do_nt_session_close(ipc_cli, ipc_tidx, info->dom.lsarpc_fnum);

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
	bzero(ipc_cli, sizeof(nt_cli));
}

/****************************************************************************
make nt client connection 
****************************************************************************/
 void client_nt_connect(struct client_info *info,
				char *username, char *password, char *workgroup)
{
	BOOL anonymous = !username || username[0] == 0;
	BOOL got_pass = password && password[0] == 0;

	if (!cli_establish_connection(ipc_cli, &ipc_tidx,
			info->dest_host, 0x20, &info->dest_ip,
		     info->myhostname,
		   (got_pass || anonymous) ? NULL : "Enter Password:",
		   username, !anonymous ? password : NULL, workgroup,
	       "IPC$", "IPC",
	       False, True, !anonymous))
	{
		DEBUG(0,("client_nt_connect: connection failed\n"));
		cli_shutdown(ipc_cli);
	}
}

/****************************************************************************
stop the nt connection(s?)
****************************************************************************/
 void client_nt_stop(void)
{
	cli_shutdown(ipc_cli);
}
#endif /* 0 */

