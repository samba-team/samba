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


#if 0
	if (!cli_initialise(cli, t_idx))
	{
		DEBUG(1,("do_nt_session_open: cli_initialise failed\n"));
		return False;
	}

	DEBUG(1,("do_nt_session_open: server connect initialisation\n"));

	if (!server_connect_init(cli, t_idx, myhostname, dest_ip, dest_host))
	{
		uint8 err_cls;
		uint32 err_num;
		cli_error(cli, t_idx, &err_cls, &err_num);
		DEBUG(1,("server_connect_init failed (%s)\n", cli_errstr(cli, t_idx)));

		return False;
	}

	DEBUG(1,("do_nt_session_open: server connect initialisation succeeded\n"));

	if (!cli_session_setup(cli, t_idx, "", "", 1, NULL, 0, workgroup))
	{
		uint8 err_cls;
		uint32 err_num;
		cli_error(cli, t_idx, &err_cls, &err_num);
		DEBUG(1,("session setup failed (%s)\n", cli_errstr(cli, t_idx)));

		return False;
	}
	
	DEBUG(1,("do_nt_session_open: server session setup succeeded\n"));

	if (!cli_send_tconX(cli, t_idx, "IPC$", "IPC", "", 1))
	{
		uint8 err_cls;
		uint32 err_num;
		cli_error(cli, t_idx, &err_cls, &err_num);
		DEBUG(1,("cli_send_tconX failed (%s)\n", cli_errstr(cli, t_idx)));

		return False;
	}
	
	DEBUG(1,("do_nt_session_open: server IPC$ connection succeeded\n"));
#endif


/****************************************************************************
experimental nt login.

****************************************************************************/
BOOL do_nt_session_open(struct cli_state *cli, int t_idx, uint16 *fnum,
				char *dest_host, char *myhostname,
				char *mach_acct,
				char *username, char *workgroup,
				uchar sess_key[16], DOM_CRED *clnt_cred)
{
	DOM_CHAL clnt_chal;
	DOM_CHAL srv_chal;

	DOM_CHAL auth2_srv_chal;

	UTIME zerotime;

	char nt_owf_mach_pwd[16];
	char nt_owf_prev_mpd[16];

	RPC_IFACE abstract;
	RPC_IFACE transfer;

	fstring mach_pwd;
	fstring prev_mpd;
	fstring dest_srv;

	/******************** initialise ********************************/

	zerotime.time = 0;

	DEBUG(1,("do_nt_session_open: %d\n", __LINE__));

	/******************* open the \PIPE\NETLOGON file *****************/

	if (((*fnum) = cli_open(cli, t_idx, PIPE_NETLOGON, O_CREAT, DENY_NONE,
	                         NULL, NULL, NULL)) == 0xffff)
	{
		DEBUG(1,("do_nt_session_open: cli_open failed\n"));
		return False;
	}

	/**************** Set Named Pipe State ***************/
	if (!rpc_pipe_set_hnd_state(cli, t_idx, PIPE_NETLOGON, *fnum, 0x4300))
	{
		DEBUG(1,("do_nt_session_open: pipe hnd state failed\n"));
		return False;
	}

	/******************* bind request on \PIPE\NETLOGON *****************/

	if (!rpc_pipe_bind(cli, t_idx, PIPE_NETLOGON, *fnum,
	                   &abstract, &transfer,
	                   False, NULL, NULL))
	{
		DEBUG(1,("do_nt_session_open: rpc bind failed\n"));
		return False;
	}

	/************ Check workstation trust account *******************/

	/* default machine password is lower-case machine name (really secure) */
	fstrcpy(mach_pwd, myhostname);
	strlower(mach_pwd);

	/* default machine password is lower-case machine name (really secure) */
	fstrcpy(prev_mpd, myhostname);
	strlower(prev_mpd);

	/******************* Request Challenge ********************/

	SIVAL(clnt_chal.data, 0, 0x11111111);
	SIVAL(clnt_chal.data, 4, 0x22222222);
	
	strcpy(dest_srv, "\\\\");
	strcat(dest_srv, dest_host);
	strupper(dest_srv);

	/* send a client challenge; receive a server challenge */
	if (!do_net_req_chal(cli, t_idx, *fnum, dest_srv, myhostname, &clnt_chal, &srv_chal))
	{
		DEBUG(1,("do_nt_session_open: request challenge failed\n"));
		return False;
	}

	/**************** Long-term Session key **************/

#ifdef DEBUG_PASSWORD
	DEBUG(100,("generating nt owf from initial machine pwd: %s\n", mach_pwd));
#endif
	nt_owf_gen(    mach_pwd, nt_owf_mach_pwd);

#ifdef DEBUG_PASSWORD
	dump_data(6, nt_owf_mach_pwd, 16);
#endif

#ifdef DEBUG_PASSWORD
	DEBUG(100,("generating nt owf from previous machine pwd: %s\n", prev_mpd));
#endif
	nt_owf_gen(    mach_pwd, nt_owf_prev_mpd);

#ifdef DEBUG_PASSWORD
	dump_data(6, nt_owf_prev_mpd, 16);
#endif

	/* calculate the session key */
	cred_session_key(&clnt_chal, &srv_chal, nt_owf_mach_pwd, sess_key);
#if 0
	cred_session_key(&clnt_chal, &srv_chal, nt_owf_prev_mpd, sess_key+8);
#else
	bzero(sess_key+8, 8);
#endif

	/******************* Authenticate 2 ********************/

	/* calculate auth-2 credentials */
	cred_create(sess_key, &clnt_chal, zerotime, &(clnt_cred->challenge));

	/* send client auth-2 challenge; receive an auth-2 challenge */
	if (!do_net_auth2(cli, t_idx, *fnum, 
	                  dest_srv, mach_acct,
	                  SEC_CHAN_WKSTA, myhostname,
	                  &(clnt_cred->challenge), 0x000001ff, &auth2_srv_chal))
	{
		DEBUG(1,("do_nt_session_open: request challenge failed\n"));
		return False;
	}

	return True;
}

/****************************************************************************
 server password set
 ****************************************************************************/
BOOL do_nt_srv_pwset(struct cli_state *cli, int t_idx, uint16 fnum,
				uint8 sess_key[16], DOM_CRED *clnt_cred, DOM_CRED *rtn_cred,
				char *new_mach_pwd,
				char *dest_host, char *mach_acct, char *myhostname)
{
	/**************** Net Server Password Set **************/

	DOM_CRED cred;
	char nt_cypher[16];
	uint8 mode = 1;
	char nt_owf_new_mach_pwd[16];

#ifdef DEBUG_PASSWORD
	DEBUG(100,("generating nt owf from new machine pwd: %s\n", new_mach_pwd));
#endif
	nt_owf_gen(new_mach_pwd, nt_owf_new_mach_pwd);

#ifdef DEBUG_PASSWORD
dump_data(6, nt_owf_new_mach_pwd, 16);
#endif

	if (!obfuscate_pwd(nt_cypher, nt_owf_new_mach_pwd, mode))
	{
		DEBUG(5,("do_nt_srv_pwset: encrypt mach pwd failed\n"));
		return False;
	}
	
	clnt_cred->timestamp.time = time(NULL);

	memcpy(&cred, clnt_cred, sizeof(cred));

	/* calculate credentials */
	cred_create(sess_key, &(clnt_cred->challenge),
	                        cred.timestamp,
	                      &(cred.challenge));

	/* send client srv_pwset challenge */
	return do_net_srv_pwset(cli, t_idx, fnum, sess_key, clnt_cred,
					  dest_host, mach_acct, 2, myhostname,
					  &cred, rtn_cred,
					  nt_cypher);
}

/****************************************************************************
 make interactive sam login info
 ****************************************************************************/
void make_nt_login_interactive(NET_ID_INFO_CTR *ctr,
				uchar sess_key[16],
				char *workgroup, char *myhostname,
				uint32 smb_userid, char *username)
{
	/****************** SAM Info Preparation *******************/

	char *smb_user_passwd = getpass("Enter NT Login Password:");

	char lm_owf_user_pwd[16];
	char nt_owf_user_pwd[16];

	nt_lm_owf_gen(smb_user_passwd, nt_owf_user_pwd, lm_owf_user_pwd);

#ifdef DEBUG_PASSWORD

	DEBUG(100,("nt owf of user password: "));
	dump_data(100, lm_owf_user_pwd, 16);

	DEBUG(100,("nt owf of user password: "));
	dump_data(100, nt_owf_user_pwd, 16);

#endif

	/* indicate an "interactive" login */
	ctr->switch_value = 1;

	/* this is used in both the SAM Logon and the SAM Logoff */
	make_id_info1(&ctr->auth.id1, workgroup, 0,
			  smb_userid, 0,
			  username, myhostname,
			  sess_key, lm_owf_user_pwd, nt_owf_user_pwd);
}

/****************************************************************************
experimental nt login.
****************************************************************************/
BOOL do_nt_login(struct cli_state *cli, int t_idx, uint16 fnum,
				uint8 sess_key[16], DOM_CRED *clnt_cred, DOM_CRED *rtn_cred,
				NET_ID_INFO_CTR *ctr, char *dest_host, char *myhostname,
				NET_USER_INFO_3 *user_info3)
{
	DOM_CRED sam_logon_rtn_cred;
	DOM_CRED cred;
	fstring dest_srv;
	fstring my_host_name;

	DEBUG(5,("do_nt_login: %d\n", __LINE__));

	/*********************** SAM Logon **********************/

	clnt_cred->timestamp.time = time(NULL);

	memcpy(&cred, clnt_cred, sizeof(cred));

	/* calculate sam logon credentials */
	cred_create(sess_key, &(clnt_cred->challenge),
	                        cred.timestamp,
	                      &(cred.challenge));

	strcpy(dest_srv, "\\\\");
	strcat(dest_srv, dest_host);
	strupper(dest_srv);

	fstrcpy(my_host_name, myhostname);
	strupper(my_host_name);

	/* send client sam-logon challenge */
	return do_net_sam_logon(cli, t_idx, fnum, sess_key, clnt_cred, 
	                  dest_srv, my_host_name, 
	                  &cred, &sam_logon_rtn_cred,
	                  ctr->switch_value, ctr, 3, user_info3,
	                  rtn_cred);
}

/****************************************************************************
nt sam logoff
****************************************************************************/
BOOL do_nt_logoff(struct cli_state *cli, int t_idx, uint16 fnum,
				uint8 sess_key[16], DOM_CRED *clnt_cred, DOM_CRED *rtn_cred,
				NET_ID_INFO_CTR *ctr, char *dest_host, char *myhostname)
{
	DOM_CRED sam_logoff_rtn_cred;
	DOM_CRED cred;
	fstring dest_srv;
	fstring my_host_name;

	DEBUG(5,("do_nt_logoff: %d\n", __LINE__));

	/*********************** SAM Logoff *********************/

	clnt_cred->timestamp.time = time(NULL);

	memcpy(&cred, clnt_cred, sizeof(cred));

	/* calculate sam logoff credentials */
	cred_create(sess_key, &(clnt_cred->challenge),
	                        cred.timestamp,
	                      &(cred.challenge));

	strcpy(dest_srv, "\\\\");
	strcat(dest_srv, dest_host);
	strupper(dest_srv);

	fstrcpy(my_host_name, myhostname);
	strupper(my_host_name);

	/* send client sam-logoff challenge; receive a sam-logoff challenge */
	return do_net_sam_logoff(cli, t_idx, fnum, sess_key, clnt_cred,
	                  dest_srv, my_host_name, 
	                  &cred, &sam_logoff_rtn_cred,
	                  ctr->switch_value, ctr, 3,
	                  rtn_cred);
}

#if 0
	/* free memory used in all rpc transactions, above */
	cli_shutdown(cli, t_idx);
#endif

/****************************************************************************
experimental nt login.
****************************************************************************/
void do_nt_session_close(struct cli_state *cli, int t_idx, uint16 fnum)
{
		/******************** close the \PIPE\NETLOGON file **************/
	if (fnum != 0xffff)
	{
		cli_close(cli, t_idx, fnum, 0);
	}

}


