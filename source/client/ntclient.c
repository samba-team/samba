/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-1997
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998
   
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

extern int DEBUGLEVEL;
extern pstring username;
extern pstring smb_login_passwd;
extern pstring workgroup;

#define CLIENT_TIMEOUT (30*1000)

#ifdef NTDOMAIN


/****************************************************************************
experimental nt login.
****************************************************************************/
BOOL do_nt_login(char *desthost, char *myhostname,
				int Client, int cnum)
{
	DOM_CHAL clnt_chal;
	DOM_CHAL srv_chal;

	DOM_CRED clnt_cred;

	DOM_CHAL auth2_srv_chal;

	DOM_CRED sam_logon_clnt_cred;
	DOM_CRED sam_logon_rtn_cred;
	DOM_CRED sam_logon_srv_cred;

	DOM_CRED sam_logoff_clnt_cred;
	DOM_CRED sam_logoff_rtn_cred;
	DOM_CRED sam_logoff_srv_cred;

	DOM_ID_INFO_1 id1;
	LSA_USER_INFO user_info1;
	LSA_POL_HND pol;
	int i;

	UTIME zerotime;

	uchar sess_key[8];
	char nt_owf_mach_pwd[16];
	fstring mach_acct;
	fstring mach_pwd;
	fstring server_name;

	RPC_IFACE abstract;
	RPC_IFACE transfer;

	static char abs_data[16];
	static char trn_data[16];

	/* received from LSA Query Info Policy, level 5 */
	fstring level5_domain_name;
	pstring level5_domain_sid;

	/* received from LSA Query Info Policy, level 3 */
	fstring level3_domain_name;
	pstring level3_domain_sid;

	uint16 fnum;
	uint32 call_id = 0;
	char *inbuf,*outbuf; 

	zerotime.time = 0;

	inbuf  = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
	outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

	if (!inbuf || !outbuf)
	{
		DEBUG(0,("out of memory\n"));
		return False;
	}
	
	/******************* open the \PIPE\lsarpc file *****************/

	if ((fnum = rpc_pipe_open(inbuf, outbuf, PIPE_LSARPC, Client, cnum)) == 0xffff)
	{
		free(inbuf); free(outbuf);
		return False;
	}

	/**************** Set Named Pipe State ***************/
	if (!rpc_pipe_set_hnd_state(PIPE_LSARPC, fnum, 0x4300))
	{
		free(inbuf); free(outbuf);
		return False;
	}

	/******************* bind request on \PIPE\lsarpc *****************/

	/* create and send a MSRPC command with api LSA_OPENPOLICY */

	DEBUG(4,("LSA RPC Bind[%x]\n", fnum));

	for (i = 0; i < sizeof(trn_data); i++)
	{
		trn_data[i] = 2 * i;
	}

	for (i = 0; i < sizeof(abs_data); i++)
	{
		abs_data[i] = i;
	}

	/* create interface UUIDs. */
	make_rpc_iface(&abstract, abs_data, 0x0);
	make_rpc_iface(&transfer, trn_data, 0x2);

	if (!rpc_pipe_bind(PIPE_LSARPC, fnum, ++call_id, &abstract, &transfer))
	{
		free(inbuf); free(outbuf);
		return False;
	}

	/******************* Open Policy ********************/

	fstrcpy(server_name, ("\\\\"));
	fstrcpy(&server_name[2], myhostname);

	/* send an open policy request; receive a policy handle */
	if (!do_lsa_open_policy(fnum, ++call_id, server_name, &pol))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/**************** Query Info Policy, level 3 ********************/

	/* send a query info policy at level 3; receive an info policy */
	if (!do_lsa_query_info_pol(fnum, ++call_id, &pol, 0x3,
	                           level3_domain_name, level3_domain_sid))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/**************** Query Info Policy, level 5 ********************/

	/* send a query info policy at level 5; receive an info policy */
	if (!do_lsa_query_info_pol(fnum, ++call_id, &pol, 0x5,
	                           level5_domain_name, level5_domain_sid))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/******************* Open Policy ********************/

	/* send a close policy request; receive a close pol response */
	if (!do_lsa_close(fnum, ++call_id, &pol))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/******************* close the \PIPE\lsarpc file *******************/

	cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
	


	/******************* open the \PIPE\NETLOGON file *****************/

	if ((fnum = rpc_pipe_open(inbuf, outbuf, PIPE_NETLOGON, Client, cnum)) == 0xffff)
	{
		free(inbuf); free(outbuf);
		return False;
	}

	/**************** Set Named Pipe State ***************/
	if (!rpc_pipe_set_hnd_state(PIPE_NETLOGON, fnum, 0x4300))
	{
		free(inbuf); free(outbuf);
		return False;
	}

	/******************* bind request on \PIPE\NETLOGON *****************/

	if (!rpc_pipe_bind(PIPE_NETLOGON, fnum, ++call_id, &abstract, &transfer))
	{
		free(inbuf); free(outbuf);
		return False;
	}

	/******************* Request Challenge ********************/

	fstrcpy(mach_acct, myhostname);
	strlower(mach_pwd);

	fstrcpy(mach_pwd , myhostname);
	fstrcat(mach_acct, "$");

	SIVAL(clnt_chal.data, 0, 0x11111111);
	SIVAL(clnt_chal.data, 4, 0x22222222);
	
	/* send a client challenge; receive a server challenge */
	if (!do_lsa_req_chal(fnum, ++call_id, desthost, myhostname, &clnt_chal, &srv_chal))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/************ Long-term Session key (default) **********/

#if 0
	/* DAMN!  can't get the machine password - need become_root() to do it! */
	/* get the machine password */
	if (!get_md4pw(mach_acct, nt_owf_mach_pwd))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	DEBUG(5,("got nt owf from smbpasswd entry: %s\n", mach_pwd));
#else

	{
		char lm_owf_mach_pwd[16];
		nt_lm_owf_gen(mach_pwd, nt_owf_mach_pwd, lm_owf_mach_pwd);
		DEBUG(5,("generating nt owf from initial machine pwd: %s\n", mach_pwd));
	}

#endif

	dump_data(6, nt_owf_mach_pwd, 16);

	/* calculate the session key */
	cred_session_key(&clnt_chal, &srv_chal, nt_owf_mach_pwd, sess_key);


	/******************* Authenticate 2 ********************/

	/* calculate auth-2 credentials */
	cred_create(sess_key, &clnt_chal, zerotime, &(clnt_cred.challenge));

	/* send client auth-2 challenge; receive an auth-2 challenge */
	if (!do_lsa_auth2(fnum, ++call_id, desthost, mach_acct, 2, myhostname,
	                  &(clnt_cred.challenge), 0x000001ff, &auth2_srv_chal))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}


	/*********************** SAM Info ***********************/

	{
		char lm_owf_user_pwd[16];
		char nt_owf_user_pwd[16];
		nt_lm_owf_gen(smb_login_passwd, nt_owf_user_pwd, lm_owf_user_pwd);

#ifdef DEBUG_PASSWORD

		DEBUG(100,("nt owf of user password: "));
		dump_data(100, lm_owf_user_pwd, 16);

		DEBUG(100,("nt owf of user password: "));
		dump_data(100, nt_owf_user_pwd, 16);

#endif

		/* this is used in both the SAM Logon and the SAM Logoff */
		make_id_info1(&id1, workgroup, 0,
	              getuid(), 0,
	              username, myhostname,
	              sess_key, lm_owf_user_pwd, nt_owf_user_pwd);
	}

	/*********************** SAM Logon **********************/

	clnt_cred.timestamp.time = sam_logon_clnt_cred.timestamp.time = time(NULL);

	/* calculate sam logon credentials, using the auth2 client challenge */
	cred_create(sess_key, &(clnt_cred.challenge), sam_logon_clnt_cred.timestamp,
	                                  &(sam_logon_clnt_cred.challenge));

	/* send client sam-logon challenge; receive a sam-logon challenge */
	if (!do_lsa_sam_logon(fnum, ++call_id, sess_key, &clnt_cred, 
	                  desthost, mach_acct, 
	                  &sam_logon_clnt_cred, &sam_logon_rtn_cred,
	                  1, 1, &id1, &user_info1,
	                  &sam_logon_srv_cred))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/*********************** SAM Logoff *********************/

	clnt_cred.timestamp.time = sam_logoff_clnt_cred.timestamp.time = time(NULL);

	/* calculate sam logoff credentials, using the sam logon return challenge */
	cred_create(sess_key, &(clnt_cred.challenge),
	                        sam_logoff_clnt_cred.timestamp,
	                      &(sam_logoff_clnt_cred.challenge));

	/* send client sam-logoff challenge; receive a sam-logoff challenge */
	if (!do_lsa_sam_logoff(fnum, ++call_id, sess_key, &clnt_cred,
	                  desthost, mach_acct, 
	                  &sam_logoff_clnt_cred, &sam_logoff_rtn_cred,
	                  1, 1, &id1,
	                  &sam_logoff_srv_cred))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/******************** close the \PIPE\NETLOGON file **************/

	cli_smb_close(inbuf, outbuf, Client, cnum, fnum);

	/* free memory used in all rpc transactions, above */
	free(inbuf); free(outbuf);

	return True;
}
#endif /* NTDOMAIN */
