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
extern pstring username;
extern pstring smb_login_passwd;
extern pstring workgroup;

#define CLIENT_TIMEOUT (30*1000)

#ifdef NTDOMAIN

/************************************************************************
 check workstation trust account status
 ************************************************************************/
BOOL wksta_trust_account_check(struct in_addr dest_ip, char *dest_host,
				char *myhostname, char *domain,
				fstring mach_pwd, fstring new_mach_pwd)
{
	pstring tmp;
	struct cli_state wksta_trust;
	fstring mach_acct;
	uchar lm_owf_mach_pwd[16];
	uchar nt_owf_mach_pwd[16];
	uchar lm_sess_pwd[24];
	uchar nt_sess_pwd[24];
	BOOL right_error_code = False;

	char *start_mach_pwd;
	char *change_mach_pwd;

	fstrcpy(mach_acct, myhostname);
	strlower(mach_pwd);

	fstrcpy(mach_pwd , myhostname);
	strcat(mach_acct, "$");
	strupper(mach_acct);

	printf("Enter Workstation Trust Account password for [%s].\nDefault is [%s]. ",
				mach_acct, mach_pwd);

	start_mach_pwd = (char*)getpass("Password:");

	if (start_mach_pwd[0] != 0)
	{
		fstrcpy(mach_pwd, start_mach_pwd);
	}
	else
	{
		mach_pwd[0] = 0;
	}

	printf("Enter new Workstation Trust Account password for [%s]\nPress Return to leave at old value. ",
				mach_acct);

	change_mach_pwd = (char*)getpass("New Password:");

	if (change_mach_pwd[0] != 0)
	{
		fstrcpy(new_mach_pwd, change_mach_pwd);
	}
	else
	{
		change_mach_pwd[0] = 0;
	}

	DEBUG(1,("initialise wksta_trust connection\n"));

	return False;

	if (!cli_initialise(&wksta_trust))
	{
		DEBUG(1,("cli_initialise failed for wksta_trust\n"));
		return False;
	}

	DEBUG(1,("server connect for wksta_trust\n"));

	if (!server_connect_init(&wksta_trust, myhostname, dest_ip, dest_host))
	{
		uint8 err_cls;
		uint32 err_num;
		cli_error(&wksta_trust, &err_cls, &err_num);
		DEBUG(1,("server_connect_init failed (%s)\n", cli_errstr(&wksta_trust)));

		cli_shutdown(&wksta_trust);
		return False;
	}

	DEBUG(1,("server connect wksta_trust succeeded\n"));

	nt_lm_owf_gen(mach_pwd, nt_owf_mach_pwd, lm_owf_mach_pwd);

	DEBUG(5,("generating nt owf from initial machine pwd: %s\n", mach_pwd));
	SMBOWFencrypt(nt_owf_mach_pwd, wksta_trust.cryptkey, nt_sess_pwd);
	SMBOWFencrypt(lm_owf_mach_pwd, wksta_trust.cryptkey, lm_sess_pwd);

	right_error_code = False;

	if (!server_validate2(&wksta_trust, mach_acct, domain,
			lm_sess_pwd, sizeof(lm_sess_pwd),
			nt_sess_pwd, sizeof(nt_sess_pwd)))
	{
		uint8 err_cls;
		uint32 err_num;
		cli_error(&wksta_trust, &err_cls, &err_num);

		if (err_num == (0xC0000000 | NT_STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT))
		{
			DEBUG(1,("server_validate: valid workstation trust account exists\n"));
			right_error_code = True;
		}

		if (err_num == (0xC0000000 | NT_STATUS_NO_SUCH_USER))
		{
			DEBUG(1,("server_validate: workstation trust account does not exist\n"));
			right_error_code = False;
		}
	}

	if (!right_error_code)
	{
		DEBUG(1,("server_validate failed (%s)\n", cli_errstr(&wksta_trust)));
	}

	cli_shutdown(&wksta_trust);
	return right_error_code;
}

/****************************************************************************
experimental nt login.
****************************************************************************/
BOOL do_nt_login(struct in_addr dest_ip, char *dest_host,
				char *myhostname,
				int Client, int cnum)
{
	DOM_CHAL clnt_chal;
	DOM_CHAL srv_chal;

	DOM_CRED clnt_cred;

	DOM_CHAL auth2_srv_chal;

	DOM_CRED srv_pwset_clnt_cred;
	DOM_CRED srv_pwset_srv_cred;

	DOM_CRED sam_logon_clnt_cred;
	DOM_CRED sam_logon_rtn_cred;
	DOM_CRED sam_logon_srv_cred;

	DOM_CRED sam_logoff_clnt_cred;
	DOM_CRED sam_logoff_rtn_cred;
	DOM_CRED sam_logoff_srv_cred;

	DOM_ID_INFO_1 id1;
	LSA_USER_INFO user_info1;
	LSA_POL_HND pol;

	UTIME zerotime;

	uchar sess_key[8];
	char nt_owf_mach_pwd[16];
	char nt_owf_new_mach_pwd[16];

	fstring server_name;
	fstring mach_acct;

	fstring mach_pwd;
	fstring new_mach_pwd;

	RPC_IFACE abstract;
	RPC_IFACE transfer;

#if 0
	static char trn_data[16] =
	{
		0x04, 0x5d, 0x88, 0x8a,
		0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00,
		0x2b, 0x10, 0x48, 0x60
	};

	static char abs_data[16] = 
	{
		0xc8, 0x4f, 0x32, 0x4b,
		0x70, 0x16, 0xd3, 0x01,
		0x12, 0x78, 0x5a, 0x47,
		0xbf, 0x6e, 0xe1, 0x88
	};
#endif

	static char abs_data[16] = 
	{
		0x78, 0x57, 0x34, 0x12,
		0x34, 0x12, 0xcd, 0xab,
		0xef, 0x00, 0x01, 0x23,
		0x45, 0x67, 0x89, 0xab
	};

	/* received from LSA Query Info Policy, level 5 */
	fstring level5_domain_name;
	pstring level5_domain_sid;

	/* received from LSA Query Info Policy, level 3 */
	fstring level3_domain_name;
	pstring level3_domain_sid;

	uint16 fnum;
	uint32 call_id = 0;
	char *inbuf,*outbuf; 

	/******************** initialise ********************************/

	zerotime.time = 0;

	inbuf  = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);
	outbuf = (char *)malloc(BUFFER_SIZE + SAFETY_MARGIN);

	if (!inbuf || !outbuf)
	{
		DEBUG(0,("out of memory\n"));
		return False;
	}
	
	/************ Check workstation trust account *******************/

	/* default machine password is lower-case machine name (really secure) */
	fstrcpy(mach_pwd, myhostname);
	strlower(mach_pwd);

	wksta_trust_account_check(dest_ip, dest_host, myhostname, workgroup, mach_pwd, new_mach_pwd);


	/******************** Open the \PIPE\lsarpc *******************/

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

#if 0
	for (i = 0; i < sizeof(trn_data); i++)
	{
		trn_data[i] = 2 * i;
	}

	for (i = 0; i < sizeof(abs_data); i++)
	{
		abs_data[i] = (i*2) + ((i*2+1) << 4);
	}

	make_rpc_iface(&transfer, trn_data, 0x2);

#endif

	/* create interface UUIDs. */
	make_rpc_iface(&abstract, abs_data, 0x0);

	if (!rpc_pipe_bind(PIPE_LSARPC, fnum, 0x3b866ecd, &abstract, &transfer))
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
	


	/************ Long-term Session key (default) **********/

	{
		char lm_owf_mach_pwd[16];
#ifdef DEBUG_PASSWORD
		DEBUG(100,("generating nt owf from initial machine pwd: %s\n", mach_pwd));
#endif
		nt_lm_owf_gen(    mach_pwd, nt_owf_mach_pwd    , lm_owf_mach_pwd     );
	}

#ifdef DEBUG_PASSWORD
	dump_data(6, nt_owf_mach_pwd, 16);
#endif

	/* calculate the session key */
	cred_session_key(&clnt_chal, &srv_chal, nt_owf_mach_pwd, sess_key);

	/*********** next new trust account password ************/
	{
		char lm_owf_new_mach_pwd[16];
#ifdef DEBUG_PASSWORD
		DEBUG(100,("generating nt owf from new     machine pwd: %s\n", new_mach_pwd));
#endif
		nt_lm_owf_gen(new_mach_pwd, nt_owf_new_mach_pwd, lm_owf_new_mach_pwd);
	}

#ifdef DEBUG_PASSWORD
	dump_data(6, nt_owf_new_mach_pwd, 16);
#endif



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

	/*********************** Logon Control2 ************************/

	/* send a logon control2 request; receive a logon control2 response */
	if (!do_lsa_logon_ctrl2(fnum, ++call_id, dest_host, 0x1))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/******************* Request Challenge ********************/

	SIVAL(clnt_chal.data, 0, 0x11111111);
	SIVAL(clnt_chal.data, 4, 0x22222222);
	
	/* send a client challenge; receive a server challenge */
	if (!do_lsa_req_chal(fnum, ++call_id, dest_host, myhostname, &clnt_chal, &srv_chal))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/******************* Authenticate 2 ********************/

	/* calculate auth-2 credentials */
	cred_create(sess_key, &clnt_chal, zerotime, &(clnt_cred.challenge));

	/* send client auth-2 challenge; receive an auth-2 challenge */
	if (!do_lsa_auth2(fnum, ++call_id, dest_host, mach_acct, 2, myhostname,
	                  &(clnt_cred.challenge), 0x000001ff, &auth2_srv_chal))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/**************** Net Server Password Set **************/

	clnt_cred.timestamp.time = srv_pwset_clnt_cred.timestamp.time = time(NULL);

	/* calculate sam logon credentials, using the auth2 client challenge */
	cred_create(sess_key, &(clnt_cred.challenge), srv_pwset_clnt_cred.timestamp,
	                                  &(srv_pwset_clnt_cred.challenge));

	/* send client srv_pwset challenge; receive a srv_pwset challenge */
	if (!do_lsa_srv_pwset(fnum, ++call_id, sess_key, 
	                  dest_host, mach_acct, 2, myhostname,
	                  &srv_pwset_clnt_cred, &srv_pwset_srv_cred,
	                  nt_owf_new_mach_pwd))
	{
		cli_smb_close(inbuf, outbuf, Client, cnum, fnum);
		free(inbuf); free(outbuf);
		return False;
	}

	/****************** SAM Info Preparation *******************/

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
	                  dest_host, mach_acct, 
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
	                  dest_host, mach_acct, 
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
