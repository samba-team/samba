/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-2000
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
#include "rpc_parse.h"
#include "nterr.h"

extern int DEBUGLEVEL;

/****************************************************************************
Initialize domain session credentials.
****************************************************************************/

uint32 cli_nt_setup_creds( const char* srv_name,
				const char* domain,
				const char* myhostname,
				const char* trust_acct,
				unsigned char trust_pwd[16],
				uint16 sec_chan)
{
	DOM_CHAL clnt_chal;
	DOM_CHAL srv_chal;
	uint32 ret;
	UTIME zerotime;
	uint8 sess_key[16];
	DOM_CRED clnt_cred;
	uint32 neg_flags = !lp_client_schannel() ? 0x000001ff : 0x400001ff;

	/******************* Request Challenge ********************/

	generate_random_buffer( clnt_chal.data, 8, False);

	/* send a client challenge; receive a server challenge */
	ret = cli_net_req_chal(srv_name, myhostname, &clnt_chal, &srv_chal);
	if (ret != 0)
	{
		DEBUG(1,("cli_nt_setup_creds: request challenge failed\n"));
		return ret;
	}

	/**************** Long-term Session key **************/

	/* calculate the session key */
	cred_session_key(&clnt_chal, &srv_chal, (char *)trust_pwd, sess_key);
	bzero(sess_key+8, 8);

	/******************* Authenticate 2 ********************/

	/* calculate auth-2 credentials */
	zerotime.time = 0;
	cred_create(sess_key, &clnt_chal, zerotime, &clnt_cred.challenge);

	if (!cli_con_set_creds(srv_name, sess_key, &clnt_cred))
	{
		return NT_STATUS_ACCESS_DENIED | 0xC0000000;
	}

	/*  
	 * Send client auth-2 challenge.
	 * Receive an auth-2 challenge response and check it.
	 */
	ret = cli_net_auth2(srv_name, trust_acct, myhostname,
	                    sec_chan, &neg_flags, &srv_chal);
	if (ret != 0x0)
	{
		DEBUG(1,("cli_nt_setup_creds: auth2 challenge failed.  status: %x\n", ret));
	}

	/* check the client secure channel status */
	if (ret == 0x0 &&
	    lp_client_schannel() == True &&
	    IS_BITS_CLR_ALL(neg_flags, 0x40000000))
	{
		/* netlogon secure channel was required, and not negotiated */
		return NT_STATUS_ACCESS_DENIED | 0xC0000000;
	}

	if (ret == 0x0 && IS_BITS_SET_ALL(neg_flags, 0x40000000))
	{
		extern cli_auth_fns cli_netsec_fns;
		struct cli_connection *con = NULL;
		struct netsec_creds creds;

#if 0
		if (!cli_connection_getsrv(srv_name, PIPE_NETLOGON, &con))
		{
			return NT_STATUS_ACCESS_DENIED | 0xC0000000;
		}
		cli_connection_unlink(con);
#endif

		safe_strcpy(creds.domain, domain    , sizeof(creds.myname)-1);
		safe_strcpy(creds.myname, myhostname, sizeof(creds.myname)-1);
		memcpy(creds.sess_key, sess_key, sizeof(creds.sess_key));
		
		if (!cli_connection_init_auth(srv_name, PIPE_NETLOGON, &con,
		                            &cli_netsec_fns,
		                            (void*)&creds))
		{
			return NT_STATUS_ACCESS_DENIED | 0xC0000000;
		}
		if (!cli_con_set_creds(srv_name, sess_key, &clnt_cred))
		{
			cli_connection_free(con);
			return NT_STATUS_ACCESS_DENIED | 0xC0000000;
		}
	}
	return ret;
}

/****************************************************************************
 Set machine password.
 ****************************************************************************/

BOOL cli_nt_srv_pwset(const char* srv_name, const char* myhostname,
				const char* trust_acct,
				unsigned char *new_hashof_trust_pwd,
				uint16 sec_chan)
{
  DEBUG(5,("cli_nt_srv_pwset: %d\n", __LINE__));

#ifdef DEBUG_PASSWORD
  dump_data(6, new_hashof_trust_pwd, 16);
#endif

  /* send client srv_pwset challenge */
  return cli_net_srv_pwset(srv_name, myhostname, trust_acct,
	                   new_hashof_trust_pwd, sec_chan);
}

/****************************************************************************
NT login - general.
*NEVER* use this code. This method of doing a logon (sending the cleartext
password equivalents, protected by the session key) is inherently insecure
given the current design of the NT Domain system. JRA.
 ****************************************************************************/
BOOL cli_nt_login_general(const char* srv_name, const char* myhostname,
				const char *domain, const char *username, 
				uint32 luid_low,
				const char* general,
				NET_ID_INFO_CTR *ctr,
				NET_USER_INFO_3 *user_info3)
{
	uint8 sess_key[16];

	DEBUG(5,("cli_nt_login_general: %d\n", __LINE__));

#ifdef DEBUG_PASSWORD

	DEBUG(100,("\"general\" user password: "));
	dump_data(100, general, strlen(general));
#endif

	if (!cli_get_sesskey_srv(srv_name, sess_key))
	{
		DEBUG(1,("could not obtain session key for %s\n", srv_name));
		return False;
	}

	/* indicate an "general" login */
	ctr->switch_value = GENERAL_LOGON_TYPE;

	/* Create the structure needed for SAM logon. */
	make_id_info4(&ctr->auth.id4, domain, 0, 
	                            luid_low, 0,
	                            username, myhostname,
	                            general);

	/* Send client sam-logon request - update credentials on success. */
	return cli_net_sam_logon(srv_name, myhostname, ctr, user_info3);
}

/****************************************************************************
NT login - interactive.
*NEVER* use this code. This method of doing a logon (sending the cleartext
password equivalents, protected by the session key) is inherently insecure
given the current design of the NT Domain system. JRA.
 ****************************************************************************/
BOOL cli_nt_login_interactive(const char* srv_name, const char* myhostname,
				const char *domain, const char *username, 
				uint32 luid_low,
				uchar *lm_owf_user_pwd,
				uchar *nt_owf_user_pwd,
				NET_ID_INFO_CTR *ctr,
				NET_USER_INFO_3 *user_info3)
{
	BOOL ret;
	uint8 sess_key[16];

	DEBUG(5,("cli_nt_login_interactive: %d\n", __LINE__));

	dump_data_pw("nt owf of user password:\n", lm_owf_user_pwd, 16);
	dump_data_pw("nt owf of user password:\n", nt_owf_user_pwd, 16);

	if (!cli_get_sesskey_srv(srv_name, sess_key))
	{
		DEBUG(1,("could not obtain session key for %s\n", srv_name));
		return False;
	}

	/* indicate an "interactive" login */
	ctr->switch_value = INTERACTIVE_LOGON_TYPE;

	/* Create the structure needed for SAM logon. */
	make_id_info1(&ctr->auth.id1, domain, 0, 
	                            luid_low, 0,
	                            username, myhostname,
	                            (char *)sess_key,
	                            lm_owf_user_pwd, nt_owf_user_pwd);

	/* Ensure we overwrite all the plaintext password
	equivalents. */
	if (lm_owf_user_pwd != NULL)
	{
		memset(lm_owf_user_pwd, 0, 16);
	}
	if (nt_owf_user_pwd != NULL)
	{
		memset(nt_owf_user_pwd, 0, 16);
	}

	/* Send client sam-logon request - update credentials on success. */
	ret = cli_net_sam_logon(srv_name, myhostname, ctr, user_info3);

	memset(ctr->auth.id1.lm_owf.data, '\0',
	       sizeof(ctr->auth.id1.lm_owf.data));
	memset(ctr->auth.id1.nt_owf.data, '\0',
	       sizeof(ctr->auth.id1.nt_owf.data));

	return ret;
}

/****************************************************************************
NT login - network.
*ALWAYS* use this call to validate a user as it does not expose plaintext
password equivalents over the network. JRA.
****************************************************************************/

BOOL cli_nt_login_network(const char* srv_name, const char* myhostname,
				const char *domain, const char *username, 
				uint32 luid_low, char lm_chal[8],
				char *lm_chal_resp,
				int lm_chal_len,
				char *nt_chal_resp,
				int nt_chal_len,
				NET_ID_INFO_CTR *ctr,
				NET_USER_INFO_3 *user_info3)
{
	uint8 sess_key[16];
	BOOL ret;
	DEBUG(5,("cli_nt_login_network: %d\n", __LINE__));

	if (!cli_get_sesskey_srv(srv_name, sess_key))
	{
		DEBUG(1,("could not obtain session key for %s\n", srv_name));
		return False;
	}

	/* indicate a "network" login */
	ctr->switch_value = NETWORK_LOGON_TYPE;

	/* Create the structure needed for SAM logon. */
	make_id_info2(&ctr->auth.id2, domain, 0, 
		luid_low, 0,
		username, myhostname,
		(uchar *)lm_chal,
	        (uchar *)lm_chal_resp, lm_chal_len,
	        (uchar *)nt_chal_resp, nt_chal_len);

	/* Send client sam-logon request - update credentials on success. */
	ret = cli_net_sam_logon(srv_name, myhostname, ctr, user_info3);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("cli sess key:"));
	dump_data(100, sess_key, 8);
	DEBUG(100,("enc padding:"));
	dump_data(100, user_info3->padding, 8);
	DEBUG(100,("enc user sess key:"));
	dump_data(100, user_info3->user_sess_key, 16);
#endif

	SamOEMhash(user_info3->user_sess_key, sess_key, 0);
	SamOEMhash(user_info3->padding      , sess_key, 3);

#ifdef DEBUG_PASSWORD
	DEBUG(100,("dec paddin:"));
	dump_data(100, user_info3->padding, 8);
	DEBUG(100,("dec user sess key:"));
	dump_data(100, user_info3->user_sess_key, 16);
#endif
	return ret;
}

/****************************************************************************
NT Logoff.
****************************************************************************/
BOOL cli_nt_logoff(const char* srv_name, const char* myhostname,
				NET_ID_INFO_CTR *ctr)
{
  DEBUG(5,("cli_nt_logoff: %d\n", __LINE__));

  /* Send client sam-logoff request - update credentials on success. */
  return cli_net_sam_logoff(srv_name, myhostname, ctr);
}

/****************************************************************************
NT SAM database sync
****************************************************************************/
BOOL net_sam_sync(const char* srv_name,
				const char* domain,
				const char* myhostname,
				const char* trust_acct,
				uchar trust_passwd[16],
				SAM_DELTA_HDR hdr_deltas[MAX_SAM_DELTAS],
				SAM_DELTA_CTR deltas    [MAX_SAM_DELTAS],
				uint32 *num_deltas)
{
	BOOL res = True;

	*num_deltas = 0;

	DEBUG(5,("Attempting SAM sync with PDC: %s\n",
		srv_name));

	res = res ? cli_nt_setup_creds( srv_name, domain, myhostname,
	                               trust_acct, 
	                               trust_passwd, SEC_CHAN_BDC) == 0x0 : False;

	memset(trust_passwd, 0, 16);

	res = res ? cli_net_sam_sync(srv_name, myhostname,
	                             0, num_deltas, hdr_deltas, deltas) : False;

	if (!res)
	{
		DEBUG(5, ("SAM synchronisation FAILED\n"));
		return False;
	}

	DEBUG(5, ("SAM synchronisation returned %d entries\n", *num_deltas));

	return True;
}

