/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison                    1998.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#ifdef SYSLOG
#undef SYSLOG
#endif

#include "includes.h"

extern int DEBUGLEVEL;

/****************************************************************************
Generate the next creds to use.
****************************************************************************/

void gen_next_creds( struct ntdom_info *nt, DOM_CRED *new_clnt_cred)
{
  /*
   * Create the new client credentials.
   */

  nt->clnt_cred.timestamp.time = time(NULL);

  memcpy(new_clnt_cred, &nt->clnt_cred, sizeof(*new_clnt_cred));

  /* Calculate the new credentials. */
  cred_create(nt->sess_key, &(nt->clnt_cred.challenge),
              new_clnt_cred->timestamp, &(new_clnt_cred->challenge));

}

/****************************************************************************
do a LSA Logon Control2
****************************************************************************/
BOOL cli_net_logon_ctrl2(const char* srv_name, uint32 status_level)
{
	prs_struct rbuf;
	prs_struct buf; 
	NET_Q_LOGON_CTRL2 q_l;
	BOOL ok = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api NET_LOGON_CTRL2 */

	DEBUG(4,("net_logon_ctrl2 status level:%x\n", status_level));

	/* store the parameters */
	make_q_logon_ctrl2(&q_l, srv_name, 0, 0, status_level);

	/* turn parameters into data stream */
	net_io_q_logon_ctrl2("", &q_l,  &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, NET_LOGON_CTRL2, &buf, &rbuf))
	{
		NET_R_LOGON_CTRL2 r_l;

		net_io_r_logon_ctrl2("", &r_l, &rbuf, 0);
		ok = (rbuf.offset != 0);

		if (ok && r_l.status != 0)
		{
			/* report error code */
			DEBUG(5,("net_logon_ctrl2: Error %s\n", get_nt_error_msg(r_l.status)));
			ok = False;
		}
	}

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	cli_connection_unlink(con);
	return ok;
}

/****************************************************************************
LSA Authenticate 2

Send the client credential, receive back a server credential.
Ensure that the server credential returned matches the session key 
encrypt of the server challenge originally received. JRA.
****************************************************************************/

uint32 cli_net_auth2(const char *srv_name,
				const char *trust_acct, 
				const char *acct_name, 
				uint16 sec_chan, 
				uint32 neg_flags, DOM_CHAL *srv_chal)
{
	prs_struct rbuf;
	prs_struct buf; 
	NET_Q_AUTH_2 q_a;
	uint32 status = 0x0;
	uint8 sess_key[16];
	DOM_CRED clnt_cred;

	struct cli_connection *con = NULL;

	if (!cli_connection_getsrv(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

	if (!cli_get_con_sesskey(con, sess_key))
	{
		return False;
	}

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api NET_AUTH2 */

	DEBUG(4,("cli_net_auth2: srv:%s acct:%s sc:%x mc: %s neg: %x\n",
	          srv_name, trust_acct, sec_chan, acct_name,
	          neg_flags));

	cli_con_get_cli_cred(con, &clnt_cred);

	/* store the parameters */
	make_q_auth_2(&q_a, srv_name, trust_acct, sec_chan, acct_name,
	              &clnt_cred.challenge, neg_flags);

	/* turn parameters into data stream */
	net_io_q_auth_2("", &q_a,  &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, NET_AUTH2, &buf, &rbuf))
	{
		NET_R_AUTH_2 r_a;

		net_io_r_auth_2("", &r_a, &rbuf, 0);
		status = (rbuf.offset == 0) ? 0xC0000000 | NT_STATUS_INVALID_PARAMETER : 0;

		if (status == 0x0 && r_a.status != 0)
		{
			/* report error code */
			DEBUG(5,("cli_net_auth2: Error %s\n",
			          get_nt_error_msg(r_a.status)));
			status = r_a.status;
		}

		if (status == 0x0)
		{
			/*
			 * Check the returned value using the initial
			 * server received challenge.
			 */
			UTIME zerotime;

			zerotime.time = 0;
			if(cred_assert( &r_a.srv_chal, sess_key,
			                srv_chal, zerotime) == 0)
			{
				/*
				 * Server replied with bad credential. Fail.
				 */
				DEBUG(5,("cli_net_auth2: server %s replied \
with bad credential (bad trust account password ?).\n", srv_name));
				status = NT_STATUS_NETWORK_CREDENTIAL_CONFLICT | 0xC0000000;
			}
		}

#if 0
		/*
		 * Try commenting this out to see if this makes the connect
		 * work for a NT 3.51 PDC. JRA.
		 */

		if (ok && r_a.srv_flgs.neg_flags != q_a.clnt_flgs.neg_flags)
		{
			/* report different neg_flags */
			DEBUG(5,("cli_net_auth2: error neg_flags (q,r) differ - (%x,%x)\n",
			q_a.clnt_flgs.neg_flags, r_a.srv_flgs.neg_flags));
			ok = False;
		}
#endif

	}
	else
	{
		DEBUG(5,("rpc_con_pipe_req FAILED\n"));
		status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
	}

	DEBUG(5,("cli_net_auth2 status: %x\n", status));

	prs_mem_free(&rbuf);
	prs_mem_free(&buf );

	return status;
}

/****************************************************************************
LSA Request Challenge. Sends our challenge to server, then gets
server response. These are used to generate the credentials.
****************************************************************************/

uint32 cli_net_req_chal( const char *srv_name, const char* myhostname,
				DOM_CHAL *clnt_chal, DOM_CHAL *srv_chal)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_REQ_CHAL q_c;
    uint32 status = 0x0;

	struct cli_connection *con = NULL;

	if (!cli_connection_init(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

  if (srv_chal == NULL || clnt_chal == NULL)
    return 0xC0000000 | NT_STATUS_INVALID_PARAMETER;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_REQCHAL */

  DEBUG(4,("cli_net_req_chal: LSA Request Challenge from %s to %s: %s\n",
         srv_name, myhostname, credstr(clnt_chal->data)));

  /* store the parameters */
  make_q_req_chal(&q_c, srv_name, myhostname, clnt_chal);

  /* turn parameters into data stream */
  net_io_q_req_chal("", &q_c,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_con_pipe_req(con, NET_REQCHAL, &buf, &rbuf))
  {
    NET_R_REQ_CHAL r_c;

    net_io_r_req_chal("", &r_c, &rbuf, 0);
    status = (rbuf.offset == 0) ? 0xC0000000 | NT_STATUS_INVALID_PARAMETER : 0;
		
    if (status == 0x0 && r_c.status != 0)
    {
      /* report error code */
      DEBUG(5,("cli_net_req_chal: Error %s\n", get_nt_error_msg(r_c.status)));
	status = r_c.status;
    }

    if (status == 0x0)
    {
      /* ok, at last: we're happy. return the challenge */
      memcpy(srv_chal, r_c.srv_chal.data, sizeof(srv_chal->data));
    }
  }
  else
  {
    DEBUG(5,("rpc_con_pipe_req FAILED\n"));
    status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return status;
}

/***************************************************************************
LSA Server Password Set.
****************************************************************************/

BOOL cli_net_srv_pwset(const char* srv_name,
				const char* myhostname,
				const char* trust_acct,
				uint8 hashed_trust_pwd[16],
				uint16 sec_chan_type)
{
  prs_struct rbuf;
  prs_struct buf; 
  DOM_CRED new_clnt_cred;
  NET_Q_SRV_PWSET q_s;
  BOOL ok = False;
  unsigned char processed_new_pwd[16];
  /* Process the new password. */

	uint8 sess_key[16];
	
	struct cli_connection *con = NULL;

	if (!cli_connection_getsrv(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

	if (!cli_get_con_sesskey(con, sess_key))
	{
		return False;
	}

	cred_hash3( processed_new_pwd, hashed_trust_pwd, sess_key, 1);

  cli_con_gen_next_creds( con, &new_clnt_cred);

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_SRV_PWSET */

  DEBUG(4,("cli_net_srv_pwset: srv:%s acct:%s sc: %d mc: %s clnt %s %x\n",
           srv_name, trust_acct, sec_chan_type, myhostname,
           credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time));

  /* store the parameters */
  make_q_srv_pwset(&q_s, srv_name, trust_acct, sec_chan_type,
                   myhostname, &new_clnt_cred, (char *)processed_new_pwd);

  /* turn parameters into data stream */
  net_io_q_srv_pwset("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_con_pipe_req(con, NET_SRVPWSET, &buf, &rbuf))
  {
    NET_R_SRV_PWSET r_s;

    net_io_r_srv_pwset("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(5,("cli_net_srv_pwset: %s\n", get_nt_error_msg(r_s.status)));
      ok = False;
    }

    /* Update the credentials. */
    if (ok && !cli_con_deal_with_creds(con, &(r_s.srv_cred)))
    {
      /*
       * Server replied with bad credential. Fail.
       */
      DEBUG(5,("cli_net_srv_pwset: server %s replied with bad credential \
(bad trust account password ?).\n", srv_name));
      ok = False;
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return ok;
}

/***************************************************************************
LSA SAM Logon - interactive or network.
****************************************************************************/

BOOL cli_net_sam_logon(const char* srv_name, const char* myhostname,
				NET_ID_INFO_CTR *ctr, 
				NET_USER_INFO_3 *user_info3)
{
  DOM_CRED new_clnt_cred;
  DOM_CRED dummy_rtn_creds;
  prs_struct rbuf;
  prs_struct buf; 
  uint16 validation_level = 3;
  NET_Q_SAM_LOGON q_s;
  BOOL ok = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_getsrv(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

  cli_con_gen_next_creds( con, &new_clnt_cred);

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_SAMLOGON */

  DEBUG(4,("cli_net_sam_logon: srv:%s mc:%s ll: %d\n",
             srv_name, myhostname, 
             ctr->switch_value));

  memset(&dummy_rtn_creds, '\0', sizeof(dummy_rtn_creds));
	dummy_rtn_creds.timestamp.time = time(NULL);

  /* store the parameters */
  make_sam_info(&(q_s.sam_id), srv_name, myhostname,
         &new_clnt_cred, &dummy_rtn_creds, ctr->switch_value, ctr);

	q_s.validation_level = validation_level;

  /* turn parameters into data stream */
  net_io_q_sam_logon("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_con_pipe_req(con, NET_SAMLOGON, &buf, &rbuf))
  {
    NET_R_SAM_LOGON r_s;

    r_s.user = user_info3;

    net_io_r_sam_logon("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(5,("cli_net_sam_logon: %s\n", get_nt_error_msg(r_s.status)));
      ok = False;
    }

    /* Update the credentials. */
    if (ok && !cli_con_deal_with_creds(con, &(r_s.srv_creds)))
    {
      /*
       * Server replied with bad credential. Fail.
       */
      DEBUG(5,("cli_net_sam_logon: server %s replied with bad credential \
(bad trust account password ?).\n", srv_name));
        ok = False;
    }

    if (ok && r_s.switch_value != 3)
    {
      /* report different switch_value */
      DEBUG(5,("cli_net_sam_logon: switch_value of 3 expected %x\n",
                   r_s.switch_value));
      ok = False;
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return ok;
}

/***************************************************************************
LSA SAM Logoff.

This currently doesnt work correctly as the domain controller 
returns NT_STATUS_INVALID_INFO_CLASS - we obviously need to
send a different info level. Right now though, I'm not sure
what that needs to be (I need to see one on the wire before
I can be sure). JRA.
****************************************************************************/
BOOL cli_net_sam_logoff(const char* srv_name, const char* myhostname,
				NET_ID_INFO_CTR *ctr)
{
  DOM_CRED new_clnt_cred;
  DOM_CRED dummy_rtn_creds;
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_SAM_LOGOFF q_s;
  BOOL ok = False;

	struct cli_connection *con = NULL;

	if (!cli_connection_getsrv(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

  cli_con_gen_next_creds( con, &new_clnt_cred);

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_SAMLOGOFF */

  DEBUG(4,("cli_net_sam_logoff: srv:%s mc:%s clnt %s %x ll: %d\n",
            srv_name, myhostname,
            credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time,
            ctr->switch_value));

  memset(&dummy_rtn_creds, '\0', sizeof(dummy_rtn_creds));

  /* store the parameters */
  make_sam_info(&(q_s.sam_id), srv_name, myhostname,
                &new_clnt_cred, &dummy_rtn_creds, ctr->switch_value, ctr);

  /* turn parameters into data stream */
  net_io_q_sam_logoff("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_con_pipe_req(con, NET_SAMLOGOFF, &buf, &rbuf))
  {
    NET_R_SAM_LOGOFF r_s;

    net_io_r_sam_logoff("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(5,("cli_net_sam_logoff: %s\n", get_nt_error_msg(r_s.status)));
      ok = False;
    }

    /* Update the credentials. */
    if (ok && !cli_con_deal_with_creds(con, &(r_s.srv_creds)))
    {
      /*
       * Server replied with bad credential. Fail.
       */
      DEBUG(5,("cli_net_sam_logoff: server %s replied with bad credential \
(bad trust account password ?).\n", srv_name ));
      ok = False;
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return ok;
}

/***************************************************************************
Synchronise SAM Database (requires SEC_CHAN_BDC).
****************************************************************************/
BOOL cli_net_sam_sync( const char* srv_name, const char* myhostname,
				uint32 database_id,
				uint32 *num_deltas,
				SAM_DELTA_HDR *hdr_deltas,
				SAM_DELTA_CTR *deltas)
{
	NET_Q_SAM_SYNC q_s;
	prs_struct rbuf;
	prs_struct buf; 
	DOM_CRED new_clnt_cred;
	BOOL ok = False;
	uint8 sess_key[16];
	
	struct cli_connection *con = NULL;

	if (!cli_connection_getsrv(srv_name, PIPE_NETLOGON, &con))
	{
		return False;
	}

	if (!cli_get_con_sesskey(con, sess_key))
	{
		return False;
	}

	cli_con_gen_next_creds(con, &new_clnt_cred);
	
	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );
	
	/* create and send a MSRPC command with api NET_SAM_SYNC */
	
	make_q_sam_sync(&q_s, srv_name, myhostname,
			&new_clnt_cred, database_id);
	
	/* turn parameters into data stream */
	net_io_q_sam_sync("", &q_s,  &buf, 0);
	
	/* send the data on \PIPE\ */
	if (rpc_con_pipe_req(con, NET_SAM_SYNC, &buf, &rbuf))
	{
		NET_R_SAM_SYNC r_s;

		r_s.hdr_deltas = hdr_deltas;
		r_s.deltas = deltas;

		net_io_r_sam_sync("", sess_key, &r_s, &rbuf, 0);
		ok = (rbuf.offset != 0);

		if (ok && r_s.status != 0 && r_s.status != STATUS_MORE_ENTRIES)
		{
			/* report error code */
			DEBUG(5,("cli_net_sam_sync: %s\n", get_nt_error_msg(r_s.status)));
			ok = False;
		}
		
		/* Update the credentials. */
		if (ok && !cli_con_deal_with_creds(con, &(r_s.srv_creds)))
		{
			DEBUG(5,("cli_net_sam_sync: server %s replied with bad \
credential (bad trust account password ?).\n", srv_name));
			ok = False;
		}

		if (ok)
		{
			*num_deltas = r_s.num_deltas2;

			if (r_s.status == STATUS_MORE_ENTRIES)
			{
				DEBUG(5, ("(More entries)\n"));
			}
		}
	}
	
	prs_mem_free(&rbuf);
	prs_mem_free(&buf );
	
	return ok;
}
