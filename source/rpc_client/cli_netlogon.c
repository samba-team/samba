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
extern pstring global_myname;

/****************************************************************************
Generate the next creds to use.
****************************************************************************/

static void gen_next_creds( struct cli_state *cli, DOM_CRED *new_clnt_cred)
{
  /*
   * Create the new client credentials.
   */

  cli->clnt_cred.timestamp.time = time(NULL);

  memcpy(new_clnt_cred, &cli->clnt_cred, sizeof(*new_clnt_cred));

  /* Calculate the new credentials. */
  cred_create(cli->sess_key, &(cli->clnt_cred.challenge),
              new_clnt_cred->timestamp, &(new_clnt_cred->challenge));

}

#if UNUSED_CODE
/****************************************************************************
do a LSA Logon Control2
****************************************************************************/
BOOL cli_net_logon_ctrl2(struct cli_state *cli, uint16 nt_pipe_fnum, uint32 status_level)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_LOGON_CTRL2 q_l;
  BOOL ok = False;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_LOGON_CTRL2 */

  DEBUG(4,("do_net_logon_ctrl2 from %s status level:%x\n",
           global_myname, status_level));

  /* store the parameters */
  make_q_logon_ctrl2(&q_l, cli->srv_name_slash, status_level);

  /* turn parameters into data stream */
  net_io_q_logon_ctrl2("", &q_l,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, nt_pipe_fnum, NET_LOGON_CTRL2, &buf, &rbuf))
  {
    NET_R_LOGON_CTRL2 r_l;

    net_io_r_logon_ctrl2("", &r_l, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_l.status != 0)
    {
      /* report error code */
      DEBUG(5,("do_net_logon_ctrl2: Error %s\n", get_nt_error_msg(r_l.status)));
      cli->nt_error = r_l.status;
      ok = False;
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return ok;
}
#endif

/****************************************************************************
LSA Authenticate 2

Send the client credential, receive back a server credential.
Ensure that the server credential returned matches the session key 
encrypt of the server challenge originally received. JRA.
****************************************************************************/

uint32 cli_net_auth2(struct cli_state *cli, uint16 nt_pipe_fnum,
				const char *trust_acct, 
				const char *srv_name, uint16 sec_chan, 
				uint32 neg_flags, DOM_CHAL *srv_chal)
{
	prs_struct rbuf;
	prs_struct buf; 
	NET_Q_AUTH_2 q_a;
	uint32 status = 0x0;

	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

	/* create and send a MSRPC command with api NET_AUTH2 */

	DEBUG(4,("cli_net_auth2: srv:%s acct:%s sc:%x mc: %s chal %s neg: %x\n",
	          cli->srv_name_slash, cli->mach_acct, sec_chan, srv_name,
	          credstr(cli->clnt_cred.challenge.data), neg_flags));

	/* store the parameters */
	make_q_auth_2(&q_a, cli->srv_name_slash, trust_acct, sec_chan, srv_name,
	              &cli->clnt_cred.challenge, neg_flags);

	/* turn parameters into data stream */
	net_io_q_auth_2("", &q_a,  &buf, 0);

	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, nt_pipe_fnum, NET_AUTH2, &buf, &rbuf))
	{
		NET_R_AUTH_2 r_a;

		net_io_r_auth_2("", &r_a, &rbuf, 0);
		status = (rbuf.offset == 0) ? 0xC0000000 | NT_STATUS_INVALID_PARAMETER : 0;

		if (status == 0x0 && r_a.status != 0)
		{
			/* report error code */
			DEBUG(5,("cli_net_auth2: Error %s\n",
			          get_nt_error_msg(r_a.status)));
			cli->nt_error = r_a.status;
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
			if(cred_assert( &r_a.srv_chal, cli->sess_key, srv_chal, zerotime) == 0)
			{
				/*
				 * Server replied with bad credential. Fail.
				 */
				DEBUG(5,("cli_net_auth2: server %s replied with bad credential (bad machine \
				password ?).\n", cli->desthost ));
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
		DEBUG(5,("rpc_api_pipe_req FAILED\n"));
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

uint32 cli_net_req_chal(struct cli_state *cli, uint16 nt_pipe_fnum, 
				const char *srv_name,
				DOM_CHAL *clnt_chal, DOM_CHAL *srv_chal)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_REQ_CHAL q_c;
    uint32 status = 0x0;

  if (srv_chal == NULL || clnt_chal == NULL)
    return 0xC0000000 | NT_STATUS_INVALID_PARAMETER;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_REQCHAL */

  DEBUG(4,("cli_net_req_chal: LSA Request Challenge from %s to %s: %s\n",
         cli->desthost, srv_name, credstr(clnt_chal->data)));

  /* store the parameters */
  make_q_req_chal(&q_c, cli->srv_name_slash, srv_name, clnt_chal);

  /* turn parameters into data stream */
  net_io_q_req_chal("", &q_c,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, nt_pipe_fnum, NET_REQCHAL, &buf, &rbuf))
  {
    NET_R_REQ_CHAL r_c;

    net_io_r_req_chal("", &r_c, &rbuf, 0);
    status = (rbuf.offset == 0) ? 0xC0000000 | NT_STATUS_INVALID_PARAMETER : 0;
		
    if (status == 0x0 && r_c.status != 0)
    {
      /* report error code */
      DEBUG(5,("cli_net_req_chal: Error %s\n", get_nt_error_msg(r_c.status)));
      cli->nt_error = r_c.status;
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
    DEBUG(5,("rpc_api_pipe_req FAILED\n"));
    status = 0xC0000000 | NT_STATUS_ACCESS_DENIED;
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return status;
}

/***************************************************************************
LSA Server Password Set.
****************************************************************************/

BOOL cli_net_srv_pwset(struct cli_state *cli, uint16 nt_pipe_fnum,
		       uint8 hashed_mach_pwd[16], uint16 sec_chan_type)
{
  prs_struct rbuf;
  prs_struct buf; 
  DOM_CRED new_clnt_cred;
  NET_Q_SRV_PWSET q_s;
  BOOL ok = False;

  gen_next_creds( cli, &new_clnt_cred);

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_SRV_PWSET */

  DEBUG(4,("cli_net_srv_pwset: srv:%s acct:%s sc: %d mc: %s clnt %s %x\n",
           cli->srv_name_slash, cli->mach_acct, sec_chan_type, global_myname,
           credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time));

  /* store the parameters */
  make_q_srv_pwset(&q_s, cli->srv_name_slash, cli->mach_acct, sec_chan_type,
                   global_myname, &new_clnt_cred, (char *)hashed_mach_pwd);

  /* turn parameters into data stream */
  net_io_q_srv_pwset("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, nt_pipe_fnum, NET_SRVPWSET, &buf, &rbuf))
  {
    NET_R_SRV_PWSET r_s;

    net_io_r_srv_pwset("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(5,("cli_net_srv_pwset: %s\n", get_nt_error_msg(r_s.status)));
      cli->nt_error = r_s.status;
      ok = False;
    }

    /* Update the credentials. */
    if (ok && !clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &(r_s.srv_cred)))
    {
      /*
       * Server replied with bad credential. Fail.
       */
      DEBUG(5,("cli_net_srv_pwset: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
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

BOOL cli_net_sam_logon(struct cli_state *cli, uint16 nt_pipe_fnum, NET_ID_INFO_CTR *ctr, 
                       NET_USER_INFO_3 *user_info3)
{
  DOM_CRED new_clnt_cred;
  DOM_CRED dummy_rtn_creds;
  prs_struct rbuf;
  prs_struct buf; 
  uint16 validation_level = 3;
  NET_Q_SAM_LOGON q_s;
  BOOL ok = False;

  gen_next_creds( cli, &new_clnt_cred);

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_SAMLOGON */

  DEBUG(4,("cli_net_sam_logon: srv:%s mc:%s clnt %s %x ll: %d\n",
             cli->srv_name_slash, global_myname, 
             credstr(new_clnt_cred.challenge.data), cli->clnt_cred.timestamp.time,
             ctr->switch_value));

  memset(&dummy_rtn_creds, '\0', sizeof(dummy_rtn_creds));
	dummy_rtn_creds.timestamp.time = time(NULL);

  /* store the parameters */
  make_sam_info(&(q_s.sam_id), cli->srv_name_slash, global_myname,
         &new_clnt_cred, &dummy_rtn_creds, ctr->switch_value, ctr, validation_level);

  /* turn parameters into data stream */
  net_io_q_sam_logon("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, nt_pipe_fnum, NET_SAMLOGON, &buf, &rbuf))
  {
    NET_R_SAM_LOGON r_s;

    r_s.user = user_info3;

    net_io_r_sam_logon("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(5,("cli_net_sam_logon: %s\n", get_nt_error_msg(r_s.status)));
      cli->nt_error = r_s.status;
      ok = False;
    }

    /* Update the credentials. */
    if (ok && !clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &(r_s.srv_creds)))
    {
      /*
       * Server replied with bad credential. Fail.
       */
      DEBUG(5,("cli_net_sam_logon: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
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
BOOL cli_net_sam_logoff(struct cli_state *cli, uint16 nt_pipe_fnum, NET_ID_INFO_CTR *ctr)
{
  DOM_CRED new_clnt_cred;
  DOM_CRED dummy_rtn_creds;
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_SAM_LOGOFF q_s;
  uint16 validation_level = 3;
  BOOL ok = False;

  gen_next_creds( cli, &new_clnt_cred);

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_SAMLOGOFF */

  DEBUG(4,("cli_net_sam_logoff: srv:%s mc:%s clnt %s %x ll: %d\n",
            cli->srv_name_slash, global_myname,
            credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time,
            ctr->switch_value));

  memset(&dummy_rtn_creds, '\0', sizeof(dummy_rtn_creds));

  /* store the parameters */
  make_sam_info(&(q_s.sam_id), cli->srv_name_slash, global_myname,
                &new_clnt_cred, &dummy_rtn_creds, ctr->switch_value, ctr, validation_level);

  /* turn parameters into data stream */
  net_io_q_sam_logoff("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, nt_pipe_fnum, NET_SAMLOGOFF, &buf, &rbuf))
  {
    NET_R_SAM_LOGOFF r_s;

    net_io_r_sam_logoff("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(5,("cli_net_sam_logoff: %s\n", get_nt_error_msg(r_s.status)));
      cli->nt_error = r_s.status;
      ok = False;
    }

    /* Update the credentials. */
    if (ok && !clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &(r_s.srv_creds)))
    {
      /*
       * Server replied with bad credential. Fail.
       */
      DEBUG(5,("cli_net_sam_logoff: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
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
BOOL cli_net_sam_sync(struct cli_state *cli, uint16 nt_pipe_fnum, uint32 database_id, uint32 *num_deltas, SAM_DELTA_HDR *hdr_deltas, SAM_DELTA_CTR *deltas)
{
	NET_Q_SAM_SYNC q_s;
	prs_struct rbuf;
	prs_struct buf; 
	DOM_CRED new_clnt_cred;
	BOOL ok = False;
	
	gen_next_creds(cli, &new_clnt_cred);
	
	prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
	prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );
	
	/* create and send a MSRPC command with api NET_SAM_SYNC */
	
	make_q_sam_sync(&q_s, cli->srv_name_slash, global_myname,
			&new_clnt_cred, database_id);
	
	/* turn parameters into data stream */
	net_io_q_sam_sync("", &q_s,  &buf, 0);
	
	/* send the data on \PIPE\ */
	if (rpc_api_pipe_req(cli, nt_pipe_fnum, NET_SAM_SYNC, &buf, &rbuf))
	{
		NET_R_SAM_SYNC r_s;

		r_s.hdr_deltas = hdr_deltas;
		r_s.deltas = deltas;

		net_io_r_sam_sync("", cli->sess_key, &r_s, &rbuf, 0);
		ok = (rbuf.offset != 0);

		if (ok && r_s.status != 0 && r_s.status != STATUS_MORE_ENTRIES)
		{
			/* report error code */
			DEBUG(5,("cli_net_sam_sync: %s\n", get_nt_error_msg(r_s.status)));
			cli->nt_error = r_s.status;
			ok = False;
		}
		
		/* Update the credentials. */
		if (ok && !clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &(r_s.srv_creds)))
		{
			DEBUG(5,("cli_net_sam_sync: server %s replied with bad credential (bad machine password ?).\n", cli->desthost));
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


BOOL do_sam_sync(struct cli_state *cli, uchar trust_passwd[16],
				const char* srv_name,
				SAM_DELTA_HDR hdr_deltas[MAX_SAM_DELTAS],
				SAM_DELTA_CTR deltas    [MAX_SAM_DELTAS],
				uint32 *num_deltas)
{
	uint16 nt_pipe_fnum;
	BOOL res = True;

	*num_deltas = 0;

	DEBUG(5,("Attempting SAM sync with PDC, domain: %s name: %s\n",
		cli->domain, srv_name));

	/* open NETLOGON session.  negotiate credentials */
	res = res ? cli_nt_session_open(cli, PIPE_NETLOGON, &nt_pipe_fnum) : False;

	res = res ? cli_nt_setup_creds(cli, nt_pipe_fnum, 
	                               cli->mach_acct, srv_name,
	                               trust_passwd, SEC_CHAN_BDC) == 0x0 : False;

	memset(trust_passwd, 0, 16);

	res = res ? cli_net_sam_sync(cli, nt_pipe_fnum, 0, num_deltas, hdr_deltas, deltas) : False;

	/* close the session */
	cli_nt_session_close(cli, nt_pipe_fnum);

	if (!res)
	{
		DEBUG(5, ("SAM synchronisation FAILED\n"));
		return False;
	}

	DEBUG(5, ("SAM synchronisation returned %d entries\n", *num_deltas));

	return True;
}

