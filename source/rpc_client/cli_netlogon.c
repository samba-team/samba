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


#include "includes.h"

extern pstring global_myname;
extern fstring global_myworkgroup;

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
BOOL cli_net_logon_ctrl2(struct cli_state *cli, NTSTATUS status_level)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_LOGON_CTRL2 q_l;
  BOOL ok = False;

  prs_init(&buf , 1024, cli->mem_ctx, MARSHALL);
  prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

  /* create and send a MSRPC command with api NET_LOGON_CTRL2 */

  DEBUG(4,("do_net_logon_ctrl2 from %s status level:%x\n",
           global_myname, status_level));

  /* store the parameters */
  init_q_logon_ctrl2(&q_l, unix_to_dos_static(cli->srv_name_slash), 
		     status_level);

  /* turn parameters into data stream */
  if(!net_io_q_logon_ctrl2("", &q_l,  &buf, 0)) {
    DEBUG(0,("cli_net_logon_ctrl2: Error : failed to marshall NET_Q_LOGON_CTRL2 struct.\n"));
    prs_mem_free(&buf);
    prs_mem_free(&rbuf);
    return False;
  }

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, NET_LOGON_CTRL2, &buf, &rbuf))
  {
    NET_R_LOGON_CTRL2 r_l;

    /*
     * Unmarshall the return buffer.
     */
    ok = net_io_r_logon_ctrl2("", &r_l, &rbuf, 0);
		
    if (ok && r_l.status != 0)
    {
      /* report error code */
      DEBUG(0,("do_net_logon_ctrl2: Error %s\n", get_nt_error_msg(r_l.status)));
      cli->nt_error = r_l.status;
      ok = False;
    }
  }

  prs_mem_free(&buf);
  prs_mem_free(&rbuf);

  return ok;
}
#endif

/****************************************************************************
LSA Authenticate 2

Send the client credential, receive back a server credential.
Ensure that the server credential returned matches the session key 
encrypt of the server challenge originally received. JRA.
****************************************************************************/

NTSTATUS cli_net_auth2(struct cli_state *cli, uint16 sec_chan, 
                   uint32 neg_flags, DOM_CHAL *srv_chal)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_AUTH_2 q_a;
  BOOL ok = False;
  NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

  prs_init(&buf , 1024, cli->mem_ctx, MARSHALL);
  prs_init(&rbuf, 0,    cli->mem_ctx, UNMARSHALL);

  /* create and send a MSRPC command with api NET_AUTH2 */

  DEBUG(4,("cli_net_auth2: srv:%s acct:%s sc:%x mc: %s chal %s neg: %x\n",
	   cli->srv_name_slash, cli->mach_acct, sec_chan, global_myname,
	   credstr(cli->clnt_cred.challenge.data), neg_flags));

  /* store the parameters */
  init_q_auth_2(&q_a, unix_to_dos_static(cli->srv_name_slash), cli->mach_acct, 
		sec_chan, global_myname, &cli->clnt_cred.challenge, neg_flags);

  /* turn parameters into data stream */
  if(!net_io_q_auth_2("", &q_a,  &buf, 0)) {
    DEBUG(0,("cli_net_auth2: Error : failed to marshall NET_Q_AUTH_2 struct.\n"));
    prs_mem_free(&buf);
    prs_mem_free(&rbuf);
    return result;
  }

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, NET_AUTH2, &buf, &rbuf))
  {
    NET_R_AUTH_2 r_a;

    ok = net_io_r_auth_2("", &r_a, &rbuf, 0);
    result = r_a.status;
		
    if (ok && !NT_STATUS_IS_OK(result))
    {
      /* report error code */
      DEBUG(0,("cli_net_auth2: Error %s\n", get_nt_error_msg(result)));
      ok = False;
    }

    if (ok)
    {
      /* 
       * Check the returned value using the initial
       * server received challenge.
       */
      UTIME zerotime;

      zerotime.time = 0;
      if(cred_assert( &r_a.srv_chal, cli->sess_key, srv_chal, zerotime) == 0) {
        /*
         * Server replied with bad credential. Fail.
         */
        DEBUG(0,("cli_net_auth2: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
        ok = False;
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
      DEBUG(0,("cli_net_auth2: error neg_flags (q,r) differ - (%x,%x)\n",
          q_a.clnt_flgs.neg_flags, r_a.srv_flgs.neg_flags));
      ok = False;
    }
#endif

  }

  prs_mem_free(&buf);
  prs_mem_free(&rbuf);

  return result;
}

/****************************************************************************
LSA Request Challenge. Sends our challenge to server, then gets
server response. These are used to generate the credentials.
****************************************************************************/

BOOL cli_net_req_chal(struct cli_state *cli, DOM_CHAL *clnt_chal, DOM_CHAL *srv_chal)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_REQ_CHAL q_c;
  BOOL valid_chal = False;

  prs_init(&buf , 1024, cli->mem_ctx, MARSHALL);
  prs_init(&rbuf, 0, cli->mem_ctx, UNMARSHALL);

  /* create and send a MSRPC command with api NET_REQCHAL */

  DEBUG(4,("cli_net_req_chal: LSA Request Challenge from %s to %s: %s\n",
         cli->desthost, global_myname, credstr(clnt_chal->data)));

  /* store the parameters */
  init_q_req_chal(&q_c, unix_to_dos_static(cli->srv_name_slash), 
		  global_myname, clnt_chal);

  /* turn parameters into data stream */
  if(!net_io_q_req_chal("", &q_c,  &buf, 0)) {
    DEBUG(0,("cli_net_req_chal: Error : failed to marshall NET_Q_REQ_CHAL struct.\n"));
    prs_mem_free(&buf);
    prs_mem_free(&rbuf);
    return False;
  }

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, NET_REQCHAL, &buf, &rbuf))
  {
    NET_R_REQ_CHAL r_c;
    BOOL ok;

    ok = net_io_r_req_chal("", &r_c, &rbuf, 0);
		
    if (ok && !NT_STATUS_IS_OK(r_c.status))
    {
      /* report error code */
      DEBUG(0,("cli_net_req_chal: Error %s\n", get_nt_error_msg(r_c.status)));
      ok = False;
    }

    if (ok)
    {
      /* ok, at last: we're happy. return the challenge */
      memcpy(srv_chal, r_c.srv_chal.data, sizeof(srv_chal->data));
      valid_chal = True;
    }
  }

  prs_mem_free(&buf);
  prs_mem_free(&rbuf);

  return valid_chal;
}

/***************************************************************************
LSA Server Password Set.
****************************************************************************/

BOOL cli_net_srv_pwset(struct cli_state *cli, uint8 hashed_mach_pwd[16])
{
  prs_struct rbuf;
  prs_struct buf; 
  DOM_CRED new_clnt_cred;
  NET_Q_SRV_PWSET q_s;
  BOOL ok = False;
  uint16 sec_chan_type = 2;

  gen_next_creds( cli, &new_clnt_cred);

  prs_init(&buf , 1024, cli->mem_ctx, MARSHALL);
  prs_init(&rbuf, 0,    cli->mem_ctx, UNMARSHALL);

  /* create and send a MSRPC command with api NET_SRV_PWSET */

  DEBUG(4,("cli_net_srv_pwset: srv:%s acct:%s sc: %d mc: %s clnt %s %x\n",
           cli->srv_name_slash, cli->mach_acct, sec_chan_type, global_myname,
           credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time));

  /* store the parameters */
  init_q_srv_pwset(&q_s, unix_to_dos_static(cli->srv_name_slash), 
		   cli->mach_acct, sec_chan_type, global_myname, 
		   &new_clnt_cred, (char *)hashed_mach_pwd);

  /* turn parameters into data stream */
  if(!net_io_q_srv_pwset("", &q_s,  &buf, 0)) {
    DEBUG(0,("cli_net_srv_pwset: Error : failed to marshall NET_Q_SRV_PWSET struct.\n"));
    prs_mem_free(&buf);
    prs_mem_free(&rbuf);
    return False;
  }

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, NET_SRVPWSET, &buf, &rbuf))
  {
    NET_R_SRV_PWSET r_s;

    ok = net_io_r_srv_pwset("", &r_s, &rbuf, 0);
		
    if (ok && !NT_STATUS_IS_OK(r_s.status))
    {
      /* report error code */
      DEBUG(0,("cli_net_srv_pwset: %s\n", get_nt_error_msg(r_s.status)));
      ok = False;
    }

    /* Update the credentials. */
    if (ok && !clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &(r_s.srv_cred)))
    {
      /*
       * Server replied with bad credential. Fail.
       */
      DEBUG(0,("cli_net_srv_pwset: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
      ok = False;
    }
  }

  prs_mem_free(&buf);
  prs_mem_free(&rbuf);

  return ok;
}

/***************************************************************************
 LSA SAM Logon internal - interactive or network. Does level 2 or 3 but always
 returns level 3.
****************************************************************************/

static NTSTATUS cli_net_sam_logon_internal(struct cli_state *cli, NET_ID_INFO_CTR *ctr, 
					   NET_USER_INFO_3 *user_info3, 
					   uint16 validation_level)
{
	DOM_CRED new_clnt_cred;
	DOM_CRED dummy_rtn_creds;
	prs_struct rbuf;
	prs_struct buf; 
	NET_Q_SAM_LOGON q_s;
	NET_R_SAM_LOGON r_s;
	NTSTATUS retval = NT_STATUS_OK;

	gen_next_creds( cli, &new_clnt_cred);

	prs_init(&buf , 1024, cli->mem_ctx, MARSHALL);
	prs_init(&rbuf, 0,    cli->mem_ctx, UNMARSHALL);

	/* create and send a MSRPC command with api NET_SAMLOGON */

	DEBUG(4,("cli_net_sam_logon_internal: srv:%s mc:%s clnt %s %x ll: %d\n",
             cli->srv_name_slash, global_myname, 
             credstr(new_clnt_cred.challenge.data), cli->clnt_cred.timestamp.time,
             ctr->switch_value));

	memset(&dummy_rtn_creds, '\0', sizeof(dummy_rtn_creds));
	dummy_rtn_creds.timestamp.time = time(NULL);

	/* store the parameters */
	q_s.validation_level = validation_level;
	init_sam_info(&q_s.sam_id, unix_to_dos_static(cli->srv_name_slash), 
		global_myname, &new_clnt_cred, &dummy_rtn_creds, 
		ctr->switch_value, ctr);

	/* turn parameters into data stream */
	if(!net_io_q_sam_logon("", &q_s,  &buf, 0)) {
		DEBUG(0,("cli_net_sam_logon_internal: Error : failed to marshall NET_Q_SAM_LOGON struct.\n"));
		retval = NT_STATUS_NO_MEMORY;
		goto out;
	}

	/* send the data on \PIPE\ */
	if (!rpc_api_pipe_req(cli, NET_SAMLOGON, &buf, &rbuf)) {
		DEBUG(0,("cli_net_sam_logon_internal: Error rpc_api_pipe_req failed.\n"));
                retval = NT_STATUS_UNSUCCESSFUL;
		goto out;
	}

	r_s.user = user_info3;

	if(!net_io_r_sam_logon("", &r_s, &rbuf, 0)) {
		DEBUG(0,("cli_net_sam_logon_internal: Error : failed to unmarshal NET_R_SAM_LOGON struct.\n"));
		retval = NT_STATUS_NO_MEMORY;
		goto out;
	}
		
	retval = r_s.status;

	/*
	 * Don't treat NT_STATUS_INVALID_INFO_CLASS as an error - we will re-issue
	 * the call.
	 */
	
	if (NT_STATUS_V(retval) == NT_STATUS_V(NT_STATUS_INVALID_INFO_CLASS)) {
		goto out;
	}

	if (!NT_STATUS_IS_OK(retval)) {
		/* report error code */
		DEBUG(0,("cli_net_sam_logon_internal: %s\n", get_nt_error_msg(r_s.status)));
		goto out;
    }

    /* Update the credentials. */
    if (!clnt_deal_with_creds(cli->sess_key, &cli->clnt_cred, &r_s.srv_creds)) {
		/*
		 * Server replied with bad credential. Fail.
		 */
		DEBUG(0,("cli_net_sam_logon_internal: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
		retval = NT_STATUS_WRONG_PASSWORD;
    }

    if (r_s.switch_value != validation_level) {
		/* report different switch_value */
		DEBUG(0,("cli_net_sam_logon: switch_value of %x expected %x\n", (unsigned int)validation_level,
					(unsigned int)r_s.switch_value));
		retval = NT_STATUS_INVALID_PARAMETER;
    }

  out:

	prs_mem_free(&buf);
	prs_mem_free(&rbuf);

	return retval;
}

/***************************************************************************
LSA SAM Logon - interactive or network.
****************************************************************************/

NTSTATUS cli_net_sam_logon(struct cli_state *cli, NET_ID_INFO_CTR *ctr, 
                         NET_USER_INFO_3 *user_info3)
{
	uint16 validation_level=3;
	NTSTATUS result;

	result = cli_net_sam_logon_internal(cli, ctr, user_info3, 
                                            validation_level);

	if (NT_STATUS_IS_OK(result)) {
		DEBUG(10,("cli_net_sam_logon: Success \n"));
	} else if (NT_STATUS_V(result) == NT_STATUS_V(NT_STATUS_INVALID_INFO_CLASS)) {
		DEBUG(10,("cli_net_sam_logon: STATUS INVALID INFO CLASS \n"));

		validation_level=2;

		/*
		 * Since this is the second time we call this function, don't care
		 * for the error. If its error, return False. 
		 */

		result = cli_net_sam_logon_internal(cli, ctr, user_info3,
                                                    validation_level);
	}

	return result;
}

/***************************************************************************
LSA SAM Logoff.

This currently doesnt work correctly as the domain controller 
returns NT_STATUS_INVALID_INFO_CLASS - we obviously need to
send a different info level. Right now though, I'm not sure
what that needs to be (I need to see one on the wire before
I can be sure). JRA.
****************************************************************************/
BOOL cli_net_sam_logoff(struct cli_state *cli, NET_ID_INFO_CTR *ctr)
{
  DOM_CRED new_clnt_cred;
  DOM_CRED dummy_rtn_creds;
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_SAM_LOGOFF q_s;
  BOOL ok = False;

  gen_next_creds( cli, &new_clnt_cred);

  prs_init(&buf , 1024, cli->mem_ctx, MARSHALL);
  prs_init(&rbuf, 0,    cli->mem_ctx, UNMARSHALL);

  /* create and send a MSRPC command with api NET_SAMLOGOFF */

  DEBUG(4,("cli_net_sam_logoff: srv:%s mc:%s clnt %s %x ll: %d\n",
            cli->srv_name_slash, global_myname,
            credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time,
            ctr->switch_value));

  memset(&dummy_rtn_creds, '\0', sizeof(dummy_rtn_creds));

  init_sam_info(&q_s.sam_id, unix_to_dos_static(cli->srv_name_slash), 
		global_myname, &new_clnt_cred, &dummy_rtn_creds, 
		ctr->switch_value, ctr);

  /* turn parameters into data stream */
  if(!net_io_q_sam_logoff("", &q_s,  &buf, 0)) {
    DEBUG(0,("cli_net_sam_logoff: Error : failed to marshall NET_Q_SAM_LOGOFF struct.\n"));
    prs_mem_free(&buf);
    prs_mem_free(&rbuf);
    return False;
  }

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, NET_SAMLOGOFF, &buf, &rbuf))
  {
    NET_R_SAM_LOGOFF r_s;

    ok = net_io_r_sam_logoff("", &r_s, &rbuf, 0);
		
    if (ok && !NT_STATUS_IS_OK(r_s.status))
    {
      /* report error code */
      DEBUG(0,("cli_net_sam_logoff: %s\n", get_nt_error_msg(r_s.status)));
      ok = False;
    }

    /* Update the credentials. */
    if (ok && !clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &(r_s.srv_creds)))
    {
      /*
       * Server replied with bad credential. Fail.
       */
      DEBUG(0,("cli_net_sam_logoff: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
      ok = False;
    }
  }

  prs_mem_free(&buf);
  prs_mem_free(&rbuf);

  return ok;
}
