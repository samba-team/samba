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

/****************************************************************************
do a LSA Logon Control2
****************************************************************************/

BOOL cli_net_logon_ctrl2(struct cli_state *cli, uint32 status_level)
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
  if (rpc_api_pipe_req(cli, NET_LOGON_CTRL2, &buf, &rbuf))
  {
    NET_R_LOGON_CTRL2 r_l;

    net_io_r_logon_ctrl2("", &r_l, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_l.status != 0)
    {
      /* report error code */
      DEBUG(0,("do_net_logon_ctrl2: Error %s\n", get_nt_error_msg(r_l.status)));
      cli->nt_error = r_l.status;
      ok = False;
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return ok;
}

/****************************************************************************
LSA Authenticate 2

Send the client credential, receive back a server credential.
Ensure that the server credential returned matches the session key 
encrypt of the server challenge originally received. JRA.
****************************************************************************/

BOOL cli_net_auth2(struct cli_state *cli, uint16 sec_chan, 
                   uint32 neg_flags, DOM_CHAL *srv_chal)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_AUTH_2 q_a;
  BOOL ok = False;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_AUTH2 */

  DEBUG(4,("cli_net_auth2: srv:%s acct:%s sc:%x mc: %s chal %s neg: %lx\n",
         cli->srv_name_slash, cli->mach_acct, sec_chan, global_myname,
         credstr(cli->clnt_cred.challenge.data), neg_flags));

  /* store the parameters */
  make_q_auth_2(&q_a, cli->srv_name_slash, cli->mach_acct, sec_chan, global_myname,
                &cli->clnt_cred.challenge, neg_flags);

  /* turn parameters into data stream */
  net_io_q_auth_2("", &q_a,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, NET_AUTH2, &buf, &rbuf))
  {
    NET_R_AUTH_2 r_a;

    net_io_r_auth_2("", &r_a, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_a.status != 0)
    {
      /* report error code */
      DEBUG(0,("cli_net_auth2: Error %s\n", get_nt_error_msg(r_a.status)));
      cli->nt_error = r_a.status;
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

    if (ok && r_a.srv_flgs.neg_flags != q_a.clnt_flgs.neg_flags)
    {
      /* report different neg_flags */
      DEBUG(0,("cli_net_auth2: error neg_flags (q,r) differ - (%lx,%lx)\n",
          q_a.clnt_flgs.neg_flags, r_a.srv_flgs.neg_flags));
      ok = False;
    }

  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return ok;
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

  if (srv_chal == NULL || clnt_chal == NULL)
    return False;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_REQCHAL */

  DEBUG(4,("cli_net_req_chal: LSA Request Challenge from %s to %s: %s\n",
         cli->desthost, global_myname, credstr(clnt_chal->data)));

  /* store the parameters */
  make_q_req_chal(&q_c, cli->srv_name_slash, global_myname, clnt_chal);

  /* turn parameters into data stream */
  net_io_q_req_chal("", &q_c,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, NET_REQCHAL, &buf, &rbuf))
  {
    NET_R_REQ_CHAL r_c;
    BOOL ok;

    net_io_r_req_chal("", &r_c, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_c.status != 0)
    {
      /* report error code */
      DEBUG(0,("cli_net_req_chal: Error %s\n", get_nt_error_msg(r_c.status)));
      cli->nt_error = r_c.status;
      ok = False;
    }

    if (ok)
    {
      /* ok, at last: we're happy. return the challenge */
      memcpy(srv_chal, r_c.srv_chal.data, sizeof(srv_chal->data));
      valid_chal = True;
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

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

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_SRV_PWSET */

  DEBUG(4,("cli_net_srv_pwset: srv:%s acct:%s sc: %d mc: %s clnt %s %lx\n",
           cli->srv_name_slash, cli->mach_acct, sec_chan_type, global_myname,
           credstr(new_clnt_cred.challenge.data), new_clnt_cred.timestamp.time));

  /* store the parameters */
  make_q_srv_pwset(&q_s, cli->srv_name_slash, cli->mach_acct, sec_chan_type,
                   global_myname, &new_clnt_cred, (char *)hashed_mach_pwd);

  /* turn parameters into data stream */
  net_io_q_srv_pwset("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, NET_SRVPWSET, &buf, &rbuf))
  {
    NET_R_SRV_PWSET r_s;

    net_io_r_srv_pwset("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(0,("cli_net_srv_pwset: %s\n", get_nt_error_msg(r_s.status)));
      cli->nt_error = r_s.status;
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

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return ok;
}

/***************************************************************************
LSA SAM Logon - interactive or network.
****************************************************************************/

BOOL cli_net_sam_logon(struct cli_state *cli, NET_ID_INFO_CTR *ctr, 
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

  DEBUG(4,("cli_net_sam_logon: srv:%s mc:%s clnt %s %lx ll: %d\n",
             cli->srv_name_slash, global_myname, 
             credstr(new_clnt_cred.challenge.data), cli->clnt_cred.timestamp.time,
             ctr->switch_value));

  memset(&dummy_rtn_creds, '\0', sizeof(dummy_rtn_creds));

  /* store the parameters */
  make_sam_info(&(q_s.sam_id), cli->srv_name_slash, global_myname,
         &new_clnt_cred, &dummy_rtn_creds, ctr->switch_value, ctr, validation_level);

  /* turn parameters into data stream */
  net_io_q_sam_logon("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, NET_SAMLOGON, &buf, &rbuf))
  {
    NET_R_SAM_LOGON r_s;

    r_s.user = user_info3;

    net_io_r_sam_logon("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(0,("cli_net_sam_logon: %s\n", get_nt_error_msg(r_s.status)));
      cli->nt_error = r_s.status;
      ok = False;
    }

    /* Update the credentials. */
    if (ok && !clnt_deal_with_creds(cli->sess_key, &(cli->clnt_cred), &(r_s.srv_creds)))
    {
      /*
       * Server replied with bad credential. Fail.
       */
      DEBUG(0,("cli_net_sam_logon: server %s replied with bad credential (bad machine \
password ?).\n", cli->desthost ));
        ok = False;
    }

    if (ok && r_s.switch_value != 3)
    {
      /* report different switch_value */
      DEBUG(0,("cli_net_sam_logon: switch_value of 3 expected %x\n",
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

BOOL cli_net_sam_logoff(struct cli_state *cli, NET_ID_INFO_CTR *ctr)
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

  DEBUG(4,("cli_net_sam_logoff: srv:%s mc:%s clnt %s %lx ll: %d\n",
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
  if (rpc_api_pipe_req(cli, NET_SAMLOGOFF, &buf, &rbuf))
  {
    NET_R_SAM_LOGOFF r_s;

    net_io_r_sam_logoff("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(0,("cli_net_sam_logoff: %s\n", get_nt_error_msg(r_s.status)));
      cli->nt_error = r_s.status;
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

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return ok;
}
