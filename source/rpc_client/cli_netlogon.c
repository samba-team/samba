
/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9.
 *  RPC Pipe client / server routines
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
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
do a LSA Logon Control2
****************************************************************************/

BOOL do_net_logon_ctrl2(struct cli_state *cli, uint16 fnum,
                        char *host_name, uint32 status_level)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_LOGON_CTRL2 q_l;
  BOOL valid_ctrl2 = False;
  fstring acct_name;

  if (host_name == NULL)
    return False;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  strcpy(acct_name, "\\\\");
  strcat(acct_name, host_name);

  /* create and send a MSRPC command with api NET_LOGON_CTRL2 */

  DEBUG(4,("LSA Logon Control2 from %s status level:%x\n",
           host_name, status_level));

  /* store the parameters */
  make_q_logon_ctrl2(&q_l, acct_name, status_level);

  /* turn parameters into data stream */
  net_io_q_logon_ctrl2("", &q_l,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, fnum, NET_LOGON_CTRL2, &buf, &rbuf))
  {
    NET_R_LOGON_CTRL2 r_l;
    BOOL ok;

    net_io_r_logon_ctrl2("", &r_l, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_l.status != 0)
    {
      /* report error code */
      DEBUG(0,("NET_R_LOGON_CTRL: %s\n", get_nt_error_msg(r_l.status)));
      ok = False;
    }

    if (ok)
    {
      valid_ctrl2 = True;
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return valid_ctrl2;
}

/****************************************************************************
do a LSA Authenticate 2
****************************************************************************/

BOOL do_net_auth2(struct cli_state *cli, uint16 fnum,
                  char *logon_srv, char *acct_name, uint16 sec_chan, 
                  char *comp_name, DOM_CHAL *clnt_chal, uint32 neg_flags, 
                  DOM_CHAL *srv_chal)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_AUTH_2 q_a;
  BOOL valid_chal = False;

  if (srv_chal == NULL || clnt_chal == NULL)
    return False;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );


  /* create and send a MSRPC command with api NET_AUTH2 */

  DEBUG(4,("LSA Authenticate 2: srv:%s acct:%s sc:%x mc: %s chal %s neg: %lx\n",
         logon_srv, acct_name, sec_chan, comp_name,
         credstr(clnt_chal->data), neg_flags));

  /* store the parameters */
  make_q_auth_2(&q_a, logon_srv, acct_name, sec_chan, comp_name,
                clnt_chal, neg_flags);

  /* turn parameters into data stream */
  net_io_q_auth_2("", &q_a,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, fnum, NET_AUTH2, &buf, &rbuf))
  {
    NET_R_AUTH_2 r_a;
    BOOL ok;

    net_io_r_auth_2("", &r_a, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_a.status != 0)
    {
      /* report error code */
      DEBUG(0,("NET_AUTH2: %s\n", get_nt_error_msg(r_a.status)));
      ok = False;
    }

    if (ok && r_a.srv_flgs.neg_flags != q_a.clnt_flgs.neg_flags)
    {
      /* report different neg_flags */
      DEBUG(0,("NET_AUTH2: error neg_flags (q,r) differ - (%lx,%lx)\n",
          q_a.clnt_flgs.neg_flags, r_a.srv_flgs.neg_flags));
      ok = False;
    }

    if (ok)
    {
      /* ok, at last: we're happy. return the challenge */
      memcpy(srv_chal, r_a.srv_chal.data, sizeof(srv_chal->data));
      valid_chal = True;
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return valid_chal;
}

/****************************************************************************
do a LSA Request Challenge
****************************************************************************/

BOOL do_net_req_chal(struct cli_state *cli, uint16 fnum,
                     char *desthost, char *myhostname,
                     DOM_CHAL *clnt_chal, DOM_CHAL *srv_chal)
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

  DEBUG(4,("LSA Request Challenge from %s to %s: %s\n",
         desthost, myhostname, credstr(clnt_chal->data)));

  /* store the parameters */
  make_q_req_chal(&q_c, desthost, myhostname, clnt_chal);

  /* turn parameters into data stream */
  net_io_q_req_chal("", &q_c,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, fnum, NET_REQCHAL, &buf, &rbuf))
  {
    NET_R_REQ_CHAL r_c;
    BOOL ok;

    net_io_r_req_chal("", &r_c, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_c.status != 0)
    {
      /* report error code */
      DEBUG(0,("NET_REQ_CHAL: %s\n", get_nt_error_msg(r_c.status)));
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
do a LSA Server Password Set
****************************************************************************/

BOOL do_net_srv_pwset(struct cli_state *cli, uint16 fnum,
                      uchar sess_key[16], DOM_CRED *sto_clnt_cred,
                      char *logon_srv, char *mach_acct, uint16 sec_chan_type,
                      char *comp_name, DOM_CRED *clnt_cred, DOM_CRED *srv_cred,
                      uint8 nt_owf_new_mach_pwd[16])
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_SRV_PWSET q_s;
  BOOL valid_cred = False;

  if (srv_cred == NULL || clnt_cred == NULL)
    return False;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );


  /* create and send a MSRPC command with api NET_SRV_PWSET */

  DEBUG(4,("LSA Server Password Set: srv:%s acct:%s sc: %d mc: %s clnt %s %lx\n",
           logon_srv, mach_acct, sec_chan_type, comp_name,
           credstr(clnt_cred->challenge.data), clnt_cred->timestamp.time));

  /* store the parameters */
  make_q_srv_pwset(&q_s, sess_key, logon_srv, mach_acct, sec_chan_type,
                   comp_name, clnt_cred, nt_owf_new_mach_pwd);

  /* turn parameters into data stream */
  net_io_q_srv_pwset("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, fnum, NET_SRVPWSET, &buf, &rbuf))
  {
    NET_R_SRV_PWSET r_s;
    BOOL ok;

    net_io_r_srv_pwset("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(0,("NET_R_SRV_PWSET: %s\n", get_nt_error_msg(r_s.status)));
      ok = False;
    }

    if (ok)
    {
      if (clnt_deal_with_creds(sess_key, sto_clnt_cred, &(r_s.srv_cred)))
      {
        DEBUG(5, ("do_net_srv_pwset: server credential check OK\n"));
        /* ok, at last: we're happy. return the challenge */
        memcpy(srv_cred, &(r_s.srv_cred), sizeof(r_s.srv_cred));
        valid_cred = True;
      }
      else
      {
        DEBUG(5, ("do_net_srv_pwset: server credential check failed\n"));
      }
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return valid_cred;
}

/***************************************************************************
do a LSA SAM Logon
****************************************************************************/

BOOL do_net_sam_logon(struct cli_state *cli, uint16 fnum,
                      uchar sess_key[8], DOM_CRED *sto_clnt_cred,
                      char *logon_srv, char *comp_name,
                      DOM_CRED *clnt_cred, DOM_CRED *rtn_cred,
                      uint16 logon_level, NET_ID_INFO_CTR *ctr,
                      uint16 validation_level, NET_USER_INFO_3 *user_info3,
                      DOM_CRED *srv_cred)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_SAM_LOGON q_s;
  BOOL valid_cred = False;

  if (srv_cred == NULL || clnt_cred == NULL || rtn_cred == NULL || user_info3 == NULL)
    return False;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );


  /* create and send a MSRPC command with api NET_SAMLOGON */

  DEBUG(4,("LSA SAM Logon: srv:%s mc:%s clnt %s %lx rtn: %s %lx ll: %d\n",
             logon_srv, comp_name, 
             credstr(clnt_cred->challenge.data), clnt_cred->timestamp.time,
             credstr(rtn_cred->challenge.data), rtn_cred ->timestamp.time,
             logon_level));

  /* store the parameters */
  make_sam_info(&(q_s.sam_id), logon_srv, comp_name,
         clnt_cred, rtn_cred, logon_level, ctr, validation_level);

  /* turn parameters into data stream */
  net_io_q_sam_logon("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, fnum, NET_SAMLOGON, &buf, &rbuf))
  {
    NET_R_SAM_LOGON r_s;
    BOOL ok;

    r_s.user = user_info3;

    net_io_r_sam_logon("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(0,("NET_SAMLOGON: %s\n", get_nt_error_msg(r_s.status)));
      ok = False;
    }

    if (ok && r_s.switch_value != 3)
    {
      /* report different switch_value */
      DEBUG(0,("NET_SAMLOGON: switch_value of 3 expected %x\n",
                   r_s.switch_value));
      ok = False;
    }

    if (ok)
    {
      if (clnt_deal_with_creds(sess_key, sto_clnt_cred, &(r_s.srv_creds)))
      {
        DEBUG(5, ("do_net_sam_logon: server credential check OK\n"));
        /* ok, at last: we're happy. return the challenge */
        memcpy(srv_cred, &(r_s.srv_creds), sizeof(r_s.srv_creds));
        valid_cred = True;
      }
      else
      {
        DEBUG(5, ("do_net_sam_logon: server credential check failed\n"));
      }
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return valid_cred;
}

/***************************************************************************
do a LSA SAM Logoff
****************************************************************************/

BOOL do_net_sam_logoff(struct cli_state *cli, uint16 fnum,
                       uchar sess_key[8], DOM_CRED *sto_clnt_cred,
                       char *logon_srv, char *comp_name,
                       DOM_CRED *clnt_cred, DOM_CRED *rtn_cred,
                       uint16 logon_level, NET_ID_INFO_CTR *ctr, 
                       uint16 validation_level, DOM_CRED *srv_cred)
{
  prs_struct rbuf;
  prs_struct buf; 
  NET_Q_SAM_LOGOFF q_s;
  BOOL valid_cred = False;

  if (srv_cred == NULL || clnt_cred == NULL || rtn_cred == NULL)
    return False;

  prs_init(&buf , 1024, 4, SAFETY_MARGIN, False);
  prs_init(&rbuf, 0,    4, SAFETY_MARGIN, True );

  /* create and send a MSRPC command with api NET_SAMLOGON */

  DEBUG(4,("LSA SAM Logoff: srv:%s mc:%s clnt %s %lx rtn: %s %lx ll: %d\n",
            logon_srv, comp_name,
            credstr(clnt_cred->challenge.data), clnt_cred->timestamp.time,
            credstr(rtn_cred->challenge.data), rtn_cred ->timestamp.time,
            logon_level));

  /* store the parameters */
  make_sam_info(&(q_s.sam_id), logon_srv, comp_name,
                clnt_cred, rtn_cred, logon_level, ctr, validation_level);

  /* turn parameters into data stream */
  net_io_q_sam_logoff("", &q_s,  &buf, 0);

  /* send the data on \PIPE\ */
  if (rpc_api_pipe_req(cli, fnum, NET_SAMLOGOFF, &buf, &rbuf))
  {
    NET_R_SAM_LOGOFF r_s;
    BOOL ok;

    net_io_r_sam_logoff("", &r_s, &rbuf, 0);
    ok = (rbuf.offset != 0);
		
    if (ok && r_s.status != 0)
    {
      /* report error code */
      DEBUG(0,("NET_SAMLOGOFF: %s\n", get_nt_error_msg(r_s.status)));
      ok = False;
    }

    if (ok)
    {
      if (clnt_deal_with_creds(sess_key, sto_clnt_cred, &(r_s.srv_creds)))
      {
        DEBUG(5, ("do_net_sam_logoff: server credential check OK\n"));
        /* ok, at last: we're happy. return the challenge */
        memcpy(srv_cred, &(r_s.srv_creds), sizeof(r_s.srv_creds));
        valid_cred = True;
      }
      else
      {
        DEBUG(5, ("do_net_sam_logoff: server credential check failed\n"));
      }
    }
  }

  prs_mem_free(&rbuf);
  prs_mem_free(&buf );

  return valid_cred;
}
