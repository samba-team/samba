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

#include "includes.h"
#include "nterr.h"

extern int DEBUGLEVEL;
extern fstring global_myworkgroup;
extern pstring global_myname;

/****************************************************************************
Initialize domain session credentials.
****************************************************************************/

BOOL cli_nt_setup_creds(struct cli_state *cli, unsigned char mach_pwd[16])
{
  DOM_CHAL clnt_chal;
  DOM_CHAL srv_chal;

  UTIME zerotime;

  /******************* Request Challenge ********************/

  generate_random_buffer( clnt_chal.data, 8, False);
	
  /* send a client challenge; receive a server challenge */
  if (!cli_net_req_chal(cli, &clnt_chal, &srv_chal))
  {
    DEBUG(0,("cli_nt_setup_creds: request challenge failed\n"));
    return False;
  }

  /**************** Long-term Session key **************/

  /* calculate the session key */
  cred_session_key(&clnt_chal, &srv_chal, mach_pwd, cli->sess_key);
  bzero(cli->sess_key+8, 8);

  /******************* Authenticate 2 ********************/

  /* calculate auth-2 credentials */
  zerotime.time = 0;
  cred_create(cli->sess_key, &clnt_chal, zerotime, &(cli->clnt_cred.challenge));

  /*  
   * Send client auth-2 challenge.
   * Receive an auth-2 challenge response and check it.
   */

  if (!cli_net_auth2(cli, SEC_CHAN_WKSTA, 0x000001ff, &srv_chal))
  {
    DEBUG(0,("cli_nt_setup_creds: auth2 challenge failed\n"));
    return False;
  }

  return True;
}

#if 0
/****************************************************************************
 server password set
 ****************************************************************************/

BOOL do_nt_srv_pwset(struct cli_state *cli, 
                     uint8 sess_key[16], DOM_CRED *clnt_cred, DOM_CRED *rtn_cred,
                     char *new_mach_pwd,
                     char *dest_host, char *mach_acct, char *myhostname)
{
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
              cred.timestamp, &(cred.challenge));

  /* send client srv_pwset challenge */
  return do_net_srv_pwset(cli, fnum, sess_key, clnt_cred,
                          dest_host, mach_acct, 2, myhostname,
                          &cred, rtn_cred, nt_cypher);
}

/****************************************************************************
 make interactive sam login info
 ****************************************************************************/

void make_nt_login_interactive(NET_ID_INFO_CTR *ctr,
                               uchar sess_key[16],
                               char *domain, char *myhostname,
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
  make_id_info1(&ctr->auth.id1, domain, 0,
                smb_userid, 0, username, myhostname,
                sess_key, lm_owf_user_pwd, nt_owf_user_pwd);
}
#endif

/****************************************************************************
NT login.
****************************************************************************/

BOOL cli_nt_login_network(struct cli_state *cli, char *domain, char *username, 
                          uint32 smb_userid_low, char lm_chal[8], char lm_chal_resp[24],
                          char nt_chal_resp[24],
                          NET_ID_INFO_CTR *ctr, NET_USER_INFO_3 *user_info3)
{
  DEBUG(5,("cli_nt_login_network: %d\n", __LINE__));

  /* indicate a "network" login */
  ctr->switch_value = NET_LOGON_TYPE;

  /* Create the structure needed for SAM logon. */
  make_id_info2(&ctr->auth.id2, domain, 0, 
                smb_userid_low, 0,
                username, global_myname,
                lm_chal, lm_chal_resp, nt_chal_resp);

  /* Send client sam-logon request - update credentials on success. */
  return cli_net_sam_logon(cli, ctr, user_info3);
}

/****************************************************************************
NT Logoff.
****************************************************************************/

BOOL cli_nt_logoff(struct cli_state *cli, NET_ID_INFO_CTR *ctr)
{
  DEBUG(5,("cli_nt_logoff: %d\n", __LINE__));

  /* Send client sam-logoff request - update credentials on success. */
  return cli_net_sam_logoff(cli, ctr);
}
