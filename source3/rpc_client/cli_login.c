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

/****************************************************************************
Initialize domain session credentials.
****************************************************************************/

BOOL cli_nt_setup_creds(struct cli_state *cli, unsigned char mach_pwd[16])
{
  DOM_CHAL clnt_chal;
  DOM_CHAL srv_chal;

  DOM_CHAL auth2_srv_chal;

  UTIME zerotime;

  RPC_IFACE abstract;
  RPC_IFACE transfer;

  /******************** initialise ********************************/

  zerotime.time = 0;

  /******************* Request Challenge ********************/

  generate_random_buffer( clnt_chal.data, 8, False);
	
  /* send a client challenge; receive a server challenge */
  if (!cli_net_req_chal(cli, &clnt_chal, &srv_chal))
  {
    DEBUG(0,("do_nt_session_open: request challenge failed\n"));
    return False;
  }

  /**************** Long-term Session key **************/

  /* calculate the session key */
  cred_session_key(&clnt_chal, &srv_chal, mach_pwd, sess_key);
  bzero(sess_key+8, 8);

  /******************* Authenticate 2 ********************/

  /* calculate auth-2 credentials */
  cred_create(sess_key, &clnt_chal, zerotime, &(clnt_cred->challenge));

  /* send client auth-2 challenge; receive an auth-2 challenge */
  if (!cli_net_auth2(cli, SEC_CHAN_WKSTA, 0x000001ff, 
                     &(cli->clnt_cred->challenge), &auth2_srv_chal))
  {
    DEBUG(0,("do_nt_session_open: auth2 challenge failed\n"));
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
                smb_userid, 0, username, myhostname,
                sess_key, lm_owf_user_pwd, nt_owf_user_pwd);
}
#endif

/****************************************************************************
 make network sam login info
 ****************************************************************************/

void make_nt_login_network(NET_ID_INFO_CTR *ctr, uint32 smb_userid, char *username,
                           char lm_chal[8], char lm_chal_resp[24], 
                           char nt_chal_resp[24])
{
  /* indicate a "network" login */
  ctr->switch_value = 2;

  /* this is used in both the SAM Logon and the SAM Logoff */
  make_id_info2(&ctr->auth.id2, myworkgroup, 0, smb_userid, 0,
                username, myhostname,
                lm_chal, lm_chal_resp, nt_chal_resp);
}

/****************************************************************************
NT login.
****************************************************************************/

BOOL cli_nt_login(struct cli_state *cli,
                 DOM_CRED *clnt_cred, DOM_CRED *rtn_cred,
                 NET_ID_INFO_CTR *ctr, NET_USER_INFO_3 *user_info3)
{
  DOM_CRED sam_logon_rtn_cred;
  DOM_CRED cred;
  fstring dest_srv;
  fstring my_host_name;

  DEBUG(5,("do_nt_login: %d\n", __LINE__));

  /*********************** SAM Logon **********************/

  cli->clnt_cred->timestamp.time = time(NULL);

  memcpy(&cred, cli->clnt_cred, sizeof(cred));

  /* calculate sam logon credentials */
  cred_create(sess_key, &(cli->clnt_cred->challenge),
              cred.timestamp, &(cred.challenge));

  strcpy(dest_srv, "\\\\");
  strcat(dest_srv, dest_host);
  strupper(dest_srv);

  fstrcpy(my_host_name, myhostname);
  strupper(my_host_name);

  /* send client sam-logon challenge */
  return cli_net_sam_logon(cli, dest_srv, my_host_name, 
                          &cred, &sam_logon_rtn_cred,
                          ctr->switch_value, ctr, 3, user_info3,
                          rtn_cred);
}

/****************************************************************************
nt sam logoff
****************************************************************************/

BOOL cli_nt_logoff(struct cli_state *cli, DOM_CRED *rtn_cred,
                  NET_ID_INFO_CTR *ctr, char *dest_host, char *myhostname)
{
  DOM_CRED sam_logoff_rtn_cred;
  DOM_CRED cred;
  fstring dest_srv;
  fstring my_host_name;

  DEBUG(5,("do_nt_logoff: %d\n", __LINE__));

  /*********************** SAM Logoff *********************/

  clnt_cred->timestamp.time = time(NULL);

  memcpy(&cred, cli->clnt_cred, sizeof(cred));

  /* calculate sam logoff credentials */
  cred_create(sess_key, &(cli->clnt_cred->challenge),
              cred.timestamp, &(cred.challenge));

  strcpy(dest_srv, "\\\\");
  strcat(dest_srv, dest_host);
  strupper(dest_srv);

  fstrcpy(my_host_name, myhostname);
  strupper(my_host_name);

  /* send client sam-logoff challenge; receive a sam-logoff challenge */
  return cli_net_sam_logoff(cli, fnum, sess_key, clnt_cred,
                           dest_srv, my_host_name, 
                           &cred, &sam_logoff_rtn_cred,
                           ctr->switch_value, ctr, 3,
                           rtn_cred);
}
