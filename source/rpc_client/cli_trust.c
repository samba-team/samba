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

/*********************************************************
 Change the domain password on the PDC.
**********************************************************/

static BOOL modify_trust_password( char *domain, char *remote_machine, 
                          unsigned char orig_trust_passwd_hash[16],
                          unsigned char new_trust_passwd_hash[16])
{
  struct cli_state cli;
  NTSTATUS result;
  DOM_SID domain_sid;

  /*
   * Ensure we have the domain SID for this domain.
   */

  if (!secrets_fetch_domain_sid(domain, &domain_sid)) {
    DEBUG(0, ("domain_client_validate: unable to fetch domain sid.\n"));
    return False;
  }

  ZERO_STRUCT(cli);
  if(cli_initialise(&cli) == NULL) {
    DEBUG(0,("modify_trust_password: unable to initialize client connection.\n"));
    return False;
  }

  if(!resolve_name( remote_machine, &cli.dest_ip, 0x20)) {
    DEBUG(0,("modify_trust_password: Can't resolve address for %s\n", remote_machine));
    cli_shutdown(&cli);
    return False;
  }

  if (ismyip(cli.dest_ip)) {
    DEBUG(0,("modify_trust_password: Machine %s is one of our addresses. Cannot add \
to ourselves.\n", remote_machine));
    cli_shutdown(&cli);
    return False;
  }

  if (!cli_connect(&cli, remote_machine, &cli.dest_ip)) {
    DEBUG(0,("modify_trust_password: unable to connect to SMB server on \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
    cli_shutdown(&cli);
    return False;
  }
  
  if (!attempt_netbios_session_request(&cli, global_myname, remote_machine, &cli.dest_ip)) {
    DEBUG(0,("modify_trust_password: machine %s rejected the NetBIOS session request.\n", 
      remote_machine ));
    cli_shutdown(&cli);
    return False;
  }

  cli.protocol = PROTOCOL_NT1;
    
  if (!cli_negprot(&cli)) {
    DEBUG(0,("modify_trust_password: machine %s rejected the negotiate protocol. \
Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
    cli_shutdown(&cli);
    return False;
  }

  if (cli.protocol != PROTOCOL_NT1) {
    DEBUG(0,("modify_trust_password: machine %s didn't negotiate NT protocol.\n", 
            remote_machine));
    cli_shutdown(&cli);
    return False;
  }
    
  /*
   * Do an anonymous session setup.
   */
    
  if (!cli_session_setup(&cli, "", "", 0, "", 0, "")) {
    DEBUG(0,("modify_trust_password: machine %s rejected the session setup. \
Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
    cli_shutdown(&cli);
    return False;
  }
    
  if (!(cli.sec_mode & 1)) {
    DEBUG(0,("modify_trust_password: machine %s isn't in user level security mode\n",
          remote_machine));
    cli_shutdown(&cli);
    return False;
  }
    
  if (!cli_send_tconX(&cli, "IPC$", "IPC", "", 1)) {
    DEBUG(0,("modify_trust_password: machine %s rejected the tconX on the IPC$ share. \
Error was : %s.\n", remote_machine, cli_errstr(&cli) ));
    cli_shutdown(&cli);
    return False;
  }

  /*
   * Ok - we have an anonymous connection to the IPC$ share.
   * Now start the NT Domain stuff :-).
   */

  if(cli_nt_session_open(&cli, PIPE_NETLOGON) == False) {
    DEBUG(0,("modify_trust_password: unable to open the domain client session to \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(&cli)));
    cli_nt_session_close(&cli);
    cli_ulogoff(&cli);
    cli_shutdown(&cli);
    return False;
  } 
  
  result = cli_nt_setup_creds(&cli, orig_trust_passwd_hash);

  if (!NT_STATUS_IS_OK(result)) {
    DEBUG(0,("modify_trust_password: unable to setup the PDC credentials to machine \
%s. Error was : %s.\n", remote_machine, get_nt_error_msg(result)));
    cli_nt_session_close(&cli);
    cli_ulogoff(&cli);
    cli_shutdown(&cli);
    return False;
  } 

  if( cli_nt_srv_pwset( &cli,new_trust_passwd_hash ) == False) {
    DEBUG(0,("modify_trust_password: unable to change password for machine %s in domain \
%s to Domain controller %s. Error was %s.\n", global_myname, domain, remote_machine, 
                            cli_errstr(&cli)));
    cli_close(&cli, cli.nt_pipe_fnum);
    cli_ulogoff(&cli);
    cli_shutdown(&cli);
    return False;
  }

  cli_nt_session_close(&cli);
  cli_ulogoff(&cli);
  cli_shutdown(&cli);

  return True;
}

/************************************************************************
 Change the trust account password for a domain.
 The user of this function must have locked the trust password file for
 update.
************************************************************************/

BOOL change_trust_account_password( char *domain, const char *remote_machine_list)
{
  fstring remote_machine;
  unsigned char old_trust_passwd_hash[16];
  unsigned char new_trust_passwd_hash[16];
  time_t lct;
  BOOL res = False;

  if(!secrets_fetch_trust_account_password(domain, old_trust_passwd_hash, &lct)) {
    DEBUG(0,("change_trust_account_password: unable to read the machine \
account password for domain %s.\n", domain));
    return False;
  }

  /*
   * Create the new (random) password.
   */
  generate_random_buffer( new_trust_passwd_hash, 16, True);

  while(remote_machine_list && 
	next_token(&remote_machine_list, remote_machine, 
		   LIST_SEP, sizeof(remote_machine))) {
    strupper(remote_machine);
    if(strequal(remote_machine, "*")) {

      /*
       * We have been asked to dynamcially determine the IP addresses of the PDC.
       */

      struct in_addr *ip_list = NULL;
      int count = 0;
      int i;

      /* Use the PDC *only* for this. */
      if(!get_dc_list(True, domain, &ip_list, &count))
        continue;

      /*
       * Try and connect to the PDC/BDC list in turn as an IP
       * address used as a string.
       */

      for(i = 0; i < count; i++) {
        fstring dc_name;
        if(!lookup_dc_name(global_myname, domain, &ip_list[i], dc_name))
          continue;
        if((res = modify_trust_password( domain, dc_name,
                                         old_trust_passwd_hash, new_trust_passwd_hash)))
          break;
      }

      SAFE_FREE(ip_list);

    } else {
      res = modify_trust_password( domain, remote_machine,
                                   old_trust_passwd_hash, new_trust_passwd_hash);
    }

    if(res) {
      DEBUG(0,("%s : change_trust_account_password: Changed password for \
domain %s.\n", timestring(False), domain));
      /*
       * Return the result of trying to write the new password
       * back into the trust account file.
       */
      res = secrets_store_trust_account_password(domain, new_trust_passwd_hash);
      memset(new_trust_passwd_hash, 0, 16);
      memset(old_trust_passwd_hash, 0, 16);
      return res;
    }
  }

  memset(new_trust_passwd_hash, 0, 16);
  memset(old_trust_passwd_hash, 0, 16);

  DEBUG(0,("%s : change_trust_account_password: Failed to change password for \
domain %s.\n", timestring(False), domain));
  return False;
}
