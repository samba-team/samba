/* 
 *  Unix SMB/Netbios implementation.
 *  Version 3.0
 *  Periodic Trust account password changing.
 *  Copyright (C) Andrew Tridgell              1992-1997,
 *  Copyright (C) Luke Kenneth Casson Leighton 1996-1997,
 *  Copyright (C) Paul Ashton                       1997.
 *  Copyright (C) Jeremy Allison                    1998.
 *  Copyright (C) Andrew Bartlett                   2001.
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

static NTSTATUS modify_trust_password( char *domain, char *remote_machine, 
				   unsigned char orig_trust_passwd_hash[16])
{
  struct cli_state *cli;
  DOM_SID domain_sid;
  struct in_addr dest_ip;
  NTSTATUS nt_status;

  /*
   * Ensure we have the domain SID for this domain.
   */

  if (!secrets_fetch_domain_sid(domain, &domain_sid)) {
    DEBUG(0, ("domain_client_validate: unable to fetch domain sid.\n"));
    return NT_STATUS_UNSUCCESSFUL;
  }

  if(!resolve_name( remote_machine, &dest_ip, 0x20)) {
	  DEBUG(0,("modify_trust_password: Can't resolve address for %s\n", remote_machine));
	  return NT_STATUS_UNSUCCESSFUL;
  }
  
  if (!NT_STATUS_IS_OK(cli_full_connection(&cli, global_myname, remote_machine, 
					   &dest_ip, 0,
					   "IPC$", "IPC",  
					   "", "",
					   "", 0))) {
	  DEBUG(0,("modify_trust_password: Connection to %s failed!\n", remote_machine));
	  return NT_STATUS_UNSUCCESSFUL;
  }
      
  /*
   * Ok - we have an anonymous connection to the IPC$ share.
   * Now start the NT Domain stuff :-).
   */

  if(cli_nt_session_open(cli, PIPE_NETLOGON) == False) {
    DEBUG(0,("modify_trust_password: unable to open the domain client session to \
machine %s. Error was : %s.\n", remote_machine, cli_errstr(cli)));
    cli_nt_session_close(cli);
    cli_ulogoff(cli);
    cli_shutdown(cli);
    return NT_STATUS_UNSUCCESSFUL;
  } 

  nt_status = trust_pw_change_and_store_it(cli, cli->mem_ctx,
					   orig_trust_passwd_hash);
  
  cli_nt_session_close(cli);
  cli_ulogoff(cli);
  cli_shutdown(cli);
  return nt_status;
}

/************************************************************************
 Change the trust account password for a domain.
************************************************************************/

NTSTATUS change_trust_account_password( char *domain, char *remote_machine_list)
{
  fstring remote_machine;
  unsigned char old_trust_passwd_hash[16];
  time_t lct;
  NTSTATUS res = NT_STATUS_UNSUCCESSFUL;

  if(!secrets_fetch_trust_account_password(domain, old_trust_passwd_hash, &lct)) {
    DEBUG(0,("change_trust_account_password: unable to read the machine \
account password for domain %s.\n", domain));
    return NT_STATUS_UNSUCCESSFUL;
  }

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
        if(NT_STATUS_IS_OK(res = modify_trust_password( domain, dc_name,
                                         old_trust_passwd_hash)))
          break;
      }

      SAFE_FREE(ip_list);

    } else {
	    res = modify_trust_password( domain, remote_machine,
					 old_trust_passwd_hash);
    }

  }

  if (!NT_STATUS_IS_OK(res)) {
	  DEBUG(0,("%s : change_trust_account_password: Failed to change password for \
domain %s.\n", timestring(False), domain));
  }
  
  return res;
}
