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
extern pstring scope;
extern pstring global_myname;

/*********************************************************
 Change the domain password on the PDC.
**********************************************************/

static BOOL modify_trust_password( char *domain, char *remote_machine, 
                          unsigned char orig_trust_passwd_hash[16],
                          unsigned char new_trust_passwd_hash[16],
                          uint16 sec_chan)
{
	struct nmb_name calling, called;
	fstring trust_acct;
	fstring srv_name;

	fstrcpy(srv_name, "\\\\");
	fstrcat(srv_name, remote_machine);
	strupper(srv_name);

	fstrcpy(trust_acct, global_myname);
	fstrcat(trust_acct, "$");

	make_nmb_name(&calling, global_myname , 0x0 , scope);
	make_nmb_name(&called , remote_machine, 0x20, scope);

	if (cli_nt_setup_creds(srv_name, domain, global_myname, trust_acct,
	                       orig_trust_passwd_hash, sec_chan) != 0x0)
	{
		return False;
	} 

	if (!cli_nt_srv_pwset( srv_name, global_myname, trust_acct,
	                       new_trust_passwd_hash,
	                       sec_chan ) )
	{
		return False;
	}

	return True;
}

/************************************************************************
 Change the trust account password for a domain.
 The user of this function must have locked the trust password file for
 update.
************************************************************************/

BOOL change_trust_account_password(char *domain, char *remote_machine_list,
					uint16 sec_chan)
{
  fstring remote_machine;
  unsigned char old_trust_passwd_hash[16];
  unsigned char new_trust_passwd_hash[16];
  time_t lct;
  BOOL res;

  if(!get_trust_account_password( old_trust_passwd_hash, &lct)) {
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
    if(modify_trust_password( domain, remote_machine, 
                old_trust_passwd_hash, new_trust_passwd_hash, sec_chan)) {
      DEBUG(0,("%s : change_trust_account_password: Changed password for \
domain %s.\n", timestring(), domain));
      /*
       * Return the result of trying to write the new password
       * back into the trust account file.
       */
      res = set_trust_account_password(new_trust_passwd_hash);
      memset(new_trust_passwd_hash, 0, 16);
      memset(old_trust_passwd_hash, 0, 16);
      return res;
    }
  }

  memset(new_trust_passwd_hash, 0, 16);
  memset(old_trust_passwd_hash, 0, 16);

  DEBUG(0,("%s : change_trust_account_password: Failed to change password for \
domain %s.\n", timestring(), domain));
  return False;
}

