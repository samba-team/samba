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
	uint16 nt_pipe_fnum;
	struct cli_state cli;
	struct nmb_name calling, called;

	make_nmb_name(&calling, global_myname , 0x0 , scope);
	make_nmb_name(&called , remote_machine, 0x20, scope);

	ZERO_STRUCT(cli);
	if(cli_initialise(&cli) == NULL)
	{
		DEBUG(0,("modify_trust_password: unable to initialize client \
connection.\n"));
		return False;
	}

	if(!resolve_name( remote_machine, &cli.dest_ip, 0x20))
	{
		DEBUG(0,("modify_trust_password: Can't resolve address for \
%s\n", remote_machine));
		return False;
	}

	if (ismyip(cli.dest_ip))
	{
		DEBUG(0,("modify_trust_password: Machine %s is one of our \
addresses. Cannot add to ourselves.\n", remote_machine));
		return False;
	}

	cli.protocol = PROTOCOL_NT1;

	pwd_set_nullpwd(&cli.usr.pwd);

	if (!cli_establish_connection(&cli, remote_machine, &cli.dest_ip,
	                              &calling, &called,
	                              "IPC$", "IPC", False, True))
	{
		fstring errstr;
		cli_safe_errstr(&cli, errstr, sizeof(errstr));
		DEBUG(0,("modify_trust_password: machine %s rejected the SMB \
session. Error was : %s.\n", remote_machine, errstr ));
		cli_shutdown(&cli);
		return False;
	}


	if (cli.protocol != PROTOCOL_NT1)
	{
		DEBUG(0,("modify_trust_password: machine %s didn't negotiate \
NT protocol.\n", remote_machine));
		cli_shutdown(&cli);
		return False;
	}

	if (!(IS_BITS_SET_ALL(cli.sec_mode, 1)))
	{
		DEBUG(0,("modify_trust_password: machine %s isn't in user \
level security mode\n", remote_machine));
		cli_shutdown(&cli);
		return False;
	}

	/*
	* Ok - we have an anonymous connection to the IPC$ share.
	* Now start the NT Domain stuff :-).
	*/

	if (!cli_nt_session_open(&cli, PIPE_NETLOGON, &nt_pipe_fnum))
	{
		fstring errstr;
		cli_safe_errstr(&cli, errstr, sizeof(errstr));
		DEBUG(0,("modify_trust_password: unable to open the domain \
client session to server %s. Error was : %s.\n", remote_machine, errstr ));
		cli_nt_session_close(&cli, nt_pipe_fnum);
		cli_ulogoff(&cli);
		cli_shutdown(&cli);
		return False;
	} 

	if (cli_nt_setup_creds(&cli, nt_pipe_fnum, 
	                       cli.mach_acct, global_myname,
	                       orig_trust_passwd_hash, sec_chan) != 0x0)
	{
		fstring errstr;
		cli_safe_errstr(&cli, errstr, sizeof(errstr));
		DEBUG(0,("modify_trust_password: unable to setup the PDC \
credentials to server %s. Error was : %s.\n", remote_machine, errstr ));
		cli_nt_session_close(&cli, nt_pipe_fnum);
		cli_ulogoff(&cli);
		cli_shutdown(&cli);
		return False;
	} 

	if (!cli_nt_srv_pwset( &cli, nt_pipe_fnum, new_trust_passwd_hash,
	                       sec_chan ) )
	{
		fstring errstr;
		cli_safe_errstr(&cli, errstr, sizeof(errstr));
		DEBUG(0,("modify_trust_password: unable to change password for \
workstation %s in domain %s to Domain controller %s. Error was %s.\n",
		            global_myname, domain, remote_machine, errstr ));
		cli_nt_session_close(&cli, nt_pipe_fnum);
		cli_ulogoff(&cli);
		cli_shutdown(&cli);
		return False;
	}

	cli_nt_session_close(&cli, nt_pipe_fnum);
	cli_ulogoff(&cli);
	cli_shutdown(&cli);

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

