/* 
   Unix SMB/CIFS implementation.
   SMB client password change routine
   Copyright (C) Andrew Tridgell 1994-1998
   
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

/*************************************************************
change a password on a remote machine using IPC calls
*************************************************************/
BOOL remote_password_change(const char *remote_machine, const char *user_name, 
			    const char *old_passwd, const char *new_passwd,
			    char *err_str, size_t err_str_len)
{
	struct nmb_name calling, called;
	struct cli_state *cli;
	struct in_addr ip;
	struct ntuser_creds creds;
	TALLOC_CTX *mem_ctx;
	NTSTATUS result;

	*err_str = '\0';
;
	if ( !(mem_ctx = talloc_init( "resolve_name" )) ) {
		DEBUG(0,("remote_password_change: talloc_init() failed\n"));
		return False;
	}

	if(!resolve_name( mem_ctx, remote_machine, &ip, 0x20)) {
		slprintf(err_str, err_str_len-1, "unable to find an IP address for machine %s.\n",
			remote_machine );
		talloc_destroy( mem_ctx );
		return False;
	}
 
	cli = NULL;
 
	make_nmb_name(&calling, global_myname() , 0x0);
	make_nmb_name(&called , remote_machine, 0x20);

	/* have to open a new connection */
	if (!(cli=cli_state_init()) || !cli_socket_connect(cli, remote_machine, &ip)) {
		DEBUG(0,("Connection to %s failed\n", remote_machine));
		return False;
	}

	if (!cli_transport_establish(cli, &calling, &called)) {
		DEBUG(1,("session request to %s failed (%s)\n", called.name, cli_errstr(cli->tree)));
		cli_shutdown(cli);
		return False;
	}

	DEBUG(4,(" session request ok\n"));

	if (NT_STATUS_IS_ERR(cli_negprot(cli))) {
		DEBUG(1,("protocol negotiation failed\n"));
		cli_shutdown(cli);
		return False;
	}

	result = cli_session_setup(cli, user_name, old_passwd, lp_workgroup());

	/* Given things like SMB signing, restrict anonymous and the like, 
	   try an authenticated connection first */
	if (NT_STATUS_IS_ERR(result)) {
		/*
		 * We should connect as the anonymous user here, in case
		 * the server has "must change password" checked...
		 * Thanks to <Nicholas.S.Jenkins@cdc.com> for this fix.
		 */

		result = cli_session_setup( cli, "", "", "" );
		if ( NT_STATUS_IS_ERR(result) ) {
			slprintf(err_str, err_str_len-1, "machine %s rejected the session setup. Error was : %s.\n",
				 remote_machine, cli_errstr(cli->tree) );
			goto out;
		}

#if 0	/* FIXME */
		init_creds(&creds, "", "", NULL);
		cli_init_creds(&cli, &creds);
	} else {
		init_creds(&creds, user_name, "", old_passwd);
		cli_init_creds(&cli, &creds);
#endif
	}

	if (NT_STATUS_IS_ERR(cli_send_tconX(cli, "IPC$", "IPC", ""))) {
		DEBUG(1,("tree connect failed: %s\n", cli_errstr(cli->tree)));
		cli_shutdown(cli);
		return False;
	}

	DEBUG(4,(" tconx ok\n"));

#if 0	/* FIXME! temporily commented out */
	/* Try not to give the password away to easily */

	cli.pipe_auth_flags = AUTH_PIPE_NTLMSSP;
	cli.pipe_auth_flags |= AUTH_PIPE_SIGN;
	cli.pipe_auth_flags |= AUTH_PIPE_SEAL;
	
	if ( !cli_nt_session_open( &cli, PI_SAMR ) ) {
		if (lp_client_lanman_auth()) {
			if (!cli_oem_change_password(&cli, user_name, new_passwd, old_passwd)) {
				slprintf(err_str, err_str_len-1, "machine %s rejected the password change: Error was : %s.\n",
					 remote_machine, cli_errstr(cli->tree) );
				result = False;
				goto out;
			}
		} else {
			slprintf(err_str, err_str_len-1, "machine %s does not support SAMR connections, but LANMAN password changed are disabled\n",
				 remote_machine);
			result = False;
			goto out;
		}
	}

	if (!NT_STATUS_IS_OK(result = cli_samr_chgpasswd_user(&cli, cli.mem_ctx, user_name, 
							      new_passwd, old_passwd))) {

		if (NT_STATUS_EQUAL(result, NT_STATUS_ACCESS_DENIED) 
		    || NT_STATUS_EQUAL(result, NT_STATUS_UNSUCCESSFUL)) {
			/* try the old Lanman method */
			if (lp_client_lanman_auth()) {
				if (!cli_oem_change_password(&cli, user_name, new_passwd, old_passwd)) {
					slprintf(err_str, err_str_len-1, "machine %s rejected the password change: Error was : %s.\n",
						 remote_machine, cli_errstr(&cli) );
					result = False;
					goto out;
				}
			} else {
				slprintf(err_str, err_str_len-1, "machine %s does not support SAMR connections, but LANMAN password changed are disabled\n",
					remote_machine);
				result = False;
				goto out;
			}
		} else {
			slprintf(err_str, err_str_len-1, "machine %s rejected the password change: Error was : %s.\n",
				 remote_machine, get_friendly_nt_error_msg(result));
			result = False;
			goto out;
		}
	}

#endif	/* FIXME! */

out:
	cli_shutdown(cli);
	talloc_destroy( mem_ctx );
	return !NT_STATUS_IS_ERR(result);
}
