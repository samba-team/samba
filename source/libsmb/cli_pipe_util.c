/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   RPC pipe client utility functions
   Copyright (C) Tim Potter                        2001,
   
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

/* Opens a SMB connection to a named pipe */

struct cli_state *cli_pipe_initialise(struct cli_state *cli, char *system_name,
				      const char *pipe_name, 
                                      struct ntuser_creds *creds)
{
	struct in_addr dest_ip;
	struct nmb_name calling, called;
	fstring dest_host;
	extern pstring global_myname;
	struct ntuser_creds anon;

	/* Initialise cli_state information */

	if (!cli_initialise(cli)) {
		return NULL;
	}

	if (!creds) {
		ZERO_STRUCT(anon);
		anon.pwd.null_pwd = 1;
		creds = &anon;
	}

	cli_init_creds(cli, creds);

	/* Establish a SMB connection */

	if (!resolve_srv_name(system_name, dest_host, &dest_ip)) {
		return NULL;
	}

	make_nmb_name(&called, dns_to_netbios_name(dest_host), 0x20);
	make_nmb_name(&calling, dns_to_netbios_name(global_myname), 0);

	if (!cli_establish_connection(cli, dest_host, &dest_ip, &calling, 
				      &called, "IPC$", "IPC", False, True)) {
		return NULL;
	}

	/* Open a NT session thingy */

	if (!cli_nt_session_open(cli, pipe_name)) {
		cli_shutdown(cli);
		return NULL;
	}

	return cli;
}

/* Shut down a SMB connection to the SAMR pipe */

void cli_pipe_shutdown(struct cli_state *cli)
{
	if (cli->fd != -1) cli_ulogoff(cli);
	cli_shutdown(cli);
}
