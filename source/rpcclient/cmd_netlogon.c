/* 
   Unix SMB/Netbios implementation.
   Version 2.2
   RPC pipe client

   Copyright (C) Tim Potter 2000

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

extern int DEBUGLEVEL;

static uint32 cmd_netlogon_logon_ctrl2(struct cli_state *cli, int argc,
				       char **argv)
{
	uint32 query_level = 1;
	TALLOC_CTX *mem_ctx;
	uint32 result = NT_STATUS_UNSUCCESSFUL;

	if (argc > 1) {
		printf("Usage: %s\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("cmd_srvsvc_srv_query_info: talloc_init failed\n"));
		goto done;
	}

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_NETLOGON)) {
		DEBUG(0, ("Could not initialize srvsvc pipe!\n"));
		goto done;
	}

	if ((result = cli_netlogon_logon_ctrl2(cli, mem_ctx, query_level))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	/* Display results */

 done:
	return result;
}

static uint32 cmd_netlogon_logon_ctrl(struct cli_state *cli, int argc,
				      char **argv)
{
	uint32 query_level = 1;
	TALLOC_CTX *mem_ctx;
	uint32 result = NT_STATUS_UNSUCCESSFUL;

	if (argc > 1) {
		printf("Usage: %s\n", argv[0]);
		return 0;
	}

	if (!(mem_ctx = talloc_init())) {
		DEBUG(0,("cmd_srvsvc_srv_query_info: talloc_init failed\n"));
		goto done;
	}

	/* Initialise RPC connection */

	if (!cli_nt_session_open (cli, PIPE_NETLOGON)) {
		DEBUG(0, ("Could not initialize srvsvc pipe!\n"));
		goto done;
	}

#if 0
	if ((result = cli_netlogon_logon_ctrl(cli, mem_ctx, query_level))
	     != NT_STATUS_NOPROBLEMO) {
		goto done;
	}
#endif

	/* Display results */

 done:
	return result;
}

/* List of commands exported by this module */

struct cmd_set netlogon_commands[] = {
	{ "NETLOGON", 	NULL,			  "" },
	{ "logonctrl2", cmd_netlogon_logon_ctrl2, "Logon Control 2" },
	{ "logonctrl",  cmd_netlogon_logon_ctrl,  "Logon Control" },
	{ NULL, NULL, NULL }
};
