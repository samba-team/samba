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
extern pstring server;

static uint32 cmd_samr_connect(int argc, char **argv)
{
	struct cli_state cli;
	POLICY_HND pol, domain_pol, user_pol;
	uint32 result = NT_STATUS_UNSUCCESSFUL;
	struct ntuser_creds creds;
	BOOL got_policy_hnd = False, got_domain_hnd = False;
	DOM_SID sid;

	if (argc > 1) {
		printf("Usage: %s\n", argv[0]);
		return 0;
	}

	/* Open a sam handle */

	ZERO_STRUCT(cli);
	init_rpcclient_creds(&creds);

	if (cli_samr_initialise(&cli, server, &creds) == NULL) {
		goto done;
	}

	if ((result = cli_samr_connect(&cli, server, 
				       SEC_RIGHTS_MAXIMUM_ALLOWED,
				       &pol)) != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_policy_hnd = True;

	string_to_sid(&sid, "S-1-5-21-1067277791-1719175008-3000797951");

	if ((result = cli_samr_open_domain(&cli, &pol, 
					   SEC_RIGHTS_MAXIMUM_ALLOWED,
					   &sid, &domain_pol)) 
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

	got_domain_hnd = True;

	if ((result = cli_samr_open_user(&cli, &domain_pol,
					 SEC_RIGHTS_MAXIMUM_ALLOWED, 500,
					 &user_pol))
	    != NT_STATUS_NOPROBLEMO) {
		goto done;
	}

done:
	if (got_domain_hnd) cli_samr_close(&cli, &domain_pol);
	if (got_policy_hnd) cli_samr_close(&cli, &pol);

	return result;
}

/* List of commands exported by this module */

struct cmd_set samr_commands[] = {
	{ "samconnect", cmd_samr_connect, "Test" },
	{ NULL, NULL, NULL }
};
