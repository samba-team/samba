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

/* Server query info */

static uint32 cmd_srvsvc_srv_query_info(struct cli_state *cli, int argc,
					char **argv)
{
	uint32 info_level = 101;
	SRV_INFO_CTR ctr;
	TALLOC_CTX *mem_ctx;

	if (argc > 2) {
		printf("Usage: %s [infolevel]\n", argv[0]);
		return 0;
	}

	if (argc == 2)
		info_level = atoi(argv[1]);

	return 0;
}

/* List of commands exported by this module */

struct cmd_set srvsvc_commands[] = {
	{ "SRVSVC", 	NULL,		   	    "" },
	{ NULL, NULL, NULL }
};
