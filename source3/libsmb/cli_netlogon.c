/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Tim Potter 2001
   
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

/* Opens a SMB connection to the netlogon pipe */

struct cli_state *cli_netlogon_initialise(struct cli_state *cli, 
					  char *system_name,
					  struct ntuser_creds *creds)
{
        return cli_pipe_initialise(cli, system_name, PIPE_NETLOGON, creds);
}

/* Logon Control 2 */

uint32 cli_netlogon_logon_ctrl2(struct cli_state *cli, TALLOC_CTX *mem_ctx,
				uint32 query_level)
{
	prs_struct qbuf, rbuf;
	NET_Q_LOGON_CTRL2 q;
	NET_R_LOGON_CTRL2 r;
	uint32 result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_net_q_logon_ctrl2(&q, cli->srv_name_slash, query_level);

	/* Marshall data and send request */

	if (!net_io_q_logon_ctrl2("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, NET_LOGON_CTRL2, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!net_io_r_logon_ctrl2("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = r.status;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}
