/* 
   Unix SMB/CIFS implementation.
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

/* Opens a SMB connection to the svrsvc pipe */

struct cli_state *cli_svrsvc_initialise(struct cli_state *cli, 
					char *system_name,
					struct ntuser_creds *creds)
{
        return cli_pipe_initialise(cli, system_name, PIPE_SRVSVC, creds);
}

NTSTATUS cli_srvsvc_net_srv_get_info(struct cli_state *cli, 
                                     TALLOC_CTX *mem_ctx,
                                     uint32 switch_value, SRV_INFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	SRV_Q_NET_SRV_GET_INFO q;
	SRV_R_NET_SRV_GET_INFO r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */

	init_srv_q_net_srv_get_info(&q, cli->srv_name_slash, switch_value);

	/* Marshall data and send request */

	if (!srv_io_q_net_srv_get_info("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SRV_NET_SRV_GET_INFO, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	r.ctr = ctr;

	if (!srv_io_r_net_srv_get_info("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	result = werror_to_ntstatus(r.status);

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}
