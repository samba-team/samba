/* 
   Unix SMB/CIFS implementation.

   RPC pipe client

   Copyright (C) Tim Potter 2003
   
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

NTSTATUS cli_echo_add_one(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			  uint32 request, uint32 *response)
{
	prs_struct qbuf, rbuf;
	ECHO_Q_ADD_ONE q;
	ECHO_R_ADD_ONE r;
	BOOL result = False;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_echo_q_add_one(&q, request);

	if (!echo_io_q_add_one("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, ECHO_ADD_ONE, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!echo_io_r_add_one("", &r, &rbuf, 0))
		goto done;

	if (response)
		*response = r.response;

	result = True;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS cli_echo_data(struct cli_state *cli, TALLOC_CTX *mem_ctx,
		       uint32 size, char *in_data, char **out_data)
{
	prs_struct qbuf, rbuf;
	ECHO_Q_ECHO_DATA q;
	ECHO_R_ECHO_DATA r;
	BOOL result = False;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_echo_q_echo_data(&q, size, in_data);

	if (!echo_io_q_echo_data("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, ECHO_DATA, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!echo_io_r_echo_data("", &r, &rbuf, 0))
		goto done;

	result = True;

	if (out_data) {
		*out_data = talloc(mem_ctx, size);
		memcpy(*out_data, r.data, size);
	}

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS cli_echo_sink_data(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			    uint32 size, char *in_data)
{
	prs_struct qbuf, rbuf;
	ECHO_Q_SINK_DATA q;
	ECHO_R_SINK_DATA r;
	BOOL result = False;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_echo_q_sink_data(&q, size, in_data);

	if (!echo_io_q_sink_data("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, ECHO_SINK_DATA, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!echo_io_r_sink_data("", &r, &rbuf, 0)) {
		goto done;
	}

	result = True;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS cli_echo_source_data(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			      uint32 size, char **out_data)
{
	prs_struct qbuf, rbuf;
	ECHO_Q_SOURCE_DATA q;
	ECHO_R_SOURCE_DATA r;
	BOOL result = False;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

        init_echo_q_source_data(&q, size);

	if (!echo_io_q_source_data("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, ECHO_SOURCE_DATA, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!echo_io_r_source_data("", &r, &rbuf, 0)) {
		goto done;
	}

	result = True;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}
