/* 
   Unix SMB/CIFS implementation.
   NT Domain Authentication SMB / MSRPC client
   Copyright (C) Andrew Tridgell 1994-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Tim Potter 2001
   Copytight (C) Rafal Szczesniak 2002
   
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

/**
 * WksQueryInfo rpc call (like query for server's capabilities)
 *
 * @param initialised client structure with \PIPE\wkssvc opened
 * @param mem_ctx memory context assigned to this rpc binding
 * @param wks100 WksQueryInfo structure
 *
 * @return NTSTATUS of rpc call
 */
 
NTSTATUS cli_wks_query_info(struct cli_state *cli, TALLOC_CTX *mem_ctx,
			    WKS_INFO_100 *wks100)
{
	prs_struct buf;
	prs_struct rbuf;
	WKS_Q_QUERY_INFO q_o;
	WKS_R_QUERY_INFO r_o;

	if (cli == NULL || wks100 == NULL)
		return NT_STATUS_UNSUCCESSFUL;

	/* init rpc parse structures */
	prs_init(&buf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	DEBUG(4, ("WksQueryInfo\n"));
	
	/* init query structure with rpc call arguments */
	init_wks_q_query_info(&q_o, cli->desthost, 100);
	
	/* marshall data */
	if (!wks_io_q_query_info("", &q_o, &buf, 0)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	/* actual rpc call over \PIPE\wkssvc */
	if (!rpc_api_pipe_req(cli, WKS_QUERY_INFO, &buf, &rbuf)) {
		prs_mem_free(&buf);
		prs_mem_free(&rbuf);
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	prs_mem_free(&buf);

	r_o.wks100 = wks100;

	/* get call results from response buffer */
	if (!wks_io_r_query_info("", &r_o, &rbuf, 0)) {
		prs_mem_free(&rbuf);
		return NT_STATUS_UNSUCCESSFUL;
	}
	
	/* check returnet status code */
	if (NT_STATUS_IS_ERR(r_o.status)) {
		/* report the error */
		DEBUG(0,("WKS_R_QUERY_INFO: %s\n", nt_errstr(r_o.status)));
		prs_mem_free(&rbuf);
		return r_o.status;
	}
	
	/* do clean up */
	prs_mem_free(&rbuf);
	
	return NT_STATUS_OK;
}

