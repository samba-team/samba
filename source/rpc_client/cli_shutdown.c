/* 
   Unix SMB/CIFS implementation.
   RPC Pipe client
 
   Copyright (C) Andrew Tridgell              1992-1998,
   Copyright (C) Luke Kenneth Casson Leighton 1996-1998,
   Copyright (C) Paul Ashton                  1997-1998.
   Copyright (C) Jeremy Allison                    1999,
   Copyright (C) Simo Sorce                        2001,
   Copyright (C) Jim McDonough (jmcd@us.ibm.com)   2003.
   
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

/* Shutdown a server */

NTSTATUS cli_shutdown_init(struct cli_state * cli, TALLOC_CTX *mem_ctx,
			   const char *msg, uint32 timeout, BOOL do_reboot,
			   BOOL force)
{
	prs_struct qbuf;
	prs_struct rbuf; 
	SHUTDOWN_Q_INIT q_s;
	SHUTDOWN_R_INIT r_s;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	if (msg == NULL) return NT_STATUS_INVALID_PARAMETER;

	ZERO_STRUCT (q_s);
	ZERO_STRUCT (r_s);

	prs_init(&qbuf , MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_shutdown_q_init(&q_s, msg, timeout, do_reboot, force);

	if (!shutdown_io_q_init("", &q_s, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SHUTDOWN_INIT, &qbuf, &rbuf))
		goto done;
	
	/* Unmarshall response */
	
	if(shutdown_io_r_init("", &r_s, &rbuf, 0))
		result = r_s.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf);

	return result;
}


/* Abort a server shutdown */

NTSTATUS cli_shutdown_abort(struct cli_state * cli, TALLOC_CTX *mem_ctx)
{
	prs_struct rbuf;
	prs_struct qbuf; 
	SHUTDOWN_Q_ABORT q_s;
	SHUTDOWN_R_ABORT r_s;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	ZERO_STRUCT (q_s);
	ZERO_STRUCT (r_s);

	prs_init(&qbuf , MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);
	
	/* Marshall data and send request */

	init_shutdown_q_abort(&q_s);

	if (!shutdown_io_q_abort("", &q_s, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, SHUTDOWN_ABORT, &qbuf, &rbuf))
	    	goto done;
	
		/* Unmarshall response */
	
	if (shutdown_io_r_abort("", &r_s, &rbuf, 0))
		result = r_s.status;

done:
	prs_mem_free(&rbuf);
	prs_mem_free(&qbuf );

	return result;
}
