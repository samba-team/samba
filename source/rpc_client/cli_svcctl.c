/*
 *  Unix SMB/CIFS implementation.
 *  RPC Pipe client / server routines
 *  Copyright (C) Gerald Carter                   2005.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include "includes.h"

/*******************************************************************
*******************************************************************/

WERROR cli_svcctl_open_scm( struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                            SVCCTL_Q_OPEN_SCMANAGER *in, SVCCTL_R_OPEN_SCMANAGER *out )
{
	prs_struct qbuf, rbuf;

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);
	
	out->status = WERR_GENERAL_FAILURE;

	/* Marshall data and send request */

	if ( svcctl_io_q_open_scmanager("", in, &qbuf, 0) ) {
		if ( rpc_api_pipe_req(cli, PI_SVCCTL, SVCCTL_OPEN_SCMANAGER_W, &qbuf, &rbuf) ) {
			/* Unmarshall response */
			if (!svcctl_io_r_open_scmanager("", out, &rbuf, 0)) {
				out->status = WERR_GENERAL_FAILURE;
			}		
		}
	}

	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return out->status;
}

/*******************************************************************
*******************************************************************/

WERROR cli_svcctl_close_service( struct cli_state *cli, TALLOC_CTX *mem_ctx, 
                            SVCCTL_Q_CLOSE_SERVICE *in, SVCCTL_R_CLOSE_SERVICE *out )
{
	prs_struct qbuf, rbuf;

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);
	
	out->status = WERR_GENERAL_FAILURE;

	/* Marshall data and send request */

	if ( svcctl_io_q_close_service("", in, &qbuf, 0) ) {
		if ( rpc_api_pipe_req(cli, PI_SVCCTL, SVCCTL_CLOSE_SERVICE, &qbuf, &rbuf) ) {
			/* Unmarshall response */
			if (!svcctl_io_r_close_service("", out, &rbuf, 0)) {
				out->status = WERR_GENERAL_FAILURE;
			}		
		}
	}

	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return out->status;
}

/*******************************************************************
*******************************************************************/

WERROR cli_svcctl_enumerate_services( struct cli_state *cli, TALLOC_CTX *mem_ctx,
                                      POLICY_HND *hSCM, uint32 type, uint32 state, 
				      uint32 *resume, uint32 buffer_size, RPC_BUFFER *buffer,
				      uint32 returned )
{
	prs_struct qbuf, rbuf;
	SVCCTL_Q_ENUM_SERVICES_STATUS q;
	SVCCTL_R_ENUM_SERVICES_STATUS r;
	WERROR result = WERR_GENERAL_FAILURE;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Initialise input parameters */


	/* Marshall data and send request */
	
	if (!svcctl_io_q_enum_services_status("", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, PI_SVCCTL, SVCCTL_ENUM_SERVICES_STATUS_W, &qbuf, &rbuf)) {
		goto done;
	}

	/* Unmarshall response */

	if (!svcctl_io_r_enum_services_status("", &r, &rbuf, 0)) {
		goto done;
	}

	/* Return output parameters */

	if (W_ERROR_IS_OK(result = r.status)) {
		*buffer = r.buffer;
	}

done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}

/*******************************************************************
*******************************************************************/

NTSTATUS cli_svcctl_start_service(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return NT_STATUS_OK;
}

/*******************************************************************
*******************************************************************/

NTSTATUS cli_svcctl_control_service(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return NT_STATUS_OK;
}

/*******************************************************************
*******************************************************************/

NTSTATUS cli_svcctl_query_status(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return NT_STATUS_OK;
}

/*******************************************************************
*******************************************************************/

NTSTATUS cli_svcctl_query_config(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return NT_STATUS_OK;
}

/*******************************************************************
*******************************************************************/

NTSTATUS cli_svcctl_get_dispname(struct cli_state *cli, TALLOC_CTX *mem_ctx )
{

	return NT_STATUS_OK;
}

