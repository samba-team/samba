/* 
   Unix SMB/CIFS implementation.
   RPC pipe client

   Copyright (C) Jim McDonough (jmcd@us.ibm.com) 2003

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

NTSTATUS cli_epm_map(struct cli_state *cli, TALLOC_CTX *mem_ctx,
		     EPM_HANDLE *handle, EPM_TOWER **tower,
		     EPM_HANDLE *entry_handle, uint32 *num_towers)
{
	prs_struct qbuf, rbuf;
	EPM_Q_MAP q;
	EPM_R_MAP r;
	BOOL result = False;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);

	/* Marshall data and send request */

	init_epm_q_map(mem_ctx, &q, *tower, *num_towers);

	if (!epm_io_q_map("map_query", &q, &qbuf, 0) ||
	    !rpc_api_pipe_req(cli, EPM_MAP_PIPE_NAME, &qbuf, &rbuf))
		goto done;

	/* Unmarshall response */

	if (!epm_io_r_map("map_reply", &r, &rbuf, 0))
		goto done;

	result = True;

 done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}
