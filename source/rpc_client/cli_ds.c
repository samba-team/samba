/* 
   Unix SMB/CIFS implementation.
   RPC pipe client
   Copyright (C) Gerald Carter                        2002,
   
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

/* implementations of client side DsXXX() functions */

NTSTATUS cli_ds_getprimarydominfo(struct cli_state *cli, TALLOC_CTX *mem_ctx, 
				  uint16 level, DS_DOMINFO_CTR *ctr)
{
	prs_struct qbuf, rbuf;
	DS_Q_GETPRIMDOMINFO q;
	DS_R_GETPRIMDOMINFO r;
	NTSTATUS result;

	ZERO_STRUCT(q);
	ZERO_STRUCT(r);

	/* Initialise parse structures */

	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);
	prs_init(&rbuf, 0, mem_ctx, UNMARSHALL);
	
	q.level = level;
	
	if (!ds_io_q_getprimdominfo("", &q, &qbuf, 0) 
	    || !rpc_api_pipe_req(cli, DS_GETPRIMDOMINFO, &qbuf, &rbuf)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}

	/* Unmarshall response */

	if (!ds_io_r_getprimdominfo("", &r, &rbuf, 0)) {
		result = NT_STATUS_UNSUCCESSFUL;
		goto done;
	}
	
	/* Return basic info - if we are requesting at info != 1 then
	   there could be trouble. */ 

	result = r.status;

	if (ctr) {
		ctr->basic = talloc(mem_ctx, sizeof(DSROLE_PRIMARY_DOMAIN_INFO_BASIC));
		if (!ctr->basic)
			goto done;
		memcpy(ctr->basic, r.info.basic, sizeof(DSROLE_PRIMARY_DOMAIN_INFO_BASIC));
	}
	
done:
	prs_mem_free(&qbuf);
	prs_mem_free(&rbuf);

	return result;
}
