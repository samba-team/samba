/* 
   Unix SMB/CIFS implementation.
   test suite for lsa rpc operations
   Copyright (C) Tim Potter 2003
   Copyright (C) Andrew Tridgell 2003
   
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

/* form a lsa open request */
static DATA_BLOB blob_lsa_open_policy_req(TALLOC_CTX *mem_ctx, BOOL sec_qos, uint32 des_access)
{
	prs_struct qbuf;
	LSA_Q_OPEN_POL q;
	LSA_SEC_QOS qos;

	ZERO_STRUCT(q);

	/* Initialise parse structures */
	prs_init(&qbuf, MAX_PDU_FRAG_LEN, mem_ctx, MARSHALL);

	/* Initialise input parameters */
	if (sec_qos) {
		init_lsa_sec_qos(&qos, 2, 1, 0);
		init_q_open_pol(&q, '\\', 0, des_access, &qos);
	} else {
		init_q_open_pol(&q, '\\', 0, des_access, NULL);
	}

	if (lsa_io_q_open_pol("", &q, &qbuf, 0))
		return data_blob_talloc(
			mem_ctx, prs_data_p(&qbuf), prs_offset(&qbuf));

	return data_blob(NULL, 0);
}

BOOL torture_rpc_lsa(int dummy)
{
        NTSTATUS status;
        struct dcerpc_pipe *p;
	DATA_BLOB request, response;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("torture_rpc_lsa");

	status = torture_rpc_connection(&p, "lsarpc");
	if (!NT_STATUS_IS_OK(status)) {
		return False;
	}
	
	request = blob_lsa_open_policy_req(mem_ctx, True, 
					   SEC_RIGHTS_MAXIMUM_ALLOWED);

	status = cli_dcerpc_request(p, LSA_OPENPOLICY, mem_ctx, &request, &response);
	if (!NT_STATUS_IS_OK(status)) {
		d_printf("Failed to LSA_OPENPOLICY - %s\n", nt_errstr(status));
	}

        torture_rpc_close(p);

	return NT_STATUS_IS_OK(status);
}
