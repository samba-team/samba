/* 
   Unix SMB/CIFS implementation.
   raw dcerpc operations

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

struct cli_request *dcerpc_raw_send(struct dcerpc_pipe *p, DATA_BLOB *blob)
{
	struct smb_trans2 trans;
	uint16 setup[2];
	struct cli_request *req;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("dcerpc_raw_send");
	if (!mem_ctx) return NULL;

	trans.in.data = *blob;
	trans.in.params = data_blob(NULL, 0);
	
	setup[0] = TRANSACT_DCERPCCMD;
	setup[1] = p->fnum;

	trans.in.max_param = 0;
	trans.in.max_data = 0x8000;
	trans.in.setup_count = 2;
	trans.in.setup = setup;
	trans.in.trans_name = "\\PIPE\\";

	req = smb_raw_trans_send(p->tree, &trans);

	talloc_destroy(mem_ctx);

	return req;
}

NTSTATUS dcerpc_raw_recv(struct dcerpc_pipe *p, 
			 struct cli_request *req,
			 TALLOC_CTX *mem_ctx,
			 DATA_BLOB *blob)
{
	struct smb_trans2 trans;
	NTSTATUS status;

	status = smb_raw_trans_recv(req, mem_ctx, &trans);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (blob) {
		*blob = trans.out.data;
	}

	return status;
}

NTSTATUS dcerpc_raw_packet(struct dcerpc_pipe *p, 
			   TALLOC_CTX *mem_ctx,
			   DATA_BLOB *request_blob,
			   DATA_BLOB *reply_blob)
{
	struct cli_request *req;
	req = dcerpc_raw_send(p, request_blob);
	return dcerpc_raw_recv(p, req, mem_ctx, reply_blob);
}
	      
