/* 
   Unix SMB/CIFS implementation.
   raw dcerpc operations

   Copyright (C) Tim Potter, 2003
   
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

static int put_uuid(char *data, int offset, struct dcerpc_uuid *uuid)
{
	int i;

	SIVAL(data, offset, uuid->time_low); offset += 4;
	SSVAL(data, offset, uuid->time_mid); offset += 2;
	SSVAL(data, offset, uuid->time_hi_and_version); offset += 2;
	for (i = 0; i < 8; i++)
		SCVAL(data, offset + i, uuid->remaining[i]);
	offset += 8;

	return offset;
}

DATA_BLOB dcerpc_raw_bind_setup(struct dcerpc_bind *parms)
{
	int i, offset, size;
	char *data;

	/* Allocate storage for bind request */

	size = 28;
	for (i = 0; i < parms->in.num_contexts; i++) {
		size += 24;	/* as header + uuid */
		size += 20 * parms->in.ctx_list[i].num_ts; /* xfer syntaxes */
	}
	size += parms->in.auth_verifier.length;

	data = smb_xmalloc(size);
	memset(data, 0, size);

	parms->in.hdr.frag_len = size;

	/* Create bind request */

	SCVAL(data, 0,  parms->in.hdr.rpc_vers);
 	SCVAL(data, 1,  parms->in.hdr.rpc_vers_minor);
	SCVAL(data, 2,  parms->in.hdr.ptype);
	SCVAL(data, 3,  parms->in.hdr.pfc_flags);
	for (i = 0; i < 4; i++)
		SCVAL(data, 4 + i, parms->in.hdr.drep[i]);
	SSVAL(data, 8,  parms->in.hdr.frag_len);
	SSVAL(data, 10, parms->in.auth_verifier.length);
	SIVAL(data, 12, parms->in.hdr.call_id);

	SSVAL(data, 16, parms->in.max_xmit_frag);
	SSVAL(data, 18, parms->in.max_recv_frag);
	SIVAL(data, 20, parms->in.assoc_group_id);
	SIVAL(data, 24, parms->in.num_contexts);

	offset = 28;
	for (i = 0; i < parms->in.num_contexts; i++) {
		struct p_ctx_list *ctx = &parms->in.ctx_list[i];
		int j;

		SSVAL(data, offset, ctx->cont_id); offset += 2;
		SSVAL(data, offset, ctx->num_ts); offset += 2;
		offset = put_uuid(data, offset, &ctx->as->if_uuid);
		SIVAL(data, offset, ctx->as->if_version); offset += 4;
		for (j = 0; j < ctx->num_ts; j++) {
			offset = put_uuid(data, offset, &ctx->ts[i]->if_uuid);
			SIVAL(data, offset, ctx->ts[i]->if_version); 
			offset += 4;
		}
	}

	if (parms->in.auth_verifier.length)
		memcpy(&data[offset], parms->in.auth_verifier.data, 
		       parms->in.auth_verifier.length);

	return data_blob(data, size);
}

NTSTATUS dcerpc_raw_bind_send(struct cli_dcerpc_pipe *p, 
			      struct dcerpc_bind *parms)
{
	struct smb_trans2 trans;
	DATA_BLOB blob;
	NTSTATUS result;
	uint16 setup[2];

	blob = dcerpc_raw_bind_setup(parms);

	ZERO_STRUCT(trans);

	trans.in.max_data = blob.length;
	trans.in.setup_count = 2;
	trans.in.setup = setup;
	trans.in.trans_name = "\\PIPE\\";

	setup[0] = TRANSACT_DCERPCCMD;
	setup[1] = p->fnum;

	trans.in.data = blob;

	result = smb_raw_trans(p->tree, p->mem_ctx, &trans);

	data_blob_free(&blob);

	return result;
}

NTSTATUS dcerpc_raw_bind_recv(struct cli_dcerpc_pipe *p, 
			      struct dcerpc_bind *parms)
{
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS dcerpc_raw_bind(struct cli_dcerpc_pipe *p, struct dcerpc_bind *parms)
{
	NTSTATUS result;

	result = dcerpc_raw_bind_send(p, parms);
	if (NT_STATUS_IS_ERR(result)) 
		return result;
	return dcerpc_raw_bind_recv(p, parms);
}
	      
DATA_BLOB dcerpc_raw_request_setup(struct dcerpc_request *parms)
{
	int size, i;
	char *data;

	/* Allocate storage for request */

	size = 24 + parms->in.stub_data.length;

	data = smb_xmalloc(size);
	memset(data, 0, size);

	parms->in.hdr.frag_len = size;
	parms->in.alloc_hint = parms->in.stub_data.length;

	SCVAL(data, 0,  parms->in.hdr.rpc_vers);
 	SCVAL(data, 1,  parms->in.hdr.rpc_vers_minor);
	SCVAL(data, 2,  parms->in.hdr.ptype);
	SCVAL(data, 3,  parms->in.hdr.pfc_flags);
	for (i = 0; i < 4; i++)
		SCVAL(data, 4 + i, parms->in.hdr.drep[i]);
	SSVAL(data, 8,  parms->in.hdr.frag_len);
	SSVAL(data, 10, parms->in.auth_verifier.length);
	SIVAL(data, 12, parms->in.hdr.call_id);

	SIVAL(data, 16, parms->in.alloc_hint);
	SSVAL(data, 20, parms->in.cont_id);
	SSVAL(data, 22, parms->in.opnum);

	if (parms->in.stub_data.length)
		memcpy(&data[24], parms->in.stub_data.data,
		       parms->in.stub_data.length);

	return data_blob(data, size);
}

NTSTATUS dcerpc_raw_request_send(struct cli_dcerpc_pipe *p, 
				 struct dcerpc_request *parms)
{
	struct smb_trans2 trans;
	DATA_BLOB blob;
	NTSTATUS result;
	uint16 setup[2];

	blob = dcerpc_raw_request_setup(parms);

	ZERO_STRUCT(trans);

	trans.in.max_data = blob.length;
	trans.in.setup_count = 2;
	trans.in.setup = setup;
	trans.in.trans_name = "\\PIPE\\";

	setup[0] = TRANSACT_DCERPCCMD;
	setup[1] = p->fnum;

	trans.in.data = blob;

	result = smb_raw_trans(p->tree, p->mem_ctx, &trans);

	data_blob_free(&blob);

	return result;
}

NTSTATUS dcerpc_raw_request_recv(struct cli_dcerpc_pipe *p, 
				 struct dcerpc_request *parms)
{
	return NT_STATUS_UNSUCCESSFUL;
}

NTSTATUS dcerpc_raw_request(struct cli_dcerpc_pipe *p, 
			    struct dcerpc_request *parms)
{
	NTSTATUS result;

	result = dcerpc_raw_request_send(p, parms);
	if (NT_STATUS_IS_ERR(result))
		return result;
	return dcerpc_raw_request_recv(p, parms);
}
