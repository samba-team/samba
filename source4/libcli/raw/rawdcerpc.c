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
	uint16 frag_length;
	DATA_BLOB payload;

	status = smb_raw_trans_recv(req, mem_ctx, &trans);
	/* STATUS_BUFFER_OVERFLOW means that there is more data
	   available via SMBreadX */
	if (!NT_STATUS_IS_OK(status) && 
	    !NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		return status;
	}

	payload = trans.out.data;

	if (trans.out.data.length < 16 || 
	    !NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		goto done;
	}

	/* we might have recieved a partial fragment, in which case we
	   need to pull the rest of it */
	frag_length = SVAL(payload.data, 8);
	if (frag_length <= payload.length) {
		goto done;
	}

	/* make sure the payload can hold the whole fragment */
	payload.data = talloc_realloc(mem_ctx, payload.data, frag_length);
	if (!payload.data) {
		return NT_STATUS_NO_MEMORY;
	}

	/* the rest of the data is available via SMBreadX */
	while (frag_length > payload.length) {
		uint32 n;
		union smb_read io;

		n = frag_length - payload.length;
		if (n > 0xFF00) {
			n = 0xFF00;
		}

		io.generic.level = RAW_READ_READX;
		io.readx.in.fnum = p->fnum;
		io.readx.in.mincnt = n;
		io.readx.in.maxcnt = n;
		io.readx.in.offset = 0;
		io.readx.in.remaining = 0;
		io.readx.out.data = payload.data + payload.length;
		status = smb_raw_read(p->tree, &io);
		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
			break;
		}
		
		n = io.readx.out.nread;
		if (n == 0) {
			status = NT_STATUS_UNSUCCESSFUL;
			break;
		}
		
		payload.length += n;

		/* if the SMBreadX returns NT_STATUS_OK then there
		   isn't any more data to be read */
		if (NT_STATUS_IS_OK(status)) {
			break;
		}
	}

done:
	if (blob) {
		*blob = payload;
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
	      

/* 
   retrieve a secondary pdu from a pipe 
*/
NTSTATUS dcerpc_raw_packet_secondary(struct dcerpc_pipe *p, 
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *blob)
{
	union smb_read io;
	uint32 n = 0x2000;
	uint32 frag_length;
	NTSTATUS status;

	*blob = data_blob_talloc(mem_ctx, NULL, n);
	if (!blob->data) {
		return NT_STATUS_NO_MEMORY;
	}

	io.generic.level = RAW_READ_READX;
	io.readx.in.fnum = p->fnum;
	io.readx.in.mincnt = n;
	io.readx.in.maxcnt = n;
	io.readx.in.offset = 0;
	io.readx.in.remaining = 0;
	io.readx.out.data = blob->data;

	status = smb_raw_read(p->tree, &io);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		return status;
	}

	blob->length = io.readx.out.nread;

	if (blob->length < 16) {
		return status;
	}

	frag_length = SVAL(blob->data, 8);
	if (frag_length <= blob->length) {
		return status;
	}

	blob->data = talloc_realloc(mem_ctx, blob->data, frag_length);
	if (!blob->data) {
		return NT_STATUS_NO_MEMORY;
	}

	while (frag_length > blob->length &&
	       NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {

		n = frag_length - blob->length;
		if (n > 0xFF00) {
			n = 0xFF00;
		}

		io.readx.in.mincnt = n;
		io.readx.in.maxcnt = n;
		io.readx.out.data = blob->data + blob->length;
		status = smb_raw_read(p->tree, &io);

		if (!NT_STATUS_IS_OK(status) &&
		    !NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
			return status;
		}
		
		n = io.readx.out.nread;
		blob->length += n;
	}

	return status;
}


/* 
   send an initial pdu in a multi-pdu sequence
*/
NTSTATUS dcerpc_raw_packet_initial(struct dcerpc_pipe *p, 
				   TALLOC_CTX *mem_ctx,
				   DATA_BLOB *blob)
{
	union smb_write io;
	NTSTATUS status;

	io.generic.level = RAW_WRITE_WRITEX;
	io.writex.in.fnum = p->fnum;
	io.writex.in.offset = 0;
	io.writex.in.wmode = PIPE_START_MESSAGE;
	io.writex.in.remaining = blob->length;
	io.writex.in.count = blob->length;
	io.writex.in.data = blob->data;

	status = smb_raw_write(p->tree, &io);
	if (NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* make sure it accepted it all */
	if (io.writex.out.nwritten != blob->length) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return status;
}
