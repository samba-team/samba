/* 
   Unix SMB/CIFS implementation.

   dcerpc over SMB transport

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

/* transport private information used by SMB pipe transport */
struct smb_private {
	uint16_t fnum;
	struct smbcli_tree *tree;
};

static struct smbcli_request *dcerpc_raw_send(struct dcerpc_pipe *p, DATA_BLOB *blob)
{
	struct smb_private *smb = p->transport.private;
	struct smb_trans2 trans;
	uint16_t setup[2];
	struct smbcli_request *req;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_init("dcerpc_raw_send");
	if (!mem_ctx) return NULL;

	trans.in.data = *blob;
	trans.in.params = data_blob(NULL, 0);
	
	setup[0] = TRANSACT_DCERPCCMD;
	setup[1] = smb->fnum;

	trans.in.max_param = 0;
	trans.in.max_data = 0x8000;
	trans.in.max_setup = 0;
	trans.in.setup_count = 2;
	trans.in.flags = 0;
	trans.in.timeout = 0;
	trans.in.setup = setup;
	trans.in.trans_name = "\\PIPE\\";

	req = smb_raw_trans_send(smb->tree, &trans);

	talloc_destroy(mem_ctx);

	return req;
}


static NTSTATUS dcerpc_raw_recv(struct dcerpc_pipe *p, 
				struct smbcli_request *req,
				TALLOC_CTX *mem_ctx,
				DATA_BLOB *blob)
{
	struct smb_private *smb = p->transport.private;
	struct smb_trans2 trans;
	NTSTATUS status;
	uint16_t frag_length;
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
	frag_length = dcerpc_get_frag_length(&payload);
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
		uint32_t n;
		union smb_read io;

		n = frag_length - payload.length;
		if (n > 0xFF00) {
			n = 0xFF00;
		}

		io.generic.level = RAW_READ_READX;
		io.readx.in.fnum = smb->fnum;
		io.readx.in.mincnt = n;
		io.readx.in.maxcnt = n;
		io.readx.in.offset = 0;
		io.readx.in.remaining = 0;
		io.readx.out.data = payload.data + payload.length;
		status = smb_raw_read(smb->tree, &io);
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

static NTSTATUS smb_full_request(struct dcerpc_pipe *p, 
				 TALLOC_CTX *mem_ctx,
				 DATA_BLOB *request_blob,
				 DATA_BLOB *reply_blob)
{
	struct smbcli_request *req;
	req = dcerpc_raw_send(p, request_blob);
	return dcerpc_raw_recv(p, req, mem_ctx, reply_blob);
}
	      

/* 
   retrieve a secondary pdu from a pipe 
*/
static NTSTATUS smb_secondary_request(struct dcerpc_pipe *p, 
			       TALLOC_CTX *mem_ctx,
			       DATA_BLOB *blob)
{
	struct smb_private *smb = p->transport.private;
	union smb_read io;
	uint32_t n = 0x2000;
	uint32_t frag_length;
	NTSTATUS status;

	*blob = data_blob_talloc(mem_ctx, NULL, n);
	if (!blob->data) {
		return NT_STATUS_NO_MEMORY;
	}

	io.generic.level = RAW_READ_READX;
	io.readx.in.fnum = smb->fnum;
	io.readx.in.mincnt = n;
	io.readx.in.maxcnt = n;
	io.readx.in.offset = 0;
	io.readx.in.remaining = 0;
	io.readx.out.data = blob->data;

	status = smb_raw_read(smb->tree, &io);
	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, STATUS_BUFFER_OVERFLOW)) {
		return status;
	}

	blob->length = io.readx.out.nread;

	if (blob->length < 16) {
		return status;
	}

	frag_length = dcerpc_get_frag_length(blob);
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
		status = smb_raw_read(smb->tree, &io);

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
static NTSTATUS smb_initial_request(struct dcerpc_pipe *p, 
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *blob)
{
	struct smb_private *smb = p->transport.private;
	union smb_write io;
	NTSTATUS status;

	io.generic.level = RAW_WRITE_WRITEX;
	io.writex.in.fnum = smb->fnum;
	io.writex.in.offset = 0;
	io.writex.in.wmode = PIPE_START_MESSAGE;
	io.writex.in.remaining = blob->length;
	io.writex.in.count = blob->length;
	io.writex.in.data = blob->data;

	status = smb_raw_write(smb->tree, &io);
	if (NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* make sure it accepted it all */
	if (io.writex.out.nwritten != blob->length) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	return status;
}


/* 
   shutdown SMB pipe connection
*/
static NTSTATUS smb_shutdown_pipe(struct dcerpc_pipe *p)
{
	struct smb_private *smb = p->transport.private;
	union smb_close c;

	/* maybe we're still starting up */
	if (!smb) return NT_STATUS_OK;

	c.close.level = RAW_CLOSE_CLOSE;
	c.close.in.fnum = smb->fnum;
	c.close.in.write_time = 0;
	smb_raw_close(smb->tree, &c);
	smbcli_tree_close(smb->tree);

	return NT_STATUS_OK;
}

/*
  return SMB server name
*/
static const char *smb_peer_name(struct dcerpc_pipe *p)
{
	struct smb_private *smb = p->transport.private;
	return smb->tree->session->transport->called.name;
}

/* 
   open a rpc connection to a named pipe 
*/
NTSTATUS dcerpc_pipe_open_smb(struct dcerpc_pipe **p, 
			      struct smbcli_tree *tree,
			      const char *pipe_name)
{
	struct smb_private *smb;
        NTSTATUS status;
	char *name = NULL;
	union smb_open io;
	TALLOC_CTX *mem_ctx;

	asprintf(&name, "\\%s", pipe_name);
	if (!name) {
		return NT_STATUS_NO_MEMORY;
	}

	io.ntcreatex.level = RAW_OPEN_NTCREATEX;
	io.ntcreatex.in.flags = 0;
	io.ntcreatex.in.root_fid = 0;
	io.ntcreatex.in.access_mask = 
		STD_RIGHT_READ_CONTROL_ACCESS | 
		SA_RIGHT_FILE_WRITE_ATTRIBUTES | 
		SA_RIGHT_FILE_WRITE_EA | 
		GENERIC_RIGHTS_FILE_READ |
		GENERIC_RIGHTS_FILE_WRITE;
	io.ntcreatex.in.file_attr = 0;
	io.ntcreatex.in.alloc_size = 0;
	io.ntcreatex.in.share_access = 
		NTCREATEX_SHARE_ACCESS_READ |
		NTCREATEX_SHARE_ACCESS_WRITE;
	io.ntcreatex.in.open_disposition = NTCREATEX_DISP_OPEN;
	io.ntcreatex.in.create_options = 0;
	io.ntcreatex.in.impersonation = NTCREATEX_IMPERSONATION_IMPERSONATION;
	io.ntcreatex.in.security_flags = 0;
	io.ntcreatex.in.fname = name;

	mem_ctx = talloc_init("torture_rpc_connection");
	if (!mem_ctx) {
		free(name);
		return NT_STATUS_NO_MEMORY;
	}
	status = smb_raw_open(tree, mem_ctx, &io);
	free(name);
	talloc_destroy(mem_ctx);

	if (!NT_STATUS_IS_OK(status)) {
                return status;
        }

        if (!(*p = dcerpc_pipe_init())) {
                return NT_STATUS_NO_MEMORY;
	}
 
	/*
	  fill in the transport methods
	*/
	(*p)->transport.transport = NCACN_NP;
	(*p)->transport.private = NULL;
	(*p)->transport.full_request = smb_full_request;
	(*p)->transport.secondary_request = smb_secondary_request;
	(*p)->transport.initial_request = smb_initial_request;
	(*p)->transport.shutdown_pipe = smb_shutdown_pipe;
	(*p)->transport.peer_name = smb_peer_name;
	
	smb = talloc((*p)->mem_ctx, sizeof(*smb));
	if (!smb) {
		dcerpc_pipe_close(*p);
		return NT_STATUS_NO_MEMORY;
	}

	smb->fnum = io.ntcreatex.out.fnum;
	smb->tree = tree;

	(*p)->transport.private = smb;
	tree->reference_count++;

        return NT_STATUS_OK;
}

/*
  return the SMB tree used for a dcerpc over SMB pipe
*/
struct smbcli_tree *dcerpc_smb_tree(struct dcerpc_pipe *p)
{
	struct smb_private *smb = p->transport.private;

	if (p->transport.transport != NCACN_NP) {
		return NULL;
	}

	return smb->tree;
}
