/* 
   Unix SMB/CIFS implementation.

   SMB2 client request handling

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/smb2/smb2.h"
#include "include/dlinklist.h"
#include "lib/events/events.h"

/*
  initialise a smb2 request
*/
struct smb2_request *smb2_request_init(struct smb2_transport *transport, 
				       uint16_t opcode, uint32_t body_size)
{
	struct smb2_request *req;

	req = talloc(transport, struct smb2_request);
	if (req == NULL) return NULL;

	req->state     = SMB2_REQUEST_INIT;
	req->transport = transport;
	req->session   = NULL;
	req->tree      = NULL;
	req->seqnum    = transport->seqnum++;
	req->status    = NT_STATUS_OK;
	req->async.fn  = NULL;
	req->next = req->prev = NULL;

	ZERO_STRUCT(req->in);
	
	req->out.allocated = SMB2_HDR_BODY+NBT_HDR_SIZE+body_size;
	req->out.buffer    = talloc_size(req, req->out.allocated);
	if (req->out.buffer == NULL) {
		talloc_free(req);
		return NULL;
	}

	req->out.size      = SMB2_HDR_BODY+NBT_HDR_SIZE + body_size;
	req->out.hdr       = req->out.buffer + NBT_HDR_SIZE;
	req->out.body      = req->out.hdr + SMB2_HDR_BODY;
	req->out.body_size = body_size;
	req->out.ptr       = req->out.body;

	SIVAL(req->out.hdr, 0,                SMB2_MAGIC);
	SSVAL(req->out.hdr, SMB2_HDR_LENGTH,  SMB2_HDR_BODY);
	SSVAL(req->out.hdr, SMB2_HDR_PAD1,    0);
	SIVAL(req->out.hdr, SMB2_HDR_STATUS,  0);
	SSVAL(req->out.hdr, SMB2_HDR_OPCODE,  opcode);
	SSVAL(req->out.hdr, SMB2_HDR_PAD2,    0);
	SIVAL(req->out.hdr, SMB2_HDR_FLAGS,   0);
	SIVAL(req->out.hdr, SMB2_HDR_UNKNOWN, 0);
	SBVAL(req->out.hdr, SMB2_HDR_SEQNUM,  req->seqnum);
	SIVAL(req->out.hdr, SMB2_HDR_PID,     0);
	SIVAL(req->out.hdr, SMB2_HDR_TID,     0);
	SBVAL(req->out.hdr, SMB2_HDR_UID,     0);
	memset(req->out.hdr+SMB2_HDR_SIG, 0, 16);

	return req;
}

/*
    initialise a smb2 request for tree operations
*/
struct smb2_request *smb2_request_init_tree(struct smb2_tree *tree, 
					    uint16_t opcode, uint32_t body_size)
{
	struct smb2_request *req = smb2_request_init(tree->session->transport, opcode, 
						     body_size);
	if (req == NULL) return NULL;

	SBVAL(req->out.hdr,  SMB2_HDR_UID, tree->session->uid);
	SIVAL(req->out.hdr,  SMB2_HDR_TID, tree->tid);
	req->session = tree->session;
	req->tree = tree;

	return req;	
}

/* destroy a request structure and return final status */
NTSTATUS smb2_request_destroy(struct smb2_request *req)
{
	NTSTATUS status;

	/* this is the error code we give the application for when a
	   _send() call fails completely */
	if (!req) return NT_STATUS_UNSUCCESSFUL;

	if (req->transport) {
		/* remove it from the list of pending requests (a null op if
		   its not in the list) */
		DLIST_REMOVE(req->transport->pending_recv, req);
	}

	if (req->state == SMBCLI_REQUEST_ERROR &&
	    NT_STATUS_IS_OK(req->status)) {
		req->status = NT_STATUS_INTERNAL_ERROR;
	}

	status = req->status;
	talloc_free(req);
	return status;
}

/*
  receive a response to a packet
*/
BOOL smb2_request_receive(struct smb2_request *req)
{
	/* req can be NULL when a send has failed. This eliminates lots of NULL
	   checks in each module */
	if (!req) return False;

	/* keep receiving packets until this one is replied to */
	while (req->state <= SMB2_REQUEST_RECV) {
		if (event_loop_once(req->transport->socket->event.ctx) != 0) {
			return False;
		}
	}

	return req->state == SMB2_REQUEST_DONE;
}

/* Return true if the last packet was in error */
BOOL smb2_request_is_error(struct smb2_request *req)
{
	return NT_STATUS_IS_ERR(req->status);
}

/*
  check if a range in the reply body is out of bounds
*/
BOOL smb2_oob_in(struct smb2_request *req, const uint8_t *ptr, uint_t size)
{
	/* be careful with wraparound! */
	if (ptr < req->in.body ||
	    ptr >= req->in.body + req->in.body_size ||
	    size > req->in.body_size ||
	    ptr + size > req->in.body + req->in.body_size) {
		return True;
	}
	return False;
}

/*
  check if a range in the outgoing body is out of bounds
*/
BOOL smb2_oob_out(struct smb2_request *req, const uint8_t *ptr, uint_t size)
{
	/* be careful with wraparound! */
	if (ptr < req->out.body ||
	    ptr >= req->out.body + req->out.body_size ||
	    size > req->out.body_size ||
	    ptr + size > req->out.body + req->out.body_size) {
		return True;
	}
	return False;
}

/*
  pull a data blob from the body of a reply
*/
DATA_BLOB smb2_pull_blob(struct smb2_request *req, uint8_t *ptr, uint_t size)
{
	if (smb2_oob_in(req, ptr, size)) {
		return data_blob(NULL, 0);
	}
	return data_blob_talloc(req, ptr, size);
}

/*
  pull a ofs/length/blob triple into a data blob
  the ptr points to the start of the offset/length pair
*/
NTSTATUS smb2_pull_ofs_blob(struct smb2_request *req, uint8_t *ptr, DATA_BLOB *blob)
{
	uint16_t ofs, size;
	if (smb2_oob_in(req, ptr, 4)) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	ofs  = SVAL(ptr, 0);
	size = SVAL(ptr, 2);
	if (smb2_oob_in(req, req->in.hdr + ofs, size)) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	*blob = data_blob_talloc(req, req->in.hdr+ofs, size);
	NT_STATUS_HAVE_NO_MEMORY(blob->data);
	return NT_STATUS_OK;
}

/*
  push a ofs/length/blob triple into a data blob
  the ptr points to the start of the offset/length pair

  NOTE: assumes blob goes immediately after the offset/length pair. Needs 
        to be generalised
*/
NTSTATUS smb2_push_ofs_blob(struct smb2_request *req, uint8_t *ptr, DATA_BLOB blob)
{
	if (smb2_oob_out(req, ptr, 4+blob.length)) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}
	SSVAL(ptr, 0, 4 + (ptr - req->out.hdr));
	SSVAL(ptr, 2, blob.length);
	memcpy(ptr+4, blob.data, blob.length);
	return NT_STATUS_OK;
}

/*
  pull a string in a ofs/length/blob format
*/
NTSTATUS smb2_pull_ofs_string(struct smb2_request *req, uint8_t *ptr, 
			      const char **str)
{
	DATA_BLOB blob;
	NTSTATUS status;
	ssize_t size;
	void *vstr;
	status = smb2_pull_ofs_blob(req, ptr, &blob);
	NT_STATUS_NOT_OK_RETURN(status);
	size = convert_string_talloc(req, CH_UTF16, CH_UNIX, 
				     blob.data, blob.length, &vstr);
	data_blob_free(&blob);
	(*str) = vstr;
	if (size == -1) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}
	return NT_STATUS_OK;
}

/*
  create a UTF16 string in a blob from a char*
*/
NTSTATUS smb2_string_blob(TALLOC_CTX *mem_ctx, const char *str, DATA_BLOB *blob)
{
	ssize_t size;
	size = convert_string_talloc(mem_ctx, CH_UNIX, CH_UTF16, 
				     str, strlen(str), (void **)&blob->data);
	if (size == -1) {
		return NT_STATUS_ILLEGAL_CHARACTER;
	}
	blob->length = size;
	return NT_STATUS_OK;	
}
