/* 
   Unix SMB/CIFS implementation.

   SMB2 client write call

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
#include "libcli/smb2/smb2_calls.h"

/*
  send a write request
*/
struct smb2_request *smb2_write_send(struct smb2_tree *tree, struct smb2_write *io)
{
	NTSTATUS status;
	struct smb2_request *req;

	req = smb2_request_init_tree(tree, SMB2_OP_WRITE, io->in.data.length + 0x30);
	if (req == NULL) return NULL;

	SSVAL(req->out.body, 0x00, io->in.buffer_code);
	SSVAL(req->out.body, 0x02, req->out.body+0x30 - req->out.hdr);
	SIVAL(req->out.body, 0x04, io->in.data.length);
	SBVAL(req->out.body, 0x08, io->in.offset);
	smb2_put_handle(req->out.body+0x10, &io->in.handle);
	memcpy(req->out.body+0x20, io->in._pad, 0x10);

	status = smb2_push_blob(&req->out, req->out.body+0x30, io->in.data);
	if (!NT_STATUS_IS_OK(status)) {
		return NULL;
	}

	smb2_transport_send(req);

	return req;
}


/*
  recv a write reply
*/
NTSTATUS smb2_write_recv(struct smb2_request *req, struct smb2_write *io)
{
	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	if (req->in.body_size < 17) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	SMB2_CHECK_BUFFER_CODE(req, 0x11);

	io->out._pad     = SVAL(req->in.body, 0x02);
	io->out.nwritten = IVAL(req->in.body, 0x04);
	memcpy(io->out.unknown, req->in.body+0x08, 9);

	return smb2_request_destroy(req);
}

/*
  sync write request
*/
NTSTATUS smb2_write(struct smb2_tree *tree, struct smb2_write *io)
{
	struct smb2_request *req = smb2_write_send(tree, io);
	return smb2_write_recv(req, io);
}
