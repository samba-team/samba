/* 
   Unix SMB/CIFS implementation.

   SMB2 client getinfo calls

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
  send a getinfo request
*/
struct smb2_request *smb2_getinfo_send(struct smb2_tree *tree, struct smb2_getinfo *io)
{
	struct smb2_request *req;

	req = smb2_request_init_tree(tree, SMB2_OP_GETINFO, 0x28);
	if (req == NULL) return NULL;

	SSVAL(req->out.body, 0x00, io->in.buffer_code);
	SSVAL(req->out.body, 0x02, io->in.level);
	SIVAL(req->out.body, 0x04, io->in.max_response_size);
	SIVAL(req->out.body, 0x08, io->in.unknown1);
	SIVAL(req->out.body, 0x0C, io->in.unknown2);
	SIVAL(req->out.body, 0x10, io->in.unknown3);
	SIVAL(req->out.body, 0x14, io->in.unknown4);
	SBVAL(req->out.body, 0x18, io->in.handle.data[0]);
	SBVAL(req->out.body, 0x20, io->in.handle.data[1]);

	smb2_transport_send(req);

	return req;
}


/*
  recv a getinfo reply
*/
NTSTATUS smb2_getinfo_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx,
			   struct smb2_getinfo *io)
{
	NTSTATUS status;

	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	if (req->in.body_size < 0x08) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	SMB2_CHECK_BUFFER_CODE(req, 0x09);

	status = smb2_pull_ofs_blob(req, req->in.body+0x02, &io->out.blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	talloc_steal(mem_ctx, io->out.blob.data);

	return smb2_request_destroy(req);
}

/*
  sync getinfo request
*/
NTSTATUS smb2_getinfo(struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
		      struct smb2_getinfo *io)
{
	struct smb2_request *req = smb2_getinfo_send(tree, io);
	return smb2_getinfo_recv(req, mem_ctx, io);
}
