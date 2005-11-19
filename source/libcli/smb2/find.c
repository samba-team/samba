/* 
   Unix SMB/CIFS implementation.

   SMB2 client find calls

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
  send a find request
*/
struct smb2_request *smb2_find_send(struct smb2_tree *tree, struct smb2_find *io)
{
	struct smb2_request *req;
	NTSTATUS status;

	req = smb2_request_init_tree(tree, SMB2_OP_FIND, 0x20, 1);
	if (req == NULL) return NULL;

	SCVAL(req->out.body, 0x02, io->in.level);
	SCVAL(req->out.body, 0x03, io->in.continue_flags);
	SIVAL(req->out.body, 0x04, io->in.unknown);
	smb2_push_handle(req->out.body+0x08, &io->in.handle);
	SIVAL(req->out.body, 0x1C, io->in.max_response_size);

	status = smb2_push_o16s16_string(&req->out, 0x18, io->in.pattern);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	smb2_transport_send(req);

	return req;
}


/*
  recv a find reply
*/
NTSTATUS smb2_find_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx,
			   struct smb2_find *io)
{
	NTSTATUS status;

	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	SMB2_CHECK_PACKET_RECV(req, 0x08, True);

	status = smb2_pull_o16s32_blob(&req->in, mem_ctx, 
				       req->in.body+0x02, &io->out.blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return smb2_request_destroy(req);
}

/*
  sync find request
*/
NTSTATUS smb2_find(struct smb2_tree *tree, TALLOC_CTX *mem_ctx,
		      struct smb2_find *io)
{
	struct smb2_request *req = smb2_find_send(tree, io);
	return smb2_find_recv(req, mem_ctx, io);
}

