/* 
   Unix SMB/CIFS implementation.

   SMB2 client tree handling

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
  send a create request
*/
struct smb2_request *smb2_create_send(struct smb2_tree *tree, struct smb2_create *io)
{
	struct smb2_request *req;
	NTSTATUS status;

	req = smb2_request_init_tree(tree, SMB2_OP_CREATE, 0x38, 1);
	if (req == NULL) return NULL;

	SSVAL(req->out.body, 0x02, io->in.oplock_flags);
	SIVAL(req->out.body, 0x04, io->in.unknown2);
	SIVAL(req->out.body, 0x08, io->in.unknown3[0]);
	SIVAL(req->out.body, 0x0C, io->in.unknown3[1]);
	SIVAL(req->out.body, 0x10, io->in.unknown3[2]);
	SIVAL(req->out.body, 0x14, io->in.unknown3[3]);
	SIVAL(req->out.body, 0x18, io->in.access_mask);
	SIVAL(req->out.body, 0x1C, io->in.file_attr);
	SIVAL(req->out.body, 0x20, io->in.share_access);
	SIVAL(req->out.body, 0x24, io->in.open_disposition);
	SIVAL(req->out.body, 0x28, io->in.create_options);

	status = smb2_push_o16s16_string(&req->out, 0x2C, io->in.fname);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	status = smb2_push_o32s32_blob(&req->out, 0x30, io->in.blob);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	smb2_transport_send(req);

	return req;
}


/*
  recv a create reply
*/
NTSTATUS smb2_create_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx, struct smb2_create *io)
{
	NTSTATUS status;

	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	SMB2_CHECK_PACKET_RECV(req, 0x58, True);

	io->out.oplock_flags   = SVAL(req->in.body, 0x02);
	io->out.create_action  = IVAL(req->in.body, 0x04);
	io->out.create_time    = smbcli_pull_nttime(req->in.body, 0x08);
	io->out.access_time    = smbcli_pull_nttime(req->in.body, 0x10);
	io->out.write_time     = smbcli_pull_nttime(req->in.body, 0x18);
	io->out.change_time    = smbcli_pull_nttime(req->in.body, 0x20);
	io->out.alloc_size     = BVAL(req->in.body, 0x28);
	io->out.size           = BVAL(req->in.body, 0x30);
	io->out.file_attr      = IVAL(req->in.body, 0x38);
	io->out._pad           = IVAL(req->in.body, 0x3C);
	smb2_pull_handle(req->in.body+0x40, &io->out.handle);
	status = smb2_pull_o32s32_blob(&req->in, mem_ctx, req->in.body+0x50, &io->out.blob);
	if (!NT_STATUS_IS_OK(status)) {
		smb2_request_destroy(req);
		return status;
	}

	return smb2_request_destroy(req);
}

/*
  sync create request
*/
NTSTATUS smb2_create(struct smb2_tree *tree, TALLOC_CTX *mem_ctx, struct smb2_create *io)
{
	struct smb2_request *req = smb2_create_send(tree, io);
	return smb2_create_recv(req, mem_ctx, io);
}
