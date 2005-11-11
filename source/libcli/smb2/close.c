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
  send a close request
*/
struct smb2_request *smb2_close_send(struct smb2_tree *tree, struct smb2_close *io)
{
	struct smb2_request *req;

	req = smb2_request_init_tree(tree, SMB2_OP_CLOSE, 0x18);
	if (req == NULL) return NULL;

	SSVAL(req->out.body, 0x00, io->in.buffer_code);
	SSVAL(req->out.body, 0x02, io->in.flags);
	SIVAL(req->out.body, 0x04, io->in._pad);
	SBVAL(req->out.body, 0x08, io->in.handle.data[0]);
	SBVAL(req->out.body, 0x10, io->in.handle.data[1]);

	smb2_transport_send(req);

	return req;
}


/*
  recv a close reply
*/
NTSTATUS smb2_close_recv(struct smb2_request *req, struct smb2_close *io)
{
	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	if (req->in.body_size < 0x3C) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	io->out.buffer_code = SVAL(req->in.body, 0x00);
	io->out.flags       = SVAL(req->in.body, 0x02);
	io->out._pad        = IVAL(req->in.body, 0x04);
	io->out.create_time = smbcli_pull_nttime(req->in.body, 0x08);
	io->out.access_time = smbcli_pull_nttime(req->in.body, 0x10);
	io->out.write_time  = smbcli_pull_nttime(req->in.body, 0x18);
	io->out.change_time = smbcli_pull_nttime(req->in.body, 0x20);
	io->out.alloc_size  = BVAL(req->in.body, 0x28);
	io->out.size        = BVAL(req->in.body, 0x30);
	io->out.file_attr   = IVAL(req->in.body, 0x38);

	return smb2_request_destroy(req);
}

/*
  sync close request
*/
NTSTATUS smb2_close(struct smb2_tree *tree, struct smb2_close *io)
{
	struct smb2_request *req = smb2_close_send(tree, io);
	return smb2_close_recv(req, io);
}
