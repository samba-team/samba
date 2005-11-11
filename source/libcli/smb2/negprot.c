/* 
   Unix SMB/CIFS implementation.

   SMB2 client negprot handling

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
  send a negprot request
*/
struct smb2_request *smb2_negprot_send(struct smb2_transport *transport, 
				       struct smb2_negprot *io)
{
	struct smb2_request *req;
	

	req = smb2_request_init(transport, SMB2_OP_NEGPROT, 0x26);
	if (req == NULL) return NULL;

	SIVAL(req->out.body, 0x00, io->in.unknown1);
	SSVAL(req->out.body, 0x04, io->in.unknown2);
	memcpy(req->out.body+0x06, io->in.unknown3, 32);

	smb2_transport_send(req);

	return req;
}

/*
  recv a negprot reply
*/
NTSTATUS smb2_negprot_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx, 
			   struct smb2_negprot *io)
{
	uint16_t blobsize;

	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	if (req->in.body_size < 0x40) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	io->out.unknown1     = IVAL(req->in.body, 0x00);
	io->out.unknown2     = IVAL(req->in.body, 0x04);
	memcpy(io->out.sessid, req->in.body + 0x08, 16);
	io->out.unknown3     = IVAL(req->in.body, 0x18);
	io->out.unknown4     = SVAL(req->in.body, 0x1C);
	io->out.unknown5     = IVAL(req->in.body, 0x1E);
	io->out.unknown6     = IVAL(req->in.body, 0x22);
	io->out.unknown7     = SVAL(req->in.body, 0x26);
	io->out.current_time = smbcli_pull_nttime(req->in.body, 0x28);
	io->out.boot_time    = smbcli_pull_nttime(req->in.body, 0x30);
	io->out.unknown8     = SVAL(req->in.body, 0x38);
	blobsize             = SVAL(req->in.body, 0x3A);
	io->out.unknown9     = IVAL(req->in.body, 0x3C);
	io->out.secblob      = smb2_pull_blob(req, req->in.body+0x40, blobsize);
	talloc_steal(mem_ctx, io->out.secblob.data);

	return smb2_request_destroy(req);
}

/*
  sync negprot request
*/
NTSTATUS smb2_negprot(struct smb2_transport *transport, 
		      TALLOC_CTX *mem_ctx, struct smb2_negprot *io)
{
	struct smb2_request *req = smb2_negprot_send(transport, io);
	return smb2_negprot_recv(req, mem_ctx, io);
}
