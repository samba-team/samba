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
	
	req = smb2_request_init(transport, SMB2_OP_NEGPROT, 0x26, False, 0);
	if (req == NULL) return NULL;

	/* this seems to be a bug, they use 0x24 but the length is 0x26 */
	SSVAL(req->out.body, 0x00, 0x24);

	SSVAL(req->out.body, 0x02, io->in.unknown1);
	memcpy(req->out.body+0x04, io->in.unknown2, 32);
	SSVAL(req->out.body, 0x24, io->in.unknown3);

	smb2_transport_send(req);

	return req;
}

/*
  recv a negprot reply
*/
NTSTATUS smb2_negprot_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx, 
			   struct smb2_negprot *io)
{
	NTSTATUS status;

	if (!smb2_request_receive(req) ||
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	SMB2_CHECK_PACKET_RECV(req, 0x40, True);

	io->out._pad         = SVAL(req->in.body, 0x02);
	io->out.unknown2     = IVAL(req->in.body, 0x04);
	memcpy(io->out.sessid, req->in.body + 0x08, 16);
	io->out.unknown3     = IVAL(req->in.body, 0x18);
	io->out.unknown4     = SVAL(req->in.body, 0x1C);
	io->out.unknown5     = IVAL(req->in.body, 0x1E);
	io->out.unknown6     = IVAL(req->in.body, 0x22);
	io->out.unknown7     = SVAL(req->in.body, 0x26);
	io->out.current_time = smbcli_pull_nttime(req->in.body, 0x28);
	io->out.boot_time    = smbcli_pull_nttime(req->in.body, 0x30);

	status = smb2_pull_o16s16_blob(&req->in, mem_ctx, req->in.body+0x38, &io->out.secblob);
	if (!NT_STATUS_IS_OK(status)) {
		smb2_request_destroy(req);
		return status;
	}
	
	io->out.unknown9     = IVAL(req->in.body, 0x3C);

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
