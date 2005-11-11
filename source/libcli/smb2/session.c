/* 
   Unix SMB/CIFS implementation.

   SMB2 client session handling

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
  initialise a smb2_session structure
 */
struct smb2_session *smb2_session_init(struct smb2_transport *transport,
				       TALLOC_CTX *parent_ctx, BOOL primary)
{
	struct smb2_session *session;
	NTSTATUS status;

	session = talloc_zero(parent_ctx, struct smb2_session);
	if (!session) {
		return NULL;
	}
	if (primary) {
		session->transport = talloc_steal(session, transport);
	} else {
		session->transport = talloc_reference(session, transport);
	}

	/* prepare a gensec context for later use */
	status = gensec_client_start(session, &session->gensec, 
				     session->transport->socket->event.ctx);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(session);
		return NULL;
	}

	return session;
}

/*
  send a session setup request
*/
struct smb2_request *smb2_session_setup_send(struct smb2_session *session, 
					     struct smb2_session_setup *io)
{
	struct smb2_request *req;
	
	req = smb2_request_init(session->transport, SMB2_OP_SESSSETUP, 
				0x10 + io->in.secblob.length);
	if (req == NULL) return NULL;

	SIVAL(req->out.body, 0x00, io->in.unknown1);
	SIVAL(req->out.body, 0x04, io->in.unknown2);
	SIVAL(req->out.body, 0x08, io->in.unknown3);
	SSVAL(req->out.body, 0x0C, io->in.unknown4);
	SSVAL(req->out.body, 0x0E, io->in.secblob.length);
	memcpy(req->out.body+0x10, io->in.secblob.data, io->in.secblob.length);

	smb2_transport_send(req);

	return req;
}


/*
  recv a session setup reply
*/
NTSTATUS smb2_session_setup_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx, 
				 struct smb2_session_setup *io)
{
	uint16_t blobsize;

	if (!smb2_request_receive(req) || 
	    smb2_request_is_error(req)) {
		return smb2_request_destroy(req);
	}

	if (req->in.body_size < 0x08) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	io->out.unknown1     = IVAL(req->in.body, 0x00);
	io->out.unknown2     = SVAL(req->in.body, 0x04);
	blobsize             = SVAL(req->in.body, 0x06);
	io->out.secblob      = smb2_pull_blob(req, req->in.body+0x08, blobsize);
	talloc_steal(mem_ctx, io->out.secblob.data);

	return smb2_request_destroy(req);
}

/*
  sync session setup request
*/
NTSTATUS smb2_session_setup(struct smb2_session *session, 
			    TALLOC_CTX *mem_ctx, struct smb2_session_setup *io)
{
	struct smb2_request *req = smb2_session_setup_send(session, io);
	return smb2_session_setup_recv(req, mem_ctx, io);
}
