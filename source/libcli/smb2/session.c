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
	NTSTATUS status;
	
	req = smb2_request_init(session->transport, SMB2_OP_SESSSETUP, 
				0x10 + io->in.secblob.length);
	if (req == NULL) return NULL;

	SBVAL(req->out.hdr,  SMB2_HDR_UID, session->uid);
	SIVAL(req->out.body, 0x00, io->in.unknown1);
	SIVAL(req->out.body, 0x04, io->in.unknown2);
	SIVAL(req->out.body, 0x08, io->in.unknown3);
	
	status = smb2_push_ofs_blob(req, req->out.body+0x0C, io->in.secblob);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(req);
		return NULL;
	}

	smb2_transport_send(req);

	return req;
}


/*
  recv a session setup reply
*/
NTSTATUS smb2_session_setup_recv(struct smb2_request *req, TALLOC_CTX *mem_ctx, 
				 struct smb2_session_setup *io)
{
	NTSTATUS status;

	if (!smb2_request_receive(req) || 
	    (smb2_request_is_error(req) && 
	     !NT_STATUS_EQUAL(req->status, NT_STATUS_MORE_PROCESSING_REQUIRED))) {
		return smb2_request_destroy(req);
	}

	if (req->in.body_size < 0x08) {
		return NT_STATUS_BUFFER_TOO_SMALL;
	}

	io->out.unknown1 = IVAL(req->in.body, 0x00);
	io->out.uid      = BVAL(req->in.hdr,  SMB2_HDR_UID);
	
	status = smb2_pull_ofs_blob(req, req->in.body+0x04, &io->out.secblob);
	if (!NT_STATUS_IS_OK(status)) {
		smb2_request_destroy(req);
		return status;
	}
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
