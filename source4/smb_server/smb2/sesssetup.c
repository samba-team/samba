/* 
   Unix SMB2 implementation.
   
   Copyright (C) Andrew Bartlett	2001-2005
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "auth/auth.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "smb_server/smb_server.h"
#include "smb_server/smb2/smb2_server.h"
#include "smbd/service_stream.h"

static NTSTATUS smb2srv_sesssetup_backend(struct smb2srv_request *req, struct smb2_session_setup *io)
{
	NTSTATUS status = NT_STATUS_ACCESS_DENIED;
	struct smbsrv_session *smb_sess = NULL;
	struct auth_session_info *session_info = NULL;
	uint64_t vuid;

	io->out._pad	= 0;
	io->out.uid	= 0;
	io->out.secblob = data_blob(NULL, 0);

	vuid = BVAL(req->in.hdr, SMB2_HDR_UID);

	/* TODO: we're stricter than the SMB version till we have
	 *       SMB2-CONTEXT test
	 */
	if (vuid == 0) {
		struct gensec_security *gensec_ctx;

		status = gensec_server_start(req, &gensec_ctx,
					     req->smb_conn->connection->event.ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC server code: %s\n", nt_errstr(status)));
			return status;
		}

		gensec_set_credentials(gensec_ctx, req->smb_conn->negotiate.server_credentials);

		gensec_set_target_service(gensec_ctx, "cifs");

		gensec_want_feature(gensec_ctx, GENSEC_FEATURE_SESSION_KEY);

		status = gensec_start_mech_by_oid(gensec_ctx, GENSEC_OID_SPNEGO);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC SPNEGO server code: %s\n", nt_errstr(status)));
			return status;
		}

		/* allocate a new session */
		smb_sess = smbsrv_session_new(req->smb_conn, gensec_ctx);
	} else {
		/* lookup an existing session */
		smb_sess = smbsrv_session_find_sesssetup(req->smb_conn, vuid);
	}

	if (!smb_sess) {
		return NT_STATUS_ACCESS_DENIED;
	}

	if (!smb_sess->gensec_ctx) {
		status = NT_STATUS_INTERNAL_ERROR;
		DEBUG(1, ("Internal ERROR: no gensec_ctx on session: %s\n", nt_errstr(status)));
		goto failed;
	}

	status = gensec_update(smb_sess->gensec_ctx, req, io->in.secblob, &io->out.secblob);
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		io->out.uid = smb_sess->vuid;
		return status;
	} else if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	status = gensec_session_info(smb_sess->gensec_ctx, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}
		
	/* Ensure this is marked as a 'real' vuid, not one
	 * simply valid for the session setup leg */
	status = smbsrv_session_sesssetup_finished(smb_sess, session_info);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}
	req->session = smb_sess;

	io->out.uid = smb_sess->vuid;
	return status;

failed:
	talloc_free(smb_sess);
	return auth_nt_status_squash(status);
}

static void smb2srv_sesssetup_send(struct smb2srv_request *req, struct smb2_session_setup *io)
{
	NTSTATUS status;

	if (NT_STATUS_IS_ERR(req->status) && !NT_STATUS_EQUAL(req->status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		smb2srv_send_error(req, req->status);
		return;
	}

	status = smb2srv_setup_reply(req, 0x08, io->out.secblob.length);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	SBVAL(req->out.hdr, SMB2_HDR_UID,    io->out.uid);

	SSVAL(req->out.body, 0x02, io->out._pad);
	status = smb2_push_o16s16_blob(&req->out, 0x04, io->out.secblob);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	smb2srv_send_reply(req);
}

void smb2srv_sesssetup_recv(struct smb2srv_request *req)
{
	struct smb2_session_setup *io;
	NTSTATUS status;

	if (req->in.body_size < 0x10) {
		smb2srv_send_error(req,  NT_STATUS_FOOBAR);
		return;
	}

	io = talloc(req, struct smb2_session_setup);
	if (!io) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(NT_STATUS_NO_MEMORY));
		talloc_free(req);
		return;
	}

	io->in._pad	= SVAL(req->in.body, 0x02);
	io->in.unknown2 = IVAL(req->in.body, 0x04);
	io->in.unknown3 = IVAL(req->in.body, 0x08);
	status = smb2_pull_o16s16_blob(&req->in, io, req->in.body+0x0C, &io->in.secblob);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	req->status = smb2srv_sesssetup_backend(req, io);

	if (req->control_flags & SMB2SRV_REQ_CTRL_FLAG_NOT_REPLY) {
		talloc_free(req);
		return;
	}
	smb2srv_sesssetup_send(req, io);
}

static NTSTATUS smb2srv_logoff_backend(struct smb2srv_request *req)
{
	/* TODO: call ntvfs backends to close file of this session */
	talloc_free(req->session);
	req->session = NULL;
	return NT_STATUS_OK;
}

static void smb2srv_logoff_send(struct smb2srv_request *req)
{
	NTSTATUS status;

	if (NT_STATUS_IS_ERR(req->status)) {
		smb2srv_send_error(req, req->status);
		return;
	}

	status = smb2srv_setup_reply(req, 0x04, 0);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	SSVAL(req->out.body, 0x02, 0);

	smb2srv_send_reply(req);
}

void smb2srv_logoff_recv(struct smb2srv_request *req)
{
	uint16_t _pad;

	if (req->in.body_size < 0x04) {
		smb2srv_send_error(req,  NT_STATUS_FOOBAR);
		return;
	}

	_pad	= SVAL(req->in.body, 0x02);

	req->status = smb2srv_logoff_backend(req);

	if (req->control_flags & SMB2SRV_REQ_CTRL_FLAG_NOT_REPLY) {
		talloc_free(req);
		return;
	}
	smb2srv_logoff_send(req);
}
