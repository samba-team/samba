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
#include "auth/credentials/credentials.h"
#include "auth/gensec/gensec.h"
#include "auth/auth.h"
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "smb_server/smb_server.h"
#include "smb_server/service_smb_proto.h"
#include "smb_server/smb2/smb2_server.h"
#include "smbd/service_stream.h"

static void smb2srv_sesssetup_send(struct smb2srv_request *req, union smb_sesssetup *io)
{
	uint16_t unknown1;

	if (NT_STATUS_IS_OK(req->status)) {
		unknown1 = 0x0003;
	} else if (NT_STATUS_EQUAL(req->status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		unknown1 = 0x0002;
	} else {
		smb2srv_send_error(req, req->status);
		return;
	}

	SMB2SRV_CHECK(smb2srv_setup_reply(req, 0x08, True, io->smb2.out.secblob.length));

	SSVAL(req->out.hdr, SMB2_HDR_UNKNOWN1,	unknown1);
	SBVAL(req->out.hdr, SMB2_HDR_UID,	io->smb2.out.uid);

	SSVAL(req->out.body, 0x02, io->smb2.out._pad);
	SMB2SRV_CHECK(smb2_push_o16s16_blob(&req->out, 0x04, io->smb2.out.secblob));

	smb2srv_send_reply(req);
}

struct smb2srv_sesssetup_callback_ctx {
	struct smb2srv_request *req;
	union smb_sesssetup *io;
	struct smbsrv_session *smb_sess;
};

static void smb2srv_sesssetup_callback(struct gensec_update_request *greq, void *private_data)
{
	struct smb2srv_sesssetup_callback_ctx *ctx = talloc_get_type(private_data,
						     struct smb2srv_sesssetup_callback_ctx);
	struct smb2srv_request *req = ctx->req;
	union smb_sesssetup *io = ctx->io;
	struct smbsrv_session *smb_sess = ctx->smb_sess;
	struct auth_session_info *session_info = NULL;
	NTSTATUS status;

	status = gensec_update_recv(greq, req, &io->smb2.out.secblob);
	if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto done;
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

done:
	io->smb2.out.uid = smb_sess->vuid;
failed:
	req->status = auth_nt_status_squash(status);
	smb2srv_sesssetup_send(req, io);
	if (!NT_STATUS_IS_OK(status) && !
	    NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		talloc_free(smb_sess);
	}
}

static void smb2srv_sesssetup_backend(struct smb2srv_request *req, union smb_sesssetup *io)
{
	NTSTATUS status;
	struct smb2srv_sesssetup_callback_ctx *callback_ctx;
	struct smbsrv_session *smb_sess = NULL;
	uint64_t vuid;

	io->smb2.out._pad	= 0;
	io->smb2.out.uid	= 0;
	io->smb2.out.secblob = data_blob(NULL, 0);

	vuid = BVAL(req->in.hdr, SMB2_HDR_UID);

	/*
	 * only when we got '0' we should allocate a new session
	 */
	if (vuid == 0) {
		struct gensec_security *gensec_ctx;

		status = gensec_server_start(req,
					     req->smb_conn->connection->event.ctx,
					     req->smb_conn->connection->msg_ctx,
					     &gensec_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC server code: %s\n", nt_errstr(status)));
			goto failed;
		}

		gensec_set_credentials(gensec_ctx, req->smb_conn->negotiate.server_credentials);

		gensec_set_target_service(gensec_ctx, "cifs");

		gensec_want_feature(gensec_ctx, GENSEC_FEATURE_SESSION_KEY);

		status = gensec_start_mech_by_oid(gensec_ctx, GENSEC_OID_SPNEGO);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC SPNEGO server code: %s\n", nt_errstr(status)));
			goto failed;
		}

		/* allocate a new session */
		smb_sess = smbsrv_session_new(req->smb_conn, req->smb_conn, gensec_ctx);
		if (!smb_sess) {
			status = NT_STATUS_INSUFFICIENT_RESOURCES;
			goto failed;
		}
		status = smbsrv_smb2_init_tcons(smb_sess);
		if (!NT_STATUS_IS_OK(status)) {
			goto failed;
		}
	} else {
		/* lookup an existing session */
		smb_sess = smbsrv_session_find_sesssetup(req->smb_conn, vuid);
	}

	if (!smb_sess) {
		status = NT_STATUS_USER_SESSION_DELETED;
		goto failed;
	}

	if (!smb_sess->gensec_ctx) {
		status = NT_STATUS_INTERNAL_ERROR;
		DEBUG(1, ("Internal ERROR: no gensec_ctx on session: %s\n", nt_errstr(status)));
		goto failed;
	}

	callback_ctx = talloc(req, struct smb2srv_sesssetup_callback_ctx);
	if (!callback_ctx) goto nomem;
	callback_ctx->req	= req;
	callback_ctx->io	= io;
	callback_ctx->smb_sess	= smb_sess;

	gensec_update_send(smb_sess->gensec_ctx, io->smb2.in.secblob,
			   smb2srv_sesssetup_callback, callback_ctx);
	return;
nomem:
	status = NT_STATUS_NO_MEMORY;
failed:
	talloc_free(smb_sess);
	req->status = auth_nt_status_squash(status);
	smb2srv_sesssetup_send(req, io);
}

void smb2srv_sesssetup_recv(struct smb2srv_request *req)
{
	union smb_sesssetup *io;

	SMB2SRV_CHECK_BODY_SIZE(req, 0x18, True);
	SMB2SRV_TALLOC_IO_PTR(io, union smb_sesssetup);

	io->smb2.level		= RAW_SESSSETUP_SMB2;
	io->smb2.in._pad	= SVAL(req->in.body, 0x02);
	io->smb2.in.unknown2	= IVAL(req->in.body, 0x04);
	io->smb2.in.unknown3	= IVAL(req->in.body, 0x08);
	SMB2SRV_CHECK(smb2_pull_o16s16_blob(&req->in, io, req->in.body+0x0C, &io->smb2.in.secblob));
	io->smb2.in.unknown4	= BVAL(req->in.body, 0x10);

	smb2srv_sesssetup_backend(req, io);
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
	if (NT_STATUS_IS_ERR(req->status)) {
		smb2srv_send_error(req, req->status);
		return;
	}

	SMB2SRV_CHECK(smb2srv_setup_reply(req, 0x04, False, 0));

	SSVAL(req->out.body, 0x02, 0);

	smb2srv_send_reply(req);
}

void smb2srv_logoff_recv(struct smb2srv_request *req)
{
	uint16_t _pad;

	SMB2SRV_CHECK_BODY_SIZE(req, 0x04, False);

	_pad	= SVAL(req->in.body, 0x02);

	req->status = smb2srv_logoff_backend(req);

	if (req->control_flags & SMB2SRV_REQ_CTRL_FLAG_NOT_REPLY) {
		talloc_free(req);
		return;
	}
	smb2srv_logoff_send(req);
}
