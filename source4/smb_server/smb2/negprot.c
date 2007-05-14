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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "smb_server/smb_server.h"
#include "smb_server/service_smb_proto.h"
#include "smb_server/smb2/smb2_server.h"
#include "smbd/service_stream.h"

static NTSTATUS smb2srv_negprot_secblob(struct smb2srv_request *req, DATA_BLOB *_blob)
{
	struct gensec_security *gensec_security;
	DATA_BLOB null_data_blob = data_blob(NULL, 0);
	DATA_BLOB blob;
	NTSTATUS nt_status;
	struct cli_credentials *server_credentials;

	nt_status = gensec_server_start(req,
					req->smb_conn->connection->event.ctx,
					req->smb_conn->connection->msg_ctx,
					&gensec_security);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Failed to start GENSEC: %s\n", nt_errstr(nt_status)));
		smbsrv_terminate_connection(req->smb_conn, "Failed to start GENSEC\n");
		return nt_status;
	}

	server_credentials = cli_credentials_init(req);
	if (!server_credentials) {
		smbsrv_terminate_connection(req->smb_conn, "Failed to init server credentials\n");
		return NT_STATUS_NO_MEMORY;
	}

	cli_credentials_set_conf(server_credentials);
	nt_status = cli_credentials_set_machine_account(server_credentials);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(10, ("Failed to obtain server credentials, perhaps a standalone server?: %s\n", nt_errstr(nt_status)));
		talloc_free(server_credentials);
		server_credentials = NULL;
	}

	req->smb_conn->negotiate.server_credentials = talloc_steal(req->smb_conn, server_credentials);

	gensec_set_target_service(gensec_security, "cifs");

	gensec_set_credentials(gensec_security, server_credentials);

	nt_status = gensec_start_mech_by_oid(gensec_security, GENSEC_OID_SPNEGO);
	if (!NT_STATUS_IS_OK(nt_status)) {
		DEBUG(0, ("Failed to start SPNEGO: %s\n", nt_errstr(nt_status)));
		smbsrv_terminate_connection(req->smb_conn, "Failed to start SPNEGO\n");
		return nt_status;
	}

	nt_status = gensec_update(gensec_security, req, null_data_blob, &blob);
	if (!NT_STATUS_IS_OK(nt_status) && !NT_STATUS_EQUAL(nt_status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		DEBUG(0, ("Failed to get SPNEGO to give us the first token: %s\n", nt_errstr(nt_status)));
		smbsrv_terminate_connection(req->smb_conn, "Failed to start SPNEGO - no first token\n");
		return nt_status;
	}

	*_blob = blob;
	return NT_STATUS_OK;
}

static NTSTATUS smb2srv_negprot_backend(struct smb2srv_request *req, struct smb2_negprot *io)
{
	NTSTATUS status;
	struct timeval current_time;
	struct timeval boot_time;

	req->smb_conn->negotiate.protocol = PROTOCOL_SMB2;

	current_time = timeval_current(); /* TODO: handle timezone?! */
	boot_time = timeval_current(); /* TODO: fix me */

	io->out._pad		= 0;
	io->out.unknown2	= 0x06;
	ZERO_STRUCT(io->out.sessid);
	io->out.unknown3	= 0x0d;
	io->out.unknown4	= 0x00;
	io->out.unknown5	= 0x01;
	io->out.unknown6	= 0x01;
	io->out.unknown7	= 0x01;
	io->out.current_time	= timeval_to_nttime(&current_time);
	io->out.boot_time	= timeval_to_nttime(&boot_time);
	status = smb2srv_negprot_secblob(req, &io->out.secblob);
	NT_STATUS_NOT_OK_RETURN(status);
	io->out.unknown9	= 0x204d4c20;

	return NT_STATUS_OK;
}

static void smb2srv_negprot_send(struct smb2srv_request *req, struct smb2_negprot *io)
{
	NTSTATUS status;

	if (NT_STATUS_IS_ERR(req->status)) {
		smb2srv_send_error(req, req->status); /* TODO: is this correct? */
		return;
	}

	status = smb2srv_setup_reply(req, 0x40, True, io->out.secblob.length);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	SSVAL(req->out.body, 0x02, io->out._pad);
	SIVAL(req->out.body, 0x04, io->out.unknown2);
	memcpy(req->out.body+0x08, io->out.sessid, 16);
	SIVAL(req->out.body, 0x18, io->out.unknown3);
	SSVAL(req->out.body, 0x1C, io->out.unknown4);
	SIVAL(req->out.body, 0x1E, io->out.unknown5);
	SIVAL(req->out.body, 0x22, io->out.unknown6);
	SSVAL(req->out.body, 0x26, io->out.unknown7);
	push_nttime(req->out.body, 0x28, io->out.current_time);
	push_nttime(req->out.body, 0x30, io->out.boot_time);
	status = smb2_push_o16s16_blob(&req->out, 0x38, io->out.secblob);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	SIVAL(req->out.body, 0x3C, io->out.unknown9);

	smb2srv_send_reply(req);
}

void smb2srv_negprot_recv(struct smb2srv_request *req)
{
	struct smb2_negprot *io;

	if (req->in.body_size < 0x26) {
		smb2srv_send_error(req,  NT_STATUS_FOOBAR);
		return;
	}

	io = talloc(req, struct smb2_negprot);
	if (!io) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(NT_STATUS_NO_MEMORY));
		talloc_free(req);
		return;
	}

	io->in.unknown1	= SVAL(req->in.body, 0x02);
	memcpy(io->in.unknown2, req->in.body + 0x04, 0x20);
	io->in.unknown3 = SVAL(req->in.body, 0x24);

	req->status = smb2srv_negprot_backend(req, io);

	if (req->control_flags & SMB2SRV_REQ_CTRL_FLAG_NOT_REPLY) {
		talloc_free(req);
		return;
	}
	smb2srv_negprot_send(req, io);
}

/*
 * reply to a SMB negprot request with dialect "SMB 2.001"
 */
void smb2srv_reply_smb_negprot(struct smbsrv_request *smb_req)
{
	struct smb2srv_request *req;
	uint32_t body_fixed_size = 0x26;

	/* create a fake SMB2 negprot request */
	req = talloc_zero(smb_req->smb_conn, struct smb2srv_request);
	if (!req) goto nomem;
	req->smb_conn		= smb_req->smb_conn;
	req->request_time	= smb_req->request_time;
	talloc_steal(req, smb_req);

	req->in.size      = NBT_HDR_SIZE+SMB2_HDR_BODY+body_fixed_size;
	req->in.allocated = req->in.size;
	req->in.buffer    = talloc_size(req, req->in.allocated);
	if (!req->in.buffer) goto nomem;
	req->in.hdr       = req->in.buffer + NBT_HDR_SIZE;
	req->in.body      = req->in.hdr + SMB2_HDR_BODY;
	req->in.body_size = body_fixed_size;
	req->in.dynamic   = NULL;

	SIVAL(req->in.hdr, 0,				SMB2_MAGIC);
	SSVAL(req->in.hdr, SMB2_HDR_LENGTH,		SMB2_HDR_BODY);
	SSVAL(req->in.hdr, SMB2_HDR_PAD1,		0);
	SIVAL(req->in.hdr, SMB2_HDR_STATUS,		0);
	SSVAL(req->in.hdr, SMB2_HDR_OPCODE,		SMB2_OP_NEGPROT);
	SSVAL(req->in.hdr, SMB2_HDR_UNKNOWN1,		0);
	SIVAL(req->in.hdr, SMB2_HDR_FLAGS,		0);
	SIVAL(req->in.hdr, SMB2_HDR_CHAIN_OFFSET,	0);
	SBVAL(req->in.hdr, SMB2_HDR_SEQNUM,		0);
	SIVAL(req->in.hdr, SMB2_HDR_PID,		0);
	SIVAL(req->in.hdr, SMB2_HDR_TID,		0);
	SBVAL(req->in.hdr, SMB2_HDR_UID,		0);
	memset(req->in.hdr+SMB2_HDR_SIG, 0, 16);

	/* this seems to be a bug, they use 0x24 but the length is 0x26 */
	SSVAL(req->in.body, 0x00, 0x24);

	SSVAL(req->in.body, 0x02, 1);
	memset(req->in.body+0x04, 0, 32);
	SSVAL(req->in.body, 0x24, 0);

	smb2srv_negprot_recv(req);
	return;
nomem:
	smbsrv_terminate_connection(smb_req->smb_conn, nt_errstr(NT_STATUS_NO_MEMORY));
	talloc_free(req);
	return;
}
