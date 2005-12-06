/* 
   Unix SMB2 implementation.
   
   Copyright (C) Andrew Tridgell	2005
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
#include "system/time.h"
#include "smbd/service_stream.h"
#include "libcli/smb2/smb2.h"
#include "smb_server/smb_server.h"
#include "smb_server/smb2/smb2_server.h"
#include "lib/stream/packet.h"


static struct smb2srv_request *smb2srv_init_request(struct smbsrv_connection *smb_conn)
{
	struct smb2srv_request *req;

	req = talloc_zero(smb_conn, struct smb2srv_request);
	if (!req) return NULL;

	req->smb_conn = smb_conn;

	return req;
}

NTSTATUS smb2srv_setup_reply(struct smb2srv_request *req, uint_t body_fixed_size, uint_t body_dynamic_size)
{
	req->out.size		= SMB2_HDR_BODY+NBT_HDR_SIZE+body_fixed_size;

	req->out.allocated	= req->out.size + body_dynamic_size;
	req->out.buffer		= talloc_size(req, req->out.allocated);
	NT_STATUS_HAVE_NO_MEMORY(req->out.buffer);

	req->out.hdr		= req->out.buffer	+ NBT_HDR_SIZE;
	req->out.body		= req->out.hdr		+ SMB2_HDR_BODY;
	req->out.body_size	= body_fixed_size;
	req->out.dynamic	= (body_dynamic_size ? req->out.body + body_fixed_size : NULL);

	SIVAL(req->out.hdr, 0,                SMB2_MAGIC);
	SSVAL(req->out.hdr, SMB2_HDR_LENGTH,  SMB2_HDR_BODY);
	SSVAL(req->out.hdr, SMB2_HDR_PAD1,    0);
	SIVAL(req->out.hdr, SMB2_HDR_STATUS,  NT_STATUS_V(req->status));
	SSVAL(req->out.hdr, SMB2_HDR_OPCODE,  SVAL(req->in.hdr, SMB2_HDR_OPCODE));
	SSVAL(req->out.hdr, SMB2_HDR_PAD2,    0);
	SIVAL(req->out.hdr, SMB2_HDR_FLAGS,   0x00000001);
	SIVAL(req->out.hdr, SMB2_HDR_UNKNOWN, 0);
	SBVAL(req->out.hdr, SMB2_HDR_SEQNUM,  req->seqnum);
	SIVAL(req->out.hdr, SMB2_HDR_PID,     IVAL(req->in.hdr, SMB2_HDR_PID));
	SIVAL(req->out.hdr, SMB2_HDR_TID,     IVAL(req->in.hdr, SMB2_HDR_TID));
	SBVAL(req->out.hdr, SMB2_HDR_UID,     BVAL(req->in.hdr, SMB2_HDR_UID));
	memset(req->out.hdr+SMB2_HDR_SIG, 0, 16);

	/* set the length of the fixed body part and +1 if there's a dynamic part also */
	SSVAL(req->out.body, 0, body_fixed_size + (body_dynamic_size?1:0));

	/* 
	 * if we have a dynamic part, make sure the first byte
	 * which is always be part of the packet is initialized
	 */
	if (body_dynamic_size) {
		SCVAL(req->out.dynamic, 0, 0);
	}

	return NT_STATUS_OK;
}

void smb2srv_send_reply(struct smb2srv_request *req)
{
	DATA_BLOB blob;
	NTSTATUS status;

	if (req->out.size > NBT_HDR_SIZE) {
		_smb_setlen(req->out.buffer, req->out.size - NBT_HDR_SIZE);
	}

	blob = data_blob_const(req->out.buffer, req->out.size);
	status = packet_send(req->smb_conn->packet, blob);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
	}
	talloc_free(req);
}

void smb2srv_send_error(struct smb2srv_request *req, NTSTATUS error)
{
	NTSTATUS status;

	status = smb2srv_setup_reply(req, 8, 1);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}

	SIVAL(req->out.hdr, SMB2_HDR_STATUS, NT_STATUS_V(error));

	SSVAL(req->out.body, 0x02, 0);
	SIVAL(req->out.body, 0x04, 0);

	smb2srv_send_reply(req);
}

static NTSTATUS smb2srv_reply(struct smb2srv_request *req)
{
	uint16_t opcode;
	uint32_t tid;
	uint64_t uid;

	opcode		= SVAL(req->in.hdr, SMB2_HDR_OPCODE);
	req->seqnum	= BVAL(req->in.hdr, SMB2_HDR_SEQNUM);
	tid		= IVAL(req->in.hdr, SMB2_HDR_TID);
	uid		= BVAL(req->in.hdr, SMB2_HDR_UID);

	req->session	= smbsrv_session_find(req->smb_conn, uid);
	req->tcon	= smbsrv_tcon_find(req->smb_conn, tid);

	errno = 0;

	/* TODO: check the seqnum */

	switch (opcode) {
	case SMB2_OP_NEGPROT:
		smb2srv_negprot_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_SESSSETUP:
		smb2srv_sesssetup_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_LOGOFF:
		if (!req->session) goto nosession;
		smb2srv_logoff_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_TCON:
		if (!req->session) goto nosession;
		smb2srv_tcon_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_TDIS:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_tdis_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_CREATE:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_create_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_CLOSE:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_close_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_FLUSH:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_flush_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_READ:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_read_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_WRITE:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_write_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_LOCK:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_lock_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_IOCTL:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_ioctl_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_CANCEL:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_cancel_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_KEEPALIVE:
		smb2srv_keepalive_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_FIND:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_find_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_NOTIFY:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_notify_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_GETINFO:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_getinfo_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_SETINFO:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_setinfo_recv(req);
		return NT_STATUS_OK;
	case SMB2_OP_BREAK:
		if (!req->session) goto nosession;
		if (!req->tcon)	goto notcon;
		smb2srv_break_recv(req);
		return NT_STATUS_OK;
	}

	DEBUG(1,("Invalid SMB2 opcode: 0x%04X\n", opcode));
	smbsrv_terminate_connection(req->smb_conn, "Invalid SMB2 opcode");
	return NT_STATUS_OK;

nosession:
	smb2srv_send_error(req, NT_STATUS_USER_SESSION_DELETED);
	return NT_STATUS_OK;
notcon:
	smb2srv_send_error(req, NT_STATUS_NETWORK_NAME_DELETED);
	return NT_STATUS_OK;
}

NTSTATUS smbsrv_recv_smb2_request(void *private, DATA_BLOB blob)
{
	struct smbsrv_connection *smb_conn = talloc_get_type(private, struct smbsrv_connection);
	struct smb2srv_request *req;
	uint32_t protocol_version;
	uint16_t buffer_code;
	uint32_t dynamic_size;

	/* see if its a special NBT packet */
	if (CVAL(blob.data,0) != 0) {
		DEBUG(2,("Special NBT packet on SMB2 connection"));
		smbsrv_terminate_connection(smb_conn, "Special NBT packet on SMB2 connection");
		return NT_STATUS_OK;
	}

	if (blob.length < (NBT_HDR_SIZE + SMB2_MIN_SIZE)) {
		DEBUG(2,("Invalid SMB2 packet length count %ld\n", (long)blob.length));
		smbsrv_terminate_connection(smb_conn, "Invalid SMB2 packet");
		return NT_STATUS_OK;
	}

	protocol_version = IVAL(blob.data, NBT_HDR_SIZE);

	if (protocol_version != SMB2_MAGIC) {
		DEBUG(2,("Invalid SMB packet: protocl prefix: 0x%08X\n", protocol_version));
		smbsrv_terminate_connection(smb_conn, "NON-SMB2 packet");
		return NT_STATUS_OK;
	}

	req = smb2srv_init_request(smb_conn);
	NT_STATUS_HAVE_NO_MEMORY(req);

	req->in.buffer		= talloc_steal(req, blob.data);
	req->in.size		= blob.length;
	req->request_time	= timeval_current();
	req->in.allocated	= req->in.size;

	req->in.hdr		= req->in.buffer+ NBT_HDR_SIZE;
	req->in.body		= req->in.hdr	+ SMB2_HDR_BODY;
	req->in.body_size	= req->in.size	- (SMB2_HDR_BODY+NBT_HDR_SIZE);
	req->in.dynamic 	= NULL;

	buffer_code		= SVAL(req->in.body, 0);
	dynamic_size		= req->in.body_size - (buffer_code & ~1);

	if (dynamic_size != 0 && (buffer_code & 1)) {
		req->in.dynamic = req->in.body + (buffer_code & ~1);
		if (smb2_oob(&req->in, req->in.dynamic, dynamic_size)) {
			DEBUG(1,("SMB2 request invalid dynamic size 0x%x\n", 
				 dynamic_size));
			smb2srv_send_error(req, NT_STATUS_INVALID_PARAMETER);
			return NT_STATUS_OK;
		}
	}

	/* 
	 * TODO: - make sure the length field is 64
	 *       - make sure it's a request
	 */

	return smb2srv_reply(req);
}

/*
 * init the SMB2 protocol related stuff
 */
NTSTATUS smbsrv_init_smb2_connection(struct smbsrv_connection *smb_conn)
{
	NTSTATUS status;

	/* now initialise a few default values associated with this smb socket */
	smb_conn->negotiate.max_send = 0xFFFF;

	/* this is the size that w2k uses, and it appears to be important for
	   good performance */
	smb_conn->negotiate.max_recv = lp_max_xmit();

	smb_conn->negotiate.zone_offset = get_time_zone(time(NULL));

	smb_conn->config.security = SEC_USER;
	smb_conn->config.nt_status_support = True;

	status = smbsrv_init_sessions(smb_conn, UINT64_MAX);
	NT_STATUS_NOT_OK_RETURN(status);

	status = smbsrv_init_tcons(smb_conn, UINT32_MAX);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
	
}
