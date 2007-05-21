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
#include "libcli/smb2/smb2.h"
#include "libcli/smb2/smb2_calls.h"
#include "smb_server/smb_server.h"
#include "smb_server/service_smb_proto.h"
#include "smb_server/smb2/smb2_server.h"
#include "smbd/service_stream.h"
#include "lib/stream/packet.h"
#include "ntvfs/ntvfs.h"

static int smb2srv_request_destructor(struct smb2srv_request *req)
{
	DLIST_REMOVE(req->smb_conn->requests2.list, req);
	if (req->pending_id) {
		idr_remove(req->smb_conn->requests2.idtree_req, req->pending_id);
	}
	return 0;
}

static int smb2srv_request_deny_destructor(struct smb2srv_request *req)
{
	return -1;
}

struct smb2srv_request *smb2srv_init_request(struct smbsrv_connection *smb_conn)
{
	struct smb2srv_request *req;

	req = talloc_zero(smb_conn, struct smb2srv_request);
	if (!req) return NULL;

	req->smb_conn = smb_conn;

	talloc_set_destructor(req, smb2srv_request_destructor);

	return req;
}

NTSTATUS smb2srv_setup_reply(struct smb2srv_request *req, uint16_t body_fixed_size,
			     BOOL body_dynamic_present, uint32_t body_dynamic_size)
{
	uint32_t flags = 0x00000001;
	uint32_t pid = IVAL(req->in.hdr, SMB2_HDR_PID);
	uint32_t tid = IVAL(req->in.hdr, SMB2_HDR_TID);

	if (req->pending_id) {
		flags |= 0x00000002;
		pid = req->pending_id;
		tid = 0;
	}

	if (body_dynamic_present) {
		if (body_dynamic_size == 0) {
			body_dynamic_size = 1;
		}
	} else {
		body_dynamic_size = 0;
	}

	req->out.size		= SMB2_HDR_BODY+NBT_HDR_SIZE+body_fixed_size;

	req->out.allocated	= req->out.size + body_dynamic_size;
	req->out.buffer		= talloc_size(req, req->out.allocated);
	NT_STATUS_HAVE_NO_MEMORY(req->out.buffer);

	req->out.hdr		= req->out.buffer	+ NBT_HDR_SIZE;
	req->out.body		= req->out.hdr		+ SMB2_HDR_BODY;
	req->out.body_fixed	= body_fixed_size;
	req->out.body_size	= body_fixed_size;
	req->out.dynamic	= (body_dynamic_size ? req->out.body + body_fixed_size : NULL);

	SIVAL(req->out.hdr, 0,				SMB2_MAGIC);
	SSVAL(req->out.hdr, SMB2_HDR_LENGTH,		SMB2_HDR_BODY);
	SSVAL(req->out.hdr, SMB2_HDR_PAD1,		0);
	SIVAL(req->out.hdr, SMB2_HDR_STATUS,		NT_STATUS_V(req->status));
	SSVAL(req->out.hdr, SMB2_HDR_OPCODE,		SVAL(req->in.hdr, SMB2_HDR_OPCODE));
	SSVAL(req->out.hdr, SMB2_HDR_UNKNOWN1,		0x0001);
	SIVAL(req->out.hdr, SMB2_HDR_FLAGS,		flags);
	SIVAL(req->out.hdr, SMB2_HDR_CHAIN_OFFSET,	0);
	SBVAL(req->out.hdr, SMB2_HDR_SEQNUM,		req->seqnum);
	SIVAL(req->out.hdr, SMB2_HDR_PID,		pid);
	SIVAL(req->out.hdr, SMB2_HDR_TID,		tid);
	SBVAL(req->out.hdr, SMB2_HDR_UID,		BVAL(req->in.hdr, SMB2_HDR_UID));
	memset(req->out.hdr+SMB2_HDR_SIG, 0, 16);

	/* set the length of the fixed body part and +1 if there's a dynamic part also */
	SSVAL(req->out.body, 0, body_fixed_size + (body_dynamic_size?1:0));

	/* 
	 * if we have a dynamic part, make sure the first byte
	 * which is always be part of the packet is initialized
	 */
	if (body_dynamic_size) {
		req->out.size += 1;
		SCVAL(req->out.dynamic, 0, 0);
	}

	return NT_STATUS_OK;
}

static NTSTATUS smb2srv_reply(struct smb2srv_request *req);

static void smb2srv_chain_reply(struct smb2srv_request *p_req)
{
	NTSTATUS status;
	struct smb2srv_request *req;
	uint32_t chain_offset;
	uint32_t protocol_version;
	uint16_t buffer_code;
	uint32_t dynamic_size;

	chain_offset = p_req->chain_offset;
	p_req->chain_offset = 0;

	if (p_req->in.size < (NBT_HDR_SIZE + chain_offset + SMB2_MIN_SIZE)) {
		DEBUG(2,("Invalid SMB2 chained packet at offset 0x%X\n",
			chain_offset));
		smbsrv_terminate_connection(p_req->smb_conn, "Invalid SMB2 chained packet");
		return;
	}

	protocol_version = IVAL(p_req->in.buffer, NBT_HDR_SIZE + chain_offset);
	if (protocol_version != SMB2_MAGIC) {
		DEBUG(2,("Invalid SMB chained packet: protocol prefix: 0x%08X\n",
			 protocol_version));
		smbsrv_terminate_connection(p_req->smb_conn, "NON-SMB2 chained packet");
		return;
	}

	req = smb2srv_init_request(p_req->smb_conn);
	if (!req) {
		smbsrv_terminate_connection(p_req->smb_conn, "SMB2 chained packet - no memory");
		return;
	}

	req->in.buffer		= talloc_steal(req, p_req->in.buffer);
	req->in.size		= p_req->in.size;
	req->request_time	= p_req->request_time;
	req->in.allocated	= req->in.size;

	req->in.hdr		= req->in.buffer+ NBT_HDR_SIZE + chain_offset;
	req->in.body		= req->in.hdr	+ SMB2_HDR_BODY;
	req->in.body_size	= req->in.size	- (NBT_HDR_SIZE+ chain_offset + SMB2_HDR_BODY);
	req->in.dynamic 	= NULL;

	buffer_code		= SVAL(req->in.body, 0);
	req->in.body_fixed	= (buffer_code & ~1);
	dynamic_size		= req->in.body_size - req->in.body_fixed;

	if (dynamic_size != 0 && (buffer_code & 1)) {
		req->in.dynamic = req->in.body + req->in.body_fixed;
		if (smb2_oob(&req->in, req->in.dynamic, dynamic_size)) {
			DEBUG(1,("SMB2 chained request invalid dynamic size 0x%x\n", 
				 dynamic_size));
			smb2srv_send_error(req, NT_STATUS_INVALID_PARAMETER);
			return;
		}
	}

	if (p_req->chained_file_handle) {
		memcpy(req->_chained_file_handle,
		       p_req->_chained_file_handle,
		       sizeof(req->_chained_file_handle));
		req->chained_file_handle = req->_chained_file_handle;
	}

	/* 
	 * TODO: - make sure the length field is 64
	 *       - make sure it's a request
	 */

	status = smb2srv_reply(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
		talloc_free(req);
		return;
	}
}

void smb2srv_send_reply(struct smb2srv_request *req)
{
	DATA_BLOB blob;
	NTSTATUS status;

	if (req->smb_conn->connection->event.fde == NULL) {
		/* the socket has been destroyed - no point trying to send a reply! */
		talloc_free(req);
		return;
	}

	if (req->out.size > NBT_HDR_SIZE) {
		_smb2_setlen(req->out.buffer, req->out.size - NBT_HDR_SIZE);
	}

	blob = data_blob_const(req->out.buffer, req->out.size);
	status = packet_send(req->smb_conn->packet, blob);
	if (!NT_STATUS_IS_OK(status)) {
		smbsrv_terminate_connection(req->smb_conn, nt_errstr(status));
	}
	if (req->chain_offset) {
		smb2srv_chain_reply(req);
		return;
	}
	talloc_free(req);
}

void smb2srv_send_error(struct smb2srv_request *req, NTSTATUS error)
{
	NTSTATUS status;

	if (req->smb_conn->connection->event.fde == NULL) {
		/* the socket has been destroyed - no point trying to send an error! */
		talloc_free(req);
		return;
	}

	status = smb2srv_setup_reply(req, 8, True, 0);
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

	opcode			= SVAL(req->in.hdr, SMB2_HDR_OPCODE);
	req->chain_offset	= IVAL(req->in.hdr, SMB2_HDR_CHAIN_OFFSET);
	req->seqnum		= BVAL(req->in.hdr, SMB2_HDR_SEQNUM);
	tid			= IVAL(req->in.hdr, SMB2_HDR_TID);
	uid			= BVAL(req->in.hdr, SMB2_HDR_UID);

	req->session	= smbsrv_session_find(req->smb_conn, uid, req->request_time);
	req->tcon	= smbsrv_smb2_tcon_find(req->session, tid, req->request_time);

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
	struct timeval cur_time = timeval_current();
	uint32_t protocol_version;
	uint16_t buffer_code;
	uint32_t dynamic_size;

	smb_conn->statistics.last_request_time = cur_time;

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
		DEBUG(2,("Invalid SMB packet: protocol prefix: 0x%08X\n",
			 protocol_version));
		smbsrv_terminate_connection(smb_conn, "NON-SMB2 packet");
		return NT_STATUS_OK;
	}

	req = smb2srv_init_request(smb_conn);
	NT_STATUS_HAVE_NO_MEMORY(req);

	req->in.buffer		= talloc_steal(req, blob.data);
	req->in.size		= blob.length;
	req->request_time	= cur_time;
	req->in.allocated	= req->in.size;

	req->in.hdr		= req->in.buffer+ NBT_HDR_SIZE;
	req->in.body		= req->in.hdr	+ SMB2_HDR_BODY;
	req->in.body_size	= req->in.size	- (SMB2_HDR_BODY+NBT_HDR_SIZE);
	req->in.dynamic 	= NULL;

	buffer_code		= SVAL(req->in.body, 0);
	req->in.body_fixed	= (buffer_code & ~1);
	dynamic_size		= req->in.body_size - req->in.body_fixed;

	if (dynamic_size != 0 && (buffer_code & 1)) {
		req->in.dynamic = req->in.body + req->in.body_fixed;
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

static NTSTATUS smb2srv_init_pending(struct smbsrv_connection *smb_conn)
{
	smb_conn->requests2.idtree_req = idr_init(smb_conn);
	NT_STATUS_HAVE_NO_MEMORY(smb_conn->requests2.idtree_req);
	smb_conn->requests2.idtree_limit	= 0x00FFFFFF & (UINT32_MAX - 1);
	smb_conn->requests2.list		= NULL;

	return NT_STATUS_OK;
}

NTSTATUS smb2srv_queue_pending(struct smb2srv_request *req)
{
	int id;

	if (req->pending_id) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	id = idr_get_new_above(req->smb_conn->requests2.idtree_req, req, 
			       1, req->smb_conn->requests2.idtree_limit);
	if (id == -1) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	DLIST_ADD_END(req->smb_conn->requests2.list, req, struct smb2srv_request *);
	req->pending_id = id;

	talloc_set_destructor(req, smb2srv_request_deny_destructor);
	smb2srv_send_error(req, STATUS_PENDING);
	talloc_set_destructor(req, smb2srv_request_destructor);

	return NT_STATUS_OK;
}

void smb2srv_cancel_recv(struct smb2srv_request *req)
{
	uint32_t pending_id;
	uint32_t flags;
	void *p;
	struct smb2srv_request *r;

	if (!req->session) goto done;

	flags		= IVAL(req->in.hdr, SMB2_HDR_FLAGS);
	pending_id	= IVAL(req->in.hdr, SMB2_HDR_PID);

	if (!(flags & 0x00000002)) {
		/* TODO: what to do here? */
		goto done;
	}
 
 	p = idr_find(req->smb_conn->requests2.idtree_req, pending_id);
	if (!p) goto done;

	r = talloc_get_type(p, struct smb2srv_request);
	if (!r) goto done;

	if (!r->ntvfs) goto done;

	ntvfs_cancel(r->ntvfs);

done:
	/* we never generate a reply for a SMB2 Cancel */
	talloc_free(req);
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

	status = smb2srv_init_pending(smb_conn);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
	
}
