/*
   Unix SMB/CIFS implementation.
   Core SMB2 server

   Copyright (C) Stefan Metzmacher 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "smbd/globals.h"
#include "../source4/libcli/smb2/smb2_constants.h"
#include "../lib/tsocket/tsocket.h"

bool smbd_is_smb2_header(const uint8_t *inbuf, size_t size)
{
	if (size < (4 + SMB2_HDR_BODY)) {
		return false;
	}

	if (IVAL(inbuf, 4) != SMB2_MAGIC) {
		return false;
	}

	return true;
}

static NTSTATUS smbd_initialize_smb2(struct smbd_server_connection *conn)
{
	NTSTATUS status;
	int ret;

	TALLOC_FREE(conn->fde);

	conn->smb2.event_ctx = smbd_event_context();

	conn->smb2.recv_queue = tevent_queue_create(conn, "smb2 recv queue");
	if (conn->smb2.recv_queue == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	conn->smb2.send_queue = tevent_queue_create(conn, "smb2 send queue");
	if (conn->smb2.send_queue == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	conn->smb2.sessions.idtree = idr_init(conn);
	if (conn->smb2.sessions.idtree == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	conn->smb2.sessions.limit = 0x0000FFFF;
	conn->smb2.sessions.list = NULL;

	ret = tstream_bsd_existing_socket(conn, smbd_server_fd(),
					  &conn->smb2.stream);
	if (ret == -1) {
		status = map_nt_error_from_unix(errno);
		return status;
	}

	/* Ensure child is set to non-blocking mode */
	set_blocking(smbd_server_fd(),false);
	return NT_STATUS_OK;
}

#define smb2_len(buf) (PVAL(buf,3)|(PVAL(buf,2)<<8)|(PVAL(buf,1)<<16))
#define _smb2_setlen(_buf,len) do { \
	uint8_t *buf = (uint8_t *)_buf; \
	buf[0] = 0; \
	buf[1] = ((len)&0xFF0000)>>16; \
	buf[2] = ((len)&0xFF00)>>8; \
	buf[3] = (len)&0xFF; \
} while (0)

static void smb2_setup_nbt_length(struct iovec *vector, int count)
{
	size_t len = 0;
	int i;

	for (i=1; i < count; i++) {
		len += vector[i].iov_len;
	}

	_smb2_setlen(vector[0].iov_base, len);
}

static NTSTATUS smbd_smb2_request_create(struct smbd_server_connection *conn,
					 const uint8_t *inbuf, size_t size,
					 struct smbd_smb2_request **_req)
{
	TALLOC_CTX *mem_pool;
	struct smbd_smb2_request *req;
	uint32_t protocol_version;
	const uint8_t *inhdr = NULL;
	off_t ofs = 0;
	uint16_t cmd;
	uint32_t next_command_ofs;

	if (size < (4 + SMB2_HDR_BODY + 2)) {
		DEBUG(0,("Invalid SMB2 packet length count %ld\n", (long)size));
		return NT_STATUS_INVALID_PARAMETER;
	}

	inhdr = inbuf + 4;

	protocol_version = IVAL(inhdr, SMB2_HDR_PROTOCOL_ID);
	if (protocol_version != SMB2_MAGIC) {
		DEBUG(0,("Invalid SMB packet: protocol prefix: 0x%08X\n",
			 protocol_version));
		return NT_STATUS_INVALID_PARAMETER;
	}

	cmd = SVAL(inhdr, SMB2_HDR_OPCODE);
	if (cmd != SMB2_OP_NEGPROT) {
		DEBUG(0,("Invalid SMB packet: first request: 0x%04X\n",
			 cmd));
		return NT_STATUS_INVALID_PARAMETER;
	}

	next_command_ofs = IVAL(inhdr, SMB2_HDR_NEXT_COMMAND);
	if (next_command_ofs != 0) {
		DEBUG(0,("Invalid SMB packet: next_command: 0x%08X\n",
			 next_command_ofs));
		return NT_STATUS_INVALID_PARAMETER;
	}

	mem_pool = talloc_pool(conn, 8192);
	if (mem_pool == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	req = talloc_zero(mem_pool, struct smbd_smb2_request);
	if (req == NULL) {
		talloc_free(mem_pool);
		return NT_STATUS_NO_MEMORY;
	}
	req->mem_pool	= mem_pool;
	req->conn	= conn;

	talloc_steal(req, inbuf);

	req->in.vector = talloc_array(req, struct iovec, 4);
	if (req->in.vector == NULL) {
		talloc_free(mem_pool);
		return NT_STATUS_NO_MEMORY;
	}
	req->in.vector_count = 4;

	memcpy(req->in.nbt_hdr, inbuf, 4);

	ofs = 0;
	req->in.vector[0].iov_base	= (void *)req->in.nbt_hdr;
	req->in.vector[0].iov_len	= 4;
	ofs += req->in.vector[0].iov_len;

	req->in.vector[1].iov_base	= (void *)(inbuf + ofs);
	req->in.vector[1].iov_len	= SMB2_HDR_BODY;
	ofs += req->in.vector[1].iov_len;

	req->in.vector[2].iov_base	= (void *)(inbuf + ofs);
	req->in.vector[2].iov_len	= SVAL(inbuf, ofs) & 0xFFFE;
	ofs += req->in.vector[2].iov_len;

	if (ofs > size) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	req->in.vector[3].iov_base	= (void *)(inbuf + ofs);
	req->in.vector[3].iov_len	= size - ofs;
	ofs += req->in.vector[3].iov_len;

	req->current_idx = 1;

	*_req = req;
	return NT_STATUS_OK;
}

static NTSTATUS smbd_smb2_request_setup_out(struct smbd_smb2_request *req)
{
	struct iovec *vector;
	int count;
	int idx;

	count = req->in.vector_count;
	vector = talloc_array(req, struct iovec, count);
	if (vector == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	vector[0].iov_base	= req->out.nbt_hdr;
	vector[0].iov_len	= 4;
	SIVAL(req->out.nbt_hdr, 0, 0);

	for (idx=1; idx < count; idx += 3) {
		const uint8_t *inhdr = NULL;
		uint8_t *outhdr = NULL;
		uint8_t *outbody = NULL;
		uint8_t *outdyn = NULL;
		size_t outdyn_size = 1;
		uint32_t next_command_ofs = 0;
		struct iovec *current = &vector[idx];

		if ((idx + 3) < count) {
			/* we have a next command */
			next_command_ofs = SMB2_HDR_BODY + 8 + 8;
			outdyn_size = 8;
		}

		inhdr = (const uint8_t *)req->in.vector[idx].iov_base;

		outhdr = talloc_array(vector, uint8_t,
				      SMB2_HDR_BODY + 8 + outdyn_size);
		if (outhdr == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		outbody = outhdr + SMB2_HDR_BODY;
		outdyn = outbody + 8;

		current[0].iov_base	= (void *)outhdr;
		current[0].iov_len	= SMB2_HDR_BODY;

		current[1].iov_base	= (void *)outbody;
		current[1].iov_len	= 8;

		current[2].iov_base	= (void *)outdyn;
		current[2].iov_len	= outdyn_size;

		/* setup the SMB2 header */
		SIVAL(outhdr, SMB2_HDR_PROTOCOL_ID,	SMB2_MAGIC);
		SSVAL(outhdr, SMB2_HDR_LENGTH,		SMB2_HDR_BODY);
		SSVAL(outhdr, SMB2_HDR_EPOCH,		0);
		SIVAL(outhdr, SMB2_HDR_STATUS,
		      NT_STATUS_V(NT_STATUS_INTERNAL_ERROR));
		SSVAL(outhdr, SMB2_HDR_OPCODE,
		      SVAL(inhdr, SMB2_HDR_OPCODE));
		SSVAL(outhdr, SMB2_HDR_CREDIT,		0);
		SIVAL(outhdr, SMB2_HDR_FLAGS,		SMB2_HDR_FLAG_REDIRECT);
		SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND,	next_command_ofs);
		SBVAL(outhdr, SMB2_HDR_MESSAGE_ID,
		      BVAL(inhdr, SMB2_HDR_MESSAGE_ID));
		SIVAL(outhdr, SMB2_HDR_PID,
		      IVAL(inhdr, SMB2_HDR_PID));
		SIVAL(outhdr, SMB2_HDR_TID,
		      IVAL(inhdr, SMB2_HDR_TID));
		SBVAL(outhdr, SMB2_HDR_SESSION_ID,
		      BVAL(inhdr, SMB2_HDR_SESSION_ID));
		memset(outhdr + SMB2_HDR_SIGNATURE, 0, 16);

		/* setup error body header */
		SSVAL(outbody, 0x00, 9);
		SSVAL(outbody, 0x02, 0);
		SIVAL(outbody, 0x04, 0);

		/* setup the dynamic part */
		SCVAL(outdyn, 0x00, 0);
	}

	req->out.vector = vector;
	req->out.vector_count = count;

	/* setup the length of the NBT packet */
	smb2_setup_nbt_length(req->out.vector, req->out.vector_count);

	return NT_STATUS_OK;
}

static void smbd_server_connection_terminate(struct smbd_server_connection *conn,
					     const char *reason)
{
	DEBUG(10,("smbd_server_connection_terminate: reason[%s]\n", reason));
	exit_server_cleanly(reason);
}

static NTSTATUS smbd_smb2_request_dispatch(struct smbd_smb2_request *req)
{
	const uint8_t *inhdr;
	int i = req->current_idx;
	uint16_t opcode;
	NTSTATUS status;

	inhdr = (const uint8_t *)req->in.vector[i].iov_base;

	/* TODO: verify more things */

	opcode = IVAL(inhdr, SMB2_HDR_OPCODE);
	DEBUG(10,("smbd_smb2_request_dispatch: opcode[%u]\n", opcode));
	switch (opcode) {
	case SMB2_OP_NEGPROT:
		return smbd_smb2_request_process_negprot(req);

	case SMB2_OP_SESSSETUP:
		return smbd_smb2_request_process_sesssetup(req);

	case SMB2_OP_LOGOFF:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_TCON:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_TDIS:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_CREATE:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_CLOSE:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_FLUSH:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_READ:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_WRITE:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_LOCK:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_IOCTL:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_CANCEL:
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_KEEPALIVE:
		return smbd_smb2_request_process_keepalive(req);

	case SMB2_OP_FIND:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_NOTIFY:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_GETINFO:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_SETINFO:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);

	case SMB2_OP_BREAK:
		status = smbd_smb2_request_check_session(req);
		if (!NT_STATUS_IS_OK(status)) {
			return smbd_smb2_request_error(req, status);
		}
		return smbd_smb2_request_error(req, NT_STATUS_NOT_IMPLEMENTED);
	}

	return smbd_smb2_request_error(req, NT_STATUS_INVALID_PARAMETER);
}

static void smbd_smb2_request_dispatch_compound(struct tevent_req *subreq);
static void smbd_smb2_request_writev_done(struct tevent_req *subreq);

static NTSTATUS smbd_smb2_request_reply(struct smbd_smb2_request *req)
{
	struct tevent_req *subreq;

	/* TODO: sign the response here */

	smb2_setup_nbt_length(req->out.vector, req->out.vector_count);

	req->current_idx += 3;

	if (req->current_idx > req->in.vector_count) {
		struct timeval zero = timeval_zero();
		subreq = tevent_wakeup_send(req,
					    req->conn->smb2.event_ctx,
					    zero);
		if (subreq == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		tevent_req_set_callback(subreq,
					smbd_smb2_request_dispatch_compound,
					req);

		return NT_STATUS_OK;
	}

	subreq = tstream_writev_queue_send(req,
					   req->conn->smb2.event_ctx,
					   req->conn->smb2.stream,
					   req->conn->smb2.send_queue,
					   req->out.vector,
					   req->out.vector_count);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_writev_done, req);

	return NT_STATUS_OK;
}

static void smbd_smb2_request_dispatch_compound(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	struct smbd_server_connection *conn = req->conn;
	NTSTATUS status;

	tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);

	DEBUG(10,("smbd_smb2_request_dispatch_compound: idx[%d] of %d vectors\n",
		  req->current_idx, req->in.vector_count));

	status = smbd_smb2_request_dispatch(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(conn, nt_errstr(status));
		return;
	}
}

static void smbd_smb2_request_writev_done(struct tevent_req *subreq)
{
	struct smbd_smb2_request *req = tevent_req_callback_data(subreq,
					struct smbd_smb2_request);
	struct smbd_server_connection *conn = req->conn;
	int ret;
	int sys_errno;
	TALLOC_CTX *mem_pool;

	ret = tstream_writev_queue_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		NTSTATUS status = map_nt_error_from_unix(sys_errno);
		smbd_server_connection_terminate(conn, nt_errstr(status));
		return;
	}

	mem_pool = req->mem_pool;
	req = NULL;
	talloc_free(mem_pool);
}

NTSTATUS smbd_smb2_request_error_ex(struct smbd_smb2_request *req,
				    NTSTATUS status,
				    DATA_BLOB *info)
{
	uint8_t *outhdr;
	uint8_t *outbody;
	int i = req->current_idx;

	DEBUG(10,("smbd_smb2_request_error_ex: idx[%d] status[%s]%s\n",
		  i, nt_errstr(status), info ? " +info" : ""));

	outhdr = (uint8_t *)req->out.vector[i].iov_base;

	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));

	outbody = outhdr + SMB2_HDR_BODY;

	req->out.vector[i+1].iov_base = (void *)outbody;
	req->out.vector[i+1].iov_len = 8;

	if (info) {
		SIVAL(outbody, 0x04, info->length);
		req->out.vector[i+2].iov_base	= (void *)info->data;
		req->out.vector[i+2].iov_len	= info->length;
	} else {
		req->out.vector[i+2].iov_base = (void *)(outbody + 8);
		req->out.vector[i+2].iov_len = 1;
	}

	/* the error packet is the last response in the chain */
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, 0);
	req->out.vector_count = req->current_idx + 3;

	return smbd_smb2_request_reply(req);
}

NTSTATUS smbd_smb2_request_error(struct smbd_smb2_request *req,
				 NTSTATUS status)
{
	return smbd_smb2_request_error_ex(req, status, NULL);
}

NTSTATUS smbd_smb2_request_done_ex(struct smbd_smb2_request *req,
				   NTSTATUS status,
				   DATA_BLOB body, DATA_BLOB *dyn)
{
	uint8_t *outhdr;
	uint8_t *outdyn;
	int i = req->current_idx;
	uint32_t next_command_ofs;

	DEBUG(10,("smbd_smb2_request_done_ex: "
		  "idx[%d] status[%s] body[%u] dyn[%s:%u]\n",
		  i, nt_errstr(status), (unsigned int)body.length,
		  dyn ? "yes": "no",
		  (unsigned int)(dyn ? dyn->length : 0)));

	if (body.length < 2) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

	if ((body.length % 2) != 0) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

	outhdr = (uint8_t *)req->out.vector[i].iov_base;
	/* the fallback dynamic buffer */
	outdyn = outhdr + SMB2_HDR_BODY + 8;

	next_command_ofs = IVAL(outhdr, SMB2_HDR_NEXT_COMMAND);
	SIVAL(outhdr, SMB2_HDR_STATUS, NT_STATUS_V(status));

	req->out.vector[i+1].iov_base = (void *)body.data;
	req->out.vector[i+1].iov_len = body.length;

	if (dyn) {
		if (dyn->length > 0) {
			req->out.vector[i+2].iov_base	= (void *)dyn->data;
			req->out.vector[i+2].iov_len	= dyn->length;
		} else {
			req->out.vector[i+2].iov_base	= (void *)outdyn;
			req->out.vector[i+2].iov_len	= 1;
		}
	} else {
		req->out.vector[i+2].iov_base = NULL;
		req->out.vector[i+2].iov_len = 0;
	}

	/* see if we need to recalculate the offset to the next response */
	if (next_command_ofs > 0) {
		next_command_ofs  = SMB2_HDR_BODY;
		next_command_ofs += req->out.vector[i+1].iov_len;
		next_command_ofs += req->out.vector[i+2].iov_len;
	}

	/* TODO: we need to add padding ... */
	if ((next_command_ofs % 8) != 0) {
		return smbd_smb2_request_error(req, NT_STATUS_INTERNAL_ERROR);
	}

	/* the error packet is the last response in the chain */
	SIVAL(outhdr, SMB2_HDR_NEXT_COMMAND, next_command_ofs);

	return smbd_smb2_request_reply(req);
}

NTSTATUS smbd_smb2_request_done(struct smbd_smb2_request *req,
				DATA_BLOB body, DATA_BLOB *dyn)
{
	return smbd_smb2_request_done_ex(req, NT_STATUS_OK, body, dyn);
}

struct smbd_smb2_request_read_state {
	size_t missing;
	bool asked_for_header;
	struct smbd_smb2_request *smb2_req;
};

static int smbd_smb2_request_next_vector(struct tstream_context *stream,
					 void *private_data,
					 TALLOC_CTX *mem_ctx,
					 struct iovec **_vector,
					 size_t *_count);
static void smbd_smb2_request_read_done(struct tevent_req *subreq);

static struct tevent_req *smbd_smb2_request_read_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbd_server_connection *conn)
{
	struct tevent_req *req;
	struct smbd_smb2_request_read_state *state;
	struct tevent_req *subreq;
	TALLOC_CTX *mem_pool;

	req = tevent_req_create(mem_ctx, &state,
				struct smbd_smb2_request_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->missing = 0;
	state->asked_for_header = false;

	mem_pool = talloc_pool(state, 8192);
	if (tevent_req_nomem(mem_pool, req)) {
		return tevent_req_post(req, ev);
	}

	state->smb2_req = talloc_zero(mem_pool, struct smbd_smb2_request);
	if (tevent_req_nomem(state->smb2_req, req)) {
		return tevent_req_post(req, ev);
	}

	state->smb2_req->mem_pool	= mem_pool;
	state->smb2_req->conn		= conn;

	subreq = tstream_readv_pdu_queue_send(state, ev, conn->smb2.stream,
					      conn->smb2.recv_queue,
					      smbd_smb2_request_next_vector,
					      state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_read_done, req);

	return req;
}

static int smbd_smb2_request_next_vector(struct tstream_context *stream,
					 void *private_data,
					 TALLOC_CTX *mem_ctx,
					 struct iovec **_vector,
					 size_t *_count)
{
	struct smbd_smb2_request_read_state *state =
		talloc_get_type_abort(private_data,
		struct smbd_smb2_request_read_state);
	struct smbd_smb2_request *req = state->smb2_req;
	struct iovec *vector;
	int idx = req->in.vector_count;
	size_t len = 0;
	uint8_t *buf = NULL;

	if (req->in.vector_count == 0) {
		/*
		 * first we need to get the NBT header
		 */
		req->in.vector = talloc_array(req, struct iovec,
					      req->in.vector_count + 1);
		if (req->in.vector == NULL) {
			return -1;
		}
		req->in.vector_count += 1;

		req->in.vector[idx].iov_base	= (void *)req->in.nbt_hdr;
		req->in.vector[idx].iov_len	= 4;

		vector = talloc_array(mem_ctx, struct iovec, 1);
		if (vector == NULL) {
			return -1;
		}

		vector[0] = req->in.vector[idx];

		*_vector = vector;
		*_count = 1;
		return 0;
	}

	if (req->in.vector_count == 1) {
		/*
		 * Now we analyze the NBT header
		 */
		state->missing = smb2_len(req->in.vector[0].iov_base);

		if (state->missing == 0) {
			/* if there're no remaining bytes, we're done */
			*_vector = NULL;
			*_count = 0;
			return 0;
		}

		req->in.vector = talloc_realloc(req, req->in.vector,
						struct iovec,
						req->in.vector_count + 1);
		if (req->in.vector == NULL) {
			return -1;
		}
		req->in.vector_count += 1;

		if (CVAL(req->in.vector[0].iov_base, 0) != 0) {
			/*
			 * it's a special NBT message,
			 * so get all remaining bytes
			 */
			len = state->missing;
		} else if (state->missing < (SMB2_HDR_BODY + 2)) {
			/*
			 * it's an invalid message, just read what we can get
			 * and let the caller handle the error
			 */
			len = state->missing;
		} else {
			/*
			 * We assume it's a SMB2 request,
			 * and we first get the header and the
			 * first 2 bytes (the struct size) of the body
			 */
			len = SMB2_HDR_BODY + 2;

			state->asked_for_header = true;
		}

		state->missing -= len;

		buf = talloc_array(req->in.vector, uint8_t, len);
		if (buf == NULL) {
			return -1;
		}

		req->in.vector[idx].iov_base	= (void *)buf;
		req->in.vector[idx].iov_len	= len;

		vector = talloc_array(mem_ctx, struct iovec, 1);
		if (vector == NULL) {
			return -1;
		}

		vector[0] = req->in.vector[idx];

		*_vector = vector;
		*_count = 1;
		return 0;
	}

	if (state->missing == 0) {
		/* if there're no remaining bytes, we're done */
		*_vector = NULL;
		*_count = 0;
		return 0;
	}

	if (state->asked_for_header) {
		const uint8_t *hdr;
		size_t full_size;
		size_t next_command_ofs;
		size_t body_size;
		uint8_t *body;
		size_t dyn_size;
		uint8_t *dyn;
		bool invalid = false;

		state->asked_for_header = false;

		/*
		 * We got the SMB2 header and the first 2 bytes
		 * of the body. We fix the size to just the header
		 * and manually copy the 2 first bytes to the body section
		 */
		req->in.vector[idx-1].iov_len = SMB2_HDR_BODY;
		hdr = (const uint8_t *)req->in.vector[idx-1].iov_base;

		/* allocate vectors for body and dynamic areas */
		req->in.vector = talloc_realloc(req, req->in.vector,
						struct iovec,
						req->in.vector_count + 2);
		if (req->in.vector == NULL) {
			return -1;
		}
		req->in.vector_count += 2;

		full_size = state->missing + SMB2_HDR_BODY + 2;
		next_command_ofs = IVAL(hdr, SMB2_HDR_NEXT_COMMAND);
		body_size = SVAL(hdr, SMB2_HDR_BODY);

		if (next_command_ofs != 0) {
			if (next_command_ofs < (SMB2_HDR_BODY + 2)) {
				/*
				 * this is invalid, just return a zero
				 * body and let the caller deal with the error
				 */
				invalid = true;
			} else if (next_command_ofs > full_size) {
				/*
				 * this is invalid, just return a zero
				 * body and let the caller deal with the error
				 */
				invalid = true;
			} else {
				full_size = next_command_ofs;
			}
		}

		if (!invalid) {
			if (body_size < 2) {
				/*
				 * this is invalid, just return a zero
				 * body and let the caller deal with the error
				 */
				invalid = true;
			} else if (body_size > (full_size - SMB2_HDR_BODY)) {
				/*
				 * this is invalid, just return a zero
				 * body and let the caller deal with the error
				 */
				invalid = true;
			}
		}

		if (invalid) {
			/* the caller should check this */
			body_size = 0;
		}

		if ((body_size % 2) != 0) {
			body_size -= 1;
		}

		dyn_size = full_size - (SMB2_HDR_BODY + body_size);

		state->missing -= (body_size - 2) + dyn_size;

		body = talloc_array(req->in.vector, uint8_t, body_size);
		if (body == NULL) {
			return -1;
		}

		dyn = talloc_array(req->in.vector, uint8_t, dyn_size);
		if (dyn == NULL) {
			return -1;
		}

		req->in.vector[idx].iov_base	= (void *)body;
		req->in.vector[idx].iov_len	= body_size;
		req->in.vector[idx+1].iov_base	= (void *)dyn;
		req->in.vector[idx+1].iov_len	= dyn_size;

		vector = talloc_array(mem_ctx, struct iovec, 2);
		if (vector == NULL) {
			return -1;
		}

		/*
		 * the first 2 bytes of the body were already fetched
		 * together with the header
		 */
		memcpy(body, hdr + SMB2_HDR_BODY, 2);
		vector[0].iov_base = body + 2;
		vector[0].iov_len = req->in.vector[idx].iov_len - 2;

		vector[1] = req->in.vector[idx+1];

		*_vector = vector;
		*_count = 2;
		return 0;
	}

	/*
	 * when we endup here, we're looking for a new SMB2 request
	 * next. And we ask for its header and the first 2 bytes of
	 * the body (like we did for the first SMB2 request).
	 */

	req->in.vector = talloc_realloc(req, req->in.vector,
					struct iovec,
					req->in.vector_count + 1);
	if (req->in.vector == NULL) {
		return -1;
	}
	req->in.vector_count += 1;

	/*
	 * We assume it's a SMB2 request,
	 * and we first get the header and the
	 * first 2 bytes (the struct size) of the body
	 */
	len = SMB2_HDR_BODY + 2;

	if (len > state->missing) {
		/* let the caller handle the error */
		len = state->missing;
	}

	state->missing -= len;
	state->asked_for_header = true;

	buf = talloc_array(req->in.vector, uint8_t, len);
	if (buf == NULL) {
		return -1;
	}

	req->in.vector[idx].iov_base	= (void *)buf;
	req->in.vector[idx].iov_len	= len;

	vector = talloc_array(mem_ctx, struct iovec, 1);
	if (vector == NULL) {
		return -1;
	}

	vector[0] = req->in.vector[idx];

	*_vector = vector;
	*_count = 1;
	return 0;
}

static void smbd_smb2_request_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	int ret;
	int sys_errno;
	NTSTATUS status;

	ret = tstream_readv_pdu_queue_recv(subreq, &sys_errno);
	if (ret == -1) {
		status = map_nt_error_from_unix(sys_errno);
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS smbd_smb2_request_read_recv(struct tevent_req *req,
					    TALLOC_CTX *mem_ctx,
					    struct smbd_smb2_request **_smb2_req)
{
	struct smbd_smb2_request_read_state *state =
		tevent_req_data(req,
		struct smbd_smb2_request_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	talloc_steal(mem_ctx, state->smb2_req->mem_pool);
	*_smb2_req = state->smb2_req;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

static void smbd_smb2_request_incoming(struct tevent_req *subreq);

void smbd_smb2_first_negprot(struct smbd_server_connection *conn,
			     const uint8_t *inbuf, size_t size)
{
	NTSTATUS status;
	struct smbd_smb2_request *req;
	struct tevent_req *subreq;

	DEBUG(10,("smbd_smb2_first_negprot: packet length %u\n",
		 (unsigned int)size));

	status = smbd_initialize_smb2(conn);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(conn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_create(conn, inbuf, size, &req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(conn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_setup_out(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(conn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_dispatch(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(conn, nt_errstr(status));
		return;
	}

	/* ask for the next request */
	subreq = smbd_smb2_request_read_send(conn,conn->smb2.event_ctx, conn);
	if (subreq == NULL) {
		smbd_server_connection_terminate(conn, "no memory for reading");
		return;
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_incoming, conn);
}

static void smbd_smb2_request_incoming(struct tevent_req *subreq)
{
	struct smbd_server_connection *conn = tevent_req_callback_data(subreq,
					      struct smbd_server_connection);
	NTSTATUS status;
	struct smbd_smb2_request *req;

	status = smbd_smb2_request_read_recv(subreq, conn, &req);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(conn, nt_errstr(status));
		return;
	}

	/* TODO: validate the incoming request */
	req->current_idx = 1;

	DEBUG(10,("smbd_smb2_request_incoming: idx[%d] of %d vectors\n",
		 req->current_idx, req->in.vector_count));

	status = smbd_smb2_request_setup_out(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(conn, nt_errstr(status));
		return;
	}

	status = smbd_smb2_request_dispatch(req);
	if (!NT_STATUS_IS_OK(status)) {
		smbd_server_connection_terminate(conn, nt_errstr(status));
		return;
	}

	/* ask for the next request (this constructs the main loop) */
	subreq = smbd_smb2_request_read_send(conn,conn->smb2.event_ctx, conn);
	if (subreq == NULL) {
		smbd_server_connection_terminate(conn, "no memory for reading");
		return;
	}
	tevent_req_set_callback(subreq, smbd_smb2_request_incoming, conn);
}
