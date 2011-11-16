/*
   Unix SMB/CIFS implementation.
   Infrastructure for async SMB client requests
   Copyright (C) Volker Lendecke 2008
   Copyright (C) Stefan Metzmacher 2011

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
#include "system/network.h"
#include "../lib/async_req/async_sock.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../lib/util/tevent_unix.h"
#include "lib/util/util_net.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/smb/smb_seal.h"
#include "../libcli/smb/smb_signing.h"
#include "../libcli/smb/read_smb.h"
#include "smbXcli_base.h"
#include "librpc/ndr/libndr.h"

struct smbXcli_conn {
	int fd;
	struct sockaddr_storage local_ss;
	struct sockaddr_storage remote_ss;
	const char *remote_name;

	struct tevent_queue *outgoing;
	struct tevent_req **pending;
	struct tevent_req *read_smb_req;

	enum protocol_types protocol;
	bool allow_signing;
	bool desire_signing;
	bool mandatory_signing;

	/*
	 * The incoming dispatch function should return:
	 * - NT_STATUS_RETRY, if more incoming PDUs are expected.
	 * - NT_STATUS_OK, if no more processing is desired, e.g.
	 *                 the dispatch function called
	 *                 tevent_req_done().
	 * - All other return values disconnect the connection.
	 */
	NTSTATUS (*dispatch_incoming)(struct smbXcli_conn *conn,
				      TALLOC_CTX *tmp_mem,
				      uint8_t *inbuf);

	struct {
		struct {
			uint32_t capabilities;
			uint32_t max_xmit;
		} client;

		struct {
			uint32_t capabilities;
			uint32_t max_xmit;
			uint16_t max_mux;
			uint16_t security_mode;
			bool readbraw;
			bool writebraw;
			bool lockread;
			bool writeunlock;
			uint32_t session_key;
			struct GUID guid;
			DATA_BLOB gss_blob;
			uint8_t challenge[8];
			const char *workgroup;
			int time_zone;
			NTTIME system_time;
		} server;

		uint32_t capabilities;
		uint32_t max_xmit;

		uint16_t mid;

		struct smb_signing_state *signing;
		struct smb_trans_enc_state *trans_enc;
	} smb1;

	struct {
		struct {
			uint16_t security_mode;
		} client;

		struct {
			uint32_t capabilities;
			uint16_t security_mode;
			struct GUID guid;
			uint32_t max_trans_size;
			uint32_t max_read_size;
			uint32_t max_write_size;
			NTTIME system_time;
			NTTIME start_time;
			DATA_BLOB gss_blob;
		} server;

		uint64_t mid;
	} smb2;
};

struct smbXcli_req_state {
	struct tevent_context *ev;
	struct smbXcli_conn *conn;

	uint8_t length_hdr[4];

	bool one_way;

	uint8_t *inbuf;

	struct {
		/* Space for the header including the wct */
		uint8_t hdr[HDR_VWV];

		/*
		 * For normal requests, smb1cli_req_send chooses a mid.
		 * SecondaryV trans requests need to use the mid of the primary
		 * request, so we need a place to store it.
		 * Assume it is set if != 0.
		 */
		uint16_t mid;

		uint16_t *vwv;
		uint8_t bytecount_buf[2];

#define MAX_SMB_IOV 5
		/* length_hdr, hdr, words, byte_count, buffers */
		struct iovec iov[1 + 3 + MAX_SMB_IOV];
		int iov_count;

		uint32_t seqnum;
		int chain_num;
		int chain_length;
		struct tevent_req **chained_requests;

		uint8_t recv_cmd;
		NTSTATUS recv_status;
		/* always an array of 3 talloc elements */
		struct iovec *recv_iov;
	} smb1;

	struct {
		const uint8_t *fixed;
		uint16_t fixed_len;
		const uint8_t *dyn;
		uint32_t dyn_len;

		uint8_t hdr[64];
		uint8_t pad[7];	/* padding space for compounding */

		/* always an array of 3 talloc elements */
		struct iovec *recv_iov;
	} smb2;
};

static int smbXcli_conn_destructor(struct smbXcli_conn *conn)
{
	/*
	 * NT_STATUS_OK, means we do not notify the callers
	 */
	smbXcli_conn_disconnect(conn, NT_STATUS_OK);

	if (conn->smb1.trans_enc) {
		common_free_encryption_state(&conn->smb1.trans_enc);
	}

	return 0;
}

struct smbXcli_conn *smbXcli_conn_create(TALLOC_CTX *mem_ctx,
					 int fd,
					 const char *remote_name,
					 enum smb_signing_setting signing_state,
					 uint32_t smb1_capabilities)
{
	struct smbXcli_conn *conn = NULL;
	void *ss = NULL;
	struct sockaddr *sa = NULL;
	socklen_t sa_length;
	int ret;

	conn = talloc_zero(mem_ctx, struct smbXcli_conn);
	if (!conn) {
		return NULL;
	}

	conn->remote_name = talloc_strdup(conn, remote_name);
	if (conn->remote_name == NULL) {
		goto error;
	}

	conn->fd = fd;

	ss = (void *)&conn->local_ss;
	sa = (struct sockaddr *)ss;
	sa_length = sizeof(conn->local_ss);
	ret = getsockname(fd, sa, &sa_length);
	if (ret == -1) {
		goto error;
	}
	ss = (void *)&conn->remote_ss;
	sa = (struct sockaddr *)ss;
	sa_length = sizeof(conn->remote_ss);
	ret = getpeername(fd, sa, &sa_length);
	if (ret == -1) {
		goto error;
	}

	conn->outgoing = tevent_queue_create(conn, "smbXcli_outgoing");
	if (conn->outgoing == NULL) {
		goto error;
	}
	conn->pending = NULL;

	conn->protocol = PROTOCOL_NONE;

	switch (signing_state) {
	case SMB_SIGNING_OFF:
		/* never */
		conn->allow_signing = false;
		conn->desire_signing = false;
		conn->mandatory_signing = false;
		break;
	case SMB_SIGNING_DEFAULT:
	case SMB_SIGNING_IF_REQUIRED:
		/* if the server requires it */
		conn->allow_signing = true;
		conn->desire_signing = false;
		conn->mandatory_signing = false;
		break;
	case SMB_SIGNING_REQUIRED:
		/* always */
		conn->allow_signing = true;
		conn->desire_signing = true;
		conn->mandatory_signing = true;
		break;
	}

	conn->smb1.client.capabilities = smb1_capabilities;
	conn->smb1.client.max_xmit = UINT16_MAX;

	conn->smb1.capabilities = conn->smb1.client.capabilities;
	conn->smb1.max_xmit = 1024;

	conn->smb1.mid = 1;

	/* initialise signing */
	conn->smb1.signing = smb_signing_init(conn,
					      conn->allow_signing,
					      conn->desire_signing,
					      conn->mandatory_signing);
	if (!conn->smb1.signing) {
		goto error;
	}

	conn->smb2.client.security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (conn->mandatory_signing) {
		conn->smb2.client.security_mode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
	}

	talloc_set_destructor(conn, smbXcli_conn_destructor);
	return conn;

 error:
	TALLOC_FREE(conn);
	return NULL;
}

bool smbXcli_conn_is_connected(struct smbXcli_conn *conn)
{
	if (conn == NULL) {
		return false;
	}

	if (conn->fd == -1) {
		return false;
	}

	return true;
}

enum protocol_types smbXcli_conn_protocol(struct smbXcli_conn *conn)
{
	return conn->protocol;
}

bool smbXcli_conn_use_unicode(struct smbXcli_conn *conn)
{
	if (conn->protocol >= PROTOCOL_SMB2_02) {
		return true;
	}

	if (conn->smb1.capabilities & CAP_UNICODE) {
		return true;
	}

	return false;
}

void smbXcli_conn_set_sockopt(struct smbXcli_conn *conn, const char *options)
{
	set_socket_options(conn->fd, options);
}

const struct sockaddr_storage *smbXcli_conn_local_sockaddr(struct smbXcli_conn *conn)
{
	return &conn->local_ss;
}

const struct sockaddr_storage *smbXcli_conn_remote_sockaddr(struct smbXcli_conn *conn)
{
	return &conn->remote_ss;
}

const char *smbXcli_conn_remote_name(struct smbXcli_conn *conn)
{
	return conn->remote_name;
}

bool smb1cli_conn_activate_signing(struct smbXcli_conn *conn,
				   const DATA_BLOB user_session_key,
				   const DATA_BLOB response)
{
	return smb_signing_activate(conn->smb1.signing,
				    user_session_key,
				    response);
}

bool smb1cli_conn_check_signing(struct smbXcli_conn *conn,
				const uint8_t *buf, uint32_t seqnum)
{
	return smb_signing_check_pdu(conn->smb1.signing, buf, seqnum);
}

bool smb1cli_conn_signing_is_active(struct smbXcli_conn *conn)
{
	return smb_signing_is_active(conn->smb1.signing);
}

void smb1cli_conn_set_encryption(struct smbXcli_conn *conn,
				 struct smb_trans_enc_state *es)
{
	/* Replace the old state, if any. */
	if (conn->smb1.trans_enc) {
		common_free_encryption_state(&conn->smb1.trans_enc);
	}
	conn->smb1.trans_enc = es;
}

bool smb1cli_conn_encryption_on(struct smbXcli_conn *conn)
{
	return common_encryption_on(conn->smb1.trans_enc);
}


static NTSTATUS smb1cli_pull_raw_error(const uint8_t *hdr)
{
	uint32_t flags2 = SVAL(hdr, HDR_FLG2);
	NTSTATUS status = NT_STATUS(IVAL(hdr, HDR_RCLS));

	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}

	if (flags2 & FLAGS2_32_BIT_ERROR_CODES) {
		return status;
	}

	return NT_STATUS_DOS(CVAL(hdr, HDR_RCLS), SVAL(hdr, HDR_ERR));
}

/**
 * Figure out if there is an andx command behind the current one
 * @param[in] buf	The smb buffer to look at
 * @param[in] ofs	The offset to the wct field that is followed by the cmd
 * @retval Is there a command following?
 */

static bool smb1cli_have_andx_command(const uint8_t *buf,
				      uint16_t ofs,
				      uint8_t cmd)
{
	uint8_t wct;
	size_t buflen = talloc_get_size(buf);

	if (!smb1cli_is_andx_req(cmd)) {
		return false;
	}

	if ((ofs == buflen-1) || (ofs == buflen)) {
		return false;
	}

	wct = CVAL(buf, ofs);
	if (wct < 2) {
		/*
		 * Not enough space for the command and a following pointer
		 */
		return false;
	}
	return (CVAL(buf, ofs+1) != 0xff);
}

/**
 * Is the SMB command able to hold an AND_X successor
 * @param[in] cmd	The SMB command in question
 * @retval Can we add a chained request after "cmd"?
 */
bool smb1cli_is_andx_req(uint8_t cmd)
{
	switch (cmd) {
	case SMBtconX:
	case SMBlockingX:
	case SMBopenX:
	case SMBreadX:
	case SMBwriteX:
	case SMBsesssetupX:
	case SMBulogoffX:
	case SMBntcreateX:
		return true;
		break;
	default:
		break;
	}

	return false;
}

static uint16_t smb1cli_alloc_mid(struct smbXcli_conn *conn)
{
	size_t num_pending = talloc_array_length(conn->pending);
	uint16_t result;

	while (true) {
		size_t i;

		result = conn->smb1.mid++;
		if ((result == 0) || (result == 0xffff)) {
			continue;
		}

		for (i=0; i<num_pending; i++) {
			if (result == smb1cli_req_mid(conn->pending[i])) {
				break;
			}
		}

		if (i == num_pending) {
			return result;
		}
	}
}

void smbXcli_req_unset_pending(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	struct smbXcli_conn *conn = state->conn;
	size_t num_pending = talloc_array_length(conn->pending);
	size_t i;

	if (state->smb1.mid != 0) {
		/*
		 * This is a [nt]trans[2] request which waits
		 * for more than one reply.
		 */
		return;
	}

	talloc_set_destructor(req, NULL);

	if (num_pending == 1) {
		/*
		 * The pending read_smb tevent_req is a child of
		 * conn->pending. So if nothing is pending anymore, we need to
		 * delete the socket read fde.
		 */
		TALLOC_FREE(conn->pending);
		conn->read_smb_req = NULL;
		return;
	}

	for (i=0; i<num_pending; i++) {
		if (req == conn->pending[i]) {
			break;
		}
	}
	if (i == num_pending) {
		/*
		 * Something's seriously broken. Just returning here is the
		 * right thing nevertheless, the point of this routine is to
		 * remove ourselves from conn->pending.
		 */
		return;
	}

	/*
	 * Remove ourselves from the conn->pending array
	 */
	for (; i < (num_pending - 1); i++) {
		conn->pending[i] = conn->pending[i+1];
	}

	/*
	 * No NULL check here, we're shrinking by sizeof(void *), and
	 * talloc_realloc just adjusts the size for this.
	 */
	conn->pending = talloc_realloc(NULL, conn->pending, struct tevent_req *,
				       num_pending - 1);
	return;
}

static int smbXcli_req_destructor(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);

	/*
	 * Make sure we really remove it from
	 * the pending array on destruction.
	 */
	state->smb1.mid = 0;
	smbXcli_req_unset_pending(req);
	return 0;
}

static bool smbXcli_conn_receive_next(struct smbXcli_conn *conn);

bool smbXcli_req_set_pending(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	struct smbXcli_conn *conn;
	struct tevent_req **pending;
	size_t num_pending;

	conn = state->conn;

	if (!smbXcli_conn_is_connected(conn)) {
		return false;
	}

	num_pending = talloc_array_length(conn->pending);

	pending = talloc_realloc(conn, conn->pending, struct tevent_req *,
				 num_pending+1);
	if (pending == NULL) {
		return false;
	}
	pending[num_pending] = req;
	conn->pending = pending;
	talloc_set_destructor(req, smbXcli_req_destructor);

	if (!smbXcli_conn_receive_next(conn)) {
		/*
		 * the caller should notify the current request
		 *
		 * And all other pending requests get notified
		 * by smbXcli_conn_disconnect().
		 */
		smbXcli_req_unset_pending(req);
		smbXcli_conn_disconnect(conn, NT_STATUS_NO_MEMORY);
		return false;
	}

	return true;
}

static void smbXcli_conn_received(struct tevent_req *subreq);

static bool smbXcli_conn_receive_next(struct smbXcli_conn *conn)
{
	size_t num_pending = talloc_array_length(conn->pending);
	struct tevent_req *req;
	struct smbXcli_req_state *state;

	if (conn->read_smb_req != NULL) {
		return true;
	}

	if (num_pending == 0) {
		if (conn->smb2.mid < UINT64_MAX) {
			/* no more pending requests, so we are done for now */
			return true;
		}

		/*
		 * If there are no more SMB2 requests possible,
		 * because we are out of message ids,
		 * we need to disconnect.
		 */
		smbXcli_conn_disconnect(conn, NT_STATUS_CONNECTION_ABORTED);
		return true;
	}

	req = conn->pending[0];
	state = tevent_req_data(req, struct smbXcli_req_state);

	/*
	 * We're the first ones, add the read_smb request that waits for the
	 * answer from the server
	 */
	conn->read_smb_req = read_smb_send(conn->pending, state->ev, conn->fd);
	if (conn->read_smb_req == NULL) {
		return false;
	}
	tevent_req_set_callback(conn->read_smb_req, smbXcli_conn_received, conn);
	return true;
}

void smbXcli_conn_disconnect(struct smbXcli_conn *conn, NTSTATUS status)
{
	if (conn->fd != -1) {
		close(conn->fd);
	}
	conn->fd = -1;

	/*
	 * Cancel all pending requests. We do not do a for-loop walking
	 * conn->pending because that array changes in
	 * smbXcli_req_unset_pending.
	 */
	while (talloc_array_length(conn->pending) > 0) {
		struct tevent_req *req;
		struct smbXcli_req_state *state;

		req = conn->pending[0];
		state = tevent_req_data(req, struct smbXcli_req_state);

		/*
		 * We're dead. No point waiting for trans2
		 * replies.
		 */
		state->smb1.mid = 0;

		smbXcli_req_unset_pending(req);

		if (NT_STATUS_IS_OK(status)) {
			/* do not notify the callers */
			continue;
		}

		/*
		 * we need to defer the callback, because we may notify more
		 * then one caller.
		 */
		tevent_req_defer_callback(req, state->ev);
		tevent_req_nterror(req, status);
	}
}

/*
 * Fetch a smb request's mid. Only valid after the request has been sent by
 * smb1cli_req_send().
 */
uint16_t smb1cli_req_mid(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);

	if (state->smb1.mid != 0) {
		return state->smb1.mid;
	}

	return SVAL(state->smb1.hdr, HDR_MID);
}

void smb1cli_req_set_mid(struct tevent_req *req, uint16_t mid)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);

	state->smb1.mid = mid;
}

uint32_t smb1cli_req_seqnum(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);

	return state->smb1.seqnum;
}

void smb1cli_req_set_seqnum(struct tevent_req *req, uint32_t seqnum)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);

	state->smb1.seqnum = seqnum;
}

static size_t smbXcli_iov_len(const struct iovec *iov, int count)
{
	size_t result = 0;
	int i;
	for (i=0; i<count; i++) {
		result += iov[i].iov_len;
	}
	return result;
}

static uint8_t *smbXcli_iov_concat(TALLOC_CTX *mem_ctx,
				   const struct iovec *iov,
				   int count)
{
	size_t len = smbXcli_iov_len(iov, count);
	size_t copied;
	uint8_t *buf;
	int i;

	buf = talloc_array(mem_ctx, uint8_t, len);
	if (buf == NULL) {
		return NULL;
	}
	copied = 0;
	for (i=0; i<count; i++) {
		memcpy(buf+copied, iov[i].iov_base, iov[i].iov_len);
		copied += iov[i].iov_len;
	}
	return buf;
}

static void smb1cli_req_flags(enum protocol_types protocol,
			      uint32_t smb1_capabilities,
			      uint8_t smb_command,
			      uint8_t additional_flags,
			      uint8_t clear_flags,
			      uint8_t *_flags,
			      uint16_t additional_flags2,
			      uint16_t clear_flags2,
			      uint16_t *_flags2)
{
	uint8_t flags = 0;
	uint16_t flags2 = 0;

	if (protocol >= PROTOCOL_LANMAN1) {
		flags |= FLAG_CASELESS_PATHNAMES;
		flags |= FLAG_CANONICAL_PATHNAMES;
	}

	if (protocol >= PROTOCOL_LANMAN2) {
		flags2 |= FLAGS2_LONG_PATH_COMPONENTS;
		flags2 |= FLAGS2_EXTENDED_ATTRIBUTES;
	}

	if (protocol >= PROTOCOL_NT1) {
		flags2 |= FLAGS2_IS_LONG_NAME;

		if (smb1_capabilities & CAP_UNICODE) {
			flags2 |= FLAGS2_UNICODE_STRINGS;
		}
		if (smb1_capabilities & CAP_STATUS32) {
			flags2 |= FLAGS2_32_BIT_ERROR_CODES;
		}
		if (smb1_capabilities & CAP_EXTENDED_SECURITY) {
			flags2 |= FLAGS2_EXTENDED_SECURITY;
		}
	}

	flags |= additional_flags;
	flags &= ~clear_flags;
	flags2 |= additional_flags2;
	flags2 &= ~clear_flags2;

	*_flags = flags;
	*_flags2 = flags2;
}

struct tevent_req *smb1cli_req_create(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint8_t smb_command,
				      uint8_t additional_flags,
				      uint8_t clear_flags,
				      uint16_t additional_flags2,
				      uint16_t clear_flags2,
				      uint32_t timeout_msec,
				      uint32_t pid,
				      uint16_t tid,
				      uint16_t uid,
				      uint8_t wct, uint16_t *vwv,
				      int iov_count,
				      struct iovec *bytes_iov)
{
	struct tevent_req *req;
	struct smbXcli_req_state *state;
	uint8_t flags = 0;
	uint16_t flags2 = 0;

	if (iov_count > MAX_SMB_IOV) {
		/*
		 * Should not happen :-)
		 */
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state,
				struct smbXcli_req_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->conn = conn;

	state->smb1.recv_cmd = 0xFF;
	state->smb1.recv_status = NT_STATUS_INTERNAL_ERROR;
	state->smb1.recv_iov = talloc_zero_array(state, struct iovec, 3);
	if (state->smb1.recv_iov == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}

	smb1cli_req_flags(conn->protocol,
			  conn->smb1.capabilities,
			  smb_command,
			  additional_flags,
			  clear_flags,
			  &flags,
			  additional_flags2,
			  clear_flags2,
			  &flags2);

	SIVAL(state->smb1.hdr, 0,           SMB_MAGIC);
	SCVAL(state->smb1.hdr, HDR_COM,     smb_command);
	SIVAL(state->smb1.hdr, HDR_RCLS,    NT_STATUS_V(NT_STATUS_OK));
	SCVAL(state->smb1.hdr, HDR_FLG,     flags);
	SSVAL(state->smb1.hdr, HDR_FLG2,    flags2);
	SSVAL(state->smb1.hdr, HDR_PIDHIGH, pid >> 16);
	SSVAL(state->smb1.hdr, HDR_TID,     tid);
	SSVAL(state->smb1.hdr, HDR_PID,     pid);
	SSVAL(state->smb1.hdr, HDR_UID,     uid);
	SSVAL(state->smb1.hdr, HDR_MID,     0); /* this comes later */
	SSVAL(state->smb1.hdr, HDR_WCT,     wct);

	state->smb1.vwv = vwv;

	SSVAL(state->smb1.bytecount_buf, 0, smbXcli_iov_len(bytes_iov, iov_count));

	state->smb1.iov[0].iov_base = (void *)state->length_hdr;
	state->smb1.iov[0].iov_len  = sizeof(state->length_hdr);
	state->smb1.iov[1].iov_base = (void *)state->smb1.hdr;
	state->smb1.iov[1].iov_len  = sizeof(state->smb1.hdr);
	state->smb1.iov[2].iov_base = (void *)state->smb1.vwv;
	state->smb1.iov[2].iov_len  = wct * sizeof(uint16_t);
	state->smb1.iov[3].iov_base = (void *)state->smb1.bytecount_buf;
	state->smb1.iov[3].iov_len  = sizeof(uint16_t);

	if (iov_count != 0) {
		memcpy(&state->smb1.iov[4], bytes_iov,
		       iov_count * sizeof(*bytes_iov));
	}
	state->smb1.iov_count = iov_count + 4;

	if (timeout_msec > 0) {
		struct timeval endtime;

		endtime = timeval_current_ofs_msec(timeout_msec);
		if (!tevent_req_set_endtime(req, ev, endtime)) {
			return req;
		}
	}

	switch (smb_command) {
	case SMBtranss:
	case SMBtranss2:
	case SMBnttranss:
	case SMBntcancel:
		state->one_way = true;
		break;
	case SMBlockingX:
		if ((wct == 8) &&
		    (CVAL(vwv+3, 0) == LOCKING_ANDX_OPLOCK_RELEASE)) {
			state->one_way = true;
		}
		break;
	}

	return req;
}

static NTSTATUS smb1cli_conn_signv(struct smbXcli_conn *conn,
				   struct iovec *iov, int iov_count,
				   uint32_t *seqnum)
{
	uint8_t *buf;

	/*
	 * Obvious optimization: Make cli_calculate_sign_mac work with struct
	 * iovec directly. MD5Update would do that just fine.
	 */

	if (iov_count < 4) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	if (iov[0].iov_len != NBT_HDR_SIZE) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	if (iov[1].iov_len != (MIN_SMB_SIZE-sizeof(uint16_t))) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	if (iov[2].iov_len > (0xFF * sizeof(uint16_t))) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	if (iov[3].iov_len != sizeof(uint16_t)) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	buf = smbXcli_iov_concat(talloc_tos(), iov, iov_count);
	if (buf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*seqnum = smb_signing_next_seqnum(conn->smb1.signing, false);
	smb_signing_sign_pdu(conn->smb1.signing, buf, *seqnum);
	memcpy(iov[1].iov_base, buf+4, iov[1].iov_len);

	TALLOC_FREE(buf);
	return NT_STATUS_OK;
}

static void smb1cli_req_writev_done(struct tevent_req *subreq);
static NTSTATUS smb1cli_conn_dispatch_incoming(struct smbXcli_conn *conn,
					       TALLOC_CTX *tmp_mem,
					       uint8_t *inbuf);

static NTSTATUS smb1cli_req_writev_submit(struct tevent_req *req,
					  struct smbXcli_req_state *state,
					  struct iovec *iov, int iov_count)
{
	struct tevent_req *subreq;
	NTSTATUS status;
	uint16_t mid;

	if (!smbXcli_conn_is_connected(state->conn)) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	if (state->conn->protocol > PROTOCOL_NT1) {
		return NT_STATUS_REVISION_MISMATCH;
	}

	if (iov_count < 4) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	if (iov[0].iov_len != NBT_HDR_SIZE) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	if (iov[1].iov_len != (MIN_SMB_SIZE-sizeof(uint16_t))) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	if (iov[2].iov_len > (0xFF * sizeof(uint16_t))) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}
	if (iov[3].iov_len != sizeof(uint16_t)) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (state->smb1.mid != 0) {
		mid = state->smb1.mid;
	} else {
		mid = smb1cli_alloc_mid(state->conn);
	}
	SSVAL(iov[1].iov_base, HDR_MID, mid);

	_smb_setlen_nbt(iov[0].iov_base, smbXcli_iov_len(&iov[1], iov_count-1));

	status = smb1cli_conn_signv(state->conn, iov, iov_count,
				    &state->smb1.seqnum);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * If we supported multiple encrytion contexts
	 * here we'd look up based on tid.
	 */
	if (common_encryption_on(state->conn->smb1.trans_enc)) {
		char *buf, *enc_buf;

		buf = (char *)smbXcli_iov_concat(talloc_tos(), iov, iov_count);
		if (buf == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		status = common_encrypt_buffer(state->conn->smb1.trans_enc,
					       (char *)buf, &enc_buf);
		TALLOC_FREE(buf);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0, ("Error in encrypting client message: %s\n",
				  nt_errstr(status)));
			return status;
		}
		buf = (char *)talloc_memdup(state, enc_buf,
					    smb_len_nbt(enc_buf)+4);
		SAFE_FREE(enc_buf);
		if (buf == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		iov[0].iov_base = (void *)buf;
		iov[0].iov_len = talloc_get_size(buf);
		iov_count = 1;
	}

	if (state->conn->dispatch_incoming == NULL) {
		state->conn->dispatch_incoming = smb1cli_conn_dispatch_incoming;
	}

	subreq = writev_send(state, state->ev, state->conn->outgoing,
			     state->conn->fd, false, iov, iov_count);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smb1cli_req_writev_done, req);
	return NT_STATUS_OK;
}

struct tevent_req *smb1cli_req_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct smbXcli_conn *conn,
				    uint8_t smb_command,
				    uint8_t additional_flags,
				    uint8_t clear_flags,
				    uint16_t additional_flags2,
				    uint16_t clear_flags2,
				    uint32_t timeout_msec,
				    uint32_t pid,
				    uint16_t tid,
				    uint16_t uid,
				    uint8_t wct, uint16_t *vwv,
				    uint32_t num_bytes,
				    const uint8_t *bytes)
{
	struct tevent_req *req;
	struct iovec iov;
	NTSTATUS status;

	iov.iov_base = discard_const_p(void, bytes);
	iov.iov_len = num_bytes;

	req = smb1cli_req_create(mem_ctx, ev, conn, smb_command,
				 additional_flags, clear_flags,
				 additional_flags2, clear_flags2,
				 timeout_msec,
				 pid, tid, uid,
				 wct, vwv, 1, &iov);
	if (req == NULL) {
		return NULL;
	}
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}
	status = smb1cli_req_chain_submit(&req, 1);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void smb1cli_req_writev_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	ssize_t nwritten;
	int err;

	nwritten = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		NTSTATUS status = map_nt_error_from_unix_common(err);
		smbXcli_conn_disconnect(state->conn, status);
		return;
	}

	if (state->one_way) {
		state->inbuf = NULL;
		tevent_req_done(req);
		return;
	}

	if (!smbXcli_req_set_pending(req)) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
}

static void smbXcli_conn_received(struct tevent_req *subreq)
{
	struct smbXcli_conn *conn =
		tevent_req_callback_data(subreq,
		struct smbXcli_conn);
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;
	uint8_t *inbuf;
	ssize_t received;
	int err;

	if (subreq != conn->read_smb_req) {
		DEBUG(1, ("Internal error: cli_smb_received called with "
			  "unexpected subreq\n"));
		status = NT_STATUS_INTERNAL_ERROR;
		smbXcli_conn_disconnect(conn, status);
		TALLOC_FREE(frame);
		return;
	}
	conn->read_smb_req = NULL;

	received = read_smb_recv(subreq, frame, &inbuf, &err);
	TALLOC_FREE(subreq);
	if (received == -1) {
		status = map_nt_error_from_unix_common(err);
		smbXcli_conn_disconnect(conn, status);
		TALLOC_FREE(frame);
		return;
	}

	status = conn->dispatch_incoming(conn, frame, inbuf);
	TALLOC_FREE(frame);
	if (NT_STATUS_IS_OK(status)) {
		/*
		 * We should not do any more processing
		 * as the dispatch function called
		 * tevent_req_done().
		 */
		return;
	} else if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
		/*
		 * We got an error, so notify all pending requests
		 */
		smbXcli_conn_disconnect(conn, status);
		return;
	}

	/*
	 * We got NT_STATUS_RETRY, so we may ask for a
	 * next incoming pdu.
	 */
	if (!smbXcli_conn_receive_next(conn)) {
		smbXcli_conn_disconnect(conn, NT_STATUS_NO_MEMORY);
	}
}

static NTSTATUS smb1cli_inbuf_parse_chain(uint8_t *buf, TALLOC_CTX *mem_ctx,
					  struct iovec **piov, int *pnum_iov)
{
	struct iovec *iov;
	int num_iov;
	size_t buflen;
	size_t taken;
	size_t remaining;
	uint8_t *hdr;
	uint8_t cmd;
	uint32_t wct_ofs;

	buflen = smb_len_nbt(buf);
	taken = 0;

	hdr = buf + NBT_HDR_SIZE;

	if (buflen < MIN_SMB_SIZE) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	/*
	 * This returns iovec elements in the following order:
	 *
	 * - SMB header
	 *
	 * - Parameter Block
	 * - Data Block
	 *
	 * - Parameter Block
	 * - Data Block
	 *
	 * - Parameter Block
	 * - Data Block
	 */
	num_iov = 1;

	iov = talloc_array(mem_ctx, struct iovec, num_iov);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	iov[0].iov_base = hdr;
	iov[0].iov_len = HDR_WCT;
	taken += HDR_WCT;

	cmd = CVAL(hdr, HDR_COM);
	wct_ofs = HDR_WCT;

	while (true) {
		size_t len = buflen - taken;
		struct iovec *cur;
		struct iovec *iov_tmp;
		uint8_t wct;
		uint32_t bcc_ofs;
		uint16_t bcc;
		size_t needed;

		/*
		 * we need at least WCT and BCC
		 */
		needed = sizeof(uint8_t) + sizeof(uint16_t);
		if (len < needed) {
			DEBUG(10, ("%s: %d bytes left, expected at least %d\n",
				   __location__, (int)len, (int)needed));
			goto inval;
		}

		/*
		 * Now we check if the specified words are there
		 */
		wct = CVAL(hdr, wct_ofs);
		needed += wct * sizeof(uint16_t);
		if (len < needed) {
			DEBUG(10, ("%s: %d bytes left, expected at least %d\n",
				   __location__, (int)len, (int)needed));
			goto inval;
		}

		/*
		 * Now we check if the specified bytes are there
		 */
		bcc_ofs = wct_ofs + sizeof(uint8_t) + wct * sizeof(uint16_t);
		bcc = SVAL(hdr, bcc_ofs);
		needed += bcc * sizeof(uint8_t);
		if (len < needed) {
			DEBUG(10, ("%s: %d bytes left, expected at least %d\n",
				   __location__, (int)len, (int)needed));
			goto inval;
		}

		/*
		 * we allocate 2 iovec structures for words and bytes
		 */
		iov_tmp = talloc_realloc(mem_ctx, iov, struct iovec,
					 num_iov + 2);
		if (iov_tmp == NULL) {
			TALLOC_FREE(iov);
			return NT_STATUS_NO_MEMORY;
		}
		iov = iov_tmp;
		cur = &iov[num_iov];
		num_iov += 2;

		cur[0].iov_len = wct * sizeof(uint16_t);
		cur[0].iov_base = hdr + (wct_ofs + sizeof(uint8_t));
		cur[1].iov_len = bcc * sizeof(uint8_t);
		cur[1].iov_base = hdr + (bcc_ofs + sizeof(uint16_t));

		taken += needed;

		if (!smb1cli_is_andx_req(cmd)) {
			/*
			 * If the current command does not have AndX chanining
			 * we are done.
			 */
			break;
		}

		if (wct == 0 && bcc == 0) {
			/*
			 * An empty response also ends the chain,
			 * most likely with an error.
			 */
			break;
		}

		if (wct < 2) {
			DEBUG(10, ("%s: wct[%d] < 2 for cmd[0x%02X]\n",
				   __location__, (int)wct, (int)cmd));
			goto inval;
		}
		cmd = CVAL(cur[0].iov_base, 0);
		if (cmd == 0xFF) {
			/*
			 * If it is the end of the chain we are also done.
			 */
			break;
		}
		wct_ofs = SVAL(cur[0].iov_base, 2);

		if (wct_ofs < taken) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		if (wct_ofs > buflen) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}

		/*
		 * we consumed everything up to the start of the next
		 * parameter block.
		 */
		taken = wct_ofs;
	}

	remaining = buflen - taken;

	if (remaining > 0 && num_iov >= 3) {
		/*
		 * The last DATA block gets the remaining
		 * bytes, this is needed to support
		 * CAP_LARGE_WRITEX and CAP_LARGE_READX.
		 */
		iov[num_iov-1].iov_len += remaining;
	}

	*piov = iov;
	*pnum_iov = num_iov;
	return NT_STATUS_OK;

inval:
	TALLOC_FREE(iov);
	return NT_STATUS_INVALID_NETWORK_RESPONSE;
}

static NTSTATUS smb1cli_conn_dispatch_incoming(struct smbXcli_conn *conn,
					       TALLOC_CTX *tmp_mem,
					       uint8_t *inbuf)
{
	struct tevent_req *req;
	struct smbXcli_req_state *state;
	NTSTATUS status;
	size_t num_pending;
	size_t i;
	uint8_t cmd;
	uint16_t mid;
	bool oplock_break;
	const uint8_t *inhdr = inbuf + NBT_HDR_SIZE;
	struct iovec *iov = NULL;
	int num_iov = 0;

	if ((IVAL(inhdr, 0) != SMB_MAGIC) /* 0xFF"SMB" */
	    && (SVAL(inhdr, 0) != 0x45ff)) /* 0xFF"E" */ {
		DEBUG(10, ("Got non-SMB PDU\n"));
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	/*
	 * If we supported multiple encrytion contexts
	 * here we'd look up based on tid.
	 */
	if (common_encryption_on(conn->smb1.trans_enc)
	    && (CVAL(inbuf, 0) == 0)) {
		uint16_t enc_ctx_num;

		status = get_enc_ctx_num(inbuf, &enc_ctx_num);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("get_enc_ctx_num returned %s\n",
				   nt_errstr(status)));
			return status;
		}

		if (enc_ctx_num != conn->smb1.trans_enc->enc_ctx_num) {
			DEBUG(10, ("wrong enc_ctx %d, expected %d\n",
				   enc_ctx_num,
				   conn->smb1.trans_enc->enc_ctx_num));
			return NT_STATUS_INVALID_HANDLE;
		}

		status = common_decrypt_buffer(conn->smb1.trans_enc,
					       (char *)inbuf);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("common_decrypt_buffer returned %s\n",
				   nt_errstr(status)));
			return status;
		}
	}

	mid = SVAL(inhdr, HDR_MID);
	num_pending = talloc_array_length(conn->pending);

	for (i=0; i<num_pending; i++) {
		if (mid == smb1cli_req_mid(conn->pending[i])) {
			break;
		}
	}
	if (i == num_pending) {
		/* Dump unexpected reply */
		return NT_STATUS_RETRY;
	}

	oplock_break = false;

	if (mid == 0xffff) {
		/*
		 * Paranoia checks that this is really an oplock break request.
		 */
		oplock_break = (smb_len_nbt(inbuf) == 51); /* hdr + 8 words */
		oplock_break &= ((CVAL(inhdr, HDR_FLG) & FLAG_REPLY) == 0);
		oplock_break &= (CVAL(inhdr, HDR_COM) == SMBlockingX);
		oplock_break &= (SVAL(inhdr, HDR_VWV+VWV(6)) == 0);
		oplock_break &= (SVAL(inhdr, HDR_VWV+VWV(7)) == 0);

		if (!oplock_break) {
			/* Dump unexpected reply */
			return NT_STATUS_RETRY;
		}
	}

	req = conn->pending[i];
	state = tevent_req_data(req, struct smbXcli_req_state);

	if (!oplock_break /* oplock breaks are not signed */
	    && !smb_signing_check_pdu(conn->smb1.signing,
				      inbuf, state->smb1.seqnum+1)) {
		DEBUG(10, ("cli_check_sign_mac failed\n"));
		return NT_STATUS_ACCESS_DENIED;
	}

	status = smb1cli_inbuf_parse_chain(inbuf, tmp_mem,
					   &iov, &num_iov);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("smb1cli_inbuf_parse_chain - %s\n",
			  nt_errstr(status)));
		return status;
	}

	cmd = CVAL(inhdr, HDR_COM);
	status = smb1cli_pull_raw_error(inhdr);

	if (state->smb1.chained_requests != NULL) {
		struct tevent_req **chain = talloc_move(tmp_mem,
					    &state->smb1.chained_requests);
		size_t num_chained = talloc_array_length(chain);
		size_t num_responses = (num_iov - 1)/2;

		if (num_responses > num_chained) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}

		for (i=0; i<num_chained; i++) {
			size_t iov_idx = 1 + (i*2);
			struct iovec *cur = &iov[iov_idx];
			uint8_t *inbuf_ref;

			req = chain[i];
			state = tevent_req_data(req, struct smbXcli_req_state);

			smbXcli_req_unset_pending(req);

			/*
			 * as we finish multiple requests here
			 * we need to defer the callbacks as
			 * they could destroy our current stack state.
			 */
			tevent_req_defer_callback(req, state->ev);

			if (i >= num_responses) {
				tevent_req_nterror(req, NT_STATUS_REQUEST_ABORTED);
				continue;
			}

			state->smb1.recv_cmd = cmd;

			if (i == (num_responses - 1)) {
				/*
				 * The last request in the chain gets the status
				 */
				state->smb1.recv_status = status;
			} else {
				cmd = CVAL(cur[0].iov_base, 0);
				state->smb1.recv_status = NT_STATUS_OK;
			}

			state->inbuf = inbuf;
			state->smb1.chain_num = i;
			state->smb1.chain_length = num_chained;

			/*
			 * Note: here we use talloc_reference() in a way
			 *       that does not expose it to the caller.
			 */
			inbuf_ref = talloc_reference(state->smb1.recv_iov, inbuf);
			if (tevent_req_nomem(inbuf_ref, req)) {
				continue;
			}

			/* copy the related buffers */
			state->smb1.recv_iov[0] = iov[0];
			state->smb1.recv_iov[1] = cur[0];
			state->smb1.recv_iov[2] = cur[1];

			tevent_req_done(req);
		}
		return NT_STATUS_RETRY;
	}

	if (num_iov != 3) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	smbXcli_req_unset_pending(req);

	state->smb1.recv_cmd = cmd;
	state->smb1.recv_status = status;
	state->inbuf = talloc_move(state->smb1.recv_iov, &inbuf);
	state->smb1.chain_num = 0;
	state->smb1.chain_length = 1;

	state->smb1.recv_iov[0] = iov[0];
	state->smb1.recv_iov[1] = iov[1];
	state->smb1.recv_iov[2] = iov[2];

	if (talloc_array_length(conn->pending) == 0) {
		tevent_req_done(req);
		return NT_STATUS_OK;
	}

	tevent_req_defer_callback(req, state->ev);
	tevent_req_done(req);
	return NT_STATUS_RETRY;
}

NTSTATUS smb1cli_req_recv(struct tevent_req *req,
			  TALLOC_CTX *mem_ctx, uint8_t **pinbuf,
			  uint8_t min_wct, uint8_t *pwct, uint16_t **pvwv,
			  uint32_t *pnum_bytes, uint8_t **pbytes)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	NTSTATUS status = NT_STATUS_OK;
	uint8_t cmd, wct;
	uint16_t num_bytes;
	size_t wct_ofs, bytes_offset;
	int i;

	if (tevent_req_is_nterror(req, &status)) {
		return status;
	}

	if (state->inbuf == NULL) {
		if (min_wct != 0) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		if (pinbuf) {
			*pinbuf = NULL;
		}
		if (pwct) {
			*pwct = 0;
		}
		if (pvwv) {
			*pvwv = NULL;
		}
		if (pnum_bytes) {
			*pnum_bytes = 0;
		}
		if (pbytes) {
			*pbytes = NULL;
		}
		/* This was a request without a reply */
		return NT_STATUS_OK;
	}

	wct_ofs = NBT_HDR_SIZE + HDR_WCT;
	cmd = CVAL(state->inbuf, NBT_HDR_SIZE + HDR_COM);

	for (i=0; i<state->smb1.chain_num; i++) {
		if (i < state->smb1.chain_num-1) {
			if (cmd == 0xff) {
				return NT_STATUS_REQUEST_ABORTED;
			}
			if (!smb1cli_is_andx_req(cmd)) {
				return NT_STATUS_INVALID_NETWORK_RESPONSE;
			}
		}

		if (!smb1cli_have_andx_command(state->inbuf, wct_ofs, cmd)) {
			/*
			 * This request was not completed because a previous
			 * request in the chain had received an error.
			 */
			return NT_STATUS_REQUEST_ABORTED;
		}

		cmd = CVAL(state->inbuf, wct_ofs + 1);
		wct_ofs = SVAL(state->inbuf, wct_ofs + 3);

		/*
		 * Skip the all-present length field. No overflow, we've just
		 * put a 16-bit value into a size_t.
		 */
		wct_ofs += 4;

		if (wct_ofs+2 > talloc_get_size(state->inbuf)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
	}

	status = smb1cli_pull_raw_error(state->inbuf+NBT_HDR_SIZE);

	if (!smb1cli_have_andx_command(state->inbuf, wct_ofs, cmd)) {

		if ((cmd == SMBsesssetupX)
		    && NT_STATUS_EQUAL(
			    status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			/*
			 * NT_STATUS_MORE_PROCESSING_REQUIRED is a
			 * valid return code for session setup
			 */
			goto no_err;
		}

		if (NT_STATUS_IS_ERR(status)) {
			/*
			 * The last command takes the error code. All
			 * further commands down the requested chain
			 * will get a NT_STATUS_REQUEST_ABORTED.
			 */
			return status;
		}
	} else {
		/*
		 * Only the last request in the chain get the returned
		 * status.
		 */
		status = NT_STATUS_OK;
	}

no_err:

	wct = CVAL(state->inbuf, wct_ofs);
	bytes_offset = wct_ofs + 1 + wct * sizeof(uint16_t);
	num_bytes = SVAL(state->inbuf, bytes_offset);

	if (wct < min_wct) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	/*
	 * wct_ofs is a 16-bit value plus 4, wct is a 8-bit value, num_bytes
	 * is a 16-bit value. So bytes_offset being size_t should be far from
	 * wrapping.
	 */
	if ((bytes_offset + 2 > talloc_get_size(state->inbuf))
	    || (bytes_offset > 0xffff)) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (pwct != NULL) {
		*pwct = wct;
	}
	if (pvwv != NULL) {
		*pvwv = (uint16_t *)(state->inbuf + wct_ofs + 1);
	}
	if (pnum_bytes != NULL) {
		*pnum_bytes = num_bytes;
	}
	if (pbytes != NULL) {
		*pbytes = (uint8_t *)state->inbuf + bytes_offset + 2;
	}
	if ((mem_ctx != NULL) && (pinbuf != NULL)) {
		if (state->smb1.chain_num == state->smb1.chain_length-1) {
			*pinbuf = talloc_move(mem_ctx, &state->inbuf);
		} else {
			*pinbuf = state->inbuf;
		}
	}

	return status;
}

size_t smb1cli_req_wct_ofs(struct tevent_req **reqs, int num_reqs)
{
	size_t wct_ofs;
	int i;

	wct_ofs = HDR_WCT;

	for (i=0; i<num_reqs; i++) {
		struct smbXcli_req_state *state;
		state = tevent_req_data(reqs[i], struct smbXcli_req_state);
		wct_ofs += smbXcli_iov_len(state->smb1.iov+2,
					   state->smb1.iov_count-2);
		wct_ofs = (wct_ofs + 3) & ~3;
	}
	return wct_ofs;
}

NTSTATUS smb1cli_req_chain_submit(struct tevent_req **reqs, int num_reqs)
{
	struct smbXcli_req_state *first_state =
		tevent_req_data(reqs[0],
		struct smbXcli_req_state);
	struct smbXcli_req_state *last_state =
		tevent_req_data(reqs[num_reqs-1],
		struct smbXcli_req_state);
	struct smbXcli_req_state *state;
	size_t wct_offset;
	size_t chain_padding = 0;
	int i, iovlen;
	struct iovec *iov = NULL;
	struct iovec *this_iov;
	NTSTATUS status;
	size_t nbt_len;

	if (num_reqs == 1) {
		return smb1cli_req_writev_submit(reqs[0], first_state,
						 first_state->smb1.iov,
						 first_state->smb1.iov_count);
	}

	iovlen = 0;
	for (i=0; i<num_reqs; i++) {
		if (!tevent_req_is_in_progress(reqs[i])) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		state = tevent_req_data(reqs[i], struct smbXcli_req_state);

		if (state->smb1.iov_count < 4) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}

		if (i == 0) {
			/*
			 * The NBT and SMB header
			 */
			iovlen += 2;
		} else {
			/*
			 * Chain padding
			 */
			iovlen += 1;
		}

		/*
		 * words and bytes
		 */
		iovlen += state->smb1.iov_count - 2;
	}

	iov = talloc_zero_array(last_state, struct iovec, iovlen);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	first_state->smb1.chained_requests = (struct tevent_req **)talloc_memdup(
		last_state, reqs, sizeof(*reqs) * num_reqs);
	if (first_state->smb1.chained_requests == NULL) {
		TALLOC_FREE(iov);
		return NT_STATUS_NO_MEMORY;
	}

	wct_offset = HDR_WCT;
	this_iov = iov;

	for (i=0; i<num_reqs; i++) {
		size_t next_padding = 0;
		uint16_t *vwv;

		state = tevent_req_data(reqs[i], struct smbXcli_req_state);

		if (i < num_reqs-1) {
			if (!smb1cli_is_andx_req(CVAL(state->smb1.hdr, HDR_COM))
			    || CVAL(state->smb1.hdr, HDR_WCT) < 2) {
				TALLOC_FREE(iov);
				TALLOC_FREE(first_state->smb1.chained_requests);
				return NT_STATUS_INVALID_PARAMETER_MIX;
			}
		}

		wct_offset += smbXcli_iov_len(state->smb1.iov+2,
					      state->smb1.iov_count-2) + 1;
		if ((wct_offset % 4) != 0) {
			next_padding = 4 - (wct_offset % 4);
		}
		wct_offset += next_padding;
		vwv = state->smb1.vwv;

		if (i < num_reqs-1) {
			struct smbXcli_req_state *next_state =
				tevent_req_data(reqs[i+1],
				struct smbXcli_req_state);
			SCVAL(vwv+0, 0, CVAL(next_state->smb1.hdr, HDR_COM));
			SCVAL(vwv+0, 1, 0);
			SSVAL(vwv+1, 0, wct_offset);
		} else if (smb1cli_is_andx_req(CVAL(state->smb1.hdr, HDR_COM))) {
			/* properly end the chain */
			SCVAL(vwv+0, 0, 0xff);
			SCVAL(vwv+0, 1, 0xff);
			SSVAL(vwv+1, 0, 0);
		}

		if (i == 0) {
			/*
			 * The NBT and SMB header
			 */
			this_iov[0] = state->smb1.iov[0];
			this_iov[1] = state->smb1.iov[1];
			this_iov += 2;
		} else {
			/*
			 * This one is a bit subtle. We have to add
			 * chain_padding bytes between the requests, and we
			 * have to also include the wct field of the
			 * subsequent requests. We use the subsequent header
			 * for the padding, it contains the wct field in its
			 * last byte.
			 */
			this_iov[0].iov_len = chain_padding+1;
			this_iov[0].iov_base = (void *)&state->smb1.hdr[
				sizeof(state->smb1.hdr) - this_iov[0].iov_len];
			memset(this_iov[0].iov_base, 0, this_iov[0].iov_len-1);
			this_iov += 1;
		}

		/*
		 * copy the words and bytes
		 */
		memcpy(this_iov, state->smb1.iov+2,
		       sizeof(struct iovec) * (state->smb1.iov_count-2));
		this_iov += state->smb1.iov_count - 2;
		chain_padding = next_padding;
	}

	nbt_len = smbXcli_iov_len(&iov[1], iovlen-1);
	if (nbt_len > first_state->conn->smb1.max_xmit) {
		TALLOC_FREE(iov);
		TALLOC_FREE(first_state->smb1.chained_requests);
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	status = smb1cli_req_writev_submit(reqs[0], last_state, iov, iovlen);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(iov);
		TALLOC_FREE(first_state->smb1.chained_requests);
		return status;
	}

	for (i=0; i < (num_reqs - 1); i++) {
		state = tevent_req_data(reqs[i], struct smbXcli_req_state);

		state->smb1.seqnum = last_state->smb1.seqnum;
	}

	return NT_STATUS_OK;
}

bool smbXcli_conn_has_async_calls(struct smbXcli_conn *conn)
{
	return ((tevent_queue_length(conn->outgoing) != 0)
		|| (talloc_array_length(conn->pending) != 0));
}

struct tevent_req *smb2cli_req_create(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint16_t cmd,
				      uint32_t additional_flags,
				      uint32_t clear_flags,
				      uint32_t timeout_msec,
				      uint32_t pid,
				      uint32_t tid,
				      uint64_t uid,
				      const uint8_t *fixed,
				      uint16_t fixed_len,
				      const uint8_t *dyn,
				      uint32_t dyn_len)
{
	struct tevent_req *req;
	struct smbXcli_req_state *state;
	uint32_t flags = 0;

	req = tevent_req_create(mem_ctx, &state,
				struct smbXcli_req_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->conn = conn;

	state->smb2.recv_iov = talloc_zero_array(state, struct iovec, 3);
	if (state->smb2.recv_iov == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}

	flags |= additional_flags;
	flags &= ~clear_flags;

	state->smb2.fixed = fixed;
	state->smb2.fixed_len = fixed_len;
	state->smb2.dyn = dyn;
	state->smb2.dyn_len = dyn_len;

	SIVAL(state->smb2.hdr, SMB2_HDR_PROTOCOL_ID,	SMB2_MAGIC);
	SSVAL(state->smb2.hdr, SMB2_HDR_LENGTH,		SMB2_HDR_BODY);
	SSVAL(state->smb2.hdr, SMB2_HDR_CREDIT_CHARGE,	1);
	SIVAL(state->smb2.hdr, SMB2_HDR_STATUS,		NT_STATUS_V(NT_STATUS_OK));
	SSVAL(state->smb2.hdr, SMB2_HDR_OPCODE,		cmd);
	SSVAL(state->smb2.hdr, SMB2_HDR_CREDIT,		31);
	SIVAL(state->smb2.hdr, SMB2_HDR_FLAGS,		flags);
	SIVAL(state->smb2.hdr, SMB2_HDR_PID,		pid);
	SIVAL(state->smb2.hdr, SMB2_HDR_TID,		tid);
	SBVAL(state->smb2.hdr, SMB2_HDR_SESSION_ID,	uid);

	switch (cmd) {
	case SMB2_OP_CANCEL:
		state->one_way = true;
		break;
	case SMB2_OP_BREAK:
		/*
		 * If this is a dummy request, it will have
		 * UINT64_MAX as message id.
		 * If we send on break acknowledgement,
		 * this gets overwritten later.
		 */
		SBVAL(state->smb2.hdr, SMB2_HDR_MESSAGE_ID, UINT64_MAX);
		break;
	}

	if (timeout_msec > 0) {
		struct timeval endtime;

		endtime = timeval_current_ofs_msec(timeout_msec);
		if (!tevent_req_set_endtime(req, ev, endtime)) {
			return req;
		}
	}

	return req;
}

static void smb2cli_writev_done(struct tevent_req *subreq);
static NTSTATUS smb2cli_conn_dispatch_incoming(struct smbXcli_conn *conn,
					       TALLOC_CTX *tmp_mem,
					       uint8_t *inbuf);

NTSTATUS smb2cli_req_compound_submit(struct tevent_req **reqs,
				     int num_reqs)
{
	struct smbXcli_req_state *state;
	struct tevent_req *subreq;
	struct iovec *iov;
	int i, num_iov, nbt_len;

	/*
	 * 1 for the nbt length
	 * per request: HDR, fixed, dyn, padding
	 * -1 because the last one does not need padding
	 */

	iov = talloc_array(reqs[0], struct iovec, 1 + 4*num_reqs - 1);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	num_iov = 1;
	nbt_len = 0;

	for (i=0; i<num_reqs; i++) {
		size_t reqlen;
		bool ret;
		uint64_t mid;

		if (!tevent_req_is_in_progress(reqs[i])) {
			return NT_STATUS_INTERNAL_ERROR;
		}

		state = tevent_req_data(reqs[i], struct smbXcli_req_state);

		if (!smbXcli_conn_is_connected(state->conn)) {
			return NT_STATUS_CONNECTION_DISCONNECTED;
		}

		if ((state->conn->protocol != PROTOCOL_NONE) &&
		    (state->conn->protocol < PROTOCOL_SMB2_02)) {
			return NT_STATUS_REVISION_MISMATCH;
		}

		if (state->conn->smb2.mid == UINT64_MAX) {
			return NT_STATUS_CONNECTION_ABORTED;
		}

		mid = state->conn->smb2.mid;
		state->conn->smb2.mid += 1;

		SBVAL(state->smb2.hdr, SMB2_HDR_MESSAGE_ID, mid);

		iov[num_iov].iov_base = state->smb2.hdr;
		iov[num_iov].iov_len  = sizeof(state->smb2.hdr);
		num_iov += 1;

		iov[num_iov].iov_base = discard_const(state->smb2.fixed);
		iov[num_iov].iov_len  = state->smb2.fixed_len;
		num_iov += 1;

		if (state->smb2.dyn != NULL) {
			iov[num_iov].iov_base = discard_const(state->smb2.dyn);
			iov[num_iov].iov_len  = state->smb2.dyn_len;
			num_iov += 1;
		}

		reqlen  = sizeof(state->smb2.hdr);
		reqlen += state->smb2.fixed_len;
		reqlen += state->smb2.dyn_len;

		if (i < num_reqs-1) {
			if ((reqlen % 8) > 0) {
				uint8_t pad = 8 - (reqlen % 8);
				iov[num_iov].iov_base = state->smb2.pad;
				iov[num_iov].iov_len = pad;
				num_iov += 1;
				reqlen += pad;
			}
			SIVAL(state->smb2.hdr, SMB2_HDR_NEXT_COMMAND, reqlen);
		}
		nbt_len += reqlen;

		ret = smbXcli_req_set_pending(reqs[i]);
		if (!ret) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/*
	 * TODO: Do signing here
	 */

	state = tevent_req_data(reqs[0], struct smbXcli_req_state);
	_smb_setlen_tcp(state->length_hdr, nbt_len);
	iov[0].iov_base = state->length_hdr;
	iov[0].iov_len  = sizeof(state->length_hdr);

	if (state->conn->dispatch_incoming == NULL) {
		state->conn->dispatch_incoming = smb2cli_conn_dispatch_incoming;
	}

	subreq = writev_send(state, state->ev, state->conn->outgoing,
			     state->conn->fd, false, iov, num_iov);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smb2cli_writev_done, reqs[0]);
	return NT_STATUS_OK;
}

struct tevent_req *smb2cli_req_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct smbXcli_conn *conn,
				    uint16_t cmd,
				    uint32_t additional_flags,
				    uint32_t clear_flags,
				    uint32_t timeout_msec,
				    uint32_t pid,
				    uint32_t tid,
				    uint64_t uid,
				    const uint8_t *fixed,
				    uint16_t fixed_len,
				    const uint8_t *dyn,
				    uint32_t dyn_len)
{
	struct tevent_req *req;
	NTSTATUS status;

	req = smb2cli_req_create(mem_ctx, ev, conn, cmd,
				 additional_flags, clear_flags,
				 timeout_msec,
				 pid, tid, uid,
				 fixed, fixed_len, dyn, dyn_len);
	if (req == NULL) {
		return NULL;
	}
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}
	status = smb2cli_req_compound_submit(&req, 1);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void smb2cli_writev_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	ssize_t nwritten;
	int err;

	nwritten = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		/* here, we need to notify all pending requests */
		NTSTATUS status = map_nt_error_from_unix_common(err);
		smbXcli_conn_disconnect(state->conn, status);
		return;
	}
}

static NTSTATUS smb2cli_inbuf_parse_compound(uint8_t *buf, TALLOC_CTX *mem_ctx,
					     struct iovec **piov, int *pnum_iov)
{
	struct iovec *iov;
	int num_iov;
	size_t buflen;
	size_t taken;
	uint8_t *first_hdr;

	num_iov = 0;

	iov = talloc_array(mem_ctx, struct iovec, num_iov);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	buflen = smb_len_tcp(buf);
	taken = 0;
	first_hdr = buf + NBT_HDR_SIZE;

	while (taken < buflen) {
		size_t len = buflen - taken;
		uint8_t *hdr = first_hdr + taken;
		struct iovec *cur;
		size_t full_size;
		size_t next_command_ofs;
		uint16_t body_size;
		struct iovec *iov_tmp;

		/*
		 * We need the header plus the body length field
		 */

		if (len < SMB2_HDR_BODY + 2) {
			DEBUG(10, ("%d bytes left, expected at least %d\n",
				   (int)len, SMB2_HDR_BODY));
			goto inval;
		}
		if (IVAL(hdr, 0) != SMB2_MAGIC) {
			DEBUG(10, ("Got non-SMB2 PDU: %x\n",
				   IVAL(hdr, 0)));
			goto inval;
		}
		if (SVAL(hdr, 4) != SMB2_HDR_BODY) {
			DEBUG(10, ("Got HDR len %d, expected %d\n",
				   SVAL(hdr, 4), SMB2_HDR_BODY));
			goto inval;
		}

		full_size = len;
		next_command_ofs = IVAL(hdr, SMB2_HDR_NEXT_COMMAND);
		body_size = SVAL(hdr, SMB2_HDR_BODY);

		if (next_command_ofs != 0) {
			if (next_command_ofs < (SMB2_HDR_BODY + 2)) {
				goto inval;
			}
			if (next_command_ofs > full_size) {
				goto inval;
			}
			full_size = next_command_ofs;
		}
		if (body_size < 2) {
			goto inval;
		}
		body_size &= 0xfffe;

		if (body_size > (full_size - SMB2_HDR_BODY)) {
			goto inval;
		}

		iov_tmp = talloc_realloc(mem_ctx, iov, struct iovec,
					 num_iov + 3);
		if (iov_tmp == NULL) {
			TALLOC_FREE(iov);
			return NT_STATUS_NO_MEMORY;
		}
		iov = iov_tmp;
		cur = &iov[num_iov];
		num_iov += 3;

		cur[0].iov_base = hdr;
		cur[0].iov_len  = SMB2_HDR_BODY;
		cur[1].iov_base = hdr + SMB2_HDR_BODY;
		cur[1].iov_len  = body_size;
		cur[2].iov_base = hdr + SMB2_HDR_BODY + body_size;
		cur[2].iov_len  = full_size - (SMB2_HDR_BODY + body_size);

		taken += full_size;
	}

	*piov = iov;
	*pnum_iov = num_iov;
	return NT_STATUS_OK;

inval:
	TALLOC_FREE(iov);
	return NT_STATUS_INVALID_NETWORK_RESPONSE;
}

static struct tevent_req *smb2cli_conn_find_pending(struct smbXcli_conn *conn,
						    uint64_t mid)
{
	size_t num_pending = talloc_array_length(conn->pending);
	size_t i;

	for (i=0; i<num_pending; i++) {
		struct tevent_req *req = conn->pending[i];
		struct smbXcli_req_state *state =
			tevent_req_data(req,
			struct smbXcli_req_state);

		if (mid == BVAL(state->smb2.hdr, SMB2_HDR_MESSAGE_ID)) {
			return req;
		}
	}
	return NULL;
}

static NTSTATUS smb2cli_conn_dispatch_incoming(struct smbXcli_conn *conn,
					       TALLOC_CTX *tmp_mem,
					       uint8_t *inbuf)
{
	struct tevent_req *req;
	struct smbXcli_req_state *state = NULL;
	struct iovec *iov;
	int i, num_iov;
	NTSTATUS status;
	bool defer = true;

	status = smb2cli_inbuf_parse_compound(inbuf, tmp_mem,
					      &iov, &num_iov);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i=0; i<num_iov; i+=3) {
		uint8_t *inbuf_ref = NULL;
		struct iovec *cur = &iov[i];
		uint8_t *inhdr = (uint8_t *)cur[0].iov_base;
		uint16_t opcode = SVAL(inhdr, SMB2_HDR_OPCODE);
		uint32_t flags = IVAL(inhdr, SMB2_HDR_FLAGS);
		uint64_t mid = BVAL(inhdr, SMB2_HDR_MESSAGE_ID);
		uint16_t req_opcode;

		req = smb2cli_conn_find_pending(conn, mid);
		if (req == NULL) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		state = tevent_req_data(req, struct smbXcli_req_state);

		req_opcode = SVAL(state->smb2.hdr, SMB2_HDR_OPCODE);
		if (opcode != req_opcode) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}

		if (!(flags & SMB2_HDR_FLAG_REDIRECT)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}

		status = NT_STATUS(IVAL(inhdr, SMB2_HDR_STATUS));
		if ((flags & SMB2_HDR_FLAG_ASYNC) &&
		    NT_STATUS_EQUAL(status, STATUS_PENDING)) {
			uint32_t req_flags = IVAL(state->smb2.hdr, SMB2_HDR_FLAGS);
			uint64_t async_id = BVAL(inhdr, SMB2_HDR_ASYNC_ID);

			req_flags |= SMB2_HDR_FLAG_ASYNC;
			SBVAL(state->smb2.hdr, SMB2_HDR_FLAGS, req_flags);
			SBVAL(state->smb2.hdr, SMB2_HDR_ASYNC_ID, async_id);
			continue;
		}

		smbXcli_req_unset_pending(req);

		/*
		 * There might be more than one response
		 * we need to defer the notifications
		 */
		if ((num_iov == 4) && (talloc_array_length(conn->pending) == 0)) {
			defer = false;
		}

		if (defer) {
			tevent_req_defer_callback(req, state->ev);
		}

		/*
		 * Note: here we use talloc_reference() in a way
		 *       that does not expose it to the caller.
		 */
		inbuf_ref = talloc_reference(state->smb2.recv_iov, inbuf);
		if (tevent_req_nomem(inbuf_ref, req)) {
			continue;
		}

		/* copy the related buffers */
		state->smb2.recv_iov[0] = cur[0];
		state->smb2.recv_iov[1] = cur[1];
		state->smb2.recv_iov[2] = cur[2];

		tevent_req_done(req);
	}

	if (defer) {
		return NT_STATUS_RETRY;
	}

	return NT_STATUS_OK;
}

NTSTATUS smb2cli_req_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			  struct iovec **piov,
			  const struct smb2cli_req_expected_response *expected,
			  size_t num_expected)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	NTSTATUS status;
	size_t body_size;
	bool found_status = false;
	bool found_size = false;
	size_t i;

	if (piov != NULL) {
		*piov = NULL;
	}

	if (tevent_req_is_nterror(req, &status)) {
		for (i=0; i < num_expected; i++) {
			if (NT_STATUS_EQUAL(status, expected[i].status)) {
				found_status = true;
				break;
			}
		}

		if (found_status) {
			return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		}

		return status;
	}

	if (num_expected == 0) {
		found_status = true;
		found_size = true;
	}

	status = NT_STATUS(IVAL(state->smb2.recv_iov[0].iov_base, SMB2_HDR_STATUS));
	body_size = SVAL(state->smb2.recv_iov[1].iov_base, 0);

	for (i=0; i < num_expected; i++) {
		if (!NT_STATUS_EQUAL(status, expected[i].status)) {
			continue;
		}

		found_status = true;
		if (expected[i].body_size == 0) {
			found_size = true;
			break;
		}

		if (expected[i].body_size == body_size) {
			found_size = true;
			break;
		}
	}

	if (!found_status) {
		return status;
	}

	if (!found_size) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (piov != NULL) {
		*piov = talloc_move(mem_ctx, &state->smb2.recv_iov);
	}

	return status;
}
