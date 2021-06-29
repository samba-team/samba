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
#include "lib/util/dlinklist.h"
#include "lib/util/iov_buf.h"
#include "../libcli/smb/smb_common.h"
#include "../libcli/smb/smb_seal.h"
#include "../libcli/smb/smb_signing.h"
#include "../libcli/smb/read_smb.h"
#include "smbXcli_base.h"
#include "librpc/ndr/libndr.h"
#include "libcli/smb/smb2_negotiate_context.h"
#include "libcli/smb/smb2_signing.h"

#include "lib/crypto/gnutls_helpers.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

struct smbXcli_conn;
struct smbXcli_req;
struct smbXcli_session;
struct smbXcli_tcon;

struct smbXcli_conn {
	int sock_fd;
	struct sockaddr_storage local_ss;
	struct sockaddr_storage remote_ss;
	const char *remote_name;

	struct tevent_queue *outgoing;
	struct tevent_req **pending;
	struct tevent_req *read_smb_req;
	struct tevent_req *suicide_req;

	enum protocol_types min_protocol;
	enum protocol_types max_protocol;
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
			const char *name;
			int time_zone;
			NTTIME system_time;
		} server;

		uint32_t capabilities;
		uint32_t max_xmit;

		uint16_t mid;

		struct smb_signing_state *signing;
		struct smb_trans_enc_state *trans_enc;

		struct tevent_req *read_braw_req;
	} smb1;

	struct {
		struct {
			uint32_t capabilities;
			uint16_t security_mode;
			struct GUID guid;
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
			uint16_t cipher;
		} server;

		uint64_t mid;
		uint16_t cur_credits;
		uint16_t max_credits;

		uint32_t cc_chunk_len;
		uint32_t cc_max_chunks;

		uint8_t io_priority;

		bool force_channel_sequence;

		uint8_t preauth_sha512[64];
	} smb2;

	struct smbXcli_session *sessions;
};

struct smb2cli_session {
	uint64_t session_id;
	uint16_t session_flags;
	DATA_BLOB application_key;
	struct smb2_signing_key *signing_key;
	bool should_sign;
	bool should_encrypt;
	struct smb2_signing_key *encryption_key;
	struct smb2_signing_key *decryption_key;
	uint64_t nonce_high_random;
	uint64_t nonce_high_max;
	uint64_t nonce_high;
	uint64_t nonce_low;
	uint16_t channel_sequence;
	bool replay_active;
	bool require_signed_response;
};

struct smbXcli_session {
	struct smbXcli_session *prev, *next;
	struct smbXcli_conn *conn;

	struct {
		uint16_t session_id;
		uint16_t action;
		DATA_BLOB application_key;
		bool protected_key;
	} smb1;

	struct smb2cli_session *smb2;

	struct {
		struct smb2_signing_key *signing_key;
		uint8_t preauth_sha512[64];
	} smb2_channel;

	/*
	 * this should be a short term hack
	 * until the upper layers have implemented
	 * re-authentication.
	 */
	bool disconnect_expired;
};

struct smbXcli_tcon {
	bool is_smb1;
	uint32_t fs_attributes;

	struct {
		uint16_t tcon_id;
		uint16_t optional_support;
		uint32_t maximal_access;
		uint32_t guest_maximal_access;
		char *service;
		char *fs_type;
	} smb1;

	struct {
		uint32_t tcon_id;
		uint8_t type;
		uint32_t flags;
		uint32_t capabilities;
		uint32_t maximal_access;
		bool should_sign;
		bool should_encrypt;
	} smb2;
};

struct smbXcli_req_state {
	struct tevent_context *ev;
	struct smbXcli_conn *conn;
	struct smbXcli_session *session; /* maybe NULL */
	struct smbXcli_tcon *tcon; /* maybe NULL */

	uint8_t length_hdr[4];

	bool one_way;

	uint8_t *inbuf;

	struct tevent_req *write_req;

	struct timeval endtime;

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

#define MAX_SMB_IOV 10
		/* length_hdr, hdr, words, byte_count, buffers */
		struct iovec iov[1 + 3 + MAX_SMB_IOV];
		int iov_count;

		bool one_way_seqnum;
		uint32_t seqnum;
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

		uint8_t transform[SMB2_TF_HDR_SIZE];
		uint8_t hdr[SMB2_HDR_BODY];
		uint8_t pad[7];	/* padding space for compounding */

		/*
		 * always an array of 3 talloc elements
		 * (without a SMB2_TRANSFORM header!)
		 *
		 * HDR, BODY, DYN
		 */
		struct iovec *recv_iov;

		/*
		 * the expected max for the response dyn_len
		 */
		uint32_t max_dyn_len;

		uint16_t credit_charge;

		bool should_sign;
		bool should_encrypt;
		uint64_t encryption_session_id;

		bool signing_skipped;
		bool require_signed_response;
		bool notify_async;
		bool got_async;
		uint16_t cancel_flags;
		uint64_t cancel_mid;
		uint64_t cancel_aid;
	} smb2;
};

static int smbXcli_conn_destructor(struct smbXcli_conn *conn)
{
	/*
	 * NT_STATUS_OK, means we do not notify the callers
	 */
	smbXcli_conn_disconnect(conn, NT_STATUS_OK);

	while (conn->sessions) {
		conn->sessions->conn = NULL;
		DLIST_REMOVE(conn->sessions, conn->sessions);
	}

	if (conn->smb1.trans_enc) {
		TALLOC_FREE(conn->smb1.trans_enc);
	}

	return 0;
}

struct smbXcli_conn *smbXcli_conn_create(TALLOC_CTX *mem_ctx,
					 int fd,
					 const char *remote_name,
					 enum smb_signing_setting signing_state,
					 uint32_t smb1_capabilities,
					 struct GUID *client_guid,
					 uint32_t smb2_capabilities)
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

	set_blocking(fd, false);
	conn->sock_fd = fd;

	conn->remote_name = talloc_strdup(conn, remote_name);
	if (conn->remote_name == NULL) {
		goto error;
	}

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

	conn->min_protocol = PROTOCOL_NONE;
	conn->max_protocol = PROTOCOL_NONE;
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
	case SMB_SIGNING_DESIRED:
		/* if the server desires it */
		conn->allow_signing = true;
		conn->desire_signing = true;
		conn->mandatory_signing = false;
		break;
	case SMB_SIGNING_IPC_DEFAULT:
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
	if (client_guid) {
		conn->smb2.client.guid = *client_guid;
	}
	conn->smb2.client.capabilities = smb2_capabilities;

	conn->smb2.cur_credits = 1;
	conn->smb2.max_credits = 0;
	conn->smb2.io_priority = 1;

	/*
	 * Samba and Windows servers accept a maximum of 16 MiB with a maximum
	 * chunk length of 1 MiB.
	 */
	conn->smb2.cc_chunk_len = 1024 * 1024;
	conn->smb2.cc_max_chunks = 16;

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

	if (conn->sock_fd == -1) {
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

bool smbXcli_conn_signing_mandatory(struct smbXcli_conn *conn)
{
	return conn->mandatory_signing;
}

/*
 * [MS-SMB] 2.2.2.3.5 - SMB1 support for passing through
 * query/set commands to the file system
 */
bool smbXcli_conn_support_passthrough(struct smbXcli_conn *conn)
{
	if (conn->protocol >= PROTOCOL_SMB2_02) {
		return true;
	}

	if (conn->smb1.capabilities & CAP_W2K_SMBS) {
		return true;
	}

	return false;
}

void smbXcli_conn_set_sockopt(struct smbXcli_conn *conn, const char *options)
{
	set_socket_options(conn->sock_fd, options);
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

uint16_t smbXcli_conn_max_requests(struct smbXcli_conn *conn)
{
	if (conn->protocol >= PROTOCOL_SMB2_02) {
		/*
		 * TODO...
		 */
		return 1;
	}

	return conn->smb1.server.max_mux;
}

NTTIME smbXcli_conn_server_system_time(struct smbXcli_conn *conn)
{
	if (conn->protocol >= PROTOCOL_SMB2_02) {
		return conn->smb2.server.system_time;
	}

	return conn->smb1.server.system_time;
}

const DATA_BLOB *smbXcli_conn_server_gss_blob(struct smbXcli_conn *conn)
{
	if (conn->protocol >= PROTOCOL_SMB2_02) {
		return &conn->smb2.server.gss_blob;
	}

	return &conn->smb1.server.gss_blob;
}

const struct GUID *smbXcli_conn_server_guid(struct smbXcli_conn *conn)
{
	if (conn->protocol >= PROTOCOL_SMB2_02) {
		return &conn->smb2.server.guid;
	}

	return &conn->smb1.server.guid;
}

bool smbXcli_conn_get_force_channel_sequence(struct smbXcli_conn *conn)
{
	return conn->smb2.force_channel_sequence;
}

void smbXcli_conn_set_force_channel_sequence(struct smbXcli_conn *conn,
					     bool v)
{
	conn->smb2.force_channel_sequence = v;
}

struct smbXcli_conn_samba_suicide_state {
	struct smbXcli_conn *conn;
	struct iovec iov;
	uint8_t buf[9];
	struct tevent_req *write_req;
};

static void smbXcli_conn_samba_suicide_cleanup(struct tevent_req *req,
					       enum tevent_req_state req_state);
static void smbXcli_conn_samba_suicide_done(struct tevent_req *subreq);

struct tevent_req *smbXcli_conn_samba_suicide_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct smbXcli_conn *conn,
						   uint8_t exitcode)
{
	struct tevent_req *req, *subreq;
	struct smbXcli_conn_samba_suicide_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smbXcli_conn_samba_suicide_state);
	if (req == NULL) {
		return NULL;
	}
	state->conn = conn;
	SIVAL(state->buf, 4, SMB_SUICIDE_PACKET);
	SCVAL(state->buf, 8, exitcode);
	_smb_setlen_nbt(state->buf, sizeof(state->buf)-4);

	if (conn->suicide_req != NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	state->iov.iov_base = state->buf;
	state->iov.iov_len = sizeof(state->buf);

	subreq = writev_send(state, ev, conn->outgoing, conn->sock_fd,
			     false, &state->iov, 1);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbXcli_conn_samba_suicide_done, req);
	state->write_req = subreq;

	tevent_req_set_cleanup_fn(req, smbXcli_conn_samba_suicide_cleanup);

	/*
	 * We need to use tevent_req_defer_callback()
	 * in order to allow smbXcli_conn_disconnect()
	 * to do a safe cleanup.
	 */
	tevent_req_defer_callback(req, ev);
	conn->suicide_req = req;

	return req;
}

static void smbXcli_conn_samba_suicide_cleanup(struct tevent_req *req,
					       enum tevent_req_state req_state)
{
	struct smbXcli_conn_samba_suicide_state *state = tevent_req_data(
		req, struct smbXcli_conn_samba_suicide_state);

	TALLOC_FREE(state->write_req);

	if (state->conn == NULL) {
		return;
	}

	if (state->conn->suicide_req == req) {
		state->conn->suicide_req = NULL;
	}
	state->conn = NULL;
}

static void smbXcli_conn_samba_suicide_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smbXcli_conn_samba_suicide_state *state = tevent_req_data(
		req, struct smbXcli_conn_samba_suicide_state);
	ssize_t nwritten;
	int err;

	state->write_req = NULL;

	nwritten = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		/* here, we need to notify all pending requests */
		NTSTATUS status = map_nt_error_from_unix_common(err);
		smbXcli_conn_disconnect(state->conn, status);
		return;
	}
	tevent_req_done(req);
}

NTSTATUS smbXcli_conn_samba_suicide_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smbXcli_conn_samba_suicide(struct smbXcli_conn *conn,
				    uint8_t exitcode)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	bool ok;

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER_MIX;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smbXcli_conn_samba_suicide_send(frame, ev, conn, exitcode);
	if (req == NULL) {
		goto fail;
	}
	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		goto fail;
	}
	status = smbXcli_conn_samba_suicide_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

uint32_t smb1cli_conn_capabilities(struct smbXcli_conn *conn)
{
	return conn->smb1.capabilities;
}

uint32_t smb1cli_conn_max_xmit(struct smbXcli_conn *conn)
{
	return conn->smb1.max_xmit;
}

bool smb1cli_conn_req_possible(struct smbXcli_conn *conn)
{
	size_t pending = talloc_array_length(conn->pending);
	uint16_t possible = conn->smb1.server.max_mux;

	if (pending >= possible) {
		return false;
	}

	return true;
}

uint32_t smb1cli_conn_server_session_key(struct smbXcli_conn *conn)
{
	return conn->smb1.server.session_key;
}

const uint8_t *smb1cli_conn_server_challenge(struct smbXcli_conn *conn)
{
	return conn->smb1.server.challenge;
}

uint16_t smb1cli_conn_server_security_mode(struct smbXcli_conn *conn)
{
	return conn->smb1.server.security_mode;
}

bool smb1cli_conn_server_readbraw(struct smbXcli_conn *conn)
{
	return conn->smb1.server.readbraw;
}

bool smb1cli_conn_server_writebraw(struct smbXcli_conn *conn)
{
	return conn->smb1.server.writebraw;
}

bool smb1cli_conn_server_lockread(struct smbXcli_conn *conn)
{
	return conn->smb1.server.lockread;
}

bool smb1cli_conn_server_writeunlock(struct smbXcli_conn *conn)
{
	return conn->smb1.server.writeunlock;
}

int smb1cli_conn_server_time_zone(struct smbXcli_conn *conn)
{
	return conn->smb1.server.time_zone;
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
	const uint8_t *hdr = buf + NBT_HDR_SIZE;
	size_t len = smb_len_nbt(buf);

	return smb_signing_check_pdu(conn->smb1.signing, hdr, len, seqnum);
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
		TALLOC_FREE(conn->smb1.trans_enc);
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

	if (conn->protocol == PROTOCOL_NONE) {
		/*
		 * This is what windows sends on the SMB1 Negprot request
		 * and some vendors reuse the SMB1 MID as SMB2 sequence number.
		 */
		return 0;
	}

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

static NTSTATUS smbXcli_req_cancel_write_req(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	struct smbXcli_conn *conn = state->conn;
	size_t num_pending = talloc_array_length(conn->pending);
	ssize_t ret;
	int err;
	bool ok;

	if (state->write_req == NULL) {
		return NT_STATUS_OK;
	}

	/*
	 * Check if it's possible to cancel the request.
	 * If the result is true it's not too late.
	 * See writev_cancel().
	 */
	ok = tevent_req_cancel(state->write_req);
	if (ok) {
		TALLOC_FREE(state->write_req);

		if (conn->protocol >= PROTOCOL_SMB2_02) {
			/*
			 * SMB2 has a sane signing state.
			 */
			return NT_STATUS_OK;
		}

		if (num_pending > 1) {
			/*
			 * We have more pending requests following us.  This
			 * means the signing state will be broken for them.
			 *
			 * As a solution we could add the requests directly to
			 * our outgoing queue and do the signing in the trigger
			 * function and then use writev_send() without passing a
			 * queue.  That way we'll only sign packets we're most
			 * likely send to the wire.
			 */
			return NT_STATUS_REQUEST_OUT_OF_SEQUENCE;
		}

		/*
		 * If we're the only request that's
		 * pending, we're able to recover the signing
		 * state.
		 */
		smb_signing_cancel_reply(conn->smb1.signing,
					 state->smb1.one_way_seqnum);
		return NT_STATUS_OK;
	}

	ret = writev_recv(state->write_req, &err);
	TALLOC_FREE(state->write_req);
	if (ret == -1) {
		return map_nt_error_from_unix_common(err);
	}

	return NT_STATUS_OK;
}

void smbXcli_req_unset_pending(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	struct smbXcli_conn *conn = state->conn;
	size_t num_pending = talloc_array_length(conn->pending);
	size_t i;
	NTSTATUS cancel_status;

	cancel_status = smbXcli_req_cancel_write_req(req);

	if (state->smb1.mid != 0) {
		/*
		 * This is a [nt]trans[2] request which waits
		 * for more than one reply.
		 */
		if (!NT_STATUS_IS_OK(cancel_status)) {
			/*
			 * If the write_req cancel didn't work
			 * we can't use the connection anymore.
			 */
			smbXcli_conn_disconnect(conn, cancel_status);
			return;
		}
		return;
	}

	tevent_req_set_cleanup_fn(req, NULL);

	if (num_pending == 1) {
		/*
		 * The pending read_smb tevent_req is a child of
		 * conn->pending. So if nothing is pending anymore, we need to
		 * delete the socket read fde.
		 */
		/* TODO: smbXcli_conn_cancel_read_req */
		TALLOC_FREE(conn->pending);
		conn->read_smb_req = NULL;

		if (!NT_STATUS_IS_OK(cancel_status)) {
			/*
			 * If the write_req cancel didn't work
			 * we can't use the connection anymore.
			 */
			smbXcli_conn_disconnect(conn, cancel_status);
			return;
		}
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

		if (!NT_STATUS_IS_OK(cancel_status)) {
			/*
			 * If the write_req cancel didn't work
			 * we can't use the connection anymore.
			 */
			smbXcli_conn_disconnect(conn, cancel_status);
			return;
		}
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

	if (!NT_STATUS_IS_OK(cancel_status)) {
		/*
		 * If the write_req cancel didn't work
		 * we can't use the connection anymore.
		 */
		smbXcli_conn_disconnect(conn, cancel_status);
		return;
	}
	return;
}

static void smbXcli_req_cleanup(struct tevent_req *req,
				enum tevent_req_state req_state)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	struct smbXcli_conn *conn = state->conn;
	NTSTATUS cancel_status;

	switch (req_state) {
	case TEVENT_REQ_RECEIVED:
		/*
		 * Make sure we really remove it from
		 * the pending array on destruction.
		 *
		 * smbXcli_req_unset_pending() calls
		 * smbXcli_req_cancel_write_req() internal
		 */
		state->smb1.mid = 0;
		smbXcli_req_unset_pending(req);
		return;
	default:
		cancel_status = smbXcli_req_cancel_write_req(req);
		if (!NT_STATUS_IS_OK(cancel_status)) {
			/*
			 * If the write_req cancel didn't work
			 * we can't use the connection anymore.
			 */
			smbXcli_conn_disconnect(conn, cancel_status);
			return;
		}
		return;
	}
}

static bool smb1cli_req_cancel(struct tevent_req *req);
static bool smb2cli_req_cancel(struct tevent_req *req);

static bool smbXcli_req_cancel(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);

	if (!smbXcli_conn_is_connected(state->conn)) {
		return false;
	}

	if (state->conn->protocol == PROTOCOL_NONE) {
		return false;
	}

	if (state->conn->protocol >= PROTOCOL_SMB2_02) {
		return smb2cli_req_cancel(req);
	}

	return smb1cli_req_cancel(req);
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
	tevent_req_set_cleanup_fn(req, smbXcli_req_cleanup);
	tevent_req_set_cancel_fn(req, smbXcli_req_cancel);

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
	conn->read_smb_req = read_smb_send(conn->pending,
					   state->ev,
					   conn->sock_fd);
	if (conn->read_smb_req == NULL) {
		return false;
	}
	tevent_req_set_callback(conn->read_smb_req, smbXcli_conn_received, conn);
	return true;
}

void smbXcli_conn_disconnect(struct smbXcli_conn *conn, NTSTATUS status)
{
	struct smbXcli_session *session;
	int sock_fd = conn->sock_fd;

	tevent_queue_stop(conn->outgoing);

	conn->sock_fd = -1;

	session = conn->sessions;
	if (talloc_array_length(conn->pending) == 0) {
		/*
		 * if we do not have pending requests
		 * there is no need to update the channel_sequence
		 */
		session = NULL;
	}
	for (; session; session = session->next) {
		smb2cli_session_increment_channel_sequence(session);
	}

	if (conn->suicide_req != NULL) {
		/*
		 * smbXcli_conn_samba_suicide_send()
		 * used tevent_req_defer_callback() already.
		 */
		if (!NT_STATUS_IS_OK(status)) {
			tevent_req_nterror(conn->suicide_req, status);
		}
		conn->suicide_req = NULL;
	}

	/*
	 * Cancel all pending requests. We do not do a for-loop walking
	 * conn->pending because that array changes in
	 * smbXcli_req_unset_pending.
	 */
	while (conn->pending != NULL &&
	       talloc_array_length(conn->pending) > 0) {
		struct tevent_req *req;
		struct smbXcli_req_state *state;
		struct tevent_req **chain;
		size_t num_chained;
		size_t i;

		req = conn->pending[0];
		state = tevent_req_data(req, struct smbXcli_req_state);

		if (state->smb1.chained_requests == NULL) {
			bool in_progress;

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

			in_progress = tevent_req_is_in_progress(req);
			if (!in_progress) {
				/*
				 * already finished
				 */
				continue;
			}

			/*
			 * we need to defer the callback, because we may notify
			 * more then one caller.
			 */
			tevent_req_defer_callback(req, state->ev);
			tevent_req_nterror(req, status);
			continue;
		}

		chain = talloc_move(conn, &state->smb1.chained_requests);
		num_chained = talloc_array_length(chain);

		for (i=0; i<num_chained; i++) {
			bool in_progress;

			req = chain[i];
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

			in_progress = tevent_req_is_in_progress(req);
			if (!in_progress) {
				/*
				 * already finished
				 */
				continue;
			}

			/*
			 * we need to defer the callback, because we may notify
			 * more than one caller.
			 */
			tevent_req_defer_callback(req, state->ev);
			tevent_req_nterror(req, status);
		}
		TALLOC_FREE(chain);
	}

	if (sock_fd != -1) {
		close(sock_fd);
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
	ssize_t ret = iov_buflen(iov, count);

	/* Ignore the overflow case for now ... */
	return ret;
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

static void smb1cli_req_cancel_done(struct tevent_req *subreq);

static bool smb1cli_req_cancel(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	uint8_t flags;
	uint16_t flags2;
	uint32_t pid;
	uint16_t mid;
	struct tevent_req *subreq;
	NTSTATUS status;

	flags = CVAL(state->smb1.hdr, HDR_FLG);
	flags2 = SVAL(state->smb1.hdr, HDR_FLG2);
	pid  = SVAL(state->smb1.hdr, HDR_PID);
	pid |= SVAL(state->smb1.hdr, HDR_PIDHIGH)<<16;
	mid = SVAL(state->smb1.hdr, HDR_MID);

	subreq = smb1cli_req_create(state, state->ev,
				    state->conn,
				    SMBntcancel,
				    flags, 0,
				    flags2, 0,
				    0, /* timeout */
				    pid,
				    state->tcon,
				    state->session,
				    0, NULL, /* vwv */
				    0, NULL); /* bytes */
	if (subreq == NULL) {
		return false;
	}
	smb1cli_req_set_mid(subreq, mid);

	status = smb1cli_req_chain_submit(&subreq, 1);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(subreq);
		return false;
	}
	smb1cli_req_set_mid(subreq, 0);

	tevent_req_set_callback(subreq, smb1cli_req_cancel_done, NULL);

	return true;
}

static void smb1cli_req_cancel_done(struct tevent_req *subreq)
{
	/* we do not care about the result */
	TALLOC_FREE(subreq);
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
				      struct smbXcli_tcon *tcon,
				      struct smbXcli_session *session,
				      uint8_t wct, uint16_t *vwv,
				      int iov_count,
				      struct iovec *bytes_iov)
{
	struct tevent_req *req;
	struct smbXcli_req_state *state;
	uint8_t flags = 0;
	uint16_t flags2 = 0;
	uint16_t uid = 0;
	uint16_t tid = 0;
	ssize_t num_bytes;

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
	state->session = session;
	state->tcon = tcon;

	if (session) {
		uid = session->smb1.session_id;
	}

	if (tcon) {
		tid = tcon->smb1.tcon_id;

		if (tcon->fs_attributes & FILE_CASE_SENSITIVE_SEARCH) {
			clear_flags |= FLAG_CASELESS_PATHNAMES;
		} else {
			/* Default setting, case insensitive. */
			additional_flags |= FLAG_CASELESS_PATHNAMES;
		}

		if (smbXcli_conn_dfs_supported(conn) &&
		    smbXcli_tcon_is_dfs_share(tcon))
		{
			additional_flags2 |= FLAGS2_DFS_PATHNAMES;
		}
	}

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
	SCVAL(state->smb1.hdr, HDR_WCT,     wct);

	state->smb1.vwv = vwv;

	num_bytes = iov_buflen(bytes_iov, iov_count);
	if (num_bytes == -1) {
		/*
		 * I'd love to add a check for num_bytes<=UINT16_MAX here, but
		 * the smbclient->samba connections can lie and transfer more.
		 */
		TALLOC_FREE(req);
		return NULL;
	}

	SSVAL(state->smb1.bytecount_buf, 0, num_bytes);

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
		state->endtime = timeval_current_ofs_msec(timeout_msec);
		if (!tevent_req_set_endtime(req, ev, state->endtime)) {
			return req;
		}
	}

	switch (smb_command) {
	case SMBtranss:
	case SMBtranss2:
	case SMBnttranss:
		state->one_way = true;
		break;
	case SMBntcancel:
		state->one_way = true;
		state->smb1.one_way_seqnum = true;
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
				   uint32_t *seqnum,
				   bool one_way_seqnum)
{
	TALLOC_CTX *frame = NULL;
	NTSTATUS status;
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

	frame = talloc_stackframe();

	buf = iov_concat(frame, &iov[1], iov_count - 1);
	if (buf == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*seqnum = smb_signing_next_seqnum(conn->smb1.signing,
					  one_way_seqnum);
	status = smb_signing_sign_pdu(conn->smb1.signing,
				      buf,
				      talloc_get_size(buf),
				      *seqnum);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	memcpy(iov[1].iov_base, buf, iov[1].iov_len);

	TALLOC_FREE(frame);
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
	uint8_t cmd;
	uint16_t mid;
	ssize_t nbtlen;

	if (!smbXcli_conn_is_connected(state->conn)) {
		return NT_STATUS_CONNECTION_DISCONNECTED;
	}

	if (state->conn->protocol > PROTOCOL_NT1) {
		DBG_ERR("called for dialect[%s] server[%s]\n",
			smb_protocol_types_string(state->conn->protocol),
			smbXcli_conn_remote_name(state->conn));
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

	cmd = CVAL(iov[1].iov_base, HDR_COM);
	if (cmd == SMBreadBraw) {
		if (smbXcli_conn_has_async_calls(state->conn)) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}
		state->conn->smb1.read_braw_req = req;
	}

	if (state->smb1.mid != 0) {
		mid = state->smb1.mid;
	} else {
		mid = smb1cli_alloc_mid(state->conn);
	}
	SSVAL(iov[1].iov_base, HDR_MID, mid);

	nbtlen = iov_buflen(&iov[1], iov_count-1);
	if ((nbtlen == -1) || (nbtlen > 0x1FFFF)) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	_smb_setlen_nbt(iov[0].iov_base, nbtlen);

	status = smb1cli_conn_signv(state->conn, iov, iov_count,
				    &state->smb1.seqnum,
				    state->smb1.one_way_seqnum);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/*
	 * If we supported multiple encrytion contexts
	 * here we'd look up based on tid.
	 */
	if (common_encryption_on(state->conn->smb1.trans_enc)) {
		char *buf, *enc_buf;

		buf = (char *)iov_concat(talloc_tos(), iov, iov_count);
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

	if (!smbXcli_req_set_pending(req)) {
		return NT_STATUS_NO_MEMORY;
	}

	tevent_req_set_cancel_fn(req, smbXcli_req_cancel);

	subreq = writev_send(state, state->ev, state->conn->outgoing,
			     state->conn->sock_fd, false, iov, iov_count);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smb1cli_req_writev_done, req);
	state->write_req = subreq;

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
				    struct smbXcli_tcon *tcon,
				    struct smbXcli_session *session,
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
				 pid, tcon, session,
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

	state->write_req = NULL;

	nwritten = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		/* here, we need to notify all pending requests */
		NTSTATUS status = map_nt_error_from_unix_common(err);
		smbXcli_conn_disconnect(state->conn, status);
		return;
	}

	if (state->one_way) {
		state->inbuf = NULL;
		tevent_req_done(req);
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
		smbXcli_conn_disconnect(conn, NT_STATUS_INTERNAL_ERROR);
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
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_RETRY)) {
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
	size_t num_iov;
	size_t buflen;
	size_t taken;
	size_t remaining;
	uint8_t *hdr;
	uint8_t cmd;
	uint32_t wct_ofs;
	NTSTATUS status;
	size_t min_size = MIN_SMB_SIZE;

	buflen = smb_len_tcp(buf);
	taken = 0;

	hdr = buf + NBT_HDR_SIZE;

	status = smb1cli_pull_raw_error(hdr);
	if (NT_STATUS_IS_ERR(status)) {
		/*
		 * This is an ugly hack to support OS/2
		 * which skips the byte_count in the DATA block
		 * on some error responses.
		 *
		 * See bug #9096
		 */
		min_size -= sizeof(uint16_t);
	}

	if (buflen < min_size) {
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
		 * we need at least WCT
		 */
		needed = sizeof(uint8_t);
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

		if ((num_iov == 1) &&
		    (len == needed) &&
		    NT_STATUS_IS_ERR(status))
		{
			/*
			 * This is an ugly hack to support OS/2
			 * which skips the byte_count in the DATA block
			 * on some error responses.
			 *
			 * See bug #9096
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

			cur[0].iov_len = 0;
			cur[0].iov_base = hdr + (wct_ofs + sizeof(uint8_t));
			cur[1].iov_len = 0;
			cur[1].iov_base = cur[0].iov_base;

			taken += needed;
			break;
		}

		/*
		 * we need at least BCC
		 */
		needed += sizeof(uint16_t);
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
			goto inval;
		}
		if (wct_ofs > buflen) {
			goto inval;
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
	uint8_t *inhdr = inbuf + NBT_HDR_SIZE;
	size_t len = smb_len_tcp(inbuf);
	struct iovec *iov = NULL;
	int num_iov = 0;
	struct tevent_req **chain = NULL;
	size_t num_chained = 0;
	size_t num_responses = 0;

	if (conn->smb1.read_braw_req != NULL) {
		req = conn->smb1.read_braw_req;
		conn->smb1.read_braw_req = NULL;
		state = tevent_req_data(req, struct smbXcli_req_state);

		smbXcli_req_unset_pending(req);

		if (state->smb1.recv_iov == NULL) {
			/*
			 * For requests with more than
			 * one response, we have to readd the
			 * recv_iov array.
			 */
			state->smb1.recv_iov = talloc_zero_array(state,
								 struct iovec,
								 3);
			if (tevent_req_nomem(state->smb1.recv_iov, req)) {
				return NT_STATUS_OK;
			}
		}

		state->smb1.recv_iov[0].iov_base = (void *)(inhdr);
		state->smb1.recv_iov[0].iov_len = len;
		ZERO_STRUCT(state->smb1.recv_iov[1]);
		ZERO_STRUCT(state->smb1.recv_iov[2]);

		state->smb1.recv_cmd = SMBreadBraw;
		state->smb1.recv_status = NT_STATUS_OK;
		state->inbuf = talloc_move(state->smb1.recv_iov, &inbuf);

		tevent_req_done(req);
		return NT_STATUS_OK;
	}

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
		inhdr = inbuf + NBT_HDR_SIZE;
		len = smb_len_nbt(inbuf);
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
		oplock_break = (len == 51); /* hdr + 8 words */
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
				      inhdr, len, state->smb1.seqnum+1)) {
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

	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED) &&
	    (state->session != NULL) && state->session->disconnect_expired)
	{
		/*
		 * this should be a short term hack
		 * until the upper layers have implemented
		 * re-authentication.
		 */
		return status;
	}

	if (state->smb1.chained_requests == NULL) {
		if (num_iov != 3) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}

		smbXcli_req_unset_pending(req);

		if (state->smb1.recv_iov == NULL) {
			/*
			 * For requests with more than
			 * one response, we have to readd the
			 * recv_iov array.
			 */
			state->smb1.recv_iov = talloc_zero_array(state,
								 struct iovec,
								 3);
			if (tevent_req_nomem(state->smb1.recv_iov, req)) {
				return NT_STATUS_OK;
			}
		}

		state->smb1.recv_cmd = cmd;
		state->smb1.recv_status = status;
		state->inbuf = talloc_move(state->smb1.recv_iov, &inbuf);

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

	chain = talloc_move(tmp_mem, &state->smb1.chained_requests);
	num_chained = talloc_array_length(chain);
	num_responses = (num_iov - 1)/2;

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

		if (state->smb1.recv_iov == NULL) {
			/*
			 * For requests with more than
			 * one response, we have to readd the
			 * recv_iov array.
			 */
			state->smb1.recv_iov = talloc_zero_array(state,
								 struct iovec,
								 3);
			if (tevent_req_nomem(state->smb1.recv_iov, req)) {
				continue;
			}
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

NTSTATUS smb1cli_req_recv(struct tevent_req *req,
			  TALLOC_CTX *mem_ctx,
			  struct iovec **piov,
			  uint8_t **phdr,
			  uint8_t *pwct,
			  uint16_t **pvwv,
			  uint32_t *pvwv_offset,
			  uint32_t *pnum_bytes,
			  uint8_t **pbytes,
			  uint32_t *pbytes_offset,
			  uint8_t **pinbuf,
			  const struct smb1cli_req_expected_response *expected,
			  size_t num_expected)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	NTSTATUS status = NT_STATUS_OK;
	struct iovec *recv_iov = NULL;
	uint8_t *hdr = NULL;
	uint8_t wct = 0;
	uint32_t vwv_offset = 0;
	uint16_t *vwv = NULL;
	uint32_t num_bytes = 0;
	uint32_t bytes_offset = 0;
	uint8_t *bytes = NULL;
	size_t i;
	bool found_status = false;
	bool found_size = false;

	if (piov != NULL) {
		*piov = NULL;
	}
	if (phdr != NULL) {
		*phdr = 0;
	}
	if (pwct != NULL) {
		*pwct = 0;
	}
	if (pvwv != NULL) {
		*pvwv = NULL;
	}
	if (pvwv_offset != NULL) {
		*pvwv_offset = 0;
	}
	if (pnum_bytes != NULL) {
		*pnum_bytes = 0;
	}
	if (pbytes != NULL) {
		*pbytes = NULL;
	}
	if (pbytes_offset != NULL) {
		*pbytes_offset = 0;
	}
	if (pinbuf != NULL) {
		*pinbuf = NULL;
	}

	if (state->inbuf != NULL) {
		recv_iov = state->smb1.recv_iov;
		state->smb1.recv_iov = NULL;
		if (state->smb1.recv_cmd != SMBreadBraw) {
			hdr = (uint8_t *)recv_iov[0].iov_base;
			wct = recv_iov[1].iov_len/2;
			vwv = (uint16_t *)recv_iov[1].iov_base;
			vwv_offset = PTR_DIFF(vwv, hdr);
			num_bytes = recv_iov[2].iov_len;
			bytes = (uint8_t *)recv_iov[2].iov_base;
			bytes_offset = PTR_DIFF(bytes, hdr);
		}
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

	status = state->smb1.recv_status;

	for (i=0; i < num_expected; i++) {
		if (!NT_STATUS_EQUAL(status, expected[i].status)) {
			continue;
		}

		found_status = true;
		if (expected[i].wct == 0) {
			found_size = true;
			break;
		}

		if (expected[i].wct == wct) {
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
		*piov = talloc_move(mem_ctx, &recv_iov);
	}

	if (phdr != NULL) {
		*phdr = hdr;
	}
	if (pwct != NULL) {
		*pwct = wct;
	}
	if (pvwv != NULL) {
		*pvwv = vwv;
	}
	if (pvwv_offset != NULL) {
		*pvwv_offset = vwv_offset;
	}
	if (pnum_bytes != NULL) {
		*pnum_bytes = num_bytes;
	}
	if (pbytes != NULL) {
		*pbytes = bytes;
	}
	if (pbytes_offset != NULL) {
		*pbytes_offset = bytes_offset;
	}
	if (pinbuf != NULL) {
		*pinbuf = state->inbuf;
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
	struct smbXcli_req_state *state;
	size_t wct_offset;
	size_t chain_padding = 0;
	int i, iovlen;
	struct iovec *iov = NULL;
	struct iovec *this_iov;
	NTSTATUS status;
	ssize_t nbt_len;

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

	iov = talloc_zero_array(first_state, struct iovec, iovlen);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	first_state->smb1.chained_requests = (struct tevent_req **)talloc_memdup(
		first_state, reqs, sizeof(*reqs) * num_reqs);
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

	nbt_len = iov_buflen(&iov[1], iovlen-1);
	if ((nbt_len == -1) || (nbt_len > first_state->conn->smb1.max_xmit)) {
		TALLOC_FREE(iov);
		TALLOC_FREE(first_state->smb1.chained_requests);
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	status = smb1cli_req_writev_submit(reqs[0], first_state, iov, iovlen);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(iov);
		TALLOC_FREE(first_state->smb1.chained_requests);
		return status;
	}

	return NT_STATUS_OK;
}

bool smbXcli_conn_has_async_calls(struct smbXcli_conn *conn)
{
	return ((tevent_queue_length(conn->outgoing) != 0)
		|| (talloc_array_length(conn->pending) != 0));
}

bool smbXcli_conn_dfs_supported(struct smbXcli_conn *conn)
{
	if (conn->protocol >= PROTOCOL_SMB2_02) {
		return (smb2cli_conn_server_capabilities(conn) & SMB2_CAP_DFS);
	}

	return (smb1cli_conn_capabilities(conn) & CAP_DFS);
}

bool smb2cli_conn_req_possible(struct smbXcli_conn *conn, uint32_t *max_dyn_len)
{
	uint16_t credits = 1;

	if (conn->smb2.cur_credits == 0) {
		if (max_dyn_len != NULL) {
			*max_dyn_len = 0;
		}
		return false;
	}

	if (conn->smb2.server.capabilities & SMB2_CAP_LARGE_MTU) {
		credits = conn->smb2.cur_credits;
	}

	if (max_dyn_len != NULL) {
		*max_dyn_len = credits * 65536;
	}

	return true;
}

uint32_t smb2cli_conn_server_capabilities(struct smbXcli_conn *conn)
{
	return conn->smb2.server.capabilities;
}

uint16_t smb2cli_conn_server_security_mode(struct smbXcli_conn *conn)
{
	return conn->smb2.server.security_mode;
}

uint32_t smb2cli_conn_max_trans_size(struct smbXcli_conn *conn)
{
	return conn->smb2.server.max_trans_size;
}

uint32_t smb2cli_conn_max_read_size(struct smbXcli_conn *conn)
{
	return conn->smb2.server.max_read_size;
}

uint32_t smb2cli_conn_max_write_size(struct smbXcli_conn *conn)
{
	return conn->smb2.server.max_write_size;
}

void smb2cli_conn_set_max_credits(struct smbXcli_conn *conn,
				  uint16_t max_credits)
{
	conn->smb2.max_credits = max_credits;
}

uint16_t smb2cli_conn_get_cur_credits(struct smbXcli_conn *conn)
{
	return conn->smb2.cur_credits;
}

uint8_t smb2cli_conn_get_io_priority(struct smbXcli_conn *conn)
{
	if (conn->protocol < PROTOCOL_SMB3_11) {
		return 0;
	}

	return conn->smb2.io_priority;
}

void smb2cli_conn_set_io_priority(struct smbXcli_conn *conn,
				  uint8_t io_priority)
{
	conn->smb2.io_priority = io_priority;
}

uint32_t smb2cli_conn_cc_chunk_len(struct smbXcli_conn *conn)
{
	return conn->smb2.cc_chunk_len;
}

void smb2cli_conn_set_cc_chunk_len(struct smbXcli_conn *conn,
				    uint32_t chunk_len)
{
	conn->smb2.cc_chunk_len = chunk_len;
}

uint32_t smb2cli_conn_cc_max_chunks(struct smbXcli_conn *conn)
{
	return conn->smb2.cc_max_chunks;
}

void smb2cli_conn_set_cc_max_chunks(struct smbXcli_conn *conn,
				    uint32_t max_chunks)
{
	conn->smb2.cc_max_chunks = max_chunks;
}

static void smb2cli_req_cancel_done(struct tevent_req *subreq);

static bool smb2cli_req_cancel(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	struct smbXcli_tcon *tcon = state->tcon;
	struct smbXcli_session *session = state->session;
	uint8_t *fixed = state->smb2.pad;
	uint16_t fixed_len = 4;
	struct tevent_req *subreq;
	struct smbXcli_req_state *substate;
	NTSTATUS status;

	SSVAL(fixed, 0, 0x04);
	SSVAL(fixed, 2, 0);

	subreq = smb2cli_req_create(state, state->ev,
				    state->conn,
				    SMB2_OP_CANCEL,
				    0, 0, /* flags */
				    0, /* timeout */
				    tcon, session,
				    fixed, fixed_len,
				    NULL, 0, 0);
	if (subreq == NULL) {
		return false;
	}
	substate = tevent_req_data(subreq, struct smbXcli_req_state);

	SIVAL(substate->smb2.hdr, SMB2_HDR_FLAGS, state->smb2.cancel_flags);
	SBVAL(substate->smb2.hdr, SMB2_HDR_MESSAGE_ID, state->smb2.cancel_mid);
	SBVAL(substate->smb2.hdr, SMB2_HDR_ASYNC_ID, state->smb2.cancel_aid);

	status = smb2cli_req_compound_submit(&subreq, 1);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(subreq);
		return false;
	}

	tevent_req_set_callback(subreq, smb2cli_req_cancel_done, NULL);

	return true;
}

static void smb2cli_req_cancel_done(struct tevent_req *subreq)
{
	/* we do not care about the result */
	TALLOC_FREE(subreq);
}

struct timeval smbXcli_req_endtime(struct tevent_req *req)
{
	struct smbXcli_req_state *state = tevent_req_data(
		req, struct smbXcli_req_state);

	return state->endtime;
}

struct tevent_req *smb2cli_req_create(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct smbXcli_conn *conn,
				      uint16_t cmd,
				      uint32_t additional_flags,
				      uint32_t clear_flags,
				      uint32_t timeout_msec,
				      struct smbXcli_tcon *tcon,
				      struct smbXcli_session *session,
				      const uint8_t *fixed,
				      uint16_t fixed_len,
				      const uint8_t *dyn,
				      uint32_t dyn_len,
				      uint32_t max_dyn_len)
{
	struct tevent_req *req;
	struct smbXcli_req_state *state;
	uint32_t flags = 0;
	uint32_t tid = 0;
	uint64_t uid = 0;
	bool use_channel_sequence = conn->smb2.force_channel_sequence;
	uint16_t channel_sequence = 0;
	bool use_replay_flag = false;

	req = tevent_req_create(mem_ctx, &state,
				struct smbXcli_req_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->conn = conn;
	state->session = session;
	state->tcon = tcon;

	if (conn->smb2.server.capabilities & SMB2_CAP_PERSISTENT_HANDLES) {
		use_channel_sequence = true;
	} else if (conn->smb2.server.capabilities & SMB2_CAP_MULTI_CHANNEL) {
		use_channel_sequence = true;
	}

	if (smbXcli_conn_protocol(conn) >= PROTOCOL_SMB3_00) {
		use_replay_flag = true;
	}

	if (smbXcli_conn_protocol(conn) >= PROTOCOL_SMB3_11) {
		flags |= SMB2_PRIORITY_VALUE_TO_MASK(conn->smb2.io_priority);
	}

	if (session) {
		uid = session->smb2->session_id;

		if (use_channel_sequence) {
			channel_sequence = session->smb2->channel_sequence;
		}

		if (use_replay_flag && session->smb2->replay_active) {
			additional_flags |= SMB2_HDR_FLAG_REPLAY_OPERATION;
		}

		state->smb2.should_sign = session->smb2->should_sign;
		state->smb2.should_encrypt = session->smb2->should_encrypt;
		state->smb2.require_signed_response =
			session->smb2->require_signed_response;

		if (cmd == SMB2_OP_SESSSETUP &&
		    !smb2_signing_key_valid(session->smb2_channel.signing_key) &&
		    smb2_signing_key_valid(session->smb2->signing_key))
		{
			/*
			 * a session bind needs to be signed
			 */
			state->smb2.should_sign = true;
		}

		if (cmd == SMB2_OP_SESSSETUP &&
		    !smb2_signing_key_valid(session->smb2_channel.signing_key)) {
			state->smb2.should_encrypt = false;
		}

		if (additional_flags & SMB2_HDR_FLAG_SIGNED) {
			if (!smb2_signing_key_valid(session->smb2_channel.signing_key)) {
				tevent_req_nterror(req, NT_STATUS_NO_USER_SESSION_KEY);
				return req;
			}

			additional_flags &= ~SMB2_HDR_FLAG_SIGNED;
			state->smb2.should_sign = true;
		}
	}

	if (tcon) {
		tid = tcon->smb2.tcon_id;

		if (tcon->smb2.should_sign) {
			state->smb2.should_sign = true;
		}
		if (tcon->smb2.should_encrypt) {
			state->smb2.should_encrypt = true;
		}
	}

	if (state->smb2.should_encrypt) {
		state->smb2.should_sign = false;
	}

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
	state->smb2.max_dyn_len = max_dyn_len;

	if (state->smb2.should_encrypt) {
		SIVAL(state->smb2.transform, SMB2_TF_PROTOCOL_ID, SMB2_TF_MAGIC);
		SBVAL(state->smb2.transform, SMB2_TF_SESSION_ID, uid);
	}

	SIVAL(state->smb2.hdr, SMB2_HDR_PROTOCOL_ID,	SMB2_MAGIC);
	SSVAL(state->smb2.hdr, SMB2_HDR_LENGTH,		SMB2_HDR_BODY);
	SSVAL(state->smb2.hdr, SMB2_HDR_OPCODE,		cmd);
	SSVAL(state->smb2.hdr, SMB2_HDR_CHANNEL_SEQUENCE, channel_sequence);
	SIVAL(state->smb2.hdr, SMB2_HDR_FLAGS,		flags);
	SIVAL(state->smb2.hdr, SMB2_HDR_PID,		0); /* reserved */
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
		state->endtime = timeval_current_ofs_msec(timeout_msec);
		if (!tevent_req_set_endtime(req, ev, state->endtime)) {
			return req;
		}
	}

	return req;
}

void smb2cli_req_set_notify_async(struct tevent_req *req)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);

	state->smb2.notify_async = true;
}

static void smb2cli_req_writev_done(struct tevent_req *subreq);
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
	int tf_iov = -1;
	struct smb2_signing_key *encryption_key = NULL;
	uint64_t encryption_session_id = 0;
	uint64_t nonce_high = UINT64_MAX;
	uint64_t nonce_low = UINT64_MAX;

	/*
	 * 1 for the nbt length, optional TRANSFORM
	 * per request: HDR, fixed, dyn, padding
	 * -1 because the last one does not need padding
	 */

	iov = talloc_array(reqs[0], struct iovec, 1 + 1 + 4*num_reqs - 1);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	num_iov = 1;
	nbt_len = 0;

	/*
	 * the session of the first request that requires encryption
	 * specifies the encryption key.
	 */
	for (i=0; i<num_reqs; i++) {
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

		if (state->session == NULL) {
			continue;
		}

		if (!state->smb2.should_encrypt) {
			continue;
		}

		encryption_key = state->session->smb2->encryption_key;
		if (!smb2_signing_key_valid(encryption_key)) {
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}

		encryption_session_id = state->session->smb2->session_id;

		state->session->smb2->nonce_low += 1;
		if (state->session->smb2->nonce_low == 0) {
			state->session->smb2->nonce_high += 1;
			state->session->smb2->nonce_low += 1;
		}

		/*
		 * CCM and GCM algorithms must never have their
		 * nonce wrap, or the security of the whole
		 * communication and the keys is destroyed.
		 * We must drop the connection once we have
		 * transfered too much data.
		 *
		 * NOTE: We assume nonces greater than 8 bytes.
		 */
		if (state->session->smb2->nonce_high >=
		    state->session->smb2->nonce_high_max)
		{
			return NT_STATUS_ENCRYPTION_FAILED;
		}

		nonce_high = state->session->smb2->nonce_high_random;
		nonce_high += state->session->smb2->nonce_high;
		nonce_low = state->session->smb2->nonce_low;

		tf_iov = num_iov;
		iov[num_iov].iov_base = state->smb2.transform;
		iov[num_iov].iov_len  = sizeof(state->smb2.transform);
		num_iov += 1;

		SBVAL(state->smb2.transform, SMB2_TF_PROTOCOL_ID, SMB2_TF_MAGIC);
		SBVAL(state->smb2.transform, SMB2_TF_NONCE,
		      nonce_low);
		SBVAL(state->smb2.transform, SMB2_TF_NONCE+8,
		      nonce_high);
		SBVAL(state->smb2.transform, SMB2_TF_SESSION_ID,
		      encryption_session_id);

		nbt_len += SMB2_TF_HDR_SIZE;
		break;
	}

	for (i=0; i<num_reqs; i++) {
		int hdr_iov;
		size_t reqlen;
		bool ret;
		uint16_t opcode;
		uint64_t avail;
		uint16_t charge;
		uint16_t credits;
		uint64_t mid;
		struct smb2_signing_key *signing_key = NULL;

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

		opcode = SVAL(state->smb2.hdr, SMB2_HDR_OPCODE);
		if (opcode == SMB2_OP_CANCEL) {
			goto skip_credits;
		}

		avail = UINT64_MAX - state->conn->smb2.mid;
		if (avail < 1) {
			return NT_STATUS_CONNECTION_ABORTED;
		}

		if (state->conn->smb2.server.capabilities & SMB2_CAP_LARGE_MTU) {
			uint32_t max_dyn_len = 1;

			max_dyn_len = MAX(max_dyn_len, state->smb2.dyn_len);
			max_dyn_len = MAX(max_dyn_len, state->smb2.max_dyn_len);

			charge = (max_dyn_len - 1)/ 65536 + 1;
		} else {
			charge = 1;
		}

		charge = MAX(state->smb2.credit_charge, charge);

		avail = MIN(avail, state->conn->smb2.cur_credits);
		if (avail < charge) {
			DBG_ERR("Insufficient credits. "
				"%"PRIu64" available, %"PRIu16" needed\n",
				avail, charge);
			return NT_STATUS_INTERNAL_ERROR;
		}

		credits = 0;
		if (state->conn->smb2.max_credits > state->conn->smb2.cur_credits) {
			credits = state->conn->smb2.max_credits -
				  state->conn->smb2.cur_credits;
		}
		if (state->conn->smb2.max_credits >= state->conn->smb2.cur_credits) {
			credits += 1;
		}

		mid = state->conn->smb2.mid;
		state->conn->smb2.mid += charge;
		state->conn->smb2.cur_credits -= charge;

		if (state->conn->smb2.server.capabilities & SMB2_CAP_LARGE_MTU) {
			SSVAL(state->smb2.hdr, SMB2_HDR_CREDIT_CHARGE, charge);
		}
		SSVAL(state->smb2.hdr, SMB2_HDR_CREDIT, credits);
		SBVAL(state->smb2.hdr, SMB2_HDR_MESSAGE_ID, mid);

		state->smb2.cancel_flags = 0;
		state->smb2.cancel_mid = mid;
		state->smb2.cancel_aid = 0;

skip_credits:
		if (state->session && encryption_key == NULL) {
			/*
			 * We prefer the channel signing key if it is
			 * already there.
			 */
			if (state->smb2.should_sign) {
				signing_key = state->session->smb2_channel.signing_key;
			}

			/*
			 * If it is a channel binding, we already have the main
			 * signing key and try that one.
			 */
			if (signing_key != NULL &&
			    !smb2_signing_key_valid(signing_key)) {
				signing_key = state->session->smb2->signing_key;
			}

			/*
			 * If we do not have any session key yet, we skip the
			 * signing of SMB2_OP_SESSSETUP requests.
			 */
			if (signing_key != NULL &&
			    !smb2_signing_key_valid(signing_key)) {
				signing_key = NULL;
			}
		}

		hdr_iov = num_iov;
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

		state->smb2.encryption_session_id = encryption_session_id;

		if (signing_key != NULL) {
			NTSTATUS status;

			status = smb2_signing_sign_pdu(signing_key,
						       state->session->conn->protocol,
						       &iov[hdr_iov], num_iov - hdr_iov);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		}

		nbt_len += reqlen;

		ret = smbXcli_req_set_pending(reqs[i]);
		if (!ret) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	state = tevent_req_data(reqs[0], struct smbXcli_req_state);
	_smb_setlen_tcp(state->length_hdr, nbt_len);
	iov[0].iov_base = state->length_hdr;
	iov[0].iov_len  = sizeof(state->length_hdr);

	if (encryption_key != NULL) {
		NTSTATUS status;
		size_t buflen = nbt_len - SMB2_TF_HDR_SIZE;
		uint8_t *buf;
		int vi;

		buf = talloc_array(iov, uint8_t, buflen);
		if (buf == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		/*
		 * We copy the buffers before encrypting them,
		 * this is at least currently needed for the
		 * to keep state->smb2.hdr.
		 *
		 * Also the callers may expect there buffers
		 * to be const.
		 */
		for (vi = tf_iov + 1; vi < num_iov; vi++) {
			struct iovec *v = &iov[vi];
			const uint8_t *o = (const uint8_t *)v->iov_base;

			memcpy(buf, o, v->iov_len);
			v->iov_base = (void *)buf;
			buf += v->iov_len;
		}

		status = smb2_signing_encrypt_pdu(encryption_key,
					state->conn->smb2.server.cipher,
					&iov[tf_iov], num_iov - tf_iov);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (state->conn->dispatch_incoming == NULL) {
		state->conn->dispatch_incoming = smb2cli_conn_dispatch_incoming;
	}

	subreq = writev_send(state, state->ev, state->conn->outgoing,
			     state->conn->sock_fd, false, iov, num_iov);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, smb2cli_req_writev_done, reqs[0]);
	state->write_req = subreq;

	return NT_STATUS_OK;
}

void smb2cli_req_set_credit_charge(struct tevent_req *req, uint16_t charge)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);

	state->smb2.credit_charge = charge;
}

struct tevent_req *smb2cli_req_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    struct smbXcli_conn *conn,
				    uint16_t cmd,
				    uint32_t additional_flags,
				    uint32_t clear_flags,
				    uint32_t timeout_msec,
				    struct smbXcli_tcon *tcon,
				    struct smbXcli_session *session,
				    const uint8_t *fixed,
				    uint16_t fixed_len,
				    const uint8_t *dyn,
				    uint32_t dyn_len,
				    uint32_t max_dyn_len)
{
	struct tevent_req *req;
	NTSTATUS status;

	req = smb2cli_req_create(mem_ctx, ev, conn, cmd,
				 additional_flags, clear_flags,
				 timeout_msec,
				 tcon, session,
				 fixed, fixed_len,
				 dyn, dyn_len,
				 max_dyn_len);
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

static void smb2cli_req_writev_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);
	ssize_t nwritten;
	int err;

	state->write_req = NULL;

	nwritten = writev_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		/* here, we need to notify all pending requests */
		NTSTATUS status = map_nt_error_from_unix_common(err);
		smbXcli_conn_disconnect(state->conn, status);
		return;
	}
}

static struct smbXcli_session* smbXcli_session_by_uid(struct smbXcli_conn *conn,
						     uint64_t uid)
{
	struct smbXcli_session *s = conn->sessions;

	for (; s; s = s->next) {
		if (s->smb2->session_id != uid) {
			continue;
		}
		break;
	}

	return s;
}

static NTSTATUS smb2cli_inbuf_parse_compound(struct smbXcli_conn *conn,
					     uint8_t *buf,
					     size_t buflen,
					     TALLOC_CTX *mem_ctx,
					     struct iovec **piov,
					     size_t *pnum_iov)
{
	struct iovec *iov;
	int num_iov = 0;
	size_t taken = 0;
	uint8_t *first_hdr = buf;
	size_t verified_buflen = 0;
	uint8_t *tf = NULL;
	size_t tf_len = 0;

	iov = talloc_array(mem_ctx, struct iovec, num_iov);
	if (iov == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	while (taken < buflen) {
		size_t len = buflen - taken;
		uint8_t *hdr = first_hdr + taken;
		struct iovec *cur;
		size_t full_size;
		size_t next_command_ofs;
		uint16_t body_size;
		struct iovec *iov_tmp;

		if (verified_buflen > taken) {
			len = verified_buflen - taken;
		} else {
			tf = NULL;
			tf_len = 0;
		}

		if (len < 4) {
			DEBUG(10, ("%d bytes left, expected at least %d\n",
				   (int)len, 4));
			goto inval;
		}
		if (IVAL(hdr, 0) == SMB2_TF_MAGIC) {
			struct smbXcli_session *s;
			uint64_t uid;
			struct iovec tf_iov[2];
			size_t enc_len;
			NTSTATUS status;

			if (len < SMB2_TF_HDR_SIZE) {
				DEBUG(10, ("%d bytes left, expected at least %d\n",
					   (int)len, SMB2_TF_HDR_SIZE));
				goto inval;
			}
			tf = hdr;
			tf_len = SMB2_TF_HDR_SIZE;
			taken += tf_len;

			hdr = first_hdr + taken;
			enc_len = IVAL(tf, SMB2_TF_MSG_SIZE);
			uid = BVAL(tf, SMB2_TF_SESSION_ID);

			if (len < SMB2_TF_HDR_SIZE + enc_len) {
				DEBUG(10, ("%d bytes left, expected at least %d\n",
					   (int)len,
					   (int)(SMB2_TF_HDR_SIZE + enc_len)));
				goto inval;
			}

			s = smbXcli_session_by_uid(conn, uid);
			if (s == NULL) {
				DEBUG(10, ("unknown session_id %llu\n",
					   (unsigned long long)uid));
				goto inval;
			}

			tf_iov[0].iov_base = (void *)tf;
			tf_iov[0].iov_len = tf_len;
			tf_iov[1].iov_base = (void *)hdr;
			tf_iov[1].iov_len = enc_len;

			status = smb2_signing_decrypt_pdu(s->smb2->decryption_key,
							  conn->smb2.server.cipher,
							  tf_iov, 2);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(iov);
				return status;
			}

			verified_buflen = taken + enc_len;
			len = enc_len;
		}

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
					 num_iov + 4);
		if (iov_tmp == NULL) {
			TALLOC_FREE(iov);
			return NT_STATUS_NO_MEMORY;
		}
		iov = iov_tmp;
		cur = &iov[num_iov];
		num_iov += 4;

		cur[0].iov_base = tf;
		cur[0].iov_len  = tf_len;
		cur[1].iov_base = hdr;
		cur[1].iov_len  = SMB2_HDR_BODY;
		cur[2].iov_base = hdr + SMB2_HDR_BODY;
		cur[2].iov_len  = body_size;
		cur[3].iov_base = hdr + SMB2_HDR_BODY + body_size;
		cur[3].iov_len  = full_size - (SMB2_HDR_BODY + body_size);

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
	struct iovec *iov = NULL;
	size_t i, num_iov = 0;
	NTSTATUS status;
	bool defer = true;
	struct smbXcli_session *last_session = NULL;
	size_t inbuf_len = smb_len_tcp(inbuf);

	status = smb2cli_inbuf_parse_compound(conn,
					      inbuf + NBT_HDR_SIZE,
					      inbuf_len,
					      tmp_mem,
					      &iov, &num_iov);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i=0; i<num_iov; i+=4) {
		uint8_t *inbuf_ref = NULL;
		struct iovec *cur = &iov[i];
		uint8_t *inhdr = (uint8_t *)cur[1].iov_base;
		uint16_t opcode = SVAL(inhdr, SMB2_HDR_OPCODE);
		uint32_t flags = IVAL(inhdr, SMB2_HDR_FLAGS);
		uint64_t mid = BVAL(inhdr, SMB2_HDR_MESSAGE_ID);
		uint16_t req_opcode;
		uint32_t req_flags;
		uint16_t credits = SVAL(inhdr, SMB2_HDR_CREDIT);
		uint32_t new_credits;
		struct smbXcli_session *session = NULL;
		struct smb2_signing_key *signing_key = NULL;
		bool was_encrypted = false;

		new_credits = conn->smb2.cur_credits;
		new_credits += credits;
		if (new_credits > UINT16_MAX) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		conn->smb2.cur_credits += credits;

		req = smb2cli_conn_find_pending(conn, mid);
		if (req == NULL) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		state = tevent_req_data(req, struct smbXcli_req_state);

		req_opcode = SVAL(state->smb2.hdr, SMB2_HDR_OPCODE);
		if (opcode != req_opcode) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}
		req_flags = SVAL(state->smb2.hdr, SMB2_HDR_FLAGS);

		if (!(flags & SMB2_HDR_FLAG_REDIRECT)) {
			return NT_STATUS_INVALID_NETWORK_RESPONSE;
		}

		status = NT_STATUS(IVAL(inhdr, SMB2_HDR_STATUS));
		if ((flags & SMB2_HDR_FLAG_ASYNC) &&
		    NT_STATUS_EQUAL(status, NT_STATUS_PENDING)) {
			uint64_t async_id = BVAL(inhdr, SMB2_HDR_ASYNC_ID);

			if (state->smb2.got_async) {
				/* We only expect one STATUS_PENDING response */
				return NT_STATUS_INVALID_NETWORK_RESPONSE;
			}
			state->smb2.got_async = true;

			/*
			 * async interim responses are not signed,
			 * even if the SMB2_HDR_FLAG_SIGNED flag
			 * is set.
			 */
			state->smb2.cancel_flags = SMB2_HDR_FLAG_ASYNC;
			state->smb2.cancel_mid = 0;
			state->smb2.cancel_aid = async_id;

			if (state->smb2.notify_async) {
				tevent_req_defer_callback(req, state->ev);
				tevent_req_notify_callback(req);
			}
			continue;
		}

		session = state->session;
		if (req_flags & SMB2_HDR_FLAG_CHAINED) {
			session = last_session;
		}
		last_session = session;

		if (flags & SMB2_HDR_FLAG_SIGNED) {
			uint64_t uid = BVAL(inhdr, SMB2_HDR_SESSION_ID);

			if (session == NULL) {
				session = smbXcli_session_by_uid(state->conn,
								 uid);
			}

			if (session == NULL) {
				return NT_STATUS_INVALID_NETWORK_RESPONSE;
			}

			last_session = session;
			signing_key = session->smb2_channel.signing_key;
		}

		if (opcode == SMB2_OP_SESSSETUP) {
			/*
			 * We prefer the channel signing key, if it is
			 * already there.
			 *
			 * If we do not have a channel signing key yet,
			 * we try the main signing key, if it is not
			 * the final response.
			 */
			if (signing_key != NULL &&
			    !smb2_signing_key_valid(signing_key) &&
			    !NT_STATUS_IS_OK(status)) {
				signing_key = session->smb2->signing_key;
			}

			if (signing_key != NULL &&
			    !smb2_signing_key_valid(signing_key)) {
				/*
				 * If we do not have a session key to
				 * verify the signature, we defer the
				 * signing check to the caller.
				 *
				 * The caller gets NT_STATUS_OK, it
				 * has to call
				 * smb2cli_session_set_session_key()
				 * or
				 * smb2cli_session_set_channel_key()
				 * which will check the signature
				 * with the channel signing key.
				 */
				signing_key = NULL;
			}

			if (!NT_STATUS_IS_OK(status)) {
				/*
				 * Only check the signature of the last response
				 * of a successfull session auth. This matches
				 * Windows behaviour for NTLM auth and reauth.
				 */
				state->smb2.require_signed_response = false;
			}
		}

		if (state->smb2.should_sign ||
		    state->smb2.require_signed_response)
		{
			if (!(flags & SMB2_HDR_FLAG_SIGNED)) {
				return NT_STATUS_ACCESS_DENIED;
			}
		}

		if (!smb2_signing_key_valid(signing_key) &&
		    state->smb2.require_signed_response) {
			signing_key = session->smb2_channel.signing_key;
		}

		if (cur[0].iov_len == SMB2_TF_HDR_SIZE) {
			const uint8_t *tf = (const uint8_t *)cur[0].iov_base;
			uint64_t uid = BVAL(tf, SMB2_TF_SESSION_ID);

			/*
			 * If the response was encrypted in a SMB2_TRANSFORM
			 * pdu, which belongs to the correct session,
			 * we do not need to do signing checks
			 *
			 * It could be the session the response belongs to
			 * or the session that was used to encrypt the
			 * SMB2_TRANSFORM request.
			 */
			if ((session && session->smb2->session_id == uid) ||
			    (state->smb2.encryption_session_id == uid)) {
				signing_key = NULL;
				was_encrypted = true;
			}
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_USER_SESSION_DELETED)) {
			/*
			 * if the server returns NT_STATUS_USER_SESSION_DELETED
			 * the response is not signed and we should
			 * propagate the NT_STATUS_USER_SESSION_DELETED
			 * status to the caller.
			 */
			state->smb2.signing_skipped = true;
			signing_key = NULL;
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			/*
			 * if the server returns
			 * NT_STATUS_INVALID_PARAMETER
			 * the response might not be encrypted.
			 */
			if (state->smb2.should_encrypt && !was_encrypted) {
				state->smb2.signing_skipped = true;
				signing_key = NULL;
			}
		}

		if (state->smb2.should_encrypt && !was_encrypted) {
			if (!state->smb2.signing_skipped) {
				return NT_STATUS_ACCESS_DENIED;
			}
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_NAME_DELETED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED) ||
		    NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
			/*
			 * if the server returns
			 * NT_STATUS_NETWORK_NAME_DELETED
			 * NT_STATUS_FILE_CLOSED
			 * NT_STATUS_INVALID_PARAMETER
			 * the response might not be signed
			 * as this happens before the signing checks.
			 *
			 * If server echos the signature (or all zeros)
			 * we should report the status from the server
			 * to the caller.
			 */
			if (signing_key) {
				int cmp;

				cmp = memcmp(inhdr+SMB2_HDR_SIGNATURE,
					     state->smb2.hdr+SMB2_HDR_SIGNATURE,
					     16);
				if (cmp == 0) {
					state->smb2.signing_skipped = true;
					signing_key = NULL;
				}
			}
			if (signing_key) {
				bool zero;
				zero = all_zero(inhdr+SMB2_HDR_SIGNATURE, 16);
				if (zero) {
					state->smb2.signing_skipped = true;
					signing_key = NULL;
				}
			}
		}

		if (signing_key) {
			NTSTATUS signing_status;

			signing_status = smb2_signing_check_pdu(signing_key,
								state->conn->protocol,
								&cur[1], 3);
			if (!NT_STATUS_IS_OK(signing_status)) {
				/*
				 * If the signing check fails, we disconnect
				 * the connection.
				 */
				return signing_status;
			}
		}

		if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED) &&
		    (session != NULL) && session->disconnect_expired)
		{
			/*
			 * this should be a short term hack
			 * until the upper layers have implemented
			 * re-authentication.
			 */
			return status;
		}

		smbXcli_req_unset_pending(req);

		/*
		 * There might be more than one response
		 * we need to defer the notifications
		 */
		if ((num_iov == 5) && (talloc_array_length(conn->pending) == 0)) {
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
		state->smb2.recv_iov[0] = cur[1];
		state->smb2.recv_iov[1] = cur[2];
		state->smb2.recv_iov[2] = cur[3];

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

	if (tevent_req_is_in_progress(req) && state->smb2.got_async) {
		return NT_STATUS_PENDING;
	}

	if (tevent_req_is_nterror(req, &status)) {
		for (i=0; i < num_expected; i++) {
			if (NT_STATUS_EQUAL(status, expected[i].status)) {
				return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
			}
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

	if (state->smb2.signing_skipped) {
		if (num_expected > 0) {
			return NT_STATUS_ACCESS_DENIED;
		}
		if (!NT_STATUS_IS_ERR(status)) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	if (!found_size) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	if (piov != NULL) {
		*piov = talloc_move(mem_ctx, &state->smb2.recv_iov);
	}

	return status;
}

NTSTATUS smb2cli_req_get_sent_iov(struct tevent_req *req,
				  struct iovec *sent_iov)
{
	struct smbXcli_req_state *state =
		tevent_req_data(req,
		struct smbXcli_req_state);

	if (tevent_req_is_in_progress(req)) {
		return NT_STATUS_PENDING;
	}

	sent_iov[0].iov_base = state->smb2.hdr;
	sent_iov[0].iov_len  = sizeof(state->smb2.hdr);

	sent_iov[1].iov_base = discard_const(state->smb2.fixed);
	sent_iov[1].iov_len  = state->smb2.fixed_len;

	if (state->smb2.dyn != NULL) {
		sent_iov[2].iov_base = discard_const(state->smb2.dyn);
		sent_iov[2].iov_len  = state->smb2.dyn_len;
	} else {
		sent_iov[2].iov_base = NULL;
		sent_iov[2].iov_len  = 0;
	}

	return NT_STATUS_OK;
}

static const struct {
	enum protocol_types proto;
	const char *smb1_name;
} smb1cli_prots[] = {
	{PROTOCOL_CORE,		"PC NETWORK PROGRAM 1.0"},
	{PROTOCOL_COREPLUS,	"MICROSOFT NETWORKS 1.03"},
	{PROTOCOL_LANMAN1,	"MICROSOFT NETWORKS 3.0"},
	{PROTOCOL_LANMAN1,	"LANMAN1.0"},
	{PROTOCOL_LANMAN2,	"LM1.2X002"},
	{PROTOCOL_LANMAN2,	"DOS LANMAN2.1"},
	{PROTOCOL_LANMAN2,	"LANMAN2.1"},
	{PROTOCOL_LANMAN2,	"Samba"},
	{PROTOCOL_NT1,		"NT LANMAN 1.0"},
	{PROTOCOL_NT1,		"NT LM 0.12"},
	{PROTOCOL_SMB2_02,	"SMB 2.002"},
	{PROTOCOL_SMB2_10,	"SMB 2.???"},
};

static const struct {
	enum protocol_types proto;
	uint16_t smb2_dialect;
} smb2cli_prots[] = {
	{PROTOCOL_SMB2_02,	SMB2_DIALECT_REVISION_202},
	{PROTOCOL_SMB2_10,	SMB2_DIALECT_REVISION_210},
	{PROTOCOL_SMB2_22,	SMB2_DIALECT_REVISION_222},
	{PROTOCOL_SMB2_24,	SMB2_DIALECT_REVISION_224},
	{PROTOCOL_SMB3_00,	SMB3_DIALECT_REVISION_300},
	{PROTOCOL_SMB3_02,	SMB3_DIALECT_REVISION_302},
	{PROTOCOL_SMB3_10,	SMB3_DIALECT_REVISION_310},
	{PROTOCOL_SMB3_11,	SMB3_DIALECT_REVISION_311},
};

struct smbXcli_negprot_state {
	struct smbXcli_conn *conn;
	struct tevent_context *ev;
	uint32_t timeout_msec;

	struct {
		uint8_t fixed[36];
	} smb2;
};

static void smbXcli_negprot_invalid_done(struct tevent_req *subreq);
static struct tevent_req *smbXcli_negprot_smb1_subreq(struct smbXcli_negprot_state *state);
static void smbXcli_negprot_smb1_done(struct tevent_req *subreq);
static struct tevent_req *smbXcli_negprot_smb2_subreq(struct smbXcli_negprot_state *state);
static void smbXcli_negprot_smb2_done(struct tevent_req *subreq);
static NTSTATUS smbXcli_negprot_dispatch_incoming(struct smbXcli_conn *conn,
						  TALLOC_CTX *frame,
						  uint8_t *inbuf);

struct tevent_req *smbXcli_negprot_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct smbXcli_conn *conn,
					uint32_t timeout_msec,
					enum protocol_types min_protocol,
					enum protocol_types max_protocol,
					uint16_t max_credits)
{
	struct tevent_req *req, *subreq;
	struct smbXcli_negprot_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smbXcli_negprot_state);
	if (req == NULL) {
		return NULL;
	}
	state->conn = conn;
	state->ev = ev;
	state->timeout_msec = timeout_msec;

	if (min_protocol == PROTOCOL_NONE) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (max_protocol == PROTOCOL_NONE) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	if (min_protocol > max_protocol) {
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
		return tevent_req_post(req, ev);
	}

	conn->min_protocol = min_protocol;
	conn->max_protocol = max_protocol;
	conn->protocol = PROTOCOL_NONE;

	if (max_protocol >= PROTOCOL_SMB2_02) {
		conn->smb2.max_credits = max_credits;
	}

	if ((min_protocol < PROTOCOL_SMB2_02) &&
	    (max_protocol < PROTOCOL_SMB2_02)) {
		/*
		 * SMB1 only...
		 */
		conn->dispatch_incoming = smb1cli_conn_dispatch_incoming;

		subreq = smbXcli_negprot_smb1_subreq(state);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, smbXcli_negprot_smb1_done, req);
		return req;
	}

	if ((min_protocol >= PROTOCOL_SMB2_02) &&
	    (max_protocol >= PROTOCOL_SMB2_02)) {
		/*
		 * SMB2 only...
		 */
		conn->dispatch_incoming = smb2cli_conn_dispatch_incoming;

		subreq = smbXcli_negprot_smb2_subreq(state);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, smbXcli_negprot_smb2_done, req);
		return req;
	}

	/*
	 * We send an SMB1 negprot with the SMB2 dialects
	 * and expect a SMB1 or a SMB2 response.
	 *
	 * smbXcli_negprot_dispatch_incoming() will fix the
	 * callback to match protocol of the response.
	 */
	conn->dispatch_incoming = smbXcli_negprot_dispatch_incoming;

	subreq = smbXcli_negprot_smb1_subreq(state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smbXcli_negprot_invalid_done, req);
	return req;
}

static void smbXcli_negprot_invalid_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	NTSTATUS status;

	/*
	 * we just want the low level error
	 */
	status = tevent_req_simple_recv_ntstatus(subreq);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	/* this should never happen */
	tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
}

static struct tevent_req *smbXcli_negprot_smb1_subreq(struct smbXcli_negprot_state *state)
{
	size_t i;
	DATA_BLOB bytes = data_blob_null;
	uint8_t flags;
	uint16_t flags2;

	/* setup the protocol strings */
	for (i=0; i < ARRAY_SIZE(smb1cli_prots); i++) {
		uint8_t c = 2;
		bool ok;

		if (smb1cli_prots[i].proto < state->conn->min_protocol) {
			continue;
		}

		if (smb1cli_prots[i].proto > state->conn->max_protocol) {
			continue;
		}

		ok = data_blob_append(state, &bytes, &c, sizeof(c));
		if (!ok) {
			return NULL;
		}

		/*
		 * We now it is already ascii and
		 * we want NULL termination.
		 */
		ok = data_blob_append(state, &bytes,
				      smb1cli_prots[i].smb1_name,
				      strlen(smb1cli_prots[i].smb1_name)+1);
		if (!ok) {
			return NULL;
		}
	}

	smb1cli_req_flags(state->conn->max_protocol,
			  state->conn->smb1.client.capabilities,
			  SMBnegprot,
			  0, 0, &flags,
			  0, 0, &flags2);

	return smb1cli_req_send(state, state->ev, state->conn,
				SMBnegprot,
				flags, ~flags,
				flags2, ~flags2,
				state->timeout_msec,
				0xFFFE, 0, NULL, /* pid, tid, session */
				0, NULL, /* wct, vwv */
				bytes.length, bytes.data);
}

static void smbXcli_negprot_smb1_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbXcli_negprot_state *state =
		tevent_req_data(req,
		struct smbXcli_negprot_state);
	struct smbXcli_conn *conn = state->conn;
	struct iovec *recv_iov = NULL;
	uint8_t *inhdr = NULL;
	uint8_t wct;
	uint16_t *vwv;
	uint32_t num_bytes;
	uint8_t *bytes;
	NTSTATUS status;
	uint16_t protnum;
	size_t i;
	size_t num_prots = 0;
	uint8_t flags;
	uint32_t client_capabilities = conn->smb1.client.capabilities;
	uint32_t both_capabilities;
	uint32_t server_capabilities = 0;
	uint32_t capabilities;
	uint32_t client_max_xmit = conn->smb1.client.max_xmit;
	uint32_t server_max_xmit = 0;
	uint32_t max_xmit;
	uint32_t server_max_mux = 0;
	uint16_t server_security_mode = 0;
	uint32_t server_session_key = 0;
	bool server_readbraw = false;
	bool server_writebraw = false;
	bool server_lockread = false;
	bool server_writeunlock = false;
	struct GUID server_guid = GUID_zero();
	DATA_BLOB server_gss_blob = data_blob_null;
	uint8_t server_challenge[8];
	char *server_workgroup = NULL;
	char *server_name = NULL;
	int server_time_zone = 0;
	NTTIME server_system_time = 0;
	static const struct smb1cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.wct = 0x11, /* NT1 */
	},
	{
		.status = NT_STATUS_OK,
		.wct = 0x0D, /* LM */
	},
	{
		.status = NT_STATUS_OK,
		.wct = 0x01, /* CORE */
	}
	};

	ZERO_STRUCT(server_challenge);

	status = smb1cli_req_recv(subreq, state,
				  &recv_iov,
				  &inhdr,
				  &wct,
				  &vwv,
				  NULL, /* pvwv_offset */
				  &num_bytes,
				  &bytes,
				  NULL, /* pbytes_offset */
				  NULL, /* pinbuf */
				  expected, ARRAY_SIZE(expected));
	TALLOC_FREE(subreq);
	if (inhdr == NULL || tevent_req_nterror(req, status)) {
		return;
	}

	flags = CVAL(inhdr, HDR_FLG);

	protnum = SVAL(vwv, 0);

	for (i=0; i < ARRAY_SIZE(smb1cli_prots); i++) {
		if (smb1cli_prots[i].proto < state->conn->min_protocol) {
			continue;
		}

		if (smb1cli_prots[i].proto > state->conn->max_protocol) {
			continue;
		}

		if (protnum != num_prots) {
			num_prots++;
			continue;
		}

		conn->protocol = smb1cli_prots[i].proto;
		break;
	}

	if (conn->protocol == PROTOCOL_NONE) {
		DBG_ERR("No compatible protocol selected by server.\n");
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if ((conn->protocol < PROTOCOL_NT1) && conn->mandatory_signing) {
		DEBUG(0,("smbXcli_negprot: SMB signing is mandatory "
			 "and the selected protocol level doesn't support it.\n"));
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	if (flags & FLAG_SUPPORT_LOCKREAD) {
		server_lockread = true;
		server_writeunlock = true;
	}

	if (conn->protocol >= PROTOCOL_NT1) {
		const char *client_signing = NULL;
		bool server_mandatory = false;
		bool server_allowed = false;
		const char *server_signing = NULL;
		bool ok;
		uint8_t key_len;

		if (wct != 0x11) {
			tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		/* NT protocol */
		server_security_mode = CVAL(vwv + 1, 0);
		server_max_mux = SVAL(vwv + 1, 1);
		server_max_xmit = IVAL(vwv + 3, 1);
		server_session_key = IVAL(vwv + 7, 1);
		server_time_zone = SVALS(vwv + 15, 1);
		server_time_zone *= 60;
		/* this time arrives in real GMT */
		server_system_time = BVAL(vwv + 11, 1);
		server_capabilities = IVAL(vwv + 9, 1);

		key_len = CVAL(vwv + 16, 1);

		if (server_capabilities & CAP_RAW_MODE) {
			server_readbraw = true;
			server_writebraw = true;
		}
		if (server_capabilities & CAP_LOCK_AND_READ) {
			server_lockread = true;
		}

		if (server_capabilities & CAP_EXTENDED_SECURITY) {
			DATA_BLOB blob1, blob2;

			if (num_bytes < 16) {
				tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
				return;
			}

			blob1 = data_blob_const(bytes, 16);
			status = GUID_from_data_blob(&blob1, &server_guid);
			if (tevent_req_nterror(req, status)) {
				return;
			}

			blob1 = data_blob_const(bytes+16, num_bytes-16);
			blob2 = data_blob_dup_talloc(state, blob1);
			if (blob1.length > 0 &&
			    tevent_req_nomem(blob2.data, req)) {
				return;
			}
			server_gss_blob = blob2;
		} else {
			DATA_BLOB blob1, blob2;

			if (num_bytes < key_len) {
				tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
				return;
			}

			if (key_len != 0 && key_len != 8) {
				tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
				return;
			}

			if (key_len == 8) {
				memcpy(server_challenge, bytes, 8);
			}

			blob1 = data_blob_const(bytes+key_len, num_bytes-key_len);
			blob2 = data_blob_const(bytes+key_len, num_bytes-key_len);
			if (blob1.length > 0) {
				size_t len;

				len = utf16_len_n(blob1.data,
						  blob1.length);
				blob1.length = len;

				ok = convert_string_talloc(state,
							   CH_UTF16LE,
							   CH_UNIX,
							   blob1.data,
							   blob1.length,
							   &server_workgroup,
							   &len);
				if (!ok) {
					status = map_nt_error_from_unix_common(errno);
					tevent_req_nterror(req, status);
					return;
				}
			}

			blob2.data += blob1.length;
			blob2.length -= blob1.length;
			if (blob2.length > 0) {
				size_t len;

				len = utf16_len_n(blob1.data,
						  blob1.length);
				blob1.length = len;

				ok = convert_string_talloc(state,
							   CH_UTF16LE,
							   CH_UNIX,
							   blob2.data,
							   blob2.length,
							   &server_name,
							   &len);
				if (!ok) {
					status = map_nt_error_from_unix_common(errno);
					tevent_req_nterror(req, status);
					return;
				}
			}
		}

		client_signing = "disabled";
		if (conn->allow_signing) {
			client_signing = "allowed";
		}
		if (conn->mandatory_signing) {
			client_signing = "required";
		}

		server_signing = "not supported";
		if (server_security_mode & NEGOTIATE_SECURITY_SIGNATURES_ENABLED) {
			server_signing = "supported";
			server_allowed = true;
		} else if (conn->mandatory_signing) {
			/*
			 * We have mandatory signing as client
			 * lets assume the server will look at our
			 * FLAGS2_SMB_SECURITY_SIGNATURES_REQUIRED
			 * flag in the session setup
			 */
			server_signing = "not announced";
			server_allowed = true;
		}
		if (server_security_mode & NEGOTIATE_SECURITY_SIGNATURES_REQUIRED) {
			server_signing = "required";
			server_mandatory = true;
		}

		ok = smb_signing_set_negotiated(conn->smb1.signing,
						server_allowed,
						server_mandatory);
		if (!ok) {
			DEBUG(1,("cli_negprot: SMB signing is required, "
				 "but client[%s] and server[%s] mismatch\n",
				 client_signing, server_signing));
			tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
			return;
		}

	} else if (conn->protocol >= PROTOCOL_LANMAN1) {
		DATA_BLOB blob1;
		uint8_t key_len;
		time_t t;

		if (wct != 0x0D) {
			tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		server_security_mode = SVAL(vwv + 1, 0);
		server_max_xmit = SVAL(vwv + 2, 0);
		server_max_mux = SVAL(vwv + 3, 0);
		server_readbraw = ((SVAL(vwv + 5, 0) & 0x1) != 0);
		server_writebraw = ((SVAL(vwv + 5, 0) & 0x2) != 0);
		server_session_key = IVAL(vwv + 6, 0);
		server_time_zone = SVALS(vwv + 10, 0);
		server_time_zone *= 60;
		/* this time is converted to GMT by make_unix_date */
		t = pull_dos_date((const uint8_t *)(vwv + 8), server_time_zone);
		unix_to_nt_time(&server_system_time, t);
		key_len = SVAL(vwv + 11, 0);

		if (num_bytes < key_len) {
			tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		if (key_len != 0 && key_len != 8) {
			tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		if (key_len == 8) {
			memcpy(server_challenge, bytes, 8);
		}

		blob1 = data_blob_const(bytes+key_len, num_bytes-key_len);
		if (blob1.length > 0) {
			size_t len;
			bool ok;

			len = utf16_len_n(blob1.data,
					  blob1.length);
			blob1.length = len;

			ok = convert_string_talloc(state,
						   CH_DOS,
						   CH_UNIX,
						   blob1.data,
						   blob1.length,
						   &server_workgroup,
						   &len);
			if (!ok) {
				status = map_nt_error_from_unix_common(errno);
				tevent_req_nterror(req, status);
				return;
			}
		}

	} else {
		/* the old core protocol */
		server_time_zone = get_time_zone(time(NULL));
		server_max_xmit = 1024;
		server_max_mux = 1;
	}

	if (server_max_xmit < 1024) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (server_max_mux < 1) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	/*
	 * Now calculate the negotiated capabilities
	 * based on the mask for:
	 * - client only flags
	 * - flags used in both directions
	 * - server only flags
	 */
	both_capabilities = client_capabilities & server_capabilities;
	capabilities = client_capabilities & SMB_CAP_CLIENT_MASK;
	capabilities |= both_capabilities & SMB_CAP_BOTH_MASK;
	capabilities |= server_capabilities & SMB_CAP_SERVER_MASK;

	max_xmit = MIN(client_max_xmit, server_max_xmit);

	conn->smb1.server.capabilities = server_capabilities;
	conn->smb1.capabilities = capabilities;

	conn->smb1.server.max_xmit = server_max_xmit;
	conn->smb1.max_xmit = max_xmit;

	conn->smb1.server.max_mux = server_max_mux;

	conn->smb1.server.security_mode = server_security_mode;

	conn->smb1.server.readbraw = server_readbraw;
	conn->smb1.server.writebraw = server_writebraw;
	conn->smb1.server.lockread = server_lockread;
	conn->smb1.server.writeunlock = server_writeunlock;

	conn->smb1.server.session_key = server_session_key;

	talloc_steal(conn, server_gss_blob.data);
	conn->smb1.server.gss_blob = server_gss_blob;
	conn->smb1.server.guid = server_guid;
	memcpy(conn->smb1.server.challenge, server_challenge, 8);
	conn->smb1.server.workgroup = talloc_move(conn, &server_workgroup);
	conn->smb1.server.name = talloc_move(conn, &server_name);

	conn->smb1.server.time_zone = server_time_zone;
	conn->smb1.server.system_time = server_system_time;

	tevent_req_done(req);
}

static size_t smbXcli_padding_helper(uint32_t offset, size_t n)
{
	if ((offset & (n-1)) == 0) return 0;
	return n - (offset & (n-1));
}

static struct tevent_req *smbXcli_negprot_smb2_subreq(struct smbXcli_negprot_state *state)
{
	size_t i;
	uint8_t *buf;
	uint16_t dialect_count = 0;
	DATA_BLOB dyn = data_blob_null;

	for (i=0; i < ARRAY_SIZE(smb2cli_prots); i++) {
		bool ok;
		uint8_t val[2];

		if (smb2cli_prots[i].proto < state->conn->min_protocol) {
			continue;
		}

		if (smb2cli_prots[i].proto > state->conn->max_protocol) {
			continue;
		}

		SSVAL(val, 0, smb2cli_prots[i].smb2_dialect);

		ok = data_blob_append(state, &dyn, val, sizeof(val));
		if (!ok) {
			return NULL;
		}

		dialect_count++;
	}

	buf = state->smb2.fixed;
	SSVAL(buf, 0, 36);
	SSVAL(buf, 2, dialect_count);
	SSVAL(buf, 4, state->conn->smb2.client.security_mode);
	SSVAL(buf, 6, 0);	/* Reserved */
	if (state->conn->max_protocol >= PROTOCOL_SMB2_22) {
		SIVAL(buf, 8, state->conn->smb2.client.capabilities);
	} else {
		SIVAL(buf, 8, 0); 	/* Capabilities */
	}
	if (state->conn->max_protocol >= PROTOCOL_SMB2_10) {
		NTSTATUS status;
		DATA_BLOB blob;

		status = GUID_to_ndr_blob(&state->conn->smb2.client.guid,
					  state, &blob);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}
		memcpy(buf+12, blob.data, 16); /* ClientGuid */
	} else {
		memset(buf+12, 0, 16);	/* ClientGuid */
	}

	if (state->conn->max_protocol >= PROTOCOL_SMB3_10) {
		NTSTATUS status;
		struct smb2_negotiate_contexts c = { .num_contexts = 0, };
		uint8_t *netname_utf16 = NULL;
		size_t netname_utf16_len = 0;
		uint32_t offset;
		DATA_BLOB b;
		uint8_t p[38];
		const uint8_t zeros[8] = {0, };
		size_t pad;
		bool ok;

		SSVAL(p, 0,  1); /* HashAlgorithmCount */
		SSVAL(p, 2, 32); /* SaltLength */
		SSVAL(p, 4, SMB2_PREAUTH_INTEGRITY_SHA512);
		generate_random_buffer(p + 6, 32);

		status = smb2_negotiate_context_add(
			state, &c, SMB2_PREAUTH_INTEGRITY_CAPABILITIES, p, 38);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}

		SSVAL(p, 0, 2); /* ChiperCount */

		SSVAL(p, 2, SMB2_ENCRYPTION_AES128_GCM);
		SSVAL(p, 4, SMB2_ENCRYPTION_AES128_CCM);

		status = smb2_negotiate_context_add(
			state, &c, SMB2_ENCRYPTION_CAPABILITIES, p, 6);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}

		ok = convert_string_talloc(state, CH_UNIX, CH_UTF16,
					   state->conn->remote_name,
					   strlen(state->conn->remote_name),
					   &netname_utf16, &netname_utf16_len);
		if (!ok) {
			return NULL;
		}

		status = smb2_negotiate_context_add(state, &c,
					SMB2_NETNAME_NEGOTIATE_CONTEXT_ID,
					netname_utf16, netname_utf16_len);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}

		status = smb2_negotiate_context_push(state, &b, c);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}

		offset = SMB2_HDR_BODY + sizeof(state->smb2.fixed) + dyn.length;
		pad = smbXcli_padding_helper(offset, 8);

		ok = data_blob_append(state, &dyn, zeros, pad);
		if (!ok) {
			return NULL;
		}
		offset += pad;

		ok = data_blob_append(state, &dyn, b.data, b.length);
		if (!ok) {
			return NULL;
		}

		SIVAL(buf, 28, offset);   /* NegotiateContextOffset */
		SSVAL(buf, 32, c.num_contexts); /* NegotiateContextCount */
		SSVAL(buf, 34, 0);        /* Reserved */
	} else {
		SBVAL(buf, 28, 0);	/* Reserved/ClientStartTime */
	}

	return smb2cli_req_send(state, state->ev,
				state->conn, SMB2_OP_NEGPROT,
				0, 0, /* flags */
				state->timeout_msec,
				NULL, NULL, /* tcon, session */
				state->smb2.fixed, sizeof(state->smb2.fixed),
				dyn.data, dyn.length,
				UINT16_MAX); /* max_dyn_len */
}

static void smbXcli_negprot_smb2_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smbXcli_negprot_state *state =
		tevent_req_data(req,
		struct smbXcli_negprot_state);
	struct smbXcli_conn *conn = state->conn;
	size_t security_offset, security_length;
	DATA_BLOB blob;
	NTSTATUS status;
	struct iovec *iov = NULL;
	uint8_t *body;
	size_t i;
	uint16_t dialect_revision;
	struct smb2_negotiate_contexts c = { .num_contexts = 0, };
	uint32_t negotiate_context_offset = 0;
	uint16_t negotiate_context_count = 0;
	DATA_BLOB negotiate_context_blob = data_blob_null;
	size_t avail;
	size_t ctx_ofs;
	size_t needed;
	struct smb2_negotiate_context *preauth = NULL;
	uint16_t hash_count;
	uint16_t salt_length;
	uint16_t hash_selected;
	gnutls_hash_hd_t hash_hnd = NULL;
	struct smb2_negotiate_context *cipher = NULL;
	struct iovec sent_iov[3] = {{0}, {0}, {0}};
	static const struct smb2cli_req_expected_response expected[] = {
	{
		.status = NT_STATUS_OK,
		.body_size = 0x41
	}
	};
	int rc;

	status = smb2cli_req_recv(subreq, state, &iov,
				  expected, ARRAY_SIZE(expected));
	if (tevent_req_nterror(req, status) || iov == NULL) {
		return;
	}

	body = (uint8_t *)iov[1].iov_base;

	dialect_revision = SVAL(body, 4);

	for (i=0; i < ARRAY_SIZE(smb2cli_prots); i++) {
		if (smb2cli_prots[i].proto < state->conn->min_protocol) {
			continue;
		}

		if (smb2cli_prots[i].proto > state->conn->max_protocol) {
			continue;
		}

		if (smb2cli_prots[i].smb2_dialect != dialect_revision) {
			continue;
		}

		conn->protocol = smb2cli_prots[i].proto;
		break;
	}

	if (conn->protocol == PROTOCOL_NONE) {
		TALLOC_FREE(subreq);

		if (state->conn->min_protocol >= PROTOCOL_SMB2_02) {
			tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		if (dialect_revision != SMB2_DIALECT_REVISION_2FF) {
			tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		/* make sure we do not loop forever */
		state->conn->min_protocol = PROTOCOL_SMB2_02;

		/*
		 * send a SMB2 negprot, in order to negotiate
		 * the SMB2 dialect.
		 */
		subreq = smbXcli_negprot_smb2_subreq(state);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, smbXcli_negprot_smb2_done, req);
		return;
	}

	conn->smb2.server.security_mode = SVAL(body, 2);
	if (conn->protocol >= PROTOCOL_SMB3_10) {
		negotiate_context_count = SVAL(body, 6);
	}

	blob = data_blob_const(body + 8, 16);
	status = GUID_from_data_blob(&blob, &conn->smb2.server.guid);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	conn->smb2.server.capabilities	= IVAL(body, 24);
	conn->smb2.server.max_trans_size= IVAL(body, 28);
	conn->smb2.server.max_read_size	= IVAL(body, 32);
	conn->smb2.server.max_write_size= IVAL(body, 36);
	conn->smb2.server.system_time	= BVAL(body, 40);
	conn->smb2.server.start_time	= BVAL(body, 48);

	security_offset = SVAL(body, 56);
	security_length = SVAL(body, 58);

	if (security_offset != SMB2_HDR_BODY + iov[1].iov_len) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (security_length > iov[2].iov_len) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	conn->smb2.server.gss_blob = data_blob_talloc(conn,
						iov[2].iov_base,
						security_length);
	if (tevent_req_nomem(conn->smb2.server.gss_blob.data, req)) {
		return;
	}

	if (conn->protocol < PROTOCOL_SMB3_10) {
		TALLOC_FREE(subreq);

		if (conn->smb2.server.capabilities & SMB2_CAP_ENCRYPTION) {
			conn->smb2.server.cipher = SMB2_ENCRYPTION_AES128_CCM;
		}
		tevent_req_done(req);
		return;
	}

	/*
	 * Here we are now at SMB3_11, so encryption should be
	 * negotiated via context, not capabilities.
	 */

	if (conn->smb2.server.capabilities & SMB2_CAP_ENCRYPTION) {
		/*
		 * Server set SMB2_CAP_ENCRYPTION capability,
		 * but *SHOULD* not, not *MUST* not. Just mask it off.
		 * NetApp seems to do this:
		 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=13009
		 */
		conn->smb2.server.capabilities &= ~SMB2_CAP_ENCRYPTION;
	}

	negotiate_context_offset = IVAL(body, 60);
	if (negotiate_context_offset < security_offset) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	ctx_ofs = negotiate_context_offset - security_offset;
	if (ctx_ofs > iov[2].iov_len) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}
	avail = iov[2].iov_len - security_length;
	needed = iov[2].iov_len - ctx_ofs;
	if (needed > avail) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	negotiate_context_blob.data = (uint8_t *)iov[2].iov_base;
	negotiate_context_blob.length = iov[2].iov_len;

	negotiate_context_blob.data += ctx_ofs;
	negotiate_context_blob.length -= ctx_ofs;

	status = smb2_negotiate_context_parse(state, negotiate_context_blob, &c);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (negotiate_context_count != c.num_contexts) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	preauth = smb2_negotiate_context_find(&c,
					SMB2_PREAUTH_INTEGRITY_CAPABILITIES);
	if (preauth == NULL) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (preauth->data.length < 6) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	hash_count = SVAL(preauth->data.data, 0);
	salt_length = SVAL(preauth->data.data, 2);
	hash_selected = SVAL(preauth->data.data, 4);

	if (hash_count != 1) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (preauth->data.length != (6 + salt_length)) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	if (hash_selected != SMB2_PREAUTH_INTEGRITY_SHA512) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	cipher = smb2_negotiate_context_find(&c, SMB2_ENCRYPTION_CAPABILITIES);
	if (cipher != NULL) {
		uint16_t cipher_count;

		if (cipher->data.length < 2) {
			tevent_req_nterror(req,
					NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		cipher_count = SVAL(cipher->data.data, 0);

		if (cipher_count > 1) {
			tevent_req_nterror(req,
					NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		if (cipher->data.length < (2 + 2 * cipher_count)) {
			tevent_req_nterror(req,
					NT_STATUS_INVALID_NETWORK_RESPONSE);
			return;
		}

		if (cipher_count == 1) {
			uint16_t cipher_selected;

			cipher_selected = SVAL(cipher->data.data, 2);

			switch (cipher_selected) {
			case SMB2_ENCRYPTION_AES128_GCM:
			case SMB2_ENCRYPTION_AES128_CCM:
				conn->smb2.server.cipher = cipher_selected;
				break;
			}
		}
	}

	/* First we hash the request */
	smb2cli_req_get_sent_iov(subreq, sent_iov);

	rc = gnutls_hash_init(&hash_hnd, GNUTLS_DIG_SHA512);
	if (rc < 0) {
		tevent_req_nterror(req,
				   gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED));
		return;
	}

	rc = gnutls_hash(hash_hnd,
			 conn->smb2.preauth_sha512,
			 sizeof(conn->smb2.preauth_sha512));
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		tevent_req_nterror(req,
				   gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED));
		return;
	}
	for (i = 0; i < 3; i++) {
		rc = gnutls_hash(hash_hnd,
				 sent_iov[i].iov_base,
				 sent_iov[i].iov_len);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			tevent_req_nterror(req,
					   gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED));
			return;
		}
	}

	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		tevent_req_nterror(req,
				   gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED));
		return;
	}

	/* This resets the hash state */
	gnutls_hash_output(hash_hnd, conn->smb2.preauth_sha512);
	TALLOC_FREE(subreq);

	/* And now we hash the response */
	rc = gnutls_hash(hash_hnd,
			 conn->smb2.preauth_sha512,
			 sizeof(conn->smb2.preauth_sha512));
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		tevent_req_nterror(req,
				   gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED));
		return;
	}
	for (i = 0; i < 3; i++) {
		rc = gnutls_hash(hash_hnd,
				 iov[i].iov_base,
				 iov[i].iov_len);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			tevent_req_nterror(req,
					   gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED));
			return;
		}
	}
	gnutls_hash_deinit(hash_hnd, conn->smb2.preauth_sha512);
	if (rc < 0) {
		tevent_req_nterror(req,
				   NT_STATUS_UNSUCCESSFUL);
		return;
	}

	tevent_req_done(req);
}

static NTSTATUS smbXcli_negprot_dispatch_incoming(struct smbXcli_conn *conn,
						  TALLOC_CTX *tmp_mem,
						  uint8_t *inbuf)
{
	size_t num_pending = talloc_array_length(conn->pending);
	struct tevent_req *subreq;
	struct smbXcli_req_state *substate;
	struct tevent_req *req;
	uint32_t protocol_magic;
	size_t inbuf_len = smb_len_nbt(inbuf);

	if (num_pending != 1) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (inbuf_len < 4) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	subreq = conn->pending[0];
	substate = tevent_req_data(subreq, struct smbXcli_req_state);
	req = tevent_req_callback_data(subreq, struct tevent_req);

	protocol_magic = IVAL(inbuf, 4);

	switch (protocol_magic) {
	case SMB_MAGIC:
		tevent_req_set_callback(subreq, smbXcli_negprot_smb1_done, req);
		conn->dispatch_incoming = smb1cli_conn_dispatch_incoming;
		return smb1cli_conn_dispatch_incoming(conn, tmp_mem, inbuf);

	case SMB2_MAGIC:
		if (substate->smb2.recv_iov == NULL) {
			/*
			 * For the SMB1 negprot we have move it.
			 */
			substate->smb2.recv_iov = substate->smb1.recv_iov;
			substate->smb1.recv_iov = NULL;
		}

		/*
		 * we got an SMB2 answer, which consumed sequence number 0
		 * so we need to use 1 as the next one.
		 *
		 * we also need to set the current credits to 0
		 * as we consumed the initial one. The SMB2 answer
		 * hopefully grant us a new credit.
		 */
		conn->smb2.mid = 1;
		conn->smb2.cur_credits = 0;
		tevent_req_set_callback(subreq, smbXcli_negprot_smb2_done, req);
		conn->dispatch_incoming = smb2cli_conn_dispatch_incoming;
		return smb2cli_conn_dispatch_incoming(conn, tmp_mem, inbuf);
	}

	DEBUG(10, ("Got non-SMB PDU\n"));
	return NT_STATUS_INVALID_NETWORK_RESPONSE;
}

NTSTATUS smbXcli_negprot_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS smbXcli_negprot(struct smbXcli_conn *conn,
			 uint32_t timeout_msec,
			 enum protocol_types min_protocol,
			 enum protocol_types max_protocol)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	bool ok;

	if (smbXcli_conn_has_async_calls(conn)) {
		/*
		 * Can't use sync call while an async call is in flight
		 */
		status = NT_STATUS_INVALID_PARAMETER_MIX;
		goto fail;
	}
	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = smbXcli_negprot_send(frame, ev, conn, timeout_msec,
				   min_protocol, max_protocol,
				   WINDOWS_CLIENT_PURE_SMB2_NEGPROT_INITIAL_CREDIT_ASK);
	if (req == NULL) {
		goto fail;
	}
	ok = tevent_req_poll_ntstatus(req, ev, &status);
	if (!ok) {
		goto fail;
	}
	status = smbXcli_negprot_recv(req);
 fail:
	TALLOC_FREE(frame);
	return status;
}

struct smb2cli_validate_negotiate_info_state {
	struct smbXcli_conn *conn;
	DATA_BLOB in_input_buffer;
	DATA_BLOB in_output_buffer;
	DATA_BLOB out_input_buffer;
	DATA_BLOB out_output_buffer;
	uint16_t dialect;
};

static void smb2cli_validate_negotiate_info_done(struct tevent_req *subreq);

struct tevent_req *smb2cli_validate_negotiate_info_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct smbXcli_conn *conn,
						uint32_t timeout_msec,
						struct smbXcli_session *session,
						struct smbXcli_tcon *tcon)
{
	struct tevent_req *req;
	struct smb2cli_validate_negotiate_info_state *state;
	uint8_t *buf;
	uint16_t dialect_count = 0;
	struct tevent_req *subreq;
	bool _save_should_sign;
	size_t i;

	req = tevent_req_create(mem_ctx, &state,
				struct smb2cli_validate_negotiate_info_state);
	if (req == NULL) {
		return NULL;
	}
	state->conn = conn;

	state->in_input_buffer = data_blob_talloc_zero(state,
					4 + 16 + 1 + 1 + 2);
	if (tevent_req_nomem(state->in_input_buffer.data, req)) {
		return tevent_req_post(req, ev);
	}
	buf = state->in_input_buffer.data;

	if (state->conn->max_protocol >= PROTOCOL_SMB2_22) {
		SIVAL(buf, 0, conn->smb2.client.capabilities);
	} else {
		SIVAL(buf, 0, 0); /* Capabilities */
	}
	if (state->conn->max_protocol >= PROTOCOL_SMB2_10) {
		NTSTATUS status;
		DATA_BLOB blob;

		status = GUID_to_ndr_blob(&conn->smb2.client.guid,
					  state, &blob);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}
		memcpy(buf+4, blob.data, 16); /* ClientGuid */
	} else {
		memset(buf+4, 0, 16);	/* ClientGuid */
	}
	if (state->conn->min_protocol >= PROTOCOL_SMB2_02) {
		SCVAL(buf, 20, conn->smb2.client.security_mode);
	} else {
		SCVAL(buf, 20, 0);
	}
	SCVAL(buf, 21, 0); /* reserved */

	for (i=0; i < ARRAY_SIZE(smb2cli_prots); i++) {
		bool ok;
		size_t ofs;

		if (smb2cli_prots[i].proto < state->conn->min_protocol) {
			continue;
		}

		if (smb2cli_prots[i].proto > state->conn->max_protocol) {
			continue;
		}

		if (smb2cli_prots[i].proto == state->conn->protocol) {
			state->dialect = smb2cli_prots[i].smb2_dialect;
		}

		ofs = state->in_input_buffer.length;
		ok = data_blob_realloc(state, &state->in_input_buffer,
				       ofs + 2);
		if (!ok) {
			tevent_req_oom(req);
			return tevent_req_post(req, ev);
		}

		buf = state->in_input_buffer.data;
		SSVAL(buf, ofs, smb2cli_prots[i].smb2_dialect);

		dialect_count++;
	}
	buf = state->in_input_buffer.data;
	SSVAL(buf, 22, dialect_count);

	_save_should_sign = smb2cli_tcon_is_signing_on(tcon);
	smb2cli_tcon_should_sign(tcon, true);
	subreq = smb2cli_ioctl_send(state, ev, conn,
				    timeout_msec, session, tcon,
				    UINT64_MAX, /* in_fid_persistent */
				    UINT64_MAX, /* in_fid_volatile */
				    FSCTL_VALIDATE_NEGOTIATE_INFO,
				    0, /* in_max_input_length */
				    &state->in_input_buffer,
				    24, /* in_max_output_length */
				    &state->in_output_buffer,
				    SMB2_IOCTL_FLAG_IS_FSCTL);
	smb2cli_tcon_should_sign(tcon, _save_should_sign);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				smb2cli_validate_negotiate_info_done,
				req);

	return req;
}

static void smb2cli_validate_negotiate_info_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb2cli_validate_negotiate_info_state *state =
		tevent_req_data(req,
		struct smb2cli_validate_negotiate_info_state);
	NTSTATUS status;
	const uint8_t *buf;
	uint32_t capabilities;
	DATA_BLOB guid_blob;
	struct GUID server_guid;
	uint16_t security_mode;
	uint16_t dialect;

	status = smb2cli_ioctl_recv(subreq, state,
				    &state->out_input_buffer,
				    &state->out_output_buffer);
	TALLOC_FREE(subreq);

	/*
	 * This response must be signed correctly for
	 * these "normal" error codes to be processed.
	 * If the packet wasn't signed correctly we will get
	 * NT_STATUS_ACCESS_DENIED or NT_STATUS_HMAC_NOT_SUPPORTED,
	 * or NT_STATUS_INVALID_NETWORK_RESPONSE
	 * from smb2_signing_check_pdu().
	 *
	 * We must never ignore the above errors here.
	 */

	if (NT_STATUS_EQUAL(status, NT_STATUS_FILE_CLOSED)) {
		/*
		 * The response was signed, but not supported
		 *
		 * Older Windows and Samba releases return
		 * NT_STATUS_FILE_CLOSED.
		 */
		tevent_req_done(req);
		return;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_DEVICE_REQUEST)) {
		/*
		 * The response was signed, but not supported
		 *
		 * This is returned by the NTVFS based Samba 4.x file server
		 * for file shares.
		 */
		tevent_req_done(req);
		return;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_FS_DRIVER_REQUIRED)) {
		/*
		 * The response was signed, but not supported
		 *
		 * This is returned by the NTVFS based Samba 4.x file server
		 * for ipc shares.
		 */
		tevent_req_done(req);
		return;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		/*
		 * The response was signed, but not supported
		 *
		 * This might be returned by older Windows versions or by
		 * NetApp SMB server implementations.
		 *
		 * See
		 *
		 * https://blogs.msdn.microsoft.com/openspecification/2012/06/28/smb3-secure-dialect-negotiation/
		 *
		 */
		tevent_req_done(req);
		return;
	}
	if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_PARAMETER)) {
		/*
		 * The response was signed, but not supported
		 *
		 * This might be returned by NetApp Ontap 7.3.7 SMB server
		 * implementations.
		 *
		 * BUG: https://bugzilla.samba.org/show_bug.cgi?id=14607
		 *
		 */
		tevent_req_done(req);
		return;
	}
	if (tevent_req_nterror(req, status)) {
		return;
	}

	if (state->out_output_buffer.length != 24) {
		tevent_req_nterror(req, NT_STATUS_INVALID_NETWORK_RESPONSE);
		return;
	}

	buf = state->out_output_buffer.data;

	capabilities = IVAL(buf, 0);
	guid_blob = data_blob_const(buf + 4, 16);
	status = GUID_from_data_blob(&guid_blob, &server_guid);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	security_mode = CVAL(buf, 20);
	dialect = SVAL(buf, 22);

	if (capabilities != state->conn->smb2.server.capabilities) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	if (!GUID_equal(&server_guid, &state->conn->smb2.server.guid)) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	if (security_mode != state->conn->smb2.server.security_mode) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	if (dialect != state->dialect) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return;
	}

	tevent_req_done(req);
}

NTSTATUS smb2cli_validate_negotiate_info_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static int smbXcli_session_destructor(struct smbXcli_session *session)
{
	if (session->conn == NULL) {
		return 0;
	}

	DLIST_REMOVE(session->conn->sessions, session);
	return 0;
}

struct smbXcli_session *smbXcli_session_create(TALLOC_CTX *mem_ctx,
					       struct smbXcli_conn *conn)
{
	struct smbXcli_session *session;

	session = talloc_zero(mem_ctx, struct smbXcli_session);
	if (session == NULL) {
		return NULL;
	}
	session->smb2 = talloc_zero(session, struct smb2cli_session);
	if (session->smb2 == NULL) {
		talloc_free(session);
		return NULL;
	}
	talloc_set_destructor(session, smbXcli_session_destructor);

	session->smb2->signing_key = talloc_zero(session,
						 struct smb2_signing_key);
	if (session->smb2->signing_key == NULL) {
		talloc_free(session);
		return NULL;
	}
	talloc_set_destructor(session->smb2->signing_key,
			      smb2_signing_key_destructor);

	DLIST_ADD_END(conn->sessions, session);
	session->conn = conn;

	session->smb2_channel.signing_key =
		talloc_zero(session, struct smb2_signing_key);
	if (session->smb2_channel.signing_key == NULL) {
		talloc_free(session);
		return NULL;
	}
	talloc_set_destructor(session->smb2_channel.signing_key,
			      smb2_signing_key_destructor);

	memcpy(session->smb2_channel.preauth_sha512,
	       conn->smb2.preauth_sha512,
	       sizeof(session->smb2_channel.preauth_sha512));

	return session;
}

struct smbXcli_session *smbXcli_session_shallow_copy(TALLOC_CTX *mem_ctx,
						struct smbXcli_session *src)
{
	struct smbXcli_session *session;
	struct timespec ts;
	NTTIME nt;

	session = talloc_zero(mem_ctx, struct smbXcli_session);
	if (session == NULL) {
		return NULL;
	}
	session->smb2 = talloc_zero(session, struct smb2cli_session);
	if (session->smb2 == NULL) {
		talloc_free(session);
		return NULL;
	}

	/*
	 * Note we keep a pointer to the session keys of the
	 * main session and rely on the caller to free the
	 * shallow copy first!
	 */
	session->conn = src->conn;
	*session->smb2 = *src->smb2;
	session->smb2_channel = src->smb2_channel;
	session->disconnect_expired = src->disconnect_expired;

	/*
	 * This is only supposed to be called in test code
	 * but we should not reuse nonces!
	 *
	 * Add the current timestamp as NTTIME to nonce_high
	 * and set nonce_low to a value we can recognize in captures.
	 */
	clock_gettime_mono(&ts);
	nt = unix_timespec_to_nt_time(ts);
	nt &= session->smb2->nonce_high_max;
	if (nt == session->smb2->nonce_high_max || nt < UINT8_MAX) {
		talloc_free(session);
		return NULL;
	}
	session->smb2->nonce_high += nt;
	session->smb2->nonce_low = UINT32_MAX;

	DLIST_ADD_END(src->conn->sessions, session);
	talloc_set_destructor(session, smbXcli_session_destructor);

	return session;
}

bool smbXcli_session_is_guest(struct smbXcli_session *session)
{
	if (session == NULL) {
		return false;
	}

	if (session->conn == NULL) {
		return false;
	}

	if (session->conn->mandatory_signing) {
		return false;
	}

	if (session->conn->protocol >= PROTOCOL_SMB2_02) {
		if (session->smb2->session_flags & SMB2_SESSION_FLAG_IS_GUEST) {
			return true;
		}
		return false;
	}

	if (session->smb1.action & SMB_SETUP_GUEST) {
		return true;
	}

	return false;
}

bool smbXcli_session_is_authenticated(struct smbXcli_session *session)
{
	const DATA_BLOB *application_key;

	if (session == NULL) {
		return false;
	}

	if (session->conn == NULL) {
		return false;
	}

	/*
	 * If we have an application key we had a session key negotiated
	 * at auth time.
	 */
	if (session->conn->protocol >= PROTOCOL_SMB2_02) {
		application_key = &session->smb2->application_key;
	} else {
		application_key = &session->smb1.application_key;
	}

	if (application_key->length == 0) {
		return false;
	}

	return true;
}

NTSTATUS smb2cli_session_signing_key(struct smbXcli_session *session,
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *key)
{
	const struct smb2_signing_key *sig = NULL;

	if (session->conn == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	/*
	 * Use channel signing key if there is one, otherwise fallback
	 * to session.
	 */

	if (smb2_signing_key_valid(session->smb2_channel.signing_key)) {
		sig = session->smb2_channel.signing_key;
	} else if (smb2_signing_key_valid(session->smb2->signing_key)) {
		sig = session->smb2->signing_key;
	} else {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	*key = data_blob_dup_talloc(mem_ctx, sig->blob);
	if (key->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

NTSTATUS smb2cli_session_encryption_key(struct smbXcli_session *session,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *key)
{
	if (session->conn == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (session->conn->protocol < PROTOCOL_SMB3_00) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (!smb2_signing_key_valid(session->smb2->encryption_key)) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	*key = data_blob_dup_talloc(mem_ctx, session->smb2->encryption_key->blob);
	if (key->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

NTSTATUS smb2cli_session_decryption_key(struct smbXcli_session *session,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *key)
{
	if (session->conn == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (session->conn->protocol < PROTOCOL_SMB3_00) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (!smb2_signing_key_valid(session->smb2->decryption_key)) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	*key = data_blob_dup_talloc(mem_ctx, session->smb2->decryption_key->blob);
	if (key->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

NTSTATUS smbXcli_session_application_key(struct smbXcli_session *session,
					 TALLOC_CTX *mem_ctx,
					 DATA_BLOB *key)
{
	const DATA_BLOB *application_key;

	*key = data_blob_null;

	if (session->conn == NULL) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	if (session->conn->protocol >= PROTOCOL_SMB2_02) {
		application_key = &session->smb2->application_key;
	} else {
		application_key = &session->smb1.application_key;
	}

	if (application_key->length == 0) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}

	*key = data_blob_dup_talloc(mem_ctx, *application_key);
	if (key->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

void smbXcli_session_set_disconnect_expired(struct smbXcli_session *session)
{
	session->disconnect_expired = true;
}

uint16_t smb1cli_session_current_id(struct smbXcli_session *session)
{
	return session->smb1.session_id;
}

void smb1cli_session_set_id(struct smbXcli_session *session,
			    uint16_t session_id)
{
	session->smb1.session_id = session_id;
}

void smb1cli_session_set_action(struct smbXcli_session *session,
				uint16_t action)
{
	session->smb1.action = action;
}

NTSTATUS smb1cli_session_set_session_key(struct smbXcli_session *session,
					 const DATA_BLOB _session_key)
{
	struct smbXcli_conn *conn = session->conn;
	uint8_t session_key[16];

	if (conn == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (session->smb1.application_key.length != 0) {
		/*
		 * TODO: do not allow this...
		 *
		 * return NT_STATUS_INVALID_PARAMETER_MIX;
		 */
		data_blob_clear_free(&session->smb1.application_key);
		session->smb1.protected_key = false;
	}

	if (_session_key.length == 0) {
		return NT_STATUS_OK;
	}

	ZERO_STRUCT(session_key);
	memcpy(session_key, _session_key.data,
	       MIN(_session_key.length, sizeof(session_key)));

	session->smb1.application_key = data_blob_talloc(session,
							 session_key,
							 sizeof(session_key));
	ZERO_STRUCT(session_key);
	if (session->smb1.application_key.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	session->smb1.protected_key = false;

	return NT_STATUS_OK;
}

NTSTATUS smb1cli_session_protect_session_key(struct smbXcli_session *session)
{
	NTSTATUS status;

	if (session->smb1.protected_key) {
		/* already protected */
		return NT_STATUS_OK;
	}

	if (session->smb1.application_key.length != 16) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	status = smb_key_derivation(session->smb1.application_key.data,
				    session->smb1.application_key.length,
				    session->smb1.application_key.data);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	session->smb1.protected_key = true;

	return NT_STATUS_OK;
}

uint8_t smb2cli_session_security_mode(struct smbXcli_session *session)
{
	struct smbXcli_conn *conn = session->conn;
	uint8_t security_mode = 0;

	if (conn == NULL) {
		return security_mode;
	}

	security_mode = SMB2_NEGOTIATE_SIGNING_ENABLED;
	if (conn->mandatory_signing) {
		security_mode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
	}
	if (session->smb2->should_sign) {
		security_mode |= SMB2_NEGOTIATE_SIGNING_REQUIRED;
	}

	return security_mode;
}

uint64_t smb2cli_session_current_id(struct smbXcli_session *session)
{
	return session->smb2->session_id;
}

uint16_t smb2cli_session_get_flags(struct smbXcli_session *session)
{
	return session->smb2->session_flags;
}

void smb2cli_session_set_id_and_flags(struct smbXcli_session *session,
				      uint64_t session_id,
				      uint16_t session_flags)
{
	session->smb2->session_id = session_id;
	session->smb2->session_flags = session_flags;
}

void smb2cli_session_increment_channel_sequence(struct smbXcli_session *session)
{
	session->smb2->channel_sequence += 1;
}

uint16_t smb2cli_session_reset_channel_sequence(struct smbXcli_session *session,
						uint16_t channel_sequence)
{
	uint16_t prev_cs;

	prev_cs = session->smb2->channel_sequence;
	session->smb2->channel_sequence = channel_sequence;

	return prev_cs;
}

uint16_t smb2cli_session_current_channel_sequence(struct smbXcli_session *session)
{
	return session->smb2->channel_sequence;
}

void smb2cli_session_start_replay(struct smbXcli_session *session)
{
	session->smb2->replay_active = true;
}

void smb2cli_session_stop_replay(struct smbXcli_session *session)
{
	session->smb2->replay_active = false;
}

void smb2cli_session_require_signed_response(struct smbXcli_session *session,
					     bool require_signed_response)
{
	session->smb2->require_signed_response = require_signed_response;
}

NTSTATUS smb2cli_session_update_preauth(struct smbXcli_session *session,
					const struct iovec *iov)
{
	gnutls_hash_hd_t hash_hnd = NULL;
	size_t i;
	int rc;

	if (session->conn == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (session->conn->protocol < PROTOCOL_SMB3_10) {
		return NT_STATUS_OK;
	}

	if (smb2_signing_key_valid(session->smb2_channel.signing_key)) {
		return NT_STATUS_OK;
	}

	rc = gnutls_hash_init(&hash_hnd,
			      GNUTLS_DIG_SHA512);
	if (rc < 0) {
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
	}

	rc = gnutls_hash(hash_hnd,
			 session->smb2_channel.preauth_sha512,
			 sizeof(session->smb2_channel.preauth_sha512));
	if (rc < 0) {
		gnutls_hash_deinit(hash_hnd, NULL);
		return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
	}
	for (i = 0; i < 3; i++) {
		rc = gnutls_hash(hash_hnd,
				 iov[i].iov_base,
				 iov[i].iov_len);
		if (rc < 0) {
			gnutls_hash_deinit(hash_hnd, NULL);
			return gnutls_error_to_ntstatus(rc, NT_STATUS_HASH_NOT_SUPPORTED);
		}
	}
	gnutls_hash_deinit(hash_hnd, session->smb2_channel.preauth_sha512);

	return NT_STATUS_OK;
}

NTSTATUS smb2cli_session_set_session_key(struct smbXcli_session *session,
					 const DATA_BLOB _session_key,
					 const struct iovec *recv_iov)
{
	struct smbXcli_conn *conn = session->conn;
	uint16_t no_sign_flags = 0;
	uint8_t session_key[16];
	bool check_signature = true;
	uint32_t hdr_flags;
	NTSTATUS status;
	struct _derivation {
		DATA_BLOB label;
		DATA_BLOB context;
	};
	struct {
		struct _derivation signing;
		struct _derivation encryption;
		struct _derivation decryption;
		struct _derivation application;
	} derivation = {
		.signing.label.length = 0,
	};
	size_t nonce_size = 0;

	if (conn == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (recv_iov[0].iov_len != SMB2_HDR_BODY) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (!conn->mandatory_signing) {
		/*
		 * only allow guest sessions without
		 * mandatory signing.
		 *
		 * If we try an authentication with username != ""
		 * and the server let us in without verifying the
		 * password we don't have a negotiated session key
		 * for signing.
		 */
		no_sign_flags = SMB2_SESSION_FLAG_IS_GUEST;
	}

	if (session->smb2->session_flags & no_sign_flags) {
		session->smb2->should_sign = false;
		return NT_STATUS_OK;
	}

	if (smb2_signing_key_valid(session->smb2->signing_key)) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (conn->protocol >= PROTOCOL_SMB3_10) {
		struct _derivation *d;
		DATA_BLOB p;

		p = data_blob_const(session->smb2_channel.preauth_sha512,
				sizeof(session->smb2_channel.preauth_sha512));

		d = &derivation.signing;
		d->label = data_blob_string_const_null("SMBSigningKey");
		d->context = p;

		d = &derivation.encryption;
		d->label = data_blob_string_const_null("SMBC2SCipherKey");
		d->context = p;

		d = &derivation.decryption;
		d->label = data_blob_string_const_null("SMBS2CCipherKey");
		d->context = p;

		d = &derivation.application;
		d->label = data_blob_string_const_null("SMBAppKey");
		d->context = p;

	} else if (conn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d;

		d = &derivation.signing;
		d->label = data_blob_string_const_null("SMB2AESCMAC");
		d->context = data_blob_string_const_null("SmbSign");

		d = &derivation.encryption;
		d->label = data_blob_string_const_null("SMB2AESCCM");
		d->context = data_blob_string_const_null("ServerIn ");

		d = &derivation.decryption;
		d->label = data_blob_string_const_null("SMB2AESCCM");
		d->context = data_blob_string_const_null("ServerOut");

		d = &derivation.application;
		d->label = data_blob_string_const_null("SMB2APP");
		d->context = data_blob_string_const_null("SmbRpc");
	}

	ZERO_STRUCT(session_key);
	memcpy(session_key, _session_key.data,
	       MIN(_session_key.length, sizeof(session_key)));

	session->smb2->signing_key->blob =
		data_blob_talloc(session->smb2->signing_key,
				 session_key,
				 sizeof(session_key));
	if (!smb2_signing_key_valid(session->smb2->signing_key)) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}

	if (conn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.signing;

		status = smb2_key_derivation(session_key, sizeof(session_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     session->smb2->signing_key->blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	session->smb2->encryption_key =
		talloc_zero(session, struct smb2_signing_key);
	if (session->smb2->encryption_key == NULL) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(session->smb2->encryption_key,
			      smb2_signing_key_destructor);

	session->smb2->encryption_key->blob =
		data_blob_dup_talloc(session->smb2->encryption_key,
				     session->smb2->signing_key->blob);
	if (!smb2_signing_key_valid(session->smb2->encryption_key)) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}

	if (conn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.encryption;

		status = smb2_key_derivation(session_key, sizeof(session_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     session->smb2->encryption_key->blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	session->smb2->decryption_key =
		talloc_zero(session, struct smb2_signing_key);
	if (session->smb2->decryption_key == NULL) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(session->smb2->decryption_key,
			      smb2_signing_key_destructor);

	session->smb2->decryption_key->blob =
		data_blob_dup_talloc(session->smb2->decryption_key,
				     session->smb2->signing_key->blob);
	if (!smb2_signing_key_valid(session->smb2->decryption_key)) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}

	if (conn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.decryption;

		status = smb2_key_derivation(session_key, sizeof(session_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     session->smb2->decryption_key->blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	session->smb2->application_key =
		data_blob_dup_talloc(session,
				     session->smb2->signing_key->blob);
	if (session->smb2->application_key.data == NULL) {
		ZERO_STRUCT(session_key);
		return NT_STATUS_NO_MEMORY;
	}

	if (conn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.application;

		status = smb2_key_derivation(session_key, sizeof(session_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     session->smb2->application_key.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	ZERO_STRUCT(session_key);

	session->smb2_channel.signing_key->blob =
		data_blob_dup_talloc(session->smb2_channel.signing_key,
				     session->smb2->signing_key->blob);
	if (!smb2_signing_key_valid(session->smb2_channel.signing_key)) {
		return NT_STATUS_NO_MEMORY;
	}

	check_signature = conn->mandatory_signing;

	hdr_flags = IVAL(recv_iov[0].iov_base, SMB2_HDR_FLAGS);
	if (hdr_flags & SMB2_HDR_FLAG_SIGNED) {
		/*
		 * Sadly some vendors don't sign the
		 * final SMB2 session setup response
		 *
		 * At least Windows and Samba are always doing this
		 * if there's a session key available.
		 *
		 * We only check the signature if it's mandatory
		 * or SMB2_HDR_FLAG_SIGNED is provided.
		 */
		check_signature = true;
	}

	if (conn->protocol >= PROTOCOL_SMB3_10) {
		check_signature = true;
	}

	if (check_signature) {
		status = smb2_signing_check_pdu(session->smb2_channel.signing_key,
						session->conn->protocol,
						recv_iov, 3);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	session->smb2->should_sign = false;
	session->smb2->should_encrypt = false;

	if (conn->desire_signing) {
		session->smb2->should_sign = true;
	}

	if (conn->smb2.server.security_mode & SMB2_NEGOTIATE_SIGNING_REQUIRED) {
		session->smb2->should_sign = true;
	}

	if (session->smb2->session_flags & SMB2_SESSION_FLAG_ENCRYPT_DATA) {
		session->smb2->should_encrypt = true;
	}

	if (conn->protocol < PROTOCOL_SMB2_24) {
		session->smb2->should_encrypt = false;
	}

	if (conn->smb2.server.cipher == 0) {
		session->smb2->should_encrypt = false;
	}

	/*
	 * CCM and GCM algorithms must never have their
	 * nonce wrap, or the security of the whole
	 * communication and the keys is destroyed.
	 * We must drop the connection once we have
	 * transfered too much data.
	 *
	 * NOTE: We assume nonces greater than 8 bytes.
	 */
	generate_nonce_buffer((uint8_t *)&session->smb2->nonce_high_random,
			      sizeof(session->smb2->nonce_high_random));
	switch (conn->smb2.server.cipher) {
	case SMB2_ENCRYPTION_AES128_CCM:
		nonce_size = SMB2_AES_128_CCM_NONCE_SIZE;
		break;
	case SMB2_ENCRYPTION_AES128_GCM:
		nonce_size = gnutls_cipher_get_iv_size(GNUTLS_CIPHER_AES_128_GCM);
		break;
	default:
		nonce_size = 0;
		break;
	}
	session->smb2->nonce_high_max = SMB2_NONCE_HIGH_MAX(nonce_size);
	session->smb2->nonce_high = 0;
	session->smb2->nonce_low = 0;

	return NT_STATUS_OK;
}

NTSTATUS smb2cli_session_create_channel(TALLOC_CTX *mem_ctx,
					struct smbXcli_session *session1,
					struct smbXcli_conn *conn,
					struct smbXcli_session **_session2)
{
	struct smbXcli_session *session2;

	if (!smb2_signing_key_valid(session1->smb2->signing_key)) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (conn == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	session2 = talloc_zero(mem_ctx, struct smbXcli_session);
	if (session2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	session2->smb2 = talloc_reference(session2, session1->smb2);
	if (session2->smb2 == NULL) {
		talloc_free(session2);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_set_destructor(session2, smbXcli_session_destructor);
	DLIST_ADD_END(conn->sessions, session2);
	session2->conn = conn;

	session2->smb2_channel.signing_key =
		talloc_zero(session2, struct smb2_signing_key);
	if (session2->smb2_channel.signing_key == NULL) {
		talloc_free(session2);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(session2->smb2_channel.signing_key,
			      smb2_signing_key_destructor);

	memcpy(session2->smb2_channel.preauth_sha512,
	       conn->smb2.preauth_sha512,
	       sizeof(session2->smb2_channel.preauth_sha512));

	*_session2 = session2;
	return NT_STATUS_OK;
}

NTSTATUS smb2cli_session_set_channel_key(struct smbXcli_session *session,
					 const DATA_BLOB _channel_key,
					 const struct iovec *recv_iov)
{
	struct smbXcli_conn *conn = session->conn;
	uint8_t channel_key[16];
	NTSTATUS status;
	struct _derivation {
		DATA_BLOB label;
		DATA_BLOB context;
	};
	struct {
		struct _derivation signing;
	} derivation = {
		.signing.label.length = 0,
	};

	if (conn == NULL) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (smb2_signing_key_valid(session->smb2_channel.signing_key)) {
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (conn->protocol >= PROTOCOL_SMB3_10) {
		struct _derivation *d;
		DATA_BLOB p;

		p = data_blob_const(session->smb2_channel.preauth_sha512,
				sizeof(session->smb2_channel.preauth_sha512));

		d = &derivation.signing;
		d->label = data_blob_string_const_null("SMBSigningKey");
		d->context = p;
	} else if (conn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d;

		d = &derivation.signing;
		d->label = data_blob_string_const_null("SMB2AESCMAC");
		d->context = data_blob_string_const_null("SmbSign");
	}

	ZERO_STRUCT(channel_key);
	memcpy(channel_key, _channel_key.data,
	       MIN(_channel_key.length, sizeof(channel_key)));

	session->smb2_channel.signing_key->blob =
		data_blob_talloc(session->smb2_channel.signing_key,
				 channel_key,
				 sizeof(channel_key));
	if (!smb2_signing_key_valid(session->smb2_channel.signing_key)) {
		ZERO_STRUCT(channel_key);
		return NT_STATUS_NO_MEMORY;
	}

	if (conn->protocol >= PROTOCOL_SMB2_24) {
		struct _derivation *d = &derivation.signing;

		status = smb2_key_derivation(channel_key, sizeof(channel_key),
					     d->label.data, d->label.length,
					     d->context.data, d->context.length,
					     session->smb2_channel.signing_key->blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	ZERO_STRUCT(channel_key);

	status = smb2_signing_check_pdu(session->smb2_channel.signing_key,
					session->conn->protocol,
					recv_iov, 3);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return NT_STATUS_OK;
}

NTSTATUS smb2cli_session_encryption_on(struct smbXcli_session *session)
{
	if (!session->smb2->should_sign) {
		/*
		 * We need required signing on the session
		 * in order to prevent man in the middle attacks.
		 */
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (session->smb2->should_encrypt) {
		return NT_STATUS_OK;
	}

	if (session->conn->protocol < PROTOCOL_SMB2_24) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (session->conn->smb2.server.cipher == 0) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (!smb2_signing_key_valid(session->smb2->signing_key)) {
		return NT_STATUS_NOT_SUPPORTED;
	}
	session->smb2->should_encrypt = true;
	return NT_STATUS_OK;
}

struct smbXcli_tcon *smbXcli_tcon_create(TALLOC_CTX *mem_ctx)
{
	struct smbXcli_tcon *tcon;

	tcon = talloc_zero(mem_ctx, struct smbXcli_tcon);
	if (tcon == NULL) {
		return NULL;
	}

	return tcon;
}

/*
 * Return a deep structure copy of a struct smbXcli_tcon *
 */

struct smbXcli_tcon *smbXcli_tcon_copy(TALLOC_CTX *mem_ctx,
				const struct smbXcli_tcon *tcon_in)
{
	struct smbXcli_tcon *tcon;

	tcon = talloc_memdup(mem_ctx, tcon_in, sizeof(struct smbXcli_tcon));
	if (tcon == NULL) {
		return NULL;
	}

	/* Deal with the SMB1 strings. */
	if (tcon_in->smb1.service != NULL) {
		tcon->smb1.service = talloc_strdup(tcon, tcon_in->smb1.service);
		if (tcon->smb1.service == NULL) {
			TALLOC_FREE(tcon);
			return NULL;
		}
	}
	if (tcon->smb1.fs_type != NULL) {
		tcon->smb1.fs_type = talloc_strdup(tcon, tcon_in->smb1.fs_type);
		if (tcon->smb1.fs_type == NULL) {
			TALLOC_FREE(tcon);
			return NULL;
		}
	}
	return tcon;
}

void smbXcli_tcon_set_fs_attributes(struct smbXcli_tcon *tcon,
				    uint32_t fs_attributes)
{
	tcon->fs_attributes = fs_attributes;
}

uint32_t smbXcli_tcon_get_fs_attributes(struct smbXcli_tcon *tcon)
{
	return tcon->fs_attributes;
}

bool smbXcli_tcon_is_dfs_share(struct smbXcli_tcon *tcon)
{
	if (tcon == NULL) {
		return false;
	}

	if (tcon->is_smb1) {
		if (tcon->smb1.optional_support & SMB_SHARE_IN_DFS) {
			return true;
		}

		return false;
	}

	if (tcon->smb2.capabilities & SMB2_SHARE_CAP_DFS) {
		return true;
	}

	return false;
}

uint16_t smb1cli_tcon_current_id(struct smbXcli_tcon *tcon)
{
	return tcon->smb1.tcon_id;
}

void smb1cli_tcon_set_id(struct smbXcli_tcon *tcon, uint16_t tcon_id)
{
	tcon->is_smb1 = true;
	tcon->smb1.tcon_id = tcon_id;
}

bool smb1cli_tcon_set_values(struct smbXcli_tcon *tcon,
			     uint16_t tcon_id,
			     uint16_t optional_support,
			     uint32_t maximal_access,
			     uint32_t guest_maximal_access,
			     const char *service,
			     const char *fs_type)
{
	tcon->is_smb1 = true;
	tcon->fs_attributes = 0;
	tcon->smb1.tcon_id = tcon_id;
	tcon->smb1.optional_support = optional_support;
	tcon->smb1.maximal_access = maximal_access;
	tcon->smb1.guest_maximal_access = guest_maximal_access;

	TALLOC_FREE(tcon->smb1.service);
	tcon->smb1.service = talloc_strdup(tcon, service);
	if (service != NULL && tcon->smb1.service == NULL) {
		return false;
	}

	TALLOC_FREE(tcon->smb1.fs_type);
	tcon->smb1.fs_type = talloc_strdup(tcon, fs_type);
	if (fs_type != NULL && tcon->smb1.fs_type == NULL) {
		return false;
	}

	return true;
}

uint32_t smb2cli_tcon_current_id(struct smbXcli_tcon *tcon)
{
	return tcon->smb2.tcon_id;
}

void smb2cli_tcon_set_id(struct smbXcli_tcon *tcon, uint32_t tcon_id)
{
	tcon->smb2.tcon_id = tcon_id;
}

uint32_t smb2cli_tcon_capabilities(struct smbXcli_tcon *tcon)
{
	return tcon->smb2.capabilities;
}

uint32_t smb2cli_tcon_flags(struct smbXcli_tcon *tcon)
{
	return tcon->smb2.flags;
}

void smb2cli_tcon_set_values(struct smbXcli_tcon *tcon,
			     struct smbXcli_session *session,
			     uint32_t tcon_id,
			     uint8_t type,
			     uint32_t flags,
			     uint32_t capabilities,
			     uint32_t maximal_access)
{
	tcon->is_smb1 = false;
	tcon->fs_attributes = 0;
	tcon->smb2.tcon_id = tcon_id;
	tcon->smb2.type = type;
	tcon->smb2.flags = flags;
	tcon->smb2.capabilities = capabilities;
	tcon->smb2.maximal_access = maximal_access;

	tcon->smb2.should_sign = false;
	tcon->smb2.should_encrypt = false;

	if (session == NULL) {
		return;
	}

	tcon->smb2.should_sign = session->smb2->should_sign;
	tcon->smb2.should_encrypt = session->smb2->should_encrypt;

	if (flags & SMB2_SHAREFLAG_ENCRYPT_DATA) {
		tcon->smb2.should_encrypt = true;
	}
}

void smb2cli_tcon_should_sign(struct smbXcli_tcon *tcon,
			      bool should_sign)
{
	tcon->smb2.should_sign = should_sign;
}

bool smb2cli_tcon_is_signing_on(struct smbXcli_tcon *tcon)
{
	if (tcon->smb2.should_encrypt) {
		return true;
	}

	return tcon->smb2.should_sign;
}

void smb2cli_tcon_should_encrypt(struct smbXcli_tcon *tcon,
				 bool should_encrypt)
{
	tcon->smb2.should_encrypt = should_encrypt;
}

bool smb2cli_tcon_is_encryption_on(struct smbXcli_tcon *tcon)
{
	return tcon->smb2.should_encrypt;
}

void smb2cli_conn_set_mid(struct smbXcli_conn *conn, uint64_t mid)
{
	conn->smb2.mid = mid;
}

uint64_t smb2cli_conn_get_mid(struct smbXcli_conn *conn)
{
	return conn->smb2.mid;
}

NTSTATUS smb2cli_parse_dyn_buffer(uint32_t dyn_offset,
				  const DATA_BLOB dyn_buffer,
				  uint32_t min_offset,
				  uint32_t buffer_offset,
				  uint32_t buffer_length,
				  uint32_t max_length,
				  uint32_t *next_offset,
				  DATA_BLOB *buffer)
{
	uint32_t offset;
	bool oob;

	*buffer = data_blob_null;
	*next_offset = dyn_offset;

	if (buffer_offset == 0) {
		/*
		 * If the offset is 0, we better ignore
		 * the buffer_length field.
		 */
		return NT_STATUS_OK;
	}

	if (buffer_length == 0) {
		/*
		 * If the length is 0, we better ignore
		 * the buffer_offset field.
		 */
		return NT_STATUS_OK;
	}

	if ((buffer_offset % 8) != 0) {
		/*
		 * The offset needs to be 8 byte aligned.
		 */
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	/*
	 * We used to enforce buffer_offset to be
	 * an exact match of the expected minimum,
	 * but the NetApp Ontap 7.3.7 SMB server
	 * gets the padding wrong and aligns the
	 * input_buffer_offset by a value of 8.
	 *
	 * So we just enforce that the offset is
	 * not lower than the expected value.
	 */
	SMB_ASSERT(min_offset >= dyn_offset);
	if (buffer_offset < min_offset) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	/*
	 * Make [input|output]_buffer_offset relative to "dyn_buffer"
	 */
	offset = buffer_offset - dyn_offset;
	oob = smb_buffer_oob(dyn_buffer.length, offset, buffer_length);
	if (oob) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	/*
	 * Give the caller a hint what we consumed,
	 * the caller may need to add possible padding.
	 */
	*next_offset = buffer_offset + buffer_length;

	if (max_length == 0) {
		/*
		 * If max_input_length is 0 we ignore the
		 * input_buffer_length, because Windows 2008 echos the
		 * DCERPC request from the requested input_buffer to
		 * the response input_buffer.
		 *
		 * We just use the same logic also for max_output_length...
		 */
		buffer_length = 0;
	}

	if (buffer_length > max_length) {
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	*buffer = (DATA_BLOB) {
		.data = dyn_buffer.data + offset,
		.length = buffer_length,
	};
	return NT_STATUS_OK;
}
