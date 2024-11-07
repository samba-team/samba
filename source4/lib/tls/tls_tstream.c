/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2010

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
#include "system/filesys.h"
#include "system/time.h"
#include "lib/util/util_file.h"
#include "../util/tevent_unix.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/tsocket/tsocket_internal.h"
#include "../lib/util/util_net.h"
#include "lib/tls/tls.h"
#include "lib/param/param.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
#include "lib/crypto/gnutls_helpers.h"

#define DH_BITS 2048

const char *tls_verify_peer_string(enum tls_verify_peer_state verify_peer)
{
	switch (verify_peer) {
	case TLS_VERIFY_PEER_NO_CHECK:
		return TLS_VERIFY_PEER_NO_CHECK_STRING;

	case TLS_VERIFY_PEER_CA_ONLY:
		return TLS_VERIFY_PEER_CA_ONLY_STRING;

	case TLS_VERIFY_PEER_CA_AND_NAME_IF_AVAILABLE:
		return TLS_VERIFY_PEER_CA_AND_NAME_IF_AVAILABLE_STRING;

	case TLS_VERIFY_PEER_CA_AND_NAME:
		return TLS_VERIFY_PEER_CA_AND_NAME_STRING;

	case TLS_VERIFY_PEER_AS_STRICT_AS_POSSIBLE:
		return TLS_VERIFY_PEER_AS_STRICT_AS_POSSIBLE_STRING;
	}

	return "unknown tls_verify_peer_state";
}

static const struct tstream_context_ops tstream_tls_ops;

struct tstream_tls {
	struct tstream_context *plain_stream;
	int error;

	gnutls_session_t tls_session;

	bool is_server;

	enum tls_verify_peer_state verify_peer;
	const char *peer_name;

	DATA_BLOB channel_bindings;

	struct tevent_context *current_ev;

	struct tevent_immediate *retry_im;

	struct {
		struct tevent_req *mgmt_req;
	} waiting_flush;

	struct {
		uint8_t *buf;
		off_t ofs;
		struct iovec iov;
		struct tevent_req *subreq;
	} push;

	struct {
		uint8_t *buf;
		struct iovec iov;
		struct tevent_req *subreq;
	} pull;

	struct {
		struct tevent_req *req;
	} handshake;

	struct {
		off_t ofs;
		size_t left;
		uint8_t buffer[1024];
		struct tevent_req *req;
	} write;

	struct {
		off_t ofs;
		size_t left;
		uint8_t buffer[1024];
		struct tevent_req *req;
	} read;

	struct {
		struct tevent_req *req;
	} disconnect;
};

static void tstream_tls_retry_handshake(struct tstream_context *stream);
static void tstream_tls_retry_read(struct tstream_context *stream);
static void tstream_tls_retry_write(struct tstream_context *stream);
static void tstream_tls_retry_disconnect(struct tstream_context *stream);
static void tstream_tls_retry_trigger(struct tevent_context *ctx,
				      struct tevent_immediate *im,
				      void *private_data);

static void tstream_tls_retry(struct tstream_context *stream, bool deferred)
{

	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);

	if (tlss->push.subreq == NULL && tlss->pull.subreq == NULL) {
		if (tlss->waiting_flush.mgmt_req != NULL) {
			struct tevent_req *req = tlss->waiting_flush.mgmt_req;

			tlss->waiting_flush.mgmt_req = NULL;

			tevent_req_done(req);
			return;
		}
	}

	if (tlss->disconnect.req) {
		tstream_tls_retry_disconnect(stream);
		return;
	}

	if (tlss->handshake.req) {
		tstream_tls_retry_handshake(stream);
		return;
	}

	if (tlss->write.req && tlss->read.req && !deferred) {
		tevent_schedule_immediate(tlss->retry_im, tlss->current_ev,
					  tstream_tls_retry_trigger,
					  stream);
	}

	if (tlss->write.req) {
		tstream_tls_retry_write(stream);
		return;
	}

	if (tlss->read.req) {
		tstream_tls_retry_read(stream);
		return;
	}
}

static void tstream_tls_retry_trigger(struct tevent_context *ctx,
				      struct tevent_immediate *im,
				      void *private_data)
{
	struct tstream_context *stream =
		talloc_get_type_abort(private_data,
		struct tstream_context);

	tstream_tls_retry(stream, true);
}

static void tstream_tls_push_done(struct tevent_req *subreq);

static ssize_t tstream_tls_push_function(gnutls_transport_ptr_t ptr,
					 const void *buf, size_t size)
{
	struct tstream_context *stream =
		talloc_get_type_abort(ptr,
		struct tstream_context);
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	struct tevent_req *subreq = NULL;
	uint8_t *nbuf;
	size_t len;

	if (tlss->error != 0) {
		errno = tlss->error;
		return -1;
	}

	if (tlss->push.subreq) {
		errno = EAGAIN;
		return -1;
	}

	len = MIN(size, UINT16_MAX - tlss->push.ofs);

	if (len == 0) {
		errno = EAGAIN;
		return -1;
	}

	nbuf = talloc_realloc(tlss, tlss->push.buf,
			      uint8_t, tlss->push.ofs + len);
	if (nbuf == NULL) {
		if (tlss->push.buf) {
			errno = EAGAIN;
			return -1;
		}

		return -1;
	}
	tlss->push.buf = nbuf;

	memcpy(tlss->push.buf + tlss->push.ofs, buf, len);
	tlss->push.ofs += len;

	tlss->push.iov.iov_base = (char *)tlss->push.buf;
	tlss->push.iov.iov_len = tlss->push.ofs;

	subreq = tstream_writev_send(tlss,
				     tlss->current_ev,
				     tlss->plain_stream,
				     &tlss->push.iov, 1);
	if (subreq == NULL) {
		errno = ENOMEM;
		return -1;
	}
	tevent_req_set_callback(subreq, tstream_tls_push_done, stream);

	tlss->push.subreq = subreq;
	return len;
}

static void tstream_tls_push_done(struct tevent_req *subreq)
{
	struct tstream_context *stream =
		tevent_req_callback_data(subreq,
		struct tstream_context);
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	int ret;
	int sys_errno;

	tlss->push.subreq = NULL;
	ZERO_STRUCT(tlss->push.iov);
	TALLOC_FREE(tlss->push.buf);
	tlss->push.ofs = 0;

	ret = tstream_writev_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tlss->error = sys_errno;
		tstream_tls_retry(stream, false);
		return;
	}

	tstream_tls_retry(stream, false);
}

static void tstream_tls_pull_done(struct tevent_req *subreq);

static ssize_t tstream_tls_pull_function(gnutls_transport_ptr_t ptr,
					 void *buf, size_t size)
{
	struct tstream_context *stream =
		talloc_get_type_abort(ptr,
		struct tstream_context);
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	struct tevent_req *subreq;
	size_t len;

	if (tlss->error != 0) {
		errno = tlss->error;
		return -1;
	}

	if (tlss->pull.subreq) {
		errno = EAGAIN;
		return -1;
	}

	if (tlss->pull.iov.iov_base) {
		uint8_t *b;
		size_t n;

		b = (uint8_t *)tlss->pull.iov.iov_base;

		n = MIN(tlss->pull.iov.iov_len, size);
		memcpy(buf, b, n);

		tlss->pull.iov.iov_len -= n;
		b += n;
		tlss->pull.iov.iov_base = (char *)b;
		if (tlss->pull.iov.iov_len == 0) {
			tlss->pull.iov.iov_base = NULL;
			TALLOC_FREE(tlss->pull.buf);
		}

		return n;
	}

	if (size == 0) {
		return 0;
	}

	len = MIN(size, UINT16_MAX);

	tlss->pull.buf = talloc_array(tlss, uint8_t, len);
	if (tlss->pull.buf == NULL) {
		return -1;
	}

	tlss->pull.iov.iov_base = (char *)tlss->pull.buf;
	tlss->pull.iov.iov_len = len;

	subreq = tstream_readv_send(tlss,
				    tlss->current_ev,
				    tlss->plain_stream,
				    &tlss->pull.iov, 1);
	if (subreq == NULL) {
		errno = ENOMEM;
		return -1;
	}
	tevent_req_set_callback(subreq, tstream_tls_pull_done, stream);

	tlss->pull.subreq = subreq;
	errno = EAGAIN;
	return -1;
}

static void tstream_tls_pull_done(struct tevent_req *subreq)
{
	struct tstream_context *stream =
		tevent_req_callback_data(subreq,
		struct tstream_context);
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	int ret;
	int sys_errno;

	tlss->pull.subreq = NULL;

	ret = tstream_readv_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tlss->error = sys_errno;
		tstream_tls_retry(stream, false);
		return;
	}

	tstream_tls_retry(stream, false);
}

static int tstream_tls_destructor(struct tstream_tls *tlss)
{
	if (tlss->tls_session) {
		gnutls_deinit(tlss->tls_session);
		tlss->tls_session = NULL;
	}

	return 0;
}

static ssize_t tstream_tls_pending_bytes(struct tstream_context *stream)
{
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	size_t ret;

	if (tlss->error != 0) {
		errno = tlss->error;
		return -1;
	}

	ret = gnutls_record_check_pending(tlss->tls_session);
	ret += tlss->read.left;

	return ret;
}

struct tstream_tls_readv_state {
	struct tstream_context *stream;

	struct iovec *vector;
	int count;

	int ret;
};

static void tstream_tls_readv_crypt_next(struct tevent_req *req);

static struct tevent_req *tstream_tls_readv_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *stream,
					struct iovec *vector,
					size_t count)
{
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	struct tevent_req *req;
	struct tstream_tls_readv_state *state;

	tlss->read.req = NULL;

	if (tlss->current_ev != ev) {
		SMB_ASSERT(tlss->push.subreq == NULL);
		SMB_ASSERT(tlss->pull.subreq == NULL);
	}

	tlss->current_ev = ev;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_tls_readv_state);
	if (req == NULL) {
		return NULL;
	}

	state->stream = stream;
	state->ret = 0;

	if (tlss->error != 0) {
		tevent_req_error(req, tlss->error);
		return tevent_req_post(req, ev);
	}

	/*
	 * we make a copy of the vector so we can change the structure
	 */
	state->vector = talloc_array(state, struct iovec, count);
	if (tevent_req_nomem(state->vector, req)) {
		return tevent_req_post(req, ev);
	}
	memcpy(state->vector, vector, sizeof(struct iovec) * count);
	state->count = count;

	tstream_tls_readv_crypt_next(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tstream_tls_readv_crypt_next(struct tevent_req *req)
{
	struct tstream_tls_readv_state *state =
		tevent_req_data(req,
		struct tstream_tls_readv_state);
	struct tstream_tls *tlss =
		tstream_context_data(state->stream,
		struct tstream_tls);

	/*
	 * copy the pending buffer first
	 */
	while (tlss->read.left > 0 && state->count > 0) {
		uint8_t *base = (uint8_t *)state->vector[0].iov_base;
		size_t len = MIN(tlss->read.left, state->vector[0].iov_len);

		memcpy(base, tlss->read.buffer + tlss->read.ofs, len);

		base += len;
		state->vector[0].iov_base = (char *) base;
		state->vector[0].iov_len -= len;

		tlss->read.ofs += len;
		tlss->read.left -= len;

		if (state->vector[0].iov_len == 0) {
			state->vector += 1;
			state->count -= 1;
		}

		state->ret += len;
	}

	if (state->count == 0) {
		tevent_req_done(req);
		return;
	}

	tlss->read.req = req;
	tstream_tls_retry_read(state->stream);
}

static void tstream_tls_retry_read(struct tstream_context *stream)
{
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	struct tevent_req *req = tlss->read.req;
	int ret;

	if (tlss->error != 0) {
		tevent_req_error(req, tlss->error);
		return;
	}

	tlss->read.left = 0;
	tlss->read.ofs = 0;

	ret = gnutls_record_recv(tlss->tls_session,
				 tlss->read.buffer,
				 sizeof(tlss->read.buffer));
	if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
		return;
	}

	tlss->read.req = NULL;

	if (gnutls_error_is_fatal(ret) != 0) {
		DEBUG(1,("TLS %s - %s\n", __location__, gnutls_strerror(ret)));
		tlss->error = EIO;
		tevent_req_error(req, tlss->error);
		return;
	}

	if (ret == 0) {
		tlss->error = EPIPE;
		tevent_req_error(req, tlss->error);
		return;
	}

	tlss->read.left = ret;
	tstream_tls_readv_crypt_next(req);
}

static int tstream_tls_readv_recv(struct tevent_req *req,
				  int *perrno)
{
	struct tstream_tls_readv_state *state =
		tevent_req_data(req,
		struct tstream_tls_readv_state);
	struct tstream_tls *tlss =
		tstream_context_data(state->stream,
		struct tstream_tls);
	int ret;

	tlss->read.req = NULL;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tstream_tls_writev_state {
	struct tstream_context *stream;

	struct iovec *vector;
	int count;

	int ret;
};

static void tstream_tls_writev_crypt_next(struct tevent_req *req);

static struct tevent_req *tstream_tls_writev_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *stream,
					const struct iovec *vector,
					size_t count)
{
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	struct tevent_req *req;
	struct tstream_tls_writev_state *state;

	tlss->write.req = NULL;

	if (tlss->current_ev != ev) {
		SMB_ASSERT(tlss->push.subreq == NULL);
		SMB_ASSERT(tlss->pull.subreq == NULL);
	}

	tlss->current_ev = ev;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_tls_writev_state);
	if (req == NULL) {
		return NULL;
	}

	state->stream = stream;
	state->ret = 0;

	if (tlss->error != 0) {
		tevent_req_error(req, tlss->error);
		return tevent_req_post(req, ev);
	}

	/*
	 * we make a copy of the vector so we can change the structure
	 */
	state->vector = talloc_array(state, struct iovec, count);
	if (tevent_req_nomem(state->vector, req)) {
		return tevent_req_post(req, ev);
	}
	memcpy(state->vector, vector, sizeof(struct iovec) * count);
	state->count = count;

	tstream_tls_writev_crypt_next(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tstream_tls_writev_crypt_next(struct tevent_req *req)
{
	struct tstream_tls_writev_state *state =
		tevent_req_data(req,
		struct tstream_tls_writev_state);
	struct tstream_tls *tlss =
		tstream_context_data(state->stream,
		struct tstream_tls);

	tlss->write.left = sizeof(tlss->write.buffer);
	tlss->write.ofs = 0;

	/*
	 * first fill our buffer
	 */
	while (tlss->write.left > 0 && state->count > 0) {
		uint8_t *base = (uint8_t *)state->vector[0].iov_base;
		size_t len = MIN(tlss->write.left, state->vector[0].iov_len);

		memcpy(tlss->write.buffer + tlss->write.ofs, base, len);

		base += len;
		state->vector[0].iov_base = (char *) base;
		state->vector[0].iov_len -= len;

		tlss->write.ofs += len;
		tlss->write.left -= len;

		if (state->vector[0].iov_len == 0) {
			state->vector += 1;
			state->count -= 1;
		}

		state->ret += len;
	}

	if (tlss->write.ofs == 0) {
		tevent_req_done(req);
		return;
	}

	tlss->write.left = tlss->write.ofs;
	tlss->write.ofs = 0;

	tlss->write.req = req;
	tstream_tls_retry_write(state->stream);
}

static void tstream_tls_retry_write(struct tstream_context *stream)
{
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	struct tevent_req *req = tlss->write.req;
	int ret;

	if (tlss->error != 0) {
		tevent_req_error(req, tlss->error);
		return;
	}

	ret = gnutls_record_send(tlss->tls_session,
				 tlss->write.buffer + tlss->write.ofs,
				 tlss->write.left);
	if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
		return;
	}

	tlss->write.req = NULL;

	if (gnutls_error_is_fatal(ret) != 0) {
		DEBUG(1,("TLS %s - %s\n", __location__, gnutls_strerror(ret)));
		tlss->error = EIO;
		tevent_req_error(req, tlss->error);
		return;
	}

	if (ret == 0) {
		tlss->error = EPIPE;
		tevent_req_error(req, tlss->error);
		return;
	}

	tlss->write.ofs += ret;
	tlss->write.left -= ret;

	if (tlss->write.left > 0) {
		tlss->write.req = req;
		tstream_tls_retry_write(stream);
		return;
	}

	tstream_tls_writev_crypt_next(req);
}

static int tstream_tls_writev_recv(struct tevent_req *req,
				   int *perrno)
{
	struct tstream_tls_writev_state *state =
		tevent_req_data(req,
		struct tstream_tls_writev_state);
	struct tstream_tls *tlss =
		tstream_context_data(state->stream,
		struct tstream_tls);
	int ret;

	tlss->write.req = NULL;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tstream_tls_disconnect_state {
	uint8_t _dummy;
};

static struct tevent_req *tstream_tls_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct tstream_context *stream)
{
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	struct tevent_req *req;
	struct tstream_tls_disconnect_state *state;

	tlss->disconnect.req = NULL;

	if (tlss->current_ev != ev) {
		SMB_ASSERT(tlss->push.subreq == NULL);
		SMB_ASSERT(tlss->pull.subreq == NULL);
	}

	tlss->current_ev = ev;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_tls_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	if (tlss->error != 0) {
		tevent_req_error(req, tlss->error);
		return tevent_req_post(req, ev);
	}

	tlss->disconnect.req = req;
	tstream_tls_retry_disconnect(stream);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tstream_tls_retry_disconnect(struct tstream_context *stream)
{
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	struct tevent_req *req = tlss->disconnect.req;
	int ret;

	if (tlss->error != 0) {
		tevent_req_error(req, tlss->error);
		return;
	}

	ret = gnutls_bye(tlss->tls_session, GNUTLS_SHUT_WR);
	if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
		return;
	}

	tlss->disconnect.req = NULL;

	if (gnutls_error_is_fatal(ret) != 0) {
		DEBUG(1,("TLS %s - %s\n", __location__, gnutls_strerror(ret)));
		tlss->error = EIO;
		tevent_req_error(req, tlss->error);
		return;
	}

	if (ret != GNUTLS_E_SUCCESS) {
		DEBUG(1,("TLS %s - %s\n", __location__, gnutls_strerror(ret)));
		tlss->error = EIO;
		tevent_req_error(req, tlss->error);
		return;
	}

	if (tlss->push.subreq != NULL || tlss->pull.subreq != NULL) {
		tlss->waiting_flush.mgmt_req = req;
		return;
	}

	tevent_req_done(req);
}

static int tstream_tls_disconnect_recv(struct tevent_req *req,
				       int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);

	tevent_req_received(req);
	return ret;
}

static const struct tstream_context_ops tstream_tls_ops = {
	.name			= "tls",

	.pending_bytes		= tstream_tls_pending_bytes,

	.readv_send		= tstream_tls_readv_send,
	.readv_recv		= tstream_tls_readv_recv,

	.writev_send		= tstream_tls_writev_send,
	.writev_recv		= tstream_tls_writev_recv,

	.disconnect_send	= tstream_tls_disconnect_send,
	.disconnect_recv	= tstream_tls_disconnect_recv,
};

struct tstream_tls_params_internal {
	gnutls_certificate_credentials_t x509_cred;
	gnutls_dh_params_t dh_params;
	const char *tls_priority;
	bool tls_enabled;
	enum tls_verify_peer_state verify_peer;
	const char *peer_name;
};

struct tstream_tls_params {
	struct tstream_tls_params_internal *internal;
};

static int tstream_tls_params_internal_destructor(struct tstream_tls_params_internal *tlsp)
{
	if (tlsp->x509_cred) {
		gnutls_certificate_free_credentials(tlsp->x509_cred);
		tlsp->x509_cred = NULL;
	}
	if (tlsp->dh_params) {
		gnutls_dh_params_deinit(tlsp->dh_params);
		tlsp->dh_params = NULL;
	}

	return 0;
}

bool tstream_tls_params_enabled(struct tstream_tls_params *tls_params)
{
	struct tstream_tls_params_internal *tlsp = tls_params->internal;

	return tlsp->tls_enabled;
}

const char *tstream_tls_params_peer_name(
	const struct tstream_tls_params *params)
{
	return params->internal->peer_name;
}

static NTSTATUS tstream_tls_setup_channel_bindings(struct tstream_tls *tlss)
{
	gnutls_datum_t cb = { .size = 0 };
	int ret;

#ifdef HAVE_GNUTLS_CB_TLS_SERVER_END_POINT
	ret = gnutls_session_channel_binding(tlss->tls_session,
					     GNUTLS_CB_TLS_SERVER_END_POINT,
					     &cb);
#else /* not HAVE_GNUTLS_CB_TLS_SERVER_END_POINT */
	ret = legacy_gnutls_server_end_point_cb(tlss->tls_session,
						tlss->is_server,
						&cb);
#endif /* not HAVE_GNUTLS_CB_TLS_SERVER_END_POINT */
	if (ret != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_ntstatus(ret,
				NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	if (cb.size != 0) {
		/*
		 * Looking at the OpenLDAP implementation
		 * for LDAP_OPT_X_SASL_CBINDING_TLS_ENDPOINT
		 * revealed that we need to prefix it with
		 * 'tls-server-end-point:'
		 */
		const char endpoint_prefix[] = "tls-server-end-point:";
		size_t prefix_size = strlen(endpoint_prefix);
		size_t size = prefix_size + cb.size;

		tlss->channel_bindings = data_blob_talloc_named(tlss, NULL, size,
								"tls_channel_bindings");
		if (tlss->channel_bindings.data == NULL) {
			gnutls_free(cb.data);
			return NT_STATUS_NO_MEMORY;
		}
		memcpy(tlss->channel_bindings.data, endpoint_prefix, prefix_size);
		memcpy(tlss->channel_bindings.data + prefix_size, cb.data, cb.size);
		gnutls_free(cb.data);
	}

	return NT_STATUS_OK;
}

const DATA_BLOB *tstream_tls_channel_bindings(struct tstream_context *tls_tstream)
{
	struct tstream_tls *tlss =
		talloc_get_type(_tstream_context_data(tls_tstream),
		struct tstream_tls);

	if (tlss == NULL) {
		return NULL;
	}

	return &tlss->channel_bindings;
}

NTSTATUS tstream_tls_params_client(TALLOC_CTX *mem_ctx,
				   bool system_cas,
				   const char * const *ca_dirs,
				   const char *ca_file,
				   const char *crl_file,
				   const char *tls_priority,
				   enum tls_verify_peer_state verify_peer,
				   const char *peer_name,
				   struct tstream_tls_params **_tlsp)
{
	struct tstream_tls_params *__tlsp = NULL;
	struct tstream_tls_params_internal *tlsp = NULL;
	bool got_ca = false;
	size_t i;
	int ret;

	__tlsp = talloc_zero(mem_ctx, struct tstream_tls_params);
	if (__tlsp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	tlsp = talloc_zero(__tlsp, struct tstream_tls_params_internal);
	if (tlsp == NULL) {
		TALLOC_FREE(__tlsp);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(tlsp, tstream_tls_params_internal_destructor);
	__tlsp->internal = tlsp;

	tlsp->verify_peer = verify_peer;
	if (peer_name != NULL) {
		tlsp->peer_name = talloc_strdup(tlsp, peer_name);
		if (tlsp->peer_name == NULL) {
			TALLOC_FREE(__tlsp);
			return NT_STATUS_NO_MEMORY;
		}
	} else if (tlsp->verify_peer >= TLS_VERIFY_PEER_CA_AND_NAME) {
		DEBUG(0,("TLS failed to missing peer_name - "
			 "with 'tls verify peer = %s'\n",
			 tls_verify_peer_string(tlsp->verify_peer)));
		TALLOC_FREE(__tlsp);
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	ret = gnutls_certificate_allocate_credentials(&tlsp->x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		DEBUG(0,("TLS %s - %s\n", __location__, gnutls_strerror(ret)));
		TALLOC_FREE(__tlsp);
		return NT_STATUS_NO_MEMORY;
	}

	if (system_cas) {
		ret = gnutls_certificate_set_x509_system_trust(tlsp->x509_cred);
		if (ret < 0) {
			DBG_ERR("gnutls_certificate_set_x509_system_trust() - %s\n",
				gnutls_strerror(ret));
			TALLOC_FREE(__tlsp);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		if (ret > 0) {
			got_ca = true;
		}
	}

	for (i = 0; ca_dirs != NULL && ca_dirs[i] != NULL; i++) {
		const char *ca_dir = ca_dirs[i];

		if (!directory_exist(ca_dir)) {
			continue;
		}

		ret = gnutls_certificate_set_x509_trust_dir(tlsp->x509_cred,
							    ca_dir,
							    GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			DBG_ERR("gnutls_certificate_set_x509_trust_dir(%s) - %s\n",
				ca_dir, gnutls_strerror(ret));
			TALLOC_FREE(__tlsp);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		if (ret > 0) {
			got_ca = true;
		}
	}

	if (ca_file && *ca_file && file_exist(ca_file)) {
		ret = gnutls_certificate_set_x509_trust_file(tlsp->x509_cred,
							     ca_file,
							     GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			DEBUG(0,("TLS failed to initialise cafile %s - %s\n",
				 ca_file, gnutls_strerror(ret)));
			TALLOC_FREE(__tlsp);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		if (ret > 0) {
			got_ca = true;
		}
	}

	if (!got_ca && tlsp->verify_peer >= TLS_VERIFY_PEER_CA_ONLY) {
		D_ERR("TLS: 'tls verify peer = %s' requires "
		      "'tls trust system cas', "
		      "'tls ca directories' or "
		      "'tls cafile'\n",
		      tls_verify_peer_string(tlsp->verify_peer));
		TALLOC_FREE(__tlsp);
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	if (crl_file && *crl_file && file_exist(crl_file)) {
		ret = gnutls_certificate_set_x509_crl_file(tlsp->x509_cred,
							   crl_file, 
							   GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			DEBUG(0,("TLS failed to initialise crlfile %s - %s\n",
				 crl_file, gnutls_strerror(ret)));
			TALLOC_FREE(__tlsp);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
	} else if (tlsp->verify_peer >= TLS_VERIFY_PEER_AS_STRICT_AS_POSSIBLE) {
		DEBUG(0,("TLS failed to missing crlfile %s - "
			 "with 'tls verify peer = %s'\n",
			 crl_file,
			 tls_verify_peer_string(tlsp->verify_peer)));
		TALLOC_FREE(__tlsp);
		return NT_STATUS_INVALID_PARAMETER_MIX;
	}

	tlsp->tls_priority = talloc_strdup(tlsp, tls_priority);
	if (tlsp->tls_priority == NULL) {
		TALLOC_FREE(__tlsp);
		return NT_STATUS_NO_MEMORY;
	}

	tlsp->tls_enabled = true;

	*_tlsp = __tlsp;
	return NT_STATUS_OK;
}

NTSTATUS tstream_tls_params_client_lpcfg(TALLOC_CTX *mem_ctx,
					 struct loadparm_context *lp_ctx,
					 const char *peer_name,
					 struct tstream_tls_params **tlsp)
{
	TALLOC_CTX *frame = talloc_stackframe();
	bool system_cas = false;
	const char * const *ca_dirs = NULL;
	const char *ptr = NULL;
	char *ca_file = NULL;
	char *crl_file = NULL;
	const char *tls_priority = NULL;
	enum tls_verify_peer_state verify_peer =
		TLS_VERIFY_PEER_AS_STRICT_AS_POSSIBLE;
	NTSTATUS status;

	system_cas = lpcfg_tls_trust_system_cas(lp_ctx);
	ca_dirs = lpcfg_tls_ca_directories(lp_ctx);

	ptr = lpcfg__tls_cafile(lp_ctx);
	if (ptr != NULL) {
		ca_file = lpcfg_tls_cafile(frame, lp_ctx);
		if (ca_file == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	ptr = lpcfg__tls_crlfile(lp_ctx);
	if (ptr != NULL) {
		crl_file = lpcfg_tls_crlfile(frame, lp_ctx);
		if (crl_file == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	tls_priority = lpcfg_tls_priority(lp_ctx);
	verify_peer = lpcfg_tls_verify_peer(lp_ctx);

	status = tstream_tls_params_client(mem_ctx,
					   system_cas,
					   ca_dirs,
					   ca_file,
					   crl_file,
					   tls_priority,
					   verify_peer,
					   peer_name,
					   tlsp);
	TALLOC_FREE(frame);
	return status;
}

static NTSTATUS tstream_tls_prepare_gnutls(struct tstream_tls_params *_tlsp,
					   struct tstream_tls *tlss)
{
	struct tstream_tls_params_internal *tlsp = NULL;
	int ret;
	unsigned int flags;
	const char *hostname = NULL;

	if (tlss->is_server) {
		flags = GNUTLS_SERVER;
	} else {
		flags = GNUTLS_CLIENT;
		/*
		 * tls_tstream can't properly handle 'New Session Ticket'
		 * messages sent 'after' the client sends the 'Finished'
		 * message.  GNUTLS_NO_TICKETS was introduced in GnuTLS 3.5.6.
		 * This flag is to indicate the session Flag session should not
		 * use resumption with session tickets.
		 */
		flags |= GNUTLS_NO_TICKETS;
	}

	/*
	 * Note we need to make sure x509_cred and dh_params
	 * from tstream_tls_params_internal stay alive for
	 * the whole lifetime of this session!
	 *
	 * See 'man gnutls_credentials_set' and
	 * 'man gnutls_certificate_set_dh_params'.
	 *
	 * Note: here we use talloc_reference() in a way
	 *       that does not expose it to the caller.
	 */
	tlsp = talloc_reference(tlss, _tlsp->internal);
	if (tlsp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	tlss->verify_peer = tlsp->verify_peer;
	if (tlsp->peer_name != NULL) {
		bool ip = is_ipaddress(tlsp->peer_name);

		tlss->peer_name = talloc_strdup(tlss, tlsp->peer_name);
		if (tlss->peer_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		if (!ip) {
			hostname = tlss->peer_name;
		}

		if (tlss->verify_peer < TLS_VERIFY_PEER_CA_AND_NAME) {
			hostname = NULL;
		}
	}

	if (tlss->current_ev != NULL) {
		tlss->retry_im = tevent_create_immediate(tlss);
		if (tlss->retry_im == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	ret = gnutls_init(&tlss->tls_session, flags);
	if (ret != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_ntstatus(ret,
			NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	ret = gnutls_set_default_priority(tlss->tls_session);
	if (ret != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_ntstatus(ret,
			NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	if (strlen(tlsp->tls_priority) > 0) {
		const char *error_pos = NULL;

		ret = gnutls_priority_set_direct(tlss->tls_session,
						 tlsp->tls_priority,
						 &error_pos);
		if (ret != GNUTLS_E_SUCCESS) {
			return gnutls_error_to_ntstatus(ret,
				NT_STATUS_CRYPTO_SYSTEM_INVALID);
		}
	}

	ret = gnutls_credentials_set(tlss->tls_session,
				     GNUTLS_CRD_CERTIFICATE,
				     tlsp->x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_ntstatus(ret,
				NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	if (hostname != NULL) {
		ret = gnutls_server_name_set(tlss->tls_session,
					     GNUTLS_NAME_DNS,
					     hostname,
					     strlen(hostname));
		if (ret != GNUTLS_E_SUCCESS) {
			return gnutls_error_to_ntstatus(ret,
					NT_STATUS_CRYPTO_SYSTEM_INVALID);
		}
	}

	if (tlss->is_server) {
		gnutls_certificate_server_set_request(tlss->tls_session,
						      GNUTLS_CERT_REQUEST);
		gnutls_dh_set_prime_bits(tlss->tls_session, DH_BITS);
	}

	return NT_STATUS_OK;
}

static NTSTATUS tstream_tls_verify_peer(struct tstream_tls *tlss)
{
	unsigned int status = UINT32_MAX;
	bool ip = true;
	const char *hostname = NULL;
	int ret;

	if (tlss->verify_peer == TLS_VERIFY_PEER_NO_CHECK) {
		return NT_STATUS_OK;
	}

	if (tlss->peer_name != NULL) {
		ip = is_ipaddress(tlss->peer_name);
	}

	if (!ip) {
		hostname = tlss->peer_name;
	}

	if (tlss->verify_peer == TLS_VERIFY_PEER_CA_ONLY) {
		hostname = NULL;
	}

	if (tlss->verify_peer >= TLS_VERIFY_PEER_CA_AND_NAME) {
		if (hostname == NULL) {
			DEBUG(1,("TLS %s - no hostname available for "
				 "verify_peer[%s] and peer_name[%s]\n",
				 __location__,
				 tls_verify_peer_string(tlss->verify_peer),
				 tlss->peer_name));
			return NT_STATUS_IMAGE_CERT_REVOKED;
		}
	}

	ret = gnutls_certificate_verify_peers3(tlss->tls_session,
					       hostname,
					       &status);
	if (ret != GNUTLS_E_SUCCESS) {
		return gnutls_error_to_ntstatus(ret,
			NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	if (status != 0) {
		DEBUG(1,("TLS %s - check failed for "
			 "verify_peer[%s] and peer_name[%s] "
			 "status 0x%x (%s%s%s%s%s%s%s%s)\n",
			 __location__,
			 tls_verify_peer_string(tlss->verify_peer),
			 tlss->peer_name,
			 status,
			 status & GNUTLS_CERT_INVALID ? "invalid " : "",
			 status & GNUTLS_CERT_REVOKED ? "revoked " : "",
			 status & GNUTLS_CERT_SIGNER_NOT_FOUND ?
				"signer_not_found " : "",
			 status & GNUTLS_CERT_SIGNER_NOT_CA ?
				"signer_not_ca " : "",
			 status & GNUTLS_CERT_INSECURE_ALGORITHM ?
				"insecure_algorithm " : "",
			 status & GNUTLS_CERT_NOT_ACTIVATED ?
				"not_activated " : "",
			 status & GNUTLS_CERT_EXPIRED ?
				"expired " : "",
			 status & GNUTLS_CERT_UNEXPECTED_OWNER ?
				"unexpected_owner " : ""));
		return NT_STATUS_IMAGE_CERT_REVOKED;
	}

	return NT_STATUS_OK;
}

struct tstream_tls_connect_state {
	struct tstream_context *tls_stream;
};

struct tevent_req *_tstream_tls_connect_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct tstream_context *plain_stream,
					     struct tstream_tls_params *_tls_params,
					     const char *location)
{
	struct tevent_req *req;
	struct tstream_tls_connect_state *state;
	struct tstream_tls *tlss;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_tls_connect_state);
	if (req == NULL) {
		return NULL;
	}

	state->tls_stream = tstream_context_create(state,
						   &tstream_tls_ops,
						   &tlss,
						   struct tstream_tls,
						   location);
	if (tevent_req_nomem(state->tls_stream, req)) {
		return tevent_req_post(req, ev);
	}
	ZERO_STRUCTP(tlss);
	talloc_set_destructor(tlss, tstream_tls_destructor);
	tlss->plain_stream = plain_stream;
	tlss->is_server = false;
	tlss->current_ev = ev;

	status = tstream_tls_prepare_gnutls(_tls_params, tlss);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	gnutls_transport_set_ptr(tlss->tls_session,
				 (gnutls_transport_ptr_t)state->tls_stream);
	gnutls_transport_set_pull_function(tlss->tls_session,
					   (gnutls_pull_func)tstream_tls_pull_function);
	gnutls_transport_set_push_function(tlss->tls_session,
					   (gnutls_push_func)tstream_tls_push_function);

	tlss->handshake.req = req;
	tstream_tls_retry_handshake(state->tls_stream);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

int tstream_tls_connect_recv(struct tevent_req *req,
			     int *perrno,
			     TALLOC_CTX *mem_ctx,
			     struct tstream_context **tls_stream)
{
	struct tstream_tls_connect_state *state =
		tevent_req_data(req,
		struct tstream_tls_connect_state);

	if (tevent_req_is_unix_error(req, perrno)) {
		tevent_req_received(req);
		return -1;
	}

	*tls_stream = talloc_move(mem_ctx, &state->tls_stream);
	tevent_req_received(req);
	return 0;
}

/*
  initialise global tls state
*/
NTSTATUS tstream_tls_params_server(TALLOC_CTX *mem_ctx,
				   const char *dns_host_name,
				   bool enabled,
				   const char *key_file,
				   const char *cert_file,
				   const char *ca_file,
				   const char *crl_file,
				   const char *dhp_file,
				   const char *tls_priority,
				   struct tstream_tls_params **_tlsp)
{
	struct tstream_tls_params *__tlsp = NULL;
	struct tstream_tls_params_internal *tlsp = NULL;
	int ret;
	struct stat st;

	if (!enabled || key_file == NULL || *key_file == 0) {
		__tlsp = talloc_zero(mem_ctx, struct tstream_tls_params);
		if (__tlsp == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		tlsp = talloc_zero(__tlsp, struct tstream_tls_params_internal);
		if (tlsp == NULL) {
			TALLOC_FREE(__tlsp);
			return NT_STATUS_NO_MEMORY;
		}

		talloc_set_destructor(tlsp, tstream_tls_params_internal_destructor);
		__tlsp->internal = tlsp;
		tlsp->tls_enabled = false;

		*_tlsp = __tlsp;
		return NT_STATUS_OK;
	}

	__tlsp = talloc_zero(mem_ctx, struct tstream_tls_params);
	if (__tlsp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	tlsp = talloc_zero(__tlsp, struct tstream_tls_params_internal);
	if (tlsp == NULL) {
		TALLOC_FREE(__tlsp);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_set_destructor(tlsp, tstream_tls_params_internal_destructor);
	__tlsp->internal = tlsp;

	if (!file_exist(ca_file)) {
		tls_cert_generate(tlsp, dns_host_name,
				  key_file, cert_file, ca_file);
	}

	if (file_exist(key_file) &&
	    !file_check_permissions(key_file, geteuid(), 0600, &st))
	{
		DEBUG(0, ("Invalid permissions on TLS private key file '%s':\n"
			  "owner uid %u should be %u, mode 0%o should be 0%o\n"
			  "This is known as CVE-2013-4476.\n"
			  "Removing all tls .pem files will cause an "
			  "auto-regeneration with the correct permissions.\n",
			  key_file,
			  (unsigned int)st.st_uid, geteuid(),
			  (unsigned int)(st.st_mode & 0777), 0600));
		TALLOC_FREE(__tlsp);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	ret = gnutls_certificate_allocate_credentials(&tlsp->x509_cred);
	if (ret != GNUTLS_E_SUCCESS) {
		DEBUG(0,("TLS %s - %s\n", __location__, gnutls_strerror(ret)));
		TALLOC_FREE(__tlsp);
		return NT_STATUS_NO_MEMORY;
	}

	if (ca_file && *ca_file) {
		ret = gnutls_certificate_set_x509_trust_file(tlsp->x509_cred,
							     ca_file,
							     GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			DEBUG(0,("TLS failed to initialise cafile %s - %s\n",
				 ca_file, gnutls_strerror(ret)));
			TALLOC_FREE(__tlsp);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
	}

	if (crl_file && *crl_file) {
		ret = gnutls_certificate_set_x509_crl_file(tlsp->x509_cred,
							   crl_file, 
							   GNUTLS_X509_FMT_PEM);
		if (ret < 0) {
			DEBUG(0,("TLS failed to initialise crlfile %s - %s\n",
				 crl_file, gnutls_strerror(ret)));
			TALLOC_FREE(__tlsp);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
	}

	ret = gnutls_certificate_set_x509_key_file(tlsp->x509_cred,
						   cert_file, key_file,
						   GNUTLS_X509_FMT_PEM);
	if (ret != GNUTLS_E_SUCCESS) {
		DEBUG(0,("TLS failed to initialise certfile %s and keyfile %s - %s\n",
			 cert_file, key_file, gnutls_strerror(ret)));
		TALLOC_FREE(__tlsp);
		return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
	}

	ret = gnutls_dh_params_init(&tlsp->dh_params);
	if (ret != GNUTLS_E_SUCCESS) {
		DEBUG(0,("TLS %s - %s\n", __location__, gnutls_strerror(ret)));
		TALLOC_FREE(__tlsp);
		return NT_STATUS_NO_MEMORY;
	}

	if (dhp_file && *dhp_file) {
		gnutls_datum_t dhparms;
		size_t size;

		dhparms.data = (uint8_t *)file_load(dhp_file, &size, 0, tlsp);

		if (!dhparms.data) {
			DEBUG(0,("TLS failed to read DH Parms from %s - %d:%s\n",
				 dhp_file, errno, strerror(errno)));
			TALLOC_FREE(__tlsp);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
		dhparms.size = size;

		ret = gnutls_dh_params_import_pkcs3(tlsp->dh_params,
						    &dhparms,
						    GNUTLS_X509_FMT_PEM);
		if (ret != GNUTLS_E_SUCCESS) {
			DEBUG(0,("TLS failed to import pkcs3 %s - %s\n",
				 dhp_file, gnutls_strerror(ret)));
			TALLOC_FREE(__tlsp);
			return NT_STATUS_CANT_ACCESS_DOMAIN_INFO;
		}
	} else {
		ret = gnutls_dh_params_generate2(tlsp->dh_params, DH_BITS);
		if (ret != GNUTLS_E_SUCCESS) {
			DEBUG(0,("TLS failed to generate dh_params - %s\n",
				 gnutls_strerror(ret)));
			TALLOC_FREE(__tlsp);
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	gnutls_certificate_set_dh_params(tlsp->x509_cred, tlsp->dh_params);

	tlsp->tls_priority = talloc_strdup(tlsp, tls_priority);
	if (tlsp->tls_priority == NULL) {
		TALLOC_FREE(__tlsp);
		return NT_STATUS_NO_MEMORY;
	}

	tlsp->tls_enabled = true;

	*_tlsp = __tlsp;
	return NT_STATUS_OK;
}

struct tstream_tls_accept_state {
	struct tstream_context *tls_stream;
};

struct tevent_req *_tstream_tls_accept_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tstream_context *plain_stream,
					    struct tstream_tls_params *_tlsp,
					    const char *location)
{
	struct tevent_req *req;
	struct tstream_tls_accept_state *state;
	struct tstream_tls *tlss;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_tls_accept_state);
	if (req == NULL) {
		return NULL;
	}

	state->tls_stream = tstream_context_create(state,
						   &tstream_tls_ops,
						   &tlss,
						   struct tstream_tls,
						   location);
	if (tevent_req_nomem(state->tls_stream, req)) {
		return tevent_req_post(req, ev);
	}
	ZERO_STRUCTP(tlss);
	talloc_set_destructor(tlss, tstream_tls_destructor);
	tlss->plain_stream = plain_stream;
	tlss->is_server = true;
	tlss->current_ev = ev;

	status = tstream_tls_prepare_gnutls(_tlsp, tlss);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NO_MEMORY)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	gnutls_transport_set_ptr(tlss->tls_session,
				 (gnutls_transport_ptr_t)state->tls_stream);
	gnutls_transport_set_pull_function(tlss->tls_session,
					   (gnutls_pull_func)tstream_tls_pull_function);
	gnutls_transport_set_push_function(tlss->tls_session,
					   (gnutls_push_func)tstream_tls_push_function);

	tlss->handshake.req = req;
	tstream_tls_retry_handshake(state->tls_stream);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tstream_tls_retry_handshake(struct tstream_context *stream)
{
	struct tstream_tls *tlss =
		tstream_context_data(stream,
		struct tstream_tls);
	struct tevent_req *req = tlss->handshake.req;
	NTSTATUS status;
	int ret;

	if (tlss->error != 0) {
		tevent_req_error(req, tlss->error);
		return;
	}

	ret = gnutls_handshake(tlss->tls_session);
	if (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN) {
		return;
	}

	tlss->handshake.req = NULL;

	if (gnutls_error_is_fatal(ret) != 0) {
		DEBUG(1,("TLS %s - %s\n", __location__, gnutls_strerror(ret)));
		tlss->error = EIO;
		tevent_req_error(req, tlss->error);
		return;
	}

	if (ret != GNUTLS_E_SUCCESS) {
		DEBUG(1,("TLS %s - %s\n", __location__, gnutls_strerror(ret)));
		tlss->error = EIO;
		tevent_req_error(req, tlss->error);
		return;
	}

	status = tstream_tls_verify_peer(tlss);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IMAGE_CERT_REVOKED)) {
		tlss->error = EINVAL;
		tevent_req_error(req, tlss->error);
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		tlss->error = EIO;
		tevent_req_error(req, tlss->error);
		return;
	}

	status = tstream_tls_setup_channel_bindings(tlss);
	if (!NT_STATUS_IS_OK(status)) {
		tlss->error = EIO;
		tevent_req_error(req, tlss->error);
		return;
	}

	if (tlss->push.subreq != NULL || tlss->pull.subreq != NULL) {
		tlss->waiting_flush.mgmt_req = req;
		return;
	}

	tevent_req_done(req);
}

int tstream_tls_accept_recv(struct tevent_req *req,
			    int *perrno,
			    TALLOC_CTX *mem_ctx,
			    struct tstream_context **tls_stream)
{
	struct tstream_tls_accept_state *state =
		tevent_req_data(req,
		struct tstream_tls_accept_state);

	if (tevent_req_is_unix_error(req, perrno)) {
		tevent_req_received(req);
		return -1;
	}

	*tls_stream = talloc_move(mem_ctx, &state->tls_stream);
	tevent_req_received(req);
	return 0;
}

struct tstream_tls_sync {
	struct tstream_tls *tlss;
	void *io_private;
	ssize_t (*io_send_fn)(void *io_private,
			      const uint8_t *buf,
			      size_t len);
	ssize_t (*io_recv_fn)(void *io_private,
			      uint8_t *buf,
			      size_t len);
};

const DATA_BLOB *tstream_tls_sync_channel_bindings(struct tstream_tls_sync *tlsss)
{
	return &tlsss->tlss->channel_bindings;
}

static ssize_t tstream_tls_sync_push_function(gnutls_transport_ptr_t ptr,
					      const void *buf, size_t size)
{
	struct tstream_tls_sync *tlsss =
		talloc_get_type_abort(ptr,
		struct tstream_tls_sync);

	return tlsss->io_send_fn(tlsss->io_private, buf, size);
}

static ssize_t tstream_tls_sync_pull_function(gnutls_transport_ptr_t ptr,
					      void *buf, size_t size)
{
	struct tstream_tls_sync *tlsss =
		talloc_get_type_abort(ptr,
		struct tstream_tls_sync);

	return tlsss->io_recv_fn(tlsss->io_private, buf, size);
}

ssize_t tstream_tls_sync_read(struct tstream_tls_sync *tlsss,
			      void *buf, size_t len)
{
	int ret;

	ret = gnutls_record_recv(tlsss->tlss->tls_session, buf, len);
	if (ret == GNUTLS_E_INTERRUPTED) {
		errno = EINTR;
		return -1;
	}
	if (ret == GNUTLS_E_AGAIN) {
		errno = EAGAIN;
		return -1;
	}

	if (ret < 0) {
		DBG_WARNING("TLS gnutls_record_recv(%zu) - %s\n",
			    (size_t)len, gnutls_strerror(ret));
		errno = EIO;
		return -1;
	}

	return ret;
}

ssize_t tstream_tls_sync_write(struct tstream_tls_sync *tlsss,
			       const void *buf, size_t len)
{
	int ret;

	ret = gnutls_record_send(tlsss->tlss->tls_session, buf, len);
	if (ret == GNUTLS_E_INTERRUPTED) {
		errno = EINTR;
		return -1;
	}
	if (ret == GNUTLS_E_AGAIN) {
		errno = EAGAIN;
		return -1;
	}

	if (ret < 0) {
		DBG_WARNING("TLS gnutls_record_send(%zu) - %s\n",
			    (size_t)len, gnutls_strerror(ret));
		errno = EIO;
		return -1;
	}

	return ret;
}

size_t tstream_tls_sync_pending(struct tstream_tls_sync *tlsss)
{
	return gnutls_record_check_pending(tlsss->tlss->tls_session);
}

NTSTATUS tstream_tls_sync_setup(struct tstream_tls_params *_tls_params,
				void *io_private,
				ssize_t (*io_send_fn)(void *io_private,
						      const uint8_t *buf,
						      size_t len),
				ssize_t (*io_recv_fn)(void *io_private,
						      uint8_t *buf,
						      size_t len),
				TALLOC_CTX *mem_ctx,
				struct tstream_tls_sync **_tlsss)
{
	struct tstream_tls_sync *tlsss = NULL;
	struct tstream_tls *tlss = NULL;
	NTSTATUS status;
	int ret;

	tlsss = talloc_zero(mem_ctx, struct tstream_tls_sync);
	if (tlsss == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	tlsss->io_private = io_private;
	tlsss->io_send_fn = io_send_fn;
	tlsss->io_recv_fn = io_recv_fn;

	tlss = talloc_zero(tlsss, struct tstream_tls);
	if (tlss == NULL) {
		TALLOC_FREE(tlsss);
		return NT_STATUS_NO_MEMORY;
	}
	talloc_set_destructor(tlss, tstream_tls_destructor);
	tlss->is_server = false;

	tlsss->tlss = tlss;

	status = tstream_tls_prepare_gnutls(_tls_params, tlss);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tlsss);
		return status;
	}

	gnutls_transport_set_ptr(tlss->tls_session,
				 (gnutls_transport_ptr_t)tlsss);
	gnutls_transport_set_pull_function(tlss->tls_session,
					   (gnutls_pull_func)tstream_tls_sync_pull_function);
	gnutls_transport_set_push_function(tlss->tls_session,
					   (gnutls_push_func)tstream_tls_sync_push_function);

	do {
		/*
		 * The caller should have the socket blocking
		 * and do the timeout handling in the
		 * io_send/recv_fn
		 */
		ret = gnutls_handshake(tlss->tls_session);
	} while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);

	if (gnutls_error_is_fatal(ret) != 0) {
		TALLOC_FREE(tlsss);
		return gnutls_error_to_ntstatus(ret,
				NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	if (ret != GNUTLS_E_SUCCESS) {
		TALLOC_FREE(tlsss);
		return gnutls_error_to_ntstatus(ret,
				NT_STATUS_CRYPTO_SYSTEM_INVALID);
	}

	status = tstream_tls_verify_peer(tlss);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tlsss);
		return status;
	}

	status = tstream_tls_setup_channel_bindings(tlss);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(tlsss);
		return status;
	}

	*_tlsss = tlsss;
	return NT_STATUS_OK;
}
