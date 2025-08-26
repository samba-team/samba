/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2010-2025

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
#include "lib/util/dlinklist.h"
#include "lib/util/time_basic.h"
#include "lib/util/util_file.h"
#include "lib/util/tevent_ntstatus.h"
#include "../util/tevent_unix.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/tsocket/tsocket_internal.h"
#include "../lib/util/util_net.h"
#include "lib/tls/tls.h"
#include "lib/param/param.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <gnutls/x509.h>
#include "lib/crypto/gnutls_helpers.h"

#ifdef HAVE_LIBQUIC
#include <netinet/quic.h>
#endif

#ifdef HAVE_LIBNGTCP2
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#endif

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
#ifdef HAVE_LIBQUIC
	bool quic;
#endif /* HAVE_LIBQUIC */
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

bool tstream_tls_params_quic_enabled(struct tstream_tls_params *tls_params)
{
	bool quic = false;
#ifdef HAVE_LIBQUIC
	struct tstream_tls_params_internal *tlsp = tls_params->internal;

	quic = tlsp->quic;
#endif /* HAVE_LIBQUIC */
	return quic;
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

NTSTATUS tstream_tls_params_quic_prepare(struct tstream_tls_params *tlsp)
{
#ifdef HAVE_LIBQUIC
	const char *tls_priority = NULL;

	if (!tlsp->internal->tls_enabled) {
		goto disable;
	}

	if (tlsp->internal->peer_name != NULL &&
	    is_ipaddress(tlsp->internal->peer_name))
	{
		goto disable;
	}

	tls_priority = talloc_strdup(tlsp->internal, QUIC_PRIORITY);
	if (tls_priority == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	talloc_free(discard_const(tlsp->internal->tls_priority));
	tlsp->internal->tls_priority = tls_priority;

	tlsp->internal->quic = true;

	return NT_STATUS_OK;
disable:
	tlsp->internal->quic = false;
#endif /* HAVE_LIBQUIC */
	return NT_STATUS_OK;
}

static NTSTATUS tstream_tls_prepare_gnutls(struct tstream_tls_params *_tlsp,
					   struct tstream_tls *tlss)
{
	struct tstream_tls_params_internal *tlsp = NULL;
	int ret;
	unsigned int flags;
	gnutls_certificate_request_t cert_req = GNUTLS_CERT_IGNORE;
	const char *hostname = NULL;

	if (tlss->is_server) {
		flags = GNUTLS_SERVER;
		cert_req = GNUTLS_CERT_REQUEST;
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

#ifdef HAVE_LIBQUIC
	if (tlss->is_server && tlsp->quic) {
		flags |= GNUTLS_NO_AUTO_SEND_TICKET;
		cert_req = GNUTLS_CERT_IGNORE;
	}
#endif /* HAVE_LIBQUIC */

	tlss->verify_peer = tlsp->verify_peer;
	if (tlsp->peer_name != NULL) {
		bool ip = is_ipaddress(tlsp->peer_name);
#ifdef HAVE_LIBQUIC
		bool force_name = tlsp->quic;
#else
		bool force_name = false;
#endif /* HAVE_LIBQUIC */

		tlss->peer_name = talloc_strdup(tlss, tlsp->peer_name);
		if (tlss->peer_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		if (!ip) {
			hostname = tlss->peer_name;
		}

		if (!force_name &&
		    tlss->verify_peer < TLS_VERIFY_PEER_CA_AND_NAME)
		{
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
						      cert_req);
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
				   const char * const *additional_dns_hostnames,
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
				  additional_dns_hostnames,
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

NTSTATUS tstream_tls_params_server_lpcfg(TALLOC_CTX *mem_ctx,
					 struct loadparm_context *lp_ctx,
					 struct tstream_tls_params **_tlsp)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status;

	status = tstream_tls_params_server(mem_ctx,
					   lpcfg_dns_hostname(lp_ctx),
					   lpcfg_additional_dns_hostnames(lp_ctx),
					   lpcfg_tls_enabled(lp_ctx),
					   lpcfg_tls_keyfile(frame, lp_ctx),
					   lpcfg_tls_certfile(frame, lp_ctx),
					   lpcfg_tls_cafile(frame, lp_ctx),
					   lpcfg_tls_crlfile(frame, lp_ctx),
					   lpcfg_tls_dhpfile(frame, lp_ctx),
					   lpcfg_tls_priority(lp_ctx),
					   _tlsp);

	TALLOC_FREE(frame);
	return status;
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

struct tstream_tls_quic_handshake_state {
	struct tstream_tls *tlss;
	int sockfd;
	struct tevent_fd *fde;
#ifdef HAVE_LIBQUIC
	struct quic_handshake_step *step;
#endif /* HAVE_LIBQUIC */
};

#ifdef HAVE_LIBQUIC
static void tstream_tls_quic_handshake_cleanup(struct tevent_req *req,
					       enum tevent_req_state req_state);
static void tstream_tls_quic_handshake_run(struct tevent_req *req);
static void tstream_tls_quic_handshake_fde(struct tevent_context *ev,
					   struct tevent_fd *fde,
					   uint16_t flags,
					   void *private_data);
static void tstream_tls_quic_handshake_done(struct tevent_req *req);
#endif /* HAVE_LIBQUIC */

struct tevent_req *tstream_tls_quic_handshake_send(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct tstream_tls_params *tlsp,
						   bool is_server,
						   uint32_t timeout_msec,
						   const char *alpn,
						   int sockfd)
{
	struct tevent_req *req = NULL;
	struct tstream_tls_quic_handshake_state *state = NULL;
#ifdef HAVE_LIBQUIC
	NTSTATUS status;
	int ret;
#endif /* HAVE_LIBQUIC */
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_tls_quic_handshake_state);
	if (req == NULL) {
		return NULL;
	}
	state->sockfd = sockfd;

	ok = tevent_req_set_endtime(req, ev,
				    timeval_current_ofs_msec(timeout_msec));
	if (!ok) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	ok = tstream_tls_params_quic_enabled(tlsp);
	if (!ok) {
		goto invalid_parameter_mix;
	}

#ifdef HAVE_LIBQUIC
	state->tlss = talloc_zero(state, struct tstream_tls);
	if (tevent_req_nomem(state->tlss, req)) {
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(state->tlss, tstream_tls_destructor);
	state->tlss->is_server = is_server;

	status = tstream_tls_prepare_gnutls(tlsp, state->tlss);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	ret = quic_session_set_alpn(state->tlss->tls_session, alpn, strlen(alpn));
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	gnutls_transport_set_int(state->tlss->tls_session, state->sockfd);

	ret = quic_handshake_init(state->tlss->tls_session, &state->step);
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	tevent_req_set_cleanup_fn(req, tstream_tls_quic_handshake_cleanup);

	state->fde = tevent_add_fd(ev,
				   state,
				   state->sockfd,
				   TEVENT_FD_ERROR | TEVENT_FD_READ,
				   tstream_tls_quic_handshake_fde,
				   req);
	if (tevent_req_nomem(state->fde, req)) {
		return tevent_req_post(req, ev);
	}

	tstream_tls_quic_handshake_run(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
#endif /* HAVE_LIBQUIC */
invalid_parameter_mix:
	tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
	return tevent_req_post(req, ev);
}

#ifdef HAVE_LIBQUIC
static void tstream_tls_quic_handshake_cleanup(struct tevent_req *req,
					       enum tevent_req_state req_state)
{
	struct tstream_tls_quic_handshake_state *state =
		tevent_req_data(req,
		struct tstream_tls_quic_handshake_state);

	if (state->tlss == NULL) {
		return;
	}

	TALLOC_FREE(state->fde);
	quic_handshake_deinit(state->tlss->tls_session);
	TALLOC_FREE(state->tlss);
}

static void tstream_tls_quic_handshake_run(struct tevent_req *req)
{
	struct tstream_tls_quic_handshake_state *state =
		tevent_req_data(req,
		struct tstream_tls_quic_handshake_state);
	struct tstream_tls *tlss = state->tlss;
	struct quic_handshake_step_sendmsg *smsg = NULL;
	struct quic_handshake_step_recvmsg *rmsg = NULL;
	ssize_t len;
	int ret;

next_step:

	SMB_ASSERT(state->step != NULL);
	len = 0;

	switch (state->step->op) {
	case QUIC_HANDSHAKE_STEP_OP_SENDMSG:
		smsg = &state->step->s_sendmsg;
		len = sendmsg(state->sockfd,
			      smsg->msg,
			      smsg->flags |
			      MSG_NOSIGNAL |
			      MSG_DONTWAIT);
		if (len == -1 && errno == EINTR) {
			/* do it again */
			goto next_step;
		}
		if (len == -1 && (
		    errno == EAGAIN ||
		    errno == EWOULDBLOCK))
		{
			TEVENT_FD_WRITEABLE(state->fde);
			return;
		}
		if (len == -1) {
			len = -errno;
		}
		if (len == 0) {
			len = -ECONNRESET;
		}
		smsg->retval = len;
		break;
	case QUIC_HANDSHAKE_STEP_OP_RECVMSG:
		rmsg = &state->step->s_recvmsg;
		len = recvmsg(state->sockfd,
			      rmsg->msg,
			      rmsg->flags |
			      MSG_DONTWAIT);
		if (len == -1 && errno == EINTR) {
			/* do it again */
			goto next_step;
		}
		if (len == -1 && (
		    errno == EAGAIN ||
		    errno == EWOULDBLOCK))
		{
			return;
		}
		if (len == -1) {
			len = -errno;
		}
		if (len == 0) {
			len = -ECONNRESET;
		}
		rmsg->retval = len;
		break;
	}

	if (len == 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	ret = quic_handshake_step(tlss->tls_session, &state->step);
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	if (state->step == NULL) {
		tstream_tls_quic_handshake_done(req);
		return;
	}

	goto next_step;
};

static void tstream_tls_quic_handshake_fde(struct tevent_context *ev,
					   struct tevent_fd *fde,
					   uint16_t flags,
					   void *private_data)
{
	struct tevent_req *req =
		talloc_get_type_abort(private_data,
		struct tevent_req);
	struct tstream_tls_quic_handshake_state *state =
		tevent_req_data(req,
		struct tstream_tls_quic_handshake_state);

	TEVENT_FD_NOT_WRITEABLE(state->fde);
	tstream_tls_quic_handshake_run(req);
}

static void tstream_tls_quic_handshake_done(struct tevent_req *req)
{
	struct tstream_tls_quic_handshake_state *state =
		tevent_req_data(req,
		struct tstream_tls_quic_handshake_state);

	if (!state->tlss->is_server) {
		struct quic_stream_info info = {};
		unsigned int optlen = sizeof(info);
		NTSTATUS status;
		int ret;

		status = tstream_tls_verify_peer(state->tlss);
		if (tevent_req_nterror(req, status)) {
			return;
		}

		/*
		 * Use the next stream_id (0) as default
		 * client stream.
		 */
		info.stream_id = -1;
		ret = getsockopt(state->sockfd,
				 SOL_QUIC,
				 QUIC_SOCKOPT_STREAM_OPEN,
				 &info,
				 &optlen);
		if (ret != 0) {
			tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
			return;
		}
	}

	tevent_req_done(req);
}
#endif /* HAVE_LIBQUIC */

NTSTATUS tstream_tls_quic_handshake_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

NTSTATUS tstream_tls_quic_handshake(struct tstream_tls_params *tlsp,
				    bool is_server,
				    uint32_t timeout_msec,
				    const char *alpn,
				    int sockfd)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct tevent_context *ev;
	struct tevent_req *req;
	NTSTATUS status = NT_STATUS_NO_MEMORY;

	ev = samba_tevent_context_init(frame);
	if (ev == NULL) {
		goto fail;
	}
	req = tstream_tls_quic_handshake_send(ev,
					      ev,
					      tlsp,
					      is_server,
					      timeout_msec,
					      alpn,
					      sockfd);
	if (req == NULL) {
		goto fail;
	}
	if (!tevent_req_poll_ntstatus(req, ev, &status)) {
		goto fail;
	}
	status = tstream_tls_quic_handshake_recv(req);
fail:
	TALLOC_FREE(frame);
	return status;
}

#ifdef HAVE_LIBNGTCP2

static const struct tstream_context_ops tstream_ngtcp2_ops;

struct tstream_ngtcp2_buffer {
	struct tstream_ngtcp2_buffer *prev, *next;
	uint64_t offset;
	size_t length;
	uint8_t buffer[NGTCP2_MAX_PMTUD_UDP_PAYLOAD_SIZE];
};

struct tstream_ngtcp2 {
	struct tdgram_context *plain_dgram;
	int error;

	ngtcp2_tstamp last_expire;
	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_conn *conn;
	int64_t stream_id;
	struct samba_sockaddr laddr;
	struct samba_sockaddr raddr;
	ngtcp2_path path;

	struct tevent_context *current_ev;

	struct tevent_immediate *retry_im;
	uint32_t keepalive_usecs;
	struct tevent_timer *keepalive_timer;

	struct {
		struct tstream_tls *tlss;
		struct tevent_req *req;
		bool done;
	} handshake;

	struct {
		struct tstream_ngtcp2_buffer b;
		struct tevent_req *subreq;
		uint64_t blocked;
	} push;

	struct {
		struct tstream_ngtcp2_buffer b;
		struct tevent_req *subreq;
	} pull;

	struct {
		struct tstream_ngtcp2_buffer *pushed;
		uint64_t pushed_offset;
		struct tstream_ngtcp2_buffer *pending;
		struct tevent_req *req;
	} writev;

	struct {
		struct tstream_ngtcp2_buffer *buffers;
		struct tevent_req *req;
	} readv;

	struct {
		struct tevent_req *req;
	} disconnect;

	struct {
		struct tevent_req *req;
	} monitor;
};

static void tstream_ngtcp2_close_stream(struct tstream_ngtcp2 *si);
static void tstream_ngtcp2_retry_handshake(struct tstream_context *stream);
static void tstream_ngtcp2_timer_start(struct tstream_context *stream);
static void tstream_ngtcp2_timer_handler(struct tevent_context *ev,
					 struct tevent_timer *te,
					 struct timeval current_time,
					 void *private_data);
static void tstream_ngtcp2_sendto_start(struct tstream_context *stream);
static void tstream_ngtcp2_sendto_done(struct tevent_req *subreq);
static void tstream_ngtcp2_recvfrom_start(struct tstream_context *stream);
static void tstream_ngtcp2_recvfrom_done(struct tevent_req *subreq);
static void tstream_ngtcp2_readv_retry(struct tstream_context *stream);
static void tstream_ngtcp2_writev_retry(struct tstream_context *stream);
static void tstream_ngtcp2_monitor_retry(struct tstream_context *stream);
static void tstream_ngtcp2_deferred_retry(struct tstream_context *stream);

static ngtcp2_conn *qwrap_ngtcp2_conn_ref_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	struct tstream_context *stream =
		talloc_get_type_abort(conn_ref->user_data,
		struct tstream_context);
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);

	return si->conn;
}

static bool tstream_ngtcp2_verbose;

static void tstream_ngtcp2_log_printf(void *user_data, const char *fmt, ...) PRINTF_ATTRIBUTE(2, 3);
static void tstream_ngtcp2_log_printf(void *user_data, const char *fmt, ...)
{
	if (tstream_ngtcp2_verbose) {
		char buffer[1024];
		va_list ap;
		struct timespec ts = timespec_current();
		struct timeval_buf tsbuf;

		va_start(ap, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, ap);
		va_end(ap);

		D_ERR("NGTCP2:%s: %s\n",
		      timespec_string_buf(&ts, true, &tsbuf),
		      buffer);
	}
}

static void tstream_ngtcp2_qlog_write_cb(void *user_data, uint32_t flags,
				       const void *data, size_t datalen)
{
	if (tstream_ngtcp2_verbose) {
		struct timespec ts = timespec_current();
		struct timeval_buf tsbuf;

		D_ERR("NGTCP2:%s: flags[%"PRIu32"] len[%zu] %*.*s\n",
		      timespec_string_buf(&ts, true, &tsbuf),
		      flags, datalen,
		      (int)datalen, (int)datalen, (const char *)data);
	}
}

static inline ngtcp2_tstamp timespec2ngtcp2_tstamp(struct timespec ts)
{
	return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

static inline struct timespec ngtcp2_tstamp2timespec(ngtcp2_tstamp _ts,
						     ngtcp2_duration rtc_offset)
{
	ngtcp2_tstamp ts = _ts + rtc_offset;
	return (struct timespec) {
		.tv_sec = ts / NGTCP2_SECONDS,
		.tv_nsec = ts % NGTCP2_SECONDS,
	};
}

static inline struct timeval timespec2timeval(struct timespec ts)
{
	return (struct timeval) {
		.tv_sec = ts.tv_sec,
		.tv_usec = ts.tv_nsec / 1000,
	};
}

static ngtcp2_tstamp _tstream_ngtcp2_timestamp(ngtcp2_duration *_rtc_offsetp,
					       const char *func,
					       unsigned line)
{
	struct timespec ts_rtc = { .tv_sec = 0, };
	struct timespec ts_mono;
	ngtcp2_tstamp ret_rtc = 0;
	ngtcp2_tstamp ret_mono;
	bool need_rtc_offset = false;
	ngtcp2_duration rtc_offset = 0;

	if (_rtc_offsetp != NULL || CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		need_rtc_offset = true;
	}

	if (need_rtc_offset) {
		ts_rtc = timespec_current();
		ret_rtc = timespec2ngtcp2_tstamp(ts_rtc);
	}

	clock_gettime_mono(&ts_mono);
	ret_mono = timespec2ngtcp2_tstamp(ts_mono);

	if (need_rtc_offset) {
		rtc_offset = ret_rtc - ret_mono;
	}

	if (CHECK_DEBUGLVL(DBGLVL_DEBUG)) {
		struct timeval_buf rtc_buf;

		DBG_DEBUG("%s:%s:%u: rtc_offset=%"PRIu64" stamp=%"PRIu64"\n",
			  timespec_string_buf(&ts_rtc, true, &rtc_buf),
			  func, line, rtc_offset, ret_mono);
	}

	if (_rtc_offsetp != NULL) {
		*_rtc_offsetp = rtc_offset;
	}

	return ret_mono;
}
#define tstream_ngtcp2_timestamp(__rtc_offsetp) \
	_tstream_ngtcp2_timestamp(__rtc_offsetp, __func__, __LINE__)

static int tstream_ngtcp2_recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
					      int64_t stream_id, uint64_t offset,
					      const uint8_t *data, size_t datalen,
					      void *user_data, void *stream_user_data)
{
	struct tstream_context *stream =
		talloc_get_type_abort(user_data,
		struct tstream_context);
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tstream_ngtcp2_buffer *cbuf = NULL;

	DBG_DEBUG("Called stream_id[%"PRIi64"] "
		  "offset[%"PRIu64"] datalen[%"PRIu64"]\n",
		  stream_id, offset, datalen);

	if (si->stream_id != stream_id) {
		return NGTCP2_ERR_STREAM_NOT_FOUND;
	}

next_buf:
	cbuf = talloc(si, struct tstream_ngtcp2_buffer);
	if (cbuf == NULL) {
		return NGTCP2_ERR_NOMEM;
	}
	cbuf->prev = cbuf->next = NULL;
	cbuf->offset = 0;
	cbuf->length = MIN(ARRAY_SIZE(cbuf->buffer), datalen);
	memcpy(cbuf->buffer, data, cbuf->length);
	DLIST_ADD_END(si->readv.buffers, cbuf);

	data += cbuf->length;
	datalen -= cbuf->length;
	if (datalen > 0) {
		goto next_buf;
	}

	return 0;
}

static int tstream_ngtcp2_acked_stream_data_offset_cb(ngtcp2_conn *conn,
						      int64_t stream_id,
						      uint64_t offset,
						      uint64_t datalen,
						      void *user_data,
						      void *stream_user_data)
{
	struct tstream_context *stream =
		talloc_get_type_abort(user_data,
		struct tstream_context);
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tstream_ngtcp2_buffer *cbuf = NULL;
	struct tstream_ngtcp2_buffer *cnext = NULL;

	DBG_DEBUG("Called stream_id[%"PRIi64"] "
		  "offset[%"PRIu64"] datalen[%"PRIu64"]\n",
		  stream_id, offset, datalen);

	if (si->stream_id != stream_id) {
		return NGTCP2_ERR_STREAM_NOT_FOUND;
	}

	for (cbuf = si->writev.pushed; cbuf != NULL; cbuf = cnext) {
		cnext = cbuf->next;

		if (cbuf->offset != offset) {
			continue;
		}
		if (cbuf->length != datalen) {
			continue;
		}

		DBG_DEBUG("REMOVE pushed[%"PRIu64"][%zd]\n",
			  cbuf->offset, cbuf->length);
		DLIST_REMOVE(si->writev.pushed, cbuf);
		TALLOC_FREE(cbuf);
	}

	DBG_DEBUG("SI stream_id[%"PRIi64"] "
		  "offset[%"PRIu64"] pushed[%"PRIu64"][%zd]\n",
		  si->stream_id, si->writev.pushed_offset,
		  si->writev.pushed ? si->writev.pushed->offset : 0,
		  si->writev.pushed ? si->writev.pushed->length : -1);

	return 0;
}

static int tstream_ngtcp2_stream_close_cb(ngtcp2_conn *conn,
					  uint32_t flags,
					  int64_t stream_id,
					  uint64_t app_error_code,
					  void *user_data,
					  void *stream_user_data)
{
	struct tstream_context *stream =
		talloc_get_type_abort(user_data,
		struct tstream_context);
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);

	DBG_WARNING("Called stream_id[%"PRIi64"] "
		    "flags[0x%x] app_error_code[%"PRIu64"]\n",
		    stream_id, flags, app_error_code);

	if (si->stream_id != stream_id) {
		return NGTCP2_ERR_STREAM_NOT_FOUND;
	}

	return 0;
}

static int tstream_ngtcp2_recv_stateless_reset_cb(ngtcp2_conn *conn,
					const ngtcp2_pkt_stateless_reset *sr,
					void *user_data)
{
	struct tstream_context *stream =
		talloc_get_type_abort(user_data,
		struct tstream_context);
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);

	DBG_WARNING("Called stream_id[%"PRIi64"]\n",
		    si->stream_id);

	return 0;
}

static void tstream_ngtcp2_rand_cb(uint8_t *dest, size_t destlen,
				   const ngtcp2_rand_ctx *rand_ctx)
{
	gnutls_rnd(GNUTLS_RND_RANDOM, dest, destlen);
	return;
}

static int tstream_ngtcp2_get_new_connection_id_cb(ngtcp2_conn *conn,
						   ngtcp2_cid *cid,
						   uint8_t *token,
						   size_t cidlen,
						   void *user_data)
{
	int ret;

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, cid->data, cidlen);
	if (ret != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, token,
			 NGTCP2_STATELESS_RESET_TOKENLEN);
	if (ret != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int tstream_ngtcp2_stream_reset_cb(ngtcp2_conn *conn,
					  int64_t stream_id,
					  uint64_t final_size,
					  uint64_t app_error_code,
					  void *user_data,
					  void *stream_user_data)
{
	struct tstream_context *stream =
		talloc_get_type_abort(user_data,
		struct tstream_context);
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);

	DBG_WARNING("Called stream_id[%"PRIi64"] "
		    "final_size[%"PRIu64"] app_error_code[%"PRIu64"]\n",
		    stream_id, final_size, app_error_code);

	if (si->stream_id != stream_id) {
		return NGTCP2_ERR_STREAM_NOT_FOUND;
	}

	return 0;
}

static int tstream_ngtcp2_destructor(struct tstream_ngtcp2 *si)
{
	/*
	 * We want tevent_req_poll()
	 * to return without any blocking.
	 *
	 * So we use tevent_context_set_wait_timeout(0)
	 * that will cause tevent_loop_once() in
	 * tevent_req_poll() to break with ENODATA.
	 */
	si->current_ev = samba_tevent_context_init(NULL);
	if (si->current_ev != NULL) {
		tevent_context_set_wait_timeout(si->current_ev, 0);
	}
	tevent_reset_immediate(si->retry_im);
	tstream_ngtcp2_close_stream(si);
	if (si->push.subreq != NULL) {
		/*
		 * We don't care about any success,
		 * we just want to send out the disconnect
		 * message if possible without blocking,
		 * using tevent_context_set_wait_timeout(0).
		 */
		tevent_req_poll(si->push.subreq, si->current_ev);
		TALLOC_FREE(si->push.subreq);
	}
	TALLOC_FREE(si->current_ev);

	return 0;
}

static void tstream_ngtcp2_close_stream(struct tstream_ngtcp2 *si)
{
	struct tstream_ngtcp2_buffer *cbuf = NULL;
	struct tstream_ngtcp2_buffer *cnext = NULL;
	ngtcp2_ccerr ccerr;
	ngtcp2_ssize ret;

	if (si->conn == NULL) {
		return;
	}

	si->error = ECONNABORTED;

	TALLOC_FREE(si->keepalive_timer);
	TALLOC_FREE(si->pull.subreq);
	TALLOC_FREE(si->push.subreq);

	for (cbuf = si->writev.pushed; cbuf != NULL; cbuf = cnext) {
		cnext = cbuf->next;
		DLIST_REMOVE(si->writev.pushed, cbuf);
		TALLOC_FREE(cbuf);
	}

	for (cbuf = si->writev.pending; cbuf != NULL; cbuf = cnext) {
		cnext = cbuf->next;
		DLIST_REMOVE(si->writev.pending, cbuf);
		TALLOC_FREE(cbuf);
	}

	for (cbuf = si->readv.buffers; cbuf != NULL; cbuf = cnext) {
		cnext = cbuf->next;
		DLIST_REMOVE(si->readv.buffers, cbuf);
		TALLOC_FREE(cbuf);
	}

	if (si->disconnect.req != NULL) {
		tevent_req_received(si->disconnect.req);
		si->disconnect.req = NULL;
	}

	if (si->writev.req != NULL) {
		tevent_req_received(si->writev.req);
		si->writev.req = NULL;
	}

	if (si->readv.req != NULL) {
		tevent_req_received(si->readv.req);
		si->readv.req = NULL;
	}

	if (si->monitor.req != NULL) {
		tevent_req_received(si->monitor.req);
		si->monitor.req = NULL;
	}

	ngtcp2_ccerr_default(&ccerr);
	ret = ngtcp2_conn_write_connection_close(si->conn,
						 &si->path,
						 NULL,
						 si->push.b.buffer,
						 sizeof(si->push.b.buffer),
						 &ccerr,
						 tstream_ngtcp2_timestamp(NULL));
	ngtcp2_conn_del(si->conn);
	si->conn = NULL;

	if (ret <= 0) {
		return;
	}

	if (si->current_ev == NULL) {
		return;
	}

	si->push.b.length = ret;
	si->push.subreq = tdgram_sendto_send(si,
					     si->current_ev,
					     si->plain_dgram,
					     si->push.b.buffer,
					     si->push.b.length,
					     NULL);
	if (si->push.subreq == NULL) {
		return;
	}

	/*
	 * We don't call tevent_req_set_callback()
	 * here as we don't care about the
	 * result by default.
	 *
	 * We only care in tstream_ngtcp2_disconnect_send()
	 * so it's called there.
	 */
	return;
}

static void tstream_ngtcp2_retry_handshake(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tevent_req *req = si->handshake.req;
	NTSTATUS status;
	ssize_t ret;

	si->handshake.req = NULL;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return;
	}

	if (si->handshake.done) {
		si->error = EINVAL;
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return;
	}

	si->handshake.done = ngtcp2_conn_get_handshake_completed(si->conn);
	if (si->handshake.done) {
		goto verify;
	}

	si->handshake.req = req;
	tstream_ngtcp2_sendto_start(stream);
	tstream_ngtcp2_recvfrom_start(stream);
	return;

verify:
	status = tstream_tls_verify_peer(si->handshake.tlss);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IMAGE_CERT_REVOKED)) {
		si->error = EINVAL;
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		si->error = EIO;
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return;
	}

	ret = ngtcp2_conn_open_bidi_stream(si->conn,
					   &si->stream_id,
					   si);
	if (ret != 0) {
		si->error = EIO;
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return;
	}

	/*
	 * We don't expect incoming messages for
	 * this handshake anymore.
	 */
	TALLOC_FREE(si->pull.subreq);
	if (si->push.subreq != NULL) {
		/*
		 * But we need to wait until we flushed all
		 * pending messages to the kernel socket.
		 */
		si->handshake.req = req;
		return;
	}

	tevent_req_done(req);
}

static void tstream_ngtcp2_timer_start(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	ngtcp2_tstamp expire = ngtcp2_conn_get_expiry(si->conn);
	struct timespec ts_expire = { .tv_sec = 0, };
	struct timeval tv_expire = { .tv_sec = 0, };
	struct timeval_buf expire_buf;
	ngtcp2_duration rtc_offset = 0;
	ngtcp2_tstamp now = tstream_ngtcp2_timestamp(&rtc_offset);
	struct timespec ts_now = { .tv_sec = 0, };
	struct timeval tv_now = { .tv_sec = 0, };
	struct timeval_buf now_buf;
	int64_t diff = 0;
	bool was_last = (si->last_expire == expire);

	ts_expire = ngtcp2_tstamp2timespec(expire, rtc_offset);
	tv_expire = timespec2timeval(ts_expire);
	ts_now = ngtcp2_tstamp2timespec(now, rtc_offset);
	tv_now = timespec2timeval(ts_now);

	DBG_DEBUG("\nNOW: %s\nEXP: %s\n",
		  timespec_string_buf(&ts_now, true, &now_buf),
		  timespec_string_buf(&ts_expire, true, &expire_buf));

	diff = expire - now;

	DBG_DEBUG("si->last_expire[%"PRIu64"] %c= expire[%"PRIu64"] "
		  "now[%"PRIu64"] diff[%"PRId64"]\n",
		  si->last_expire,
		  was_last ? '=' : '!',
		  expire,
		  now,
		  diff);

	if (!was_last) {
		si->last_expire = expire;
	}

	if (diff <= 0) {
		/*
		 * already expired
		 *
		 * If we got the same value from
		 * ngtcp2_conn_get_expiry() as the
		 * last time we should avoid cpu spinning,
		 * so we always wait a keepalive cycle.
		 *
		 * Otherwise we want the timer to fire directly.
		 */
		if (was_last) {
			tv_expire = timeval_add(&tv_now, 0, si->keepalive_usecs);
		} else {
			tv_expire = (struct timeval) { .tv_sec = 0, };
		}
	}

	/*
	 * If we need to push out pending data from the caller
	 * and didn't hit a blocking state from
	 * ngtcp2_conn_writev_stream(), we want fire the timer
	 * directly.
	 */
	if (si->writev.pending != NULL && si->push.blocked == 0) {
		tv_expire = (struct timeval) { .tv_sec = 0, };
	}

	DBG_DEBUG("NEW-TIMER:\nnow: %s\nexp: %s\n",
		  timeval_str_buf(&tv_now, false, true, &now_buf),
		  timeval_str_buf(&tv_expire, false, true, &expire_buf));

	TALLOC_FREE(si->keepalive_timer);
	si->keepalive_timer = tevent_add_timer(si->current_ev,
					       si,
					       tv_expire,
					       tstream_ngtcp2_timer_handler,
					       stream);
	if (si->keepalive_timer == NULL) {
		si->error = ENOMEM;
		DBG_WARNING("si->error[%d] \n", si->error);
		tstream_ngtcp2_deferred_retry(stream);
		return;
	}
}

static void tstream_ngtcp2_timer_handler(struct tevent_context *ev,
					 struct tevent_timer *te,
					 struct timeval current_time,
					 void *private_data)
{
	struct tstream_context *stream =
		talloc_get_type_abort(private_data,
		struct tstream_context);
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);

	TALLOC_FREE(si->keepalive_timer);

	DBG_DEBUG("tstream_ngtcp2_sendto_start...\n");
	tstream_ngtcp2_sendto_start(stream);
}

static void tstream_ngtcp2_sendto_start(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tevent_req *req = si->writev.req;
	struct tstream_ngtcp2_buffer *cbuf = NULL;
	ngtcp2_ssize nwritten = -1;
	ngtcp2_vec _datav[1] = {{}};
	ngtcp2_ssize *pnwritten = NULL;
	int64_t stream_id = -1;
	ngtcp2_vec *datav = NULL;
	size_t datavcnt = 0;
	uint32_t sflags = NGTCP2_WRITE_STREAM_FLAG_NONE;
	ssize_t ret;
	size_t dbytes = 0;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return;
	}

	if (si->push.subreq != NULL) {
		DBG_DEBUG("ALREADY...\n");
		return;
	}

	if (si->push.b.length != 0) {
		DBG_DEBUG("DIRECTLY(%zu)...\n", si->push.b.length);
		goto send_directly;
	}

write_more:
	cbuf = si->writev.pending;
	if (cbuf != NULL) {
		_datav[0].base = cbuf->buffer + cbuf->offset;
		_datav[0].len = cbuf->length - cbuf->offset;
		dbytes = _datav[0].len;
		datav = _datav;
		datavcnt = ARRAY_SIZE(_datav);
		pnwritten = &nwritten;
		stream_id = si->stream_id;
		if (cbuf->next != NULL) {
			sflags |= NGTCP2_WRITE_STREAM_FLAG_MORE;
		} else {
			sflags &= ~NGTCP2_WRITE_STREAM_FLAG_MORE;
		}
	}

	ret = ngtcp2_conn_writev_stream(si->conn,
					&si->path,
					NULL,
					si->push.b.buffer,
					sizeof(si->push.b.buffer),
					pnwritten,
					sflags,
					stream_id,
					datav,
					datavcnt,
					tstream_ngtcp2_timestamp(NULL));

	DBG_DEBUG("sid[%"PRIi64"] "
		  "ngtcp2_conn_writev_stream ret[%zd] %s "
		  "dbytes[%zu] nwritten[%zd]\n",
		  si->stream_id,
		  ret, ngtcp2_strerror(ret),
		  dbytes, nwritten);

	if (ret == 0 || ret == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
		if (dbytes != 0) {
			/*
			 * The congestion windows is full
			 * we need to stop send and wait
			 * for incoming messages.
			 *
			 * We still call tstream_ngtcp2_timer_start()
			 * but that will see si->push.blocked.
			 */
			si->push.blocked += 1;
			tstream_ngtcp2_recvfrom_start(stream);
		}
		DBG_DEBUG("tstream_ngtcp2_timer_start...\n");
		tstream_ngtcp2_timer_start(stream);
		return;
	}

	if (ret == NGTCP2_ERR_WRITE_MORE) {
		if (nwritten < 1) {
			ngtcp2_conn_set_tls_error(si->conn, ret);
			si->error = EPIPE;
			DBG_WARNING("si->error[%d] \n", si->error);
			tstream_ngtcp2_deferred_retry(stream);
			return;
		}
		/* handled below */
	} else if (ret < 0) {
		ngtcp2_conn_set_tls_error(si->conn, ret);
		si->error = EPIPE;
		DBG_WARNING("si->error[%d] \n", si->error);
		tstream_ngtcp2_deferred_retry(stream);
		return;
	}

	if (nwritten > 0) {
		cbuf->offset += nwritten;
		if (cbuf->offset == cbuf->length) {
			DLIST_REMOVE(si->writev.pending, cbuf);
			cbuf->offset = si->writev.pushed_offset;
			si->writev.pushed_offset += cbuf->length;
			DLIST_ADD_END(si->writev.pushed, cbuf);
		}
	}
	if (ret == NGTCP2_ERR_WRITE_MORE) {
		DBG_DEBUG("MORE...\n");
		goto write_more;
	}

	DBG_DEBUG("tstream_ngtcp2_timer_start...\n");
	tstream_ngtcp2_timer_start(stream);

	si->push.b.length = ret;
send_directly:
	si->push.subreq = tdgram_sendto_send(si,
					     si->current_ev,
					     si->plain_dgram,
					     si->push.b.buffer,
					     si->push.b.length,
					     NULL);
	if (si->push.subreq == NULL) {
		si->error = ENOMEM;
		DBG_WARNING("si->error[%d] \n", si->error);
		tstream_ngtcp2_deferred_retry(stream);
		return;
	}
	tevent_req_set_callback(si->push.subreq,
				tstream_ngtcp2_sendto_done,
				stream);

	return;
}

static void tstream_ngtcp2_sendto_done(struct tevent_req *subreq)
{
	struct tstream_context *stream =
		tevent_req_callback_data(subreq,
		struct tstream_context);
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	ssize_t ret;
	int error = 0;

	SMB_ASSERT(si->push.subreq == subreq);
	si->push.subreq = NULL;

	ret = tdgram_sendto_recv(subreq, &error);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		si->error = error;
		DBG_WARNING("si->error[%d] \n", si->error);
		tstream_ngtcp2_deferred_retry(stream);
		return;
	}

	if (si->push.b.length != ret) {
		si->error = EIO;
		tstream_ngtcp2_deferred_retry(stream);
		return;
	}
	si->push.b.length = 0;

	DBG_DEBUG("tstream_ngtcp2_deferred_retry...\n");
	tstream_ngtcp2_deferred_retry(stream);
}

static void tstream_ngtcp2_recvfrom_start(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct timespec ts = timespec_current();
	struct timeval_buf tsbuf;

	if (si->pull.subreq != NULL) {
		DBG_DEBUG("%s: ALREADY... in_progress[%u]\n",
			  timespec_string_buf(&ts, true, &tsbuf),
			  tevent_req_is_in_progress(si->pull.subreq));
		return;
	}

	DBG_DEBUG("RECVFROM...\n");
	si->pull.subreq = tdgram_recvfrom_send(si,
					       si->current_ev,
					       si->plain_dgram);
	if (si->pull.subreq == NULL) {
		si->error = ENOMEM;
		DBG_WARNING("si->error[%d] \n", si->error);
		tstream_ngtcp2_deferred_retry(stream);
		return;
	}
	DBG_DEBUG("%s: ...RECVFROM in_progress[%u]\n",
		  timespec_string_buf(&ts, true, &tsbuf),
		  tevent_req_is_in_progress(si->pull.subreq));
	tevent_req_set_callback(si->pull.subreq,
				tstream_ngtcp2_recvfrom_done,
				stream);
}

static void tstream_ngtcp2_recvfrom_done(struct tevent_req *subreq)
{
	struct tstream_context *stream =
		tevent_req_callback_data(subreq,
		struct tstream_context);
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	ssize_t ret;
	int error = 0;
	uint8_t *buf = NULL;
	struct timespec ts = timespec_current();
	struct timeval_buf tsbuf;

	SMB_ASSERT(si->pull.subreq == subreq);
	si->pull.subreq = NULL;

	ret = tdgram_recvfrom_recv(subreq, &error, si, &buf, NULL);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		si->error = error;
		DBG_WARNING("si->error[%d] \n", si->error);
		tstream_ngtcp2_deferred_retry(stream);
		return;
	}

	ret = ngtcp2_conn_read_pkt(si->conn,
				   &si->path,
				   NULL,
				   buf,
				   ret,
				   tstream_ngtcp2_timestamp(NULL));

	DBG_DEBUG("%s: handshake_done[%u] sid[%"PRIi64"] "
		  "ngtcp2_conn_read_pkt ret[%zd] %s\n",
		  timespec_string_buf(&ts, true, &tsbuf),
		  si->handshake.done, si->stream_id,
		  ret, ngtcp2_strerror(ret));
	if (ret < 0) {
		si->error = ret;
		tstream_ngtcp2_deferred_retry(stream);
		return;
	}

	/*
	 * Once we got a message from the peer
	 * ngtcp2_conn_read_pkt() reset the
	 * internal state, so we might be able
	 * to send more data now or need to
	 * send some acks or pings.
	 */
	si->push.blocked = 0;
	DBG_DEBUG("tstream_ngtcp2_sendto_start...\n");
	tstream_ngtcp2_sendto_start(stream);

	/*
	 * We likely also got some incoming stream
	 * data so we need to check if a pending
	 * readv_send can make some progress.
	 */
	DBG_DEBUG("tstream_ngtcp2_deferred_retry...\n");
	tstream_ngtcp2_deferred_retry(stream);
}

static size_t tstream_ngtcp2_common_retry(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	size_t num_requests = 0;

	if (si->handshake.req != NULL && !si->handshake.done) {
		num_requests += 1;
	}

	if (si->writev.req != NULL) {
		num_requests += 1;
	}

	if (si->readv.req != NULL) {
		num_requests += 1;
	}

	if (si->monitor.req != NULL) {
		num_requests += 1;
	}

	if (num_requests == 0) {
		DBG_DEBUG("%s: DISMANTLE\n", __location__);
		si->last_expire = 0;
		TALLOC_FREE(si->keepalive_timer);
		TALLOC_FREE(si->pull.subreq);
		TALLOC_FREE(si->push.subreq);
		tevent_reset_immediate(si->retry_im);
		si->current_ev = NULL;
	}

	if (si->push.subreq == NULL && si->pull.subreq == NULL) {
		if (si->handshake.req != NULL && si->handshake.done) {
			struct tevent_req *req = si->handshake.req;

			si->handshake.req = NULL;

			/* tevent_req_defer_callback was used */
			tevent_req_done(req);
		}

		if (si->disconnect.req != NULL) {
			struct tevent_req *req = si->disconnect.req;

			si->disconnect.req = NULL;

			/* tevent_req_defer_callback was used */
			tevent_req_done(req);
		}
	}

	return num_requests;
}

static void tstream_ngtcp2_direct_retry(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	size_t num_requests = tstream_ngtcp2_common_retry(stream);

	/*
	 * If there are more than one pending highlevel
	 * request we need to retry again.
	 *
	 * But we can't do that if
	 * ngtcp2_conn_writev_stream() indicated
	 * a blocking situation. So we need to
	 * wait for [e]poll to notice an incoming
	 * message or the keepalive timer to
	 * trigger more progress.
	 */
	if (num_requests > 1 && si->push.blocked == 0) {
		DBG_DEBUG("tstream_ngtcp2_deferred_retry...\n");
		tstream_ngtcp2_deferred_retry(stream);
	}

	if (si->handshake.req != NULL && !si->handshake.done) {
		tstream_ngtcp2_retry_handshake(stream);
		return;
	}

	if (si->writev.req != NULL) {
		tstream_ngtcp2_writev_retry(stream);
		return;
	}

	if (si->readv.req != NULL) {
		tstream_ngtcp2_readv_retry(stream);
		return;
	}

	if (si->monitor.req != NULL) {
		tstream_ngtcp2_monitor_retry(stream);
		return;
	}
}

static void tstream_ngtcp2_retry_trigger(struct tevent_context *ctx,
					 struct tevent_immediate *im,
					 void *private_data)
{
	struct tstream_context *stream =
		talloc_get_type_abort(private_data,
		struct tstream_context);

	tstream_ngtcp2_direct_retry(stream);
}

static void tstream_ngtcp2_deferred_retry(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	size_t num_requests = tstream_ngtcp2_common_retry(stream);

	if (num_requests == 0) {
		/*
		 * connection is dismantled
		 * and si->current_ev is NULL,
		 * so we need to stop here
		 * and wait for the next
		 * highlevel request to start
		 * the engine again.
		 */
		return;
	}

	tevent_schedule_immediate(si->retry_im,
				  si->current_ev,
				  tstream_ngtcp2_retry_trigger,
				  stream);
}

static ssize_t tstream_ngtcp2_pending_bytes(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tstream_ngtcp2_buffer *cbuf = NULL;
	size_t ret = 0;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		errno = si->error;
		return -1;
	}

	for (cbuf = si->readv.buffers; cbuf != NULL; cbuf = cbuf->next) {
		ret += cbuf->length - cbuf->offset;
	}

	DBG_DEBUG("ret[%zu]\n", ret);

	return ret;
}

struct tstream_ngtcp2_readv_state {
	struct tstream_context *stream;

	struct iovec *vector;
	int count;

	int ret;
};

static void tstream_ngtcp2_readv_cleanup(struct tevent_req *req,
					 enum tevent_req_state req_state)
{
	struct tstream_ngtcp2_readv_state *state =
		tevent_req_data(req,
		struct tstream_ngtcp2_readv_state);

	if (state->stream != NULL) {
		struct tstream_context *stream = state->stream;
		struct tstream_ngtcp2 *si =
			tstream_context_data(stream,
			struct tstream_ngtcp2);

		state->stream = NULL;

		SMB_ASSERT(si->readv.req == req);
		si->readv.req = NULL;

		tstream_ngtcp2_deferred_retry(stream);
	}
}

static void tstream_ngtcp2_readv_next(struct tevent_req *req);

static struct tevent_req *tstream_ngtcp2_readv_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *stream,
					struct iovec *vector,
					size_t count)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tevent_req *req;
	struct tstream_ngtcp2_readv_state *state;

	SMB_ASSERT(si->readv.req == NULL);

	if (si->current_ev != ev) {
		SMB_ASSERT(si->push.subreq == NULL);
		SMB_ASSERT(si->pull.subreq == NULL);
		SMB_ASSERT(si->keepalive_timer == NULL);
	}

	si->current_ev = ev;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_ngtcp2_readv_state);
	if (req == NULL) {
		return NULL;
	}

	state->stream = stream;
	state->ret = 0;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
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

	DBG_DEBUG("tstream_ngtcp2_readv_next...\n");
	si->readv.req = req;
	tevent_req_defer_callback(req, ev);
	tevent_req_set_cleanup_fn(req, tstream_ngtcp2_readv_cleanup);
	tstream_ngtcp2_readv_next(req);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tstream_ngtcp2_readv_next(struct tevent_req *req)
{
	struct tstream_ngtcp2_readv_state *state =
		tevent_req_data(req,
		struct tstream_ngtcp2_readv_state);
	struct tstream_ngtcp2 *si =
		tstream_context_data(state->stream,
		struct tstream_ngtcp2);

	DBG_DEBUG("START si->read.buffers[%u] state->count[%u] state->ret[%u]\n",
		  !!si->readv.buffers, state->count, state->ret);

	/*
	 * copy the pending buffer first
	 */
	while (si->readv.buffers != NULL && state->count > 0) {
		struct tstream_ngtcp2_buffer *cbuf = si->readv.buffers;
		uint8_t *base = (uint8_t *)state->vector[0].iov_base;
		size_t len = MIN(cbuf->length - cbuf->offset, state->vector[0].iov_len);

		memcpy(base, cbuf->buffer + cbuf->offset, len);

		base += len;
		state->vector[0].iov_base = (char *) base;
		state->vector[0].iov_len -= len;

		cbuf->offset += len;
		if (cbuf->offset == cbuf->length) {
			DLIST_REMOVE(si->readv.buffers, cbuf);
			ngtcp2_conn_extend_max_offset(si->conn, cbuf->length);
			ngtcp2_conn_extend_max_stream_offset(si->conn,
							     si->stream_id,
							     cbuf->length);
			TALLOC_FREE(cbuf);
		}

		if (state->vector[0].iov_len == 0) {
			state->vector += 1;
			state->count -= 1;
		}

		state->ret += len;
	}

	if (state->count == 0) {
		DBG_DEBUG("DONE state->red[%d]\n", state->ret);
		tevent_req_done(req);
		return;
	}

	DBG_DEBUG("tstream_ngtcp2_recvfrom_start...\n");
	tstream_ngtcp2_recvfrom_start(state->stream);
}

static void tstream_ngtcp2_readv_retry(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tevent_req *req = si->readv.req;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return;
	}

	DBG_DEBUG("tstream_ngtcp2_readv_next...\n");
	tstream_ngtcp2_readv_next(req);
}

static int tstream_ngtcp2_readv_recv(struct tevent_req *req,
				     int *perrno)
{
	struct tstream_ngtcp2_readv_state *state =
		tevent_req_data(req,
		struct tstream_ngtcp2_readv_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}
	DBG_DEBUG("tsocket_simple_int_recv... %d: %s\n",
		  ret, strerror(ret == -1 ? *perrno : 0));

	tevent_req_received(req);
	return ret;
}

struct tstream_ngtcp2_writev_state {
	struct tstream_context *stream;

	int ret;
};

static void tstream_ngtcp2_writev_cleanup(struct tevent_req *req,
					  enum tevent_req_state req_state)
{
	struct tstream_ngtcp2_writev_state *state =
		tevent_req_data(req,
		struct tstream_ngtcp2_writev_state);

	if (state->stream != NULL) {
		struct tstream_context *stream = state->stream;
		struct tstream_ngtcp2 *si =
			tstream_context_data(stream,
			struct tstream_ngtcp2);

		state->stream = NULL;

		SMB_ASSERT(si->writev.req == req);
		si->writev.req = NULL;

		tstream_ngtcp2_deferred_retry(stream);
	}
}

static struct tevent_req *tstream_ngtcp2_writev_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *stream,
					const struct iovec *vector,
					size_t count)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tevent_req *req = NULL;
	struct tstream_ngtcp2_writev_state *state = NULL;
	struct tstream_ngtcp2_buffer *buffers = NULL;
	struct tstream_ngtcp2_buffer *cbuf = NULL;
	size_t vi = 0;
	size_t vofs = 0;
	size_t nbytes = 0;
	size_t nbuffers = 0;

	SMB_ASSERT(si->writev.req == NULL);

	if (si->current_ev != ev) {
		SMB_ASSERT(si->push.subreq == NULL);
		SMB_ASSERT(si->pull.subreq == NULL);
		SMB_ASSERT(si->keepalive_timer == NULL);
	}

	si->current_ev = ev;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_ngtcp2_writev_state);
	if (req == NULL) {
		return NULL;
	}

	state->stream = stream;
	state->ret = 0;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return tevent_req_post(req, ev);
	}

	for (vi = 0; vi < count;) {
		const uint8_t *b = vector[vi].iov_base;
		size_t l = vector[vi].iov_len;
		size_t n;

		b += vofs;
		l -= vofs;

		if (l == 0) {
			vofs = 0;
			vi += 1;
			continue;
		}

		if (cbuf == NULL) {
			cbuf = talloc(si, struct tstream_ngtcp2_buffer);
			if (cbuf == NULL) {
				si->error = ENOMEM;
				DBG_WARNING("si->error[%d] \n", si->error);
				tevent_req_error(req, si->error);
				return tevent_req_post(req, ev);
			}
			cbuf->prev = cbuf->next = NULL;
			cbuf->offset = 0;
			cbuf->length = 0;
			talloc_reparent(si, state, cbuf);
			DLIST_ADD_END(buffers, cbuf);
		}

		n = ARRAY_SIZE(cbuf->buffer) - cbuf->length;
		n = MIN(n, l);

		memcpy(cbuf->buffer + cbuf->length, b, n);

		nbytes += n;

		vofs += n;
		cbuf->length += n;
		if (ARRAY_SIZE(cbuf->buffer) == cbuf->length) {
			cbuf = NULL;
		}
	}

	while (buffers != NULL) {
		cbuf = buffers;

		DLIST_REMOVE(buffers, cbuf);

		nbuffers += 1;
		DLIST_ADD_END(si->writev.pending, cbuf);
		talloc_reparent(state, si, cbuf);
	}

	DBG_DEBUG("tstream_ngtcp2_writev_retry... "
		  "count[%zu] buffers[%zu] bytes[%zu]\n",
		  count, nbuffers, nbytes);
	si->writev.req = req;
	tevent_req_defer_callback(req, ev);
	tevent_req_set_cleanup_fn(req, tstream_ngtcp2_writev_cleanup);
	tstream_ngtcp2_writev_retry(state->stream);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tstream_ngtcp2_writev_retry(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tevent_req *req = si->writev.req;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return;
	}

	if (si->writev.pending == NULL) {
		DBG_DEBUG("sid[%"PRIi64"] done\n", si->stream_id);
		tevent_req_done(req);
		return;
	}

	DBG_DEBUG("tstream_ngtcp2_sendto_start...\n");
	tstream_ngtcp2_sendto_start(stream);
}

static int tstream_ngtcp2_writev_recv(struct tevent_req *req,
				      int *perrno)
{
	struct tstream_ngtcp2_writev_state *state =
		tevent_req_data(req,
		struct tstream_ngtcp2_writev_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}
	DBG_DEBUG("tsocket_simple_int_recv... %d: %s\n",
		  ret, strerror(ret == -1 ? *perrno : 0));

	tevent_req_received(req);
	return ret;
}

struct tstream_ngtcp2_disconnect_state {
	struct tstream_context *stream;
};

static void tstream_ngtcp2_disconnect_cleanup(struct tevent_req *req,
					      enum tevent_req_state req_state)
{
	struct tstream_ngtcp2_disconnect_state *state =
		tevent_req_data(req,
		struct tstream_ngtcp2_disconnect_state);

	if (state->stream != NULL) {
		struct tstream_ngtcp2 *si =
			tstream_context_data(state->stream,
			struct tstream_ngtcp2);

		SMB_ASSERT(si->disconnect.req == req);
		si->disconnect.req = NULL;
		state->stream = NULL;
	}
}

static struct tevent_req *tstream_ngtcp2_disconnect_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si =
		tstream_context_data(stream,
		struct tstream_ngtcp2);
	struct tevent_req *req;
	struct tstream_ngtcp2_disconnect_state *state;

	SMB_ASSERT(si->disconnect.req == NULL);

	if (si->current_ev != ev) {
		SMB_ASSERT(si->push.subreq == NULL);
		SMB_ASSERT(si->pull.subreq == NULL);
		SMB_ASSERT(si->keepalive_timer == NULL);
	}

	si->current_ev = ev;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_ngtcp2_disconnect_state);
	if (req == NULL) {
		return NULL;
	}
	state->stream = stream;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return tevent_req_post(req, ev);
	}

	tevent_req_defer_callback(req, ev);
	tevent_req_set_cleanup_fn(req, tstream_ngtcp2_disconnect_cleanup);

	tstream_ngtcp2_close_stream(si);

	si->disconnect.req = req;
	if (si->push.subreq != NULL) {
		/*
		 * We need to wait until we flushed all
		 * pending messages to the kernel socket.
		 */
		tevent_req_set_callback(si->push.subreq,
					tstream_ngtcp2_sendto_done,
					stream);
		return req;
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static int tstream_ngtcp2_disconnect_recv(struct tevent_req *req,
					  int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	DBG_DEBUG("tsocket_simple_int_recv... %d: %s\n",
		  ret, strerror(ret == -1 ? *perrno : 0));

	tevent_req_received(req);
	return ret;
}

struct tstream_ngtcp2_monitor_state {
	struct tstream_context *stream;
};

static void tstream_ngtcp2_monitor_cleanup(struct tevent_req *req,
					   enum tevent_req_state req_state)
{
	struct tstream_ngtcp2_monitor_state *state =
		tevent_req_data(req,
		struct tstream_ngtcp2_monitor_state);

	if (state->stream != NULL) {
		struct tstream_context *stream = state->stream;
		struct tstream_ngtcp2 *si =
			tstream_context_data(stream,
			struct tstream_ngtcp2);

		state->stream = NULL;

		SMB_ASSERT(si->monitor.req == req);
		si->monitor.req = NULL;

		tstream_ngtcp2_deferred_retry(stream);
	}
}

static struct tevent_req *tstream_ngtcp2_monitor_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si = tstream_context_data(stream,
							 struct tstream_ngtcp2);
	struct tevent_req *req;
	struct tstream_ngtcp2_monitor_state *state;

	SMB_ASSERT(si->monitor.req == NULL);

	if (si->current_ev != ev) {
		SMB_ASSERT(si->push.subreq == NULL);
		SMB_ASSERT(si->pull.subreq == NULL);
		SMB_ASSERT(si->keepalive_timer == NULL);
	}

	si->current_ev = ev;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_ngtcp2_monitor_state);
	if (req == NULL) {
		return NULL;
	}
	state->stream = stream;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return tevent_req_post(req, ev);
	}

	DBG_DEBUG("tstream_ngtcp2_monitor_retry...\n");
	si->monitor.req = req;
	tevent_req_defer_callback(req, ev);
	tevent_req_set_cleanup_fn(req, tstream_ngtcp2_monitor_cleanup);
	tstream_ngtcp2_monitor_retry(stream);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
}

static void tstream_ngtcp2_monitor_retry(struct tstream_context *stream)
{
	struct tstream_ngtcp2 *si = tstream_context_data(stream,
							 struct tstream_ngtcp2);
	struct tevent_req *req = si->monitor.req;

	if (si->error != 0) {
		DBG_WARNING("si->error[%d] \n", si->error);
		tevent_req_error(req, si->error);
		return;
	}

	DBG_DEBUG("AGAIN...\n");

	tstream_ngtcp2_timer_start(stream);
	tstream_ngtcp2_recvfrom_start(stream);
}

static int tstream_ngtcp2_monitor_recv(struct tevent_req *req, int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	DBG_DEBUG("tsocket_simple_int_recv... %d: %s\n",
		  ret, strerror(ret == -1 ? *perrno : 0));

	tevent_req_received(req);
	return ret;
}

static const struct tstream_context_ops tstream_ngtcp2_ops = {
	.name			= "ngtcp2",

	.pending_bytes		= tstream_ngtcp2_pending_bytes,

	.readv_send		= tstream_ngtcp2_readv_send,
	.readv_recv		= tstream_ngtcp2_readv_recv,

	.writev_send		= tstream_ngtcp2_writev_send,
	.writev_recv		= tstream_ngtcp2_writev_recv,

	.disconnect_send	= tstream_ngtcp2_disconnect_send,
	.disconnect_recv	= tstream_ngtcp2_disconnect_recv,

	.monitor_send		= tstream_ngtcp2_monitor_send,
	.monitor_recv		= tstream_ngtcp2_monitor_recv,
};

#endif /* HAVE_LIBNGTCP2 */

struct tstream_tls_ngtcp2_connect_state {
	struct tstream_context *quic_stream;
};

static void tstream_tls_ngtcp2_connect_cleanup(struct tevent_req *req,
					       enum tevent_req_state req_state);

struct tevent_req *_tstream_tls_ngtcp2_connect_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct tstream_tls_params *tlsp,
						    uint32_t timeout_msec,
						    const char *alpn,
						    int *sockfd,
						    const char *location)
{
	struct tevent_req *req = NULL;
	struct tstream_tls_ngtcp2_connect_state *state = NULL;
#ifdef HAVE_LIBNGTCP2
	struct tstream_ngtcp2 *si = NULL;
	gnutls_datum_t alpn_data = {
		.data = discard_const_p(unsigned char, "smb"),
		.size = 3,
	};
	ngtcp2_callbacks callbacks = {
		.client_initial = /* required client */
			ngtcp2_crypto_client_initial_cb,
		.recv_crypto_data = /* required */
			ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb, /* required */
		.decrypt = ngtcp2_crypto_decrypt_cb, /* required */
		.hp_mask = ngtcp2_crypto_hp_mask_cb, /* required */
		.recv_stream_data =
			tstream_ngtcp2_recv_stream_data_cb, /* used */
		.acked_stream_data_offset =
			tstream_ngtcp2_acked_stream_data_offset_cb, /* used */
		.stream_close =
			tstream_ngtcp2_stream_close_cb, /* used */
		.recv_stateless_reset =
			tstream_ngtcp2_recv_stateless_reset_cb, /* used */
		.recv_retry = ngtcp2_crypto_recv_retry_cb, /* required client */
		.rand = tstream_ngtcp2_rand_cb, /* required */
		.get_new_connection_id = /* required */
			tstream_ngtcp2_get_new_connection_id_cb,
		.update_key = ngtcp2_crypto_update_key_cb, /* required */
		.stream_reset =
			tstream_ngtcp2_stream_reset_cb, /* used */
		.delete_crypto_aead_ctx = /* required */
			ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = /* required */
			ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.get_path_challenge_data = /* required */
			ngtcp2_crypto_get_path_challenge_data_cb,
		.version_negotiation = /* required */
			ngtcp2_crypto_version_negotiation_cb,
	};
	ngtcp2_cid dcid = {
		.datalen = NGTCP2_MIN_INITIAL_DCIDLEN,
	};
	ngtcp2_cid scid = {
		.datalen = NGTCP2_MIN_INITIAL_DCIDLEN,
	};
	ngtcp2_settings settings = {};
	ngtcp2_transport_params params = {};
	uint32_t available_versions32[2];
	union {
		uint32_t v32[2];
		uint8_t v8[8];
	} available_versions;
	NTSTATUS status;
	int ret;
#endif /* HAVE_LIBNGTCP2 */
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_tls_ngtcp2_connect_state);
	if (req == NULL) {
		return NULL;
	}
	tevent_req_defer_callback(req, ev);
	tevent_req_set_cleanup_fn(req, tstream_tls_ngtcp2_connect_cleanup);

#ifdef HAVE_LIBNGTCP2
	state->quic_stream = tstream_context_create(state,
						    &tstream_ngtcp2_ops,
						    &si,
						    struct tstream_ngtcp2,
						    location);
	if (tevent_req_nomem(state->quic_stream, req)) {
		return tevent_req_post(req, ev);
	}
	ZERO_STRUCTP(si);
	talloc_set_destructor(si, tstream_ngtcp2_destructor);

	si->laddr = (struct samba_sockaddr) {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};
	si->raddr = (struct samba_sockaddr) {
		.sa_socklen = sizeof(struct sockaddr_storage),
	};

	ret = getsockname(*sockfd, &si->laddr.u.sa, &si->laddr.sa_socklen);
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	ret = getpeername(*sockfd, &si->raddr.u.sa, &si->raddr.sa_socklen);
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	ret = tdgram_bsd_existing_socket(si, *sockfd, &si->plain_dgram);
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}
	*sockfd = -1;
	tdgram_bsd_optimize_recvfrom(si->plain_dgram, true);
#endif /* HAVE_LIBNGTCP2 */

	ok = tevent_req_set_endtime(req, ev,
				    timeval_current_ofs_msec(timeout_msec));
	if (!ok) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	ok = tstream_tls_params_quic_enabled(tlsp);
	if (!ok) {
		goto invalid_parameter_mix;
	}

#ifdef HAVE_LIBNGTCP2

	si->conn_ref.get_conn = qwrap_ngtcp2_conn_ref_get_conn;
	si->conn_ref.user_data = state->quic_stream;

	si->handshake.tlss = talloc_zero(state, struct tstream_tls);
	if (tevent_req_nomem(si->handshake.tlss, req)) {
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(si->handshake.tlss, tstream_tls_destructor);
	si->handshake.tlss->is_server = false;

	status = tstream_tls_prepare_gnutls(tlsp, si->handshake.tlss);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	gnutls_session_set_ptr(si->handshake.tlss->tls_session, &si->conn_ref);
	ngtcp2_crypto_gnutls_configure_client_session(si->handshake.tlss->tls_session);

	ret = gnutls_alpn_set_protocols(si->handshake.tlss->tls_session,
					&alpn_data, 1,
					GNUTLS_ALPN_MANDATORY);
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, dcid.data, dcid.datalen);
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	ret = gnutls_rnd(GNUTLS_RND_RANDOM, scid.data, scid.datalen);
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	si->path = (ngtcp2_path) {
		.local = {
			.addr = &si->laddr.u.sa,
			.addrlen = si->laddr.sa_socklen,
		},
		.remote = {
			.addr = &si->raddr.u.sa,
			.addrlen = si->raddr.sa_socklen,
		},
	};

	available_versions32[0] = NGTCP2_PROTO_VER_V2;
	available_versions32[1] = NGTCP2_PROTO_VER_V1;

	available_versions.v32[0] = htonl(available_versions32[0]);
	available_versions.v32[1] = htonl(available_versions32[1]);

	ngtcp2_settings_default(&settings);

	settings.initial_ts = tstream_ngtcp2_timestamp(NULL);
	settings.handshake_timeout = timeout_msec * NGTCP2_MILLISECONDS;
	settings.log_printf = tstream_ngtcp2_log_printf;
	settings.qlog_write = tstream_ngtcp2_qlog_write_cb;

	if (CHECK_DEBUGLVL(11)) {
		tstream_ngtcp2_verbose = true;
	}

	settings.available_versions = available_versions32;
	settings.available_versionslen = ARRAY_SIZE(available_versions32);

	/*
	 * Copied from quic_transport_param_init
	 */
	params.max_udp_payload_size = 65527 /* QUIC_MAX_UDP_PAYLOAD */;
	params.ack_delay_exponent = 3 /* QUIC_DEF_ACK_DELAY_EXPONENT */;
	params.max_ack_delay = 25000 /* QUIC_DEF_ACK_DELAY */;
	params.active_connection_id_limit = 7 /* QUIC_CONN_ID_DEF */;
	params.max_idle_timeout = 30000000 /* QUIC_DEF_IDLE_TIMEOUT */;
	params.initial_max_data = (uint64_t)65536U /* QUIC_PATH_MAX_PMTU */ * 32;
	params.initial_max_stream_data_bidi_local = (uint64_t)65536U /* QUIC_PATH_MAX_PMTU */ * 16;
	params.initial_max_stream_data_bidi_remote = (uint64_t)65536U /* QUIC_PATH_MAX_PMTU */ * 16;
	params.initial_max_stream_data_uni = (uint64_t)65536U /* QUIC_PATH_MAX_PMTU */ * 16;
	params.initial_max_streams_bidi = 100 /* QUIC_DEF_STREAMS */;
	params.initial_max_streams_uni = 100 /* QUIC_DEF_STREAMS */;

	params.version_info_present = 1;
	params.version_info.chosen_version = NGTCP2_PROTO_VER_V1;
	params.version_info.available_versions = available_versions.v8;
	params.version_info.available_versionslen = ARRAY_SIZE(available_versions.v8);

	params.max_ack_delay *= NGTCP2_MICROSECONDS;
	params.max_idle_timeout *= NGTCP2_MICROSECONDS;

	ret = ngtcp2_conn_client_new(&si->conn,
				     &dcid,
				     &scid,
				     &si->path,
				     NGTCP2_PROTO_VER_V1,
				     &callbacks,
				     &settings,
				     &params,
				     NULL,
				     state->quic_stream);
	if (ret != 0) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	si->keepalive_usecs = 1500 * 1000;
	ngtcp2_conn_set_keep_alive_timeout(si->conn, si->keepalive_usecs * NGTCP2_MICROSECONDS);
	ngtcp2_conn_set_tls_native_handle(si->conn,
					  si->handshake.tlss->tls_session);

	si->retry_im = tevent_create_immediate(si);
	if (tevent_req_nomem(si->retry_im, req)) {
		return tevent_req_post(req, ev);
	}

	si->current_ev = ev;
	si->handshake.req = req;
	tstream_ngtcp2_retry_handshake(state->quic_stream);
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}

	return req;
#endif /* HAVE_LIBNGTCP2 */
invalid_parameter_mix:
	tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER_MIX);
	return tevent_req_post(req, ev);
}

static void tstream_tls_ngtcp2_connect_cleanup(struct tevent_req *req,
					       enum tevent_req_state req_state)
{
	struct tstream_tls_ngtcp2_connect_state *state =
		tevent_req_data(req,
		struct tstream_tls_ngtcp2_connect_state);

	if (req_state == TEVENT_REQ_DONE) {
		return;
	}

	TALLOC_FREE(state->quic_stream);
}

int tstream_tls_ngtcp2_connect_recv(struct tevent_req *req,
				    int *perrno,
				    TALLOC_CTX *mem_ctx,
				    struct tstream_context **quic_stream)
{
	struct tstream_tls_ngtcp2_connect_state *state =
		tevent_req_data(req,
		struct tstream_tls_ngtcp2_connect_state);

	if (tevent_req_is_unix_error(req, perrno)) {
		tevent_req_received(req);
		return -1;
	}

	*quic_stream = talloc_move(mem_ctx, &state->quic_stream);
	tevent_req_received(req);
	return 0;
}
