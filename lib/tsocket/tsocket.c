/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tsocket
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/filesys.h"
#include "tsocket.h"
#include "tsocket_internal.h"
#include "lib/util/iov_buf.h"

int tsocket_simple_int_recv(struct tevent_req *req, int *perrno)
{
	enum tevent_req_state state;
	uint64_t error;

	if (!tevent_req_is_error(req, &state, &error)) {
		return 0;
	}

	switch (state) {
	case TEVENT_REQ_NO_MEMORY:
		*perrno = ENOMEM;
		return -1;
	case TEVENT_REQ_TIMED_OUT:
		*perrno = ETIMEDOUT;
		return -1;
	case TEVENT_REQ_USER_ERROR:
		*perrno = (int)error;
		return -1;
	default:
		break;
	}

	*perrno = EIO;
	return -1;
}

struct tsocket_address *_tsocket_address_create(TALLOC_CTX *mem_ctx,
						const struct tsocket_address_ops *ops,
						void *pstate,
						size_t psize,
						const char *type,
						const char *location)
{
	void **ppstate = (void **)pstate;
	struct tsocket_address *addr;

	addr = talloc_zero(mem_ctx, struct tsocket_address);
	if (!addr) {
		return NULL;
	}
	addr->ops = ops;
	addr->location = location;
	addr->private_data = talloc_size(addr, psize);
	if (!addr->private_data) {
		talloc_free(addr);
		return NULL;
	}
	talloc_set_name_const(addr->private_data, type);

	*ppstate = addr->private_data;
	return addr;
}

char *tsocket_address_string(const struct tsocket_address *addr,
			     TALLOC_CTX *mem_ctx)
{
	if (!addr) {
		return talloc_strdup(mem_ctx, "NULL");
	}
	return addr->ops->string(addr, mem_ctx);
}

struct tsocket_address *_tsocket_address_copy(const struct tsocket_address *addr,
					      TALLOC_CTX *mem_ctx,
					      const char *location)
{
	return addr->ops->copy(addr, mem_ctx, location);
}

struct tdgram_context {
	const char *location;
	const struct tdgram_context_ops *ops;
	void *private_data;

	struct tevent_req *recvfrom_req;
	struct tevent_req *sendto_req;
};

static int tdgram_context_destructor(struct tdgram_context *dgram)
{
	if (dgram->recvfrom_req) {
		tevent_req_received(dgram->recvfrom_req);
	}

	if (dgram->sendto_req) {
		tevent_req_received(dgram->sendto_req);
	}

	return 0;
}

struct tdgram_context *_tdgram_context_create(TALLOC_CTX *mem_ctx,
					const struct tdgram_context_ops *ops,
					void *pstate,
					size_t psize,
					const char *type,
					const char *location)
{
	struct tdgram_context *dgram;
	void **ppstate = (void **)pstate;
	void *state;

	dgram = talloc(mem_ctx, struct tdgram_context);
	if (dgram == NULL) {
		return NULL;
	}
	dgram->location		= location;
	dgram->ops		= ops;
	dgram->recvfrom_req	= NULL;
	dgram->sendto_req	= NULL;

	state = talloc_size(dgram, psize);
	if (state == NULL) {
		talloc_free(dgram);
		return NULL;
	}
	talloc_set_name_const(state, type);

	dgram->private_data = state;

	talloc_set_destructor(dgram, tdgram_context_destructor);

	*ppstate = state;
	return dgram;
}

void *_tdgram_context_data(struct tdgram_context *dgram)
{
	return dgram->private_data;
}

struct tdgram_recvfrom_state {
	const struct tdgram_context_ops *ops;
	struct tdgram_context *dgram;
	uint8_t *buf;
	size_t len;
	struct tsocket_address *src;
};

static void tdgram_recvfrom_cleanup(struct tevent_req *req,
				    enum tevent_req_state req_state)
{
	struct tdgram_recvfrom_state *state = tevent_req_data(req,
					      struct tdgram_recvfrom_state);

	if (state->dgram) {
		state->dgram->recvfrom_req = NULL;
		state->dgram = NULL;
	}
}

static void tdgram_recvfrom_done(struct tevent_req *subreq);

struct tevent_req *tdgram_recvfrom_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tdgram_context *dgram)
{
	struct tevent_req *req;
	struct tdgram_recvfrom_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_recvfrom_state);
	if (req == NULL) {
		return NULL;
	}

	state->ops = dgram->ops;
	state->dgram = dgram;
	state->buf = NULL;
	state->len = 0;
	state->src = NULL;

	if (dgram->recvfrom_req) {
		tevent_req_error(req, EBUSY);
		goto post;
	}
	dgram->recvfrom_req = req;

	tevent_req_set_cleanup_fn(req, tdgram_recvfrom_cleanup);

	subreq = state->ops->recvfrom_send(state, ev, dgram);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tdgram_recvfrom_done, req);
	if (!tevent_req_is_in_progress(subreq)) {
		/*
		 * Allow the caller of
		 * tdgram_recvfrom_send() to
		 * see tevent_req_is_in_progress()
		 * reporting false too.
		 *
		 * Useful for callers using
		 * tdgram_bsd_optimize_recvfrom(true)
		 * in order to check if data
		 * was already waiting in the
		 * receice buffer.
		 */
		tdgram_recvfrom_done(subreq);
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tdgram_recvfrom_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct tdgram_recvfrom_state *state = tevent_req_data(req,
					      struct tdgram_recvfrom_state);
	ssize_t ret;
	int sys_errno;

	ret = state->ops->recvfrom_recv(subreq, &sys_errno, state,
					&state->buf, &state->src);
	if (ret == -1) {
		tevent_req_error(req, sys_errno);
		return;
	}

	state->len = ret;

	tevent_req_done(req);
}

ssize_t tdgram_recvfrom_recv(struct tevent_req *req,
			     int *perrno,
			     TALLOC_CTX *mem_ctx,
			     uint8_t **buf,
			     struct tsocket_address **src)
{
	struct tdgram_recvfrom_state *state = tevent_req_data(req,
					      struct tdgram_recvfrom_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		*buf = talloc_move(mem_ctx, &state->buf);
		ret = state->len;
		if (src) {
			*src = talloc_move(mem_ctx, &state->src);
		}
	}

	tevent_req_received(req);
	return ret;
}

struct tdgram_sendto_state {
	const struct tdgram_context_ops *ops;
	struct tdgram_context *dgram;
	ssize_t ret;
};

static void tdgram_sendto_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state)
{
	struct tdgram_sendto_state *state = tevent_req_data(req,
					    struct tdgram_sendto_state);

	if (state->dgram) {
		state->dgram->sendto_req = NULL;
		state->dgram = NULL;
	}
}

static void tdgram_sendto_done(struct tevent_req *subreq);

struct tevent_req *tdgram_sendto_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct tdgram_context *dgram,
				      const uint8_t *buf, size_t len,
				      const struct tsocket_address *dst)
{
	struct tevent_req *req;
	struct tdgram_sendto_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_sendto_state);
	if (req == NULL) {
		return NULL;
	}

	state->ops = dgram->ops;
	state->dgram = dgram;
	state->ret = -1;

	if (len == 0) {
		tevent_req_error(req, EINVAL);
		goto post;
	}

	if (dgram->sendto_req) {
		tevent_req_error(req, EBUSY);
		goto post;
	}
	dgram->sendto_req = req;

	tevent_req_set_cleanup_fn(req, tdgram_sendto_cleanup);

	subreq = state->ops->sendto_send(state, ev, dgram,
					 buf, len, dst);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tdgram_sendto_done, req);

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tdgram_sendto_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct tdgram_sendto_state *state = tevent_req_data(req,
					    struct tdgram_sendto_state);
	ssize_t ret;
	int sys_errno;

	ret = state->ops->sendto_recv(subreq, &sys_errno);
	if (ret == -1) {
		tevent_req_error(req, sys_errno);
		return;
	}

	state->ret = ret;

	tevent_req_done(req);
}

ssize_t tdgram_sendto_recv(struct tevent_req *req,
			   int *perrno)
{
	struct tdgram_sendto_state *state = tevent_req_data(req,
					    struct tdgram_sendto_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tdgram_disconnect_state {
	const struct tdgram_context_ops *ops;
};

static void tdgram_disconnect_done(struct tevent_req *subreq);

struct tevent_req *tdgram_disconnect_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct tdgram_context *dgram)
{
	struct tevent_req *req;
	struct tdgram_disconnect_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	state->ops = dgram->ops;

	if (dgram->recvfrom_req || dgram->sendto_req) {
		tevent_req_error(req, EBUSY);
		goto post;
	}

	subreq = state->ops->disconnect_send(state, ev, dgram);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tdgram_disconnect_done, req);

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tdgram_disconnect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct tdgram_disconnect_state *state = tevent_req_data(req,
						struct tdgram_disconnect_state);
	int ret;
	int sys_errno;

	ret = state->ops->disconnect_recv(subreq, &sys_errno);
	if (ret == -1) {
		tevent_req_error(req, sys_errno);
		return;
	}

	tevent_req_done(req);
}

int tdgram_disconnect_recv(struct tevent_req *req,
			   int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);

	tevent_req_received(req);
	return ret;
}

struct tstream_context {
	const char *location;
	const struct tstream_context_ops *ops;
	void *private_data;

	struct tevent_req *readv_req;
	struct tevent_req *writev_req;
	struct tevent_req *disconnect_req;
	struct tevent_req *monitor_req;
};

static void tstream_monitor_disconnect(struct tstream_context *stream, int err);

static int tstream_context_destructor(struct tstream_context *stream)
{
	if (stream->readv_req) {
		tevent_req_received(stream->readv_req);
	}

	if (stream->writev_req) {
		tevent_req_received(stream->writev_req);
	}

	if (stream->disconnect_req != NULL) {
		tevent_req_received(stream->disconnect_req);
	}

	if (stream->monitor_req != NULL) {
		tevent_req_received(stream->monitor_req);
	}

	return 0;
}

struct tstream_context *_tstream_context_create(TALLOC_CTX *mem_ctx,
					const struct tstream_context_ops *ops,
					void *pstate,
					size_t psize,
					const char *type,
					const char *location)
{
	struct tstream_context *stream;
	void **ppstate = (void **)pstate;
	void *state;

	stream = talloc(mem_ctx, struct tstream_context);
	if (stream == NULL) {
		return NULL;
	}
	stream->location	= location;
	stream->ops		= ops;
	stream->readv_req	= NULL;
	stream->writev_req	= NULL;
	stream->disconnect_req	= NULL;
	stream->monitor_req	= NULL;

	state = talloc_size(stream, psize);
	if (state == NULL) {
		talloc_free(stream);
		return NULL;
	}
	talloc_set_name_const(state, type);

	stream->private_data = state;

	talloc_set_destructor(stream, tstream_context_destructor);

	*ppstate = state;
	return stream;
}

void *_tstream_context_data(struct tstream_context *stream)
{
	return stream->private_data;
}

ssize_t tstream_pending_bytes(struct tstream_context *stream)
{
	ssize_t ret;

	ret = stream->ops->pending_bytes(stream);
	if (ret == -1) {
		int sys_errno = errno;
		tstream_monitor_disconnect(stream, sys_errno);
		errno = sys_errno;
	}

	return ret;
}

struct tstream_readv_state {
	const struct tstream_context_ops *ops;
	struct tstream_context *stream;
	int ret;
};

static void tstream_readv_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state)
{
	struct tstream_readv_state *state = tevent_req_data(req,
					    struct tstream_readv_state);

	if (state->stream) {
		state->stream->readv_req = NULL;
		state->stream = NULL;
	}
}

static void tstream_readv_done(struct tevent_req *subreq);

struct tevent_req *tstream_readv_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct tstream_context *stream,
				      struct iovec *vector,
				      size_t count)
{
	struct tevent_req *req;
	struct tstream_readv_state *state;
	struct tevent_req *subreq;
	ssize_t to_read;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_readv_state);
	if (req == NULL) {
		return NULL;
	}

	state->ops = stream->ops;
	state->stream = stream;
	state->ret = -1;

	/* first check if the input is ok */
#ifdef IOV_MAX
	if (count > IOV_MAX) {
		tevent_req_error(req, EMSGSIZE);
		goto post;
	}
#endif

	to_read = iov_buflen(vector, count);

	if (to_read < 0) {
		tevent_req_error(req, EMSGSIZE);
		goto post;
	}

	if (to_read == 0) {
		tevent_req_error(req, EINVAL);
		goto post;
	}

	if (stream->disconnect_req != NULL) {
		tevent_req_error(req, ECONNABORTED);
		goto post;
	}

	if (stream->readv_req) {
		tevent_req_error(req, EBUSY);
		goto post;
	}
	stream->readv_req = req;

	tevent_req_set_cleanup_fn(req, tstream_readv_cleanup);

	subreq = state->ops->readv_send(state, ev, stream, vector, count);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tstream_readv_done, req);

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tstream_readv_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct tstream_readv_state *state = tevent_req_data(req,
					    struct tstream_readv_state);
	ssize_t ret;
	int sys_errno;

	ret = state->ops->readv_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tstream_monitor_disconnect(state->stream, sys_errno);
		tevent_req_error(req, sys_errno);
		return;
	}

	state->ret = ret;

	tevent_req_done(req);
}

int tstream_readv_recv(struct tevent_req *req,
		       int *perrno)
{
	struct tstream_readv_state *state = tevent_req_data(req,
					    struct tstream_readv_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tstream_writev_state {
	const struct tstream_context_ops *ops;
	struct tstream_context *stream;
	int ret;
};

static void tstream_writev_cleanup(struct tevent_req *req,
				   enum tevent_req_state req_state)
{
	struct tstream_writev_state *state = tevent_req_data(req,
					     struct tstream_writev_state);

	if (state->stream) {
		state->stream->writev_req = NULL;
		state->stream = NULL;
	}
}

static void tstream_writev_done(struct tevent_req *subreq);

struct tevent_req *tstream_writev_send(TALLOC_CTX *mem_ctx,
				       struct tevent_context *ev,
				       struct tstream_context *stream,
				       const struct iovec *vector,
				       size_t count)
{
	struct tevent_req *req;
	struct tstream_writev_state *state;
	struct tevent_req *subreq;
	ssize_t to_write;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_writev_state);
	if (req == NULL) {
		return NULL;
	}

	state->ops = stream->ops;
	state->stream = stream;
	state->ret = -1;

	/* first check if the input is ok */
#ifdef IOV_MAX
	if (count > IOV_MAX) {
		tevent_req_error(req, EMSGSIZE);
		goto post;
	}
#endif

	to_write = iov_buflen(vector, count);
	if (to_write < 0) {
		tevent_req_error(req, EMSGSIZE);
		goto post;
	}

	if (to_write == 0) {
		tevent_req_error(req, EINVAL);
		goto post;
	}

	if (stream->disconnect_req != NULL) {
		tevent_req_error(req, ECONNABORTED);
		goto post;
	}

	if (stream->writev_req) {
		tevent_req_error(req, EBUSY);
		goto post;
	}
	stream->writev_req = req;

	tevent_req_set_cleanup_fn(req, tstream_writev_cleanup);

	subreq = state->ops->writev_send(state, ev, stream, vector, count);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tstream_writev_done, req);

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tstream_writev_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct tstream_writev_state *state = tevent_req_data(req,
					     struct tstream_writev_state);
	ssize_t ret;
	int sys_errno;

	ret = state->ops->writev_recv(subreq, &sys_errno);
	if (ret == -1) {
		tstream_monitor_disconnect(state->stream, sys_errno);
		tevent_req_error(req, sys_errno);
		return;
	}

	state->ret = ret;

	tevent_req_done(req);
}

int tstream_writev_recv(struct tevent_req *req,
		       int *perrno)
{
	struct tstream_writev_state *state = tevent_req_data(req,
					     struct tstream_writev_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

struct tstream_disconnect_state {
	const struct tstream_context_ops *ops;
	struct tstream_context *stream;
};

static void tstream_disconnect_cleanup(struct tevent_req *req,
				       enum tevent_req_state req_state)
{
	struct tstream_disconnect_state *state = tevent_req_data(req,
						 struct tstream_disconnect_state);

	if (state->stream != NULL) {
		state->stream->disconnect_req = NULL;
		state->stream = NULL;
	}

	return;
}

static void tstream_disconnect_done(struct tevent_req *subreq);

struct tevent_req *tstream_disconnect_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct tstream_context *stream)
{
	struct tevent_req *req;
	struct tstream_disconnect_state *state;
	struct tevent_req *subreq;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_disconnect_state);
	if (req == NULL) {
		return NULL;
	}

	state->ops = stream->ops;
	state->stream = stream;

	if (stream->readv_req || stream->writev_req) {
		tevent_req_error(req, EBUSY);
		goto post;
	}

	if (stream->disconnect_req != NULL) {
		tevent_req_error(req, EALREADY);
		goto post;
	}
	stream->disconnect_req = req;

	tevent_req_set_cleanup_fn(req, tstream_disconnect_cleanup);

	subreq = state->ops->disconnect_send(state, ev, stream);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tstream_disconnect_done, req);

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tstream_disconnect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct tstream_disconnect_state *state = tevent_req_data(req,
						 struct tstream_disconnect_state);
	int ret;
	int sys_errno;

	ret = state->ops->disconnect_recv(subreq, &sys_errno);
	if (ret == -1) {
		tstream_monitor_disconnect(state->stream, sys_errno);
		tevent_req_error(req, sys_errno);
		return;
	}

	tstream_monitor_disconnect(state->stream, ECONNABORTED);

	tevent_req_done(req);
}

int tstream_disconnect_recv(struct tevent_req *req,
			   int *perrno)
{
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);

	tevent_req_received(req);
	return ret;
}

struct tstream_monitor_state {
	const struct tstream_context_ops *ops;
	struct tstream_context *stream;
	struct tevent_req *subreq;
	int ret;
};

static void tstream_monitor_cleanup(struct tevent_req *req,
				    enum tevent_req_state req_state)
{
	struct tstream_monitor_state *state =
		tevent_req_data(req,
		struct tstream_monitor_state);

	TALLOC_FREE(state->subreq);

	if (state->stream != NULL) {
		state->stream->monitor_req = NULL;
		state->stream = NULL;
	}
}

static void tstream_monitor_done(struct tevent_req *subreq);

struct tevent_req *tstream_monitor_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct tstream_context *stream)
{
	struct tevent_req *req = NULL;
	struct tstream_monitor_state *state = NULL;
	struct tevent_req *subreq = NULL;
	ssize_t pending;

	req = tevent_req_create(mem_ctx, &state,
				struct tstream_monitor_state);
	if (req == NULL) {
		return NULL;
	}

	state->ops = stream->ops;
	state->stream = stream;
	state->ret = -1;

	if (stream->disconnect_req != NULL) {
		tevent_req_error(req, ECONNABORTED);
		return tevent_req_post(req, ev);
	}

	if (stream->monitor_req != NULL) {
		tevent_req_error(req, EALREADY);
		return tevent_req_post(req, ev);
	}
	stream->monitor_req = req;

	tevent_req_set_cleanup_fn(req, tstream_monitor_cleanup);
	tevent_req_defer_callback(req, ev);

	if (state->ops->monitor_send != NULL) {
		subreq = state->ops->monitor_send(state,
						  ev,
						  stream);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, tstream_monitor_done, req);

		state->subreq = subreq;
		return req;
	}

	pending = stream->ops->pending_bytes(stream);
	if (pending < 0) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	/*
	 * just remain forever pending until
	 * tstream_monitor_disconnect() is triggered
	 * in any way.
	 */
	return req;
}

static void tstream_monitor_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct tstream_monitor_state *state =
		tevent_req_data(req,
		struct tstream_monitor_state);
	ssize_t ret;
	int sys_errno;

	state->subreq = NULL;

	ret = state->ops->monitor_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, sys_errno);
		return;
	}

	state->ret = ret;

	tevent_req_done(req);
}

static void tstream_monitor_disconnect(struct tstream_context *stream, int err)
{
	if (stream == NULL) {
		return;
	}

	if (stream->monitor_req == NULL) {
		return;
	}

	/*
	 * tevent_req_defer_callback() was used
	 * so it's safe to call
	 */
	tevent_req_error(stream->monitor_req, err);
}

int tstream_monitor_recv(struct tevent_req *req, int *perrno)
{
	struct tstream_monitor_state *state =
		tevent_req_data(req,
		struct tstream_monitor_state);
	int ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}
