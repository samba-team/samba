/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher 2009

     ** NOTE! The following LGPL license applies to the tevent
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
#include "system/network.h"
#include "tsocket.h"
#include "tsocket_internal.h"

static int tsocket_context_destructor(struct tsocket_context *sock)
{
	tsocket_disconnect(sock);
	return 0;
}

struct tsocket_context *_tsocket_context_create(TALLOC_CTX *mem_ctx,
						const struct tsocket_context_ops *ops,
						void *pstate,
						size_t psize,
						const char *type,
						const char *location)
{
	void **ppstate = (void **)pstate;
	struct tsocket_context *sock;

	sock = talloc_zero(mem_ctx, struct tsocket_context);
	if (!sock) {
		return NULL;
	}
	sock->ops = ops;
	sock->location = location;
	sock->private_data = talloc_size(sock, psize);
	if (!sock->private_data) {
		talloc_free(sock);
		return NULL;
	}
	talloc_set_name_const(sock->private_data, type);

	talloc_set_destructor(sock, tsocket_context_destructor);

	*ppstate = sock->private_data;
	return sock;
}

int tsocket_set_event_context(struct tsocket_context *sock,
			      struct tevent_context *ev)
{
	return sock->ops->set_event_context(sock, ev);
}

int tsocket_set_readable_handler(struct tsocket_context *sock,
				 tsocket_event_handler_t handler,
				 void *private_data)
{
	return sock->ops->set_read_handler(sock, handler, private_data);
}

int tsocket_set_writeable_handler(struct tsocket_context *sock,
				  tsocket_event_handler_t handler,
				  void *private_data)
{
	return sock->ops->set_write_handler(sock, handler, private_data);
}

int tsocket_connect(struct tsocket_context *sock,
		    const struct tsocket_address *remote_addr)
{
	return sock->ops->connect_to(sock, remote_addr);
}

int tsocket_listen(struct tsocket_context *sock,
		   int queue_size)
{
	return sock->ops->listen_on(sock, queue_size);
}

int _tsocket_accept(struct tsocket_context *sock,
		    TALLOC_CTX *mem_ctx,
		    struct tsocket_context **new_sock,
		    const char *location)
{
	return sock->ops->accept_new(sock, mem_ctx, new_sock, location);
}

ssize_t tsocket_pending(struct tsocket_context *sock)
{
	return sock->ops->pending_data(sock);
}

int tsocket_readv(struct tsocket_context *sock,
		  const struct iovec *vector, size_t count)
{
	return sock->ops->readv_data(sock, vector, count);
}

int tsocket_writev(struct tsocket_context *sock,
		   const struct iovec *vector, size_t count)
{
	return sock->ops->writev_data(sock, vector, count);
}

ssize_t tsocket_recvfrom(struct tsocket_context *sock,
			 uint8_t *data, size_t len,
			 TALLOC_CTX *addr_ctx,
			 struct tsocket_address **src_addr)
{
	return sock->ops->recvfrom_data(sock, data, len, addr_ctx, src_addr);
}

ssize_t tsocket_sendto(struct tsocket_context *sock,
		       const uint8_t *data, size_t len,
		       const struct tsocket_address *dest_addr)
{
	return sock->ops->sendto_data(sock, data, len, dest_addr);
}

int tsocket_get_status(const struct tsocket_context *sock)
{
	return sock->ops->get_status(sock);
}

int _tsocket_get_local_address(const struct tsocket_context *sock,
			       TALLOC_CTX *mem_ctx,
			       struct tsocket_address **local_addr,
			       const char *location)
{
	return sock->ops->get_local_address(sock, mem_ctx,
					    local_addr, location);
}

int _tsocket_get_remote_address(const struct tsocket_context *sock,
				TALLOC_CTX *mem_ctx,
				struct tsocket_address **remote_addr,
				const char *location)
{
	return sock->ops->get_remote_address(sock, mem_ctx,
					     remote_addr, location);
}

int tsocket_get_option(const struct tsocket_context *sock,
		       const char *option,
		       TALLOC_CTX *mem_ctx,
		       char **value)
{
	return sock->ops->get_option(sock, option, mem_ctx, value);
}

int tsocket_set_option(const struct tsocket_context *sock,
		       const char *option,
		       bool force,
		       const char *value)
{
	return sock->ops->set_option(sock, option, force, value);
}

void tsocket_disconnect(struct tsocket_context *sock)
{
	sock->ops->disconnect(sock);
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

int _tsocket_address_create_socket(const struct tsocket_address *addr,
				   enum tsocket_type type,
				   TALLOC_CTX *mem_ctx,
				   struct tsocket_context **sock,
				   const char *location)
{
	return addr->ops->create_socket(addr, type, mem_ctx, sock, location);
}

struct tdgram_context {
	const char *location;
	const struct tdgram_context_ops *ops;
	void *private_data;
};

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
	dgram->location	= location;
	dgram->ops	= ops;

	state = talloc_size(dgram, psize);
	if (state == NULL) {
		talloc_free(dgram);
		return NULL;
	}
	talloc_set_name_const(state, type);

	dgram->private_data = state;

	*ppstate = state;
	return dgram;
}

void *_tdgram_context_data(struct tdgram_context *dgram)
{
	return dgram->private_data;
}

struct tdgram_recvfrom_state {
	const struct tdgram_context_ops *ops;
	uint8_t *buf;
	size_t len;
	struct tsocket_address *src;
};

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

	subreq = state->ops->recvfrom_send(state, ev, dgram);
	if (tevent_req_nomem(subreq, req)) {
		goto post;
	}
	tevent_req_set_callback(subreq, tdgram_recvfrom_done, req);

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
	ssize_t ret;
};

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
	state->ret = -1;

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

struct tdgram_sendto_queue_state {
	/* this structs are owned by the caller */
	struct {
		struct tevent_context *ev;
		struct tdgram_context *dgram;
		const uint8_t *buf;
		size_t len;
		const struct tsocket_address *dst;
	} caller;
	ssize_t ret;
};

static void tdgram_sendto_queue_trigger(struct tevent_req *req,
					 void *private_data);
static void tdgram_sendto_queue_done(struct tevent_req *subreq);

/**
 * @brief Queue a dgram blob for sending through the socket
 * @param[in] mem_ctx	The memory context for the result
 * @param[in] ev	The event context the operation should work on
 * @param[in] dgram	The tdgram_context to send the message buffer
 * @param[in] queue	The existing dgram queue
 * @param[in] buf	The message buffer
 * @param[in] len	The message length
 * @param[in] dst	The destination socket address
 * @retval		The async request handle
 *
 * This function queues a blob for sending to destination through an existing
 * dgram socket. The async callback is triggered when the whole blob is
 * delivered to the underlying system socket.
 *
 * The caller needs to make sure that all non-scalar input parameters hang
 * arround for the whole lifetime of the request.
 */
struct tevent_req *tdgram_sendto_queue_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tdgram_context *dgram,
					    struct tevent_queue *queue,
					    const uint8_t *buf,
					    size_t len,
					    struct tsocket_address *dst)
{
	struct tevent_req *req;
	struct tdgram_sendto_queue_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct tdgram_sendto_queue_state);
	if (!req) {
		return NULL;
	}

	state->caller.ev	= ev;
	state->caller.dgram	= dgram;
	state->caller.buf	= buf;
	state->caller.len	= len;
	state->caller.dst	= dst;
	state->ret		= -1;

	ok = tevent_queue_add(queue,
			      ev,
			      req,
			      tdgram_sendto_queue_trigger,
			      NULL);
	if (!ok) {
		tevent_req_nomem(NULL, req);
		goto post;
	}

	return req;

 post:
	tevent_req_post(req, ev);
	return req;
}

static void tdgram_sendto_queue_trigger(struct tevent_req *req,
					 void *private_data)
{
	struct tdgram_sendto_queue_state *state = tevent_req_data(req,
					struct tdgram_sendto_queue_state);
	struct tevent_req *subreq;

	subreq = tdgram_sendto_send(state,
				    state->caller.ev,
				    state->caller.dgram,
				    state->caller.buf,
				    state->caller.len,
				    state->caller.dst);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, tdgram_sendto_queue_done, req);
}

static void tdgram_sendto_queue_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(subreq,
				 struct tevent_req);
	struct tdgram_sendto_queue_state *state = tevent_req_data(req,
					struct tdgram_sendto_queue_state);
	ssize_t ret;
	int sys_errno;

	ret = tdgram_sendto_recv(subreq, &sys_errno);
	talloc_free(subreq);
	if (ret == -1) {
		tevent_req_error(req, sys_errno);
		return;
	}
	state->ret = ret;

	tevent_req_done(req);
}

ssize_t tdgram_sendto_queue_recv(struct tevent_req *req, int *perrno)
{
	struct tdgram_sendto_queue_state *state = tevent_req_data(req,
					struct tdgram_sendto_queue_state);
	ssize_t ret;

	ret = tsocket_simple_int_recv(req, perrno);
	if (ret == 0) {
		ret = state->ret;
	}

	tevent_req_received(req);
	return ret;
}

