/*
   Unix SMB/CIFS implementation.
   async socket syscalls
   Copyright (C) Volker Lendecke 2008

     ** NOTE! The following LGPL license applies to the async_sock
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include <talloc.h>
#include <tevent.h>
#include "lib/async_req/async_sock.h"
#include "lib/util/iov_buf.h"

/* Note: lib/util/ is currently GPL */
#include "lib/util/tevent_unix.h"
#include "lib/util/samba_util.h"

struct async_connect_state {
	int fd;
	struct tevent_fd *fde;
	int result;
	long old_sockflags;
	socklen_t address_len;
	struct sockaddr_storage address;

	void (*before_connect)(void *private_data);
	void (*after_connect)(void *private_data);
	void *private_data;
};

static void async_connect_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state);
static void async_connect_connected(struct tevent_context *ev,
				    struct tevent_fd *fde, uint16_t flags,
				    void *priv);

/**
 * @brief async version of connect(2)
 * @param[in] mem_ctx	The memory context to hang the result off
 * @param[in] ev	The event context to work from
 * @param[in] fd	The socket to recv from
 * @param[in] address	Where to connect?
 * @param[in] address_len Length of *address
 * @retval The async request
 *
 * This function sets the socket into non-blocking state to be able to call
 * connect in an async state. This will be reset when the request is finished.
 */

struct tevent_req *async_connect_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev, int fd,
	const struct sockaddr *address, socklen_t address_len,
	void (*before_connect)(void *private_data),
	void (*after_connect)(void *private_data),
	void *private_data)
{
	struct tevent_req *req;
	struct async_connect_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct async_connect_state);
	if (req == NULL) {
		return NULL;
	}

	/**
	 * We have to set the socket to nonblocking for async connect(2). Keep
	 * the old sockflags around.
	 */

	state->fd = fd;
	state->before_connect = before_connect;
	state->after_connect = after_connect;
	state->private_data = private_data;

	state->old_sockflags = fcntl(fd, F_GETFL, 0);
	if (state->old_sockflags == -1) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	tevent_req_set_cleanup_fn(req, async_connect_cleanup);

	state->address_len = address_len;
	if (address_len > sizeof(state->address)) {
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}
	memcpy(&state->address, address, address_len);

	ret = set_blocking(fd, false);
	if (ret == -1) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	if (state->before_connect != NULL) {
		state->before_connect(state->private_data);
	}

	state->result = connect(fd, address, address_len);

	if (state->after_connect != NULL) {
		state->after_connect(state->private_data);
	}

	if (state->result == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	/*
	 * The only errno indicating that an initial connect is still
	 * in flight is EINPROGRESS.
	 *
	 * This allows callers like open_socket_out_send() to reuse
	 * fds and call us with an fd for which the connect is still
	 * in flight. The proper thing to do for callers would be
	 * closing the fd and starting from scratch with a fresh
	 * socket.
	 */

	if (errno != EINPROGRESS) {
		tevent_req_error(req, errno);
		return tevent_req_post(req, ev);
	}

	/*
	 * Note for historic reasons TEVENT_FD_WRITE is not enough
	 * to get notified for POLLERR or EPOLLHUP even if they
	 * come together with POLLOUT. That means we need to
	 * use TEVENT_FD_READ in addition until we have
	 * TEVENT_FD_ERROR.
	 */
	state->fde = tevent_add_fd(ev, state, fd, TEVENT_FD_READ|TEVENT_FD_WRITE,
				   async_connect_connected, req);
	if (state->fde == NULL) {
		tevent_req_error(req, ENOMEM);
		return tevent_req_post(req, ev);
	}
	return req;
}

static void async_connect_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state)
{
	struct async_connect_state *state =
		tevent_req_data(req, struct async_connect_state);

	TALLOC_FREE(state->fde);
	if (state->fd != -1) {
		int ret;

		ret = fcntl(state->fd, F_SETFL, state->old_sockflags);
		if (ret == -1) {
			abort();
		}

		state->fd = -1;
	}
}

/**
 * fde event handler for connect(2)
 * @param[in] ev	The event context that sent us here
 * @param[in] fde	The file descriptor event associated with the connect
 * @param[in] flags	Indicate read/writeability of the socket
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_connect_connected(struct tevent_context *ev,
				    struct tevent_fd *fde, uint16_t flags,
				    void *priv)
{
	struct tevent_req *req = talloc_get_type_abort(
		priv, struct tevent_req);
	struct async_connect_state *state =
		tevent_req_data(req, struct async_connect_state);
	int ret;
	int socket_error = 0;
	socklen_t slen = sizeof(socket_error);

	ret = getsockopt(state->fd, SOL_SOCKET, SO_ERROR,
			 &socket_error, &slen);

	if (ret != 0) {
		/*
		 * According to Stevens this is the Solaris behaviour
		 * in case the connection encountered an error:
		 * getsockopt() fails, error is in errno
		 */
		tevent_req_error(req, errno);
		return;
	}

	if (socket_error != 0) {
		/*
		 * Berkeley derived implementations (including) Linux
		 * return the pending error via socket_error.
		 */
		tevent_req_error(req, socket_error);
		return;
	}

	tevent_req_done(req);
	return;
}

int async_connect_recv(struct tevent_req *req, int *perrno)
{
	int err = tevent_req_simple_recv_unix(req);

	if (err != 0) {
		*perrno = err;
		return -1;
	}

	return 0;
}

struct writev_state {
	struct tevent_context *ev;
	struct tevent_queue_entry *queue_entry;
	int fd;
	struct tevent_fd *fde;
	struct iovec *iov;
	int count;
	size_t total_size;
	uint16_t flags;
	bool err_on_readability;
};

static void writev_cleanup(struct tevent_req *req,
			   enum tevent_req_state req_state);
static bool writev_cancel(struct tevent_req *req);
static void writev_trigger(struct tevent_req *req, void *private_data);
static void writev_handler(struct tevent_context *ev, struct tevent_fd *fde,
			   uint16_t flags, void *private_data);

struct tevent_req *writev_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       struct tevent_queue *queue, int fd,
			       bool err_on_readability,
			       struct iovec *iov, int count)
{
	struct tevent_req *req;
	struct writev_state *state;

	req = tevent_req_create(mem_ctx, &state, struct writev_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fd = fd;
	state->total_size = 0;
	state->count = count;
	state->iov = (struct iovec *)talloc_memdup(
		state, iov, sizeof(struct iovec) * count);
	if (tevent_req_nomem(state->iov, req)) {
		return tevent_req_post(req, ev);
	}
	state->flags = TEVENT_FD_WRITE|TEVENT_FD_READ;
	state->err_on_readability = err_on_readability;

	tevent_req_set_cleanup_fn(req, writev_cleanup);
	tevent_req_set_cancel_fn(req, writev_cancel);

	if (queue == NULL) {
		state->fde = tevent_add_fd(state->ev, state, state->fd,
				    state->flags, writev_handler, req);
		if (tevent_req_nomem(state->fde, req)) {
			return tevent_req_post(req, ev);
		}
		return req;
	}

	/*
	 * writev_trigger tries a nonblocking write. If that succeeds,
	 * we can't directly notify the callback to call
	 * writev_recv. The callback would TALLOC_FREE(req) after
	 * calling writev_recv even before writev_trigger can inspect
	 * it for success.
	 */
	tevent_req_defer_callback(req, ev);

	state->queue_entry = tevent_queue_add_optimize_empty(
		queue, ev, req, writev_trigger, NULL);
	if (tevent_req_nomem(state->queue_entry, req)) {
		return tevent_req_post(req, ev);
	}
	if (!tevent_req_is_in_progress(req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void writev_cleanup(struct tevent_req *req,
			   enum tevent_req_state req_state)
{
	struct writev_state *state = tevent_req_data(req, struct writev_state);

	TALLOC_FREE(state->queue_entry);
	TALLOC_FREE(state->fde);
}

static bool writev_cancel(struct tevent_req *req)
{
	struct writev_state *state = tevent_req_data(req, struct writev_state);

	if (state->total_size > 0) {
		/*
		 * We've already started to write :-(
		 */
		return false;
	}

	TALLOC_FREE(state->queue_entry);
	TALLOC_FREE(state->fde);

	tevent_req_defer_callback(req, state->ev);
	tevent_req_error(req, ECANCELED);
	return true;
}

static void writev_do(struct tevent_req *req, struct writev_state *state)
{
	ssize_t written;
	bool ok;

	written = writev(state->fd, state->iov, state->count);
	if ((written == -1) &&
	    ((errno == EINTR) ||
	     (errno == EAGAIN) ||
	     (errno == EWOULDBLOCK))) {
		/* retry after going through the tevent loop */
		return;
	}
	if (written == -1) {
		tevent_req_error(req, errno);
		return;
	}
	if (written == 0) {
		tevent_req_error(req, EPIPE);
		return;
	}
	state->total_size += written;

	ok = iov_advance(&state->iov, &state->count, written);
	if (!ok) {
		tevent_req_error(req, EIO);
		return;
	}

	if (state->count == 0) {
		tevent_req_done(req);
		return;
	}
}

static void writev_trigger(struct tevent_req *req, void *private_data)
{
	struct writev_state *state = tevent_req_data(req, struct writev_state);

	state->queue_entry = NULL;

	writev_do(req, state);
	if (!tevent_req_is_in_progress(req)) {
		return;
	}

	state->fde = tevent_add_fd(state->ev, state, state->fd, state->flags,
			    writev_handler, req);
	if (tevent_req_nomem(state->fde, req)) {
		return;
	}
}

static void writev_handler(struct tevent_context *ev, struct tevent_fd *fde,
			   uint16_t flags, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct writev_state *state =
		tevent_req_data(req, struct writev_state);

	if ((state->flags & TEVENT_FD_READ) && (flags & TEVENT_FD_READ)) {
		int ret, value;

		if (state->err_on_readability) {
			/* Readable and the caller wants an error on read. */
			tevent_req_error(req, EPIPE);
			return;
		}

		/* Might be an error. Check if there are bytes to read */
		ret = ioctl(state->fd, FIONREAD, &value);
		/* FIXME - should we also check
		   for ret == 0 and value == 0 here ? */
		if (ret == -1) {
			/* There's an error. */
			tevent_req_error(req, EPIPE);
			return;
		}
		/* A request for TEVENT_FD_READ will succeed from now and
		   forevermore until the bytes are read so if there was
		   an error we'll wait until we do read, then get it in
		   the read callback function. Until then, remove TEVENT_FD_READ
		   from the flags we're waiting for. */
		state->flags &= ~TEVENT_FD_READ;
		TEVENT_FD_NOT_READABLE(fde);

		/* If not writable, we're done. */
		if (!(flags & TEVENT_FD_WRITE)) {
			return;
		}
	}

	writev_do(req, state);
}

ssize_t writev_recv(struct tevent_req *req, int *perrno)
{
	struct writev_state *state =
		tevent_req_data(req, struct writev_state);
	ssize_t ret;

	if (tevent_req_is_unix_error(req, perrno)) {
		tevent_req_received(req);
		return -1;
	}
	ret = state->total_size;
	tevent_req_received(req);
	return ret;
}

struct read_packet_state {
	int fd;
	struct tevent_fd *fde;
	uint8_t *buf;
	size_t nread;
	ssize_t (*more)(uint8_t *buf, size_t buflen, void *private_data);
	void *private_data;
};

static void read_packet_cleanup(struct tevent_req *req,
				 enum tevent_req_state req_state);
static void read_packet_handler(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags, void *private_data);

struct tevent_req *read_packet_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    int fd, size_t initial,
				    ssize_t (*more)(uint8_t *buf,
						    size_t buflen,
						    void *private_data),
				    void *private_data)
{
	struct tevent_req *req;
	struct read_packet_state *state;

	req = tevent_req_create(mem_ctx, &state, struct read_packet_state);
	if (req == NULL) {
		return NULL;
	}
	state->fd = fd;
	state->nread = 0;
	state->more = more;
	state->private_data = private_data;

	tevent_req_set_cleanup_fn(req, read_packet_cleanup);

	state->buf = talloc_array(state, uint8_t, initial);
	if (tevent_req_nomem(state->buf, req)) {
		return tevent_req_post(req, ev);
	}

	state->fde = tevent_add_fd(ev, state, fd,
				   TEVENT_FD_READ, read_packet_handler,
				   req);
	if (tevent_req_nomem(state->fde, req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void read_packet_cleanup(struct tevent_req *req,
			   enum tevent_req_state req_state)
{
	struct read_packet_state *state =
		tevent_req_data(req, struct read_packet_state);

	TALLOC_FREE(state->fde);
}

static void read_packet_handler(struct tevent_context *ev,
				struct tevent_fd *fde,
				uint16_t flags, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct read_packet_state *state =
		tevent_req_data(req, struct read_packet_state);
	size_t total = talloc_get_size(state->buf);
	ssize_t nread, more;
	uint8_t *tmp;

	nread = recv(state->fd, state->buf+state->nread, total-state->nread,
		     0);
	if ((nread == -1) && (errno == ENOTSOCK)) {
		nread = read(state->fd, state->buf+state->nread,
			     total-state->nread);
	}
	if ((nread == -1) && (errno == EINTR)) {
		/* retry */
		return;
	}
	if (nread == -1) {
		tevent_req_error(req, errno);
		return;
	}
	if (nread == 0) {
		tevent_req_error(req, EPIPE);
		return;
	}

	state->nread += nread;
	if (state->nread < total) {
		/* Come back later */
		return;
	}

	/*
	 * We got what was initially requested. See if "more" asks for -- more.
	 */
	if (state->more == NULL) {
		/* Nobody to ask, this is a async read_data */
		tevent_req_done(req);
		return;
	}

	more = state->more(state->buf, total, state->private_data);
	if (more == -1) {
		/* We got an invalid packet, tell the caller */
		tevent_req_error(req, EIO);
		return;
	}
	if (more == 0) {
		/* We're done, full packet received */
		tevent_req_done(req);
		return;
	}

	if (total + more < total) {
		tevent_req_error(req, EMSGSIZE);
		return;
	}

	tmp = talloc_realloc(state, state->buf, uint8_t, total+more);
	if (tevent_req_nomem(tmp, req)) {
		return;
	}
	state->buf = tmp;
}

ssize_t read_packet_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			 uint8_t **pbuf, int *perrno)
{
	struct read_packet_state *state =
		tevent_req_data(req, struct read_packet_state);

	if (tevent_req_is_unix_error(req, perrno)) {
		tevent_req_received(req);
		return -1;
	}
	*pbuf = talloc_move(mem_ctx, &state->buf);
	tevent_req_received(req);
	return talloc_get_size(*pbuf);
}

struct wait_for_read_state {
	struct tevent_fd *fde;
	int fd;
	bool check_errors;
};

static void wait_for_read_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state);
static void wait_for_read_done(struct tevent_context *ev,
			       struct tevent_fd *fde,
			       uint16_t flags,
			       void *private_data);

struct tevent_req *wait_for_read_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev, int fd,
				      bool check_errors)
{
	struct tevent_req *req;
	struct wait_for_read_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wait_for_read_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_set_cleanup_fn(req, wait_for_read_cleanup);

	state->fde = tevent_add_fd(ev, state, fd, TEVENT_FD_READ,
				   wait_for_read_done, req);
	if (tevent_req_nomem(state->fde, req)) {
		return tevent_req_post(req, ev);
	}

	state->fd = fd;
	state->check_errors = check_errors;
	return req;
}

static void wait_for_read_cleanup(struct tevent_req *req,
				  enum tevent_req_state req_state)
{
	struct wait_for_read_state *state =
		tevent_req_data(req, struct wait_for_read_state);

	TALLOC_FREE(state->fde);
}

static void wait_for_read_done(struct tevent_context *ev,
			       struct tevent_fd *fde,
			       uint16_t flags,
			       void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct wait_for_read_state *state =
	    tevent_req_data(req, struct wait_for_read_state);
	ssize_t nread;
	char c;

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}

	if (!state->check_errors) {
		tevent_req_done(req);
		return;
	}

	nread = recv(state->fd, &c, 1, MSG_PEEK);

	if (nread == 0) {
		tevent_req_error(req, EPIPE);
		return;
	}

	if ((nread == -1) && (errno == EINTR)) {
		/* come back later */
		return;
	}

	if ((nread == -1) && (errno == ENOTSOCK)) {
		/* Ignore this specific error on pipes */
		tevent_req_done(req);
		return;
	}

	if (nread == -1) {
		tevent_req_error(req, errno);
		return;
	}

	tevent_req_done(req);
}

bool wait_for_read_recv(struct tevent_req *req, int *perr)
{
	int err = tevent_req_simple_recv_unix(req);

	if (err != 0) {
		*perr = err;
		return false;
	}

	return true;
}

struct accept_state {
	struct tevent_fd *fde;
	int listen_sock;
	socklen_t addrlen;
	struct sockaddr_storage addr;
	int sock;
};

static void accept_handler(struct tevent_context *ev, struct tevent_fd *fde,
			   uint16_t flags, void *private_data);

struct tevent_req *accept_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       int listen_sock)
{
	struct tevent_req *req;
	struct accept_state *state;

	req = tevent_req_create(mem_ctx, &state, struct accept_state);
	if (req == NULL) {
		return NULL;
	}

	state->listen_sock = listen_sock;

	state->fde = tevent_add_fd(ev, state, listen_sock, TEVENT_FD_READ,
				   accept_handler, req);
	if (tevent_req_nomem(state->fde, req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void accept_handler(struct tevent_context *ev, struct tevent_fd *fde,
			   uint16_t flags, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct accept_state *state = tevent_req_data(req, struct accept_state);
	int ret;

	TALLOC_FREE(state->fde);

	if ((flags & TEVENT_FD_READ) == 0) {
		tevent_req_error(req, EIO);
		return;
	}
	state->addrlen = sizeof(state->addr);

	ret = accept(state->listen_sock, (struct sockaddr *)&state->addr,
		     &state->addrlen);
	if ((ret == -1) && (errno == EINTR)) {
		/* retry */
		return;
	}
	if (ret == -1) {
		tevent_req_error(req, errno);
		return;
	}
	smb_set_close_on_exec(ret);
	state->sock = ret;
	tevent_req_done(req);
}

int accept_recv(struct tevent_req *req, struct sockaddr_storage *paddr,
		socklen_t *paddrlen, int *perr)
{
	struct accept_state *state = tevent_req_data(req, struct accept_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return -1;
	}
	if (paddr != NULL) {
		memcpy(paddr, &state->addr, state->addrlen);
	}
	if (paddrlen != NULL) {
		*paddrlen = state->addrlen;
	}
	return state->sock;
}
