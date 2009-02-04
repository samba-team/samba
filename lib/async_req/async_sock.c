/*
   Unix SMB/CIFS implementation.
   async socket syscalls
   Copyright (C) Volker Lendecke 2008

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
#include "lib/talloc/talloc.h"
#include "lib/tevent/tevent.h"
#include "lib/async_req/async_req.h"
#include "lib/async_req/async_sock.h"
#include <fcntl.h>

#ifndef TALLOC_FREE
#define TALLOC_FREE(ctx) do { talloc_free(ctx); ctx=NULL; } while(0)
#endif

/**
 * Discriminator for async_syscall_state
 */
enum async_syscall_type {
	ASYNC_SYSCALL_SEND,
	ASYNC_SYSCALL_SENDALL,
	ASYNC_SYSCALL_RECV,
	ASYNC_SYSCALL_RECVALL,
	ASYNC_SYSCALL_CONNECT
};

/**
 * Holder for syscall arguments and the result
 */

struct async_syscall_state {
	enum async_syscall_type syscall_type;
	struct tevent_fd *fde;

	union {
		struct param_send {
			int fd;
			const void *buffer;
			size_t length;
			int flags;
		} param_send;
		struct param_sendall {
			int fd;
			const void *buffer;
			size_t length;
			int flags;
			size_t sent;
		} param_sendall;
		struct param_recv {
			int fd;
			void *buffer;
			size_t length;
			int flags;
		} param_recv;
		struct param_recvall {
			int fd;
			void *buffer;
			size_t length;
			int flags;
			size_t received;
		} param_recvall;
		struct param_connect {
			/**
			 * connect needs to be done on a nonblocking
			 * socket. Keep the old flags around
			 */
			long old_sockflags;
			int fd;
			const struct sockaddr *address;
			socklen_t address_len;
		} param_connect;
	} param;

	union {
		ssize_t result_ssize_t;
		size_t result_size_t;
		int result_int;
	} result;
	int sys_errno;
};

/**
 * @brief Map async_req states to unix-style errnos
 * @param[in]  req	The async req to get the state from
 * @param[out] err	Pointer to take the unix-style errno
 *
 * @return true if the async_req is in an error state, false otherwise
 */

bool async_req_is_errno(struct async_req *req, int *err)
{
	enum async_req_state state;
	uint64_t error;

	if (!async_req_is_error(req, &state, &error)) {
		return false;
	}

	switch (state) {
	case ASYNC_REQ_USER_ERROR:
		*err = (int)error;
		break;
	case ASYNC_REQ_TIMED_OUT:
		*err = ETIME;
		break;
	case ASYNC_REQ_NO_MEMORY:
		*err = ENOMEM;
		break;
	default:
		*err = EIO;
		break;
	}
	return true;
}

int async_req_simple_recv_errno(struct async_req *req)
{
	int err;

	if (async_req_is_errno(req, &err)) {
		return err;
	}

	return 0;
}

/**
 * @brief Create a new async syscall req
 * @param[in] mem_ctx	The memory context to hang the result off
 * @param[in] ev	The event context to work from
 * @param[in] type	Which syscall will this be
 * @param[in] pstate	Where to put the newly created private_data state
 * @retval The new request
 *
 * This is a helper function to prepare a new struct async_req with an
 * associated struct async_syscall_state. The async_syscall_state will be put
 * into the async_req as private_data.
 */

static struct async_req *async_syscall_new(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   enum async_syscall_type type,
					   struct async_syscall_state **pstate)
{
	struct async_req *result;
	struct async_syscall_state *state;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct async_syscall_state)) {
		return NULL;
	}
	state->syscall_type = type;

	result->private_data = state;

	*pstate = state;

	return result;
}

/**
 * @brief Create a new async syscall req based on a fd
 * @param[in] mem_ctx	The memory context to hang the result off
 * @param[in] ev	The event context to work from
 * @param[in] type	Which syscall will this be
 * @param[in] fd	The file descriptor we work on
 * @param[in] fde_flags TEVENT_FD_READ/WRITE -- what are we interested in?
 * @param[in] fde_cb	The callback function for the file descriptor event
 * @param[in] pstate	Where to put the newly created private_data state
 * @retval The new request
 *
 * This is a helper function to prepare a new struct async_req with an
 * associated struct async_syscall_state and an associated file descriptor
 * event.
 */

static struct async_req *async_fde_syscall_new(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	enum async_syscall_type type,
	int fd,
	uint16_t fde_flags,
	void (*fde_cb)(struct tevent_context *ev,
		       struct tevent_fd *fde, uint16_t flags,
		       void *priv),
	struct async_syscall_state **pstate)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_syscall_new(mem_ctx, ev, type, &state);
	if (result == NULL) {
		return NULL;
	}

	state->fde = tevent_add_fd(ev, state, fd, fde_flags, fde_cb, result);
	if (state->fde == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}
	*pstate = state;
	return result;
}

/**
 * Retrieve a ssize_t typed result from an async syscall
 * @param[in] req	The syscall that has just finished
 * @param[out] perrno	Where to put the syscall's errno
 * @retval The return value from the asynchronously called syscall
 */

ssize_t async_syscall_result_ssize_t(struct async_req *req, int *perrno)
{
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);

	*perrno = state->sys_errno;
	return state->result.result_ssize_t;
}

/**
 * Retrieve a size_t typed result from an async syscall
 * @param[in] req	The syscall that has just finished
 * @param[out] perrno	Where to put the syscall's errno
 * @retval The return value from the asynchronously called syscall
 */

size_t async_syscall_result_size_t(struct async_req *req, int *perrno)
{
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);

	*perrno = state->sys_errno;
	return state->result.result_size_t;
}

/**
 * Retrieve a int typed result from an async syscall
 * @param[in] req	The syscall that has just finished
 * @param[out] perrno	Where to put the syscall's errno
 * @retval The return value from the asynchronously called syscall
 */

int async_syscall_result_int(struct async_req *req, int *perrno)
{
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);

	*perrno = state->sys_errno;
	return state->result.result_int;
}

/**
 * fde event handler for the "send" syscall
 * @param[in] ev	The event context that sent us here
 * @param[in] fde	The file descriptor event associated with the send
 * @param[in] flags	Can only be TEVENT_FD_WRITE here
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_send_callback(struct tevent_context *ev,
				struct tevent_fd *fde, uint16_t flags,
				void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	struct param_send *p = &state->param.param_send;

	if (state->syscall_type != ASYNC_SYSCALL_SEND) {
		async_req_error(req, EIO);
		return;
	}

	state->result.result_ssize_t = send(p->fd, p->buffer, p->length,
					    p->flags);
	state->sys_errno = errno;

	TALLOC_FREE(state->fde);

	async_req_done(req);
}

/**
 * Async version of send(2)
 * @param[in] mem_ctx	The memory context to hang the result off
 * @param[in] ev	The event context to work from
 * @param[in] fd	The socket to send to
 * @param[in] buffer	The buffer to send
 * @param[in] length	How many bytes to send
 * @param[in] flags	flags passed to send(2)
 *
 * This function is a direct counterpart of send(2)
 */

struct async_req *async_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     int fd, const void *buffer, size_t length,
			     int flags)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_fde_syscall_new(
		mem_ctx, ev, ASYNC_SYSCALL_SEND,
		fd, TEVENT_FD_WRITE, async_send_callback,
		&state);
	if (result == NULL) {
		return NULL;
	}

	state->param.param_send.fd = fd;
	state->param.param_send.buffer = buffer;
	state->param.param_send.length = length;
	state->param.param_send.flags = flags;

	return result;
}

/**
 * fde event handler for the "sendall" syscall group
 * @param[in] ev	The event context that sent us here
 * @param[in] fde	The file descriptor event associated with the send
 * @param[in] flags	Can only be TEVENT_FD_WRITE here
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_sendall_callback(struct tevent_context *ev,
				   struct tevent_fd *fde, uint16_t flags,
				   void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	struct param_sendall *p = &state->param.param_sendall;

	if (state->syscall_type != ASYNC_SYSCALL_SENDALL) {
		async_req_error(req, EIO);
		return;
	}

	state->result.result_ssize_t = send(p->fd,
					    (const char *)p->buffer + p->sent,
					    p->length - p->sent, p->flags);
	state->sys_errno = errno;

	if (state->result.result_ssize_t == -1) {
		async_req_error(req, state->sys_errno);
		return;
	}

	if (state->result.result_ssize_t == 0) {
		async_req_error(req, EOF);
		return;
	}

	p->sent += state->result.result_ssize_t;
	if (p->sent > p->length) {
		async_req_error(req, EIO);
		return;
	}

	if (p->sent == p->length) {
		TALLOC_FREE(state->fde);
		async_req_done(req);
	}
}

/**
 * @brief Send all bytes to a socket
 * @param[in] mem_ctx	The memory context to hang the result off
 * @param[in] ev	The event context to work from
 * @param[in] fd	The socket to send to
 * @param[in] buffer	The buffer to send
 * @param[in] length	How many bytes to send
 * @param[in] flags	flags passed to send(2)
 *
 * async_sendall calls send(2) as long as it is necessary to send all of the
 * "length" bytes
 */

struct async_req *sendall_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       int fd, const void *buffer, size_t length,
			       int flags)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_fde_syscall_new(
		mem_ctx, ev, ASYNC_SYSCALL_SENDALL,
		fd, TEVENT_FD_WRITE, async_sendall_callback,
		&state);
	if (result == NULL) {
		return NULL;
	}

	state->param.param_sendall.fd = fd;
	state->param.param_sendall.buffer = buffer;
	state->param.param_sendall.length = length;
	state->param.param_sendall.flags = flags;
	state->param.param_sendall.sent = 0;

	return result;
}

ssize_t sendall_recv(struct async_req *req, int *perr)
{
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	int err;

	err = async_req_simple_recv_errno(req);

	if (err != 0) {
		*perr = err;
		return -1;
	}

	return state->result.result_ssize_t;
}

/**
 * fde event handler for the "recv" syscall
 * @param[in] ev	The event context that sent us here
 * @param[in] fde	The file descriptor event associated with the recv
 * @param[in] flags	Can only be TEVENT_FD_READ here
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_recv_callback(struct tevent_context *ev,
				struct tevent_fd *fde, uint16_t flags,
				void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	struct param_recv *p = &state->param.param_recv;

	if (state->syscall_type != ASYNC_SYSCALL_RECV) {
		async_req_error(req, EIO);
		return;
	}

	state->result.result_ssize_t = recv(p->fd, p->buffer, p->length,
					    p->flags);
	state->sys_errno = errno;

	TALLOC_FREE(state->fde);

	async_req_done(req);
}

/**
 * Async version of recv(2)
 * @param[in] mem_ctx	The memory context to hang the result off
 * @param[in] ev	The event context to work from
 * @param[in] fd	The socket to recv from
 * @param[in] buffer	The buffer to recv into
 * @param[in] length	How many bytes to recv
 * @param[in] flags	flags passed to recv(2)
 *
 * This function is a direct counterpart of recv(2)
 */

struct async_req *async_recv(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			     int fd, void *buffer, size_t length,
			     int flags)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_fde_syscall_new(
		mem_ctx, ev, ASYNC_SYSCALL_RECV,
		fd, TEVENT_FD_READ, async_recv_callback,
		&state);

	if (result == NULL) {
		return NULL;
	}

	state->param.param_recv.fd = fd;
	state->param.param_recv.buffer = buffer;
	state->param.param_recv.length = length;
	state->param.param_recv.flags = flags;

	return result;
}

/**
 * fde event handler for the "recvall" syscall group
 * @param[in] ev	The event context that sent us here
 * @param[in] fde	The file descriptor event associated with the recv
 * @param[in] flags	Can only be TEVENT_FD_READ here
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_recvall_callback(struct tevent_context *ev,
				   struct tevent_fd *fde, uint16_t flags,
				   void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	struct param_recvall *p = &state->param.param_recvall;

	if (state->syscall_type != ASYNC_SYSCALL_RECVALL) {
		async_req_error(req, EIO);
		return;
	}

	state->result.result_ssize_t = recv(p->fd,
					    (char *)p->buffer + p->received,
					    p->length - p->received, p->flags);
	state->sys_errno = errno;

	if (state->result.result_ssize_t == -1) {
		async_req_error(req, state->sys_errno);
		return;
	}

	if (state->result.result_ssize_t == 0) {
		async_req_error(req, EIO);
		return;
	}

	p->received += state->result.result_ssize_t;
	if (p->received > p->length) {
		async_req_error(req, EIO);
		return;
	}

	if (p->received == p->length) {
		TALLOC_FREE(state->fde);
		async_req_done(req);
	}
}

/**
 * Receive a specified number of bytes from a socket
 * @param[in] mem_ctx	The memory context to hang the result off
 * @param[in] ev	The event context to work from
 * @param[in] fd	The socket to recv from
 * @param[in] buffer	The buffer to recv into
 * @param[in] length	How many bytes to recv
 * @param[in] flags	flags passed to recv(2)
 *
 * async_recvall will call recv(2) until "length" bytes are received
 */

struct async_req *recvall_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
			       int fd, void *buffer, size_t length,
			       int flags)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_fde_syscall_new(
		mem_ctx, ev, ASYNC_SYSCALL_RECVALL,
		fd, TEVENT_FD_READ, async_recvall_callback,
		&state);
	if (result == NULL) {
		return NULL;
	}

	state->param.param_recvall.fd = fd;
	state->param.param_recvall.buffer = buffer;
	state->param.param_recvall.length = length;
	state->param.param_recvall.flags = flags;
	state->param.param_recvall.received = 0;

	return result;
}

ssize_t recvall_recv(struct async_req *req, int *perr)
{
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	int err;

	err = async_req_simple_recv_errno(req);

	if (err != 0) {
		*perr = err;
		return -1;
	}

	return state->result.result_ssize_t;
}

struct async_connect_state {
	int fd;
	int result;
	int sys_errno;
	long old_sockflags;
};

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

struct async_req *async_connect_send(TALLOC_CTX *mem_ctx,
				     struct tevent_context *ev,
				     int fd, const struct sockaddr *address,
				     socklen_t address_len)
{
	struct async_req *result;
	struct async_connect_state *state;
	struct tevent_fd *fde;

	if (!async_req_setup(mem_ctx, &result, &state,
			     struct async_connect_state)) {
		return NULL;
	}

	/**
	 * We have to set the socket to nonblocking for async connect(2). Keep
	 * the old sockflags around.
	 */

	state->fd = fd;
	state->sys_errno = 0;

	state->old_sockflags = fcntl(fd, F_GETFL, 0);
	if (state->old_sockflags == -1) {
		goto post_errno;
	}

	set_blocking(fd, false);

	state->result = connect(fd, address, address_len);
	if (state->result == 0) {
		state->sys_errno = 0;
		goto post_status;
	}

	/**
	 * A number of error messages show that something good is progressing
	 * and that we have to wait for readability.
	 *
	 * If none of them are present, bail out.
	 */

	if (!(errno == EINPROGRESS || errno == EALREADY ||
#ifdef EISCONN
	      errno == EISCONN ||
#endif
	      errno == EAGAIN || errno == EINTR)) {
		goto post_errno;
	}

	fde = tevent_add_fd(ev, state, fd, TEVENT_FD_READ | TEVENT_FD_WRITE,
			   async_connect_connected, result);
	if (fde == NULL) {
		state->sys_errno = ENOMEM;
		goto post_status;
	}
	return result;

 post_errno:
	state->sys_errno = errno;
 post_status:
	fcntl(fd, F_SETFL, state->old_sockflags);
	if (!async_post_error(result, ev, state->sys_errno)) {
		goto fail;
	}
	return result;
 fail:
	TALLOC_FREE(result);
	return NULL;
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
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_connect_state *state = talloc_get_type_abort(
		req->private_data, struct async_connect_state);

	TALLOC_FREE(fde);

	/*
	 * Stevens, Network Programming says that if there's a
	 * successful connect, the socket is only writable. Upon an
	 * error, it's both readable and writable.
	 */
	if ((flags & (TEVENT_FD_READ|TEVENT_FD_WRITE))
	    == (TEVENT_FD_READ|TEVENT_FD_WRITE)) {
		int sockerr;
		socklen_t err_len = sizeof(sockerr);

		if (getsockopt(state->fd, SOL_SOCKET, SO_ERROR,
			       (void *)&sockerr, &err_len) == 0) {
			errno = sockerr;
		}

		state->sys_errno = errno;

		DEBUG(10, ("connect returned %s\n", strerror(errno)));

		fcntl(state->fd, F_SETFL, state->old_sockflags);
		async_req_error(req, state->sys_errno);
		return;
	}

	state->sys_errno = 0;
	async_req_done(req);
}

int async_connect_recv(struct async_req *req, int *perrno)
{
	struct async_connect_state *state = talloc_get_type_abort(
		req->private_data, struct async_connect_state);
	int err;

	fcntl(state->fd, F_SETFL, state->old_sockflags);


	if (async_req_is_errno(req, &err)) {
		*perrno = err;
		return -1;
	}
	if (state->sys_errno == 0) {
		return 0;
	}

	*perrno = state->sys_errno;
	return -1;
}
