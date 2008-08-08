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
	struct fd_event *fde;

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
					   struct event_context *ev,
					   enum async_syscall_type type,
					   struct async_syscall_state **pstate)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_req_new(mem_ctx, ev);
	if (result == NULL) {
		return NULL;
	}

	state = talloc(result, struct async_syscall_state);
	if (state == NULL) {
		TALLOC_FREE(result);
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
 * @param[in] fde_flags EVENT_FD_READ/WRITE -- what are we interested in?
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
	struct event_context *ev,
	enum async_syscall_type type,
	int fd,
	uint16_t fde_flags,
	void (*fde_cb)(struct event_context *ev,
		       struct fd_event *fde, uint16_t flags,
		       void *priv),
	struct async_syscall_state **pstate)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_syscall_new(mem_ctx, ev, type, &state);
	if (result == NULL) {
		return NULL;
	}

	state->fde = event_add_fd(ev, state, fd, fde_flags, fde_cb, result);
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

ssize_t async_syscall_result_ssize_t(struct async_req **req, int *perrno)
{
	struct async_syscall_state *state = talloc_get_type_abort(
		(*req)->private_data, struct async_syscall_state);

	int sys_errno = state->sys_errno;
	ssize_t result = state->result.result_ssize_t;

	TALLOC_FREE(*req);

	*perrno = sys_errno;
	return result;
}

/**
 * Retrieve a size_t typed result from an async syscall
 * @param[in] req	The syscall that has just finished
 * @param[out] perrno	Where to put the syscall's errno
 * @retval The return value from the asynchronously called syscall
 */

size_t async_syscall_result_size_t(struct async_req **req, int *perrno)
{
	struct async_syscall_state *state = talloc_get_type_abort(
		(*req)->private_data, struct async_syscall_state);

	int sys_errno = state->sys_errno;
	size_t result = state->result.result_ssize_t;

	TALLOC_FREE(*req);

	*perrno = sys_errno;
	return result;
}

/**
 * Retrieve a int typed result from an async syscall
 * @param[in] req	The syscall that has just finished
 * @param[out] perrno	Where to put the syscall's errno
 * @retval The return value from the asynchronously called syscall
 */

ssize_t async_syscall_result_int(struct async_req **req, int *perrno)
{
	struct async_syscall_state *state = talloc_get_type_abort(
		(*req)->private_data, struct async_syscall_state);

	int sys_errno = state->sys_errno;
	int result = state->result.result_ssize_t;

	TALLOC_FREE(*req);

	*perrno = sys_errno;
	return result;
}

/**
 * fde event handler for the "send" syscall
 * @param[in] ev	The event context that sent us here
 * @param[in] fde	The file descriptor event associated with the send
 * @param[in] flags	Can only be EVENT_FD_WRITE here
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_send_callback(struct event_context *ev,
				struct fd_event *fde, uint16_t flags,
				void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	struct param_send *p = &state->param.param_send;

	SMB_ASSERT(state->syscall_type == ASYNC_SYSCALL_SEND);

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

struct async_req *async_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
			     int fd, const void *buffer, size_t length,
			     int flags)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_fde_syscall_new(
		mem_ctx, ev, ASYNC_SYSCALL_SEND,
		fd, EVENT_FD_WRITE, async_send_callback,
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
 * @param[in] flags	Can only be EVENT_FD_WRITE here
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_sendall_callback(struct event_context *ev,
				   struct fd_event *fde, uint16_t flags,
				   void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	struct param_sendall *p = &state->param.param_sendall;

	SMB_ASSERT(state->syscall_type == ASYNC_SYSCALL_SENDALL);

	state->result.result_ssize_t = send(p->fd, (char *)p->buffer + p->sent,
					    p->length - p->sent, p->flags);
	state->sys_errno = errno;

	if (state->result.result_ssize_t == -1) {
		async_req_error(req, map_nt_error_from_unix(state->sys_errno));
		return;
	}

	if (state->result.result_ssize_t == 0) {
		async_req_error(req, NT_STATUS_END_OF_FILE);
		return;
	}

	p->sent += state->result.result_ssize_t;
	SMB_ASSERT(p->sent <= p->length);

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

struct async_req *async_sendall(TALLOC_CTX *mem_ctx, struct event_context *ev,
				int fd, const void *buffer, size_t length,
				int flags)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_fde_syscall_new(
		mem_ctx, ev, ASYNC_SYSCALL_SENDALL,
		fd, EVENT_FD_WRITE, async_sendall_callback,
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

/**
 * fde event handler for the "recv" syscall
 * @param[in] ev	The event context that sent us here
 * @param[in] fde	The file descriptor event associated with the recv
 * @param[in] flags	Can only be EVENT_FD_READ here
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_recv_callback(struct event_context *ev,
				struct fd_event *fde, uint16_t flags,
				void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	struct param_recv *p = &state->param.param_recv;

	SMB_ASSERT(state->syscall_type == ASYNC_SYSCALL_RECV);

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

struct async_req *async_recv(TALLOC_CTX *mem_ctx, struct event_context *ev,
			     int fd, void *buffer, size_t length,
			     int flags)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_fde_syscall_new(
		mem_ctx, ev, ASYNC_SYSCALL_RECV,
		fd, EVENT_FD_READ, async_recv_callback,
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
 * @param[in] flags	Can only be EVENT_FD_READ here
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_recvall_callback(struct event_context *ev,
				   struct fd_event *fde, uint16_t flags,
				   void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	struct param_recvall *p = &state->param.param_recvall;

	SMB_ASSERT(state->syscall_type == ASYNC_SYSCALL_RECVALL);

	state->result.result_ssize_t = recv(p->fd,
					    (char *)p->buffer + p->received,
					    p->length - p->received, p->flags);
	state->sys_errno = errno;

	if (state->result.result_ssize_t == -1) {
		async_req_error(req, map_nt_error_from_unix(state->sys_errno));
		return;
	}

	if (state->result.result_ssize_t == 0) {
		async_req_error(req, NT_STATUS_END_OF_FILE);
		return;
	}

	p->received += state->result.result_ssize_t;
	SMB_ASSERT(p->received <= p->length);

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

struct async_req *async_recvall(TALLOC_CTX *mem_ctx, struct event_context *ev,
				int fd, void *buffer, size_t length,
				int flags)
{
	struct async_req *result;
	struct async_syscall_state *state;

	result = async_fde_syscall_new(
		mem_ctx, ev, ASYNC_SYSCALL_RECVALL,
		fd, EVENT_FD_READ, async_recvall_callback,
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

/**
 * fde event handler for connect(2)
 * @param[in] ev	The event context that sent us here
 * @param[in] fde	The file descriptor event associated with the connect
 * @param[in] flags	Indicate read/writeability of the socket
 * @param[in] priv	private data, "struct async_req *" in this case
 */

static void async_connect_callback(struct event_context *ev,
				   struct fd_event *fde, uint16_t flags,
				   void *priv)
{
	struct async_req *req = talloc_get_type_abort(
		priv, struct async_req);
	struct async_syscall_state *state = talloc_get_type_abort(
		req->private_data, struct async_syscall_state);
	struct param_connect *p = &state->param.param_connect;

	SMB_ASSERT(state->syscall_type == ASYNC_SYSCALL_CONNECT);

	TALLOC_FREE(state->fde);

	/*
	 * Stevens, Network Programming says that if there's a
	 * successful connect, the socket is only writable. Upon an
	 * error, it's both readable and writable.
	 */
	if ((flags & (EVENT_FD_READ|EVENT_FD_WRITE))
	    == (EVENT_FD_READ|EVENT_FD_WRITE)) {
		int sockerr;
		socklen_t err_len = sizeof(sockerr);

		if (getsockopt(p->fd, SOL_SOCKET, SO_ERROR,
			       (void *)&sockerr, &err_len) == 0) {
			errno = sockerr;
		}

		state->sys_errno = errno;

		DEBUG(10, ("connect returned %s\n", strerror(errno)));

		sys_fcntl_long(p->fd, F_SETFL, p->old_sockflags);

		async_req_error(req, map_nt_error_from_unix(state->sys_errno));
		return;
	}

	sys_fcntl_long(p->fd, F_SETFL, p->old_sockflags);

	state->result.result_int = 0;
	state->sys_errno = 0;

	async_req_done(req);
}

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

struct async_req *async_connect(TALLOC_CTX *mem_ctx, struct event_context *ev,
				int fd, const struct sockaddr *address,
				socklen_t address_len)
{
	struct async_req *result;
	struct async_syscall_state *state;
	struct param_connect *p;

	result = async_syscall_new(mem_ctx, ev, ASYNC_SYSCALL_CONNECT, &state);
	if (result == NULL) {
		return NULL;
	}
	p = &state->param.param_connect;

	/**
	 * We have to set the socket to nonblocking for async connect(2). Keep
	 * the old sockflags around.
	 */

	p->old_sockflags = sys_fcntl_long(fd, F_GETFL, 0);

	if (p->old_sockflags == -1) {
		if (async_post_status(result, map_nt_error_from_unix(errno))) {
			return result;
		}
		TALLOC_FREE(result);
		return NULL;
	}

	set_blocking(fd, true);

	state->result.result_int = connect(fd, address, address_len);

	if (state->result.result_int == 0) {
		state->sys_errno = 0;
		if (async_post_status(result, NT_STATUS_OK)) {
			return result;
		}
		sys_fcntl_long(fd, F_SETFL, p->old_sockflags);
		TALLOC_FREE(result);
		return NULL;
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

		state->sys_errno = errno;

		if (async_post_status(result, map_nt_error_from_unix(errno))) {
			return result;
		}
		sys_fcntl_long(fd, F_SETFL, p->old_sockflags);
		TALLOC_FREE(result);
		return NULL;
	}

	state->fde = event_add_fd(ev, state, fd,
				  EVENT_FD_READ | EVENT_FD_WRITE,
				  async_connect_callback, state);
	if (state->fde == NULL) {
		sys_fcntl_long(fd, F_SETFL, p->old_sockflags);
		TALLOC_FREE(result);
		return NULL;
	}

	state->param.param_connect.fd = fd;
	state->param.param_connect.address = address;
	state->param.param_connect.address_len = address_len;

	return result;
}

