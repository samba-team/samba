/*
   Unix SMB/CIFS implementation.
   Infrastructure for async winbind requests
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
#include "winbindd/winbindd.h"
#include "winbindd/winbindd_proto.h"

static int make_nonstd_fd(int fd)
{
	int i;
	int sys_errno = 0;
	int fds[3];
	int num_fds = 0;

	if (fd == -1) {
		return -1;
	}
	while (fd < 3) {
		fds[num_fds++] = fd;
		fd = dup(fd);
		if (fd == -1) {
			sys_errno = errno;
			break;
		}
	}
	for (i=0; i<num_fds; i++) {
		close(fds[i]);
	}
	if (fd == -1) {
		errno = sys_errno;
	}
	return fd;
}

/****************************************************************************
 Set a fd into blocking/nonblocking mode. Uses POSIX O_NONBLOCK if available,
 else
 if SYSV use O_NDELAY
 if BSD use FNDELAY
 Set close on exec also.
****************************************************************************/

static int make_safe_fd(int fd)
{
	int result, flags;
	int new_fd = make_nonstd_fd(fd);

	if (new_fd == -1) {
		goto fail;
	}

	/* Socket should be nonblocking. */

#ifdef O_NONBLOCK
#define FLAG_TO_SET O_NONBLOCK
#else
#ifdef SYSV
#define FLAG_TO_SET O_NDELAY
#else /* BSD */
#define FLAG_TO_SET FNDELAY
#endif
#endif

	if ((flags = fcntl(new_fd, F_GETFL)) == -1) {
		goto fail;
	}

	flags |= FLAG_TO_SET;
	if (fcntl(new_fd, F_SETFL, flags) == -1) {
		goto fail;
	}

#undef FLAG_TO_SET

	/* Socket should be closed on exec() */
#ifdef FD_CLOEXEC
	result = flags = fcntl(new_fd, F_GETFD, 0);
	if (flags >= 0) {
		flags |= FD_CLOEXEC;
		result = fcntl( new_fd, F_SETFD, flags );
	}
	if (result < 0) {
		goto fail;
	}
#endif
	return new_fd;

 fail:
	if (new_fd != -1) {
		int sys_errno = errno;
		close(new_fd);
		errno = sys_errno;
	}
	return -1;
}

static bool winbind_closed_fd(int fd)
{
	struct timeval tv;
	fd_set r_fds;

	if (fd == -1) {
		return true;
	}

	FD_ZERO(&r_fds);
	FD_SET(fd, &r_fds);
	ZERO_STRUCT(tv);

	if ((select(fd+1, &r_fds, NULL, NULL, &tv) == -1)
	    || FD_ISSET(fd, &r_fds)) {
		return true;
	}

	return false;
}

struct wb_context {
	struct async_req_queue *queue;
	int fd;
	bool is_priv;
};

struct wb_context *wb_context_init(TALLOC_CTX *mem_ctx)
{
	struct wb_context *result;

	result = talloc(mem_ctx, struct wb_context);
	if (result == NULL) {
		return NULL;
	}
	result->queue = async_req_queue_init(result);
	if (result->queue == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}
	result->fd = -1;
	return result;
}

static struct async_req *wb_connect_send(TALLOC_CTX *mem_ctx,
					 struct event_context *ev,
					 struct wb_context *wb_ctx,
					 const char *dir)
{
	struct async_req *req;
	struct sockaddr_un sunaddr;
	struct stat st;
	char *path = NULL;
	NTSTATUS status;

	if (wb_ctx->fd != -1) {
		close(wb_ctx->fd);
		wb_ctx->fd = -1;
	}

	/* Check permissions on unix socket directory */

	if (lstat(dir, &st) == -1) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto post_status;
	}

	if (!S_ISDIR(st.st_mode) ||
	    (st.st_uid != 0 && st.st_uid != geteuid())) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto post_status;
	}

	/* Connect to socket */

	path = talloc_asprintf(talloc_tos(), "%s/%s", dir,
			       WINBINDD_SOCKET_NAME);
	if (path == NULL) {
		goto nomem;
	}

	sunaddr.sun_family = AF_UNIX;
	strlcpy(sunaddr.sun_path, path, sizeof(sunaddr.sun_path));
	TALLOC_FREE(path);

	/* If socket file doesn't exist, don't bother trying to connect
	   with retry.  This is an attempt to make the system usable when
	   the winbindd daemon is not running. */

	if ((lstat(sunaddr.sun_path, &st) == -1)
	    || !S_ISSOCK(st.st_mode)
	    || (st.st_uid != 0 && st.st_uid != geteuid())) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto post_status;
	}

	wb_ctx->fd = make_safe_fd(socket(AF_UNIX, SOCK_STREAM, 0));
	if (wb_ctx->fd == -1) {
		status = map_nt_error_from_unix(errno);
		goto post_status;
	}

	req = async_connect_send(mem_ctx, ev, wb_ctx->fd,
				 (struct sockaddr *)&sunaddr,
				 sizeof(sunaddr));
	if (req == NULL) {
		goto nomem;
	}
	if (!async_req_set_timeout(req, ev, timeval_set(30, 0))) {
		TALLOC_FREE(req);
		goto nomem;
	}

	return req;

 nomem:
	status = NT_STATUS_NO_MEMORY;
 post_status:
	req = async_req_new(mem_ctx);
	if (req == NULL) {
		return NULL;
	}
	if (async_post_status(req, ev, status)) {
		return req;
	}
	TALLOC_FREE(req);
	return NULL;
}

static NTSTATUS wb_connect_recv(struct async_req *req)
{
	int dummy;

	return async_connect_recv(req, &dummy);
}

static struct winbindd_request *winbindd_request_copy(
	TALLOC_CTX *mem_ctx,
	const struct winbindd_request *req)
{
	struct winbindd_request *result;

	result = (struct winbindd_request *)TALLOC_MEMDUP(
		mem_ctx, req, sizeof(struct winbindd_request));
	if (result == NULL) {
		return NULL;
	}

	if (result->extra_len == 0) {
		return result;
	}

	result->extra_data.data = (char *)TALLOC_MEMDUP(
		result, result->extra_data.data, result->extra_len);
	if (result->extra_data.data == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}
	return result;
}

struct wb_int_trans_state {
	struct event_context *ev;
	int fd;
	struct winbindd_request *wb_req;
	struct winbindd_response *wb_resp;
};

static void wb_int_trans_write_done(struct async_req *subreq);
static void wb_int_trans_read_done(struct async_req *subreq);

static struct async_req *wb_int_trans_send(TALLOC_CTX *mem_ctx,
					   struct event_context *ev, int fd,
					   struct winbindd_request *wb_req)
{
	struct async_req *result;
	struct async_req *subreq;
	struct wb_int_trans_state *state;

	result = async_req_new(mem_ctx);
	if (result == NULL) {
		return NULL;
	}
	state = talloc(result, struct wb_int_trans_state);
	if (state == NULL) {
		goto fail;
	}
	result->private_data = state;

	if (winbind_closed_fd(fd)) {
		if (!async_post_status(result, ev,
				       NT_STATUS_PIPE_DISCONNECTED)) {
			goto fail;
		}
		return result;
	}

	state->ev = ev;
	state->fd = fd;
	state->wb_req = wb_req;

	state->wb_req->length = sizeof(struct winbindd_request);
	state->wb_req->pid = getpid();

	subreq = wb_req_write_send(state, state->ev, state->fd, state->wb_req);
	if (subreq == NULL) {
		goto fail;
	}
	subreq->async.fn = wb_int_trans_write_done;
	subreq->async.priv = result;

	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void wb_int_trans_write_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct wb_int_trans_state *state = talloc_get_type_abort(
		req->private_data, struct wb_int_trans_state);
	NTSTATUS status;

	status = wb_req_write_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_error(req, status);
		return;
	}

	subreq = wb_resp_read_send(state, state->ev, state->fd);
	if (subreq == NULL) {
		async_req_error(req, NT_STATUS_NO_MEMORY);
	}
	subreq->async.fn = wb_int_trans_read_done;
	subreq->async.priv = req;
}

static void wb_int_trans_read_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct wb_int_trans_state *state = talloc_get_type_abort(
		req->private_data, struct wb_int_trans_state);
	NTSTATUS status;

	status = wb_resp_read_recv(subreq, state, &state->wb_resp);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_error(req, status);
		return;
	}

	async_req_done(req);
}

static NTSTATUS wb_int_trans_recv(struct async_req *req,
				  TALLOC_CTX *mem_ctx,
				  struct winbindd_response **presponse)
{
	struct wb_int_trans_state *state = talloc_get_type_abort(
		req->private_data, struct wb_int_trans_state);
	NTSTATUS status;

	if (async_req_is_error(req, &status)) {
		return status;
	}

	*presponse = talloc_move(mem_ctx, &state->wb_resp);
	return NT_STATUS_OK;
}

static const char *winbindd_socket_dir(void)
{
#ifdef SOCKET_WRAPPER
	const char *env_dir;

	env_dir = getenv(WINBINDD_SOCKET_DIR_ENVVAR);
	if (env_dir) {
		return env_dir;
	}
#endif

	return WINBINDD_SOCKET_DIR;
}

struct wb_open_pipe_state {
	struct wb_context *wb_ctx;
	struct event_context *ev;
	bool need_priv;
	struct winbindd_request wb_req;
};

static void wb_open_pipe_connect_nonpriv_done(struct async_req *subreq);
static void wb_open_pipe_ping_done(struct async_req *subreq);
static void wb_open_pipe_getpriv_done(struct async_req *subreq);
static void wb_open_pipe_connect_priv_done(struct async_req *subreq);

static struct async_req *wb_open_pipe_send(TALLOC_CTX *mem_ctx,
					   struct event_context *ev,
					   struct wb_context *wb_ctx,
					   bool need_priv)
{
	struct async_req *result;
	struct async_req *subreq;
	struct wb_open_pipe_state *state;

	result = async_req_new(mem_ctx);
	if (result == NULL) {
		return NULL;
	}
	state = talloc(result, struct wb_open_pipe_state);
	if (state == NULL) {
		goto fail;
	}
	result->private_data = state;

	state->wb_ctx = wb_ctx;
	state->ev = ev;
	state->need_priv = need_priv;

	if (wb_ctx->fd != -1) {
		close(wb_ctx->fd);
		wb_ctx->fd = -1;
	}

	subreq = wb_connect_send(state, ev, wb_ctx, winbindd_socket_dir());
	if (subreq == NULL) {
		goto fail;
	}

	subreq->async.fn = wb_open_pipe_connect_nonpriv_done;
	subreq->async.priv = result;
	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void wb_open_pipe_connect_nonpriv_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct wb_open_pipe_state *state = talloc_get_type_abort(
		req->private_data, struct wb_open_pipe_state);
	NTSTATUS status;

	status = wb_connect_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		state->wb_ctx->is_priv = true;
		async_req_error(req, status);
		return;
	}

	ZERO_STRUCT(state->wb_req);
	state->wb_req.cmd = WINBINDD_INTERFACE_VERSION;

	subreq = wb_int_trans_send(state, state->ev, state->wb_ctx->fd,
				   &state->wb_req);
	if (async_req_nomem(subreq, req)) {
		return;
	}

	subreq->async.fn = wb_open_pipe_ping_done;
	subreq->async.priv = req;
}

static void wb_open_pipe_ping_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct wb_open_pipe_state *state = talloc_get_type_abort(
		req->private_data, struct wb_open_pipe_state);
	struct winbindd_response *wb_resp;
	NTSTATUS status;

	status = wb_int_trans_recv(subreq, state, &wb_resp);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_error(req, status);
		return;
	}

	if (!state->need_priv) {
		async_req_done(req);
		return;
	}

	state->wb_req.cmd = WINBINDD_PRIV_PIPE_DIR;

	subreq = wb_int_trans_send(state, state->ev, state->wb_ctx->fd,
				   &state->wb_req);
	if (async_req_nomem(subreq, req)) {
		return;
	}

	subreq->async.fn = wb_open_pipe_getpriv_done;
	subreq->async.priv = req;
}

static void wb_open_pipe_getpriv_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct wb_open_pipe_state *state = talloc_get_type_abort(
		req->private_data, struct wb_open_pipe_state);
	struct winbindd_response *wb_resp = NULL;
	NTSTATUS status;

	status = wb_int_trans_recv(subreq, state, &wb_resp);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_error(req, status);
		return;
	}

	close(state->wb_ctx->fd);
	state->wb_ctx->fd = -1;

	subreq = wb_connect_send(state, state->ev, state->wb_ctx,
				 (char *)wb_resp->extra_data.data);
	TALLOC_FREE(wb_resp);
	if (async_req_nomem(subreq, req)) {
		return;
	}

	subreq->async.fn = wb_open_pipe_connect_priv_done;
	subreq->async.priv = req;
}

static void wb_open_pipe_connect_priv_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct wb_open_pipe_state *state = talloc_get_type_abort(
		req->private_data, struct wb_open_pipe_state);
	NTSTATUS status;

	status = wb_connect_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		async_req_error(req, status);
		return;
	}
	state->wb_ctx->is_priv = true;
	async_req_done(req);
}

static NTSTATUS wb_open_pipe_recv(struct async_req *req)
{
	return async_req_simple_recv(req);
}

struct wb_trans_state {
	struct wb_trans_state *prev, *next;
	struct wb_context *wb_ctx;
	struct event_context *ev;
	struct winbindd_request *wb_req;
	struct winbindd_response *wb_resp;
	int num_retries;
	bool need_priv;
};

static void wb_trans_connect_done(struct async_req *subreq);
static void wb_trans_done(struct async_req *subreq);
static void wb_trans_retry_wait_done(struct async_req *subreq);

static void wb_trigger_trans(struct async_req *req)
{
	struct wb_trans_state *state = talloc_get_type_abort(
		req->private_data, struct wb_trans_state);
	struct async_req *subreq;

	if ((state->wb_ctx->fd == -1)
	    || (state->need_priv && !state->wb_ctx->is_priv)) {

		subreq = wb_open_pipe_send(state, state->ev, state->wb_ctx,
					   state->need_priv);
		if (async_req_nomem(subreq, req)) {
			return;
		}
		subreq->async.fn = wb_trans_connect_done;
		subreq->async.priv = req;
		return;
	}

	subreq = wb_int_trans_send(state, state->ev, state->wb_ctx->fd,
				   state->wb_req);
	if (async_req_nomem(subreq, req)) {
		return;
	}
	subreq->async.fn = wb_trans_done;
	subreq->async.priv = req;
}

struct async_req *wb_trans_send(TALLOC_CTX *mem_ctx, struct event_context *ev,
				struct wb_context *wb_ctx, bool need_priv,
				const struct winbindd_request *wb_req)
{
	struct async_req *result;
	struct wb_trans_state *state;

	result = async_req_new(mem_ctx);
	if (result == NULL) {
		return NULL;
	}
	state = talloc(result, struct wb_trans_state);
	if (state == NULL) {
		goto fail;
	}
	result->private_data = state;

	state->wb_ctx = wb_ctx;
	state->ev = ev;
	state->wb_req = winbindd_request_copy(state, wb_req);
	if (state->wb_req == NULL) {
		goto fail;
	}
	state->num_retries = 10;
	state->need_priv = need_priv;

	if (!async_req_enqueue(wb_ctx->queue, ev, result, wb_trigger_trans)) {
		goto fail;
	}
	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static bool wb_trans_retry(struct async_req *req,
			   struct wb_trans_state *state,
			   NTSTATUS status)
{
	struct async_req *subreq;

	if (NT_STATUS_IS_OK(status)) {
		return false;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)
	    || NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		/*
		 * Winbind not around or we can't connect to the pipe. Fail
		 * immediately.
		 */
		async_req_error(req, status);
		return true;
	}

	state->num_retries -= 1;
	if (state->num_retries == 0) {
		async_req_error(req, status);
		return true;
	}

	/*
	 * The transfer as such failed, retry after one second
	 */

	if (state->wb_ctx->fd != -1) {
		close(state->wb_ctx->fd);
		state->wb_ctx->fd = -1;
	}

	subreq = async_wait_send(state, state->ev, timeval_set(1, 0));
	if (async_req_nomem(subreq, req)) {
		return true;
	}

	subreq->async.fn = wb_trans_retry_wait_done;
	subreq->async.priv = req;
	return true;
}

static void wb_trans_retry_wait_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct wb_trans_state *state = talloc_get_type_abort(
		req->private_data, struct wb_trans_state);
	NTSTATUS status;

	status = async_wait_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		async_req_error(req, status);
		return;
	}

	subreq = wb_open_pipe_send(state, state->ev, state->wb_ctx,
				   state->need_priv);
	if (async_req_nomem(subreq, req)) {
		return;
	}
	subreq->async.fn = wb_trans_connect_done;
	subreq->async.priv = req;
}

static void wb_trans_connect_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct wb_trans_state *state = talloc_get_type_abort(
		req->private_data, struct wb_trans_state);
	NTSTATUS status;

	status = wb_open_pipe_recv(subreq);
	TALLOC_FREE(subreq);

	if (wb_trans_retry(req, state, status)) {
		return;
	}

	subreq = wb_int_trans_send(state, state->ev, state->wb_ctx->fd,
				   state->wb_req);
	if (async_req_nomem(subreq, req)) {
		return;
	}

	subreq->async.fn = wb_trans_done;
	subreq->async.priv = req;
}

static void wb_trans_done(struct async_req *subreq)
{
	struct async_req *req = talloc_get_type_abort(
		subreq->async.priv, struct async_req);
	struct wb_trans_state *state = talloc_get_type_abort(
		req->private_data, struct wb_trans_state);
	NTSTATUS status;

	status = wb_int_trans_recv(subreq, state, &state->wb_resp);
	TALLOC_FREE(subreq);

	if (wb_trans_retry(req, state, status)) {
		return;
	}

	async_req_done(req);
}

NTSTATUS wb_trans_recv(struct async_req *req, TALLOC_CTX *mem_ctx,
		       struct winbindd_response **presponse)
{
	struct wb_trans_state *state = talloc_get_type_abort(
		req->private_data, struct wb_trans_state);
	NTSTATUS status;

	if (async_req_is_error(req, &status)) {
		return status;
	}

	*presponse = talloc_move(mem_ctx, &state->wb_resp);
	return NT_STATUS_OK;
}
