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
#include "wbc_async.h"

struct wb_context {
	struct tevent_queue *queue;
	int fd;
	bool is_priv;
};

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

struct wb_context *wb_context_init(TALLOC_CTX *mem_ctx)
{
	struct wb_context *result;

	result = talloc(mem_ctx, struct wb_context);
	if (result == NULL) {
		return NULL;
	}
	result->queue = tevent_queue_create(result, "wb_trans");
	if (result->queue == NULL) {
		TALLOC_FREE(result);
		return NULL;
	}
	result->fd = -1;
	return result;
}

struct wb_connect_state {
	int dummy;
};

static void wbc_connect_connected(struct tevent_req *subreq);

static struct tevent_req *wb_connect_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct wb_context *wb_ctx,
					  const char *dir)
{
	struct tevent_req *result, *subreq;
	struct wb_connect_state *state;
	struct sockaddr_un sunaddr;
	struct stat st;
	char *path = NULL;
	wbcErr wbc_err;

	result = tevent_req_create(mem_ctx, &state, struct wb_connect_state);
	if (result == NULL) {
		return NULL;
	}

	if (wb_ctx->fd != -1) {
		close(wb_ctx->fd);
		wb_ctx->fd = -1;
	}

	/* Check permissions on unix socket directory */

	if (lstat(dir, &st) == -1) {
		wbc_err = WBC_ERR_WINBIND_NOT_AVAILABLE;
		goto post_status;
	}

	if (!S_ISDIR(st.st_mode) ||
	    (st.st_uid != 0 && st.st_uid != geteuid())) {
		wbc_err = WBC_ERR_WINBIND_NOT_AVAILABLE;
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
		wbc_err = WBC_ERR_WINBIND_NOT_AVAILABLE;
		goto post_status;
	}

	wb_ctx->fd = make_safe_fd(socket(AF_UNIX, SOCK_STREAM, 0));
	if (wb_ctx->fd == -1) {
		wbc_err = map_wbc_err_from_errno(errno);
		goto post_status;
	}

	subreq = async_connect_send(mem_ctx, ev, wb_ctx->fd,
				    (struct sockaddr *)&sunaddr,
				    sizeof(sunaddr));
	if (subreq == NULL) {
		goto nomem;
	}
	tevent_req_set_callback(subreq, wbc_connect_connected, result);

	if (!tevent_req_set_endtime(subreq, ev, timeval_current_ofs(30, 0))) {
		goto nomem;
	}

	return result;

 post_status:
	tevent_req_error(result, wbc_err);
	return tevent_req_post(result, ev);
 nomem:
	TALLOC_FREE(result);
	return NULL;
}

static void wbc_connect_connected(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int res, err;

	res = async_connect_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (res == -1) {
		tevent_req_error(req, map_wbc_err_from_errno(err));
		return;
	}
	tevent_req_done(req);
}

static wbcErr wb_connect_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_wbcerr(req);
}

struct wb_int_trans_state {
	struct tevent_context *ev;
	int fd;
	struct winbindd_request *wb_req;
	struct winbindd_response *wb_resp;
};

static void wb_int_trans_write_done(struct tevent_req *subreq);
static void wb_int_trans_read_done(struct tevent_req *subreq);

static struct tevent_req *wb_int_trans_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct tevent_queue *queue, int fd,
					    struct winbindd_request *wb_req)
{
	struct tevent_req *result, *subreq;
	struct wb_int_trans_state *state;

	result = tevent_req_create(mem_ctx, &state,
				   struct wb_int_trans_state);
	if (result == NULL) {
		return NULL;
	}

	if (winbind_closed_fd(fd)) {
		tevent_req_error(result, WBC_ERR_WINBIND_NOT_AVAILABLE);
		return tevent_req_post(result, ev);
	}

	state->ev = ev;
	state->fd = fd;
	state->wb_req = wb_req;
	state->wb_req->length = sizeof(struct winbindd_request);
	state->wb_req->pid = getpid();

	subreq = wb_req_write_send(state, state->ev, queue, state->fd,
				   state->wb_req);
	if (subreq == NULL) {
		goto fail;
	}
	tevent_req_set_callback(subreq, wb_int_trans_write_done, result);

	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void wb_int_trans_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_int_trans_state *state = tevent_req_data(
		req, struct wb_int_trans_state);
	wbcErr wbc_err;

	wbc_err = wb_req_write_recv(subreq);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_err)) {
		tevent_req_error(req, wbc_err);
		return;
	}

	subreq = wb_resp_read_send(state, state->ev, state->fd);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_int_trans_read_done, req);
}

static void wb_int_trans_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_int_trans_state *state = tevent_req_data(
		req, struct wb_int_trans_state);
	wbcErr wbc_err;

	wbc_err = wb_resp_read_recv(subreq, state, &state->wb_resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_err)) {
		tevent_req_error(req, wbc_err);
		return;
	}

	tevent_req_done(req);
}

static wbcErr wb_int_trans_recv(struct tevent_req *req,
				TALLOC_CTX *mem_ctx,
				struct winbindd_response **presponse)
{
	struct wb_int_trans_state *state = tevent_req_data(
		req, struct wb_int_trans_state);
	wbcErr wbc_err;

	if (tevent_req_is_wbcerr(req, &wbc_err)) {
		return wbc_err;
	}

	*presponse = talloc_move(mem_ctx, &state->wb_resp);
	return WBC_ERR_SUCCESS;
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
	struct tevent_context *ev;
	bool need_priv;
	struct winbindd_request wb_req;
};

static void wb_open_pipe_connect_nonpriv_done(struct tevent_req *subreq);
static void wb_open_pipe_ping_done(struct tevent_req *subreq);
static void wb_open_pipe_getpriv_done(struct tevent_req *subreq);
static void wb_open_pipe_connect_priv_done(struct tevent_req *subreq);

static struct tevent_req *wb_open_pipe_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct wb_context *wb_ctx,
					    bool need_priv)
{
	struct tevent_req *result, *subreq;
	struct wb_open_pipe_state *state;

	result = tevent_req_create(mem_ctx, &state, struct wb_open_pipe_state);
	if (result == NULL) {
		return NULL;
	}
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
	tevent_req_set_callback(subreq, wb_open_pipe_connect_nonpriv_done,
				result);
	return result;

 fail:
	TALLOC_FREE(result);
	return NULL;
}

static void wb_open_pipe_connect_nonpriv_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_open_pipe_state *state = tevent_req_data(
		req, struct wb_open_pipe_state);
	wbcErr wbc_err;

	wbc_err = wb_connect_recv(subreq);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_err)) {
		state->wb_ctx->is_priv = true;
		tevent_req_error(req, wbc_err);
		return;
	}

	ZERO_STRUCT(state->wb_req);
	state->wb_req.cmd = WINBINDD_INTERFACE_VERSION;

	subreq = wb_int_trans_send(state, state->ev, NULL, state->wb_ctx->fd,
				   &state->wb_req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_open_pipe_ping_done, req);
}

static void wb_open_pipe_ping_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_open_pipe_state *state = tevent_req_data(
		req, struct wb_open_pipe_state);
	struct winbindd_response *wb_resp;
	wbcErr wbc_err;

	wbc_err = wb_int_trans_recv(subreq, state, &wb_resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_err)) {
		tevent_req_error(req, wbc_err);
		return;
	}

	if (!state->need_priv) {
		tevent_req_done(req);
		return;
	}

	state->wb_req.cmd = WINBINDD_PRIV_PIPE_DIR;

	subreq = wb_int_trans_send(state, state->ev, NULL, state->wb_ctx->fd,
				   &state->wb_req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_open_pipe_getpriv_done, req);
}

static void wb_open_pipe_getpriv_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_open_pipe_state *state = tevent_req_data(
		req, struct wb_open_pipe_state);
	struct winbindd_response *wb_resp = NULL;
	wbcErr wbc_err;

	wbc_err = wb_int_trans_recv(subreq, state, &wb_resp);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_err)) {
		tevent_req_error(req, wbc_err);
		return;
	}

	close(state->wb_ctx->fd);
	state->wb_ctx->fd = -1;

	subreq = wb_connect_send(state, state->ev, state->wb_ctx,
				  (char *)wb_resp->extra_data.data);
	TALLOC_FREE(wb_resp);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_open_pipe_connect_priv_done, req);
}

static void wb_open_pipe_connect_priv_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_open_pipe_state *state = tevent_req_data(
		req, struct wb_open_pipe_state);
	wbcErr wbc_err;

	wbc_err = wb_connect_recv(subreq);
	TALLOC_FREE(subreq);
	if (!WBC_ERROR_IS_OK(wbc_err)) {
		tevent_req_error(req, wbc_err);
		return;
	}
	state->wb_ctx->is_priv = true;
	tevent_req_done(req);
}

static wbcErr wb_open_pipe_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_wbcerr(req);
}

struct wb_trans_state {
	struct wb_trans_state *prev, *next;
	struct wb_context *wb_ctx;
	struct tevent_context *ev;
	struct winbindd_request *wb_req;
	struct winbindd_response *wb_resp;
	int num_retries;
	bool need_priv;
};

static void wb_trans_connect_done(struct tevent_req *subreq);
static void wb_trans_done(struct tevent_req *subreq);
static void wb_trans_retry_wait_done(struct tevent_req *subreq);

struct tevent_req *wb_trans_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 struct wb_context *wb_ctx, bool need_priv,
				 struct winbindd_request *wb_req)
{
	struct tevent_req *req, *subreq;
	struct wb_trans_state *state;

	req = tevent_req_create(mem_ctx, &state, struct wb_trans_state);
	if (req == NULL) {
		return NULL;
	}
	state->wb_ctx = wb_ctx;
	state->ev = ev;
	state->wb_req = wb_req;
	state->num_retries = 10;
	state->need_priv = need_priv;

	if ((wb_ctx->fd == -1) || (need_priv && !wb_ctx->is_priv)) {
		subreq = wb_open_pipe_send(state, ev, wb_ctx, need_priv);
		if (subreq == NULL) {
			goto fail;
		}
		tevent_req_set_callback(subreq, wb_trans_connect_done, req);
		return req;
	}

	subreq = wb_int_trans_send(state, ev, wb_ctx->queue, wb_ctx->fd,
				   wb_req);
	if (subreq == NULL) {
		goto fail;
	}
	tevent_req_set_callback(subreq, wb_trans_done, req);
	return req;
 fail:
	TALLOC_FREE(req);
	return NULL;
}

static bool wb_trans_retry(struct tevent_req *req,
			   struct wb_trans_state *state,
			   wbcErr wbc_err)
{
	struct tevent_req *subreq;

	if (WBC_ERROR_IS_OK(wbc_err)) {
		return false;
	}

	if (wbc_err == WBC_ERR_WINBIND_NOT_AVAILABLE) {
		/*
		 * Winbind not around or we can't connect to the pipe. Fail
		 * immediately.
		 */
		tevent_req_error(req, wbc_err);
		return true;
	}

	state->num_retries -= 1;
	if (state->num_retries == 0) {
		tevent_req_error(req, wbc_err);
		return true;
	}

	/*
	 * The transfer as such failed, retry after one second
	 */

	if (state->wb_ctx->fd != -1) {
		close(state->wb_ctx->fd);
		state->wb_ctx->fd = -1;
	}

	subreq = tevent_wakeup_send(state, state->ev,
				    timeval_current_ofs(1, 0));
	if (tevent_req_nomem(subreq, req)) {
		return true;
	}
	tevent_req_set_callback(subreq, wb_trans_retry_wait_done, req);
	return true;
}

static void wb_trans_retry_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_trans_state *state = tevent_req_data(
		req, struct wb_trans_state);
	bool ret;

	ret = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_error(req, WBC_ERR_UNKNOWN_FAILURE);
		return;
	}

	subreq = wb_open_pipe_send(state, state->ev, state->wb_ctx,
				   state->need_priv);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_trans_connect_done, req);
}

static void wb_trans_connect_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_trans_state *state = tevent_req_data(
		req, struct wb_trans_state);
	wbcErr wbc_err;

	wbc_err = wb_open_pipe_recv(subreq);
	TALLOC_FREE(subreq);

	if (wb_trans_retry(req, state, wbc_err)) {
		return;
	}

	subreq = wb_int_trans_send(state, state->ev, NULL, state->wb_ctx->fd,
				   state->wb_req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, wb_trans_done, req);
}

static void wb_trans_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct wb_trans_state *state = tevent_req_data(
		req, struct wb_trans_state);
	wbcErr wbc_err;

	wbc_err = wb_int_trans_recv(subreq, state, &state->wb_resp);
	TALLOC_FREE(subreq);

	if (wb_trans_retry(req, state, wbc_err)) {
		return;
	}

	tevent_req_done(req);
}

wbcErr wb_trans_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		     struct winbindd_response **presponse)
{
	struct wb_trans_state *state = tevent_req_data(
		req, struct wb_trans_state);
	wbcErr wbc_err;

	if (tevent_req_is_wbcerr(req, &wbc_err)) {
		return wbc_err;
	}

	*presponse = talloc_move(mem_ctx, &state->wb_resp);
	return WBC_ERR_SUCCESS;
}
