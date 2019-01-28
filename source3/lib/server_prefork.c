/*
   Unix SMB/CIFS implementation.
   Common server globals

   Copyright (C) Simo Sorce <idra@samba.org> 2011

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
#include "serverid.h"
#include "messages.h"
#include "system/time.h"
#include "system/shmem.h"
#include "system/filesys.h"
#include "server_prefork.h"
#include "../lib/util/samba_util.h"
#include "../lib/util/tevent_unix.h"

struct prefork_pool {
	int listen_fd_size;
	struct pf_listen_fd *listen_fds;

	prefork_main_fn_t *main_fn;
	void *private_data;

	int pool_size;
	struct pf_worker_data *pool;

	int allowed_clients;

	prefork_sigchld_fn_t *sigchld_fn;
	void *sigchld_data;
};

static bool prefork_setup_sigchld_handler(struct tevent_context *ev_ctx,
					    struct prefork_pool *pfp);

static int prefork_pool_destructor(struct prefork_pool *pfp)
{
	anonymous_shared_free(pfp->pool);
	return 0;
}

bool prefork_create_pool(TALLOC_CTX *mem_ctx,
			 struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 int listen_fd_size, struct pf_listen_fd *listen_fds,
			 int min_children, int max_children,
			 prefork_main_fn_t *main_fn, void *private_data,
			 struct prefork_pool **pf_pool)
{
	struct prefork_pool *pfp;
	pid_t pid;
	time_t now = time(NULL);
	size_t data_size;
	int ret;
	int i;
	bool ok;

	pfp = talloc_zero(mem_ctx, struct prefork_pool);
	if (!pfp) {
		DEBUG(1, ("Out of memory!\n"));
		return false;
	}
	pfp->listen_fd_size = listen_fd_size;
	pfp->listen_fds = talloc_array(pfp, struct pf_listen_fd,
				       listen_fd_size);
	if (!pfp->listen_fds) {
		DEBUG(1, ("Out of memory!\n"));
		return false;
	}
	for (i = 0; i < listen_fd_size; i++) {
		pfp->listen_fds[i] = listen_fds[i];
		/* force sockets in non-blocking mode */
		set_blocking(listen_fds[i].fd, false);
	}
	pfp->main_fn = main_fn;
	pfp->private_data = private_data;

	pfp->pool_size = max_children;
	data_size = sizeof(struct pf_worker_data) * max_children;

	pfp->pool = (struct pf_worker_data *)anonymous_shared_allocate(
		data_size);
	if (pfp->pool == NULL) {
		DEBUG(1, ("Failed to mmap memory for prefork pool!\n"));
		talloc_free(pfp);
		return false;
	}
	talloc_set_destructor(pfp, prefork_pool_destructor);

	for (i = 0; i < min_children; i++) {

		pfp->pool[i].allowed_clients = 1;
		pfp->pool[i].started = now;

		pid = fork();
		switch (pid) {
		case -1:
			DEBUG(1, ("Failed to prefork child n. %d !\n", i));
			break;

		case 0: /* THE CHILD */

			pfp->pool[i].status = PF_WORKER_ALIVE;
			ret = pfp->main_fn(ev_ctx, msg_ctx,
					   &pfp->pool[i], i + 1,
					   pfp->listen_fd_size,
					   pfp->listen_fds,
					   pfp->private_data);
			exit(ret);

		default: /* THE PARENT */
			pfp->pool[i].pid = pid;
			break;
		}
	}

	ok = prefork_setup_sigchld_handler(ev_ctx, pfp);
	if (!ok) {
		DEBUG(1, ("Failed to setup SIGCHLD Handler!\n"));
		talloc_free(pfp);
		return false;
	}

	*pf_pool = pfp;
	return true;
}

/* Provide the new max children number in new_max
 * (must be larger than current max).
 * Returns: 0 if all fine
 *	    ENOSPC if mremap fails to expand
 *	    EINVAL if new_max is invalid
 */
int prefork_expand_pool(struct prefork_pool *pfp, int new_max)
{
	struct prefork_pool *pool;
	size_t old_size;
	size_t new_size;
	int ret;

	if (new_max <= pfp->pool_size) {
		return EINVAL;
	}

	old_size = sizeof(struct pf_worker_data) * pfp->pool_size;
	new_size = sizeof(struct pf_worker_data) * new_max;

	pool = (struct prefork_pool *)anonymous_shared_resize(
		&pfp->pool, new_size, false);
	if (pool == NULL) {
		ret = errno;
		DEBUG(3, ("Failed to mremap memory (%d: %s)!\n",
			  ret, strerror(ret)));
		return ret;
	}

	memset(&pool[pfp->pool_size], 0, new_size - old_size);

	pfp->pool_size = new_max;

	return 0;
}

int prefork_add_children(struct tevent_context *ev_ctx,
			 struct messaging_context *msg_ctx,
			 struct prefork_pool *pfp,
			 int num_children)
{
	pid_t pid;
	time_t now = time(NULL);
	int ret;
	int i, j;

	for (i = 0, j = 0; i < pfp->pool_size && j < num_children; i++) {

		if (pfp->pool[i].status != PF_WORKER_NONE) {
			continue;
		}

		pfp->pool[i].allowed_clients = 1;
		pfp->pool[i].started = now;

		pid = fork();
		switch (pid) {
		case -1:
			DEBUG(1, ("Failed to prefork child n. %d !\n", j));
			break;

		case 0: /* THE CHILD */

			pfp->pool[i].status = PF_WORKER_ALIVE;
			ret = pfp->main_fn(ev_ctx, msg_ctx,
					   &pfp->pool[i], i + 1,
					   pfp->listen_fd_size,
					   pfp->listen_fds,
					   pfp->private_data);

			pfp->pool[i].status = PF_WORKER_EXITING;
			exit(ret);

		default: /* THE PARENT */
			pfp->pool[i].pid = pid;
			j++;
			break;
		}
	}

	DEBUG(5, ("Added %d children!\n", j));

	return j;
}

struct prefork_oldest {
	int num;
	time_t started;
};

/* sort in inverse order */
static int prefork_sort_oldest(const void *ap, const void *bp)
{
	const struct prefork_oldest *a = (const struct prefork_oldest *)ap;
	const struct prefork_oldest *b = (const struct prefork_oldest *)bp;

	if (a->started == b->started) {
		return 0;
	}
	if (a->started < b->started) {
		return 1;
	}
	return -1;
}

int prefork_retire_children(struct messaging_context *msg_ctx,
			    struct prefork_pool *pfp,
			    int num_children, time_t age_limit)
{
	const DATA_BLOB ping = data_blob_null;
	time_t now = time(NULL);
	struct prefork_oldest *oldest;
	int i, j;

	oldest = talloc_array(pfp, struct prefork_oldest, pfp->pool_size);
	if (!oldest) {
		return -1;
	}

	for (i = 0; i < pfp->pool_size; i++) {
		oldest[i].num = i;
		if (pfp->pool[i].status == PF_WORKER_ALIVE ||
		    pfp->pool[i].status == PF_WORKER_ACCEPTING) {
			oldest[i].started = pfp->pool[i].started;
		} else {
			oldest[i].started = now;
		}
	}

	qsort(oldest, pfp->pool_size,
		sizeof(struct prefork_oldest),
		prefork_sort_oldest);

	for (i = 0, j = 0; i < pfp->pool_size && j < num_children; i++) {
		if (((pfp->pool[i].status == PF_WORKER_ALIVE) &&
		     (pfp->pool[i].num_clients < 1)) &&
		    (pfp->pool[i].started <= age_limit)) {
			/* tell the child it's time to give up */
			DEBUG(5, ("Retiring pid %u!\n", (unsigned int)pfp->pool[i].pid));
			pfp->pool[i].cmds = PF_SRV_MSG_EXIT;
			messaging_send(msg_ctx,
					pid_to_procid(pfp->pool[i].pid),
					MSG_PREFORK_PARENT_EVENT, &ping);
			j++;
		}
	}

	return j;
}

int prefork_count_children(struct prefork_pool *pfp, int *active)
{
	int i, a, t;

	a = 0;
	t = 0;
	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].status == PF_WORKER_NONE) {
			continue;
		}

		t++;

		if ((pfp->pool[i].status == PF_WORKER_EXITING) ||
		    (pfp->pool[i].num_clients <= 0)) {
			continue;
		}

		a++;
	}

	if (active) {
		*active = a;
	}
	return t;
}

static void prefork_cleanup_loop(struct prefork_pool *pfp)
{
	int status;
	pid_t pid;
	int i;

	/* TODO: should we use a process group id wait instead of looping ? */
	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].status == PF_WORKER_NONE ||
		    pfp->pool[i].pid == 0) {
			continue;
		}

		pid = waitpid(pfp->pool[i].pid, &status, WNOHANG);
		if (pid > 0) {

			if (pfp->pool[i].status != PF_WORKER_EXITING) {
				DEBUG(3, ("Child (%d) terminated abnormally:"
					  " %d\n", (int)pid, status));
			} else {
				DEBUG(10, ("Child (%d) terminated with status:"
					   " %d\n", (int)pid, status));
			}

			/* reset all fields,
			 * this makes status = PF_WORK_NONE */
			memset(&pfp->pool[i], 0,
				sizeof(struct pf_worker_data));
		}
	}

}

int prefork_count_allowed_connections(struct prefork_pool *pfp)
{
	int c;
	int i;

	c = 0;
	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].status == PF_WORKER_NONE ||
		    pfp->pool[i].status == PF_WORKER_EXITING) {
			continue;
		}

		if (pfp->pool[i].num_clients < 0) {
			continue;
		}

		c += pfp->pool[i].allowed_clients - pfp->pool[i].num_clients;
	}

	return c;
}

void prefork_increase_allowed_clients(struct prefork_pool *pfp, int max)
{
	int i;

	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].status == PF_WORKER_NONE ||
		    pfp->pool[i].status == PF_WORKER_EXITING) {
			continue;
		}

		if (pfp->pool[i].num_clients < 0) {
			continue;
		}

		if (pfp->pool[i].allowed_clients < max) {
			pfp->pool[i].allowed_clients++;
		}
	}
}

void prefork_decrease_allowed_clients(struct prefork_pool *pfp)
{
	int i;

	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].status == PF_WORKER_NONE ||
		    pfp->pool[i].status == PF_WORKER_EXITING) {
			continue;
		}

		if (pfp->pool[i].num_clients < 0) {
			continue;
		}

		if (pfp->pool[i].allowed_clients > 1) {
			pfp->pool[i].allowed_clients--;
		}
	}
}

void prefork_reset_allowed_clients(struct prefork_pool *pfp)
{
	int i;

	for (i = 0; i < pfp->pool_size; i++) {
		pfp->pool[i].allowed_clients = 1;
	}
}

void prefork_send_signal_to_all(struct prefork_pool *pfp, int signal_num)
{
	int i;

	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].status == PF_WORKER_NONE) {
			continue;
		}

		kill(pfp->pool[i].pid, signal_num);
	}
}

void prefork_warn_active_children(struct messaging_context *msg_ctx,
				  struct prefork_pool *pfp)
{
	const DATA_BLOB ping = data_blob_null;
	int i;

	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].status == PF_WORKER_NONE) {
			continue;
		}

		messaging_send(msg_ctx,
				pid_to_procid(pfp->pool[i].pid),
				MSG_PREFORK_PARENT_EVENT, &ping);
	}
}

static void prefork_sigchld_handler(struct tevent_context *ev_ctx,
				    struct tevent_signal *se,
				    int signum, int count,
				    void *siginfo, void *pvt)
{
	struct prefork_pool *pfp;

	pfp = talloc_get_type_abort(pvt, struct prefork_pool);

	/* run the cleanup function to make sure all dead children are
	 * properly and timely retired. */
	prefork_cleanup_loop(pfp);

	if (pfp->sigchld_fn) {
		pfp->sigchld_fn(ev_ctx, pfp, pfp->sigchld_data);
	}
}

static bool prefork_setup_sigchld_handler(struct tevent_context *ev_ctx,
					  struct prefork_pool *pfp)
{
	struct tevent_signal *se;

	se = tevent_add_signal(ev_ctx, pfp, SIGCHLD, 0,
				prefork_sigchld_handler, pfp);
	if (!se) {
		DEBUG(0, ("Failed to setup SIGCHLD handler!\n"));
		return false;
	}

	return true;
}

void prefork_set_sigchld_callback(struct prefork_pool *pfp,
				  prefork_sigchld_fn_t *sigchld_fn,
				  void *private_data)
{
	pfp->sigchld_fn = sigchld_fn;
	pfp->sigchld_data = private_data;
}

/* ==== Functions used by children ==== */

struct pf_listen_state {
	struct tevent_context *ev;
	struct pf_worker_data *pf;

	int listen_fd_size;
	struct pf_listen_fd *listen_fds;

	struct pf_listen_fd accept;

	struct tsocket_address *srv_addr;
	struct tsocket_address *cli_addr;

	int error;
};

struct pf_listen_ctx {
	TALLOC_CTX *fde_ctx;
	struct tevent_req *req;
	int listen_fd;
	void *listen_fd_data;
};

static void prefork_listen_accept_handler(struct tevent_context *ev,
					  struct tevent_fd *fde,
					  uint16_t flags, void *pvt);

struct tevent_req *prefork_listen_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct pf_worker_data *pf,
					int listen_fd_size,
					struct pf_listen_fd *listen_fds)
{
	struct tevent_req *req;
	struct pf_listen_state *state;
	struct pf_listen_ctx *ctx;
	struct tevent_fd *fde;
	TALLOC_CTX *fde_ctx;
	int i;

	req = tevent_req_create(mem_ctx, &state, struct pf_listen_state);
	if (!req) {
		return NULL;
	}

	state->ev = ev;
	state->pf = pf;
	state->listen_fd_size = listen_fd_size;
	state->listen_fds = listen_fds;
	state->accept.fd = -1;
	state->accept.fd_data = NULL;
	state->error = 0;

	fde_ctx = talloc_new(state);
	if (tevent_req_nomem(fde_ctx, req)) {
		return tevent_req_post(req, ev);
	}

	/* race on accept */
	for (i = 0; i < state->listen_fd_size; i++) {
		ctx = talloc(fde_ctx, struct pf_listen_ctx);
		if (tevent_req_nomem(ctx, req)) {
			return tevent_req_post(req, ev);
		}
		ctx->fde_ctx = fde_ctx;
		ctx->req = req;
		ctx->listen_fd = state->listen_fds[i].fd;
		ctx->listen_fd_data = state->listen_fds[i].fd_data;

		fde = tevent_add_fd(state->ev, fde_ctx,
				    ctx->listen_fd, TEVENT_FD_READ,
				    prefork_listen_accept_handler, ctx);
		if (tevent_req_nomem(fde, req)) {
			return tevent_req_post(req, ev);
		}
	}

	pf->status = PF_WORKER_ACCEPTING;

	return req;
}

static void prefork_listen_accept_handler(struct tevent_context *ev,
					  struct tevent_fd *fde,
					  uint16_t flags, void *pvt)
{
	struct pf_listen_state *state;
	struct tevent_req *req;
	struct pf_listen_ctx *ctx;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int soerr = 0;
	socklen_t solen = sizeof(soerr);
	int sd = -1;
	int ret;

	ctx = talloc_get_type_abort(pvt, struct pf_listen_ctx);
	req = ctx->req;
	state = tevent_req_data(ctx->req, struct pf_listen_state);

	if ((state->pf->cmds == PF_SRV_MSG_EXIT) &&
	    (state->pf->num_clients <= 0)) {
		/* We have been asked to exit, so drop here and the next
		 * child will pick it up */
		state->pf->status = PF_WORKER_EXITING;
		state->error = EINTR;
		goto done;
	}

	/* before proceeding check that the listening fd is ok */
	ret = getsockopt(ctx->listen_fd, SOL_SOCKET, SO_ERROR, &soerr, &solen);
	if (ret == -1) {
		/* this is a fatal error, we cannot continue listening */
		state->error = EBADF;
		goto done;
	}
	if (soerr != 0) {
		/* this is a fatal error, we cannot continue listening */
		state->error = soerr;
		goto done;
	}

	ZERO_STRUCT(addr);
	addrlen = sizeof(addr);
	sd = accept(ctx->listen_fd, (struct sockaddr *)&addr, &addrlen);
	if (sd == -1) {
		state->error = errno;
		DEBUG(6, ("Accept failed! (%d, %s)\n",
			  state->error, strerror(state->error)));
		goto done;
	}
	smb_set_close_on_exec(sd);

	state->accept.fd = sd;
	state->accept.fd_data = ctx->listen_fd_data;

	ret = tsocket_address_bsd_from_sockaddr(state,
					(struct sockaddr *)(void *)&addr,
					addrlen, &state->cli_addr);
	if (ret < 0) {
		state->error = errno;
		goto done;
	}

	ZERO_STRUCT(addr);
	addrlen = sizeof(addr);
	ret = getsockname(sd, (struct sockaddr *)(void *)&addr, &addrlen);
	if (ret < 0) {
		state->error = errno;
		goto done;
	}

	ret = tsocket_address_bsd_from_sockaddr(state,
					(struct sockaddr *)(void *)&addr,
					addrlen, &state->srv_addr);
	if (ret < 0) {
		state->error = errno;
		goto done;
	}

done:
	/* do not track the listen fds anymore */
	talloc_free(ctx->fde_ctx);
	tevent_req_done(req);
}

int prefork_listen_recv(struct tevent_req *req,
			TALLOC_CTX *mem_ctx, int *fd,
			void **fd_data,
			struct tsocket_address **srv_addr,
			struct tsocket_address **cli_addr)
{
	struct pf_listen_state *state;
	int ret = 0;

	state = tevent_req_data(req, struct pf_listen_state);

	if (state->error) {
		ret = state->error;
	} else {
		if (!tevent_req_is_unix_error(req, &ret)) {
			ret = 0;
		}
	}

	if (ret) {
		if (state->accept.fd != -1) {
			close(state->accept.fd);
		}
	} else {
		*fd = state->accept.fd;
		if (fd_data != NULL) {
			*fd_data = state->accept.fd_data;
		}
		*srv_addr = talloc_move(mem_ctx, &state->srv_addr);
		*cli_addr = talloc_move(mem_ctx, &state->cli_addr);
		state->pf->num_clients++;
	}
	if (state->pf->status == PF_WORKER_ACCEPTING) {
		state->pf->status = PF_WORKER_ALIVE;
	}

	tevent_req_received(req);
	return ret;
}
