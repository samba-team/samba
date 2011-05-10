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
#include "system/time.h"
#include "system/shmem.h"
#include "system/filesys.h"
#include "server_prefork.h"
#include "../lib/util/util.h"
#include "../lib/util/tevent_unix.h"

struct prefork_pool {

	int listen_fd_size;
	int *listen_fds;

	int lock_fd;

	prefork_main_fn_t *main_fn;
	void *private_data;

	int pool_size;
	struct pf_worker_data *pool;

	int allowed_clients;
};

int prefork_pool_destructor(struct prefork_pool *pfp)
{
	munmap(pfp->pool, pfp->pool_size * sizeof(struct pf_worker_data));
	return 0;
}

bool prefork_create_pool(struct tevent_context *ev_ctx, TALLOC_CTX *mem_ctx,
			 int listen_fd_size, int *listen_fds,
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

	pfp = talloc(mem_ctx, struct prefork_pool);
	if (!pfp) {
		DEBUG(1, ("Out of memory!\n"));
		return false;
	}
	pfp->listen_fd_size = listen_fd_size;
	pfp->listen_fds = talloc_array(pfp, int, listen_fd_size);
	if (!pfp->listen_fds) {
		DEBUG(1, ("Out of memory!\n"));
		return false;
	}
	for (i = 0; i < listen_fd_size; i++) {
		pfp->listen_fds[i] = listen_fds[i];
	}
	pfp->main_fn = main_fn;
	pfp->private_data = private_data;

	pfp->lock_fd = create_unlink_tmp(NULL);
	if (pfp->lock_fd == -1) {
		DEBUG(1, ("Failed to create prefork lock fd!\n"));
		talloc_free(pfp);
		return false;
	}

	pfp->pool_size = max_children;
	data_size = sizeof(struct pf_worker_data) * max_children;

	pfp->pool = mmap(NULL, data_size, PROT_READ|PROT_WRITE,
			 MAP_SHARED|MAP_ANONYMOUS, -1, 0);
	if (pfp->pool == MAP_FAILED) {
		DEBUG(1, ("Failed to mmap memory for prefork pool!\n"));
		talloc_free(pfp);
		return false;
	}
	talloc_set_destructor(pfp, prefork_pool_destructor);

	for (i = 0; i < min_children; i++) {

		pfp->pool[i].allowed_clients = 1;
		pfp->pool[i].started = now;

		pid = sys_fork();
		switch (pid) {
		case -1:
			DEBUG(1, ("Failed to prefork child n. %d !\n", i));
			break;

		case 0: /* THE CHILD */

			pfp->pool[i].status = PF_WORKER_IDLE;
			ret = pfp->main_fn(ev_ctx, &pfp->pool[i],
					   pfp->listen_fd_size,
					   pfp->listen_fds,
					   pfp->lock_fd,
					   pfp->private_data);
			exit(ret);

		default: /* THE PARENT */
			pfp->pool[i].pid = pid;
			break;
		}
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
	struct pf_worker_data *pool;
	size_t old_size;
	size_t new_size;

	if (new_max <= pfp->pool_size) {
		return EINVAL;
	}

	old_size = sizeof(struct pf_worker_data) * pfp->pool_size;
	new_size = sizeof(struct pf_worker_data) * new_max;

	pool = mremap(pfp->pool, old_size, new_size, 0);
	if (pool == MAP_FAILED) {
		DEBUG(3, ("Failed to mremap memory for prefork pool!\n"));
		return ENOSPC;
	}

	memset(&pool[pfp->pool_size], 0, new_size - old_size);

	pfp->pool_size = new_max;

	return 0;
}

int prefork_add_children(struct tevent_context *ev_ctx,
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

		pid = sys_fork();
		switch (pid) {
		case -1:
			DEBUG(1, ("Failed to prefork child n. %d !\n", j));
			break;

		case 0: /* THE CHILD */

			pfp->pool[i].status = PF_WORKER_IDLE;
			ret = pfp->main_fn(ev_ctx, &pfp->pool[i],
					   pfp->listen_fd_size,
					   pfp->listen_fds,
					   pfp->lock_fd,
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
	struct prefork_oldest *a = (struct prefork_oldest *)ap;
	struct prefork_oldest *b = (struct prefork_oldest *)bp;

	if (a->started == b->started) {
		return 0;
	}
	if (a->started < b->started) {
		return 1;
	}
	return -1;
}

int prefork_retire_children(struct prefork_pool *pfp,
			    int num_children, time_t age_limit)
{
	time_t now = time(NULL);
	struct prefork_oldest *oldest;
	int i, j;

	oldest = talloc_array(pfp, struct prefork_oldest, pfp->pool_size);
	if (!oldest) {
		return -1;
	}

	for (i = 0; i < pfp->pool_size; i++) {
		oldest[i].num = i;
		if (pfp->pool[i].status == PF_WORKER_IDLE) {
			oldest[i].started = pfp->pool[i].started;
		} else {
			oldest[i].started = now;
		}
	}

	qsort(oldest, pfp->pool_size,
		sizeof(struct prefork_oldest),
		prefork_sort_oldest);

	for (i = 0, j = 0; i < pfp->pool_size && j < num_children; i++) {
		if (pfp->pool[i].status == PF_WORKER_IDLE &&
		    pfp->pool[i].started <= age_limit) {
			/* tell the child it's time to give up */
			DEBUG(5, ("Retiring pid %d!\n", pfp->pool[i].pid));
			pfp->pool[i].cmds = PF_SRV_MSG_EXIT;
			kill(pfp->pool[i].pid, SIGHUP);
			j++;
		}
	}

	return j;
}

int prefork_count_active_children(struct prefork_pool *pfp, int *total)
{
	int i, a, t;

	a = 0;
	t = 0;
	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].status == PF_WORKER_NONE) {
			continue;
		}

		t++;

		if (pfp->pool[i].num_clients == 0) {
			continue;
		}

		a++;
	}

	*total = t;
	return a;
}

/* to be used to finally mark a children as dead, so that it's slot can
 * be reused */
bool prefork_mark_pid_dead(struct prefork_pool *pfp, pid_t pid)
{
	int i;

	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].pid == pid) {
			if (pfp->pool[i].status != PF_WORKER_EXITING) {
				DEBUG(2, ("pid %d terminated abnormally!\n",
					  (int)pid));
			}

			/* reset all fields,
			 * this makes status = PF_WORK_NONE */
			memset(&pfp->pool[i], 0,
				sizeof(struct pf_worker_data));

			return true;
		}
	}

	return false;
}

void prefork_increase_allowed_clients(struct prefork_pool *pfp, int max)
{
	int i;

	for (i = 0; i < pfp->pool_size; i++) {
		if (pfp->pool[i].status == PF_WORKER_NONE) {
			continue;
		}

		if (pfp->pool[i].allowed_clients < max) {
			pfp->pool[i].allowed_clients++;
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


/* ==== Functions used by children ==== */

static SIG_ATOMIC_T pf_alarm;

static void pf_alarm_cb(int signum)
{
	pf_alarm = 1;
}


/*
 * Parameters:
 * pf - the worker shared data structure
 * lock_fd - the file descriptor used for locking
 * timeout - expressed in seconds:
 *		-1 never timeouts,
 *		0 timeouts immediately
 *		N seconds before timing out
 *
 * Returns values:
 * negative errno on fatal error
 * 0 on success to acquire lock
 * -1 on timeout/lock held by other
 * -2 on server msg to terminate
 * ERRNO on other errors
 */

static int prefork_grab_lock(struct pf_worker_data *pf,
			     int lock_fd, int timeout)
{
	struct flock lock;
	int op;
	int ret;

	if (pf->cmds == PF_SRV_MSG_EXIT) {
		return -2;
	}

	pf_alarm = 0;

	if (timeout > 0) {
		CatchSignal(SIGALRM, pf_alarm_cb);
		alarm(timeout);
	}

	if (timeout == 0) {
		op = F_SETLK;
	} else {
		op = F_SETLKW;
	}

	ret = 0;
	do {
		ZERO_STRUCT(lock);
		lock.l_type = F_WRLCK;
		lock.l_whence = SEEK_SET;

		ret = fcntl(lock_fd, op, &lock);
		if (ret == 0) break;

		ret = errno;

		if (pf->cmds == PF_SRV_MSG_EXIT) {
			ret = -2;
			goto done;
		}

		switch (ret) {
		case EINTR:
			break;

		case EACCES:
		case EAGAIN:
			/* lock held by other proc */
			ret = -1;
			goto done;
		default:
			goto done;
		}

		if (pf_alarm == 1) {
			/* timed out */
			ret = -1;
			goto done;
		}
	} while (timeout != 0);

	if (ret != 0) {
		/* We have the Lock */
		pf->status = PF_WORKER_ACCEPTING;
	}

done:
	if (timeout > 0) {
		alarm(0);
		CatchSignal(SIGALRM, SIG_IGN);
	}

	if (ret > 0) {
		DEBUG(1, ("Failed to get lock (%d, %s)!\n",
			  ret, strerror(ret)));
	}
	return ret;
}

/*
 * Parameters:
 * pf - the worker shared data structure
 * lock_fd - the file descriptor used for locking
 * timeout - expressed in seconds:
 *		-1 never timeouts,
 *		0 timeouts immediately
 *		N seconds before timing out
 *
 * Returns values:
 * negative errno on fatal error
 * 0 on success to release lock
 * -1 on timeout
 * ERRNO on error
 */

static int prefork_release_lock(struct pf_worker_data *pf,
				int lock_fd, int timeout)
{
	struct flock lock;
	int op;
	int ret;

	pf_alarm = 0;

	if (timeout > 0) {
		CatchSignal(SIGALRM, pf_alarm_cb);
		alarm(timeout);
	}

	if (timeout == 0) {
		op = F_SETLK;
	} else {
		op = F_SETLKW;
	}

	do {
		ZERO_STRUCT(lock);
		lock.l_type = F_UNLCK;
		lock.l_whence = SEEK_SET;

		ret = fcntl(lock_fd, op, &lock);
		if (ret == 0) break;

		ret = errno;

		if (ret != EINTR) {
			goto done;
		}

		if (pf_alarm == 1) {
			/* timed out */
			ret = -1;
			goto done;
		}
	} while (timeout != 0);

done:
	if (timeout > 0) {
		alarm(0);
		CatchSignal(SIGALRM, SIG_IGN);
	}

	if (ret > 0) {
		DEBUG(1, ("Failed to release lock (%d, %s)!\n",
			  ret, strerror(ret)));
	}
	return ret;
}

/* ==== async code ==== */

#define PF_ASYNC_LOCK_GRAB	0x01
#define PF_ASYNC_LOCK_RELEASE	0x02
#define PF_ASYNC_ACTION_MASK	0x03
#define PF_ASYNC_LOCK_DONE	0x04

struct pf_lock_state {
	struct pf_worker_data *pf;
	int lock_fd;
	int flags;
};

static void prefork_lock_handler(struct tevent_context *ev,
					struct tevent_timer *te,
					struct timeval curtime, void *pvt);

static struct tevent_req *prefork_lock_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						struct pf_worker_data *pf,
						int lock_fd, int action)
{
	struct tevent_req *req;
	struct pf_lock_state *state;

	req = tevent_req_create(mem_ctx, &state, struct pf_lock_state);
	if (!req) {
		return NULL;
	}

	state->pf = pf;
	state->lock_fd = lock_fd;
	state->flags = action;

	/* try once immediately */
	prefork_lock_handler(ev, NULL, tevent_timeval_zero(), req);
	if (state->flags & PF_ASYNC_LOCK_DONE) {
		tevent_req_post(req, ev);
	}

	return req;
}

static void prefork_lock_handler(struct tevent_context *ev,
				 struct tevent_timer *te,
				 struct timeval curtime, void *pvt)
{
	struct tevent_req *req;
	struct pf_lock_state *state;
	struct timeval tv;
	int timeout = 0;
	int ret;

	req = talloc_get_type_abort(pvt, struct tevent_req);
	state = tevent_req_data(req, struct pf_lock_state);

	if (state->pf->num_clients > 0) {
		timeout = 1;
	}

	switch (state->flags & PF_ASYNC_ACTION_MASK) {
	case PF_ASYNC_LOCK_GRAB:
		ret = prefork_grab_lock(state->pf, state->lock_fd, timeout);
		break;
	case PF_ASYNC_LOCK_RELEASE:
		ret = prefork_release_lock(state->pf, state->lock_fd, timeout);
		break;
	default:
		ret = EINVAL;
		break;
	}

	switch (ret) {
	case 0:
		state->flags |= PF_ASYNC_LOCK_DONE;
		tevent_req_done(req);
		return;
	case -1:
		if (timeout) {
			tv = tevent_timeval_zero();
		} else {
			tv = tevent_timeval_current_ofs(0, 100000);
		}
		te = tevent_add_timer(ev, state, tv,
					prefork_lock_handler, req);
		tevent_req_nomem(te, req);
		return;
	case -2:
		/* server tells us to stop */
		state->flags |= PF_ASYNC_LOCK_DONE;
		tevent_req_error(req, -2);
		return;
	default:
		state->flags |= PF_ASYNC_LOCK_DONE;
		tevent_req_error(req, ret);
		return;
	}
}

static int prefork_lock_recv(struct tevent_req *req)
{
	int ret;

	if (!tevent_req_is_unix_error(req, &ret)) {
		ret = 0;
	}

	tevent_req_received(req);
	return ret;
}

struct pf_listen_state {
	struct tevent_context *ev;
	struct pf_worker_data *pf;

	int listen_fd_size;
	int *listen_fds;

	int lock_fd;

	struct sockaddr *addr;
	socklen_t *addrlen;

	int accept_fd;

	int error;
};

static void prefork_listen_lock_done(struct tevent_req *subreq);
static void prefork_listen_accept_handler(struct tevent_context *ev,
					  struct tevent_fd *fde,
					  uint16_t flags, void *pvt);
static void prefork_listen_release_done(struct tevent_req *subreq);

struct tevent_req *prefork_listen_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct pf_worker_data *pf,
					int listen_fd_size,
					int *listen_fds,
					int lock_fd,
					struct sockaddr *addr,
					socklen_t *addrlen)
{
	struct tevent_req *req, *subreq;
	struct pf_listen_state *state;

	req = tevent_req_create(mem_ctx, &state, struct pf_listen_state);
	if (!req) {
		return NULL;
	}

	state->ev = ev;
	state->pf = pf;
	state->lock_fd = lock_fd;
	state->listen_fd_size = listen_fd_size;
	state->listen_fds = listen_fds;
	state->addr = addr;
	state->addrlen = addrlen;
	state->accept_fd = -1;
	state->error = 0;

	subreq = prefork_lock_send(state, state->ev, state->pf,
				   state->lock_fd, PF_ASYNC_LOCK_GRAB);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, prefork_listen_lock_done, req);
	return req;
}

struct pf_listen_ctx {
	TALLOC_CTX *fde_ctx;
	struct tevent_req *req;
	int listen_fd;
};

static void prefork_listen_lock_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	struct pf_listen_state *state;
	struct pf_listen_ctx *ctx;
	struct tevent_fd *fde;
	TALLOC_CTX *fde_ctx;
	int ret;
	int i;

	req = tevent_req_callback_data(subreq, struct tevent_req);
	state = tevent_req_data(req, struct pf_listen_state);

	ret = prefork_lock_recv(subreq);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	fde_ctx = talloc_new(state);
	if (tevent_req_nomem(fde_ctx, req)) {
		return;
	}

	/* next step, accept */
	for (i = 0; i < state->listen_fd_size; i++) {
		ctx = talloc(fde_ctx, struct pf_listen_ctx);
		if (tevent_req_nomem(ctx, req)) {
			return;
		}
		ctx->fde_ctx = fde_ctx;
		ctx->req = req;
		ctx->listen_fd = state->listen_fds[i];

		fde = tevent_add_fd(state->ev, fde_ctx,
				    ctx->listen_fd, TEVENT_FD_READ,
				    prefork_listen_accept_handler, ctx);
		if (tevent_req_nomem(fde, req)) {
			return;
		}
	}
}

static void prefork_listen_accept_handler(struct tevent_context *ev,
					  struct tevent_fd *fde,
					  uint16_t flags, void *pvt)
{
	struct pf_listen_state *state;
	struct tevent_req *req, *subreq;
	struct pf_listen_ctx *ctx;
	int err = 0;
	int sd = -1;

	ctx = talloc_get_type_abort(pvt, struct pf_listen_ctx);
	state = tevent_req_data(ctx->req, struct pf_listen_state);

	sd = accept(ctx->listen_fd, state->addr, state->addrlen);
	if (sd == -1) {
		if (errno == EINTR) {
			/* keep trying */
			return;
		}
		err = errno;
		DEBUG(6, ("Accept failed! (%d, %s)\n", err, strerror(err)));

	}

	/* do not track the listen fds anymore */
	req = ctx->req;
	talloc_free(ctx->fde_ctx);
	ctx = NULL;
	if (err) {
		tevent_req_error(req, err);
		return;
	}

	state->accept_fd = sd;

	/* release lock now */
	subreq = prefork_lock_send(state, state->ev, state->pf,
				   state->lock_fd, PF_ASYNC_LOCK_RELEASE);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, prefork_listen_release_done, req);
}

static void prefork_listen_release_done(struct tevent_req *subreq)
{
	struct tevent_req *req;
	int ret;

	req = tevent_req_callback_data(subreq, struct tevent_req);

	ret = prefork_lock_recv(subreq);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

int prefork_listen_recv(struct tevent_req *req, int *fd)
{
	struct pf_listen_state *state;
	int ret;

	state = tevent_req_data(req, struct pf_listen_state);

	if (tevent_req_is_unix_error(req, &ret)) {
		if (state->accept_fd != -1) {
			close(state->accept_fd);
		}
	} else {
		*fd = state->accept_fd;
		ret = 0;
		state->pf->status = PF_WORKER_BUSY;
		state->pf->num_clients++;
	}

	tevent_req_received(req);
	return ret;
}
