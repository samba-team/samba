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

struct prefork_pool {

	int listen_fd;
	int lock_fd;

	prefork_main_fn_t *main_fn;
	void *private_data;

	int pool_size;
	struct pf_worker_data *pool;
};

int prefork_pool_destructor(struct prefork_pool *pfp)
{
	munmap(pfp->pool, pfp->pool_size * sizeof(struct pf_worker_data));
	return 0;
}

bool prefork_create_pool(struct tevent_context *ev_ctx,
			 TALLOC_CTX *mem_ctx, int listen_fd,
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
	pfp->listen_fd = listen_fd;
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
		pid = sys_fork();
		switch (pid) {
		case -1:
			DEBUG(1, ("Failed to prefork child n. %d !\n", i));
			break;

		case 0: /* THE CHILD */

			pfp->pool[i].status = PF_WORKER_IDLE;

			ret = pfp->main_fn(ev_ctx, &pfp->pool[i],
					   pfp->listen_fd, pfp->lock_fd,
					   pfp->private_data);
			exit(ret);

		default: /* THE PARENT */
			pfp->pool[i].pid = pid;
			pfp->pool[i].started = now;
			break;
		}
	}

	*pf_pool = pfp;
	return true;
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

		pid = sys_fork();
		switch (pid) {
		case -1:
			DEBUG(1, ("Failed to prefork child n. %d !\n", j));
			break;

		case 0: /* THE CHILD */

			pfp->pool[i].status = PF_WORKER_IDLE;
			ret = pfp->main_fn(ev_ctx, &pfp->pool[i],
					   pfp->listen_fd, pfp->lock_fd,
					   pfp->private_data);

			pfp->pool[i].status = PF_WORKER_EXITING;
			exit(ret);

		default: /* THE PARENT */
			pfp->pool[i].pid = pid;
			pfp->pool[i].started = now;
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

/* returns:
 * negative errno on error
 * -2 if server commands to terminate
 * 0 if all ok
 * ERRNO on other errors
 */

int prefork_wait_for_client(struct pf_worker_data *pf,
			    int lock_fd, int listen_fd,
			    struct sockaddr *addr,
			    socklen_t *addrlen, int *fd)
{
	int ret;
	int sd = -1;
	int err;

	ret = prefork_grab_lock(pf, lock_fd, -1);
	if (ret != 0) {
		return ret;
	}

	err = 0;
	do {
		sd = accept(listen_fd, addr, addrlen);

		if (sd != -1) break;

		if (errno == EINTR) {
			if (pf->cmds == PF_SRV_MSG_EXIT) {
				err = -2;
			}
		} else {
			err = errno;
		}

	} while ((sd == -1) && (err == 0));

	/* return lock now, even if the accept failed.
	 * if it takes more than 10 seconds we are in deep trouble */
	ret = prefork_release_lock(pf, lock_fd, 2);
	if (ret != 0) {
		/* we were unable to release the lock!! */
		DEBUG(0, ("Terminating due to fatal failure!\n"));

		/* Just exit we cannot hold the whole server, better to error
		 * on this one client and hope it was a transiet problem */
		err = -2;
	}

	if (err != 0) {
		if (sd != -1) {
			close(sd);
			sd = -1;
		}
		return err;
	}

	pf->status = PF_WORKER_BUSY;
	pf->num_clients++;
	*fd = sd;
	return 0;
}
