/*
 * Unix SMB/CIFS implementation.
 * sync dummy implementation of the pthreadpool API
 * Copyright (C) Volker Lendecke 2009
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <fcntl.h>
#include <sys/time.h>

#include "pthreadpool.h"

struct pthreadpool {
	/*
	 * pipe for signalling
	 */
	int sig_pipe[2];

	/*
	 * Have we sent something into the pipe that has not been
	 * retrieved yet?
	 */
	int pipe_busy;

	/*
	 * Jobids that we have not sent into the pipe yet
	 */
	size_t num_ids;
	int *ids;
};

int pthreadpool_init(unsigned max_threads, struct pthreadpool **presult)
{
	struct pthreadpool *pool;
	int ret;

	pool = (struct pthreadpool *)calloc(1, sizeof(struct pthreadpool));
	if (pool == NULL) {
		return ENOMEM;
	}
	ret = pipe(pool->sig_pipe);
	if (ret == -1) {
		int err = errno;
		free(pool);
		return err;
	}
	*presult = pool;
	return 0;
}

int pthreadpool_signal_fd(struct pthreadpool *pool)
{
	return pool->sig_pipe[0];
}

static int pthreadpool_write_to_pipe(struct pthreadpool *pool)
{
	ssize_t written;

	if (pool->pipe_busy) {
		return 0;
	}
	if (pool->num_ids == 0) {
		return 0;
	}

	written = -1;
	errno = EINTR;

	while ((written == -1) && (errno == EINTR)) {
		written = write(pool->sig_pipe[1], &pool->ids[0], sizeof(int));
	}
	if (written == -1) {
		return errno;
	}
	if (written != sizeof(int)) {
		/*
		 * If a single int only partially fits into the pipe,
		 * we can assume ourselves pretty broken
		 */
		close(pool->sig_pipe[1]);
		pool->sig_pipe[1] = -1;
		return EIO;
	}

	if (pool->num_ids > 1) {
		memmove(pool->ids, pool->ids+1, sizeof(int) * (pool->num_ids-1));
	}
	pool->num_ids -= 1;
	pool->pipe_busy = 1;
	return 0;
}

int pthreadpool_add_job(struct pthreadpool *pool, int job_id,
			void (*fn)(void *private_data), void *private_data)
{
	int *tmp;

	if (pool->sig_pipe[1] == -1) {
		return EIO;
	}

	fn(private_data);

	tmp = realloc(pool->ids, sizeof(int) * (pool->num_ids+1));
	if (tmp == NULL) {
		return ENOMEM;
	}
	pool->ids = tmp;
	pool->ids[pool->num_ids] = job_id;
	pool->num_ids += 1;

	return pthreadpool_write_to_pipe(pool);

}

int pthreadpool_finished_job(struct pthreadpool *pool, int *jobid)
{
	int ret_jobid;
	ssize_t nread;

	nread = -1;
	errno = EINTR;

	while ((nread == -1) && (errno == EINTR)) {
		nread = read(pool->sig_pipe[0], &ret_jobid, sizeof(int));
	}
	if (nread == -1) {
		return errno;
	}
	if (nread != sizeof(int)) {
		return EINVAL;
	}
	*jobid = ret_jobid;

	pool->pipe_busy = 0;
	return pthreadpool_write_to_pipe(pool);
}

int pthreadpool_destroy(struct pthreadpool *pool)
{
	if (pool->sig_pipe[0] != -1) {
		close(pool->sig_pipe[0]);
		pool->sig_pipe[0] = -1;
	}

	if (pool->sig_pipe[1] != -1) {
		close(pool->sig_pipe[1]);
		pool->sig_pipe[1] = -1;
	}
	free(pool->ids);
	free(pool);
	return 0;
}
