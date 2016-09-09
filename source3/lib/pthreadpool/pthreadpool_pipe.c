/*
 * Unix SMB/CIFS implementation.
 * threadpool implementation based on pthreads
 * Copyright (C) Volker Lendecke 2009,2011
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

#include "replace.h"
#include "system/filesys.h"
#include "pthreadpool_pipe.h"
#include "pthreadpool.h"

struct pthreadpool_pipe {
	struct pthreadpool *pool;
	int num_jobs;
	pid_t pid;
	int pipe_fds[2];
};

static int pthreadpool_pipe_signal(int jobid,
				   void (*job_fn)(void *private_data),
				   void *job_private_data,
				   void *private_data);

int pthreadpool_pipe_init(unsigned max_threads,
			  struct pthreadpool_pipe **presult)
{
	struct pthreadpool_pipe *pool;
	int ret;

	pool = calloc(1, sizeof(struct pthreadpool_pipe));
	if (pool == NULL) {
		return ENOMEM;
	}
	pool->pid = getpid();

	ret = pipe(pool->pipe_fds);
	if (ret == -1) {
		int err = errno;
		free(pool);
		return err;
	}

	ret = pthreadpool_init(max_threads, &pool->pool,
			       pthreadpool_pipe_signal, pool);
	if (ret != 0) {
		close(pool->pipe_fds[0]);
		close(pool->pipe_fds[1]);
		free(pool);
		return ret;
	}

	*presult = pool;
	return 0;
}

static int pthreadpool_pipe_signal(int jobid,
				   void (*job_fn)(void *private_data),
				   void *job_private_data,
				   void *private_data)
{
	struct pthreadpool_pipe *pool = private_data;
	ssize_t written;

	do {
		written = write(pool->pipe_fds[1], &jobid, sizeof(jobid));
	} while ((written == -1) && (errno == EINTR));

	if (written != sizeof(jobid)) {
		return errno;
	}

	return 0;
}

int pthreadpool_pipe_destroy(struct pthreadpool_pipe *pool)
{
	int ret;

	if (pool->num_jobs != 0) {
		return EBUSY;
	}

	ret = pthreadpool_destroy(pool->pool);
	if (ret != 0) {
		return ret;
	}

	close(pool->pipe_fds[0]);
	pool->pipe_fds[0] = -1;

	close(pool->pipe_fds[1]);
	pool->pipe_fds[1] = -1;

	free(pool);
	return 0;
}

static int pthreadpool_pipe_reinit(struct pthreadpool_pipe *pool)
{
	pid_t pid = getpid();
	int signal_fd;
	int ret;

	if (pid == pool->pid) {
		return 0;
	}

	signal_fd = pool->pipe_fds[0];

	close(pool->pipe_fds[0]);
	pool->pipe_fds[0] = -1;

	close(pool->pipe_fds[1]);
	pool->pipe_fds[1] = -1;

	ret = pipe(pool->pipe_fds);
	if (ret != 0) {
		return errno;
	}

	ret = dup2(pool->pipe_fds[0], signal_fd);
	if (ret != 0) {
		return errno;
	}

	pool->pipe_fds[0] = signal_fd;
	pool->num_jobs = 0;

	return 0;
}

int pthreadpool_pipe_add_job(struct pthreadpool_pipe *pool, int job_id,
			     void (*fn)(void *private_data),
			     void *private_data)
{
	int ret;

	ret = pthreadpool_pipe_reinit(pool);
	if (ret != 0) {
		return ret;
	}

	ret = pthreadpool_add_job(pool->pool, job_id, fn, private_data);
	if (ret != 0) {
		return ret;
	}

	pool->num_jobs += 1;

	return 0;
}

int pthreadpool_pipe_signal_fd(struct pthreadpool_pipe *pool)
{
	return pool->pipe_fds[0];
}

int pthreadpool_pipe_finished_jobs(struct pthreadpool_pipe *pool, int *jobids,
				   unsigned num_jobids)
{
	ssize_t to_read, nread, num_jobs;
	pid_t pid = getpid();

	if (pool->pid != pid) {
		return EINVAL;
	}

	to_read = sizeof(int) * num_jobids;

	do {
		nread = read(pool->pipe_fds[0], jobids, to_read);
	} while ((nread == -1) && (errno == EINTR));

	if (nread == -1) {
		return -errno;
	}
	if ((nread % sizeof(int)) != 0) {
		return -EINVAL;
	}

	num_jobs = nread / sizeof(int);

	if (num_jobs > pool->num_jobs) {
		return -EINVAL;
	}
	pool->num_jobs -= num_jobs;

	return num_jobs;
}
