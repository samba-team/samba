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
};

int pthreadpool_pipe_init(unsigned max_threads,
			  struct pthreadpool_pipe **presult)
{
	struct pthreadpool_pipe *p;
	int ret;

	p = malloc(sizeof(struct pthreadpool_pipe));
	if (p == NULL) {
		return ENOMEM;
	}

	ret = pthreadpool_init(max_threads, &p->pool);
	if (ret != 0) {
		free(p);
		return ret;
	}

	*presult = p;
	return 0;
}

int pthreadpool_pipe_destroy(struct pthreadpool_pipe *pool)
{
	int ret;

	ret = pthreadpool_destroy(pool->pool);
	if (ret != 0) {
		return ret;
	}
	free(pool);
	return 0;
}

int pthreadpool_pipe_add_job(struct pthreadpool_pipe *pool, int job_id,
			     void (*fn)(void *private_data),
			     void *private_data)
{
	int ret;
	ret = pthreadpool_add_job(pool->pool, job_id, fn, private_data);
	return ret;
}

int pthreadpool_pipe_signal_fd(struct pthreadpool_pipe *pool)
{
	int fd;
	fd = pthreadpool_signal_fd(pool->pool);
	return fd;
}

int pthreadpool_pipe_finished_jobs(struct pthreadpool_pipe *pool, int *jobids,
				   unsigned num_jobids)
{
	int ret;
	ret = pthreadpool_finished_jobs(pool->pool, jobids, num_jobids);
	return ret;
}
