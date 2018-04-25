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


#include "replace.h"
#include "pthreadpool.h"

struct pthreadpool {
	bool stopped;

	/*
	 * Indicate job completion
	 */
	int (*signal_fn)(int jobid,
			 void (*job_fn)(void *private_data),
			 void *job_fn_private_data,
			 void *private_data);
	void *signal_fn_private_data;
};

int pthreadpool_init(unsigned max_threads, struct pthreadpool **presult,
		     int (*signal_fn)(int jobid,
				      void (*job_fn)(void *private_data),
				      void *job_fn_private_data,
				      void *private_data),
		     void *signal_fn_private_data)
{
	struct pthreadpool *pool;

	pool = (struct pthreadpool *)calloc(1, sizeof(struct pthreadpool));
	if (pool == NULL) {
		return ENOMEM;
	}
	pool->stopped = false;
	pool->signal_fn = signal_fn;
	pool->signal_fn_private_data = signal_fn_private_data;

	*presult = pool;
	return 0;
}

size_t pthreadpool_max_threads(struct pthreadpool *pool)
{
	return 0;
}

size_t pthreadpool_queued_jobs(struct pthreadpool *pool)
{
	return 0;
}

int pthreadpool_add_job(struct pthreadpool *pool, int job_id,
			void (*fn)(void *private_data), void *private_data)
{
	if (pool->stopped) {
		return EINVAL;
	}

	fn(private_data);

	return pool->signal_fn(job_id, fn, private_data,
			       pool->signal_fn_private_data);
}

size_t pthreadpool_cancel_job(struct pthreadpool *pool, int job_id,
			      void (*fn)(void *private_data), void *private_data)
{
	return 0;
}

int pthreadpool_stop(struct pthreadpool *pool)
{
	pool->stopped = true;
	return 0;
}

int pthreadpool_destroy(struct pthreadpool *pool)
{
	free(pool);
	return 0;
}
