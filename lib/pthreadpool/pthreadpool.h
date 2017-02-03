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

#ifndef __PTHREADPOOL_H__
#define __PTHREADPOOL_H__

struct pthreadpool;

/**
 * @defgroup pthreadpool The pthreadpool API
 *
 * This API provides a way to run threadsafe functions in a helper
 * thread. It is initially intended to run getaddrinfo asynchronously.
 */


/**
 * @brief Create a pthreadpool
 *
 * A struct pthreadpool is the basis for for running threads in the
 * background.
 *
 * @param[in]	max_threads	Maximum parallelism in this pool
 * @param[out]	presult		Pointer to the threadpool returned
 * @return			success: 0, failure: errno
 *
 * max_threads=0 means unlimited parallelism. The caller has to take
 * care to not overload the system.
 */
int pthreadpool_init(unsigned max_threads, struct pthreadpool **presult,
		     int (*signal_fn)(int jobid,
				      void (*job_fn)(void *private_data),
				      void *job_fn_private_data,
				      void *private_data),
		     void *signal_fn_private_data);

/**
 * @brief Destroy a pthreadpool
 *
 * Destroy a pthreadpool. If jobs are submitted, but not yet active in
 * a thread, they won't get executed. If a job has already been
 * submitted to a thread, the job function will continue running, and
 * the signal function might still be called. The caller of
 * pthreadpool_init must make sure the required resources are still
 * around when the pool is destroyed with pending jobs.  The last
 * thread to exit will finally free() the pool memory.
 *
 * @param[in]	pool		The pool to destroy
 * @return			success: 0, failure: errno
 */
int pthreadpool_destroy(struct pthreadpool *pool);

/**
 * @brief Add a job to a pthreadpool
 *
 * This adds a job to a pthreadpool. The job can be identified by
 * job_id. This integer will be passed to signal_fn() when the
 * job is completed.
 *
 * @param[in]	pool		The pool to run the job on
 * @param[in]	job_id		A custom identifier
 * @param[in]	fn		The function to run asynchronously
 * @param[in]	private_data	Pointer passed to fn
 * @return			success: 0, failure: errno
 */
int pthreadpool_add_job(struct pthreadpool *pool, int job_id,
			void (*fn)(void *private_data), void *private_data);

#endif
