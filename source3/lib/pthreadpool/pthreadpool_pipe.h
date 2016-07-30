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

#ifndef __PTHREADPOOL_PIPE_H__
#define __PTHREADPOOL_PIPE_H__

struct pthreadpool_pipe;

int pthreadpool_pipe_init(unsigned max_threads,
			  struct pthreadpool_pipe **presult);

int pthreadpool_pipe_destroy(struct pthreadpool_pipe *pool);

int pthreadpool_pipe_add_job(struct pthreadpool_pipe *pool, int job_id,
			     void (*fn)(void *private_data),
			     void *private_data);

int pthreadpool_pipe_signal_fd(struct pthreadpool_pipe *pool);

int pthreadpool_pipe_finished_jobs(struct pthreadpool_pipe *pool, int *jobids,
				   unsigned num_jobids);

#endif
