/*
 * Unix SMB/CIFS implementation.
 * threadpool implementation based on pthreads
 * Copyright (C) Volker Lendecke 2016
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

#ifndef __PTHREADPOOL_TEVENT_H__
#define __PTHREADPOOL_TEVENT_H__

#include <tevent.h>

void pthreadpool_tevent_cleanup_orphaned_jobs(void);

struct pthreadpool_tevent;

int pthreadpool_tevent_init(TALLOC_CTX *mem_ctx, unsigned max_threads,
			    struct pthreadpool_tevent **presult);

struct pthreadpool_tevent_wrapper_ops {
	const char *name;

	bool (*before_job)(struct pthreadpool_tevent *wrap_tp,
			   void *private_state,
			   struct pthreadpool_tevent *main_tp,
			   const char *location);
	bool (*after_job)(struct pthreadpool_tevent *wrap_tp,
			  void *private_state,
			  struct pthreadpool_tevent *main_tp,
			  const char *location);
};

struct pthreadpool_tevent *_pthreadpool_tevent_wrapper_create(
				struct pthreadpool_tevent *main_tp,
				TALLOC_CTX *mem_ctx,
				const struct pthreadpool_tevent_wrapper_ops *ops,
				void *pstate,
				size_t psize,
				const char *type,
				const char *location);
#define pthreadpool_tevent_wrapper_create(main_tp, mem_ctx, ops, state, type) \
	_pthreadpool_tevent_wrapper_create(main_tp, mem_ctx, ops, \
				       state, sizeof(type), #type, __location__)

/*
 * this can only be called directly after
 * pthreadpool_tevent_wrapper_create()
 */
void pthreadpool_tevent_force_per_thread_cwd(struct pthreadpool_tevent *pool,
					     const void *private_state);

size_t pthreadpool_tevent_max_threads(struct pthreadpool_tevent *pool);
size_t pthreadpool_tevent_queued_jobs(struct pthreadpool_tevent *pool);
bool pthreadpool_tevent_per_thread_cwd(struct pthreadpool_tevent *pool);

/*
 * return true - if tevent_req_cancel() was called.
 */
bool pthreadpool_tevent_current_job_canceled(void);
/*
 * return true - if talloc_free() was called on the job request,
 * tevent_context or pthreadpool_tevent.
 */
bool pthreadpool_tevent_current_job_orphaned(void);
/*
 * return true if canceled and orphaned are both false.
 */
bool pthreadpool_tevent_current_job_continue(void);

/*
 * return true if the current job can rely on a per thread
 * current working directory.
 */
bool pthreadpool_tevent_current_job_per_thread_cwd(void);

struct tevent_req *pthreadpool_tevent_job_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct pthreadpool_tevent *pool,
	void (*fn)(void *private_data), void *private_data);

int pthreadpool_tevent_job_recv(struct tevent_req *req);

#endif
