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

struct pthreadpool_tevent;

int pthreadpool_tevent_init(TALLOC_CTX *mem_ctx, unsigned max_threads,
			    struct pthreadpool_tevent **presult);

size_t pthreadpool_tevent_max_threads(struct pthreadpool_tevent *pool);
size_t pthreadpool_tevent_queued_jobs(struct pthreadpool_tevent *pool);

struct tevent_req *pthreadpool_tevent_job_send(
	TALLOC_CTX *mem_ctx, struct tevent_context *ev,
	struct pthreadpool_tevent *pool,
	void (*fn)(void *private_data), void *private_data);

int pthreadpool_tevent_job_recv(struct tevent_req *req);

#endif
