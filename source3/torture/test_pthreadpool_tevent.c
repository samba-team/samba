/*
 * Unix SMB/CIFS implementation.
 * Test pthreadpool_tevent
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

#include "includes.h"
#include "system/select.h"
#include "proto.h"
#include "lib/pthreadpool/pthreadpool_tevent.h"

static void job_fn(void *private_data);

bool run_pthreadpool_tevent(int dummy)
{
	struct tevent_context *ev;
	struct pthreadpool_tevent *pool;
	struct tevent_req *req;
	int ret, val;
	bool ok;

	ev = tevent_context_init_byname(NULL, "poll");
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		return false;
	}

	ret = pthreadpool_tevent_init(ev, 100, &pool);
	if (ret != 0) {
		fprintf(stderr, "pthreadpool_tevent_init failed: %s\n",
			strerror(ret));
		return false;
	}

	val = -1;

	req = pthreadpool_tevent_job_send(ev, ev, pool, job_fn, &val);
	if (req == NULL) {
		fprintf(stderr, "pthreadpool_tevent_job_send failed\n");
		return false;
	}

	ok = tevent_req_poll(req, ev);
	if (!ok) {
		fprintf(stderr, "tevent_req_poll failed\n");
		return false;
	}

	ret = pthreadpool_tevent_job_recv(req);
	if (ret != 0) {
		fprintf(stderr, "pthreadpool_tevent_job failed: %s\n",
			strerror(ret));
		return false;
	}

	printf("%d\n", val);

	TALLOC_FREE(pool);
	TALLOC_FREE(ev);
	return true;
}

static void job_fn(void *private_data)
{
	int *pret = private_data;
	*pret = 4711;

	poll(NULL, 0, 100);
}
