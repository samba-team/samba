/*
 * Unix SMB/CIFS implementation.
 * Little pthreadpool benchmark
 *
 * Copyright (C) Volker Lendecke 2014
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
#include "lib/pthreadpool/pthreadpool.h"
#include "proto.h"

extern int torture_numops;

static void null_job(void *private_data)
{
	return;
}

bool run_bench_pthreadpool(int dummy)
{
	struct pthreadpool *pool;
	int i, ret;

	ret = pthreadpool_init(1, &pool);
	if (ret != 0) {
		d_fprintf(stderr, "pthreadpool_init failed: %s\n",
			  strerror(ret));
		return false;
	}

	for (i=0; i<torture_numops; i++) {
		int jobid;

		ret = pthreadpool_add_job(pool, 0, null_job, NULL);
		if (ret != 0) {
			d_fprintf(stderr, "pthreadpool_add_job failed: %s\n",
				  strerror(ret));
			break;
		}
		ret = pthreadpool_finished_jobs(pool, &jobid, 1);
		if (ret < 0) {
			d_fprintf(stderr, "pthreadpool_finished_job failed: %s\n",
				  strerror(-ret));
			break;
		}
	}

	pthreadpool_destroy(pool);

	return (ret == 1);
}
