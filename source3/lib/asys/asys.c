/*
 * Async syscalls
 * Copyright (C) Volker Lendecke 2012
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

#include "asys.h"
#include <stdlib.h>
#include <errno.h>
#include "../pthreadpool/pthreadpool.h"

struct asys_pwrite_args {
	int fildes;
	const void *buf;
	size_t nbyte;
	off_t offset;
};

struct asys_pread_args {
	int fildes;
	void *buf;
	size_t nbyte;
	off_t offset;
};

struct asys_fsync_args {
	int fildes;
};

union asys_job_args {
	struct asys_pwrite_args pwrite_args;
	struct asys_pread_args pread_args;
	struct asys_fsync_args fsync_args;
};

struct asys_job {
	void *private_data;
	union asys_job_args args;
	ssize_t ret;
	int err;
	char busy;
	char canceled;
};

struct asys_context {
	struct pthreadpool *pool;
	int pthreadpool_fd;

	unsigned num_jobs;
	struct asys_job **jobs;
};

struct asys_creds_context {
	int dummy;
};

int asys_context_init(struct asys_context **pctx, unsigned max_parallel)
{
	struct asys_context *ctx;
	int ret;

	ctx = calloc(1, sizeof(struct asys_context));
	if (ctx == NULL) {
		return ENOMEM;
	}
	ret = pthreadpool_init(max_parallel, &ctx->pool);
	if (ret != 0) {
		free(ctx);
		return ret;
	}
	ctx->pthreadpool_fd = pthreadpool_signal_fd(ctx->pool);

	*pctx = ctx;
	return 0;
}

int asys_signalfd(struct asys_context *ctx)
{
	return ctx->pthreadpool_fd;
}

int asys_context_destroy(struct asys_context *ctx)
{
	int ret;
	unsigned i;

	for (i=0; i<ctx->num_jobs; i++) {
		if (ctx->jobs[i]->busy) {
			return EBUSY;
		}
	}

	ret = pthreadpool_destroy(ctx->pool);
	if (ret != 0) {
		return ret;
	}
	for (i=0; i<ctx->num_jobs; i++) {
		free(ctx->jobs[i]);
	}
	free(ctx->jobs);
	free(ctx);
	return 0;
}

static int asys_new_job(struct asys_context *ctx, int *jobid,
			struct asys_job **pjob)
{
	struct asys_job **tmp;
	struct asys_job *job;
	unsigned i;

	for (i=0; i<ctx->num_jobs; i++) {
		job = ctx->jobs[i];
		if (!job->busy) {
			job->err = 0;
			*pjob = job;
			*jobid = i;
			return 0;
		}
	}

	if (ctx->num_jobs+1 == 0) {
		return EBUSY; 	/* overflow */
	}

	tmp = realloc(ctx->jobs, sizeof(struct asys_job *)*(ctx->num_jobs+1));
	if (tmp == NULL) {
		return ENOMEM;
	}
	ctx->jobs = tmp;

	job = calloc(1, sizeof(struct asys_job));
	if (job == NULL) {
		return ENOMEM;
	}
	ctx->jobs[ctx->num_jobs] = job;

	*jobid = ctx->num_jobs;
	*pjob = job;
	ctx->num_jobs += 1;
	return 0;
}

static void asys_pwrite_do(void *private_data);

int asys_pwrite(struct asys_context *ctx, int fildes, const void *buf,
		size_t nbyte, off_t offset, void *private_data)
{
	struct asys_job *job;
	struct asys_pwrite_args *args;
	int jobid;
	int ret;

	ret = asys_new_job(ctx, &jobid, &job);
	if (ret != 0) {
		return ret;
	}
	job->private_data = private_data;

	args = &job->args.pwrite_args;
	args->fildes = fildes;
	args->buf = buf;
	args->nbyte = nbyte;
	args->offset = offset;

	ret = pthreadpool_add_job(ctx->pool, jobid, asys_pwrite_do, job);
	if (ret != 0) {
		return ret;
	}
	job->busy = 1;

	return 0;
}

static void asys_pwrite_do(void *private_data)
{
	struct asys_job *job = (struct asys_job *)private_data;
	struct asys_pwrite_args *args = &job->args.pwrite_args;

	job->ret = pwrite(args->fildes, args->buf, args->nbyte, args->offset);
	if (job->ret == -1) {
		job->err = errno;
	}
}

static void asys_pread_do(void *private_data);

int asys_pread(struct asys_context *ctx, int fildes, void *buf,
	       size_t nbyte, off_t offset, void *private_data)
{
	struct asys_job *job;
	struct asys_pread_args *args;
	int jobid;
	int ret;

	ret = asys_new_job(ctx, &jobid, &job);
	if (ret != 0) {
		return ret;
	}
	job->private_data = private_data;

	args = &job->args.pread_args;
	args->fildes = fildes;
	args->buf = buf;
	args->nbyte = nbyte;
	args->offset = offset;

	ret = pthreadpool_add_job(ctx->pool, jobid, asys_pread_do, job);
	if (ret != 0) {
		return ret;
	}
	job->busy = 1;

	return 0;
}

static void asys_pread_do(void *private_data)
{
	struct asys_job *job = (struct asys_job *)private_data;
	struct asys_pread_args *args = &job->args.pread_args;

	job->ret = pread(args->fildes, args->buf, args->nbyte, args->offset);
	if (job->ret == -1) {
		job->err = errno;
	}
}

static void asys_fsync_do(void *private_data);

int asys_fsync(struct asys_context *ctx, int fildes, void *private_data)
{
	struct asys_job *job;
	struct asys_fsync_args *args;
	int jobid;
	int ret;

	ret = asys_new_job(ctx, &jobid, &job);
	if (ret != 0) {
		return ret;
	}
	job->private_data = private_data;

	args = &job->args.fsync_args;
	args->fildes = fildes;

	ret = pthreadpool_add_job(ctx->pool, jobid, asys_fsync_do, job);
	if (ret != 0) {
		return ret;
	}
	job->busy = 1;

	return 0;
}

static void asys_fsync_do(void *private_data)
{
	struct asys_job *job = (struct asys_job *)private_data;
	struct asys_fsync_args *args = &job->args.fsync_args;

	job->ret = fsync(args->fildes);
	if (job->ret == -1) {
		job->err = errno;
	}
}

void asys_cancel(struct asys_context *ctx, void *private_data)
{
	unsigned i;

	for (i=0; i<ctx->num_jobs; i++) {
		struct asys_job *job = ctx->jobs[i];

		if (job->private_data == private_data) {
			job->canceled = 1;
		}
	}
}

int asys_result(struct asys_context *ctx, ssize_t *pret, int *perrno,
		void *pdata)
{
	void **pprivate_data = (void **)pdata;
	struct asys_job *job;
	int ret, jobid;

	ret = pthreadpool_finished_job(ctx->pool, &jobid);
	if (ret != 0) {
		return ret;
	}
	if ((jobid < 0) || (jobid >= ctx->num_jobs)) {
		return EIO;
	}

	job = ctx->jobs[jobid];

	if (job->canceled) {
		return ECANCELED;
	}

	*pret = job->ret;
	*perrno = job->err;
	*pprivate_data = job->private_data;
	job->busy = 0;
	return 0;
}
