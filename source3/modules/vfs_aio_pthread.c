/*
 * Simulate Posix AIO using pthreads.
 *
 * Based on the aio_fork work from Volker and Volker's pthreadpool library.
 *
 * Copyright (C) Volker Lendecke 2008
 * Copyright (C) Jeremy Allison 2012
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"
#include "system/filesys.h"
#include "system/shmem.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/pthreadpool/pthreadpool.h"

struct aio_extra;
static struct pthreadpool *pool;
static int aio_pthread_jobid;

struct aio_private_data {
	struct aio_private_data *prev, *next;
	int jobid;
	SMB_STRUCT_AIOCB *aiocb;
	ssize_t ret_size;
	int ret_errno;
	bool cancelled;
	bool write_command;
	bool flush_write;
};

/* List of outstanding requests we have. */
static struct aio_private_data *pd_list;

static void aio_pthread_handle_completion(struct event_context *event_ctx,
				struct fd_event *event,
				uint16 flags,
				void *p);


/************************************************************************
 Ensure thread pool is initialized.
***********************************************************************/

static bool init_aio_threadpool(struct event_context *ev_ctx,
				struct pthreadpool **pp_pool,
				void (*completion_fn)(struct event_context *,
						struct fd_event *,
						uint16,
						void *))
{
	struct fd_event *sock_event = NULL;
	int ret = 0;

	if (*pp_pool) {
		return true;
	}

	ret = pthreadpool_init(aio_pending_size, pp_pool);
	if (ret) {
		errno = ret;
		return false;
	}
	sock_event = tevent_add_fd(ev_ctx,
				NULL,
				pthreadpool_signal_fd(*pp_pool),
				TEVENT_FD_READ,
				completion_fn,
				NULL);
	if (sock_event == NULL) {
		pthreadpool_destroy(*pp_pool);
		*pp_pool = NULL;
		return false;
	}

	DEBUG(10,("init_aio_threadpool: initialized with up to %d threads\n",
		  aio_pending_size));

	return true;
}


/************************************************************************
 Worker function - core of the pthread aio engine.
 This is the function that actually does the IO.
***********************************************************************/

static void aio_worker(void *private_data)
{
	struct aio_private_data *pd =
			(struct aio_private_data *)private_data;

	if (pd->write_command) {
		pd->ret_size = sys_pwrite(pd->aiocb->aio_fildes,
				(const void *)pd->aiocb->aio_buf,
				pd->aiocb->aio_nbytes,
				pd->aiocb->aio_offset);
		if (pd->ret_size == -1 && errno == ESPIPE) {
			/* Maintain the fiction that pipes can
			   be seeked (sought?) on. */
			pd->ret_size = sys_write(pd->aiocb->aio_fildes,
					(const void *)pd->aiocb->aio_buf,
					pd->aiocb->aio_nbytes);
		}
		if (pd->ret_size != -1 && pd->flush_write) {
			/*
			 * Optimization - flush if requested.
			 * Ignore error as upper layer will
			 * also do this.
			 */
			(void)fsync(pd->aiocb->aio_fildes);
		}
	} else {
		pd->ret_size = sys_pread(pd->aiocb->aio_fildes,
				(void *)pd->aiocb->aio_buf,
				pd->aiocb->aio_nbytes,
				pd->aiocb->aio_offset);
		if (pd->ret_size == -1 && errno == ESPIPE) {
			/* Maintain the fiction that pipes can
			   be seeked (sought?) on. */
			pd->ret_size = sys_read(pd->aiocb->aio_fildes,
					(void *)pd->aiocb->aio_buf,
					pd->aiocb->aio_nbytes);
		}
	}
	if (pd->ret_size == -1) {
		pd->ret_errno = errno;
	} else {
		pd->ret_errno = 0;
	}
}

/************************************************************************
 Private data destructor.
***********************************************************************/

static int pd_destructor(struct aio_private_data *pd)
{
	DLIST_REMOVE(pd_list, pd);
	return 0;
}

/************************************************************************
 Create and initialize a private data struct.
***********************************************************************/

static struct aio_private_data *create_private_data(TALLOC_CTX *ctx,
					SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd = talloc_zero(ctx, struct aio_private_data);
	if (!pd) {
		return NULL;
	}
	pd->jobid = aio_pthread_jobid++;
	pd->aiocb = aiocb;
	pd->ret_size = -1;
	pd->ret_errno = EINPROGRESS;
	talloc_set_destructor(pd, pd_destructor);
	DLIST_ADD_END(pd_list, pd, struct aio_private_data *);
	return pd;
}

/************************************************************************
 Spin off a threadpool (if needed) and initiate a pread call.
***********************************************************************/

static int aio_pthread_read(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_extra *aio_ex = (struct aio_extra *)aiocb->aio_sigevent.sigev_value.sival_ptr;
	struct aio_private_data *pd = NULL;
	int ret;

	if (!init_aio_threadpool(handle->conn->sconn->ev_ctx,
				&pool,
				aio_pthread_handle_completion)) {
		return -1;
	}

	pd = create_private_data(aio_ex, aiocb);
	if (pd == NULL) {
		DEBUG(10, ("aio_pthread_read: Could not create private data.\n"));
		return -1;
	}

	ret = pthreadpool_add_job(pool, pd->jobid, aio_worker, (void *)pd);
	if (ret) {
		errno = ret;
		return -1;
	}

	DEBUG(10, ("aio_pthread_read: jobid=%d pread requested "
		"of %llu bytes at offset %llu\n",
		pd->jobid,
		(unsigned long long)pd->aiocb->aio_nbytes,
		(unsigned long long)pd->aiocb->aio_offset));

	return 0;
}

/************************************************************************
 Spin off a threadpool (if needed) and initiate a pwrite call.
***********************************************************************/

static int aio_pthread_write(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_extra *aio_ex = (struct aio_extra *)aiocb->aio_sigevent.sigev_value.sival_ptr;
	struct aio_private_data *pd = NULL;
	int ret;

	if (!init_aio_threadpool(handle->conn->sconn->ev_ctx,
				&pool,
				aio_pthread_handle_completion)) {
		return -1;
	}

	pd = create_private_data(aio_ex, aiocb);
	if (pd == NULL) {
		DEBUG(10, ("aio_pthread_write: Could not create private data.\n"));
		return -1;
	}

	pd->write_command = true;
	if (lp_strict_sync(SNUM(fsp->conn)) &&
			(lp_syncalways(SNUM(fsp->conn)) ||
				aio_write_through_requested(aio_ex))) {
		pd->flush_write = true;
	}


	ret = pthreadpool_add_job(pool, pd->jobid, aio_worker, (void *)pd);
	if (ret) {
		errno = ret;
		return -1;
	}

	DEBUG(10, ("aio_pthread_write: jobid=%d pwrite requested "
		"of %llu bytes at offset %llu\n",
		pd->jobid,
		(unsigned long long)pd->aiocb->aio_nbytes,
		(unsigned long long)pd->aiocb->aio_offset));

	return 0;
}

/************************************************************************
 Find the private data by jobid.
***********************************************************************/

static struct aio_private_data *find_private_data_by_jobid(int jobid)
{
	struct aio_private_data *pd;

	for (pd = pd_list; pd != NULL; pd = pd->next) {
		if (pd->jobid == jobid) {
			return pd;
		}
	}

	return NULL;
}

/************************************************************************
 Callback when an IO completes.
***********************************************************************/

static void aio_pthread_handle_completion(struct event_context *event_ctx,
				struct fd_event *event,
				uint16 flags,
				void *p)
{
	struct aio_extra *aio_ex = NULL;
	struct aio_private_data *pd = NULL;
	int jobid = 0;
	int ret;

	DEBUG(10, ("aio_pthread_handle_completion called with flags=%d\n",
			(int)flags));

	if ((flags & EVENT_FD_READ) == 0) {
		return;
	}

	ret = pthreadpool_finished_job(pool, &jobid);
	if (ret) {
		smb_panic("aio_pthread_handle_completion");
		return;
	}

	pd = find_private_data_by_jobid(jobid);
	if (pd == NULL) {
		DEBUG(1, ("aio_pthread_handle_completion cannot find jobid %d\n",
			  jobid));
		return;
	}

	aio_ex = (struct aio_extra *)pd->aiocb->aio_sigevent.sigev_value.sival_ptr;
	smbd_aio_complete_aio_ex(aio_ex);

	DEBUG(10,("aio_pthread_handle_completion: jobid %d completed\n",
		jobid ));
	TALLOC_FREE(aio_ex);
}

/************************************************************************
 Find the private data by aiocb.
***********************************************************************/

static struct aio_private_data *find_private_data_by_aiocb(SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd;

	for (pd = pd_list; pd != NULL; pd = pd->next) {
		if (pd->aiocb == aiocb) {
			return pd;
		}
	}

	return NULL;
}

/************************************************************************
 Called to return the result of a completed AIO.
 Should only be called if aio_error returns something other than EINPROGRESS.
 Returns:
	Any other value - return from IO operation.
***********************************************************************/

static ssize_t aio_pthread_return_fn(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd = find_private_data_by_aiocb(aiocb);

	if (pd == NULL) {
		errno = EINVAL;
		DEBUG(0, ("aio_pthread_return_fn: returning EINVAL\n"));
		return -1;
	}

	pd->aiocb = NULL;

	if (pd->cancelled) {
		errno = ECANCELED;
		return -1;
	}

	if (pd->ret_size == -1) {
		errno = pd->ret_errno;
	}

	return pd->ret_size;
}

/************************************************************************
 Called to check the result of an AIO.
 Returns:
	EINPROGRESS - still in progress.
	EINVAL - invalid aiocb.
	ECANCELED - request was cancelled.
	0 - request completed successfully.
	Any other value - errno from IO operation.
***********************************************************************/

static int aio_pthread_error_fn(struct vfs_handle_struct *handle,
			     struct files_struct *fsp,
			     SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd = find_private_data_by_aiocb(aiocb);

	if (pd == NULL) {
		return EINVAL;
	}
	if (pd->cancelled) {
		return ECANCELED;
	}
	return pd->ret_errno;
}

/************************************************************************
 Called to request the cancel of an AIO, or all of them on a specific
 fsp if aiocb == NULL.
***********************************************************************/

static int aio_pthread_cancel(struct vfs_handle_struct *handle,
			struct files_struct *fsp,
			SMB_STRUCT_AIOCB *aiocb)
{
	struct aio_private_data *pd = NULL;

	for (pd = pd_list; pd != NULL; pd = pd->next) {
		if (pd->aiocb == NULL) {
			continue;
		}
		if (pd->aiocb->aio_fildes != fsp->fh->fd) {
			continue;
		}
		if ((aiocb != NULL) && (pd->aiocb != aiocb)) {
			continue;
		}

		/*
		 * We let the child do its job, but we discard the result when
		 * it's finished.
		 */

		pd->cancelled = true;
	}

	return AIO_CANCELED;
}

/************************************************************************
 Callback for a previously detected job completion.
***********************************************************************/

static void aio_pthread_handle_immediate(struct tevent_context *ctx,
				struct tevent_immediate *im,
				void *private_data)
{
	struct aio_extra *aio_ex = NULL;
	struct aio_private_data *pd = (struct aio_private_data *)private_data;

	aio_ex = (struct aio_extra *)pd->aiocb->aio_sigevent.sigev_value.sival_ptr;
	smbd_aio_complete_aio_ex(aio_ex);
	TALLOC_FREE(aio_ex);
}

/************************************************************************
 Private data struct used in suspend completion code.
***********************************************************************/

struct suspend_private {
	int num_entries;
	int num_finished;
	const SMB_STRUCT_AIOCB * const *aiocb_array;
};

/************************************************************************
 Callback when an IO completes from a suspend call.
***********************************************************************/

static void aio_pthread_handle_suspend_completion(struct event_context *event_ctx,
				struct fd_event *event,
				uint16 flags,
				void *p)
{
	struct suspend_private *sp = (struct suspend_private *)p;
	struct aio_private_data *pd = NULL;
	struct tevent_immediate *im = NULL;
	int jobid;
	int i;

	DEBUG(10, ("aio_pthread_handle_suspend_completion called with flags=%d\n",
			(int)flags));

	if ((flags & EVENT_FD_READ) == 0) {
		return;
	}

	if (pthreadpool_finished_job(pool, &jobid)) {
		smb_panic("aio_pthread_handle_suspend_completion: can't find job.");
		return;
	}

	pd = find_private_data_by_jobid(jobid);
	if (pd == NULL) {
		DEBUG(1, ("aio_pthread_handle_completion cannot find jobid %d\n",
			  jobid));
		return;
	}

	/* Is this a jobid with an aiocb we're interested in ? */
	for (i = 0; i < sp->num_entries; i++) {
		if (sp->aiocb_array[i] == pd->aiocb) {
			sp->num_finished++;
			return;
		}
	}

	/* Jobid completed we weren't waiting for.
	   We must reschedule this as an immediate event
	   on the main event context. */
	im = tevent_create_immediate(NULL);
	if (!im) {
		exit_server_cleanly("aio_pthread_handle_suspend_completion: no memory");
	}

	DEBUG(10,("aio_pthread_handle_suspend_completion: "
			"re-scheduling job id %d\n",
			jobid));

	tevent_schedule_immediate(im,
			server_event_context(),
			aio_pthread_handle_immediate,
			(void *)pd);
}


static void aio_pthread_suspend_timed_out(struct tevent_context *event_ctx,
					struct tevent_timer *te,
					struct timeval now,
					void *private_data)
{
	bool *timed_out = (bool *)private_data;
	/* Remove this timed event handler. */
	TALLOC_FREE(te);
	*timed_out = true;
}

/************************************************************************
 Called to request everything to stop until all IO is completed.
***********************************************************************/

static int aio_pthread_suspend(struct vfs_handle_struct *handle,
			struct files_struct *fsp,
			const SMB_STRUCT_AIOCB * const aiocb_array[],
			int n,
			const struct timespec *timeout)
{
	struct event_context *ev = NULL;
	struct fd_event *sock_event = NULL;
	int ret = -1;
	struct suspend_private sp;
	bool timed_out = false;
	TALLOC_CTX *frame = talloc_stackframe();

	/* This is a blocking call, and has to use a sub-event loop. */
	ev = event_context_init(frame);
	if (ev == NULL) {
		errno = ENOMEM;
		goto out;
	}

	if (timeout) {
		struct timeval tv = convert_timespec_to_timeval(*timeout);
		struct tevent_timer *te = tevent_add_timer(ev,
						frame,
						timeval_current_ofs(tv.tv_sec,
								    tv.tv_usec),
						aio_pthread_suspend_timed_out,
						&timed_out);
		if (!te) {
			errno = ENOMEM;
			goto out;
		}
	}

	ZERO_STRUCT(sp);
	sp.num_entries = n;
	sp.aiocb_array = aiocb_array;
	sp.num_finished = 0;

	sock_event = tevent_add_fd(ev,
				frame,
				pthreadpool_signal_fd(pool),
				TEVENT_FD_READ,
				aio_pthread_handle_suspend_completion,
				(void *)&sp);
	if (sock_event == NULL) {
		pthreadpool_destroy(pool);
		pool = NULL;
		goto out;
	}
	/*
	 * We're going to cheat here. We know that smbd/aio.c
	 * only calls this when it's waiting for every single
	 * outstanding call to finish on a close, so just wait
	 * individually for each IO to complete. We don't care
	 * what order they finish - only that they all do. JRA.
	 */
	while (sp.num_entries != sp.num_finished) {
		if (tevent_loop_once(ev) == -1) {
			goto out;
		}

		if (timed_out) {
			errno = EAGAIN;
			goto out;
		}
	}

	ret = 0;

  out:

	TALLOC_FREE(frame);
	return ret;
}

#if defined(HAVE_OPENAT) && defined(USE_LINUX_THREAD_CREDENTIALS)
/*
 * We must have openat() to do any thread-based
 * asynchronous opens. We also must be using
 * thread-specific credentials (Linux-only
 * for now).
 */

/*
 * NB. This threadpool is shared over all
 * instances of this VFS module in this
 * process, as is the current jobid.
 */

static struct pthreadpool *open_pool;
static int aio_pthread_open_jobid;

struct aio_open_private_data {
	struct aio_open_private_data *prev, *next;
	/* Inputs. */
	int jobid;
	int dir_fd;
	int flags;
	mode_t mode;
	uint64_t mid;
	bool in_progress;
	const char *fname;
	char *dname;
	struct smbd_server_connection *sconn;
	const struct security_unix_token *ux_tok;
	/* Returns. */
	int ret_fd;
	int ret_errno;
};

/* List of outstanding requests we have. */
static struct aio_open_private_data *open_pd_list;

/************************************************************************
 Find the open private data by jobid.
***********************************************************************/

static struct aio_open_private_data *find_open_private_data_by_jobid(int jobid)
{
	struct aio_open_private_data *opd;

	for (opd = open_pd_list; opd != NULL; opd = opd->next) {
		if (opd->jobid == jobid) {
			return opd;
		}
	}

	return NULL;
}

/************************************************************************
 Find the open private data by mid.
***********************************************************************/

static struct aio_open_private_data *find_open_private_data_by_mid(uint64_t mid)
{
	struct aio_open_private_data *opd;

	for (opd = open_pd_list; opd != NULL; opd = opd->next) {
		if (opd->mid == mid) {
			return opd;
		}
	}

	return NULL;
}

/************************************************************************
 Callback when an open completes.
***********************************************************************/

static void aio_open_handle_completion(struct event_context *event_ctx,
				struct fd_event *event,
				uint16 flags,
				void *p)
{
	struct aio_open_private_data *opd = NULL;
	int jobid = 0;
	int ret;

	DEBUG(10, ("aio_open_handle_completion called with flags=%d\n",
		(int)flags));

	if ((flags & EVENT_FD_READ) == 0) {
		return;
	}

	ret = pthreadpool_finished_job(open_pool, &jobid);
	if (ret) {
		smb_panic("aio_open_handle_completion");
		/* notreached. */
		return;
	}

	opd = find_open_private_data_by_jobid(jobid);
	if (opd == NULL) {
		DEBUG(0, ("aio_open_handle_completion cannot find jobid %d\n",
			jobid));
		smb_panic("aio_open_handle_completion - no jobid");
		/* notreached. */
		return;
	}

	DEBUG(10,("aio_open_handle_completion: jobid %d mid %llu "
		"for file %s/%s completed\n",
		jobid,
		(unsigned long long)opd->mid,
		opd->dname,
		opd->fname));

	opd->in_progress = false;

	/* Find outstanding event and reschdule. */
	if (!schedule_deferred_open_message_smb(opd->sconn, opd->mid)) {
		/*
		 * Outstanding event didn't exist or was
		 * cancelled. Free up the fd and throw
		 * away the result.
		 */
		if (opd->ret_fd != -1) {
			close(opd->ret_fd);
			opd->ret_fd = -1;
		}
		TALLOC_FREE(opd);
	}
}

/*****************************************************************
 The core of the async open code - the worker function. Note we
 use the new openat() system call to avoid any problems with
 current working directory changes plus we change credentials
 on the thread to prevent any security race conditions.
*****************************************************************/

static void aio_open_worker(void *private_data)
{
	struct aio_open_private_data *opd =
		(struct aio_open_private_data *)private_data;

	/* Become the correct credential on this thread. */
	if (set_thread_credentials(opd->ux_tok->uid,
				opd->ux_tok->gid,
				(size_t)opd->ux_tok->ngroups,
				opd->ux_tok->groups) != 0) {
		opd->ret_fd = -1;
		opd->ret_errno = errno;
		return;
	}

	opd->ret_fd = openat(opd->dir_fd,
			opd->fname,
			opd->flags,
			opd->mode);

	if (opd->ret_fd == -1) {
		opd->ret_errno = errno;
	} else {
		/* Create was successful. */
		opd->ret_errno = 0;
	}
}

/************************************************************************
 Open private data destructor.
***********************************************************************/

static int opd_destructor(struct aio_open_private_data *opd)
{
	if (opd->dir_fd != -1) {
		close(opd->dir_fd);
	}
	DLIST_REMOVE(open_pd_list, opd);
	return 0;
}

/************************************************************************
 Create and initialize a private data struct for async open.
***********************************************************************/

static struct aio_open_private_data *create_private_open_data(const files_struct *fsp,
					int flags,
					mode_t mode)
{
	struct aio_open_private_data *opd = talloc_zero(NULL,
					struct aio_open_private_data);
	const char *fname = NULL;

	if (!opd) {
		return NULL;
	}

	opd->jobid = aio_pthread_open_jobid++;
	opd->dir_fd = -1;
	opd->ret_fd = -1;
	opd->ret_errno = EINPROGRESS;
	opd->flags = flags;
	opd->mode = mode;
	opd->mid = fsp->mid;
	opd->in_progress = true;
	opd->sconn = fsp->conn->sconn;

	/* Copy our current credentials. */
	opd->ux_tok = copy_unix_token(opd, get_current_utok(fsp->conn));
	if (opd->ux_tok == NULL) {
		TALLOC_FREE(opd);
		return NULL;
	}

	/*
	 * Copy the parent directory name and the
	 * relative path within it.
	 */
	if (parent_dirname(opd,
			fsp->fsp_name->base_name,
			&opd->dname,
			&fname) == false) {
		TALLOC_FREE(opd);
		return NULL;
	}
	opd->fname = talloc_strdup(opd, fname);
	if (opd->fname == NULL) {
		TALLOC_FREE(opd);
		return NULL;
	}

#if defined(O_DIRECTORY)
	opd->dir_fd = open(opd->dname, O_RDONLY|O_DIRECTORY);
#else
	opd->dir_fd = open(opd->dname, O_RDONLY);
#endif
	if (opd->dir_fd == -1) {
		TALLOC_FREE(opd);
		return NULL;
	}

	talloc_set_destructor(opd, opd_destructor);
	DLIST_ADD_END(open_pd_list, opd, struct aio_open_private_data *);
	return opd;
}

/*****************************************************************
 Setup an async open.
*****************************************************************/

static int open_async(const files_struct *fsp,
			int flags,
			mode_t mode)
{
	struct aio_open_private_data *opd = NULL;
	int ret;

	if (!init_aio_threadpool(fsp->conn->sconn->ev_ctx,
			&open_pool,
			aio_open_handle_completion)) {
		return -1;
	}

	opd = create_private_open_data(fsp, flags, mode);
	if (opd == NULL) {
		DEBUG(10, ("open_async: Could not create private data.\n"));
		return -1;
	}

	ret = pthreadpool_add_job(open_pool,
				opd->jobid,
				aio_open_worker,
				(void *)opd);
	if (ret) {
		errno = ret;
		return -1;
	}

	DEBUG(5,("open_async: mid %llu jobid %d created for file %s/%s\n",
		(unsigned long long)opd->mid,
		opd->jobid,
		opd->dname,
		opd->fname));

	/* Cause the calling code to reschedule us. */
	errno = EINTR; /* Maps to NT_STATUS_RETRY. */
	return -1;
}

/*****************************************************************
 Look for a matching SMB2 mid. If we find it we're rescheduled,
 just return the completed open.
*****************************************************************/

static bool find_completed_open(files_struct *fsp,
				int *p_fd,
				int *p_errno)
{
	struct aio_open_private_data *opd;

	opd = find_open_private_data_by_mid(fsp->mid);
	if (!opd) {
		return false;
	}

	if (opd->in_progress) {
		DEBUG(0,("find_completed_open: mid %llu "
			"jobid %d still in progress for "
			"file %s/%s. PANIC !\n",
			(unsigned long long)opd->mid,
			opd->jobid,
			opd->dname,
			opd->fname));
		/* Disaster ! This is an open timeout. Just panic. */
		smb_panic("find_completed_open - in_progress\n");
		/* notreached. */
		return false;
	}

	*p_fd = opd->ret_fd;
	*p_errno = opd->ret_errno;

	DEBUG(5,("find_completed_open: mid %llu returning "
		"fd = %d, errno = %d (%s) "
		"jobid (%d) for file %s\n",
		(unsigned long long)opd->mid,
		opd->ret_fd,
		opd->ret_errno,
		strerror(opd->ret_errno),
		opd->jobid,
		smb_fname_str_dbg(fsp->fsp_name)));

	/* Now we can free the opd. */
	TALLOC_FREE(opd);
	return true;
}

/*****************************************************************
 The core open function. Only go async on O_CREAT|O_EXCL
 opens to prevent any race conditions.
*****************************************************************/

static int aio_pthread_open_fn(vfs_handle_struct *handle,
			struct smb_filename *smb_fname,
			files_struct *fsp,
			int flags,
			mode_t mode)
{
	int my_errno = 0;
	int fd = -1;
	bool aio_allow_open = lp_parm_bool(
		SNUM(handle->conn), "aio_pthread", "aio open", false);

	if (smb_fname->stream_name) {
		/* Don't handle stream opens. */
		errno = ENOENT;
		return -1;
	}

	if (!aio_allow_open) {
		/* aio opens turned off. */
		return open(smb_fname->base_name, flags, mode);
	}

	if (!(flags & O_CREAT)) {
		/* Only creates matter. */
		return open(smb_fname->base_name, flags, mode);
	}

	if (!(flags & O_EXCL)) {
		/* Only creates with O_EXCL matter. */
		return open(smb_fname->base_name, flags, mode);
	}

	/*
	 * See if this is a reentrant call - i.e. is this a
	 * restart of an existing open that just completed.
	 */

	if (find_completed_open(fsp,
				&fd,
				&my_errno)) {
		errno = my_errno;
		return fd;
	}

	/* Ok, it's a create exclusive call - pass it to a thread helper. */
	return open_async(fsp, flags, mode);
}
#endif

static int aio_pthread_connect(vfs_handle_struct *handle, const char *service,
			       const char *user)
{
	/*********************************************************************
	 * How many threads to initialize ?
	 * 100 per process seems insane as a default until you realize that
	 * (a) Threads terminate after 1 second when idle.
	 * (b) Throttling is done in SMB2 via the crediting algorithm.
	 * (c) SMB1 clients are limited to max_mux (50) outstanding
	 *     requests and Windows clients don't use this anyway.
	 * Essentially we want this to be unlimited unless smb.conf
	 * says different.
	 *********************************************************************/
	aio_pending_size = lp_parm_int(
		SNUM(handle->conn), "aio_pthread", "aio num threads", 100);
	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static struct vfs_fn_pointers vfs_aio_pthread_fns = {
	.connect_fn = aio_pthread_connect,
#if defined(HAVE_OPENAT) && defined(USE_LINUX_THREAD_CREDENTIALS)
	.open_fn = aio_pthread_open_fn,
#endif
	.aio_read_fn = aio_pthread_read,
	.aio_write_fn = aio_pthread_write,
	.aio_return_fn = aio_pthread_return_fn,
	.aio_cancel_fn = aio_pthread_cancel,
	.aio_error_fn = aio_pthread_error_fn,
	.aio_suspend_fn = aio_pthread_suspend,
};

NTSTATUS vfs_aio_pthread_init(void);
NTSTATUS vfs_aio_pthread_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"aio_pthread", &vfs_aio_pthread_fns);
}
