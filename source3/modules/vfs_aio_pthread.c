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
#include "../lib/pthreadpool/pthreadpool_tevent.h"
#ifdef HAVE_LINUX_FALLOC_H
#include <linux/falloc.h>
#endif

#if defined(HAVE_OPENAT) && defined(HAVE_LINUX_THREAD_CREDENTIALS)

/*
 * We must have openat() to do any thread-based
 * asynchronous opens. We also must be using
 * thread-specific credentials (Linux-only
 * for now).
 */

struct aio_open_private_data {
	struct aio_open_private_data *prev, *next;
	/* Inputs. */
	int dir_fd;
	int flags;
	mode_t mode;
	uint64_t mid;
	bool in_progress;
	const char *fname;
	char *dname;
	connection_struct *conn;
	const struct security_unix_token *ux_tok;
	uint64_t initial_allocation_size;
	/* Returns. */
	int ret_fd;
	int ret_errno;
};

/* List of outstanding requests we have. */
static struct aio_open_private_data *open_pd_list;

static void aio_open_do(struct aio_open_private_data *opd);

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

static void aio_open_handle_completion(struct tevent_req *subreq)
{
	struct aio_open_private_data *opd =
		tevent_req_callback_data(subreq,
		struct aio_open_private_data);
	int ret;
	struct smbXsrv_connection *xconn;

	ret = pthreadpool_tevent_job_recv(subreq);
	TALLOC_FREE(subreq);
	if (ret != 0) {
		bool ok;

		if (ret != EAGAIN) {
			smb_panic("aio_open_handle_completion");
			/* notreached. */
			return;
		}
		/*
		 * Make sure we run as the user again
		 */
		ok = change_to_user(opd->conn, opd->conn->vuid);
		if (!ok) {
			smb_panic("Can't change to user");
			return;
		}
		/*
		 * If we get EAGAIN from pthreadpool_tevent_job_recv() this
		 * means the lower level pthreadpool failed to create a new
		 * thread. Fallback to sync processing in that case to allow
		 * some progress for the client.
		 */
		aio_open_do(opd);
	}

	DEBUG(10,("aio_open_handle_completion: mid %llu "
		"for file %s/%s completed\n",
		(unsigned long long)opd->mid,
		opd->dname,
		opd->fname));

	opd->in_progress = false;

	/*
	 * TODO: In future we need a proper algorithm
	 * to find the correct connection for a fsp.
	 * For now we only have one connection, so this is correct...
	 */
	xconn = opd->conn->sconn->client->connections;

	/* Find outstanding event and reschedule. */
	if (!schedule_deferred_open_message_smb(xconn, opd->mid)) {
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

	aio_open_do(opd);
}

static void aio_open_do(struct aio_open_private_data *opd)
{
	opd->ret_fd = openat(opd->dir_fd,
			opd->fname,
			opd->flags,
			opd->mode);

	if (opd->ret_fd == -1) {
		opd->ret_errno = errno;
	} else {
		/* Create was successful. */
		opd->ret_errno = 0;

#if defined(HAVE_LINUX_FALLOCATE)
		/*
		 * See if we can set the initial
		 * allocation size. We don't record
		 * the return for this as it's an
		 * optimization - the upper layer
		 * will also do this for us once
		 * the open returns.
		 */
		if (opd->initial_allocation_size) {
			(void)fallocate(opd->ret_fd,
					FALLOC_FL_KEEP_SIZE,
					0,
					(off_t)opd->initial_allocation_size);
		}
#endif
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

	*opd = (struct aio_open_private_data) {
		.dir_fd = -1,
		.ret_fd = -1,
		.ret_errno = EINPROGRESS,
		.flags = flags,
		.mode = mode,
		.mid = fsp->mid,
		.in_progress = true,
		.conn = fsp->conn,
		.initial_allocation_size = fsp->initial_allocation_size,
	};

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
	DLIST_ADD_END(open_pd_list, opd);
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
	struct tevent_req *subreq = NULL;

	opd = create_private_open_data(fsp, flags, mode);
	if (opd == NULL) {
		DEBUG(10, ("open_async: Could not create private data.\n"));
		return -1;
	}

	subreq = pthreadpool_tevent_job_send(opd,
					     fsp->conn->sconn->ev_ctx,
					     fsp->conn->sconn->pool,
					     aio_open_worker, opd);
	if (subreq == NULL) {
		return -1;
	}
	tevent_req_set_callback(subreq, aio_open_handle_completion, opd);

	DEBUG(5,("open_async: mid %llu created for file %s/%s\n",
		(unsigned long long)opd->mid,
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
			"still in progress for "
			"file %s/%s. PANIC !\n",
			(unsigned long long)opd->mid,
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
		"for file %s\n",
		(unsigned long long)opd->mid,
		opd->ret_fd,
		opd->ret_errno,
		strerror(opd->ret_errno),
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

static struct vfs_fn_pointers vfs_aio_pthread_fns = {
#if defined(HAVE_OPENAT) && defined(HAVE_LINUX_THREAD_CREDENTIALS)
	.open_fn = aio_pthread_open_fn,
#endif
};

static_decl_vfs;
NTSTATUS vfs_aio_pthread_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"aio_pthread", &vfs_aio_pthread_fns);
}
