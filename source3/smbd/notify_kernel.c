/*
   Unix SMB/Netbios implementation.
   Version 3.0
   change notify handling - linux kernel based implementation
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Volker Lendecke 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

#if HAVE_KERNEL_CHANGE_NOTIFY

#ifndef DN_ACCESS
#define DN_ACCESS       0x00000001      /* File accessed in directory */
#define DN_MODIFY       0x00000002      /* File modified in directory */
#define DN_CREATE       0x00000004      /* File created in directory */
#define DN_DELETE       0x00000008      /* File removed from directory */
#define DN_RENAME       0x00000010      /* File renamed in directory */
#define DN_ATTRIB       0x00000020      /* File changed attribute */
#define DN_MULTISHOT    0x80000000      /* Don't remove notifier */
#endif


#ifndef RT_SIGNAL_NOTIFY
#define RT_SIGNAL_NOTIFY (SIGRTMIN+2)
#endif

#ifndef F_SETSIG
#define F_SETSIG 10
#endif

#ifndef F_NOTIFY
#define F_NOTIFY 1026
#endif

/****************************************************************************
 This is the structure to keep the information needed to
 determine if a directory has changed.
*****************************************************************************/

struct dnotify_ctx {
	struct dnotify_ctx *prev, *next;

	int fd;
	files_struct *fsp;
};

static struct dnotify_ctx *dnotify_list;
static int dnotify_signal_pipe[2];

/****************************************************************************
 The signal handler for change notify.
 The Linux kernel has a bug in that we should be able to block any
 further delivery of RT signals until the kernel_check_notify() function
 unblocks them, but it seems that any signal mask we're setting here is
 being overwritten on exit from this handler. I should create a standalone
 test case for the kernel hackers. JRA.
*****************************************************************************/

static void dnotify_signal_handler(int sig, siginfo_t *info, void *unused)
{
	int saved_errno;

	/*
	 * According to http://www.opengroup.org/onlinepubs/009695399/ write
	 * to a pipe either writes all or nothing, so we can safely write a
	 * full sizeof(int) and not risk the pipe to become out of sync with
	 * the receiving end.
	 *
	 * We don't care about the result of the write() call. If the pipe is
	 * full, then this signal is lost, we can't do anything about it.
	 */

	saved_errno = errno;
	write(dnotify_signal_pipe[1], (const void *)&info->si_fd, sizeof(int));
	errno = saved_errno;

	sys_select_signal(RT_SIGNAL_NOTIFY);
}

/****************************************************************************
 The upper level handler informed when the pipe is ready for reading
*****************************************************************************/

static void dnotify_pipe_handler(struct event_context *event_ctx,
				 struct fd_event *event,
				 uint16 flags,
				 void *private_data)
{
	int res, fd;
	struct dnotify_ctx *ctx;

	res = read(dnotify_signal_pipe[0], (void *)&fd, sizeof(int));

	if (res == -1) {
		DEBUG(0, ("Read from the dnotify pipe failed: %s\n",
			  strerror(errno)));
		TALLOC_FREE(event); /* Don't try again */
		return;
	}

	if (res != sizeof(int)) {
		smb_panic("read from dnotify pipe gave wrong number of "
			  "bytes\n");
	}

	for (ctx = dnotify_list; ctx; ctx = ctx->next) {
		if (ctx->fd == fd) {
			notify_fsp(ctx->fsp, 0, NULL);
		}
	}
}

/****************************************************************************
 Register a change notify request.
*****************************************************************************/

static int kernel_register_notify(connection_struct *conn, char *path,
				  uint32 flags)
{
	int fd;
	unsigned long kernel_flags;
	
	fd = sys_open(path,O_RDONLY, 0);

	if (fd == -1) {
		DEBUG(3,("Failed to open directory %s for change notify\n",
			 path));
		return -1;
	}

	if (sys_fcntl_long(fd, F_SETSIG, RT_SIGNAL_NOTIFY) == -1) {
		DEBUG(3,("Failed to set signal handler for change notify\n"));
		close(fd);
		return -1;
	}

	kernel_flags = DN_CREATE|DN_DELETE|DN_RENAME; /* creation/deletion
						       * changes
						       * everything! */
	if (flags & FILE_NOTIFY_CHANGE_FILE)        kernel_flags |= DN_MODIFY;
	if (flags & FILE_NOTIFY_CHANGE_DIR_NAME)    kernel_flags
							    |= DN_RENAME
							    |DN_DELETE;
	if (flags & FILE_NOTIFY_CHANGE_ATTRIBUTES)  kernel_flags |= DN_ATTRIB;
	if (flags & FILE_NOTIFY_CHANGE_SIZE)        kernel_flags |= DN_MODIFY;
	if (flags & FILE_NOTIFY_CHANGE_LAST_WRITE)  kernel_flags |= DN_MODIFY;
	if (flags & FILE_NOTIFY_CHANGE_LAST_ACCESS) kernel_flags |= DN_ACCESS;
	if (flags & FILE_NOTIFY_CHANGE_CREATION)    kernel_flags |= DN_CREATE;
	if (flags & FILE_NOTIFY_CHANGE_SECURITY)    kernel_flags |= DN_ATTRIB;
	if (flags & FILE_NOTIFY_CHANGE_EA)          kernel_flags |= DN_ATTRIB;
	if (flags & FILE_NOTIFY_CHANGE_FILE_NAME)   kernel_flags
							    |= DN_RENAME
							    |DN_DELETE;

	if (sys_fcntl_long(fd, F_NOTIFY, kernel_flags) == -1) {
		DEBUG(3,("Failed to set async flag for change notify\n"));
		close(fd);
		return -1;
	}

	DEBUG(3,("kernel change notify on %s (ntflags=0x%x flags=0x%x) "
		 "fd=%d\n", path, (int)flags, (int)kernel_flags, fd));

	return fd;
}

/****************************************************************************
 See if the kernel supports change notify.
****************************************************************************/

static BOOL kernel_notify_available(void) 
{
	int fd, ret;
	fd = open("/tmp", O_RDONLY);
	if (fd == -1)
		return False; /* uggh! */
	ret = sys_fcntl_long(fd, F_NOTIFY, 0);
	close(fd);
	return ret == 0;
}

static int dnotify_ctx_destructor(struct dnotify_ctx *ctx)
{
	close(ctx->fd);
	DLIST_REMOVE(dnotify_list, ctx);
	return 0;
}

static void *kernel_notify_add(TALLOC_CTX *mem_ctx,
			       struct event_context *event_ctx,
			       files_struct *fsp,
			       uint32 *filter)
{
	struct dnotify_ctx *ctx;

	if (!(ctx = TALLOC_P(mem_ctx, struct dnotify_ctx))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	ctx->fsp = fsp;
	ctx->fd = kernel_register_notify(fsp->conn, fsp->fsp_name, *filter);

	if (ctx->fd == -1) {
		TALLOC_FREE(ctx);
		return NULL;
	}

	DLIST_ADD(dnotify_list, ctx);
	talloc_set_destructor(ctx, dnotify_ctx_destructor);

	return ctx;
}

/****************************************************************************
 Setup kernel based change notify.
****************************************************************************/

struct cnotify_fns *kernel_notify_init(struct event_context *event_ctx)
{
	static struct cnotify_fns cnotify;
        struct sigaction act;

	if (pipe(dnotify_signal_pipe) == -1) {
		DEBUG(0, ("Failed to create signal pipe: %s\n",
			  strerror(errno)));
		return NULL;
	}

	if ((set_blocking(dnotify_signal_pipe[0], False) == -1)
	    || (set_blocking(dnotify_signal_pipe[1], False) == -1)) {
		DEBUG(0, ("Failed to set signal pipe to non-blocking: %s\n",
			  strerror(errno)));
		close(dnotify_signal_pipe[0]);
		close(dnotify_signal_pipe[1]);
		return NULL;
	}

	if (event_add_fd(event_ctx, NULL, dnotify_signal_pipe[0],
			 EVENT_FD_READ, dnotify_pipe_handler, NULL) == NULL) {
		DEBUG(0, ("Failed to set signal event handler\n"));
		close(dnotify_signal_pipe[0]);
		close(dnotify_signal_pipe[1]);
		return NULL;
	}

	ZERO_STRUCT(act);

	act.sa_sigaction = dnotify_signal_handler;
	act.sa_flags = SA_SIGINFO;
	sigemptyset( &act.sa_mask );
	if (sigaction(RT_SIGNAL_NOTIFY, &act, NULL) != 0) {
		DEBUG(0,("Failed to setup RT_SIGNAL_NOTIFY handler\n"));
		return NULL;
	}

	if (!kernel_notify_available())
		return NULL;

	cnotify.notify_add = kernel_notify_add;

	/* the signal can start off blocked due to a bug in bash */
	BlockSignals(False, RT_SIGNAL_NOTIFY);

	return &cnotify;
}

#else
 void notify_kernel_dummy(void);

 void notify_kernel_dummy(void) {}
#endif /* HAVE_KERNEL_CHANGE_NOTIFY */
