/*
 * inotify change notify support
 *
 * Copyright (c) Andrew Tridgell 2006
 * Copyright (c) Volker Lendecke 2007
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA
 */

#include "includes.h"

#ifdef HAVE_INOTIFY

#include <linux/inotify.h>
#include <asm/unistd.h>

#ifndef HAVE_INOTIFY_INIT
/*
  glibc doesn't define these functions yet (as of March 2006)
*/
static int inotify_init(void)
{
	return syscall(__NR_inotify_init);
}

static int inotify_add_watch(int fd, const char *path, __u32 mask)
{
	return syscall(__NR_inotify_add_watch, fd, path, mask);
}

static int inotify_rm_watch(int fd, int wd)
{
	return syscall(__NR_inotify_rm_watch, fd, wd);
}
#endif

struct inotify_ctx {
	struct inotify_ctx *prev, *next;
	int wd;
	files_struct *fsp;
};

static struct inotify_ctx *inotify_list;

static int inotify_watch_fd;

/*
  map from a change notify mask to a inotify mask. Remove any bits
  which we can handle
*/
static const struct {
	uint32_t notify_mask;
	uint32_t inotify_mask;
} inotify_mapping[] = {
	{FILE_NOTIFY_CHANGE_FILE_NAME,
	 IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO},
	{FILE_NOTIFY_CHANGE_DIR_NAME,
	 IN_CREATE|IN_DELETE|IN_MOVED_FROM|IN_MOVED_TO},
	{FILE_NOTIFY_CHANGE_ATTRIBUTES,
	 IN_ATTRIB|IN_MOVED_TO|IN_MOVED_FROM|IN_MODIFY},
	{FILE_NOTIFY_CHANGE_LAST_WRITE,  IN_ATTRIB},
	{FILE_NOTIFY_CHANGE_LAST_ACCESS, IN_ATTRIB},
	{FILE_NOTIFY_CHANGE_EA,          IN_ATTRIB},
	{FILE_NOTIFY_CHANGE_SECURITY,    IN_ATTRIB}
};

static uint32_t inotify_map(uint32 *filter)
{
	int i;
	uint32_t out=0;
	for (i=0;i<ARRAY_SIZE(inotify_mapping);i++) {
		if (inotify_mapping[i].notify_mask & *filter) {
			out |= inotify_mapping[i].inotify_mask;
			*filter &= ~inotify_mapping[i].notify_mask;
		}
	}
	return out;
}

static int inotify_ctx_destructor(struct inotify_ctx *ctx)
{
	if (inotify_rm_watch(inotify_watch_fd, ctx->wd) == -1) {
		DEBUG(0, ("inotify_rm_watch failed: %s\n", strerror(errno)));
	}
	DLIST_REMOVE(inotify_list, ctx);
	return 0;
}

static void *inotify_add(TALLOC_CTX *mem_ctx, 
			 struct event_context *event_ctx,
			 files_struct *fsp, uint32 *pfilter)
{
	struct inotify_ctx *ctx;
	uint32_t inotify_mask;
	pstring fullpath;
	uint32 filter;
	
	filter = *pfilter;
	if ((filter & (FILE_NOTIFY_CHANGE_FILE
		       |FILE_NOTIFY_CHANGE_DIR_NAME)) == 0) {
		/*
		 * This first implementation only looks at create/delete
		 */
		return NULL;
	}

	inotify_mask = inotify_map(&filter);

	if (inotify_mask == 0) {
		DEBUG(10, ("inotify_mask == 0, nothing to do\n"));
		return NULL;
	}

	pstrcpy(fullpath, fsp->fsp_name);
	if (!canonicalize_path(fsp->conn, fullpath)) {
		DEBUG(0, ("failed to canonicalize path '%s'\n", fullpath));
		return NULL;
	}

	if (*fullpath != '/') {
		DEBUG(0, ("canonicalized path '%s' into `%s`\n", fsp->fsp_name,
			  fullpath));
		DEBUGADD(0, ("but expected an absolute path\n"));
		return NULL;
	}
	
	if (!(ctx = TALLOC_P(mem_ctx, struct inotify_ctx))) {
		DEBUG(0, ("talloc failed\n"));
		return NULL;
	}

	ctx->fsp = fsp;
	ctx->wd = inotify_add_watch(inotify_watch_fd, fullpath, inotify_mask);

	if (ctx->wd == -1) {
		DEBUG(5, ("inotify_add_watch failed: %s\n", strerror(errno)));
		TALLOC_FREE(ctx);
		return NULL;
	}

	DLIST_ADD(inotify_list, ctx);
	talloc_set_destructor(ctx, inotify_ctx_destructor);

	*pfilter = filter;
	return ctx;
}

static void inotify_dispatch(struct inotify_event *e)
{
	struct inotify_ctx *ctx;

	for (ctx = inotify_list; ctx; ctx = ctx->next) {
		if (ctx->wd == e->wd) {
			break;
		}
	}

	if (ctx == NULL) {
		/* not found */
		return;
	}

	if (e->mask & IN_CREATE) {
		notify_fsp(ctx->fsp, NOTIFY_ACTION_ADDED, e->name);
	}

	if (e->mask & IN_DELETE) {
		notify_fsp(ctx->fsp, NOTIFY_ACTION_REMOVED, e->name);
	}
}

static void inotify_callback(struct event_context *event_ctx,
			     struct fd_event *event,
			     uint16 flags,
			     void *private_data)
{
	char *buf, *p;
	int bufsize;

	/*
	  we must use FIONREAD as we cannot predict the length of the
	  filenames, and thus can't know how much to allocate
	  otherwise
	*/
	if ((ioctl(inotify_watch_fd, FIONREAD, &bufsize) != 0)
	    || (bufsize == 0)) {
		DEBUG(0,("No data on inotify fd?!\n"));
		return;
	}

	if (!(buf = SMB_MALLOC_ARRAY(char, bufsize))) {
		DEBUG(0, ("malloc failed\n"));
		return;
	}

	if (read(inotify_watch_fd, buf, bufsize) != bufsize) {
		DEBUG(0,("Failed to read all inotify data\n"));
		SAFE_FREE(buf);
		return;
	}

	p = buf;

	while (bufsize > sizeof(struct inotify_event)) {
		struct inotify_event *iev = (struct inotify_event *)p;
		size_t len = sizeof(struct inotify_event) + iev->len;

		if ((len > bufsize)
		    || ((iev->len != 0) && (iev->name[iev->len-1] != '\0'))) {
			smb_panic("invalid inotify reply\n");
		}

		inotify_dispatch(iev);

		p += len;
		bufsize -= len;
	}

	SAFE_FREE(buf);
	return;
}

static struct cnotify_fns inotify_fns =
{
    inotify_add,
};

struct cnotify_fns *inotify_notify_init(struct event_context *event_ctx)
{
	inotify_watch_fd = inotify_init();

	DEBUG(10, ("inotify_notify_init called\n"));

	if (inotify_watch_fd == -1) {
		DEBUG(0, ("inotify_init failed: %s\n", strerror(errno)));
		return NULL;
	}

	if (event_add_fd(event_ctx, NULL, inotify_watch_fd,
			 EVENT_FD_READ, inotify_callback,
			 NULL) == NULL) {
		DEBUG(0, ("event_add_fd failed\n"));
		close(inotify_watch_fd);
		inotify_watch_fd = -1;
		return NULL;
	}

	return &inotify_fns;
}

#endif
