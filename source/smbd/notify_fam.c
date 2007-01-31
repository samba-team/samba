/*
 * FAM file notification support.
 *
 * Copyright (c) James Peach 2005
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

#ifdef HAVE_FAM_CHANGE_NOTIFY

#include <fam.h>

#if !defined(HAVE_FAM_H_FAMCODES_TYPEDEF)
/* Gamin provides this typedef which means we can't use 'enum FAMCodes' as per
 * every other FAM implementation. Phooey.
 */
typedef enum FAMCodes FAMCodes;
#endif

/* NOTE: There are multiple versions of FAM floating around the net, each with
 * slight differences from the original SGI FAM implementation. In this file,
 * we rely only on the SGI features and do not assume any extensions. For
 * example, we do not look at FAMErrno, because it is not set by the original
 * implementation.
 *
 * Random FAM links:
 *	http://oss.sgi.com/projects/fam/
 *	http://savannah.nongnu.org/projects/fam/
 *	http://sourceforge.net/projects/bsdfam/
 */

static void *fam_notify_add(TALLOC_CTX *mem_ctx,
			    struct event_context *event_ctx,
			    files_struct *fsp, uint32 *filter);

/* ------------------------------------------------------------------------- */

struct fam_notify_ctx {
	struct fam_notify_ctx *prev, *next;
	FAMConnection *fam_connection;
	struct FAMRequest fr;
	files_struct *fsp;
	char *path;
	uint32 filter;
};

static struct fam_notify_ctx *fam_notify_list;
static FAMConnection fam_connection;
static void fam_handler(struct event_context *event_ctx,
			struct fd_event *fd_event,
			uint16 flags,
			void *private_data);

static NTSTATUS fam_open_connection(FAMConnection *fam_conn,
				    struct event_context *event_ctx)
{
	int res;
	char *name;

	ZERO_STRUCTP(fam_conn);
	FAMCONNECTION_GETFD(fam_conn) = -1;

	if (asprintf(&name, "smbd (%lu)", (unsigned long)sys_getpid()) == -1) {
		DEBUG(0, ("No memory\n"));
		return NT_STATUS_NO_MEMORY;
	}

	res = FAMOpen2(fam_conn, name);
	SAFE_FREE(name);

	if (res < 0) {
		DEBUG(5, ("FAM file change notifications not available\n"));
		/*
		 * No idea how to get NT_STATUS from a FAM result
		 */
		FAMCONNECTION_GETFD(fam_conn) = -1;
		return NT_STATUS_UNEXPECTED_IO_ERROR;
	}

	if (event_add_fd(event_ctx, event_ctx,
			 FAMCONNECTION_GETFD(fam_conn),
			 EVENT_FD_READ, fam_handler,
			 (void *)fam_conn) == NULL) {
		DEBUG(0, ("event_add_fd failed\n"));
		FAMClose(fam_conn);
		FAMCONNECTION_GETFD(fam_conn) = -1;
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static void fam_reopen(FAMConnection *fam_conn,
		       struct event_context *event_ctx,
		       struct fam_notify_ctx *notify_list)
{
	struct fam_notify_ctx *ctx;

	DEBUG(5, ("Re-opening FAM connection\n"));

	FAMClose(fam_conn);

	if (!NT_STATUS_IS_OK(fam_open_connection(fam_conn, event_ctx))) {
		DEBUG(5, ("Re-opening fam connection failed\n"));
		return;
	}

	for (ctx = notify_list; ctx; ctx = ctx->next) {
		FAMMonitorDirectory(fam_conn, ctx->path, &ctx->fr, NULL);
	}
}

static void fam_handler(struct event_context *event_ctx,
			struct fd_event *fd_event,
			uint16 flags,
			void *private_data)
{
	FAMConnection *fam_conn = (FAMConnection *)private_data;
	FAMEvent fam_event;
	struct fam_notify_ctx *ctx;
	char *name;

	if (FAMPending(fam_conn) == 0) {
		DEBUG(10, ("fam_handler called but nothing pending\n"));
		return;
	}

	if (FAMNextEvent(fam_conn, &fam_event) != 1) {
		DEBUG(10, ("FAMNextEvent returned an error\n"));
		TALLOC_FREE(fd_event);
		fam_reopen(fam_conn, event_ctx, fam_notify_list);
		return;
	}

	if ((fam_event.code != FAMCreated) && (fam_event.code != FAMDeleted)) {
		DEBUG(10, ("Ignoring code FAMCode %d for file %s\n",
			   (int)fam_event.code, fam_event.filename));
		return;
	}

	for (ctx = fam_notify_list; ctx; ctx = ctx->next) {
		if (memcmp(&fam_event.fr, &ctx->fr, sizeof(FAMRequest)) == 0) {
			break;
		}
	}

	if (ctx == NULL) {
		DEBUG(5, ("Discarding event for file %s\n",
			  fam_event.filename));
		return;
	}

	if ((name = strrchr_m(fam_event.filename, '\\')) == NULL) {
		name = fam_event.filename;
	}

	notify_fsp(ctx->fsp,
		   fam_event.code == FAMCreated
		   ? NOTIFY_ACTION_ADDED : NOTIFY_ACTION_REMOVED,
		   name);
}

static int fam_notify_ctx_destructor(struct fam_notify_ctx *ctx)
{
	if (FAMCONNECTION_GETFD(ctx->fam_connection) != -1) {
		FAMCancelMonitor(&fam_connection, &ctx->fr);
	}
	DLIST_REMOVE(fam_notify_list, ctx);
	return 0;
}

static void *fam_notify_add(TALLOC_CTX *mem_ctx,
			    struct event_context *event_ctx,
			    files_struct *fsp, uint32 *filter)
{
	struct fam_notify_ctx *ctx;
	pstring fullpath;

	if ((*filter & FILE_NOTIFY_CHANGE_FILE_NAME) == 0) {
		DEBUG(10, ("filter = %u, no FILE_NOTIFY_CHANGE_FILE_NAME\n",
			   *filter));
		return NULL;
	}

	/* FAM needs an absolute pathname. */

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
	
	if (!(ctx = TALLOC_P(mem_ctx, struct fam_notify_ctx))) {
		return NULL;
	}

	ctx->fsp = fsp;
	ctx->fam_connection = &fam_connection;

	/*
	 * The FAM module in this early state will only take care of
	 * FAMCreated and FAMDeleted events
	 */

	ctx->filter = FILE_NOTIFY_CHANGE_FILE_NAME;

	if (!(ctx->path = talloc_strdup(ctx, fullpath))) {
		DEBUG(0, ("talloc_strdup failed\n"));
		TALLOC_FREE(ctx);
		return NULL;
	}

	/*
	 * Leave the rest to smbd itself
	 */

	*filter &= ~FILE_NOTIFY_CHANGE_FILE_NAME;

	DLIST_ADD(fam_notify_list, ctx);
	talloc_set_destructor(ctx, fam_notify_ctx_destructor);

	/*
	 * Only directories monitored so far
	 */

	if (FAMCONNECTION_GETFD(ctx->fam_connection) != -1) {
		FAMMonitorDirectory(ctx->fam_connection, ctx->path, &ctx->fr,
				    NULL);
	}
	else {
		/*
		 * If the re-open is successful, this will establish the
		 * FAMMonitor from the list
		 */
		fam_reopen(ctx->fam_connection, event_ctx, fam_notify_list);
	}

	return ctx;
}

static struct cnotify_fns global_fam_notify =
{
    fam_notify_add,
};

struct cnotify_fns *fam_notify_init(struct event_context *event_ctx)
{

	ZERO_STRUCT(fam_connection);
	FAMCONNECTION_GETFD(&fam_connection) = -1;

	if (!NT_STATUS_IS_OK(fam_open_connection(&fam_connection,
						 event_ctx))) {
		DEBUG(0, ("FAM file change notifications not available\n"));
		return NULL;
	}

	DEBUG(10, ("enabling FAM change notifications\n"));
	return &global_fam_notify;
}

#endif /* HAVE_FAM_CHANGE_NOTIFY */
