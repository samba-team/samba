/* 
   Unix SMB/CIFS implementation.

   Copyright (C) Andrew Tridgell 2006
   
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

/*
  abstract the various kernel interfaces to change notify into a
  single Samba friendly interface
*/

#include "includes.h"
#include "system/filesys.h"
#include "ntvfs/sysdep/sys_notify.h"
#include "lib/events/events.h"
#include "dlinklist.h"

/* list of registered backends */
static struct sys_notify_backend *backends;


/*
  initialise a system change notify backend
*/
struct sys_notify_context *sys_notify_init(int snum,
					   TALLOC_CTX *mem_ctx, 
					   struct event_context *ev)
{
	struct sys_notify_context *ctx;
	const char *bname;
	struct sys_notify_backend *b;

	if (ev == NULL) {
		ev = event_context_find(mem_ctx);
	}

	ctx = talloc_zero(mem_ctx, struct sys_notify_context);
	if (ctx == NULL) {
		return NULL;
	}

	ctx->ev = ev;

	bname = lp_parm_string(snum, "notify", "backend");
	if (!bname) {
		if (backends) {
			bname = backends->name;
		} else {
			bname = "__unknown__";
		}
	}

	for (b=backends;b;b=b->next) {
		if (strcasecmp(b->name, bname) == 0) {
			bname = b->name;
			break;
		}
	}

	ctx->name = bname;
	ctx->notify_watch = NULL;

	if (b != NULL) {
		ctx->notify_watch = b->notify_watch;
	}

	return ctx;
}

/*
  add a watch
*/
NTSTATUS sys_notify_watch(struct sys_notify_context *ctx, const char *dirpath,
			  uint32_t filter, sys_notify_callback_t callback,
			  void *private, void **handle)
{
	if (!ctx->notify_watch) {
		return NT_STATUS_NOT_IMPLEMENTED;
	}
	return ctx->notify_watch(ctx, dirpath, filter, callback, private, handle);
}

/*
  register a notify backend
*/
NTSTATUS sys_notify_register(struct sys_notify_backend *backend)
{
	DLIST_ADD(backends, backend);
	return NT_STATUS_OK;
}
