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

#include "librpc/gen_ndr/notify.h"

struct sys_notify_context;

typedef void (*sys_notify_callback_t)(struct sys_notify_context *, 
				      void *, struct notify_event *ev);

struct sys_notify_context {
	struct event_context *ev;
	void *private; /* for use of backend */
	NTSTATUS (*notify_watch)(struct sys_notify_context *ctx, const char *dirpath,
				 uint32_t filter, sys_notify_callback_t callback,
				 void *private, void **handle);
	const char *name;
};

struct sys_notify_backend {
	struct sys_notify_backend *next, *prev;
	const char *name;
	NTSTATUS (*notify_watch)(struct sys_notify_context *ctx, const char *dirpath,
				 uint32_t filter, sys_notify_callback_t callback,
				 void *private, void **handle);
};

NTSTATUS sys_notify_register(struct sys_notify_backend *backend);
struct sys_notify_context *sys_notify_init(int snum,
					   TALLOC_CTX *mem_ctx, 
					   struct event_context *ev);
NTSTATUS sys_notify_watch(struct sys_notify_context *ctx, const char *dirpath,
			  uint32_t filter, sys_notify_callback_t callback,
			  void *private, void **handle);

