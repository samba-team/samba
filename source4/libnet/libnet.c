/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   
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
#include "libnet/libnet.h"
#include "lib/events/events.h"

struct libnet_context *libnet_context_init(struct event_context *ev)
{
	/* default name resolution methods */
	const char *nr_methods[] = { "lmhosts", "wins", "host", "bcast", NULL };
	int nr_count = 0, nr_i;

	struct libnet_context *ctx;

	/* create brand new libnet context */ 
	ctx = talloc(NULL, struct libnet_context);
	if (!ctx) {
		return NULL;
	}

	/* events */
	if (ev == NULL) {
		ev = event_context_find(ctx);
		if (ev == NULL) {
			talloc_free(ctx);
			return NULL;
		}
	}
	ctx->event_ctx = ev;

	/* count name resolution methods */
	while (nr_methods[nr_count]) nr_count++;

	/* assign name resolution methods */
	ctx->name_res_methods = talloc_array(ctx, char*, nr_count+1);
	for (nr_i = 0; nr_i < nr_count; nr_i++) {
		ctx->name_res_methods[nr_i] = talloc_strdup(ctx, nr_methods[nr_i]);
	}
	ctx->name_res_methods[nr_i] = NULL;
	
	return ctx;
}
