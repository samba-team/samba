/* 
   Unix SMB/CIFS implementation.
   
   Copyright (C) Stefan Metzmacher	2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "libnet/libnet.h"
#include "lib/events/events.h"

struct libnet_context *libnet_context_init(struct event_context *ev)
{
	struct libnet_context *ctx;

	/* create brand new libnet context */ 
	ctx = talloc(ev, struct libnet_context);
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

	/* name resolution methods */
	ctx->name_res_methods = str_list_copy(ctx, lp_name_resolve_order());

	/* connected services' params */
	ZERO_STRUCT(ctx->samr);
	ZERO_STRUCT(ctx->lsa);	

	/* default buffer size for various operations requiring specifying a buffer */
	ctx->samr.buf_size = 128;

	return ctx;
}
