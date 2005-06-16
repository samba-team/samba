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
	struct libnet_context *ctx;

	ctx = talloc(NULL, struct libnet_context);
	if (!ctx) {
		return NULL;
	}

	if (ev == NULL) {
		ev = event_context_init(ctx);
		if (ev == NULL) {
			talloc_free(ctx);
			return NULL;
		}
	}
	ctx->event_ctx = ev;

	return ctx;
}

