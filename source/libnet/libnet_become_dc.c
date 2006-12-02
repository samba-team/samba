/*
   Unix SMB/CIFS implementation.

   Copyright (C) Stefan Metzmacher	2006

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
#include "libcli/composite/composite.h"

struct composite_context *libnet_BecomeDC_send(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	struct composite_context *c;

	c = composite_create(mem_ctx, ctx->event_ctx);
	if (c == NULL) return NULL;

	composite_error(c, NT_STATUS_NOT_IMPLEMENTED);
	return c;
}

NTSTATUS libnet_BecomeDC_recv(struct composite_context *c, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	NTSTATUS status;

	status = composite_wait(c);

	talloc_free(c);
	return status;
}

NTSTATUS libnet_BecomeDC(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	NTSTATUS status;
	struct composite_context *c;
	c = libnet_BecomeDC_send(ctx, mem_ctx, r);
	status = libnet_BecomeDC_recv(c, mem_ctx, r);
	return status;
}
