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

struct libnet_context *libnet_context_init(void)
{
	TALLOC_CTX *mem_ctx;
	struct libnet_context *ctx;

	mem_ctx = talloc_init("libnet_context");

	ctx = talloc_p(mem_ctx, struct libnet_context);
	if (!ctx) {
		return NULL;
	}

	ctx->mem_ctx = mem_ctx;

	return ctx;
}

void libnet_context_destroy(struct libnet_context **libnetctx)
{
	talloc_destroy((*libnetctx)->mem_ctx);

	(*libnetctx) = NULL;
}
