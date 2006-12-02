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

struct composite_context *libnet_BecomeDC_send(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	return NULL;
}

NTSTATUS libnet_BecomeDC_recv(struct composite_context *c, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS libnet_BecomeDC(struct libnet_context *ctx, TALLOC_CTX *mem_ctx, struct libnet_BecomeDC *r)
{
	NTSTATUS status;
	struct composite_context *c;
	c = libnet_BecomeDC_send(ctx, mem_ctx, r);
	status = libnet_BecomeDC_recv(c, mem_ctx, r);
	return status;
}
