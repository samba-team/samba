/* 
   Unix SMB/CIFS implementation.

   general name resolution interface

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"

/*
  general name resolution - async send
 */
struct smbcli_composite *resolve_name_send(struct nbt_name *name, struct event_context *event_ctx)
{
	return resolve_name_bcast_send(name, event_ctx);
}

/*
  general name resolution method - recv side
 */
NTSTATUS resolve_name_recv(struct smbcli_composite *c, 
			   TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	return resolve_name_bcast_recv(c, mem_ctx, reply_addr);
}

/*
  general name resolution - sync call
 */
NTSTATUS resolve_name(struct nbt_name *name, TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	struct smbcli_composite *c = resolve_name_send(name, NULL);
	return resolve_name_recv(c, mem_ctx, reply_addr);
}
