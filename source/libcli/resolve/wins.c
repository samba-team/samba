/* 
   Unix SMB/CIFS implementation.

   wins name resolution module

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
#include "libcli/nbt/libnbt.h"
#include "libcli/resolve/resolve.h"

/*
  wins name resolution method - async send
 */
struct composite_context *resolve_name_wins_send(TALLOC_CTX *mem_ctx, 
						 struct event_context *event_ctx,
						 struct nbt_name *name)
{
	const char **address_list = lp_wins_server_list();
	if (address_list == NULL) return NULL;
	return resolve_name_nbtlist_send(mem_ctx, event_ctx, name, address_list, False, True);
}

/*
  wins name resolution method - recv side
 */
NTSTATUS resolve_name_wins_recv(struct composite_context *c, 
				TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	return resolve_name_nbtlist_recv(c, mem_ctx, reply_addr);
}

/*
  wins name resolution method - sync call
 */
NTSTATUS resolve_name_wins(struct nbt_name *name, 
			    TALLOC_CTX *mem_ctx,
			    const char **reply_addr)
{
	struct composite_context *c = resolve_name_wins_send(mem_ctx, NULL, name);
	return resolve_name_wins_recv(c, mem_ctx, reply_addr);
}

