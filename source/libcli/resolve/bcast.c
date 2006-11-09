/* 
   Unix SMB/CIFS implementation.

   broadcast name resolution module

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
#include "libcli/resolve/resolve.h"
#include "system/network.h"
#include "lib/socket/netif.h"

/*
  broadcast name resolution method - async send
 */
struct composite_context *resolve_name_bcast_send(TALLOC_CTX *mem_ctx, 
						  struct event_context *event_ctx,
						  struct nbt_name *name)
{
	int num_interfaces = iface_count();
	const char **address_list;
	struct composite_context *c;
	int i, count=0;

	address_list = talloc_array(mem_ctx, const char *, num_interfaces+1);
	if (address_list == NULL) return NULL;

	for (i=0;i<num_interfaces;i++) {
		const char *bcast = iface_n_bcast(i);
		if (bcast == NULL) continue;
		address_list[count] = talloc_strdup(address_list, bcast);
		if (address_list[count] == NULL) {
			talloc_free(address_list);
			return NULL;
		}
		count++;
	}
	address_list[count] = NULL;

	c = resolve_name_nbtlist_send(mem_ctx, event_ctx, name, address_list, True, False);
	talloc_free(address_list);

	return c;	
}

/*
  broadcast name resolution method - recv side
 */
NTSTATUS resolve_name_bcast_recv(struct composite_context *c, 
				 TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	return resolve_name_nbtlist_recv(c, mem_ctx, reply_addr);
}

/*
  broadcast name resolution method - sync call
 */
NTSTATUS resolve_name_bcast(struct nbt_name *name, 
			    TALLOC_CTX *mem_ctx,
			    const char **reply_addr)
{
	struct composite_context *c = resolve_name_bcast_send(mem_ctx, NULL, name);
	return resolve_name_bcast_recv(c, mem_ctx, reply_addr);
}

