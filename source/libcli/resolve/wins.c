/* 
   Unix SMB/CIFS implementation.

   wins name resolution module

   Copyright (C) Andrew Tridgell 2005
   
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
#include "libcli/nbt/libnbt.h"
#include "libcli/resolve/resolve.h"
#include "param/param.h"

struct resolve_wins_data {
	const char **address_list;
};

/**
  wins name resolution method - async send
 */
struct composite_context *resolve_name_wins_send(
				TALLOC_CTX *mem_ctx, 
				struct event_context *event_ctx,
				void *userdata,
				struct nbt_name *name)
{
	struct resolve_wins_data *wins_data = talloc_get_type(userdata, struct resolve_wins_data);
	if (wins_data->address_list == NULL) return NULL;
	return resolve_name_nbtlist_send(mem_ctx, event_ctx, name, wins_data->address_list, false, true);
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
			    const char **address_list,
			    const char **reply_addr)
{
	struct composite_context *c;
	struct resolve_wins_data *wins_data = talloc(mem_ctx, struct resolve_wins_data);
	wins_data->address_list = address_list;
	c = resolve_name_wins_send(mem_ctx, NULL, wins_data, name);
	return resolve_name_wins_recv(c, mem_ctx, reply_addr);
}

bool resolve_context_add_wins_method(struct resolve_context *ctx, const char **address_list)
{
	struct resolve_wins_data *wins_data = talloc(ctx, struct resolve_wins_data);
	wins_data->address_list = str_list_copy(wins_data, address_list);
	return resolve_context_add_method(ctx, resolve_name_wins_send, resolve_name_wins_recv,
					  wins_data);
}
