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
#include "system/network.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/nbt/libnbt.h"
#include "libcli/composite/composite.h"

struct bcast_state {
	struct nbt_name name;
	struct nbt_name_socket *nbtsock;
	int num_queries;
	struct nbt_name_request **queries;
	struct nbt_name_query *io_queries;
	const char *reply_addr;
};

/*
  handle events during broadcast name resolution
*/
static void bcast_handler(struct nbt_name_request *req)
{
	struct smbcli_composite *c = talloc_get_type(req->async.private, 
						     struct smbcli_composite);
	struct bcast_state *state = talloc_get_type(c->private, struct bcast_state);
	int i;

	for (i=0;i<state->num_queries;i++) {
		if (req == state->queries[i]) break;
	}
	if (i == state->num_queries) {
		/* not for us?! */
		c->status = NT_STATUS_INTERNAL_ERROR;
		c->state = SMBCLI_REQUEST_ERROR;		
		goto done;
	} 

	c->status = nbt_name_query_recv(req, state, &state->io_queries[i]);
	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = SMBCLI_REQUEST_ERROR;
	} else {
		c->state = SMBCLI_REQUEST_DONE;
		state->reply_addr = talloc_steal(state, state->io_queries[i].out.reply_addr);
	}

done:
	talloc_free(state->nbtsock);
	if (c->async.fn) {
		c->async.fn(c);
	}
}

/*
  broadcast name resolution method - async send
 */
struct smbcli_composite *resolve_name_bcast_send(struct nbt_name *name, 
						 struct event_context *event_ctx)
{
	struct smbcli_composite *c;
	struct bcast_state *state;
	int i;
	NTSTATUS status;

	c = talloc_zero(NULL, struct smbcli_composite);
	if (c == NULL) goto failed;

	state = talloc(c, struct bcast_state);
	if (state == NULL) goto failed;

	status = nbt_name_dup(state, name, &state->name);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	state->nbtsock = nbt_name_socket_init(state, event_ctx);
	if (state->nbtsock == NULL) goto failed;

	state->num_queries = iface_count();

	state->io_queries = talloc_array(state, struct nbt_name_query, state->num_queries);
	if (!state->io_queries) goto failed;

	state->queries = talloc_array(state, struct nbt_name_request *, state->num_queries);
	if (!state->queries) goto failed;

	for (i=0;i<state->num_queries;i++) {
		struct ipv4_addr *ip = iface_n_bcast(i);
		const char *addr = sys_inet_ntoa(*ip);
		if (!addr) goto failed;

		state->io_queries[i].in.name = state->name;
		state->io_queries[i].in.dest_addr = talloc_strdup(state->io_queries, addr);
		if (!state->io_queries[i].in.dest_addr) goto failed;
		state->io_queries[i].in.broadcast = True;
		state->io_queries[i].in.wins_lookup = False;
		state->io_queries[i].in.timeout = lp_parm_int(-1, "nbt", "bcastTimeout", 5);

		state->queries[i] = nbt_name_query_send(state->nbtsock, &state->io_queries[i]);
		if (!state->queries[i]) goto failed;

		state->queries[i]->async.fn = bcast_handler;
		state->queries[i]->async.private = c;
	}

	c->state = SMBCLI_REQUEST_SEND;
	c->private = state;
	c->event_ctx = talloc_reference(c, state->nbtsock->event_ctx);

	return c;

failed:
	talloc_free(c);
	return NULL;
}

/*
  broadcast name resolution method - recv side
 */
NTSTATUS resolve_name_bcast_recv(struct smbcli_composite *c, 
				 TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	NTSTATUS status;

	status = smb_composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct bcast_state *state = talloc_get_type(c->private, struct bcast_state);
		*reply_addr = talloc_steal(mem_ctx, state->reply_addr);
	}

	talloc_free(c);
	return status;
}

/*
  broadcast name resolution method - sync call
 */
NTSTATUS resolve_name_bcast(struct nbt_name *name, 
			    TALLOC_CTX *mem_ctx,
			    const char **reply_addr)
{
	struct smbcli_composite *c = resolve_name_bcast_send(name, NULL);
	return resolve_name_bcast_recv(c, mem_ctx, reply_addr);
}

