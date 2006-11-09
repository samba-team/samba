/* 
   Unix SMB/CIFS implementation.

   nbt list of addresses name resolution module

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

/*
  TODO: we should lower the timeout, and add retries for each name
*/

#include "includes.h"
#include "libcli/composite/composite.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "librpc/gen_ndr/ndr_nbt.h"
#include "libcli/nbt/libnbt.h"

struct nbtlist_state {
	struct nbt_name name;
	struct nbt_name_socket *nbtsock;
	int num_queries;
	struct nbt_name_request **queries;
	struct nbt_name_query *io_queries;
	const char *reply_addr;
};

/*
  handle events during nbtlist name resolution
*/
static void nbtlist_handler(struct nbt_name_request *req)
{
	struct composite_context *c = talloc_get_type(req->async.private, 
						      struct composite_context);
	struct nbtlist_state *state = talloc_get_type(c->private_data, struct nbtlist_state);
	struct nbt_name_query *q;
	int i;

	for (i=0;i<state->num_queries;i++) {
		if (req == state->queries[i]) break;
	}

	if (i == state->num_queries) {
		/* not for us?! */
		composite_error(c, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	q = &state->io_queries[i];

	c->status = nbt_name_query_recv(req, state, q);

	/* free the network resource directly */
	talloc_free(state->nbtsock);
	if (!composite_is_ok(c)) return;

	if (state->io_queries[i].out.num_addrs < 1) {
		composite_error(c, NT_STATUS_UNEXPECTED_NETWORK_ERROR);
		return;
	}

	/* favor a local address if possible */
	state->reply_addr = NULL;
	for (i=0;i<q->out.num_addrs;i++) {
		if (iface_is_local(q->out.reply_addrs[i])) {
			state->reply_addr = talloc_steal(state, 
							 q->out.reply_addrs[i]);
			break;
		}
	}

	if (state->reply_addr == NULL) {
		state->reply_addr = talloc_steal(state, 
						 q->out.reply_addrs[0]);
	}

	composite_done(c);
}

/*
  nbtlist name resolution method - async send
 */
struct composite_context *resolve_name_nbtlist_send(TALLOC_CTX *mem_ctx,
						    struct event_context *event_ctx,
						    struct nbt_name *name, 
						    const char **address_list,
						    BOOL broadcast,
						    BOOL wins_lookup)
{
	struct composite_context *c;
	struct nbtlist_state *state;
	int i;

	c = composite_create(event_ctx, event_ctx);
	if (c == NULL) return NULL;

	c->event_ctx = talloc_reference(c, event_ctx);
	if (composite_nomem(c->event_ctx, c)) return c;

	state = talloc(c, struct nbtlist_state);
	if (composite_nomem(state, c)) return c;
	c->private_data = state;

	c->status = nbt_name_dup(state, name, &state->name);
	if (!composite_is_ok(c)) return c;

	state->name.name = strupper_talloc(state, state->name.name);
	if (composite_nomem(state->name.name, c)) return c;
	if (state->name.scope) {
		state->name.scope = strupper_talloc(state, state->name.scope);
		if (composite_nomem(state->name.scope, c)) return c;
	}

	state->nbtsock = nbt_name_socket_init(state, event_ctx);
	if (composite_nomem(state->nbtsock, c)) return c;

	/* count the address_list size */
	for (i=0;address_list[i];i++) /* noop */ ;

	state->num_queries = i;
	state->io_queries = talloc_array(state, struct nbt_name_query, state->num_queries);
	if (composite_nomem(state->io_queries, c)) return c;

	state->queries = talloc_array(state, struct nbt_name_request *, state->num_queries);
	if (composite_nomem(state->queries, c)) return c;

	for (i=0;i<state->num_queries;i++) {
		state->io_queries[i].in.name        = state->name;
		state->io_queries[i].in.dest_addr   = talloc_strdup(state->io_queries, address_list[i]);
		if (composite_nomem(state->io_queries[i].in.dest_addr, c)) return c;

		state->io_queries[i].in.broadcast   = broadcast;
		state->io_queries[i].in.wins_lookup = wins_lookup;
		state->io_queries[i].in.timeout     = lp_parm_int(-1, "nbt", "timeout", 1);
		state->io_queries[i].in.retries     = 2;

		state->queries[i] = nbt_name_query_send(state->nbtsock, &state->io_queries[i]);
		if (composite_nomem(state->queries[i], c)) return c;

		state->queries[i]->async.fn      = nbtlist_handler;
		state->queries[i]->async.private = c;
	}

	return c;
}

/*
  nbt list of addresses name resolution method - recv side
 */
NTSTATUS resolve_name_nbtlist_recv(struct composite_context *c, 
				   TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct nbtlist_state *state = talloc_get_type(c->private_data, struct nbtlist_state);
		*reply_addr = talloc_steal(mem_ctx, state->reply_addr);
	}

	talloc_free(c);
	return status;
}

/*
  nbt list of addresses name resolution method - sync call
 */
NTSTATUS resolve_name_nbtlist(struct nbt_name *name, 
			      TALLOC_CTX *mem_ctx,
			      const char **address_list,
			      BOOL broadcast, BOOL wins_lookup,
			      const char **reply_addr)
{
	struct composite_context *c = resolve_name_nbtlist_send(mem_ctx, NULL, name, address_list, 
							        broadcast, wins_lookup);
	return resolve_name_nbtlist_recv(c, mem_ctx, reply_addr);
}

