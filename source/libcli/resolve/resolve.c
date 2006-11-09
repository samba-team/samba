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
#include "lib/events/events.h"
#include "libcli/composite/composite.h"
#include "libcli/resolve/resolve.h"
#include "librpc/gen_ndr/ndr_nbt.h"

struct resolve_state {
	struct nbt_name name;
	const char **methods;
	struct composite_context *creq;
	const char *reply_addr;
};

static struct composite_context *setup_next_method(struct composite_context *c);

/* pointers to the resolver backends */
static const struct resolve_method {
	const char *name;
	struct composite_context *(*send_fn)(TALLOC_CTX *mem_ctx, struct event_context *, struct nbt_name *);
	NTSTATUS (*recv_fn)(struct composite_context *, TALLOC_CTX *, const char **);

} resolve_methods[] = {
	{ "bcast", resolve_name_bcast_send,  resolve_name_bcast_recv },
	{ "wins",  resolve_name_wins_send,   resolve_name_wins_recv },
	{ "host",  resolve_name_host_send,   resolve_name_host_recv }
};


/* 
   find a matching backend
*/
static const struct resolve_method *find_method(const char *name)
{
	int i;
	if (name == NULL) return NULL;
	for (i=0;i<ARRAY_SIZE(resolve_methods);i++) {
		if (strcasecmp(name, resolve_methods[i].name) == 0) {
			return &resolve_methods[i];
		}
	}
	return NULL;
}

/*
  handle completion of one name resolve method
*/
static void resolve_handler(struct composite_context *creq)
{
	struct composite_context *c = creq->async.private_data;
	struct resolve_state *state = talloc_get_type(c->private_data, struct resolve_state);
	const struct resolve_method *method = find_method(state->methods[0]);

	c->status = method->recv_fn(creq, state, &state->reply_addr);
	
	if (!NT_STATUS_IS_OK(c->status)) {
		state->methods++;
		state->creq = setup_next_method(c);
		if (state->creq != NULL) {
			return;
		}
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	} else {
		c->state = COMPOSITE_STATE_DONE;
	}
	if (c->async.fn) {
		c->async.fn(c);
	}
}


static struct composite_context *setup_next_method(struct composite_context *c)
{
	struct resolve_state *state = talloc_get_type(c->private_data, struct resolve_state);
	struct composite_context *creq = NULL;

	do {
		const struct resolve_method *method = find_method(state->methods[0]);
		if (method) {
			creq = method->send_fn(c, c->event_ctx, &state->name);
		}
		if (creq == NULL && state->methods[0]) state->methods++;

	} while (!creq && state->methods[0]);

	if (creq) {
		creq->async.fn = resolve_handler;
		creq->async.private_data = c;
	}

	return creq;
}

/*
  general name resolution - async send
 */
struct composite_context *resolve_name_send(struct nbt_name *name, struct event_context *event_ctx,
					    const char **methods)
{
	struct composite_context *c;
	struct resolve_state *state;

	c = composite_create(event_ctx, event_ctx);
	if (c == NULL) return NULL;

	if (methods == NULL) {
		composite_error(c, NT_STATUS_INVALID_PARAMETER);
		return c;
	}

	if (event_ctx == NULL) {
		c->event_ctx = event_context_init(c);
	} else {
		c->event_ctx = talloc_reference(c, event_ctx);
	}
	if (composite_nomem(c->event_ctx, c)) return c;

	state = talloc(c, struct resolve_state);
	if (composite_nomem(state, c)) return c;
	c->private_data = state;

	c->status = nbt_name_dup(state, name, &state->name);
	if (!composite_is_ok(c)) return c;
	
	state->methods = str_list_copy(state, methods);
	if (composite_nomem(state->methods, c)) return c;

	if (is_ipaddress(state->name.name) || 
	    strcasecmp(state->name.name, "localhost") == 0) {
		struct ipv4_addr ip = interpret_addr2(state->name.name);
		state->reply_addr = talloc_strdup(state, sys_inet_ntoa(ip));
		if (composite_nomem(state->reply_addr, c)) return c;
		composite_done(c);
		return c;
	}

	state->creq = setup_next_method(c);
	if (composite_nomem(state->creq, c)) return c;
	
	return c;
}

/*
  general name resolution method - recv side
 */
NTSTATUS resolve_name_recv(struct composite_context *c, 
			   TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct resolve_state *state = talloc_get_type(c->private_data, struct resolve_state);
		*reply_addr = talloc_steal(mem_ctx, state->reply_addr);
	}

	talloc_free(c);
	return status;
}

/*
  general name resolution - sync call
 */
NTSTATUS resolve_name(struct nbt_name *name, TALLOC_CTX *mem_ctx, const char **reply_addr, 
		      struct event_context *ev)
{
	struct composite_context *c = resolve_name_send(name, ev, lp_name_resolve_order());
	return resolve_name_recv(c, mem_ctx, reply_addr);
}

/* Initialise a struct nbt_name with a NULL scope */

void make_nbt_name(struct nbt_name *nbt, const char *name, int type)
{
	nbt->name = name;
	nbt->scope = NULL;
	nbt->type = type;
}

/* Initialise a struct nbt_name with a NBT_NAME_CLIENT (0x00) name */

void make_nbt_name_client(struct nbt_name *nbt, const char *name)
{
	make_nbt_name(nbt, name, NBT_NAME_CLIENT);
}

/* Initialise a struct nbt_name with a NBT_NAME_SERVER (0x20) name */

void make_nbt_name_server(struct nbt_name *nbt, const char *name)
{
	make_nbt_name(nbt, name, NBT_NAME_SERVER);
}
