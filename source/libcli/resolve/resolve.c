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
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"

struct resolve_state {
	struct nbt_name name;
	const char **methods;
	struct composite_context *req;
	const char *reply_addr;
};

static struct composite_context *setup_next_method(struct composite_context *c);

/* pointers to the resolver backends */
static const struct resolve_method {
	const char *name;
	struct composite_context *(*send_fn)(struct nbt_name *, struct event_context *);
	NTSTATUS (*recv_fn)(struct composite_context *, TALLOC_CTX *, const char **);
} methods[] = {
	{ "bcast", resolve_name_bcast_send, resolve_name_bcast_recv },
	{ "wins",  resolve_name_wins_send, resolve_name_wins_recv },
	{ "host",  resolve_name_host_send, resolve_name_host_recv }
};


/* 
   find a matching backend
*/
static const struct resolve_method *find_method(const char *name)
{
	int i;
	if (name == NULL) return NULL;
	for (i=0;i<ARRAY_SIZE(methods);i++) {
		if (strcasecmp(name, methods[i].name) == 0) {
			return &methods[i];
		}
	}
	return NULL;
}

/*
  handle completion of one name resolve method
*/
static void resolve_handler(struct composite_context *req)
{
	struct composite_context *c = req->async.private;
	struct resolve_state *state = talloc_get_type(c->private, struct resolve_state);
	const struct resolve_method *method = find_method(state->methods[0]);

	c->status = method->recv_fn(req, state, &state->reply_addr);
	
	if (!NT_STATUS_IS_OK(c->status)) {
		state->methods++;
		state->req = setup_next_method(c);
		if (state->req != NULL) {
			return;
		}
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = SMBCLI_REQUEST_ERROR;
	} else {
		c->state = SMBCLI_REQUEST_DONE;
	}
	if (c->async.fn) {
		c->async.fn(c);
	}
}


static struct composite_context *setup_next_method(struct composite_context *c)
{
	struct resolve_state *state = talloc_get_type(c->private, struct resolve_state);
	struct composite_context *req = NULL;

	do {
		const struct resolve_method *method = find_method(state->methods[0]);
		if (method) {
			req = method->send_fn(&state->name, c->event_ctx);
		}
		if (req == NULL) state->methods++;
	} while (!req && state->methods[0]);

	if (req) {
		req->async.fn = resolve_handler;
		req->async.private = c;
	}

	return req;
}

/*
  general name resolution - async send
 */
struct composite_context *resolve_name_send(struct nbt_name *name, struct event_context *event_ctx)
{
	struct composite_context *c;
	struct resolve_state *state;
	NTSTATUS status;

	c = talloc_zero(NULL, struct composite_context);
	if (c == NULL) goto failed;

	state = talloc(c, struct resolve_state);
	if (state == NULL) goto failed;

	status = nbt_name_dup(state, name, &state->name);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	state->methods = lp_name_resolve_order();
	if (state->methods == NULL) {
		return NULL;
	}

	c->state = SMBCLI_REQUEST_SEND;
	c->private = state;
	if (event_ctx == NULL) {
		c->event_ctx = event_context_init(c);
		if (c->event_ctx == NULL) goto failed;
	} else {
		c->event_ctx = talloc_reference(c, event_ctx);
	}

	state->req = setup_next_method(c);
	if (state->req == NULL) goto failed;
	
	return c;

failed:
	talloc_free(c);
	return NULL;
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
		struct resolve_state *state = talloc_get_type(c->private, struct resolve_state);
		*reply_addr = talloc_steal(mem_ctx, state->reply_addr);
	}

	talloc_free(c);
	return status;
}

/*
  general name resolution - sync call
 */
NTSTATUS resolve_name(struct nbt_name *name, TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	struct composite_context *c = resolve_name_send(name, NULL);
	return resolve_name_recv(c, mem_ctx, reply_addr);
}
