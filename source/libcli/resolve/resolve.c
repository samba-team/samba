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

struct resolve_state {
	struct nbt_name name;
	const char **methods;
	struct smbcli_composite *req;
	const char *reply_addr;
};

static struct smbcli_composite *setup_next_method(struct smbcli_composite *c);

/*
  handle completion of one name resolve method
*/
static void resolve_handler(struct smbcli_composite *req)
{
	struct smbcli_composite *c = req->async.private;
	struct resolve_state *state = talloc_get_type(c->private, struct resolve_state);
	const char *method = state->methods[0];

	if (strcasecmp(method, "bcast")) {
		c->status = resolve_name_bcast_recv(req, state, &state->reply_addr);
	} else if (strcasecmp(method, "wins")) {
		c->status = resolve_name_wins_recv(req, state, &state->reply_addr);
	} else {
		c->status = NT_STATUS_INTERNAL_ERROR;
	}
	
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


static struct smbcli_composite *setup_next_method(struct smbcli_composite *c)
{
	struct resolve_state *state = talloc_get_type(c->private, struct resolve_state);
	const char *method;
	struct smbcli_composite *req = NULL;

	do {
		method = state->methods[0];
		if (method == NULL) break;
		if (strcasecmp(method, "bcast")) {
			req = resolve_name_bcast_send(&state->name, c->event_ctx);
		} else if (strcasecmp(method, "wins")) {
			req = resolve_name_wins_send(&state->name, c->event_ctx);
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
struct smbcli_composite *resolve_name_send(struct nbt_name *name, struct event_context *event_ctx)
{
	struct smbcli_composite *c;
	struct resolve_state *state;
	NTSTATUS status;

	c = talloc_zero(NULL, struct smbcli_composite);
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
	c->event_ctx = talloc_reference(c, event_ctx);

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
NTSTATUS resolve_name_recv(struct smbcli_composite *c, 
			   TALLOC_CTX *mem_ctx, const char **reply_addr)
{
	NTSTATUS status;

	status = smb_composite_wait(c);

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
	struct smbcli_composite *c = resolve_name_send(name, NULL);
	return resolve_name_recv(c, mem_ctx, reply_addr);
}
