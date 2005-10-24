/* 
   Unix SMB/CIFS implementation.

   implements a non-blocking connect operation that is aware of the samba4
   events system

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Volker Lendecke 2005
   
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
#include "lib/socket/socket.h"
#include "lib/events/events.h"
#include "librpc/gen_ndr/nbt.h"
#include "libcli/composite/composite.h"


struct connect_state {
	struct composite_context *ctx;
	struct socket_context *sock;
	const char *my_address;
	int my_port;
	const char *server_address;
	int server_port;
	uint32_t flags;
	struct fd_event *connect_ev;
};

static void socket_connect_handler(struct event_context *ev,
				   struct fd_event *fde, 
				   uint16_t flags, void *private);
static void socket_connect_recv_addr(struct composite_context *ctx);
static void socket_connect_recv_conn(struct composite_context *ctx);

struct composite_context *socket_connect_send(struct socket_context *sock,
					      const char *my_address,
					      int my_port,
					      const char *server_address,
					      int server_port,
					      uint32_t flags,
					      struct event_context *event_ctx)
{
	struct composite_context *result, *ctx;
	struct connect_state *state;

	result = talloc_zero(NULL, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = event_ctx;

	state = talloc(result, struct connect_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->sock = talloc_reference(state, sock);
	if (state->sock == NULL) goto failed;
	state->my_address = talloc_strdup(state, my_address);
	if (state->sock == NULL) goto failed;
	state->my_port = my_port;
	state->server_address = talloc_strdup(state, server_address);
	if (state->sock == NULL) goto failed;
	state->server_port = server_port;
	state->flags = flags;

	set_blocking(socket_get_fd(sock), False);

	if (strcmp(sock->backend_name, "ipv4") == 0) {
		struct nbt_name name;
		make_nbt_name_client(&name, server_address);
		ctx = resolve_name_send(&name, result->event_ctx,
					lp_name_resolve_order());
		if (ctx == NULL) goto failed;
		ctx->async.fn = socket_connect_recv_addr;
		ctx->async.private_data = state;
		return result;
	}

	ctx = talloc_zero(state, struct composite_context);
	if (ctx == NULL) goto failed;
	ctx->state = COMPOSITE_STATE_IN_PROGRESS;
	ctx->event_ctx = event_ctx;
	ctx->async.fn = socket_connect_recv_conn;
	ctx->async.private_data = state;

	state->ctx->status = socket_connect(sock, my_address, my_port, 
					    server_address, server_port,
					    flags);
	if (NT_STATUS_IS_ERR(state->ctx->status) && 
	    !NT_STATUS_EQUAL(state->ctx->status,
			     NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		composite_trigger_error(state->ctx);
		return result;
	}

	state->connect_ev = event_add_fd(state->ctx->event_ctx, state,
					 socket_get_fd(sock), EVENT_FD_WRITE, 
					 socket_connect_handler, ctx);
	if (state->connect_ev == NULL) {
		state->ctx->status = NT_STATUS_NO_MEMORY;
		composite_trigger_error(state->ctx);
		return result;
	}

	return result;

 failed:
	talloc_free(result);
	return NULL;
}

/*
  handle write events on connect completion
*/
static void socket_connect_handler(struct event_context *ev,
				   struct fd_event *fde, 
				   uint16_t flags, void *private)
{
	struct composite_context *ctx =
		talloc_get_type(private, struct composite_context);
	struct connect_state *state =
		talloc_get_type(ctx->async.private_data,
				struct connect_state);

	ctx->status = socket_connect_complete(state->sock, state->flags);
	if (!composite_is_ok(ctx)) return;

	composite_done(ctx);
}

static void socket_connect_recv_addr(struct composite_context *ctx)
{
	struct connect_state *state =
		talloc_get_type(ctx->async.private_data, struct connect_state);
	const char *addr;

	state->ctx->status = resolve_name_recv(ctx, state, &addr);
	if (!composite_is_ok(state->ctx)) return;

	ctx = talloc_zero(state, struct composite_context);
	if (composite_nomem(ctx, state->ctx)) return;
	ctx->state = COMPOSITE_STATE_IN_PROGRESS;
	ctx->event_ctx = state->ctx->event_ctx;
	ctx->async.fn = socket_connect_recv_conn;
	ctx->async.private_data = state;

	state->ctx->status = socket_connect(state->sock,
					    state->my_address,
					    state->my_port, 
					    state->server_address,
					    state->server_port,
					    state->flags);
	if (NT_STATUS_IS_ERR(state->ctx->status) && 
	    !NT_STATUS_EQUAL(state->ctx->status,
			     NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		composite_error(state->ctx, state->ctx->status);
		return;
	}

	state->connect_ev = event_add_fd(ctx->event_ctx, state,
					 socket_get_fd(state->sock),
					 EVENT_FD_WRITE, 
					 socket_connect_handler, ctx);
	if (composite_nomem(state->connect_ev, state->ctx)) return;

	return;
}

static void socket_connect_recv_conn(struct composite_context *ctx)
{
	struct connect_state *state =
		talloc_get_type(ctx->async.private_data, struct connect_state);

	state->ctx->status = ctx->status;
	if (!composite_is_ok(state->ctx)) return;

	/* We have to free the event context here because the continuation
	 * function might add an event for this socket directly. */
	talloc_free(state->connect_ev);

	composite_done(state->ctx);
}

NTSTATUS socket_connect_recv(struct composite_context *ctx)
{
	NTSTATUS status = composite_wait(ctx);
	talloc_free(ctx);
	return status;
}

NTSTATUS socket_connect_ev(struct socket_context *sock,
			   const char *my_address, int my_port,
			   const char *server_address, int server_port,
			   uint32_t flags, struct event_context *ev)
{
	struct composite_context *ctx;
	ctx = socket_connect_send(sock, my_address, my_port,
				  server_address, server_port, flags, ev);
	return socket_connect_recv(ctx);
}
