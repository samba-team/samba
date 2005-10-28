/* 
   Unix SMB/CIFS implementation.

   Fire connect requests to a host and a number of ports, with a timeout
   between the connect request. Return if the first connect comes back
   successfully or return the last error.

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
#include "libcli/composite/composite.h"


struct connect_multi_state {
	struct composite_context *ctx;
	const char *server_address;
	int num_ports;
	uint16_t *ports;

	struct socket_context *result;
	uint16_t result_port;

	int num_connects_sent, num_connects_in_fly;
	struct fd_event **write_events;
	struct socket_context **sockets;
	struct timed_event *next_timeout;
};

static void connect_multi_connect_handler(struct event_context *ev,
					  struct fd_event *fde, 
					  uint16_t flags, void *p);
static NTSTATUS connect_multi_next_socket(struct connect_multi_state *state);
static void connect_multi_fire_next(struct event_context *ev,
				    struct timed_event *te,
				    struct timeval tv, void *p);

struct composite_context *socket_connect_multi_send(TALLOC_CTX *mem_ctx,
						    const char *server_address,
						    int num_server_ports,
						    uint16_t *server_ports,
						    struct event_context *event_ctx)
{
	struct composite_context *result;
	struct connect_multi_state *state;
	int i;

	result = talloc_zero(mem_ctx, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->event_ctx = event_ctx;

	state = talloc(result, struct connect_multi_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->server_address = talloc_strdup(state, server_address);
	if (state->server_address == NULL) goto failed;

	state->num_ports = num_server_ports;
	state->ports = talloc_array(state, uint16_t, state->num_ports);
	if (state->ports == NULL) goto failed;

	for (i=0; i<state->num_ports; i++) {
		state->ports[i] = server_ports[i];
	}

	state->sockets =
		talloc_array(state, struct socket_context *, state->num_ports);
	if (state->sockets == NULL) goto failed;

	state->write_events =
		talloc_array(state, struct fd_event *, state->num_ports);
	if (state->write_events == NULL) goto failed;

	state->num_connects_sent = 0;
	state->num_connects_in_fly = 0;

	result->status = connect_multi_next_socket(state);

	if (!NT_STATUS_IS_OK(result->status)) {
		composite_trigger_error(result);
		return result;
	}

	return result;

 failed:
	talloc_free(result);
	return NULL;
}

static NTSTATUS connect_multi_next_socket(struct connect_multi_state *state)
{
	NTSTATUS status;
	int res, next = state->num_connects_sent;

	status = socket_create("ipv4", SOCKET_TYPE_STREAM,
			       &state->sockets[next], 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	res = set_blocking(socket_get_fd(state->sockets[next]), False);
	if (res != 0) {
		return map_nt_error_from_unix(errno);
	}

	talloc_steal(state->sockets, state->sockets[next]);

	status = socket_connect(state->sockets[next], NULL, 0,
				state->server_address, state->ports[next], 0);

	if (!NT_STATUS_IS_OK(status) &&
	    !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		return status;
	}
	
	state->write_events[next] =
		event_add_fd(state->ctx->event_ctx, state->write_events,
			     socket_get_fd(state->sockets[next]),
			     EVENT_FD_WRITE,
			     connect_multi_connect_handler, state);

	if (state->write_events[next] == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	state->num_connects_sent += 1;
	state->num_connects_in_fly += 1;

	if (state->num_ports > state->num_connects_sent) {
		state->next_timeout =
			event_add_timed(state->ctx->event_ctx, state,
					timeval_current_ofs(0, 2000),
					connect_multi_fire_next, state);
		if (state->next_timeout == NULL) {
			talloc_free(state->sockets[next]);
			state->sockets[next] = NULL;
			talloc_free(state->write_events[next]);
			state->write_events[next] = NULL;
			return NT_STATUS_NO_MEMORY;
		}
	}

	return NT_STATUS_OK;
}

static void connect_multi_fire_next(struct event_context *ev,
				    struct timed_event *te,
				    struct timeval tv, void *p)
{
	struct connect_multi_state *state =
		talloc_get_type(p, struct connect_multi_state);

	state->ctx->status = connect_multi_next_socket(state);
	if (!composite_is_ok(state->ctx)) return;
}

static void connect_multi_connect_handler(struct event_context *ev,
					  struct fd_event *fde, 
					  uint16_t flags, void *p)
{
	struct connect_multi_state *state =
		talloc_get_type(p, struct connect_multi_state);
	int i;

	for (i=0; i<state->num_connects_sent; i++) {
		if (fde == state->write_events[i]) {
			break;
		}
	}

	if (i == state->num_connects_sent) {
		composite_error(state->ctx, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	state->num_connects_in_fly -= 1;

	state->ctx->status = socket_connect_complete(state->sockets[i], 0);
	if (NT_STATUS_IS_OK(state->ctx->status)) {
		state->result = talloc_steal(state, state->sockets[i]);
		state->result_port = state->ports[i];
		talloc_free(state->sockets);
		state->sockets = NULL;
		talloc_free(state->write_events);
		state->write_events = NULL;
		composite_done(state->ctx);
		return;
	}

	talloc_free(state->sockets[i]);
	state->sockets[i] = NULL;

	if ((state->num_connects_in_fly == 0) &&
	    (state->num_connects_sent == state->num_ports)) {
		composite_error(state->ctx, state->ctx->status);
		return;
	}

	if (state->num_connects_in_fly != 0) {
		/* Waiting for something to happen on the net or the next
		 * timeout to trigger */
		return;
	}

	SMB_ASSERT(state->num_connects_sent < state->num_ports);
	SMB_ASSERT(state->next_timeout != NULL);

	/* There are ports left but nothing on the net, so trigger the next
	 * one immediately. */
	talloc_free(state->next_timeout);
	state->next_timeout =
		event_add_timed(state->ctx->event_ctx, state, timeval_zero(),
				connect_multi_fire_next, state);
	if (composite_nomem(state->next_timeout, state->ctx)) return;
}

NTSTATUS socket_connect_multi_recv(struct composite_context *ctx,
				   TALLOC_CTX *mem_ctx,
				   struct socket_context **result,
				   uint16_t *port)
{
	NTSTATUS status = composite_wait(ctx);
	if (NT_STATUS_IS_OK(status)) {
		struct connect_multi_state *state =
			talloc_get_type(ctx->private_data,
					struct connect_multi_state);
		*result = talloc_steal(mem_ctx, state->result);
		*port = state->result_port;
	}
	talloc_free(ctx);
	return status;
}

NTSTATUS socket_connect_multi(TALLOC_CTX *mem_ctx,
			      const char *server_address,
			      int num_server_ports, uint16_t *server_ports,
			      struct event_context *event_ctx,
			      struct socket_context **result,
			      uint16_t *result_port)
{
	struct composite_context *ctx =
		socket_connect_multi_send(mem_ctx, server_address,
					  num_server_ports, server_ports,
					  event_ctx);
	return socket_connect_multi_recv(ctx, mem_ctx, result, result_port);
}
