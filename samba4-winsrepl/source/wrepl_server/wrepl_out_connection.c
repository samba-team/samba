/* 
   Unix SMB/CIFS implementation.
   
   WINS Replication server
   
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_winsrepl.h"
#include "wrepl_server/wrepl_server.h"
#include "nbt_server/wins/winsdb.h"
#include "ldb/include/ldb.h"
#include "libcli/composite/composite.h"
#include "libcli/wrepl/winsrepl.h"

enum wreplsrv_out_connect_stage {
	WREPLSRV_OUT_CONNECT_STAGE_WAIT_SOCKET,
	WREPLSRV_OUT_CONNECT_STAGE_WAIT_ASSOC_CTX,
	WREPLSRV_OUT_CONNECT_STAGE_DONE
};

struct wreplsrv_out_connect_state {
	enum wreplsrv_out_connect_stage stage;
	struct composite_context *c;
	struct wrepl_request *req;
	struct wrepl_associate assoc_io;
	struct wreplsrv_out_connection *wreplconn;
};

static void wreplsrv_out_connect_handler(struct wrepl_request *req);

static NTSTATUS wreplsrv_out_connect_wait_socket(struct wreplsrv_out_connect_state *state)
{
	NTSTATUS status;

	status = wrepl_connect_recv(state->req);
	NT_STATUS_NOT_OK_RETURN(status);

	state->req = wrepl_associate_send(state->wreplconn->sock, &state->assoc_io);
	NT_STATUS_HAVE_NO_MEMORY(state->req);

	state->req->async.fn		= wreplsrv_out_connect_handler;
	state->req->async.private	= state;

	state->stage = WREPLSRV_OUT_CONNECT_STAGE_WAIT_ASSOC_CTX;

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_out_connect_wait_assoc_ctx(struct wreplsrv_out_connect_state *state)
{
	NTSTATUS status;

	status = wrepl_associate_recv(state->req, &state->assoc_io);
	NT_STATUS_NOT_OK_RETURN(status);

	state->wreplconn->assoc_ctx.peer_ctx = state->assoc_io.out.assoc_ctx;

	state->wreplconn->partner->pull.wreplconn = state->wreplconn;
	talloc_steal(state->wreplconn->partner, state->wreplconn);

	state->stage = WREPLSRV_OUT_CONNECT_STAGE_DONE;

	return NT_STATUS_OK;
}

static void wreplsrv_out_connect_handler(struct wrepl_request *req)
{
	struct wreplsrv_out_connect_state *state = talloc_get_type(req->async.private,
						   struct wreplsrv_out_connect_state);
	struct composite_context *c = state->c;

	switch (state->stage) {
	case WREPLSRV_OUT_CONNECT_STAGE_WAIT_SOCKET:
		c->status = wreplsrv_out_connect_wait_socket(state);
		break;
	case WREPLSRV_OUT_CONNECT_STAGE_WAIT_ASSOC_CTX:
		c->status = wreplsrv_out_connect_wait_assoc_ctx(state);
		c->state  = COMPOSITE_STATE_DONE;
		break;
	case WREPLSRV_OUT_CONNECT_STAGE_DONE:
		c->status = NT_STATUS_INTERNAL_ERROR;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}

	if (c->state >= COMPOSITE_STATE_DONE && c->async.fn) {
		c->async.fn(c);
	}
}

static struct composite_context *wreplsrv_out_connect_send(struct wreplsrv_partner *partner)
{
	struct composite_context *c = NULL;
	struct wreplsrv_service *service = partner->service;
	struct wreplsrv_out_connect_state *state = NULL;
	struct wreplsrv_out_connection *wreplconn;

	c = talloc_zero(partner, struct composite_context);
	if (!c) goto failed;

	state = talloc_zero(c, struct wreplsrv_out_connect_state);
	if (!state) goto failed;
	state->c	= c;

	c->state	= COMPOSITE_STATE_IN_PROGRESS;
	c->event_ctx	= service->task->event_ctx;
	c->private_data	= state;

	/* we have a connection already, so use it */
	if (partner->pull.wreplconn) {
		if (!partner->pull.wreplconn->sock->dead) {
			state->stage	= WREPLSRV_OUT_CONNECT_STAGE_DONE;
			state->wreplconn= partner->pull.wreplconn;
			composite_trigger_done(c);
			return c;
		} else {
			talloc_free(partner->pull.wreplconn);
			partner->pull.wreplconn = NULL;
		}
	}

	wreplconn = talloc_zero(state, struct wreplsrv_out_connection);
	if (!wreplconn) goto failed;

	wreplconn->service	= service;
	wreplconn->partner	= partner;
	wreplconn->sock		= wrepl_socket_init(wreplconn, service->task->event_ctx);
	if (!wreplconn->sock) goto failed;

	state->stage	= WREPLSRV_OUT_CONNECT_STAGE_WAIT_SOCKET;
	state->wreplconn= wreplconn;
	state->req	= wrepl_connect_send(wreplconn->sock,
					     partner->address
					     /*, partner->our_address */);
	if (!state->req) goto failed;

	state->req->async.fn		= wreplsrv_out_connect_handler;
	state->req->async.private	= state;

	return c;
failed:
	talloc_free(c);
	return NULL;
}

static NTSTATUS wreplsrv_out_connect_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
					  struct wreplsrv_out_connection **wreplconn)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct wreplsrv_out_connect_state *state = talloc_get_type(c->private_data,
							   struct wreplsrv_out_connect_state);
		talloc_reference(mem_ctx, state->wreplconn);
		*wreplconn = state->wreplconn;
	}

	talloc_free(c);
	return status;
	
}

enum wreplsrv_pull_table_stage {
	WREPLSRV_PULL_TABLE_STAGE_WAIT_CONNECTION,
	WREPLSRV_PULL_TABLE_STAGE_WAIT_TABLE_REPLY,
	WREPLSRV_PULL_TABLE_STAGE_DONE
};

struct wreplsrv_pull_table_io {
	struct {
		struct wreplsrv_partner *partner;
	} in;
	struct {
		uint32_t num_owners;
		struct wrepl_wins_owner *owners;
	} out;
};

struct wreplsrv_pull_table_state {
	enum wreplsrv_pull_table_stage stage;
	struct composite_context *c;
	struct wrepl_request *req;
	struct wrepl_pull_table table_io;
	struct wreplsrv_pull_table_io *io;
	struct composite_context *creq;
	struct wreplsrv_out_connection *wreplconn;
};

static void wreplsrv_pull_table_handler_req(struct wrepl_request *req);

static NTSTATUS wreplsrv_pull_table_wait_connection(struct wreplsrv_pull_table_state *state)
{
	NTSTATUS status;

	status = wreplsrv_out_connect_recv(state->creq, state, &state->wreplconn);
	NT_STATUS_NOT_OK_RETURN(status);

	state->table_io.in.assoc_ctx = state->wreplconn->assoc_ctx.peer_ctx;
	state->req = wrepl_pull_table_send(state->wreplconn->sock, &state->table_io);
	NT_STATUS_HAVE_NO_MEMORY(state->req);

	state->req->async.fn		= wreplsrv_pull_table_handler_req;
	state->req->async.private	= state;

	state->stage = WREPLSRV_PULL_TABLE_STAGE_WAIT_TABLE_REPLY;

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_pull_table_wait_table_reply(struct wreplsrv_pull_table_state *state)
{
	NTSTATUS status;

	status = wrepl_pull_table_recv(state->req, state, &state->table_io);
	NT_STATUS_NOT_OK_RETURN(status);

	state->stage = WREPLSRV_PULL_TABLE_STAGE_DONE;

	return NT_STATUS_OK;
}

static void wreplsrv_pull_table_handler(struct wreplsrv_pull_table_state *state)
{
	struct composite_context *c = state->c;

	switch (state->stage) {
	case WREPLSRV_PULL_TABLE_STAGE_WAIT_CONNECTION:
		c->status = wreplsrv_pull_table_wait_connection(state);
		break;
	case WREPLSRV_PULL_TABLE_STAGE_WAIT_TABLE_REPLY:
		c->status = wreplsrv_pull_table_wait_table_reply(state);
		c->state  = COMPOSITE_STATE_DONE;
		break;
	case WREPLSRV_PULL_TABLE_STAGE_DONE:
		c->status = NT_STATUS_INTERNAL_ERROR;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}

	if (c->state >= COMPOSITE_STATE_DONE && c->async.fn) {
		c->async.fn(c);
	}
}

static void wreplsrv_pull_table_handler_creq(struct composite_context *creq)
{
	struct wreplsrv_pull_table_state *state = talloc_get_type(creq->async.private_data,
						  struct wreplsrv_pull_table_state);
	wreplsrv_pull_table_handler(state);
	return;
}

static void wreplsrv_pull_table_handler_req(struct wrepl_request *req)
{
	struct wreplsrv_pull_table_state *state = talloc_get_type(req->async.private,
						  struct wreplsrv_pull_table_state);
	wreplsrv_pull_table_handler(state);
	return;
}

static struct composite_context *wreplsrv_pull_table_send(TALLOC_CTX *mem_ctx, struct wreplsrv_pull_table_io *io)
{
	struct composite_context *c = NULL;
	struct wreplsrv_service *service = io->in.partner->service;
	struct wreplsrv_pull_table_state *state = NULL;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (!c) goto failed;

	state = talloc_zero(c, struct wreplsrv_pull_table_state);
	if (!state) goto failed;
	state->c	= c;
	state->io	= io;

	c->state	= COMPOSITE_STATE_IN_PROGRESS;
	c->event_ctx	= service->task->event_ctx;
	c->private_data	= state;

	state->stage	= WREPLSRV_PULL_TABLE_STAGE_WAIT_CONNECTION;
	state->creq	= wreplsrv_out_connect_send(io->in.partner);
	if (!state->creq) goto failed;

	state->creq->async.fn		= wreplsrv_pull_table_handler_creq;
	state->creq->async.private_data	= state;

	return c;
failed:
	talloc_free(c);
	return NULL;
}

static NTSTATUS wreplsrv_pull_table_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
					 struct wreplsrv_pull_table_io *io)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct wreplsrv_pull_table_state *state = talloc_get_type(c->private_data,
							  struct wreplsrv_pull_table_state);
		io->out.num_owners	= state->table_io.out.num_partners;
		io->out.owners		= state->table_io.out.partners;
		talloc_reference(mem_ctx, state->table_io.out.partners);
	}

	talloc_free(c);
	return status;	
}

enum wreplsrv_pull_names_stage {
	WREPLSRV_PULL_NAMES_STAGE_WAIT_CONNECTION,
	WREPLSRV_PULL_NAMES_STAGE_WAIT_SEND_REPLY,
	WREPLSRV_PULL_NAMES_STAGE_DONE
};

struct wreplsrv_pull_names_io {
	struct {
		struct wreplsrv_partner *partner;
		struct wrepl_wins_owner owner;
	} in;
	struct {
		uint32_t num_names;
		struct wrepl_name *names;
	} out;
};

struct wreplsrv_pull_names_state {
	enum wreplsrv_pull_names_stage stage;
	struct composite_context *c;
	struct wrepl_request *req;
	struct wrepl_pull_names pull_io;
	struct wreplsrv_pull_names_io *io;
	struct composite_context *creq;
	struct wreplsrv_out_connection *wreplconn;
};

static void wreplsrv_pull_names_handler_req(struct wrepl_request *req);

static NTSTATUS wreplsrv_pull_names_wait_connection(struct wreplsrv_pull_names_state *state)
{
	NTSTATUS status;

	status = wreplsrv_out_connect_recv(state->creq, state, &state->wreplconn);
	NT_STATUS_NOT_OK_RETURN(status);

	state->pull_io.in.assoc_ctx	= state->wreplconn->assoc_ctx.peer_ctx;
	state->pull_io.in.partner	= state->io->in.owner;
	state->req = wrepl_pull_names_send(state->wreplconn->sock, &state->pull_io);
	NT_STATUS_HAVE_NO_MEMORY(state->req);

	state->req->async.fn		= wreplsrv_pull_names_handler_req;
	state->req->async.private	= state;

	state->stage = WREPLSRV_PULL_NAMES_STAGE_WAIT_SEND_REPLY;

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_pull_names_wait_send_reply(struct wreplsrv_pull_names_state *state)
{
	NTSTATUS status;

	status = wrepl_pull_names_recv(state->req, state, &state->pull_io);
	NT_STATUS_NOT_OK_RETURN(status);

	state->stage = WREPLSRV_PULL_NAMES_STAGE_DONE;

	return NT_STATUS_OK;
}

static void wreplsrv_pull_names_handler(struct wreplsrv_pull_names_state *state)
{
	struct composite_context *c = state->c;

	switch (state->stage) {
	case WREPLSRV_PULL_NAMES_STAGE_WAIT_CONNECTION:
		c->status = wreplsrv_pull_names_wait_connection(state);
		break;
	case WREPLSRV_PULL_NAMES_STAGE_WAIT_SEND_REPLY:
		c->status = wreplsrv_pull_names_wait_send_reply(state);
		c->state  = COMPOSITE_STATE_DONE;
		break;
	case WREPLSRV_PULL_NAMES_STAGE_DONE:
		c->status = NT_STATUS_INTERNAL_ERROR;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}

	if (c->state >= COMPOSITE_STATE_DONE && c->async.fn) {
		c->async.fn(c);
	}
}

static void wreplsrv_pull_names_handler_creq(struct composite_context *creq)
{
	struct wreplsrv_pull_names_state *state = talloc_get_type(creq->async.private_data,
						  struct wreplsrv_pull_names_state);
	wreplsrv_pull_names_handler(state);
	return;
}

static void wreplsrv_pull_names_handler_req(struct wrepl_request *req)
{
	struct wreplsrv_pull_names_state *state = talloc_get_type(req->async.private,
						  struct wreplsrv_pull_names_state);
	wreplsrv_pull_names_handler(state);
	return;
}

static struct composite_context *wreplsrv_pull_names_send(TALLOC_CTX *mem_ctx, struct wreplsrv_pull_names_io *io)
{
	struct composite_context *c = NULL;
	struct wreplsrv_service *service = io->in.partner->service;
	struct wreplsrv_pull_names_state *state = NULL;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (!c) goto failed;

	state = talloc_zero(c, struct wreplsrv_pull_names_state);
	if (!state) goto failed;
	state->c	= c;
	state->io	= io;

	c->state	= COMPOSITE_STATE_IN_PROGRESS;
	c->event_ctx	= service->task->event_ctx;
	c->private_data	= state;

	state->stage	= WREPLSRV_PULL_NAMES_STAGE_WAIT_CONNECTION;
	state->creq	= wreplsrv_out_connect_send(io->in.partner);
	if (!state->creq) goto failed;

	state->creq->async.fn		= wreplsrv_pull_names_handler_creq;
	state->creq->async.private_data	= state;

	return c;
failed:
	talloc_free(c);
	return NULL;
}

static NTSTATUS wreplsrv_pull_names_recv(struct composite_context *c, TALLOC_CTX *mem_ctx,
					 struct wreplsrv_pull_names_io *io)
{
	NTSTATUS status;

	status = composite_wait(c);

	if (NT_STATUS_IS_OK(status)) {
		struct wreplsrv_pull_names_state *state = talloc_get_type(c->private_data,
							  struct wreplsrv_pull_names_state);
		io->out.num_names	= state->pull_io.out.num_names;
		io->out.names		= state->pull_io.out.names;
		talloc_reference(mem_ctx, state->pull_io.out.names);
	}

	talloc_free(c);
	return status;
	
}

enum wreplsrv_pull_cycle_stage {
	WREPLSRV_PULL_CYCLE_STAGE_WAIT_TABLE_REPLY,
	WREPLSRV_PULL_CYCLE_STAGE_WAIT_SEND_REPLIES,
	WREPLSRV_PULL_CYCLE_STAGE_DONE
};

struct wreplsrv_pull_cycle_state {
	enum wreplsrv_pull_cycle_stage stage;
	struct composite_context *c;
	struct wreplsrv_partner *partner;
	struct wreplsrv_pull_table_io table_io;
	uint32_t current;
	struct wreplsrv_pull_names_io names_io;
	struct composite_context *creq;
};

static void wreplsrv_pull_cycle_handler_creq(struct composite_context *creq);

static NTSTATUS wreplsrv_pull_cycle_next_owner(struct wreplsrv_pull_cycle_state *state)
{
	struct wreplsrv_owner *current_owner;
	struct wreplsrv_owner *local_owner;
	uint32_t i;
	uint64_t old_max_version = 0;
	BOOL do_pull = False;

	for (i=state->current; i < state->table_io.out.num_owners; i++) {
		current_owner = wreplsrv_find_owner(state->partner->pull.table,
						    state->table_io.out.owners[i].address);

		local_owner = wreplsrv_find_owner(state->partner->service->table,
						  state->table_io.out.owners[i].address);
		/*
		 * this means we are ourself the current owner,
		 * and we don't want replicate ourself
		 */
		if (!current_owner) continue;

		/*
		 * this means we don't have any records of this owner
		 * so fetch them
		 */
		if (!local_owner) {
			do_pull		= True;
			
			break;
		}

		/*
		 * this means the remote partner has some new records of this owner
		 * fetch them
		 */
		if (current_owner->owner.max_version > local_owner->owner.max_version) {
			do_pull		= True;
			old_max_version	= local_owner->owner.max_version;
			break;
		}
	}
	state->current = i;

	if (do_pull) {
		state->names_io.in.partner		= state->partner;
		state->names_io.in.owner		= current_owner->owner;
		state->names_io.in.owner.min_version	= old_max_version;
		state->creq = wreplsrv_pull_names_send(state, &state->names_io);
		NT_STATUS_HAVE_NO_MEMORY(state->creq);

		state->creq->async.fn		= wreplsrv_pull_cycle_handler_creq;
		state->creq->async.private_data	= state;

		return STATUS_MORE_ENTRIES;
	}

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_pull_cycle_wait_table_reply(struct wreplsrv_pull_cycle_state *state)
{
	NTSTATUS status;
	uint32_t i;

	status = wreplsrv_pull_table_recv(state->creq, state, &state->table_io);
	NT_STATUS_NOT_OK_RETURN(status);

	/* update partner table */
	for (i=0; i < state->table_io.out.num_owners; i++) {
		BOOL is_our_addr;

		is_our_addr = wreplsrv_is_our_address(state->partner->service,
						      state->table_io.out.owners[i].address);
		if (is_our_addr) continue;

		status = wreplsrv_add_table(state->partner->service,
					    state->partner, 
					    &state->partner->pull.table,
					    state->table_io.out.owners[i].address,
					    state->table_io.out.owners[i].max_version);
		NT_STATUS_NOT_OK_RETURN(status);
	}

	status = wreplsrv_pull_cycle_next_owner(state);
	if (NT_STATUS_IS_OK(status)) {
		state->stage = WREPLSRV_PULL_CYCLE_STAGE_DONE;
	} else if (NT_STATUS_EQUAL(STATUS_MORE_ENTRIES, status)) {
		state->stage = WREPLSRV_PULL_CYCLE_STAGE_WAIT_SEND_REPLIES;
		status = NT_STATUS_OK;	
	}

	return status;
}

static NTSTATUS wreplsrv_pull_cycle_apply_records(struct wreplsrv_pull_cycle_state *state)
{
	NTSTATUS status;

	/* TODO: ! */
	DEBUG(0,("TODO: apply records count[%u]:owner[%s]:min[%llu]:max[%llu]:partner[%s]\n",
		state->names_io.out.num_names, state->names_io.in.owner.address,
		state->names_io.in.owner.min_version, state->names_io.in.owner.max_version,
		state->partner->address));

	status = wreplsrv_add_table(state->partner->service,
				    state->partner->service,
				    &state->partner->service->table,
				    state->names_io.in.owner.address,
				    state->names_io.in.owner.max_version);
	NT_STATUS_NOT_OK_RETURN(status);

	talloc_free(state->names_io.out.names);
	ZERO_STRUCT(state->names_io);

	return NT_STATUS_OK;
}

static NTSTATUS wreplsrv_pull_cycle_wait_send_replies(struct wreplsrv_pull_cycle_state *state)
{
	NTSTATUS status;

	status = wreplsrv_pull_names_recv(state->creq, state, &state->names_io);
	NT_STATUS_NOT_OK_RETURN(status);

	/*
	 * TODO: this should maybe an async call,
	 *       because we may need some network access
	 *       for conflict resolving
	 */
	status = wreplsrv_pull_cycle_apply_records(state);
	NT_STATUS_NOT_OK_RETURN(status);

	status = wreplsrv_pull_cycle_next_owner(state);
	if (NT_STATUS_IS_OK(status)) {
		state->stage = WREPLSRV_PULL_CYCLE_STAGE_DONE;
	} else if (NT_STATUS_EQUAL(STATUS_MORE_ENTRIES, status)) {
		state->stage = WREPLSRV_PULL_CYCLE_STAGE_WAIT_SEND_REPLIES;
		status = NT_STATUS_OK;	
	}
	return status;
}

static void wreplsrv_pull_cycle_handler(struct wreplsrv_pull_cycle_state *state)
{
	struct composite_context *c = state->c;

	switch (state->stage) {
	case WREPLSRV_PULL_CYCLE_STAGE_WAIT_TABLE_REPLY:
		c->status = wreplsrv_pull_cycle_wait_table_reply(state);
		break;
	case WREPLSRV_PULL_CYCLE_STAGE_WAIT_SEND_REPLIES:
		c->status = wreplsrv_pull_cycle_wait_send_replies(state);
		break;
	case WREPLSRV_PULL_NAMES_STAGE_DONE:
		c->status = NT_STATUS_INTERNAL_ERROR;
	}

	if (state->stage == WREPLSRV_PULL_NAMES_STAGE_DONE) {
		c->state  = COMPOSITE_STATE_DONE;
	}

	if (!NT_STATUS_IS_OK(c->status)) {
		c->state = COMPOSITE_STATE_ERROR;
	}

	if (c->state >= COMPOSITE_STATE_DONE && c->async.fn) {
		c->async.fn(c);
	}
}

static void wreplsrv_pull_cycle_handler_creq(struct composite_context *creq)
{
	struct wreplsrv_pull_cycle_state *state = talloc_get_type(creq->async.private_data,
						  struct wreplsrv_pull_cycle_state);
	wreplsrv_pull_cycle_handler(state);
	return;
}

static struct composite_context *wreplsrv_pull_cycle_send(struct wreplsrv_partner *partner)
{
	struct composite_context *c = NULL;
	struct wreplsrv_service *service = partner->service;
	struct wreplsrv_pull_cycle_state *state = NULL;

	c = talloc_zero(partner, struct composite_context);
	if (!c) goto failed;

	state = talloc_zero(c, struct wreplsrv_pull_cycle_state);
	if (!state) goto failed;
	state->c	= c;
	state->partner	= partner;

	c->state	= COMPOSITE_STATE_IN_PROGRESS;
	c->event_ctx	= service->task->event_ctx;
	c->private_data	= state;

	state->stage	= WREPLSRV_PULL_CYCLE_STAGE_WAIT_TABLE_REPLY;
	state->table_io.in.partner	= partner;
	state->creq = wreplsrv_pull_table_send(state, &state->table_io);
	if (!state->creq) goto failed;

	state->creq->async.fn		= wreplsrv_pull_cycle_handler_creq;
	state->creq->async.private_data	= state;

	return c;
failed:
	talloc_free(c);
	return NULL;
}

static NTSTATUS wreplsrv_pull_cycle_recv(struct composite_context *c)
{
	NTSTATUS status;

	status = composite_wait(c);

	talloc_free(c);
	return status;
	
}

static void wreplsrv_pull_handler_te(struct event_context *ev, struct timed_event *te,
				     struct timeval t, void *ptr);

static void wreplsrv_pull_handler_creq(struct composite_context *creq)
{
	struct wreplsrv_partner *partner = talloc_get_type(creq->async.private_data, struct wreplsrv_partner);
	uint32_t interval;

	partner->pull.last_status = wreplsrv_pull_cycle_recv(partner->pull.creq);
	partner->pull.creq = NULL;
	if (!NT_STATUS_IS_OK(partner->pull.last_status)) {
		interval = partner->pull.error_count * partner->pull.retry_interval;
		interval = MIN(interval, partner->pull.interval);
		partner->pull.error_count++;

		DEBUG(1,("wreplsrv_pull_cycle(%s): %s: next: %us\n",
			 partner->address, nt_errstr(partner->pull.last_status),
			 interval));
	} else {
		interval = partner->pull.interval;
		partner->pull.error_count = 0;

		DEBUG(2,("wreplsrv_pull_cycle(%s): %s: next: %us\n",
			 partner->address, nt_errstr(partner->pull.last_status),
			 interval));
	}

	partner->pull.te = event_add_timed(partner->service->task->event_ctx, partner,
					   timeval_current_ofs(interval, 0),
					   wreplsrv_pull_handler_te, partner);
	if (!partner->pull.te) {
		DEBUG(0,("wreplsrv_pull_handler_creq: event_add_timed() failed! no memory!\n"));
	}
}

static void wreplsrv_pull_handler_te(struct event_context *ev, struct timed_event *te,
				     struct timeval t, void *ptr)
{
	struct wreplsrv_partner *partner = talloc_get_type(ptr, struct wreplsrv_partner);

	partner->pull.creq = wreplsrv_pull_cycle_send(partner);
	if (!partner->pull.creq) {
		DEBUG(1,("wreplsrv_pull_cycle_send(%s) failed\n",
			 partner->address));
		goto requeue;
	}

	partner->pull.creq->async.fn		= wreplsrv_pull_handler_creq;
	partner->pull.creq->async.private_data	= partner;

	return;
requeue:
	/* retry later */
	partner->pull.te = event_add_timed(partner->service->task->event_ctx, partner,
					   timeval_add(&t, partner->pull.retry_interval, 0),
					   wreplsrv_pull_handler_te, partner);
	if (!partner->pull.te) {
		DEBUG(0,("wreplsrv_pull_handler_te: event_add_timed() failed! no memory!\n"));
	}
}

NTSTATUS wreplsrv_setup_out_connections(struct wreplsrv_service *service)
{
	struct wreplsrv_partner *cur;

	for (cur = service->partners; cur; cur = cur->next) {
		if (cur->type & WINSREPL_PARTNER_PULL) {
			cur->pull.te = event_add_timed(service->task->event_ctx, cur,
						       timeval_zero(), wreplsrv_pull_handler_te, cur);
			NT_STATUS_HAVE_NO_MEMORY(cur->pull.te);
		}
	}

	return NT_STATUS_OK;
}
