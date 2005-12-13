/* 
   Unix SMB/CIFS implementation.

   "secure" wins server WACK processing

   Copyright (C) Andrew Tridgell	2005
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
#include "nbt_server/nbt_server.h"
#include "nbt_server/wins/winsdb.h"
#include "system/time.h"
#include "libcli/composite/composite.h"

struct wins_challenge_io {
	struct {
		struct nbtd_server *nbtd_server;
		struct event_context *event_ctx;
		struct nbt_name *name;
		uint32_t num_addresses;
		const char **addresses;
	} in;
	struct {
		uint32_t num_addresses;
		const char **addresses;
	} out;
};

struct wins_challenge_state {
	struct wins_challenge_io *io;
	uint32_t current_address;
	struct nbt_name_query query;
};

static void wins_challenge_handler(struct nbt_name_request *req)
{
	struct composite_context *ctx = talloc_get_type(req->async.private, struct composite_context);
	struct wins_challenge_state *state = talloc_get_type(ctx->private_data, struct wins_challenge_state);

	ctx->status = nbt_name_query_recv(req, state, &state->query);

	/* if we timed out then try the next owner address, if any */
	if (NT_STATUS_EQUAL(ctx->status, NT_STATUS_IO_TIMEOUT)) {
		state->current_address++;
		if (state->current_address < state->io->in.num_addresses) {
			struct nbtd_interface *iface;

			state->query.in.dest_addr = state->io->in.addresses[state->current_address];
			
			iface = nbtd_find_interface(state->io->in.nbtd_server, state->query.in.dest_addr);
			if (!iface) {
				composite_error(ctx, NT_STATUS_INTERNAL_ERROR);
				return;
			}

			ZERO_STRUCT(state->query.out);
			req = nbt_name_query_send(iface->nbtsock, &state->query);
			composite_continue_nbt(ctx, req, wins_challenge_handler, ctx);
			return;
		}
	}

	composite_done(ctx);
}

static NTSTATUS wins_challenge_recv(struct composite_context *ctx, TALLOC_CTX *mem_ctx, struct wins_challenge_io *io)
{
	NTSTATUS status = ctx->status;
	struct wins_challenge_state *state = talloc_get_type(ctx->private_data, struct wins_challenge_state);

	if (NT_STATUS_IS_OK(status)) {
		io->out.num_addresses	= state->query.out.num_addrs;
		io->out.addresses	= state->query.out.reply_addrs;
		talloc_steal(mem_ctx, io->out.addresses);
	} else {
		ZERO_STRUCT(io->out);
	}

	talloc_free(ctx);
	return status;
}

static struct composite_context *wins_challenge_send(TALLOC_CTX *mem_ctx, struct wins_challenge_io *io)
{
	struct composite_context *result;
	struct wins_challenge_state *state;
	struct nbt_name_request *req;
	struct nbtd_interface *iface;

	result = talloc_zero(mem_ctx, struct composite_context);
	if (result == NULL) return NULL;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->event_ctx = talloc_reference(result, io->in.event_ctx);

	state = talloc_zero(result, struct wins_challenge_state);
	if (state == NULL) goto failed;
	result->private_data = state;

	/* package up the state variables for this wack request */
	state->io		= io;
	state->current_address	= 0;

	/* setup a name query to the first address */
	state->query.in.name        = *state->io->in.name;
	state->query.in.dest_addr   = state->io->in.addresses[state->current_address];
	state->query.in.broadcast   = False;
	state->query.in.wins_lookup = True;
	state->query.in.timeout     = 1;
	state->query.in.retries     = 2;
	ZERO_STRUCT(state->query.out);

	iface = nbtd_find_interface(state->io->in.nbtd_server, state->query.in.dest_addr);
	if (!iface) {
		goto failed;
	}

	req = nbt_name_query_send(iface->nbtsock, &state->query);
	if (req == NULL) goto failed;

	req->async.fn = wins_challenge_handler;
	req->async.private = result;

	return result;
failed:
	talloc_free(result);
	return NULL;
}

struct wins_release_demand_io {
	struct {
		struct nbtd_server *nbtd_server;
		struct event_context *event_ctx;
		struct nbt_name *name;
		uint16_t nb_flags;
		uint32_t num_addresses;
		const char **addresses;
	} in;
};

struct wins_release_demand_state {
	struct wins_release_demand_io *io;
	uint32_t current_address;
	uint32_t addresses_left;
	struct nbt_name_release release;
};

static void wins_release_demand_handler(struct nbt_name_request *req)
{
	struct composite_context *ctx = talloc_get_type(req->async.private, struct composite_context);
	struct wins_release_demand_state *state = talloc_get_type(ctx->private_data, struct wins_release_demand_state);

	ctx->status = nbt_name_release_recv(req, state, &state->release);

	/* if we timed out then try the next owner address, if any */
	if (NT_STATUS_EQUAL(ctx->status, NT_STATUS_IO_TIMEOUT)) {
		state->current_address++;
		state->addresses_left--;
		if (state->current_address < state->io->in.num_addresses) {
			struct nbtd_interface *iface;

			state->release.in.dest_addr = state->io->in.addresses[state->current_address];
			state->release.in.address   = state->release.in.dest_addr;
			state->release.in.timeout   = (state->addresses_left > 1 ? 2 : 1);
			state->release.in.retries   = (state->addresses_left > 1 ? 0 : 2);

			iface = nbtd_find_interface(state->io->in.nbtd_server, state->release.in.dest_addr);
			if (!iface) {
				composite_error(ctx, NT_STATUS_INTERNAL_ERROR);
				return;
			}

			ZERO_STRUCT(state->release.out);
			req = nbt_name_release_send(iface->nbtsock, &state->release);
			composite_continue_nbt(ctx, req, wins_release_demand_handler, ctx);
			return;
		}
	}

	composite_done(ctx);
}

static NTSTATUS wins_release_demand_recv(struct composite_context *ctx,
					 TALLOC_CTX *mem_ctx,
					 struct wins_release_demand_io *io)
{
	NTSTATUS status = ctx->status;
	talloc_free(ctx);
	return status;
}

static struct composite_context *wins_release_demand_send(TALLOC_CTX *mem_ctx, struct wins_release_demand_io *io)
{
	struct composite_context *result;
	struct wins_release_demand_state *state;
	struct nbt_name_request *req;
	struct nbtd_interface *iface;

	result = talloc_zero(mem_ctx, struct composite_context);
	if (result == NULL) return NULL;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->event_ctx = talloc_reference(result, io->in.event_ctx);

	state = talloc_zero(result, struct wins_release_demand_state);
	if (state == NULL) goto failed;
	result->private_data = state;

	/* package up the state variables for this wack request */
	state->io		= io;
	state->current_address	= 0;
	state->addresses_left	= state->io->in.num_addresses;

	/* 
	 * setup a name query to the first address
	 * - if we have more than one address try the first
	 *   with 2 secs timeout and no retry
	 * - otherwise use 1 sec timeout (w2k3 uses 0.5 sec here)
	 *   with 2 retries
	 */
	state->release.in.name        = *state->io->in.name;
	state->release.in.dest_addr   = state->io->in.addresses[state->current_address];
	state->release.in.address     = state->release.in.dest_addr;
	state->release.in.broadcast   = False;
	state->release.in.timeout     = (state->addresses_left > 1 ? 2 : 1);
	state->release.in.retries     = (state->addresses_left > 1 ? 0 : 2);
	ZERO_STRUCT(state->release.out);

	iface = nbtd_find_interface(state->io->in.nbtd_server, state->release.in.dest_addr);
	if (!iface) {
		goto failed;
	}

	req = nbt_name_release_send(iface->nbtsock, &state->release);
	if (req == NULL) goto failed;

	req->async.fn = wins_release_demand_handler;
	req->async.private = result;

	return result;
failed:
	talloc_free(result);
	return NULL;
}

struct wack_state {
	struct wins_server *winssrv;
	struct nbt_name_socket *nbtsock;
	struct nbt_name_packet *request_packet;
	struct winsdb_record *rec;
	struct nbt_peer_socket src;
	const char **owner_addresses;
	const char *reg_address;
	struct nbt_name_query query;
};


/*
  deny a registration request
*/
static void wins_wack_deny(struct wack_state *state)
{
	nbtd_name_registration_reply(state->nbtsock, state->request_packet, 
				     &state->src, NBT_RCODE_ACT);
	DEBUG(4,("WINS: denied name registration request for %s from %s:%d\n",
		 nbt_name_string(state, state->rec->name), state->src.addr, state->src.port));
	talloc_free(state);
}

/*
  allow a registration request
*/
static void wins_wack_allow(struct wack_state *state)
{
	NTSTATUS status;
	uint32_t ttl = wins_server_ttl(state->winssrv, state->request_packet->additional[0].ttl);
	struct winsdb_record *rec = state->rec, *rec2;

	status = winsdb_lookup(state->winssrv->wins_db, rec->name, state, &rec2);
	if (!NT_STATUS_IS_OK(status)
	    || rec2->version != rec->version
	    || strcmp(rec2->wins_owner, rec->wins_owner) != 0) {
		DEBUG(1,("WINS: record %s changed during WACK - failing registration\n",
			 nbt_name_string(state, rec->name)));
		wins_wack_deny(state);
		return;
	}

	nbtd_name_registration_reply(state->nbtsock, state->request_packet, 
				     &state->src, NBT_RCODE_OK);

	rec->expire_time = time(NULL) + ttl;
	rec->registered_by = state->src.addr;

	/* TODO: is it correct to only add this address? */
	rec->addresses = winsdb_addr_list_add(rec->addresses,
					      state->reg_address,
					      WINSDB_OWNER_LOCAL,
					      rec->expire_time);
	if (rec->addresses == NULL) goto failed;

	/* if we have more than one address, this becomes implicit a MHOMED record */
	if (winsdb_addr_list_length(rec->addresses) > 1) {
		rec->type = WREPL_TYPE_MHOMED;
	}

	winsdb_modify(state->winssrv->wins_db, rec, WINSDB_FLAG_ALLOC_VERSION | WINSDB_FLAG_TAKE_OWNERSHIP);

	DEBUG(4,("WINS: accepted registration of %s with address %s\n",
		 nbt_name_string(state, rec->name), state->reg_address));

failed:
	talloc_free(state);
}

/*
  called when a name query to a current owner completes
*/
static void wins_wack_handler(struct nbt_name_request *req)
{
	struct wack_state *state = talloc_get_type(req->async.private, struct wack_state);
	NTSTATUS status;
	int i;
	struct winsdb_record *rec = state->rec;

	status = nbt_name_query_recv(req, state, &state->query);

	/* if we timed out then try the next owner address, if any */
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		state->owner_addresses++;
		if (state->owner_addresses[0] == NULL) {
			wins_wack_allow(state);
			return;
		}
		state->query.in.dest_addr = state->owner_addresses[0];

		req = nbt_name_query_send(state->nbtsock, &state->query);
		if (req == NULL) goto failed;

		req->async.fn = wins_wack_handler;
		req->async.private = state;
		return;
	}

	/* if the owner denies it holds the name, then allow
	   the registration */
	if (!NT_STATUS_IS_OK(status)) {
		wins_wack_allow(state);
		return;
	}

	/* if the owner still wants the name and doesn't reply
	   with the address trying to be registered, then deny
	   the registration */
	if (!str_list_check(state->query.out.reply_addrs, state->reg_address)) {
		wins_wack_deny(state);
		return;
	}

	/* we are going to allow the registration, but first remove any addresses
	   from the record that aren't in the reply from the client */
	for (i=0; state->query.out.reply_addrs[i]; i++) {
		if (!winsdb_addr_list_check(rec->addresses, state->query.out.reply_addrs[i])) {
			winsdb_addr_list_remove(rec->addresses, state->query.out.reply_addrs[i]);
		}
	}

	wins_wack_allow(state);
	return;

failed:
	talloc_free(state);
}


/*
  a client has asked to register a unique name that someone else owns. We
  need to ask each of the current owners if they still want it. If they do
  then reject the registration, otherwise allow it
*/
void wins_register_wack(struct nbt_name_socket *nbtsock, 
			struct nbt_name_packet *packet, 
			struct winsdb_record *rec,
			const struct nbt_peer_socket *src)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	struct wack_state *state;
	struct nbt_name_request *req;
	uint32_t ttl;

	state = talloc(nbtsock, struct wack_state);
	if (state == NULL) goto failed;

	/* package up the state variables for this wack request */
	state->winssrv         = winssrv;
	state->nbtsock         = nbtsock;
	state->request_packet  = talloc_steal(state, packet);
	state->rec             = talloc_steal(state, rec);
	state->owner_addresses = winsdb_addr_string_list(state, rec->addresses);
	if (state->owner_addresses == NULL) goto failed;
	state->reg_address     = packet->additional[0].rdata.netbios.addresses[0].ipaddr;
	state->src.port        = src->port;
	state->src.addr        = talloc_strdup(state, src->addr);
	if (state->src.addr == NULL) goto failed;

	/* setup a name query to the first address */
	state->query.in.name        = *rec->name;
	state->query.in.dest_addr   = state->owner_addresses[0];
	state->query.in.broadcast   = False;
	state->query.in.wins_lookup = True;
	state->query.in.timeout     = 1;
	state->query.in.retries     = 2;

	/* the LOGON type is a nasty hack */
	if (rec->name->type == NBT_NAME_LOGON) {
		wins_wack_allow(state);
		return;
	}

	/* send a WACK to the client, specifying the maximum time it could
	   take to check with the owner, plus some slack */
	ttl = 5 + 4 * winsdb_addr_list_length(rec->addresses);
	nbtd_wack_reply(nbtsock, packet, src, ttl);

	req = nbt_name_query_send(nbtsock, &state->query);
	if (req == NULL) goto failed;

	req->async.fn = wins_wack_handler;
	req->async.private = state;
	return;	

failed:
	talloc_free(state);
	nbtd_name_registration_reply(nbtsock, packet, src, NBT_RCODE_SVR);
}

/*
  wrepl_server needs to be able to do a name query request, but some windows
  servers always send the reply to port 137, regardless of the request
  port. To cope with this we use a irpc request to the NBT server
  which has port 137 open, and thus can receive the replies
*/
struct proxy_wins_challenge_state {
	struct irpc_message *msg;
	struct nbtd_proxy_wins_challenge *req;
	struct wins_challenge_io io;
	struct composite_context *c_req;
};

static void proxy_wins_challenge_handler(struct composite_context *c_req)
{
	NTSTATUS status;
	uint32_t i;
	struct proxy_wins_challenge_state *s = talloc_get_type(c_req->async.private_data,
							       struct proxy_wins_challenge_state);

	status = wins_challenge_recv(s->c_req, s, &s->io);
	if (!NT_STATUS_IS_OK(status)) {
		ZERO_STRUCT(s->req->out);
		irpc_send_reply(s->msg, status);
		return;
	}

	s->req->out.num_addrs	= s->io.out.num_addresses;		
	/* TODO: fix pidl to handle inline ipv4address arrays */
	s->req->out.addrs	= talloc_array(s->msg, struct nbtd_proxy_wins_addr,
					       s->io.out.num_addresses);
	if (!s->req->out.addrs) {
		ZERO_STRUCT(s->req->out);
		irpc_send_reply(s->msg, NT_STATUS_NO_MEMORY);
		return;
	}
	for (i=0; i < s->io.out.num_addresses; i++) {
		s->req->out.addrs[i].addr = talloc_steal(s->req->out.addrs, s->io.out.addresses[i]);
	}

	irpc_send_reply(s->msg, status);
}

NTSTATUS nbtd_proxy_wins_challenge(struct irpc_message *msg, 
				   struct nbtd_proxy_wins_challenge *req)
{
	struct nbtd_server *nbtd_server =
		talloc_get_type(msg->private, struct nbtd_server);
	struct proxy_wins_challenge_state *s;
	uint32_t i;

	s = talloc(msg, struct proxy_wins_challenge_state);
        NT_STATUS_HAVE_NO_MEMORY(s);

	s->msg = msg;
	s->req = req;

	s->io.in.nbtd_server	= nbtd_server;
	s->io.in.event_ctx	= msg->ev;
	s->io.in.name		= &req->in.name;
	s->io.in.num_addresses	= req->in.num_addrs;
	s->io.in.addresses	= talloc_array(s, const char *, req->in.num_addrs);
	NT_STATUS_HAVE_NO_MEMORY(s->io.in.addresses);
	/* TODO: fix pidl to handle inline ipv4address arrays */
	for (i=0; i < req->in.num_addrs; i++) {
		s->io.in.addresses[i]	= talloc_steal(s->io.in.addresses, req->in.addrs[i].addr);
	}

	s->c_req = wins_challenge_send(s, &s->io);
	NT_STATUS_HAVE_NO_MEMORY(s->c_req);

	s->c_req->async.fn		= proxy_wins_challenge_handler;
	s->c_req->async.private_data	= s;

	msg->defer_reply = True;
	return NT_STATUS_OK;
}

/*
  wrepl_server needs to be able to do a name release demands, but some windows
  servers always send the reply to port 137, regardless of the request
  port. To cope with this we use a irpc request to the NBT server
  which has port 137 open, and thus can receive the replies
*/
struct proxy_wins_release_demand_state {
	struct irpc_message *msg;
	struct nbtd_proxy_wins_release_demand *req;
	struct wins_release_demand_io io;
	struct composite_context *c_req;
};

static void proxy_wins_release_demand_handler(struct composite_context *c_req)
{
	NTSTATUS status;
	struct proxy_wins_release_demand_state *s = talloc_get_type(c_req->async.private_data,
							       struct proxy_wins_release_demand_state);

	status = wins_release_demand_recv(s->c_req, s, &s->io);

	irpc_send_reply(s->msg, status);
}

NTSTATUS nbtd_proxy_wins_release_demand(struct irpc_message *msg, 
				   struct nbtd_proxy_wins_release_demand *req)
{
	struct nbtd_server *nbtd_server =
		talloc_get_type(msg->private, struct nbtd_server);
	struct proxy_wins_release_demand_state *s;
	uint32_t i;

	s = talloc(msg, struct proxy_wins_release_demand_state);
        NT_STATUS_HAVE_NO_MEMORY(s);

	s->msg = msg;
	s->req = req;

	s->io.in.nbtd_server	= nbtd_server;
	s->io.in.event_ctx	= msg->ev;
	s->io.in.name		= &req->in.name;
	s->io.in.num_addresses	= req->in.num_addrs;
	s->io.in.addresses	= talloc_array(s, const char *, req->in.num_addrs);
	NT_STATUS_HAVE_NO_MEMORY(s->io.in.addresses);
	/* TODO: fix pidl to handle inline ipv4address arrays */
	for (i=0; i < req->in.num_addrs; i++) {
		s->io.in.addresses[i]	= talloc_steal(s->io.in.addresses, req->in.addrs[i].addr);
	}

	s->c_req = wins_release_demand_send(s, &s->io);
	NT_STATUS_HAVE_NO_MEMORY(s->c_req);

	s->c_req->async.fn		= proxy_wins_release_demand_handler;
	s->c_req->async.private_data	= s;

	msg->defer_reply = True;
	return NT_STATUS_OK;
}
