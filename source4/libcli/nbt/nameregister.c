/* 
   Unix SMB/CIFS implementation.

   send out a name registration request

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
#include "libcli/nbt/libnbt.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"
#include "system/network.h"

/*
  send a nbt name registration request
*/
struct nbt_name_request *nbt_name_register_send(struct nbt_name_socket *nbtsock,
						struct nbt_name_register *io)
{
	struct nbt_name_request *req;
	struct nbt_name_packet *packet;

	packet = talloc_zero(nbtsock, struct nbt_name_packet);
	if (packet == NULL) return NULL;

	packet->qdcount = 1;
	packet->arcount = 1;
	packet->operation = NBT_OPCODE_REGISTER;
	if (io->in.broadcast) {
		packet->operation |= NBT_FLAG_BROADCAST;
	}
	if (io->in.register_demand) {
		packet->operation |= NBT_FLAG_RECURSION_DESIRED;
	}

	packet->questions = talloc_array(packet, struct nbt_name_question, 1);
	if (packet->questions == NULL) goto failed;

	packet->questions[0].name           = io->in.name;
	packet->questions[0].question_type  = NBT_QTYPE_NETBIOS;
	packet->questions[0].question_class = NBT_QCLASS_IP;

	packet->additional = talloc_array(packet, struct nbt_res_rec, 1);
	if (packet->additional == NULL) goto failed;

	packet->additional[0].name                   = io->in.name;
	packet->additional[0].rr_type                = NBT_QTYPE_NETBIOS;
	packet->additional[0].rr_class               = NBT_QCLASS_IP;
	packet->additional[0].ttl                    = io->in.ttl;
	packet->additional[0].rdata.netbios.length   = 6;
	packet->additional[0].rdata.netbios.addresses = talloc_array(packet->additional,
								     struct nbt_rdata_address, 1);
	if (packet->additional[0].rdata.netbios.addresses == NULL) goto failed;
	packet->additional[0].rdata.netbios.addresses[0].nb_flags = io->in.nb_flags;
	packet->additional[0].rdata.netbios.addresses[0].ipaddr = 
		talloc_strdup(packet->additional, io->in.address);
	if (packet->additional[0].rdata.netbios.addresses[0].ipaddr == NULL) goto failed;
	
	req = nbt_name_request_send(nbtsock, io->in.dest_addr, lp_nbt_port(), packet,
				    io->in.timeout, io->in.retries, False);
	if (req == NULL) goto failed;

	talloc_free(packet);
	return req;

failed:
	talloc_free(packet);
	return NULL;	
}

/*
  wait for a registration reply
*/
NTSTATUS nbt_name_register_recv(struct nbt_name_request *req, 
				TALLOC_CTX *mem_ctx, struct nbt_name_register *io)
{
	NTSTATUS status;
	struct nbt_name_packet *packet;

	status = nbt_name_request_recv(req);
	if (!NT_STATUS_IS_OK(status) ||
	    req->num_replies == 0) {
		talloc_free(req);
		return status;
	}
	
	packet = req->replies[0].packet;
	io->out.reply_from = talloc_steal(mem_ctx, req->replies[0].reply_addr);

	if (packet->ancount != 1 ||
	    packet->answers[0].rr_type != NBT_QTYPE_NETBIOS ||
	    packet->answers[0].rr_class != NBT_QCLASS_IP) {
		talloc_free(req);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}

	io->out.rcode = packet->operation & NBT_RCODE;
	io->out.name = packet->answers[0].name;
	if (packet->answers[0].rdata.netbios.length < 6) {
		talloc_free(req);
		return NT_STATUS_INVALID_NETWORK_RESPONSE;
	}
	io->out.reply_addr = talloc_steal(mem_ctx, 
					  packet->answers[0].rdata.netbios.addresses[0].ipaddr);
	talloc_steal(mem_ctx, io->out.name.name);
	talloc_steal(mem_ctx, io->out.name.scope);
	    
	talloc_free(req);

	return NT_STATUS_OK;
}

/*
  synchronous name registration request
*/
NTSTATUS nbt_name_register(struct nbt_name_socket *nbtsock, 
			   TALLOC_CTX *mem_ctx, struct nbt_name_register *io)
{
	struct nbt_name_request *req = nbt_name_register_send(nbtsock, io);
	return nbt_name_register_recv(req, mem_ctx, io);
}


/*
  a 4 step broadcast registration. 3 lots of name registration requests, followed by
  a name registration demand
*/
struct register_bcast_state {
	struct nbt_name_socket *nbtsock;
	struct nbt_name_register *io;
	struct nbt_name_request *req;
};


/*
  state handler for 4 stage name registration
*/
static void name_register_bcast_handler(struct nbt_name_request *req)
{
	struct composite_context *c = talloc_get_type(req->async.private, struct composite_context);
	struct register_bcast_state *state = talloc_get_type(c->private, struct register_bcast_state);
	NTSTATUS status;

	status = nbt_name_register_recv(state->req, state, state->io);
	if (NT_STATUS_EQUAL(status, NT_STATUS_IO_TIMEOUT)) {
		if (state->io->in.register_demand == True) {
			/* all done */
			c->state = SMBCLI_REQUEST_DONE;
			c->status = NT_STATUS_OK;
			goto done;
		}

		/* the registration timed out - good, send the demand */
		state->io->in.register_demand = True;
		state->io->in.retries         = 0;
		state->req = nbt_name_register_send(state->nbtsock, state->io);
		if (state->req == NULL) {
			c->state = SMBCLI_REQUEST_ERROR;
			c->status = NT_STATUS_NO_MEMORY;
		} else {
			state->req->async.fn      = name_register_bcast_handler;
			state->req->async.private = c;
		}
	} else if (!NT_STATUS_IS_OK(status)) {
		c->state = SMBCLI_REQUEST_ERROR;
		c->status = status;
	} else {
		c->state = SMBCLI_REQUEST_ERROR;
		c->status = NT_STATUS_CONFLICTING_ADDRESSES;
		DEBUG(3,("Name registration conflict from %s for %s<%02x> with ip %s - rcode %d\n",
			 state->io->out.reply_from, 
			 state->io->out.name.name,
			 state->io->out.name.type,
			 state->io->out.reply_addr,
			 state->io->out.rcode));
	}

done:
	if (c->state >= SMBCLI_REQUEST_DONE &&
	    c->async.fn) {
		c->async.fn(c);
	}
}

/*
  the async send call for a 4 stage name registration
*/
struct composite_context *nbt_name_register_bcast_send(struct nbt_name_socket *nbtsock,
						      struct nbt_name_register_bcast *io)
{
	struct composite_context *c;
	struct register_bcast_state *state;

	c = talloc_zero(nbtsock, struct composite_context);
	if (c == NULL) goto failed;

	state = talloc(c, struct register_bcast_state);
	if (state == NULL) goto failed;

	state->io = talloc(state, struct nbt_name_register);
	if (state->io == NULL) goto failed;

	state->io->in.name            = io->in.name;
	state->io->in.dest_addr       = io->in.dest_addr;
	state->io->in.address         = io->in.address;
	state->io->in.nb_flags        = io->in.nb_flags;
	state->io->in.register_demand = False;
	state->io->in.broadcast       = True;
	state->io->in.ttl             = io->in.ttl;
	state->io->in.timeout         = 1;
	state->io->in.retries         = 2;

	state->nbtsock = nbtsock;

	state->req = nbt_name_register_send(nbtsock, state->io);
	if (state->req == NULL) goto failed;

	state->req->async.fn      = name_register_bcast_handler;
	state->req->async.private = c;

	c->private   = state;
	c->state     = SMBCLI_REQUEST_SEND;
	c->event_ctx = nbtsock->event_ctx;

	return c;

failed:
	talloc_free(c);
	return NULL;
}

/*
  broadcast 4 part name register - recv
*/
NTSTATUS nbt_name_register_bcast_recv(struct composite_context *c)
{
	NTSTATUS status;
	status = composite_wait(c);
	talloc_free(c);
	return status;
}

/*
  broadcast 4 part name register - sync interface
*/
NTSTATUS nbt_name_register_bcast(struct nbt_name_socket *nbtsock,
				 struct nbt_name_register_bcast *io)
{
	struct composite_context *c = nbt_name_register_bcast_send(nbtsock, io);
	return nbt_name_register_bcast_recv(c);
}
