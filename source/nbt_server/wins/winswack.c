/* 
   Unix SMB/CIFS implementation.

   "secure" wins server WACK processing

   Copyright (C) Andrew Tridgell	2005
   
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
	uint32_t ttl;
	time_t now = time(NULL);
	struct winsdb_record *rec = state->rec, *rec2;

	status = winsdb_lookup(state->winssrv->wins_db, rec->name, state, &rec2);
	if (!NT_STATUS_IS_OK(status) || rec2->version != rec->version) {
		DEBUG(1,("WINS: record %s changed during WACK - failing registration\n",
			 nbt_name_string(state, rec->name)));
		wins_wack_deny(state);
		return;
	}

	nbtd_name_registration_reply(state->nbtsock, state->request_packet, 
				     &state->src, NBT_RCODE_OK);

	ttl = wins_server_ttl(state->winssrv, state->request_packet->additional[0].ttl);
	if (now + ttl > rec->expire_time) {
		rec->expire_time = now + ttl;
	}
	rec->addresses = winsdb_addr_list_add(rec->addresses,
					      state->reg_address,
					      WINSDB_OWNER_LOCAL,
					      rec->expire_time);
	if (rec->addresses == NULL) goto failed;

	rec->registered_by = state->src.addr;

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
