/* 
   Unix SMB/CIFS implementation.

   answer name queries

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
#include "dlinklist.h"
#include "system/network.h"
#include "nbt_server/nbt_server.h"

/*
  send a name query reply
*/
static void nbt_name_query_reply(struct nbt_name_socket *nbtsock, 
				 struct nbt_name_packet *request_packet, 
				 const char *src_address, int src_port,
				 struct nbt_name *name, uint32_t ttl,
				 uint16_t nb_flags, const char *address)
{
	struct nbt_name_packet *packet;

	packet = talloc_zero(nbtsock, struct nbt_name_packet);
	if (packet == NULL) return;

	packet->name_trn_id = request_packet->name_trn_id;
	packet->ancount = 1;
	packet->operation = 
		NBT_FLAG_REPLY | 
		NBT_OPCODE_QUERY | 
		NBT_FLAG_AUTHORITIVE |
		NBT_FLAG_RECURSION_DESIRED |
		NBT_FLAG_RECURSION_AVAIL;

	packet->answers = talloc_array(packet, struct nbt_res_rec, 1);
	if (packet->answers == NULL) goto failed;

	packet->answers[0].name     = *name;
	packet->answers[0].rr_type  = NBT_QTYPE_NETBIOS;
	packet->answers[0].rr_class = NBT_QCLASS_IP;
	packet->answers[0].ttl      = ttl;
	packet->answers[0].rdata.netbios.length = 6;
	packet->answers[0].rdata.netbios.addresses = talloc_array(packet->answers,
							    struct nbt_rdata_address, 1);
	if (packet->answers[0].rdata.netbios.addresses == NULL) goto failed;
	packet->answers[0].rdata.netbios.addresses[0].nb_flags = nb_flags;
	packet->answers[0].rdata.netbios.addresses[0].ipaddr = htonl(inet_addr(address));

	DEBUG(7,("Sending name query reply for %s<%02x> at %s to %s:%d\n", 
		 name->name, name->type, src_address, address, src_port));
	
	nbt_name_reply_send(nbtsock, src_address, src_port, packet);

failed:
	talloc_free(packet);
}


/*
  answer a name query
*/
void nbt_request_query(struct nbt_name_socket *nbtsock, 
		       struct nbt_name_packet *packet, 
		       const char *src_address, int src_port)
{
	struct nbt_interface *iface;
	struct nbt_iface_name *iname;
	struct nbt_name *name;

	/* see if its a node status query */
	if (packet->qdcount == 1 &&
	    packet->questions[0].question_type == NBT_QTYPE_STATUS) {
		nbt_query_status(nbtsock, packet, src_address, src_port);
		return;
	}

	/* if its a WINS query then direct to our WINS server */
	if ((packet->operation & NBT_FLAG_RECURSION_DESIRED) &&
	    !(packet->operation & NBT_FLAG_BROADCAST)) {
		nbt_query_wins(nbtsock, packet, src_address, src_port);
		return;
	}

	/* find the interface for this query */
	iface = nbt_iface_find(nbtsock, src_address);

	NBT_ASSERT_PACKET(packet, src_address, packet->qdcount == 1);
	NBT_ASSERT_PACKET(packet, src_address, packet->questions[0].question_type == NBT_QTYPE_NETBIOS);
	NBT_ASSERT_PACKET(packet, src_address, packet->questions[0].question_class == NBT_QCLASS_IP);

	/* see if we have the requested name on this interface */
	name = &packet->questions[0].name;

	iname = nbt_find_iname(iface, name, NBT_NM_ACTIVE);
	if (iname == NULL) {
		DEBUG(7,("Query for %s<%02x> from %s - not found on %s\n",
			 name->name, name->type, src_address, iface->ip_address));
		return;
	}

	nbt_name_query_reply(nbtsock, packet, src_address, src_port,
			     &iname->name, iname->ttl, iname->nb_flags, 
			     iface->ip_address);
}
