/* 
   Unix SMB/CIFS implementation.

   answer node status queries

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
  send a name status reply
*/
static void nbt_node_status_reply(struct nbt_name_socket *nbtsock, 
				  struct nbt_name_packet *request_packet, 
				  const char *src_address, int src_port,
				  struct nbt_name *name, 
				  struct nbt_interface *iface)
{
	struct nbt_name_packet *packet;
	uint32_t name_count;
	struct nbt_iface_name *iname;
	
	/* work out how many names to send */
	name_count = 0;
	for (iname=iface->names;iname;iname=iname->next) {
		if ((iname->nb_flags & NBT_NM_ACTIVE) && 
		    strcmp(iname->name.name, "*") != 0) {
			name_count++;
		}
	}

	packet = talloc_zero(nbtsock, struct nbt_name_packet);
	if (packet == NULL) return;

	packet->name_trn_id = request_packet->name_trn_id;
	packet->ancount = 1;
	packet->operation = NBT_OPCODE_QUERY | NBT_FLAG_REPLY | NBT_FLAG_AUTHORITIVE;

	packet->answers = talloc_array(packet, struct nbt_res_rec, 1);
	if (packet->answers == NULL) goto failed;

	packet->answers[0].name     = *name;
	packet->answers[0].rr_type  = NBT_QTYPE_STATUS;
	packet->answers[0].rr_class = NBT_QCLASS_IP;
	packet->answers[0].ttl      = 0;
	packet->answers[0].rdata.status.num_names = name_count;
	packet->answers[0].rdata.status.names = talloc_array(packet->answers,
							     struct nbt_status_name, name_count);
	if (packet->answers[0].rdata.status.names == NULL) goto failed;

	name_count = 0;
	for (iname=iface->names;iname;iname=iname->next) {
		if ((iname->nb_flags & NBT_NM_ACTIVE) && 
		    strcmp(iname->name.name, "*") != 0) {
			struct nbt_status_name *n = &packet->answers[0].rdata.status.names[name_count];
			n->name = talloc_asprintf(packet->answers, "%-15s", iname->name.name);
			if (n->name == NULL) goto failed;
			n->type     = iname->name.type;
			n->nb_flags = iname->nb_flags;
			name_count++;
		}
	}
	/* we deliberately don't fill in the statistics structure as
	   it could lead to giving attackers too much information */
	ZERO_STRUCT(packet->answers[0].rdata.status.statistics);

	DEBUG(7,("Sending node status reply for %s<%02x> to %s:%d\n", 
		 name->name, name->type, src_address, src_port));
	
	nbt_name_reply_send(nbtsock, src_address, src_port, packet);

failed:
	talloc_free(packet);
}


/*
  answer a node status query
*/
void nbt_query_status(struct nbt_name_socket *nbtsock, 
		      struct nbt_name_packet *packet, 
		      const char *src_address, int src_port)
{
	struct nbt_name *name;
	struct nbt_iface_name *iname;
	struct nbt_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						      struct nbt_interface);

	NBT_ASSERT_PACKET(packet, src_address, packet->qdcount == 1);
	NBT_ASSERT_PACKET(packet, src_address, packet->questions[0].question_type == NBT_QTYPE_STATUS);
	NBT_ASSERT_PACKET(packet, src_address, packet->questions[0].question_class == NBT_QCLASS_IP);

	/* see if we have the requested name on this interface */
	name = &packet->questions[0].name;

	iname = nbt_find_iname(iface, name, NBT_NM_ACTIVE);
	if (iname == NULL) {
		DEBUG(7,("Node status query for %s<%02x> from %s - not found on %s\n",
			 name->name, name->type, src_address, iface->ip_address));
		return;
	}

	nbt_node_status_reply(nbtsock, packet, src_address, src_port, &iname->name, iface);
}
