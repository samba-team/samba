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
  answer a name query
*/
void nbtd_request_query(struct nbt_name_socket *nbtsock, 
			struct nbt_name_packet *packet, 
			const char *src_address, int src_port)
{
	struct nbtd_iface_name *iname;
	struct nbt_name *name;
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);

	/* see if its a node status query */
	if (packet->qdcount == 1 &&
	    packet->questions[0].question_type == NBT_QTYPE_STATUS) {
		nbtd_query_status(nbtsock, packet, src_address, src_port);
		return;
	}

	NBTD_ASSERT_PACKET(packet, src_address, packet->qdcount == 1);
	NBTD_ASSERT_PACKET(packet, src_address, 
			   packet->questions[0].question_type == NBT_QTYPE_NETBIOS);
	NBTD_ASSERT_PACKET(packet, src_address, 
			   packet->questions[0].question_class == NBT_QCLASS_IP);

	/* see if we have the requested name on this interface */
	name = &packet->questions[0].name;

	iname = nbtd_find_iname(iface, name, 0);

	if (iname == NULL) {
		/* don't send negative replies to broadcast queries */
		if (packet->operation & NBT_FLAG_BROADCAST) {
			return;
		}

		/* if the name does not exist, then redirect to WINS
		   server if recursion has been asked for */
		if (packet->operation & NBT_FLAG_RECURSION_DESIRED) {
			nbtd_winsserver_request(nbtsock, packet, src_address, src_port);
			return;
		}

		/* otherwise send a negative reply */
		nbtd_negative_name_query_reply(nbtsock, packet, 
					       src_address, src_port);
		return;
	}

	/* if the name is not yet active and its a broadcast query then
	   ignore it for now */
	if (!(iname->nb_flags & NBT_NM_ACTIVE) && 
	    (packet->operation & NBT_FLAG_BROADCAST)) {
		DEBUG(7,("Query for %s<%02x> from %s - name not active yet on %s\n",
			 name->name, name->type, src_address, iface->ip_address));
		return;
	}

	nbtd_name_query_reply(nbtsock, packet, src_address, src_port,
			      &iname->name, iname->ttl, iname->nb_flags, 
			      nbtd_address_list(iface, packet));
}
