/* 
   Unix SMB/CIFS implementation.

   answer node status queries

   Copyright (C) Andrew Tridgell	2005
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "../lib/util/dlinklist.h"
#include "system/network.h"
#include "nbt_server/nbt_server.h"
#include "lib/socket/socket.h"
#include "librpc/gen_ndr/ndr_nbt.h"

struct nbt_name_packet *nbtd_node_status_reply_packet(
	TALLOC_CTX *mem_ctx,
	uint16_t trn_id,
	const struct nbt_name *name,
	struct nbtd_interface *iface)
{
	struct nbtd_iface_name *iname;
	struct nbt_name_packet *packet;
	struct nbt_res_rec *answer;
	struct nbt_rdata_status *stat;
	uint32_t num_names;
	NTSTATUS status;

	num_names = 0;
	for (iname = iface->names; iname != NULL; iname = iname->next) {
		if ((iname->nb_flags & NBT_NM_ACTIVE) == 0) {
			continue;
		}
		if (strcmp(iname->name.name, "*") == 0) {
			continue;
		}
		num_names += 1;
	}

	packet = talloc_zero(mem_ctx, struct nbt_name_packet);
	if (packet == NULL) {
		return NULL;
	}

	packet->name_trn_id = trn_id;
	packet->ancount = 1;
	packet->operation =
		NBT_OPCODE_QUERY |
		NBT_FLAG_REPLY |
		NBT_FLAG_AUTHORITATIVE;

	packet->answers = talloc_array(packet, struct nbt_res_rec, 1);
	if (packet->answers == NULL) {
		goto failed;
	}

	answer = &packet->answers[0];

	status = nbt_name_dup(packet->answers, name, &answer->name);
	if (!NT_STATUS_IS_OK(status)) {
		goto failed;
	}

	answer->rr_type  = NBT_QTYPE_STATUS;
	answer->rr_class = NBT_QCLASS_IP;
	answer->ttl      = 0;

	stat = &packet->answers[0].rdata.status;

	stat->num_names = num_names;
	stat->names = talloc_zero_array(
		packet->answers,
		struct nbt_status_name,
		num_names);
	if (stat->names == NULL) {
		goto failed;
	}

	num_names = 0;
	for (iname = iface->names; iname != NULL; iname = iname->next) {
		struct nbt_status_name *n = &stat->names[num_names];

		if ((iname->nb_flags & NBT_NM_ACTIVE) == 0) {
			continue;
		}
		if (strcmp(iname->name.name, "*") == 0) {
			continue;
		}

		n->name = talloc_asprintf(
			stat->names,
			"%-15s",
			iname->name.name);
		if (n->name == NULL) {
			goto failed;
		}
		n->type = iname->name.type;
		n->nb_flags = iname->nb_flags;

		num_names += 1;
	}

	return packet;

failed:
	TALLOC_FREE(packet);
	return NULL;
}

/*
  send a name status reply
*/
static void nbtd_node_status_reply(struct nbt_name_socket *nbtsock, 
				   struct nbt_name_packet *request_packet, 
				   struct socket_address *src,
				   struct nbt_name *name, 
				   struct nbtd_interface *iface)
{
	struct nbt_name_packet *packet;
	struct nbtd_server *nbtsrv = iface->nbtsrv;

	packet = nbtd_node_status_reply_packet(
		nbtsock,
		request_packet->name_trn_id,
		name,
		iface);
	if (packet == NULL) {
		return;
	}

	DEBUG(7,("Sending node status reply for %s to %s:%d\n", 
		 nbt_name_string(packet, name), src->addr, src->port));
	
	nbtsrv->stats.total_sent++;
	nbt_name_reply_send(nbtsock, src, packet);

	talloc_free(packet);
}


/*
  answer a node status query
*/
void nbtd_query_status(struct nbt_name_socket *nbtsock, 
		       struct nbt_name_packet *packet, 
		       struct socket_address *src)
{
	struct nbt_name *name;
	struct nbtd_iface_name *iname;
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private_data,
						       struct nbtd_interface);

	NBTD_ASSERT_PACKET(packet, src, packet->qdcount == 1);
	NBTD_ASSERT_PACKET(packet, src, packet->questions[0].question_type == NBT_QTYPE_STATUS);
	NBTD_ASSERT_PACKET(packet, src, packet->questions[0].question_class == NBT_QCLASS_IP);

	/* see if we have the requested name on this interface */
	name = &packet->questions[0].name;

	iname = nbtd_find_iname(iface, name, NBT_NM_ACTIVE);
	if (iname == NULL) {
		DEBUG(7,("Node status query for %s from %s - not found on %s\n",
			 nbt_name_string(packet, name), src->addr, iface->ip_address));
		return;
	}

	nbtd_node_status_reply(nbtsock, packet, src, 
			       &iname->name, iface);
}
