/* 
   Unix SMB/CIFS implementation.

   core wins server handling

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
#include "nbt_server/winsdb.h"
#include "system/time.h"

/*
  register a new name with WINS
*/
static uint8_t wins_register_new(struct nbt_name_socket *nbtsock, 
				 struct nbt_name_packet *packet, 
				 const char *src_address, int src_port)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	struct nbt_name *name = &packet->questions[0].name;
	uint32_t ttl = packet->additional[0].ttl;
	struct winsdb_record rec;

	ttl = MIN(ttl, winssrv->max_ttl);
	ttl = MAX(ttl, winssrv->min_ttl);

	rec.name          = name;
	rec.nb_flags      = packet->additional[0].rdata.netbios.addresses[0].nb_flags;
	rec.state         = WINS_REC_ACTIVE;
	rec.expire_time   = time(NULL) + ttl;
	rec.registered_by = src_address;
	rec.addresses     = str_list_make(packet, 
					  packet->additional[0].rdata.netbios.addresses[0].ipaddr,
					  NULL);
	
	return winsdb_add(winssrv, &rec);
}


/*
  register a name
*/
static void nbtd_winsserver_register(struct nbt_name_socket *nbtsock, 
				     struct nbt_name_packet *packet, 
				     const char *src_address, int src_port)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	struct nbt_name *name = &packet->questions[0].name;
	struct winsdb_record *rec;
	uint8_t rcode = 0;

	rec = winsdb_load(winssrv, name, packet);
	if (rec == NULL) {
		rcode = wins_register_new(nbtsock, packet, src_address, src_port);
	} else if (rec->state != WINS_REC_ACTIVE) {
		uint32_t ttl = packet->additional[0].ttl;
		ttl = MIN(ttl, winssrv->max_ttl);
		ttl = MAX(ttl, winssrv->min_ttl);
		rec->nb_flags      = packet->additional[0].rdata.netbios.addresses[0].nb_flags;
		rec->state         = WINS_REC_ACTIVE;
		rec->expire_time   = time(NULL) + ttl;
		rec->registered_by = src_address;
		rec->addresses     = str_list_make(packet, 
						   packet->additional[0].rdata.netbios.addresses[0].ipaddr,
						   NULL);
		winsdb_modify(winssrv, rec);
	} else {
		rcode = NBT_RCODE_ACT;
	}

	nbtd_name_registration_reply(nbtsock, packet, src_address, src_port, rcode);
}



/*
  query a name
*/
static void nbtd_winsserver_query(struct nbt_name_socket *nbtsock, 
				  struct nbt_name_packet *packet, 
				  const char *src_address, int src_port)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	struct nbt_name *name = &packet->questions[0].name;
	struct winsdb_record *rec;

	rec = winsdb_load(winssrv, name, packet);
	if (rec == NULL || rec->state != WINS_REC_ACTIVE) {
		nbtd_negative_name_query_reply(nbtsock, packet, src_address, src_port);
		return;
	}

	nbtd_name_query_reply(nbtsock, packet, src_address, src_port, name, 
			      0, rec->nb_flags, rec->addresses);
}

/*
  release a name
*/
static void nbtd_winsserver_release(struct nbt_name_socket *nbtsock, 
				    struct nbt_name_packet *packet, 
				    const char *src_address, int src_port)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	struct nbt_name *name = &packet->questions[0].name;
	struct winsdb_record *rec;

	rec = winsdb_load(winssrv, name, packet);
	if (rec != NULL && rec->state == WINS_REC_ACTIVE) {
		rec->state = WINS_REC_RELEASED;
		winsdb_modify(winssrv, rec);
	}

	/* we match w2k3 by always giving a positive reply to name releases. */
	nbtd_name_release_reply(nbtsock, packet, src_address, src_port, NBT_RCODE_OK);
}


/*
  answer a name query
*/
void nbtd_winsserver_request(struct nbt_name_socket *nbtsock, 
			     struct nbt_name_packet *packet, 
			     const char *src_address, int src_port)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	if ((packet->operation & NBT_FLAG_BROADCAST) || winssrv == NULL) {
		return;
	}

	switch (packet->operation & NBT_OPCODE) {
	case NBT_OPCODE_QUERY:
		nbtd_winsserver_query(nbtsock, packet, src_address, src_port);
		break;

	case NBT_OPCODE_REGISTER:
	case NBT_OPCODE_REFRESH:
	case NBT_OPCODE_REFRESH2:
	case NBT_OPCODE_MULTI_HOME_REG:
		nbtd_winsserver_register(nbtsock, packet, src_address, src_port);
		break;

	case NBT_OPCODE_RELEASE:
		nbtd_winsserver_release(nbtsock, packet, src_address, src_port);
		break;
	}

}

/*
  startup the WINS server, if configured
*/
NTSTATUS nbtd_winsserver_init(struct nbtd_server *nbtsrv)
{
	if (!lp_wins_support()) {
		nbtsrv->winssrv = NULL;
		return NT_STATUS_OK;
	}

	nbtsrv->winssrv = talloc(nbtsrv, struct wins_server);
	NT_STATUS_HAVE_NO_MEMORY(nbtsrv->winssrv);

	nbtsrv->winssrv->max_ttl = lp_max_wins_ttl();
	nbtsrv->winssrv->min_ttl = lp_min_wins_ttl();

	return winsdb_init(nbtsrv->winssrv);
}
