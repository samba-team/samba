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
  work out the ttl we will use given a client requested ttl
*/
uint32_t wins_server_ttl(struct wins_server *winssrv, uint32_t ttl)
{
	ttl = MIN(ttl, winssrv->max_ttl);
	ttl = MAX(ttl, winssrv->min_ttl);
	return ttl;
}

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
	uint32_t ttl = wins_server_ttl(winssrv, packet->additional[0].ttl);
	uint16_t nb_flags = packet->additional[0].rdata.netbios.addresses[0].nb_flags;
	const char *address = packet->additional[0].rdata.netbios.addresses[0].ipaddr;
	struct winsdb_record rec;

	rec.name          = name;
	rec.nb_flags      = nb_flags;
	rec.state         = WINS_REC_ACTIVE;
	rec.expire_time   = time(NULL) + ttl;
	rec.registered_by = src_address;
	if (IS_GROUP_NAME(name, nb_flags)) {
		rec.addresses     = str_list_make(packet, "255.255.255.255", NULL);
	} else {
		rec.addresses     = str_list_make(packet, address, NULL);
	}
	if (rec.addresses == NULL) return NBT_RCODE_SVR;

	DEBUG(4,("WINS: accepted registration of %s with address %s\n",
		 nbt_name_string(packet, name), rec.addresses[0]));
	
	return winsdb_add(winssrv, &rec);
}


/*
  update the ttl on an existing record
*/
static uint8_t wins_update_ttl(struct nbt_name_socket *nbtsock, 
			       struct nbt_name_packet *packet, 
			       struct winsdb_record *rec,
			       const char *src_address, int src_port)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	uint32_t ttl = wins_server_ttl(winssrv, packet->additional[0].ttl);
	const char *address = packet->additional[0].rdata.netbios.addresses[0].ipaddr;
	time_t now = time(NULL);

	if (now + ttl > rec->expire_time) {
		rec->expire_time   = now + ttl;
	}
	rec->registered_by = src_address;

	DEBUG(5,("WINS: refreshed registration of %s at %s\n",
		 nbt_name_string(packet, rec->name), address));
	
	return winsdb_modify(winssrv, rec);
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
	uint8_t rcode = NBT_RCODE_OK;
	uint16_t nb_flags = packet->additional[0].rdata.netbios.addresses[0].nb_flags;
	const char *address = packet->additional[0].rdata.netbios.addresses[0].ipaddr;

	/* as a special case, the local master browser name is always accepted
	   for registration, but never stored */
	if (name->type == NBT_NAME_MASTER) {
		goto done;
	}

	rec = winsdb_load(winssrv, name, packet);
	if (rec == NULL) {
		rcode = wins_register_new(nbtsock, packet, src_address, src_port);
		goto done;
	} else if (rec->state != WINS_REC_ACTIVE) {
		winsdb_delete(winssrv, rec);
		rcode = wins_register_new(nbtsock, packet, src_address, src_port);
		goto done;
	}

	/* its an active name - first see if the registration is of the right type */
	if ((rec->nb_flags & NBT_NM_GROUP) && !(nb_flags & NBT_NM_GROUP)) {
		DEBUG(2,("WINS: Attempt to register unique name %s when group name is active\n",
			 nbt_name_string(packet, name)));
		rcode = NBT_RCODE_ACT;
		goto done;
	}

	/* if its an active unique name, and the registration is for a group, then
	   see if the unique name owner still wants the name */
	if (!(rec->nb_flags & NBT_NM_GROUP) && (nb_flags & NBT_NM_GROUP)) {
		wins_register_wack(nbtsock, packet, rec, src_address, src_port);
		return;
	}

	/* if the registration is for a group, then just update the expiry time 
	   and we are done */
	if (IS_GROUP_NAME(name, nb_flags)) {
		wins_update_ttl(nbtsock, packet, rec, src_address, src_port);
		goto done;
	}

	/* if the registration is for an address that is currently active, then 
	   just update the expiry time */
	if (str_list_check(rec->addresses, address)) {
		wins_update_ttl(nbtsock, packet, rec, src_address, src_port);
		goto done;
	}

	/* we have to do a WACK to see if the current owner is willing
	   to give up its claim */	
	wins_register_wack(nbtsock, packet, rec, src_address, src_port);
	return;

done:
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
	if (rec == NULL || 
	    rec->state != WINS_REC_ACTIVE || 
	    IS_GROUP_NAME(name, rec->nb_flags)) {
		goto done;
	}

	/* we only allow releases from an owner - other releases are
	   silently ignored */
	if (str_list_check(rec->addresses, src_address)) {
		const char *address = packet->additional[0].rdata.netbios.addresses[0].ipaddr;

		DEBUG(4,("WINS: released name %s at %s\n", nbt_name_string(rec, rec->name), address));
		str_list_remove(rec->addresses, address);
		if (rec->addresses[0] == NULL) {
			rec->state = WINS_REC_RELEASED;
		}
		winsdb_modify(winssrv, rec);
	}

done:
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
