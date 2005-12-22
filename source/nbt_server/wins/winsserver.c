/* 
   Unix SMB/CIFS implementation.

   core wins server handling

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
#include "smbd/service_task.h"

/*
  work out the ttl we will use given a client requested ttl
*/
uint32_t wins_server_ttl(struct wins_server *winssrv, uint32_t ttl)
{
	ttl = MIN(ttl, winssrv->config.max_renew_interval);
	ttl = MAX(ttl, winssrv->config.min_renew_interval);
	return ttl;
}

static enum wrepl_name_type wrepl_type(uint16_t nb_flags, struct nbt_name *name, BOOL mhomed)
{
	/* this copes with the nasty hack that is the type 0x1c name */
	if (name->type == NBT_NAME_LOGON) {
		return WREPL_TYPE_SGROUP;
	}
	if (nb_flags & NBT_NM_GROUP) {
		return WREPL_TYPE_GROUP;
	}
	if (mhomed) {
		return WREPL_TYPE_MHOMED;
	}
	return WREPL_TYPE_UNIQUE;
}

/*
  register a new name with WINS
*/
static uint8_t wins_register_new(struct nbt_name_socket *nbtsock, 
				 struct nbt_name_packet *packet, 
				 const struct nbt_peer_socket *src,
				 enum wrepl_name_type type)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	struct nbt_name *name = &packet->questions[0].name;
	uint32_t ttl = wins_server_ttl(winssrv, packet->additional[0].ttl);
	uint16_t nb_flags = packet->additional[0].rdata.netbios.addresses[0].nb_flags;
	const char *address = packet->additional[0].rdata.netbios.addresses[0].ipaddr;
	struct winsdb_record rec;
	enum wrepl_name_node node;

#define WREPL_NODE_NBT_FLAGS(nb_flags) \
	((nb_flags & NBT_NM_OWNER_TYPE)>>13)

	node	= WREPL_NODE_NBT_FLAGS(nb_flags);

	rec.name		= name;
	rec.type		= type;
	rec.state		= WREPL_STATE_ACTIVE;
	rec.node		= node;
	rec.is_static		= False;
	rec.expire_time		= time(NULL) + ttl;
	rec.version		= 0; /* will allocated later */
	rec.wins_owner		= NULL; /* will be set later */
	rec.registered_by	= src->addr;
	rec.addresses		= winsdb_addr_list_make(packet);
	if (rec.addresses == NULL) return NBT_RCODE_SVR;

	rec.addresses     = winsdb_addr_list_add(rec.addresses,
						 address,
						 WINSDB_OWNER_LOCAL,
						 rec.expire_time);
	if (rec.addresses == NULL) return NBT_RCODE_SVR;

	DEBUG(4,("WINS: accepted registration of %s with address %s\n",
		 nbt_name_string(packet, name), rec.addresses[0]->address));
	
	return winsdb_add(winssrv->wins_db, &rec, WINSDB_FLAG_ALLOC_VERSION | WINSDB_FLAG_TAKE_OWNERSHIP);
}


/*
  update the ttl on an existing record
*/
static uint8_t wins_update_ttl(struct nbt_name_socket *nbtsock, 
			       struct nbt_name_packet *packet, 
			       struct winsdb_record *rec,
			       struct winsdb_addr *winsdb_addr,
			       const struct nbt_peer_socket *src)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	uint32_t ttl = wins_server_ttl(winssrv, packet->additional[0].ttl);
	const char *address = packet->additional[0].rdata.netbios.addresses[0].ipaddr;
	uint32_t modify_flags = 0;

	rec->expire_time   = time(NULL) + ttl;
	rec->registered_by = src->addr;

	if (winsdb_addr) {
		winsdb_addr->wins_owner  = WINSDB_OWNER_LOCAL;
		winsdb_addr->expire_time = rec->expire_time;
	}

	if (strcmp(WINSDB_OWNER_LOCAL, rec->wins_owner) != 0) {
		modify_flags = WINSDB_FLAG_ALLOC_VERSION | WINSDB_FLAG_TAKE_OWNERSHIP;
	}

	DEBUG(5,("WINS: refreshed registration of %s at %s\n",
		 nbt_name_string(packet, rec->name), address));
	
	return winsdb_modify(winssrv->wins_db, rec, modify_flags);
}

/*
  do a sgroup merge
*/
static uint8_t wins_sgroup_merge(struct nbt_name_socket *nbtsock, 
				 struct nbt_name_packet *packet, 
			         struct winsdb_record *rec,
			         const char *address,
			         const struct nbt_peer_socket *src)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	uint32_t ttl = wins_server_ttl(winssrv, packet->additional[0].ttl);

	rec->expire_time   = time(NULL) + ttl;
	rec->registered_by = src->addr;

	rec->addresses     = winsdb_addr_list_add(rec->addresses,
						  address,
						  WINSDB_OWNER_LOCAL,
						  rec->expire_time);
	if (rec->addresses == NULL) return NBT_RCODE_SVR;

	DEBUG(5,("WINS: sgroup merge of %s at %s\n",
		 nbt_name_string(packet, rec->name), address));
	
	return winsdb_modify(winssrv->wins_db, rec, WINSDB_FLAG_ALLOC_VERSION | WINSDB_FLAG_TAKE_OWNERSHIP);
}

/*
  register a name
*/
static void nbtd_winsserver_register(struct nbt_name_socket *nbtsock, 
				     struct nbt_name_packet *packet, 
				     const struct nbt_peer_socket *src)
{
	NTSTATUS status;
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	struct nbt_name *name = &packet->questions[0].name;
	struct winsdb_record *rec;
	uint8_t rcode = NBT_RCODE_OK;
	uint16_t nb_flags = packet->additional[0].rdata.netbios.addresses[0].nb_flags;
	const char *address = packet->additional[0].rdata.netbios.addresses[0].ipaddr;
	BOOL mhomed = ((packet->operation & NBT_OPCODE) == NBT_OPCODE_MULTI_HOME_REG);
	enum wrepl_name_type new_type = wrepl_type(nb_flags, name, mhomed);
	struct winsdb_addr *winsdb_addr = NULL;

	/*
	 * as a special case, the local master browser name is always accepted
	 * for registration, but never stored, but w2k3 stores it if it's registered
	 * as a group name, (but a query for the 0x1D name still returns not found!)
	 */
	if (name->type == NBT_NAME_MASTER && !(nb_flags & NBT_NM_GROUP)) {
		rcode = NBT_RCODE_OK;
		goto done;
	}

	/* w2k3 refuses 0x1B names with marked as group */
	if (name->type == NBT_NAME_PDC && (nb_flags & NBT_NM_GROUP)) {
		rcode = NBT_RCODE_RFS;
		goto done;
	}

	/* w2k3 refuses 0x1C names with out marked as group */
	if (name->type == NBT_NAME_LOGON && !(nb_flags & NBT_NM_GROUP)) {
		rcode = NBT_RCODE_RFS;
		goto done;
	}

	/* w2k3 refuses 0x1E names with out marked as group */
	if (name->type == NBT_NAME_BROWSER && !(nb_flags & NBT_NM_GROUP)) {
		rcode = NBT_RCODE_RFS;
		goto done;
	}

	status = winsdb_lookup(winssrv->wins_db, name, packet, &rec);
	if (NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_NOT_FOUND, status)) {
		rcode = wins_register_new(nbtsock, packet, src, new_type);
		goto done;
	} else if (!NT_STATUS_IS_OK(status)) {
		rcode = NBT_RCODE_SVR;
		goto done;
	} else if (rec->is_static) {
		if (rec->type == WREPL_TYPE_GROUP || rec->type == WREPL_TYPE_SGROUP) {
			rcode = NBT_RCODE_OK;
			goto done;
		}
		rcode = NBT_RCODE_ACT;
		goto done;
	}

	if (rec->type == WREPL_TYPE_GROUP) {
		if (new_type != WREPL_TYPE_GROUP) {
			DEBUG(2,("WINS: Attempt to register name %s as non normal group(%u)"
				 " while a normal group is already there\n",
				 nbt_name_string(packet, name), new_type));
			rcode = NBT_RCODE_ACT;
			goto done;
		}

		if (rec->state == WREPL_STATE_ACTIVE) {
			/* TODO: is this correct? */
			rcode = wins_update_ttl(nbtsock, packet, rec, NULL, src);
			goto done;
		}

		/* TODO: is this correct? */
		winsdb_delete(winssrv->wins_db, rec);
		rcode = wins_register_new(nbtsock, packet, src, new_type);
		goto done;
	}

	if (rec->state != WREPL_STATE_ACTIVE) {
		winsdb_delete(winssrv->wins_db, rec);
		rcode = wins_register_new(nbtsock, packet, src, new_type);
		goto done;
	}

	switch (rec->type) {
	case WREPL_TYPE_UNIQUE:
	case WREPL_TYPE_MHOMED:
		/* 
		 * if its an active unique name, and the registration is for a group, then
		 * see if the unique name owner still wants the name
		 * TODO: is this correct?
		 */
		if (new_type == WREPL_TYPE_GROUP || new_type == WREPL_TYPE_GROUP) {
			wins_register_wack(nbtsock, packet, rec, src);
			return;
		}

		/* 
		 * if the registration is for an address that is currently active, then 
		 * just update the expiry time of the record and the address
		 * TODO: is this correct?
		 */
		winsdb_addr = winsdb_addr_list_check(rec->addresses, address);
		if (winsdb_addr) {
			rcode = wins_update_ttl(nbtsock, packet, rec, winsdb_addr, src);
			goto done;
		}

		/*
		 * we have to do a WACK to see if the current owner is willing
		 * to give up its claim
		 */
		wins_register_wack(nbtsock, packet, rec, src);
		return;

	case WREPL_TYPE_GROUP:
		/* this should not be reached as normal groups are handled above */
		DEBUG(0,("BUG at %s\n",__location__));
		rcode = NBT_RCODE_ACT;
		goto done;

	case WREPL_TYPE_SGROUP:
		/* if the new record isn't also a special group, refuse the registration */ 
		if (new_type != WREPL_TYPE_SGROUP) {
			DEBUG(2,("WINS: Attempt to register name %s as non special group(%u)"
				 " while a special group is already there\n",
				 nbt_name_string(packet, name), new_type));
			rcode = NBT_RCODE_ACT;
			goto done;
		}

		/* 
		 * if the registration is for an address that is currently active, then 
		 * just update the expiry time
		 * just update the expiry time of the record and the address
		 * TODO: is this correct?
		 */
		winsdb_addr = winsdb_addr_list_check(rec->addresses, address);
		if (winsdb_addr) {
			rcode = wins_update_ttl(nbtsock, packet, rec, winsdb_addr, src);
			goto done;
		}

		rcode = wins_sgroup_merge(nbtsock, packet, rec, address, src);
		goto done;
	}

done:
	nbtd_name_registration_reply(nbtsock, packet, src, rcode);
}

/*
  query a name
*/
static void nbtd_winsserver_query(struct nbt_name_socket *nbtsock, 
				  struct nbt_name_packet *packet, 
				  const struct nbt_peer_socket *src)
{
	NTSTATUS status;
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	struct nbt_name *name = &packet->questions[0].name;
	struct winsdb_record *rec;
	const char **addresses;
	uint16_t nb_flags = 0; /* TODO: ... */

	if (name->type == NBT_NAME_MASTER) {
		goto notfound;
	}

	status = winsdb_lookup(winssrv->wins_db, name, packet, &rec);
	if (!NT_STATUS_IS_OK(status)) {
		goto notfound;
	}

	/*
	 * for group's we always reply with
	 * 255.255.255.255 as address, even if
	 * the record is released or tombstoned
	 */
	if (rec->type == WREPL_TYPE_GROUP) {
		addresses = talloc_array(packet, const char *, 2);
		if (addresses == NULL) {
			nbtd_negative_name_query_reply(nbtsock, packet, src);
			return;
		}
		addresses[0] = WINSDB_GROUP_ADDRESS;
		addresses[1] = NULL;
		goto found;
	}

	if (rec->state != WREPL_STATE_ACTIVE) {
		goto notfound;
	}

	addresses = winsdb_addr_string_list(packet, rec->addresses);
	if (!addresses) {
		goto notfound;
	}
found:
	nbtd_name_query_reply(nbtsock, packet, src, name, 
			      0, nb_flags, addresses);
	return;

notfound:
	nbtd_negative_name_query_reply(nbtsock, packet, src);
}

/*
  release a name
*/
static void nbtd_winsserver_release(struct nbt_name_socket *nbtsock, 
				    struct nbt_name_packet *packet, 
				    const struct nbt_peer_socket *src)
{
	NTSTATUS status;
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	struct nbt_name *name = &packet->questions[0].name;
	struct winsdb_record *rec;
	uint32_t modify_flags = 0;
	uint8_t ret;

	status = winsdb_lookup(winssrv->wins_db, name, packet, &rec);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	if (rec->is_static) {
		if (rec->type == WREPL_TYPE_UNIQUE || rec->type == WREPL_TYPE_MHOMED) {
			goto done;
		}
		nbtd_name_release_reply(nbtsock, packet, src, NBT_RCODE_ACT);
		return;
	}

	if (rec->state != WREPL_STATE_ACTIVE) {
		goto done;
	}

	/* 
	 * TODO: do we need to check if
	 *       src->addr matches packet->additional[0].rdata.netbios.addresses[0].ipaddr
	 *       here?
	 */

	/* 
	 * we only allow releases from an owner - other releases are
	 * silently ignored
	 */
	if (!winsdb_addr_list_check(rec->addresses, src->addr)) {
		goto done;
	}

	DEBUG(4,("WINS: released name %s from %s\n", nbt_name_string(rec, rec->name), src->addr));

	switch (rec->type) {
	case WREPL_TYPE_UNIQUE:
		rec->state = WREPL_STATE_RELEASED;
		break;

	case WREPL_TYPE_GROUP:
		rec->state = WREPL_STATE_RELEASED;
		break;

	case WREPL_TYPE_SGROUP:
		winsdb_addr_list_remove(rec->addresses, src->addr);
		/* TODO: do we need to take the ownership here? */
		if (winsdb_addr_list_length(rec->addresses) == 0) {
			rec->state = WREPL_STATE_RELEASED;
		}
		break;

	case WREPL_TYPE_MHOMED:
		winsdb_addr_list_remove(rec->addresses, src->addr);
		/* TODO: do we need to take the ownership here? */
		if (winsdb_addr_list_length(rec->addresses) == 0) {
			rec->state = WREPL_STATE_RELEASED;
		}
		break;
	}

	if (rec->state == WREPL_STATE_RELEASED) {
		rec->expire_time = time(NULL) + winssrv->config.tombstone_interval;
	}

	ret = winsdb_modify(winssrv->wins_db, rec, modify_flags);
	if (ret != NBT_RCODE_OK) {
		DEBUG(1,("WINS: FAILED: released name %s at %s: error:%u\n",
			nbt_name_string(rec, rec->name), src->addr, ret));
	}
done:
	/* we match w2k3 by always giving a positive reply to name releases. */
	nbtd_name_release_reply(nbtsock, packet, src, NBT_RCODE_OK);
}


/*
  answer a name query
*/
void nbtd_winsserver_request(struct nbt_name_socket *nbtsock, 
			     struct nbt_name_packet *packet, 
			     const struct nbt_peer_socket *src)
{
	struct nbtd_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						       struct nbtd_interface);
	struct wins_server *winssrv = iface->nbtsrv->winssrv;
	if ((packet->operation & NBT_FLAG_BROADCAST) || winssrv == NULL) {
		return;
	}

	switch (packet->operation & NBT_OPCODE) {
	case NBT_OPCODE_QUERY:
		nbtd_winsserver_query(nbtsock, packet, src);
		break;

	case NBT_OPCODE_REGISTER:
	case NBT_OPCODE_REFRESH:
	case NBT_OPCODE_REFRESH2:
	case NBT_OPCODE_MULTI_HOME_REG:
		nbtd_winsserver_register(nbtsock, packet, src);
		break;

	case NBT_OPCODE_RELEASE:
		nbtd_winsserver_release(nbtsock, packet, src);
		break;
	}

}

/*
  startup the WINS server, if configured
*/
NTSTATUS nbtd_winsserver_init(struct nbtd_server *nbtsrv)
{
	uint32_t tombstone_interval;

	if (!lp_wins_support()) {
		nbtsrv->winssrv = NULL;
		return NT_STATUS_OK;
	}

	nbtsrv->winssrv = talloc_zero(nbtsrv, struct wins_server);
	NT_STATUS_HAVE_NO_MEMORY(nbtsrv->winssrv);

	nbtsrv->winssrv->config.max_renew_interval = lp_max_wins_ttl();
	nbtsrv->winssrv->config.min_renew_interval = lp_min_wins_ttl();
	tombstone_interval = lp_parm_int(-1,"wreplsrv","tombstone_interval", 6*24*60*60);
	nbtsrv->winssrv->config.tombstone_interval = tombstone_interval;

	nbtsrv->winssrv->wins_db     = winsdb_connect(nbtsrv->winssrv);
	if (!nbtsrv->winssrv->wins_db) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	irpc_add_name(nbtsrv->task->msg_ctx, "wins_server");

	return NT_STATUS_OK;
}
