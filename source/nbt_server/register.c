/* 
   Unix SMB/CIFS implementation.

   register our names

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
#include "nbt_server/nbt_server.h"
#include "libcli/raw/libcliraw.h"
#include "libcli/composite/composite.h"

/*
  start a timer to refresh this name
*/
static void nbt_start_refresh_timer(struct nbt_iface_name *iname)
{
}


/*
  a name registration has completed
*/
static void nbt_register_handler(struct smbcli_composite *req)
{
	struct nbt_iface_name *iname = talloc_get_type(req->async.private, struct nbt_iface_name);
	NTSTATUS status;

	status = nbt_name_register_bcast_recv(req);
	if (NT_STATUS_IS_OK(status)) {
		/* good - nobody complained about our registration */
		iname->nb_flags |= NBT_NM_ACTIVE;
		DEBUG(3,("Registered %s<%02x> on interface %s\n",
			 iname->name.name, iname->name.type, iname->iface->bcast_address));
		nbt_start_refresh_timer(iname);
		return;
	}

	/* someone must have replied with an objection! */
	iname->nb_flags |= NBT_NM_CONFLICT;

	DEBUG(1,("Error registering %s<%02x> on interface %s - %s\n",
		 iname->name.name, iname->name.type, iname->iface->bcast_address,
		 nt_errstr(status)));
}


/*
  register a name on a network interface
*/
static void nbt_register_name_iface(struct nbt_interface *iface,
				    const char *name, enum nbt_name_type type,
				    uint16_t nb_flags)
{
	struct nbt_iface_name *iname;
	const char *scope = lp_netbios_scope();
	struct nbt_name_register_bcast io;
	struct smbcli_composite *req;

	iname = talloc(iface, struct nbt_iface_name);
	if (!iname) return;

	iname->iface     = iface;
	iname->name.name = talloc_strdup(iname, name);
	iname->name.type = type;
	if (scope && *scope) {
		iname->name.scope = talloc_strdup(iname, scope);
	} else {
		iname->name.scope = NULL;
	}
	iname->nb_flags          = nb_flags;
	iname->ttl               = lp_parm_int(-1, "nbtd", "bcast_ttl", 300000);
	iname->registration_time = timeval_zero();

	DLIST_ADD(iface->names, iname);

	if (nb_flags & NBT_NM_PERMANENT) {
		/* permanent names are not announced and are immediately active */
		iname->nb_flags |= NBT_NM_ACTIVE;
		iname->ttl       = 0;
		return;
	}

	/* setup a broadcast name registration request */
	io.in.name            = iname->name;
	io.in.dest_addr       = iface->bcast_address;
	io.in.address         = iface->ip_address;
	io.in.nb_flags        = nb_flags;
	io.in.ttl             = iname->ttl;

	req = nbt_name_register_bcast_send(iface->nbtsock, &io);
	if (req == NULL) return;

	req->async.fn = nbt_register_handler;
	req->async.private = iname;
}


/*
  register one name on all our interfaces
*/
static void nbt_register_name(struct nbt_server *nbtsrv, 
			      const char *name, enum nbt_name_type type,
			      uint16_t nb_flags)
{
	struct nbt_interface *iface;
	
	/* register with all the local interfaces */
	for (iface=nbtsrv->interfaces;iface;iface=iface->next) {
		nbt_register_name_iface(iface, name, type, nb_flags);
	}

	/* register on our general broadcast interface as a permanent name */
	nbt_register_name_iface(nbtsrv->bcast_interface, name, type, nb_flags | NBT_NM_PERMANENT);

	/* TODO: register with our WINS servers */
}


/*
  register our names on all interfaces
*/
void nbt_register_names(struct nbt_server *nbtsrv)
{
	uint16_t nb_flags = NBT_NODE_M;

	/* note that we don't initially mark the names "ACTIVE". They are 
	   marked active once registration is successful */
	nbt_register_name(nbtsrv, lp_netbios_name(), NBT_NAME_CLIENT, nb_flags);
	nbt_register_name(nbtsrv, lp_netbios_name(), NBT_NAME_USER,   nb_flags);
	nbt_register_name(nbtsrv, lp_netbios_name(), NBT_NAME_SERVER, nb_flags);
	nbt_register_name(nbtsrv, lp_workgroup(),    NBT_NAME_CLIENT, nb_flags | NBT_NM_GROUP);
	nbt_register_name(nbtsrv, lp_workgroup(),    NBT_NAME_SERVER, nb_flags | NBT_NM_GROUP);
	nbt_register_name(nbtsrv, "__SAMBA__",       NBT_NAME_CLIENT, nb_flags | NBT_NM_PERMANENT);
	nbt_register_name(nbtsrv, "__SAMBA__",       NBT_NAME_SERVER, nb_flags | NBT_NM_PERMANENT);
}
