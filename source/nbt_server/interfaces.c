/* 
   Unix SMB/CIFS implementation.

   NBT interface handling

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
#include "smbd/service_task.h"


/*
  receive an incoming request and dispatch it to the right place
*/
static void nbt_request_handler(struct nbt_name_socket *nbtsock, 
				struct nbt_name_packet *packet, 
				const char *src_address, int src_port)
{
	switch (packet->operation & NBT_OPCODE) {
	case NBT_OPCODE_QUERY:
		nbt_request_query(nbtsock, packet, src_address, src_port);
		break;
	}
}



/*
  find a registered name on an interface
*/
struct nbt_iface_name *nbt_find_iname(struct nbt_interface *iface, struct nbt_name *name, 
				      uint16_t nb_flags)
{
	struct nbt_iface_name *iname;
	for (iname=iface->names;iname;iname=iname->next) {
		if (iname->name.type == name->type &&
		    StrCaseCmp(name->name, iname->name.name) == 0 &&
		    ((iname->nb_flags & nb_flags) == nb_flags)) {
			return iname;
		}
	}
	return NULL;
}

/*
  start listening on the given address
*/
static NTSTATUS nbt_add_socket(struct nbt_server *nbtsrv, 
			       const char *address, 
			       const char *bcast, 
			       const char *netmask)
{
	struct nbt_interface *iface;
	NTSTATUS status;
	struct nbt_name_socket *bcast_nbtsock;

	/*
	  we actually create two sockets. One listens on the broadcast address
	  for the interface, and the other listens on our specific address. This
	  allows us to run with "bind interfaces only" while still receiving 
	  broadcast addresses, and also simplifies matching incoming requests 
	  to interfaces
	*/

	iface = talloc(nbtsrv, struct nbt_interface);
	NT_STATUS_HAVE_NO_MEMORY(iface);

	iface->nbtsrv        = nbtsrv;
	iface->bcast_address = talloc_steal(iface, bcast);
	iface->ip_address    = talloc_steal(iface, address);
	iface->netmask       = talloc_steal(iface, netmask);
	iface->names         = NULL;

	if (strcmp(netmask, "0.0.0.0") != 0) {
		bcast_nbtsock = nbt_name_socket_init(iface, nbtsrv->task->event_ctx);
		NT_STATUS_HAVE_NO_MEMORY(iface->ip_address);

		status = socket_listen(bcast_nbtsock->sock, bcast, lp_nbt_port(), 0, 0);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Failed to bind to %s:%d - %s\n", 
				 bcast, lp_nbt_port(), nt_errstr(status)));
			talloc_free(iface);
			return status;
		}

		nbt_set_incoming_handler(bcast_nbtsock, nbt_request_handler, iface);
	}

	iface->nbtsock = nbt_name_socket_init(iface, nbtsrv->task->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(iface->ip_address);

	status = socket_listen(iface->nbtsock->sock, address, lp_nbt_port(), 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 address, lp_nbt_port(), nt_errstr(status)));
		talloc_free(iface);
		return status;
	}

	/* we need to be able to send broadcasts out */
	socket_set_option(iface->nbtsock->sock, "SO_BROADCAST", "1");

	nbt_set_incoming_handler(iface->nbtsock, nbt_request_handler, iface);

	if (strcmp(netmask, "0.0.0.0") == 0) {
		DLIST_ADD(nbtsrv->bcast_interface, iface);
	} else {
		DLIST_ADD(nbtsrv->interfaces, iface);
	}

	return NT_STATUS_OK;
}


/*
  setup our listening sockets on the configured network interfaces
*/
NTSTATUS nbt_startup_interfaces(struct nbt_server *nbtsrv)
{
	int num_interfaces = iface_count();
	int i;
	TALLOC_CTX *tmp_ctx = talloc_new(nbtsrv);
	NTSTATUS status;

	/* if we are allowing incoming packets from any address, then
	   we also need to bind to the wildcard address */
	if (!lp_bind_interfaces_only()) {
		const char *primary_address;

		/* the primary address is the address we will return
		   for non-WINS queries not made on a specific
		   interface */
		if (num_interfaces > 0) {
			primary_address = sys_inet_ntoa(*iface_n_ip(0));
		} else {
			primary_address = sys_inet_ntoa(interpret_addr2(
								lp_netbios_name()));
		}
		primary_address = talloc_strdup(tmp_ctx, primary_address);
		NT_STATUS_HAVE_NO_MEMORY(primary_address);

		status = nbt_add_socket(nbtsrv, 
					primary_address,
					talloc_strdup(tmp_ctx, "255.255.255.255"),
					talloc_strdup(tmp_ctx, "0.0.0.0"));
		NT_STATUS_NOT_OK_RETURN(status);
	}

	for (i=0; i<num_interfaces; i++) {
		const char *address = talloc_strdup(tmp_ctx, sys_inet_ntoa(*iface_n_ip(i)));
		const char *bcast   = talloc_strdup(tmp_ctx, sys_inet_ntoa(*iface_n_bcast(i)));
		const char *netmask = talloc_strdup(tmp_ctx, sys_inet_ntoa(*iface_n_netmask(i)));

		status = nbt_add_socket(nbtsrv, address, bcast, netmask);
		NT_STATUS_NOT_OK_RETURN(status);
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}
