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
  see if a src address matches an interface
*/
static BOOL nbt_iface_match(struct nbt_interface *iface, const char *src_address)
{
	struct ipv4_addr ip1, ip2, mask;
	ip1  = interpret_addr2(iface->ip_address);
	ip2  = interpret_addr2(src_address);
	mask = interpret_addr2(iface->netmask);
	return same_net(ip1, ip2, mask);
}


/*
  find the appropriate interface for a incoming packet. If a local interface isn't
  found then the general broadcast interface is used
*/
struct nbt_interface *nbt_iface_find(struct nbt_name_socket *nbtsock, const char *src_address)
{
	struct nbt_interface *iface = talloc_get_type(nbtsock->incoming.private, struct nbt_interface);
	struct nbt_server *nbtsrv = iface->nbtsrv;
	
	/* it might have been received by one of our specific bound
	   addresses */
	if (iface != nbtsrv->bcast_interface) {
		return iface;
	}

	/* it came in on our broadcast interface - try to find a match */
	for (iface=nbtsrv->interfaces;iface;iface=iface->next) {
		if (nbt_iface_match(iface, src_address)) {
			return iface;
		}
	}

	/* it didn't match any specific interface - use our general broadcast interface */
	return nbtsrv->bcast_interface;
}


/*
  start listening on the given address
*/
static NTSTATUS nbt_add_socket(struct nbt_server *nbtsrv, 
			       const char *bind_address, 
			       const char *address, 
			       const char *bcast, 
			       const char *netmask)
{
	struct nbt_interface *iface;
	NTSTATUS status;

	iface = talloc(nbtsrv, struct nbt_interface);
	NT_STATUS_HAVE_NO_MEMORY(iface);

	iface->nbtsrv        = nbtsrv;
	iface->bcast_address = talloc_steal(iface, bcast);
	iface->ip_address    = talloc_steal(iface, address);
	iface->netmask       = talloc_steal(iface, netmask);
	iface->names         = NULL;

	iface->nbtsock = nbt_name_socket_init(iface, nbtsrv->task->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(iface->ip_address);

	status = socket_listen(iface->nbtsock->sock, bind_address, lp_nbt_port(), 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 address, lp_nbt_port(), nt_errstr(status)));
		talloc_free(iface);
		return status;
	}

	socket_set_option(iface->nbtsock->sock, "SO_BROADCAST", "1");

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
	const char *primary_address;

	/* the primary address is the address we will return for non-WINS queries 
	   not made on a specific interface */
	if (num_interfaces > 0) {
		primary_address = talloc_strdup(tmp_ctx, sys_inet_ntoa(*iface_n_ip(0)));
	} else {
		primary_address = sys_inet_ntoa(interpret_addr2(lp_netbios_name()));
	}

	status = nbt_add_socket(nbtsrv, 
				"0.0.0.0",
				primary_address,
				talloc_strdup(tmp_ctx, "255.255.255.255"),
				talloc_strdup(tmp_ctx, "0.0.0.0"));
	NT_STATUS_NOT_OK_RETURN(status);

	for (i=0; i<num_interfaces; i++) {
		const char *address = talloc_strdup(tmp_ctx, sys_inet_ntoa(*iface_n_ip(i)));
		const char *bcast   = talloc_strdup(tmp_ctx, sys_inet_ntoa(*iface_n_bcast(i)));
		const char *netmask = talloc_strdup(tmp_ctx, sys_inet_ntoa(*iface_n_netmask(i)));

		status = nbt_add_socket(nbtsrv, address, address, bcast, netmask);
		NT_STATUS_NOT_OK_RETURN(status);
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}
