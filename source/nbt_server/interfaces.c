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
#include "libcli/nbt/libnbt.h"

/*
  start listening on the given address
*/
static NTSTATUS nbt_add_socket(struct nbt_server *nbtsrv, 
			       const char *address, const char *bcast)
{
	struct nbt_interface *iface;
	NTSTATUS status;

	iface = talloc(nbtsrv, struct nbt_interface);
	NT_STATUS_HAVE_NO_MEMORY(iface);

	iface->nbtsrv = nbtsrv;
	iface->bcast_address = talloc_steal(iface, bcast);
	iface->ip_address = talloc_steal(iface, address);

	iface->nbtsock = nbt_name_socket_init(iface, nbtsrv->task->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(iface->ip_address);

	status = socket_listen(iface->nbtsock->sock, address, lp_nbt_port(), 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 address, lp_nbt_port(), nt_errstr(status)));
		talloc_free(iface);
		return status;
	}

	DLIST_ADD(nbtsrv->interfaces, iface);

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

	status = nbt_add_socket(nbtsrv, 
				talloc_strdup(tmp_ctx, "0.0.0.0"), 
				talloc_strdup(tmp_ctx, "255.255.255.255"));
	NT_STATUS_NOT_OK_RETURN(status);

	for (i=0; i<num_interfaces; i++) {
		const char *address = talloc_strdup(tmp_ctx, sys_inet_ntoa(*iface_n_ip(i)));
		const char *bcast   = talloc_strdup(tmp_ctx, sys_inet_ntoa(*iface_n_bcast(i)));

		status = nbt_add_socket(nbtsrv, address, bcast);
		NT_STATUS_NOT_OK_RETURN(status);
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}
