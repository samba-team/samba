/* 
   Unix SMB/CIFS implementation.

   NBT datagram server

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
#include "smbd/service_task.h"
#include "lib/socket/socket.h"

/*
  a list of mailslots that we have static handlers for
*/
static const struct {
	const char *mailslot_name;
	dgram_mailslot_handler_t handler;
} mailslot_handlers[] = {
	{ NBT_MAILSLOT_NETLOGON, nbtd_mailslot_netlogon_handler },
	{ NBT_MAILSLOT_NTLOGON,  nbtd_mailslot_ntlogon_handler },
	{ NBT_MAILSLOT_BROWSE,   nbtd_mailslot_browse_handler }
};

/*
  receive an incoming dgram request. This is used for general datagram
  requests. Mailslot requests for our listening mailslots
  are handled in the specific mailslot handlers
*/
void dgram_request_handler(struct nbt_dgram_socket *dgmsock, 
			   struct nbt_dgram_packet *packet,
			   const struct nbt_peer_socket *src)
{
	DEBUG(0,("General datagram request from %s:%d\n", src->addr, src->port));
	NDR_PRINT_DEBUG(nbt_dgram_packet, packet);
}


/*
  setup the port 138 datagram listener for a given interface
*/
NTSTATUS nbtd_dgram_setup(struct nbtd_interface *iface, const char *bind_address)
{
	struct nbt_dgram_socket *bcast_dgmsock;
	struct nbtd_server *nbtsrv = iface->nbtsrv;
	NTSTATUS status;
	/* the list of mailslots that we are interested in */
	int i;

	/* listen for broadcasts on port 138 */
	bcast_dgmsock = nbt_dgram_socket_init(iface, nbtsrv->task->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(bcast_dgmsock);
	
	status = socket_listen(bcast_dgmsock->sock, iface->bcast_address, 
			       lp_dgram_port(), 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 iface->bcast_address, lp_dgram_port(), nt_errstr(status)));
		return status;
	}
	
	dgram_set_incoming_handler(bcast_dgmsock, dgram_request_handler, iface);

	/* listen for unicasts on port 138 */
	iface->dgmsock = nbt_dgram_socket_init(iface, nbtsrv->task->event_ctx);
	NT_STATUS_HAVE_NO_MEMORY(iface->dgmsock);

	status = socket_listen(iface->dgmsock->sock, bind_address, 
			       lp_dgram_port(), 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 bind_address, lp_dgram_port(), nt_errstr(status)));
		return status;
	}
	dgram_set_incoming_handler(iface->dgmsock, dgram_request_handler, iface);


	for (i=0;i<ARRAY_SIZE(mailslot_handlers);i++) {
		/* note that we don't need to keep the pointer
		   to the dgmslot around - the callback is all
		   we need */
		struct dgram_mailslot_handler *dgmslot;

		dgmslot = dgram_mailslot_listen(bcast_dgmsock, 
						mailslot_handlers[i].mailslot_name,
						mailslot_handlers[i].handler, iface);
		NT_STATUS_HAVE_NO_MEMORY(dgmslot);

		dgmslot = dgram_mailslot_listen(iface->dgmsock, 
						mailslot_handlers[i].mailslot_name,
						mailslot_handlers[i].handler, iface);
		NT_STATUS_HAVE_NO_MEMORY(dgmslot);
	}

	return NT_STATUS_OK;
}
