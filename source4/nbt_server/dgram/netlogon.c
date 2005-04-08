/* 
   Unix SMB/CIFS implementation.

   NBT datagram netlogon server

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
#include "lib/socket/socket.h"

/*
  handle incoming netlogon mailslot requests
*/
void nbtd_mailslot_netlogon_handler(struct dgram_mailslot_handler *dgmslot, 
				    struct nbt_dgram_packet *packet, 
				    const char *src_address, int src_port)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	struct nbt_netlogon_packet *netlogon = 
		talloc(dgmslot, struct nbt_netlogon_packet);
	if (netlogon == NULL) goto failed;

	DEBUG(2,("netlogon request from %s:%d\n", src_address, src_port));
	status = dgram_mailslot_netlogon_parse(dgmslot, netlogon, packet, netlogon);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	NDR_PRINT_DEBUG(nbt_netlogon_packet, netlogon);

	talloc_free(netlogon);
	return;

failed:
	DEBUG(2,("nbtd netlogon handler failed from %s:%d - %s\n",
		 src_address, src_port, nt_errstr(status)));
	talloc_free(netlogon);
}
