/* 
   Unix SMB/CIFS implementation.

   NBT datagram ntlogon server

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
  handle incoming ntlogon mailslot requests
*/
void nbtd_mailslot_ntlogon_handler(struct dgram_mailslot_handler *dgmslot, 
				    struct nbt_dgram_packet *packet, 
				    const char *src_address, int src_port)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	struct nbtd_interface *iface = 
		talloc_get_type(dgmslot->private, struct nbtd_interface);
	struct nbt_ntlogon_packet *ntlogon = 
		talloc(dgmslot, struct nbt_ntlogon_packet);
	struct nbtd_iface_name *iname;
	struct nbt_name *name = &packet->data.msg.dest_name;

	if (ntlogon == NULL) goto failed;

	/*
	  see if the we are listening on the destination netbios name
	*/
	iname = nbtd_find_iname(iface, name, 0);
	if (iname == NULL) {
		status = NT_STATUS_BAD_NETWORK_NAME;
		goto failed;
	}

	DEBUG(2,("ntlogon request to %s from %s:%d\n", 
		 nbt_name_string(ntlogon, name), src_address, src_port));
	status = dgram_mailslot_ntlogon_parse(dgmslot, ntlogon, packet, ntlogon);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	NDR_PRINT_DEBUG(nbt_ntlogon_packet, ntlogon);

	switch (ntlogon->command) {
	default:
		DEBUG(2,("unknown ntlogon op %d from %s:%d\n", 
			 ntlogon->command, src_address, src_port));
		break;
	}

	talloc_free(ntlogon);
	return;

failed:
	DEBUG(2,("nbtd ntlogon handler failed from %s:%d - %s\n",
		 src_address, src_port, nt_errstr(status)));
	talloc_free(ntlogon);
}
