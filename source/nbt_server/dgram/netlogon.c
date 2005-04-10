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
  reply to a GETDC request
 */
static void nbtd_netlogon_getdc(struct dgram_mailslot_handler *dgmslot, 
				struct nbt_dgram_packet *packet, 
				const char *src_address, int src_port,
				struct nbt_netlogon_packet *netlogon)
{
	struct nbt_name *name = &packet->data.msg.dest_name;
	struct nbt_netlogon_packet reply;
	struct nbt_netlogon_response_from_pdc *pdc;

	/* only answer getdc requests on the PDC or LOGON names */
	if (name->type != NBT_NAME_PDC && name->type != NBT_NAME_LOGON) {
		return;
	}

	/* setup a GETDC reply */
	reply.command = NETLOGON_RESPONSE_FROM_PDC;
	pdc = &reply.req.response;

	pdc->pdc_name         = lp_netbios_name();
	pdc->unicode_pdc_name = pdc->pdc_name;
	pdc->domain_name      = lp_workgroup();
	pdc->nt_version       = 1;
	pdc->lmnt_token       = 0xFFFF;
	pdc->lm20_token       = 0xFFFF;


	packet->data.msg.dest_name.type = 0;

	dgram_mailslot_netlogon_reply(dgmslot->dgmsock, 
				      packet, 
				      netlogon->req.pdc.mailslot_name,
				      &reply);
}


/*
  handle incoming netlogon mailslot requests
*/
void nbtd_mailslot_netlogon_handler(struct dgram_mailslot_handler *dgmslot, 
				    struct nbt_dgram_packet *packet, 
				    const char *src_address, int src_port)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	struct nbtd_interface *iface = 
		talloc_get_type(dgmslot->private, struct nbtd_interface);
	struct nbt_netlogon_packet *netlogon = 
		talloc(dgmslot, struct nbt_netlogon_packet);
	struct nbtd_iface_name *iname;
	struct nbt_name *name = &packet->data.msg.dest_name;

	if (netlogon == NULL) goto failed;

	/*
	  see if the we are listening on the destination netbios name
	*/
	iname = nbtd_find_iname(iface, name, 0);
	if (iname == NULL) {
		status = NT_STATUS_BAD_NETWORK_NAME;
		goto failed;
	}

	DEBUG(2,("netlogon request to %s from %s:%d\n", 
		 nbt_name_string(netlogon, name), src_address, src_port));
	status = dgram_mailslot_netlogon_parse(dgmslot, netlogon, packet, netlogon);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	NDR_PRINT_DEBUG(nbt_netlogon_packet, netlogon);

	switch (netlogon->command) {
	case NETLOGON_QUERY_FOR_PDC:
		nbtd_netlogon_getdc(dgmslot, packet, src_address, src_port, netlogon);
		break;
	default:
		DEBUG(2,("unknown netlogon op %d from %s:%d\n", 
			 netlogon->command, src_address, src_port));
		break;
	}

	talloc_free(netlogon);
	return;

failed:
	DEBUG(2,("nbtd netlogon handler failed from %s:%d - %s\n",
		 src_address, src_port, nt_errstr(status)));
	talloc_free(netlogon);
}
