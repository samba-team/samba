/* 
   Unix SMB/CIFS implementation.

   packet utility functions

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

/*
  we received a badly formed packet - log it
*/
void nbtd_bad_packet(struct nbt_name_packet *packet, 
		     const char *src_address, const char *reason)
{
	DEBUG(2,("nbtd: bad packet '%s' from %s\n", reason, src_address));
	if (DEBUGLVL(5)) {
		NDR_PRINT_DEBUG(nbt_name_packet, packet);		
	}
}


/*
  see if an incoming packet is from one of our own interfaces
*/
BOOL nbtd_self_packet(struct nbt_name_socket *nbtsock, 
		      struct nbt_name_packet *packet, 
		      const char *src_address, int src_port)
{
	struct nbt_interface *iface = talloc_get_type(nbtsock->incoming.private, 
						      struct nbt_interface);
	struct nbt_server *nbtsrv = iface->nbtsrv;
	
	if (src_port != lp_nbt_port()) {
		return False;
	}

	for (iface=nbtsrv->interfaces;iface;iface=iface->next) {
		if (strcmp(src_address, iface->ip_address) == 0) {
			return True;
		}
	}

	if (nbtsrv->bcast_interface &&
	    strcmp(src_address, nbtsrv->bcast_interface->ip_address) == 0) {
		return True;
	}

	return False;
}
