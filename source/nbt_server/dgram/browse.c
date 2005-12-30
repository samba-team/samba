/* 
   Unix SMB/CIFS implementation.

   NBT datagram browse server

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

/*
  handle incoming browse mailslot requests
*/
void nbtd_mailslot_browse_handler(struct dgram_mailslot_handler *dgmslot, 
				  struct nbt_dgram_packet *packet, 
				  const struct nbt_peer_socket *src)
{
	DEBUG(2,("Browse request on '%s' from %s:%d\n", 
		  dgmslot->mailslot_name, src->addr, src->port));
}
