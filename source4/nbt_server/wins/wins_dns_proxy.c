/* 
   Unix SMB/CIFS implementation.

   wins server dns proxy

   Copyright (C) Stefan Metzmacher	2005
      
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
#include "nbt_server/wins/winsdb.h"
#include "nbt_server/wins/winsserver.h"
#include "system/time.h"
#include "libcli/composite/composite.h"
#include "smbd/service_task.h"

/*
  dns proxy query a name
*/
void nbtd_wins_dns_proxy_query(struct nbt_name_socket *nbtsock, 
			       struct nbt_name_packet *packet, 
			       const struct nbt_peer_socket *src)
{
	/* TODO: add a real implementation here */
	nbtd_negative_name_query_reply(nbtsock, packet, src);
}
