/* 
   Unix SMB/CIFS implementation.

   core wins server handling

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



static void nbtd_winsserver_query(struct nbt_name_socket *nbtsock, 
				  struct nbt_name_packet *packet, 
				  const char *src_address, int src_port)
{
	nbtd_negative_name_query_reply(nbtsock, packet, src_address, src_port);
}

static void nbtd_winsserver_register(struct nbt_name_socket *nbtsock, 
				    struct nbt_name_packet *packet, 
				    const char *src_address, int src_port)
{
	nbtd_negative_name_registration_reply(nbtsock, packet, src_address, src_port);
}


static void nbtd_winsserver_release(struct nbt_name_socket *nbtsock, 
				    struct nbt_name_packet *packet, 
				    const char *src_address, int src_port)
{
}


/*
  answer a name query
*/
void nbtd_winsserver_request(struct nbt_name_socket *nbtsock, 
			     struct nbt_name_packet *packet, 
			     const char *src_address, int src_port)
{
	if (packet->operation & NBT_FLAG_BROADCAST) {
		return;
	}

	switch (packet->operation & NBT_OPCODE) {
	case NBT_OPCODE_QUERY:
		nbtd_winsserver_query(nbtsock, packet, src_address, src_port);
		break;

	case NBT_OPCODE_REGISTER:
	case NBT_OPCODE_REFRESH:
	case NBT_OPCODE_REFRESH2:
	case NBT_OPCODE_MULTI_HOME_REG:
		nbtd_winsserver_register(nbtsock, packet, src_address, src_port);
		break;

	case NBT_OPCODE_RELEASE:
		nbtd_winsserver_release(nbtsock, packet, src_address, src_port);
		break;
	}

}

/*
  startup the WINS server, if configured
*/
NTSTATUS nbtd_winsserver_init(struct nbtd_server *nbtsrv)
{
	if (!lp_wins_support()) {
		nbtsrv->wins_db = NULL;
		return NT_STATUS_OK;
	}

	nbtsrv->wins_db = ldb_wrap_connect(nbtsrv, lp_wins_url(), 0, NULL);
	if (nbtsrv->wins_db == NULL) {
		return NT_STATUS_INTERNAL_DB_ERROR;
	}

	return NT_STATUS_OK;
}
