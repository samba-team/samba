/* 
   Unix SMB/CIFS implementation.

   NBT server structures

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

#include "libcli/nbt/libnbt.h"

/* 
   a list of our registered names on each interface
*/
struct nbt_iface_name {
	struct nbt_iface_name *next, *prev;
	struct nbt_interface *iface;
	struct nbt_name name;
	uint16_t nb_flags;
	struct timeval registration_time;
	uint32_t ttl;
};


/* a list of network interfaces we are listening on */
struct nbt_interface {
	struct nbt_interface *next, *prev;
	struct nbt_server *nbtsrv;
	const char *ip_address;
	const char *bcast_address;
	const char *netmask;
	struct nbt_name_socket *nbtsock;
	struct nbt_iface_name *names;
};


/*
  top level context structure for the nbt server
*/
struct nbt_server {
	struct task_server *task;

	/* the list of local network interfaces */
	struct nbt_interface *interfaces;

	/* broadcast interface used for receiving packets only */
	struct nbt_interface *bcast_interface;
};



/* check a condition on an incoming packet */
#define NBT_ASSERT_PACKET(packet, src_address, test) do { \
	if (!(test)) { \
		nbt_bad_packet(packet, src_address, #test); \
		return; \
	} \
} while (0)
