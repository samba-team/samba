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


/* a list of network interfaces we are listening on */
struct nbt_interface {
	struct nbt_interface *next, *prev;
	const char *ip_address;
	const char *bcast_address;
	struct nbt_name_socket *nbtsock;
	struct nbt_server *nbtsrv;
};


/*
  top level context structure for the nbt server
*/
struct nbt_server {
	struct task_server *task;

	struct nbt_interface *interfaces;
};



