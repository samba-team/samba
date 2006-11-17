/* 
   ctdb database library

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/


/*
  a pending ctdb request
*/
struct ctdb_request {
	
};

/*
  an installed ctdb remote call
*/
struct ctdb_registered_call {
	struct ctdb_registered_call *next, *prev;
	uint32_t id;
	ctdb_fn_t fn;
};

/*
  state associated with one node
*/
struct ctdb_node {
	struct ctdb_context *ctdb;
	struct ctdb_node *next, *prev;
	const char *address;
	int port;
	int fd;
};

/* main state of the ctdb daemon */
struct ctdb_context {
	struct event_context *ev;
	struct ctdb_node *nodes; /* list of nodes in the cluster */
	struct ctdb_registered_call *calls; /* list of registered calls */
	char *err_msg;
	struct tdb_context *ltdb;
};


#define CTDB_SOCKET "/tmp/ctdb.sock"
