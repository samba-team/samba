/* 
   ctdb over TCP

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

#include "includes.h"
#include "lib/events/events.h"
#include "system/network.h"
#include "system/filesys.h"
#include "ctdb_private.h"
#include "ctdb_tcp.h"

/*
  called when socket becomes readable
*/
void ctdb_tcp_node_read(struct event_context *ev, struct fd_event *fde, 
			uint16_t flags, void *private)
{
	struct ctdb_node *node = talloc_get_type(private, struct ctdb_node);
	printf("connection to node %s:%u is readable\n", 
	       node->address.address, node->address.port);
	event_set_fd_flags(fde, 0);
}


/*
  called when an incoming connection is readable
*/
void ctdb_tcp_incoming_read(struct event_context *ev, struct fd_event *fde, 
			    uint16_t flags, void *private)
{
	struct ctdb_incoming *in = talloc_get_type(private, struct ctdb_incoming);
	char c;
	printf("Incoming data\n");
	if (read(in->fd, &c, 1) <= 0) {
		/* socket is dead */
		close(in->fd);
		talloc_free(in);
	}
}

