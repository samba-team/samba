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


/* ctdb_tcp main state */
struct ctdb_tcp {
	int listen_fd;
};

/*
  incoming packet structure - only used when we get a partial packet
  on read
*/
struct ctdb_tcp_partial {
	uint8_t *data;
	uint32_t length;
};


/*
  state associated with an incoming connection
*/
struct ctdb_incoming {
	struct ctdb_context *ctdb;
	int fd;
	struct ctdb_tcp_partial partial;
};

/*
  outgoing packet structure - only allocated when we can't write immediately
  to the socket
*/
struct ctdb_tcp_packet {
	struct ctdb_tcp_packet *next, *prev;
	uint8_t *data;
	uint32_t length;
};

/*
  state associated with one tcp node
*/
struct ctdb_tcp_node {
	int fd;
	struct fd_event *fde;
	struct ctdb_tcp_packet *queue;
};


/* prototypes internal to tcp transport */
void ctdb_tcp_node_write(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private);
void ctdb_tcp_incoming_read(struct event_context *ev, struct fd_event *fde, 
			    uint16_t flags, void *private);
int ctdb_tcp_queue_pkt(struct ctdb_node *node, uint8_t *data, uint32_t length);
int ctdb_tcp_listen(struct ctdb_context *ctdb);
void ctdb_tcp_node_connect(struct event_context *ev, struct timed_event *te, 
			   struct timeval t, void *private);

#define CTDB_TCP_ALIGNMENT 8
