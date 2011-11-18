/* 
   ctdb database library

   Copyright (C) Andrew Tridgell  2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _CTDB_TCP_H
#define _CTDB_TCP_H
 
/* ctdb_tcp main state */
struct ctdb_tcp {
	struct ctdb_context *ctdb;
	int listen_fd;
};

/*
  state associated with an incoming connection
*/
struct ctdb_incoming {
	struct ctdb_context *ctdb;
	int fd;
	struct ctdb_queue *queue;
};

/*
  state associated with one tcp node
*/
struct ctdb_tcp_node {
	int fd;
	struct ctdb_queue *out_queue;
	struct fd_event *connect_fde;
	struct timed_event *connect_te;
};


/* prototypes internal to tcp transport */
int ctdb_tcp_queue_pkt(struct ctdb_node *node, uint8_t *data, uint32_t length);
int ctdb_tcp_listen(struct ctdb_context *ctdb);
void ctdb_tcp_node_connect(struct event_context *ev, struct timed_event *te, 
			   struct timeval t, void *private_data);
void ctdb_tcp_read_cb(uint8_t *data, size_t cnt, void *args);
void ctdb_tcp_tnode_cb(uint8_t *data, size_t cnt, void *private_data);
void ctdb_tcp_stop_connection(struct ctdb_node *node);

#define CTDB_TCP_ALIGNMENT 8

#endif /* _CTDB_TCP_H */
