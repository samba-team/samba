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
  called when we fail to send a message to a node
*/
static void ctdb_tcp_node_dead(struct event_context *ev, struct timed_event *te, 
			       struct timeval t, void *private)
{
	struct ctdb_node *node = talloc_get_type(private, struct ctdb_node);
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private, 
						      struct ctdb_tcp_node);

	/* flush the queue */
	while (tnode->queue) {
		struct ctdb_tcp_packet *pkt = tnode->queue;
		DLIST_REMOVE(tnode->queue, pkt);
		talloc_free(pkt);
	}

	/* start a new connect cycle to try to re-establish the
	   link */
	talloc_free(tnode->fde);
	close(tnode->fd);
	tnode->fd = -1;
	event_add_timed(node->ctdb->ev, node, timeval_zero(), 
			ctdb_tcp_node_connect, node);
}

/*
  called when socket becomes readable
*/
void ctdb_tcp_node_write(struct event_context *ev, struct fd_event *fde, 
			 uint16_t flags, void *private)
{
	struct ctdb_node *node = talloc_get_type(private, struct ctdb_node);
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private, 
						      struct ctdb_tcp_node);
	if (flags & EVENT_FD_READ) {
		/* getting a read event on this fd in the current tcp model is
		   always an error, as we have separate read and write
		   sockets. In future we may combine them, but for now it must
		   mean that the socket is dead, so we try to reconnect */
		talloc_free(tnode->fde);
		close(tnode->fd);
		tnode->fd = -1;
		event_add_timed(node->ctdb->ev, node, timeval_zero(), 
				ctdb_tcp_node_connect, node);
		return;
	}

	while (tnode->queue) {
		struct ctdb_tcp_packet *pkt = tnode->queue;
		ssize_t n;

		n = write(tnode->fd, pkt->data, pkt->length);

		if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			event_add_timed(node->ctdb->ev, node, timeval_zero(), 
					ctdb_tcp_node_dead, node);
			EVENT_FD_NOT_WRITEABLE(tnode->fde);
			return;
		}
		if (n <= 0) return;
		
		if (n != pkt->length) {
			pkt->length -= n;
			pkt->data += n;
			return;
		}

		DLIST_REMOVE(tnode->queue, pkt);
		talloc_free(pkt);
	}

	EVENT_FD_NOT_WRITEABLE(tnode->fde);
}


/*
  called when an incoming connection is readable
*/
void ctdb_tcp_incoming_read(struct event_context *ev, struct fd_event *fde, 
			    uint16_t flags, void *private)
{
	struct ctdb_incoming *in = talloc_get_type(private, struct ctdb_incoming);
	int num_ready = 0;
	uint8_t *data;

	/* NOTE: we don't yet handle combined packets or partial
	   packets. Obviously that needed fixing, using a similar
	   scheme to the Samba4 packet layer */

	if (ioctl(in->fd, FIONREAD, &num_ready) != 0 ||
	    num_ready == 0) {
		/* we've lost the link from another node. We don't
		   notify the upper layers, as we only want to trigger
		   a full node reorganisation when a send fails - that
		   allows nodes to restart without penalty as long as
		   the network is idle */
		talloc_free(in);
		return;
	}

	data = talloc_size(in, num_ready);
	if (data == NULL) {
		/* not much we can do except drop the socket */
		talloc_free(in);
		return;
	}

	if (read(in->fd, data, num_ready) != num_ready) {
		talloc_free(in);
		return;
	}

	/* tell the ctdb layer above that we have a packet */
	in->ctdb->upcalls->recv_pkt(in->ctdb, data, num_ready);
}

/*
  queue a packet for sending
*/
int ctdb_tcp_queue_pkt(struct ctdb_node *node, uint8_t *data, uint32_t length)
{
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private, 
						      struct ctdb_tcp_node);
	struct ctdb_tcp_packet *pkt;
	
	if (tnode->fd == -1) {
		ctdb_set_error(node->ctdb, "Sending to dead node %s\n", node->name);
		return -1;
	}

	/* if the queue is empty then try an immediate write, avoiding
	   queue overhead. This relies on non-blocking sockets */
	if (tnode->queue == NULL) {
		ssize_t n = write(tnode->fd, data, length);
		if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			event_add_timed(node->ctdb->ev, node, timeval_zero(), 
					ctdb_tcp_node_dead, node);
			/* yes, we report success, as the dead node is 
			   handled via a separate event */
			return 0;
		}
		if (n > 0) {
			data += n;
			length -= n;
		}
		if (length == 0) return 0;
	}

	pkt = talloc(tnode, struct ctdb_tcp_packet);
	CTDB_NO_MEMORY(node->ctdb, pkt);

	pkt->data = talloc_memdup(pkt, data, length);
	CTDB_NO_MEMORY(node->ctdb, pkt->data);

	pkt->length = length;

	if (tnode->queue == NULL) {
		EVENT_FD_WRITEABLE(tnode->fde);
	}

	DLIST_ADD_END(tnode->queue, pkt, struct ctdb_tcp_packet *);

	return 0;
}
