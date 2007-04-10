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
#include "lib/util/dlinklist.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
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
		node->ctdb->upcalls->node_dead(node);
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



static void tcp_read_cb(uint8_t *data, int cnt, void *args)
{
	struct ctdb_incoming *in = talloc_get_type(args, struct ctdb_incoming);
	struct ctdb_req_header *hdr;

	if (cnt < sizeof(*hdr)) {
		ctdb_set_error(in->ctdb, "Bad packet length %d\n", cnt);
		return;
	}
	hdr = (struct ctdb_req_header *)data;
	if (cnt != hdr->length) {
		ctdb_set_error(in->ctdb, "Bad header length %d expected %d\n", 
			       hdr->length, cnt);
		return;
	}

	if (hdr->ctdb_magic != CTDB_MAGIC) {
		ctdb_set_error(in->ctdb, "Non CTDB packet rejected\n");
		return;
	}

	if (hdr->ctdb_version != CTDB_VERSION) {
		ctdb_set_error(in->ctdb, "Bad CTDB version 0x%x rejected\n", hdr->ctdb_version);
		return;
	}

	/* most common case - we got a whole packet in one go
	   tell the ctdb layer above that we have a packet */
	in->ctdb->upcalls->recv_pkt(in->ctdb, data, cnt);
}

/*
  called when an incoming connection is readable
*/
void ctdb_tcp_incoming_read(struct event_context *ev, struct fd_event *fde, 
			    uint16_t flags, void *private)
{
	struct ctdb_incoming *in = talloc_get_type(private, struct ctdb_incoming);

	ctdb_read_pdu(in->fd, in, &in->partial, tcp_read_cb, in);
}

/*
  queue a packet for sending
*/
int ctdb_tcp_queue_pkt(struct ctdb_node *node, uint8_t *data, uint32_t length)
{
	struct ctdb_tcp_node *tnode = talloc_get_type(node->private, 
						      struct ctdb_tcp_node);
	struct ctdb_tcp_packet *pkt;
	uint32_t length2;

	/* enforce the length and alignment rules from the tcp packet allocator */
	length2 = (length+(CTDB_TCP_ALIGNMENT-1)) & ~(CTDB_TCP_ALIGNMENT-1);
	*(uint32_t *)data = length2;

	if (length2 != length) {
		memset(data+length, 0, length2-length);
	}
	
	/* if the queue is empty then try an immediate write, avoiding
	   queue overhead. This relies on non-blocking sockets */
	if (tnode->queue == NULL && tnode->fd != -1) {
		ssize_t n = write(tnode->fd, data, length2);
		if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			event_add_timed(node->ctdb->ev, node, timeval_zero(), 
					ctdb_tcp_node_dead, node);
			/* yes, we report success, as the dead node is 
			   handled via a separate event */
			return 0;
		}
		if (n > 0) {
			data += n;
			length2 -= n;
		}
		if (length2 == 0) return 0;
	}

	pkt = talloc(tnode, struct ctdb_tcp_packet);
	CTDB_NO_MEMORY(node->ctdb, pkt);

	pkt->data = talloc_memdup(pkt, data, length2);
	CTDB_NO_MEMORY(node->ctdb, pkt->data);

	pkt->length = length2;

	if (tnode->queue == NULL && tnode->fd != -1) {
		EVENT_FD_WRITEABLE(tnode->fde);
	}

	DLIST_ADD_END(tnode->queue, pkt, struct ctdb_tcp_packet *);

	return 0;
}
