/* 
   ctdb database library
   Utility functions to read/write blobs of data from a file descriptor
   and handle the case where we might need multiple read/writes to get all the
   data.

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
#include "lib/tdb/include/tdb.h"
#include "lib/events/events.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "../include/ctdb.h"

/* structures for packet queueing - see common/ctdb_io.c */
struct ctdb_partial {
	uint8_t *data;
	uint32_t length;
};

struct ctdb_queue_pkt {
	struct ctdb_queue_pkt *next, *prev;
	uint8_t *data;
	uint32_t length;
};

struct ctdb_queue {
	struct ctdb_context *ctdb;
	struct ctdb_partial partial; /* partial input packet */
	struct ctdb_queue_pkt *out_queue;
	struct fd_event *fde;
	int fd;
	size_t alignment;
	void *private_data;
	ctdb_queue_cb_fn_t callback;
};



/*
  called when an incoming connection is readable
*/
static void queue_io_read(struct ctdb_queue *queue)
{
	int num_ready = 0;
	ssize_t nread;
	uint8_t *data, *data_base;

	if (ioctl(queue->fd, FIONREAD, &num_ready) != 0 ||
	    num_ready == 0) {
		/* the descriptor has been closed */
		goto failed;
	}


	queue->partial.data = talloc_realloc_size(queue, queue->partial.data, 
						  num_ready + queue->partial.length);

	if (queue->partial.data == NULL) {
		goto failed;
	}

	nread = read(queue->fd, queue->partial.data + queue->partial.length, num_ready);
	if (nread <= 0) {
		goto failed;
	}


	data = queue->partial.data;
	nread += queue->partial.length;

	queue->partial.data = NULL;
	queue->partial.length = 0;

	if (nread >= 4 && *(uint32_t *)data == nread) {
		/* it is the responsibility of the incoming packet
		 function to free 'data' */
		queue->callback(data, nread, queue->private_data);
		return;
	}

	data_base = data;

	while (nread >= 4 && *(uint32_t *)data <= nread) {
		/* we have at least one packet */
		uint8_t *d2;
		uint32_t len;
		len = *(uint32_t *)data;
		d2 = talloc_memdup(queue, data, len);
		if (d2 == NULL) {
			/* sigh */
			goto failed;
		}
		queue->callback(d2, len, queue->private_data);
		data += len;
		nread -= len;		
	}

	if (nread > 0) {
		/* we have only part of a packet */
		if (data_base == data) {
			queue->partial.data = data;
			queue->partial.length = nread;
		} else {
			queue->partial.data = talloc_memdup(queue, data, nread);
			if (queue->partial.data == NULL) {
				goto failed;
			}
			queue->partial.length = nread;
			talloc_free(data_base);
		}
		return;
	}

	talloc_free(data_base);
	return;

failed:
	queue->callback(NULL, 0, queue->private_data);
}


/* used when an event triggers a dead queue */
static void queue_dead(struct event_context *ev, struct timed_event *te, 
		       struct timeval t, void *private_data)
{
	struct ctdb_queue *queue = talloc_get_type(private_data, struct ctdb_queue);
	queue->callback(NULL, 0, queue->private_data);
}


/*
  called when an incoming connection is writeable
*/
static void queue_io_write(struct ctdb_queue *queue)
{
	while (queue->out_queue) {
		struct ctdb_queue_pkt *pkt = queue->out_queue;
		ssize_t n;

		n = write(queue->fd, pkt->data, pkt->length);

		if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			event_add_timed(queue->ctdb->ev, queue, timeval_zero(), 
					queue_dead, queue);
			EVENT_FD_NOT_WRITEABLE(queue->fde);
			return;
		}
		if (n <= 0) return;
		
		if (n != pkt->length) {
			pkt->length -= n;
			pkt->data += n;
			return;
		}

		DLIST_REMOVE(queue->out_queue, pkt);
		talloc_free(pkt);
	}

	EVENT_FD_NOT_WRITEABLE(queue->fde);
}

/*
  called when an incoming connection is readable or writeable
*/
static void queue_io_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private_data)
{
	struct ctdb_queue *queue = talloc_get_type(private_data, struct ctdb_queue);

	if (flags & EVENT_FD_READ) {
		queue_io_read(queue);
	} else {
		queue_io_write(queue);
	}
}


/*
  queue a packet for sending
*/
int ctdb_queue_send(struct ctdb_queue *queue, uint8_t *data, uint32_t length)
{
	struct ctdb_queue_pkt *pkt;
	uint32_t length2;

	/* enforce the length and alignment rules from the tcp packet allocator */
	length2 = (length+(queue->alignment-1)) & ~(queue->alignment-1);
	*(uint32_t *)data = length2;

	if (length2 != length) {
		memset(data+length, 0, length2-length);
	}
	
	/* if the queue is empty then try an immediate write, avoiding
	   queue overhead. This relies on non-blocking sockets */
	if (queue->out_queue == NULL && queue->fd != -1) {
		ssize_t n = write(queue->fd, data, length2);
		if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			event_add_timed(queue->ctdb->ev, queue, timeval_zero(), 
					queue_dead, queue);
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

	pkt = talloc(queue, struct ctdb_queue_pkt);
	CTDB_NO_MEMORY(queue->ctdb, pkt);

	pkt->data = talloc_memdup(pkt, data, length2);
	CTDB_NO_MEMORY(queue->ctdb, pkt->data);

	pkt->length = length2;

	if (queue->out_queue == NULL && queue->fd != -1) {
		EVENT_FD_WRITEABLE(queue->fde);
	}

	DLIST_ADD_END(queue->out_queue, pkt, struct ctdb_queue_pkt *);

	return 0;
}


/*
  setup the fd used by the queue
 */
int ctdb_queue_set_fd(struct ctdb_queue *queue, int fd)
{
	queue->fd = fd;
	talloc_free(queue->fde);
	queue->fde = NULL;

	if (fd != -1) {
		queue->fde = event_add_fd(queue->ctdb->ev, queue, fd, EVENT_FD_READ, 
					  queue_io_handler, queue);
		if (queue->fde == NULL) {
			return -1;
		}

		if (queue->out_queue) {
			EVENT_FD_WRITEABLE(queue->fde);		
		}
	}

	return 0;
}



/*
  setup a packet queue on a socket
 */
struct ctdb_queue *ctdb_queue_setup(struct ctdb_context *ctdb,
				    TALLOC_CTX *mem_ctx, int fd, int alignment,
				    
				    ctdb_queue_cb_fn_t callback,
				    void *private_data)
{
	struct ctdb_queue *queue;

	queue = talloc_zero(mem_ctx, struct ctdb_queue);
	CTDB_NO_MEMORY_NULL(ctdb, queue);

	queue->ctdb = ctdb;
	queue->fd = fd;
	queue->alignment = alignment;
	queue->private_data = private_data;
	queue->callback = callback;
	if (fd != -1) {
		if (ctdb_queue_set_fd(queue, fd) != 0) {
			talloc_free(queue);
			return NULL;
		}
	}

	return queue;
}
