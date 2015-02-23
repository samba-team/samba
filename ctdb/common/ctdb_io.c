/* 
   ctdb database library
   Utility functions to read/write blobs of data from a file descriptor
   and handle the case where we might need multiple read/writes to get all the
   data.

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

#include "includes.h"
#include "tdb.h"
#include "lib/util/dlinklist.h"
#include "system/network.h"
#include "system/filesys.h"
#include "../include/ctdb_private.h"
#include "../include/ctdb_client.h"
#include <stdarg.h>

#define QUEUE_BUFFER_SIZE	(16*1024)

/* structures for packet queueing - see common/ctdb_io.c */
struct ctdb_buffer {
	uint8_t *data;
	uint32_t length;
	uint32_t size;
	uint32_t extend;
};

struct ctdb_queue_pkt {
	struct ctdb_queue_pkt *next, *prev;
	uint8_t *data;
	uint32_t length;
	uint32_t full_length;
	uint8_t buf[];
};

struct ctdb_queue {
	struct ctdb_context *ctdb;
	struct tevent_immediate *im;
	struct ctdb_buffer buffer; /* input buffer */
	struct ctdb_queue_pkt *out_queue, *out_queue_tail;
	uint32_t out_queue_length;
	struct fd_event *fde;
	int fd;
	size_t alignment;
	void *private_data;
	ctdb_queue_cb_fn_t callback;
	bool *destroyed;
	const char *name;
};



int ctdb_queue_length(struct ctdb_queue *queue)
{
	return queue->out_queue_length;
}

static void queue_process(struct ctdb_queue *queue);

static void queue_process_event(struct tevent_context *ev, struct tevent_immediate *im,
				void *private_data)
{
	struct ctdb_queue *queue = talloc_get_type(private_data, struct ctdb_queue);

	queue_process(queue);
}

/*
 * This function is used to process data in queue buffer.
 *
 * Queue callback function can end up freeing the queue, there should not be a
 * loop processing packets from queue buffer.  Instead set up a timed event for
 * immediate run to process remaining packets from buffer.
 */
static void queue_process(struct ctdb_queue *queue)
{
	uint32_t pkt_size;
	uint8_t *data;

	if (queue->buffer.length < sizeof(pkt_size)) {
		return;
	}

	pkt_size = *(uint32_t *)queue->buffer.data;
	if (pkt_size == 0) {
		DEBUG(DEBUG_CRIT, ("Invalid packet of length 0\n"));
		goto failed;
	}

	if (queue->buffer.length < pkt_size) {
		if (pkt_size > QUEUE_BUFFER_SIZE) {
			queue->buffer.extend = pkt_size;
		}
		return;
	}

	/* Extract complete packet */
	data = talloc_size(queue, pkt_size);
	if (data == NULL) {
		DEBUG(DEBUG_ERR, ("read error alloc failed for %u\n", pkt_size));
		return;
	}
	memcpy(data, queue->buffer.data, pkt_size);

	/* Shift packet out from buffer */
	if (queue->buffer.length > pkt_size) {
		memmove(queue->buffer.data,
			queue->buffer.data + pkt_size,
			queue->buffer.length - pkt_size);
	}
	queue->buffer.length -= pkt_size;

	if (queue->buffer.length > 0) {
		/* There is more data to be processed, schedule an event */
		tevent_schedule_immediate(queue->im, queue->ctdb->ev,
					  queue_process_event, queue);
	} else {
		if (queue->buffer.size > QUEUE_BUFFER_SIZE) {
			TALLOC_FREE(queue->buffer.data);
			queue->buffer.size = 0;
		}
	}

	/* It is the responsibility of the callback to free 'data' */
	queue->callback(data, pkt_size, queue->private_data);
	return;

failed:
	queue->callback(NULL, 0, queue->private_data);

}


/*
  called when an incoming connection is readable
  This function MUST be safe for reentry via the queue callback!
*/
static void queue_io_read(struct ctdb_queue *queue)
{
	int num_ready = 0;
	ssize_t nread;
	uint8_t *data;
	int navail;

	/* check how much data is available on the socket for immediately
	   guaranteed nonblocking access.
	   as long as we are careful never to try to read more than this
	   we know all reads will be successful and will neither block
	   nor fail with a "data not available right now" error
	*/
	if (ioctl(queue->fd, FIONREAD, &num_ready) != 0) {
		return;
	}
	if (num_ready == 0) {
		/* the descriptor has been closed */
		goto failed;
	}

	if (queue->buffer.data == NULL) {
		/* starting fresh, allocate buf to read data */
		queue->buffer.data = talloc_size(queue, QUEUE_BUFFER_SIZE);
		if (queue->buffer.data == NULL) {
			DEBUG(DEBUG_ERR, ("read error alloc failed for %u\n", num_ready));
			goto failed;
		}
		queue->buffer.size = QUEUE_BUFFER_SIZE;
	} else if (queue->buffer.extend > 0) {
		/* extending buffer */
		data = talloc_realloc_size(queue, queue->buffer.data, queue->buffer.extend);
		if (data == NULL) {
			DEBUG(DEBUG_ERR, ("read error realloc failed for %u\n", queue->buffer.extend));
			goto failed;
		}
		queue->buffer.data = data;
		queue->buffer.size = queue->buffer.extend;
		queue->buffer.extend = 0;
	}

	navail = queue->buffer.size - queue->buffer.length;
	if (num_ready > navail) {
		num_ready = navail;
	}

	if (num_ready > 0) {
		nread = sys_read(queue->fd,
				 queue->buffer.data + queue->buffer.length,
				 num_ready);
		if (nread <= 0) {
			DEBUG(DEBUG_ERR, ("read error nread=%d\n", (int)nread));
			goto failed;
		}
		queue->buffer.length += nread;
	}

	queue_process(queue);
	return;

failed:
	queue->callback(NULL, 0, queue->private_data);
}


/* used when an event triggers a dead queue */
static void queue_dead(struct event_context *ev, struct tevent_immediate *im,
		       void *private_data)
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
		if (queue->ctdb->flags & CTDB_FLAG_TORTURE) {
			n = write(queue->fd, pkt->data, 1);
		} else {
			n = write(queue->fd, pkt->data, pkt->length);
		}

		if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			if (pkt->length != pkt->full_length) {
				/* partial packet sent - we have to drop it */
				DLIST_REMOVE(queue->out_queue, pkt);
				queue->out_queue_length--;
				talloc_free(pkt);
			}
			talloc_free(queue->fde);
			queue->fde = NULL;
			queue->fd = -1;
			tevent_schedule_immediate(queue->im, queue->ctdb->ev,
						  queue_dead, queue);
			return;
		}
		if (n <= 0) return;
		
		if (n != pkt->length) {
			pkt->length -= n;
			pkt->data += n;
			return;
		}

		DLIST_REMOVE(queue->out_queue, pkt);
		queue->out_queue_length--;
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
	struct ctdb_req_header *hdr = (struct ctdb_req_header *)data;
	struct ctdb_queue_pkt *pkt;
	uint32_t length2, full_length;

	if (queue->alignment) {
		/* enforce the length and alignment rules from the tcp packet allocator */
		length2 = (length+(queue->alignment-1)) & ~(queue->alignment-1);
		*(uint32_t *)data = length2;
	} else {
		length2 = length;
	}

	if (length2 != length) {
		memset(data+length, 0, length2-length);
	}

	full_length = length2;
	
	/* if the queue is empty then try an immediate write, avoiding
	   queue overhead. This relies on non-blocking sockets */
	if (queue->out_queue == NULL && queue->fd != -1 &&
	    !(queue->ctdb->flags & CTDB_FLAG_TORTURE)) {
		ssize_t n = write(queue->fd, data, length2);
		if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK) {
			talloc_free(queue->fde);
			queue->fde = NULL;
			queue->fd = -1;
			tevent_schedule_immediate(queue->im, queue->ctdb->ev,
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

	pkt = talloc_size(
		queue, offsetof(struct ctdb_queue_pkt, buf) + length2);
	CTDB_NO_MEMORY(queue->ctdb, pkt);
	talloc_set_name_const(pkt, "struct ctdb_queue_pkt");

	pkt->data = pkt->buf;
	memcpy(pkt->data, data, length2);

	pkt->length = length2;
	pkt->full_length = full_length;

	if (queue->out_queue == NULL && queue->fd != -1) {
		EVENT_FD_WRITEABLE(queue->fde);
	}

	DLIST_ADD_END(queue->out_queue, pkt, NULL);

	queue->out_queue_length++;

	if (queue->ctdb->tunable.verbose_memory_names != 0) {
		switch (hdr->operation) {
		case CTDB_REQ_CONTROL: {
			struct ctdb_req_control *c = (struct ctdb_req_control *)hdr;
			talloc_set_name(pkt, "ctdb_queue_pkt: %s control opcode=%u srvid=%llu datalen=%u",
					queue->name, (unsigned)c->opcode, (unsigned long long)c->srvid, (unsigned)c->datalen);
			break;
		}
		case CTDB_REQ_MESSAGE: {
			struct ctdb_req_message *m = (struct ctdb_req_message *)hdr;
			talloc_set_name(pkt, "ctdb_queue_pkt: %s message srvid=%llu datalen=%u",
					queue->name, (unsigned long long)m->srvid, (unsigned)m->datalen);
			break;
		}
		default:
			talloc_set_name(pkt, "ctdb_queue_pkt: %s operation=%u length=%u src=%u dest=%u",
					queue->name, (unsigned)hdr->operation, (unsigned)hdr->length,
					(unsigned)hdr->srcnode, (unsigned)hdr->destnode);
			break;
		}
	}

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
		tevent_fd_set_auto_close(queue->fde);

		if (queue->out_queue) {
			EVENT_FD_WRITEABLE(queue->fde);		
		}
	}

	return 0;
}

/* If someone sets up this pointer, they want to know if the queue is freed */
static int queue_destructor(struct ctdb_queue *queue)
{
	TALLOC_FREE(queue->buffer.data);
	queue->buffer.length = 0;
	queue->buffer.size = 0;
	if (queue->destroyed != NULL)
		*queue->destroyed = true;
	return 0;
}

/*
  setup a packet queue on a socket
 */
struct ctdb_queue *ctdb_queue_setup(struct ctdb_context *ctdb,
				    TALLOC_CTX *mem_ctx, int fd, int alignment,
				    ctdb_queue_cb_fn_t callback,
				    void *private_data, const char *fmt, ...)
{
	struct ctdb_queue *queue;
	va_list ap;

	queue = talloc_zero(mem_ctx, struct ctdb_queue);
	CTDB_NO_MEMORY_NULL(ctdb, queue);
	va_start(ap, fmt);
	queue->name = talloc_vasprintf(mem_ctx, fmt, ap);
	va_end(ap);
	CTDB_NO_MEMORY_NULL(ctdb, queue->name);

	queue->im= tevent_create_immediate(queue);
	CTDB_NO_MEMORY_NULL(ctdb, queue->im);

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
	talloc_set_destructor(queue, queue_destructor);

	return queue;
}
