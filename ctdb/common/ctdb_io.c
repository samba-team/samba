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

#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"

#include <tdb.h>
#include <talloc.h>
#include <tevent.h>

#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/sys_rw.h"

#include "ctdb_private.h"
#include "ctdb_client.h"

#include "common/logging.h"
#include "common/common.h"

/* structures for packet queueing - see common/ctdb_io.c */
struct ctdb_buffer {
	uint8_t *data;
	uint32_t length;
	uint32_t size;
	uint32_t offset;
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
	struct tevent_fd *fde;
	int fd;
	size_t alignment;
	void *private_data;
	ctdb_queue_cb_fn_t callback;
	TALLOC_CTX *data_pool;
	const char *name;
	uint32_t buffer_size;
};



uint32_t ctdb_queue_length(struct ctdb_queue *queue)
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
	uint8_t *data = NULL;

	if (queue->buffer.length < sizeof(pkt_size)) {
		return;
	}

	/* Did we at least read the size into the buffer */
	pkt_size = *(uint32_t *)(queue->buffer.data + queue->buffer.offset);
	if (pkt_size == 0) {
		DEBUG(DEBUG_CRIT, ("Invalid packet of length 0\n"));
		goto failed;
	}

	/* the buffer doesn't contain the full packet, return to get the rest */
	if (queue->buffer.length < pkt_size) {
		return;
	}

	/* Extract complete packet */
	data = talloc_memdup(queue->data_pool,
			     queue->buffer.data + queue->buffer.offset,
			     pkt_size);

	if (data == NULL) {
		D_ERR("read error alloc failed for %u\n", pkt_size);
		return;
	}

	queue->buffer.offset += pkt_size;
	queue->buffer.length -= pkt_size;

	if (queue->buffer.offset < pkt_size ||
	    queue->buffer.offset > queue->buffer.size) {
		D_ERR("buffer offset overflow\n");
		TALLOC_FREE(queue->buffer.data);
		memset(&queue->buffer, 0, sizeof(queue->buffer));
		goto failed;
	}

	if (queue->buffer.length > 0) {
		/* There is more data to be processed, schedule an event */
		tevent_schedule_immediate(queue->im, queue->ctdb->ev,
					  queue_process_event, queue);
	} else {
		if (queue->buffer.size > queue->buffer_size) {
			TALLOC_FREE(queue->buffer.data);
			queue->buffer.size = 0;
		}
		queue->buffer.offset = 0;
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
	uint32_t pkt_size = 0;
	uint32_t start_offset;
	ssize_t nread;
	uint8_t *data;

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
		queue->buffer.data = talloc_size(queue, queue->buffer_size);
		if (queue->buffer.data == NULL) {
			DEBUG(DEBUG_ERR, ("read error alloc failed for %u\n", num_ready));
			goto failed;
		}
		queue->buffer.size = queue->buffer_size;
		goto data_read;
	}

	if (sizeof(pkt_size) > queue->buffer.length) {
		/* data read is not sufficient to gather message size */
		goto buffer_shift;
	}

	pkt_size = *(uint32_t *)(queue->buffer.data + queue->buffer.offset);
	if (pkt_size > queue->buffer.size) {
		data = talloc_realloc_size(queue,
					   queue->buffer.data,
					   pkt_size);
		if (data == NULL) {
			DBG_ERR("read error realloc failed for %u\n", pkt_size);
			goto failed;
		}
		queue->buffer.data = data;
		queue->buffer.size = pkt_size;
		/* fall through here as we might need to move the data as well */
	}

buffer_shift:
	if (sizeof(pkt_size) > queue->buffer.size - queue->buffer.offset ||
	    pkt_size > queue->buffer.size - queue->buffer.offset) {
		/* Either the offset has progressed too far to host at least
		 * the size information or the remaining space in the buffer
		 * is not sufficient for the full message.
		 * Therefore, move the data and try again.
		 */
		memmove(queue->buffer.data,
			queue->buffer.data + queue->buffer.offset,
			queue->buffer.length);
		queue->buffer.offset = 0;
	}

data_read:
	start_offset = queue->buffer.length + queue->buffer.offset;
	if (start_offset < queue->buffer.length) {
		DBG_ERR("Buffer overflow\n");
		goto failed;
	}
	if (start_offset > queue->buffer.size) {
		DBG_ERR("Buffer overflow\n");
		goto failed;
	}

	num_ready = MIN(num_ready, queue->buffer.size - start_offset);

	if (num_ready > 0) {
		nread = sys_read(queue->fd,
				 queue->buffer.data +
					queue->buffer.offset +
					queue->buffer.length,
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
static void queue_dead(struct tevent_context *ev, struct tevent_immediate *im,
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
			TALLOC_FREE(queue->fde);
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

	TEVENT_FD_NOT_WRITEABLE(queue->fde);
}

/*
  called when an incoming connection is readable or writeable
*/
static void queue_io_handler(struct tevent_context *ev, struct tevent_fd *fde,
			     uint16_t flags, void *private_data)
{
	struct ctdb_queue *queue = talloc_get_type(private_data, struct ctdb_queue);

	if (flags & TEVENT_FD_READ) {
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

	/* If the queue does not have valid fd, no point queueing a packet */
	if (queue->fd == -1) {
		return 0;
	}

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
			TALLOC_FREE(queue->fde);
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
		TEVENT_FD_WRITEABLE(queue->fde);
	}

	DLIST_ADD_END(queue->out_queue, pkt);

	queue->out_queue_length++;

	if (queue->ctdb->tunable.verbose_memory_names != 0) {
		switch (hdr->operation) {
		case CTDB_REQ_CONTROL: {
			struct ctdb_req_control_old *c = (struct ctdb_req_control_old *)hdr;
			talloc_set_name(pkt, "ctdb_queue_pkt: %s control opcode=%u srvid=%llu datalen=%u",
					queue->name, (unsigned)c->opcode, (unsigned long long)c->srvid, (unsigned)c->datalen);
			break;
		}
		case CTDB_REQ_MESSAGE: {
			struct ctdb_req_message_old *m = (struct ctdb_req_message_old *)hdr;
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
	TALLOC_FREE(queue->fde);

	if (fd != -1) {
		queue->fde = tevent_add_fd(queue->ctdb->ev, queue, fd,
					   TEVENT_FD_READ,
					   queue_io_handler, queue);
		if (queue->fde == NULL) {
			return -1;
		}
		tevent_fd_set_auto_close(queue->fde);

		if (queue->out_queue) {
			TEVENT_FD_WRITEABLE(queue->fde);
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

	queue->buffer_size = ctdb->tunable.queue_buffer_size;
	/* In client code, ctdb->tunable is not initialized.
	 * This does not affect recovery daemon.
	 */
	if (queue->buffer_size == 0) {
		queue->buffer_size = 1024;
	}

	queue->data_pool = talloc_pool(queue, queue->buffer_size);
	if (queue->data_pool == NULL) {
		TALLOC_FREE(queue);
		return NULL;
	}

	return queue;
}
