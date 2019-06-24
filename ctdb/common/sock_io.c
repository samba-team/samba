/*
   Generic Unix-domain Socket I/O

   Copyright (C) Amitay Isaacs  2016

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
#include "system/filesys.h"
#include "system/network.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/sys_rw.h"
#include "lib/util/debug.h"
#include "lib/util/blocking.h"

#include "common/logging.h"
#include "common/sock_io.h"

bool sock_clean(const char *sockpath)
{
	int ret;

	ret = unlink(sockpath);
	if (ret == 0) {
		D_WARNING("Removed stale socket %s\n", sockpath);
	} else if (errno != ENOENT) {
		D_ERR("Failed to remove stale socket %s\n", sockpath);
		return false;
	}

	return true;
}

int sock_connect(const char *sockpath)
{
	struct sockaddr_un addr;
	size_t len;
	int fd, ret;

	if (sockpath == NULL) {
		D_ERR("Invalid socket path\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	len = strlcpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	if (len >= sizeof(addr.sun_path)) {
		D_ERR("Socket path too long, len=%zu\n", strlen(sockpath));
		return -1;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		D_ERR("socket() failed, errno=%d\n", errno);
		return -1;
	}

	ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		D_ERR("connect() failed, errno=%d\n", errno);
		close(fd);
		return -1;
	}

	return fd;
}

struct sock_queue {
	struct tevent_context *ev;
	sock_queue_callback_fn_t callback;
	void *private_data;
	int fd;

	struct tevent_immediate *im;
	struct tevent_queue *queue;
	struct tevent_fd *fde;
	uint8_t *buf;
	size_t buflen, begin, end;
};

/*
 * The reserved talloc headers, SOCK_QUEUE_OBJ_COUNT,
 * and the pre-allocated pool-memory SOCK_QUEUE_POOL_SIZE,
 * are used for the sub-objects queue->im, queue->queue, queue->fde
 * and queue->buf.
 * If the memory allocating sub-objects of struct sock_queue change,
 * those values need to be adjusted.
 */
#define SOCK_QUEUE_OBJ_COUNT 4
#define SOCK_QUEUE_POOL_SIZE 2048

static bool sock_queue_set_fd(struct sock_queue *queue, int fd);
static void sock_queue_handler(struct tevent_context *ev,
			       struct tevent_fd *fde, uint16_t flags,
			       void *private_data);
static void sock_queue_process(struct sock_queue *queue);
static void sock_queue_process_event(struct tevent_context *ev,
				     struct tevent_immediate *im,
				     void *private_data);

struct sock_queue *sock_queue_setup(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    int fd,
				    sock_queue_callback_fn_t callback,
				    void *private_data)
{
	struct sock_queue *queue;

	queue = talloc_pooled_object(mem_ctx, struct sock_queue,
				     SOCK_QUEUE_OBJ_COUNT, SOCK_QUEUE_POOL_SIZE);
	if (queue == NULL) {
		return NULL;
	}
	memset(queue, 0, sizeof(struct sock_queue));

	queue->ev = ev;
	queue->callback = callback;
	queue->private_data = private_data;

	queue->im = tevent_create_immediate(queue);
	if (queue->im == NULL) {
		talloc_free(queue);
		return NULL;
	}

	queue->queue = tevent_queue_create(queue, "out-queue");
	if (queue->queue == NULL) {
		talloc_free(queue);
		return NULL;
	}

	if (! sock_queue_set_fd(queue, fd)) {
		talloc_free(queue);
		return NULL;
	}

	return queue;
}

static bool sock_queue_set_fd(struct sock_queue *queue, int fd)
{
	TALLOC_FREE(queue->fde);
	queue->fd = fd;

	if (fd != -1) {
		int ret;

		ret = set_blocking(fd, false);
		if (ret != 0) {
			return false;
		}

		queue->fde = tevent_add_fd(queue->ev, queue, fd,
					   TEVENT_FD_READ,
					   sock_queue_handler, queue);
		if (queue->fde == NULL) {
			return false;
		}
		tevent_fd_set_auto_close(queue->fde);
	}

	return true;
}

static void sock_queue_handler(struct tevent_context *ev,
			       struct tevent_fd *fde, uint16_t flags,
			       void *private_data)
{
	struct sock_queue *queue = talloc_get_type_abort(
		private_data, struct sock_queue);
	int ret, num_ready;
	ssize_t nread;

	ret = ioctl(queue->fd, FIONREAD, &num_ready);
	if (ret != 0) {
		/* Ignore */
		return;
	}

	if (num_ready == 0) {
		/* descriptor has been closed */
		goto fail;
	}

	if ((size_t)num_ready > queue->buflen - queue->end) {
		queue->buf = talloc_realloc_size(queue, queue->buf,
						 queue->end + num_ready);
		if (queue->buf == NULL) {
			goto fail;
		}
		queue->buflen = queue->end + num_ready;
	}

	nread = sys_read(queue->fd, queue->buf + queue->end, num_ready);
	if (nread < 0) {
		goto fail;
	}
	queue->end += nread;

	sock_queue_process(queue);
	return;

fail:
	queue->callback(NULL, 0, queue->private_data);
}

static void sock_queue_process(struct sock_queue *queue)
{
	uint32_t pkt_size;

	if ((queue->end - queue->begin) < sizeof(uint32_t)) {
		/* not enough data */
		return;
	}

	pkt_size = *(uint32_t *)(queue->buf + queue->begin);
	if (pkt_size == 0) {
		D_ERR("Invalid packet of length 0\n");
		queue->callback(NULL, 0, queue->private_data);
		return;
	}

	if ((queue->end - queue->begin) < pkt_size) {
		/* not enough data */
		return;
	}

	queue->callback(queue->buf + queue->begin, pkt_size,
			queue->private_data);
	queue->begin += pkt_size;

	if (queue->begin < queue->end) {
		/* more data to be processed */
		tevent_schedule_immediate(queue->im, queue->ev,
					  sock_queue_process_event, queue);
	} else {
		TALLOC_FREE(queue->buf);
		queue->buflen = 0;
		queue->begin = 0;
		queue->end = 0;
	}
}

static void sock_queue_process_event(struct tevent_context *ev,
				     struct tevent_immediate *im,
				     void *private_data)
{
	struct sock_queue *queue = talloc_get_type_abort(
		private_data, struct sock_queue);

	sock_queue_process(queue);
}

struct sock_queue_write_state {
	uint8_t *pkt;
	uint32_t pkt_size;
};

static void sock_queue_trigger(struct tevent_req *req, void *private_data);

int sock_queue_write(struct sock_queue *queue, uint8_t *buf, size_t buflen)
{
	struct tevent_req *req;
	struct sock_queue_write_state *state;
	struct tevent_queue_entry *qentry;

	if (buflen >= INT32_MAX) {
		return -1;
	}

	req = tevent_req_create(queue, &state, struct sock_queue_write_state);
	if (req == NULL) {
		return -1;
	}

	state->pkt = buf;
	state->pkt_size = (uint32_t)buflen;

	qentry = tevent_queue_add_entry(queue->queue, queue->ev, req,
					sock_queue_trigger, queue);
	if (qentry == NULL) {
		talloc_free(req);
		return -1;
	}

	return 0;
}

static void sock_queue_trigger(struct tevent_req *req, void *private_data)
{
	struct sock_queue *queue = talloc_get_type_abort(
		private_data, struct sock_queue);
	struct sock_queue_write_state *state = tevent_req_data(
		req, struct sock_queue_write_state);
	size_t offset = 0;

	do {
		ssize_t nwritten;

		nwritten = sys_write(queue->fd, state->pkt + offset,
				     state->pkt_size - offset);
		if (nwritten < 0) {
			queue->callback(NULL, 0, queue->private_data);
			return;
		}
		offset += nwritten;

	} while (offset < state->pkt_size);

	tevent_req_done(req);
	talloc_free(req);
}
