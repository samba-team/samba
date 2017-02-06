/*
   Communication endpoint implementation

   Copyright (C) Amitay Isaacs 2015

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

#include <talloc.h>
#include <tdb.h>

#include "lib/util/blocking.h"
#include "lib/util/tevent_unix.h"

#include "pkt_read.h"
#include "pkt_write.h"
#include "comm.h"

/*
 * Communication endpoint around a socket
 */

#define SMALL_PKT_SIZE	1024

struct comm_context {
	int fd;
	comm_read_handler_fn read_handler;
	void *read_private_data;
	comm_dead_handler_fn dead_handler;
	void *dead_private_data;
	uint8_t small_pkt[SMALL_PKT_SIZE];
	struct tevent_req *read_req, *write_req;
	struct tevent_fd *fde;
	struct tevent_queue *queue;
};

static void comm_fd_handler(struct tevent_context *ev,
			    struct tevent_fd *fde,
			    uint16_t flags, void *private_data);
static struct tevent_req *comm_read_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct comm_context *comm,
					 uint8_t *buf, size_t buflen);
static void comm_read_failed(struct tevent_req *req);


int comm_setup(TALLOC_CTX *mem_ctx, struct tevent_context *ev, int fd,
	       comm_read_handler_fn read_handler, void *read_private_data,
	       comm_dead_handler_fn dead_handler, void *dead_private_data,
	       struct comm_context **result)
{
	struct comm_context *comm;
	int ret;

	if (fd < 0) {
		return EINVAL;
	}

	if (dead_handler == NULL) {
		return EINVAL;
	}

	/* Socket queue relies on non-blocking sockets. */
	ret = set_blocking(fd, false);
	if (ret == -1) {
		return EIO;
	}

	comm = talloc_zero(mem_ctx, struct comm_context);
	if (comm == NULL) {
		return ENOMEM;
	}

	comm->fd = fd;
	comm->read_handler = read_handler;
	comm->read_private_data = read_private_data;
	comm->dead_handler = dead_handler;
	comm->dead_private_data = dead_private_data;

	comm->queue = tevent_queue_create(comm, "comm write queue");
	if (comm->queue == NULL) {
		goto fail;
	}

	/* Set up to write packets */
	comm->fde = tevent_add_fd(ev, comm, fd, TEVENT_FD_READ,
				  comm_fd_handler, comm);
	if (comm->fde == NULL) {
		goto fail;
	}

	/* Set up to read packets */
	if (read_handler != NULL) {
		struct tevent_req *req;

		req = comm_read_send(comm, ev, comm, comm->small_pkt,
				     SMALL_PKT_SIZE);
		if (req == NULL) {
			goto fail;
		}

		tevent_req_set_callback(req, comm_read_failed, comm);
		comm->read_req = req;
	}

	*result = comm;
	return 0;

fail:
	talloc_free(comm);
	return ENOMEM;
}


/*
 * Read packets
 */

struct comm_read_state {
	struct tevent_context *ev;
	struct comm_context *comm;
	uint8_t *buf;
	size_t buflen;
	struct tevent_req *subreq;
};

static ssize_t comm_read_more(uint8_t *buf, size_t buflen, void *private_data);
static void comm_read_done(struct tevent_req *subreq);

static struct tevent_req *comm_read_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct comm_context *comm,
					 uint8_t *buf, size_t buflen)
{
	struct tevent_req *req, *subreq;
	struct comm_read_state *state;

	req = tevent_req_create(mem_ctx, &state, struct comm_read_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->comm = comm;
	state->buf = buf;
	state->buflen = buflen;

	subreq = pkt_read_send(state, state->ev, comm->fd, sizeof(uint32_t),
			       state->buf, state->buflen,
			       comm_read_more, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	state->subreq = subreq;

	tevent_req_set_callback(subreq, comm_read_done, req);
	return req;
}

static ssize_t comm_read_more(uint8_t *buf, size_t buflen, void *private_data)
{
	uint32_t packet_len;

	if (buflen < sizeof(uint32_t)) {
		return sizeof(uint32_t) - buflen;
	}

	packet_len = *(uint32_t *)buf;

	return packet_len - buflen;
}

static void comm_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct comm_read_state *state = tevent_req_data(
		req, struct comm_read_state);
	struct comm_context *comm = state->comm;
	ssize_t nread;
	uint8_t *buf;
	bool free_buf;
	int err = 0;

	nread = pkt_read_recv(subreq, state, &buf, &free_buf, &err);
	TALLOC_FREE(subreq);
	state->subreq = NULL;
	if (nread == -1) {
		tevent_req_error(req, err);
		return;
	}

	comm->read_handler(buf, nread, comm->read_private_data);

	if (free_buf) {
		talloc_free(buf);
	}

	subreq = pkt_read_send(state, state->ev, comm->fd, sizeof(uint32_t),
			       state->buf, state->buflen,
			       comm_read_more, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	state->subreq = subreq;

	tevent_req_set_callback(subreq, comm_read_done, req);
}

static void comm_read_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
	}
}

static void comm_read_failed(struct tevent_req *req)
{
	struct comm_context *comm = tevent_req_callback_data(
		req, struct comm_context);

	comm_read_recv(req, NULL);
	TALLOC_FREE(req);
	comm->read_req = NULL;
	if (comm->dead_handler != NULL) {
		comm->dead_handler(comm->dead_private_data);
	}
}


/*
 * Write packets
 */

struct comm_write_entry {
	struct comm_context *comm;
	struct tevent_queue_entry *qentry;
	struct tevent_req *req;
};

struct comm_write_state {
	struct tevent_context *ev;
	struct comm_context *comm;
	struct comm_write_entry *entry;
	struct tevent_req *subreq;
	uint8_t *buf;
	size_t buflen, nwritten;
};

static int comm_write_entry_destructor(struct comm_write_entry *entry);
static void comm_write_trigger(struct tevent_req *req, void *private_data);
static void comm_write_done(struct tevent_req *subreq);

struct tevent_req *comm_write_send(TALLOC_CTX *mem_ctx,
				   struct tevent_context *ev,
				   struct comm_context *comm,
				   uint8_t *buf, size_t buflen)
{
	struct tevent_req *req;
	struct comm_write_state *state;
	struct comm_write_entry *entry;

	req = tevent_req_create(mem_ctx, &state, struct comm_write_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->comm = comm;
	state->buf = buf;
	state->buflen = buflen;

	entry = talloc_zero(state, struct comm_write_entry);
	if (tevent_req_nomem(entry, req)) {
		return tevent_req_post(req, ev);
	}

	entry->comm = comm;
	entry->req = req;
	entry->qentry = tevent_queue_add_entry(comm->queue, ev, req,
					       comm_write_trigger, NULL);
	if (tevent_req_nomem(entry->qentry, req)) {
		return tevent_req_post(req, ev);
	}

	state->entry = entry;
	talloc_set_destructor(entry, comm_write_entry_destructor);

	return req;
}

static int comm_write_entry_destructor(struct comm_write_entry *entry)
{
	struct comm_context *comm = entry->comm;

	if (comm->write_req == entry->req) {
		comm->write_req = NULL;
		TEVENT_FD_NOT_WRITEABLE(comm->fde);
	}

	TALLOC_FREE(entry->qentry);
	return 0;
}

static void comm_write_trigger(struct tevent_req *req, void *private_data)
{
	struct comm_write_state *state = tevent_req_data(
		req, struct comm_write_state);
	struct comm_context *comm = state->comm;
	struct tevent_req *subreq;

	comm->write_req = req;

	subreq = pkt_write_send(state, state->ev, comm->fd,
				state->buf, state->buflen);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	state->subreq = subreq;
	tevent_req_set_callback(subreq, comm_write_done, req);
	TEVENT_FD_WRITEABLE(comm->fde);
}

static void comm_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct comm_write_state *state = tevent_req_data(
		req, struct comm_write_state);
	struct comm_context *comm = state->comm;
	ssize_t nwritten;
	int err = 0;

	TEVENT_FD_NOT_WRITEABLE(comm->fde);
	nwritten = pkt_write_recv(subreq, &err);
	TALLOC_FREE(subreq);
	state->subreq = NULL;
	comm->write_req = NULL;
	if (nwritten == -1) {
		if (err == EPIPE) {
			comm->dead_handler(comm->dead_private_data);
		}
		tevent_req_error(req, err);
		return;
	}

	state->nwritten = nwritten;
	state->entry->qentry = NULL;
	TALLOC_FREE(state->entry);
	tevent_req_done(req);
}

bool comm_write_recv(struct tevent_req *req, int *perr)
{
	struct comm_write_state *state = tevent_req_data(
		req, struct comm_write_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	if (state->nwritten != state->buflen) {
		*perr = EIO;
		return false;
	}

	*perr = 0;
	return true;
}

static void comm_fd_handler(struct tevent_context *ev,
			    struct tevent_fd *fde,
			    uint16_t flags, void *private_data)
{
	struct comm_context *comm = talloc_get_type_abort(
		private_data, struct comm_context);

	if (flags & TEVENT_FD_READ) {
		struct comm_read_state *read_state;

		if (comm->read_req == NULL) {
			/* This should never happen */
			abort();
		}

		read_state = tevent_req_data(comm->read_req,
					     struct comm_read_state);
		pkt_read_handler(ev, fde, flags, read_state->subreq);
	}

	if (flags & TEVENT_FD_WRITE) {
		struct comm_write_state *write_state;

		if (comm->write_req == NULL) {
			TEVENT_FD_NOT_WRITEABLE(comm->fde);
			return;
		}

		write_state = tevent_req_data(comm->write_req,
					      struct comm_write_state);
		pkt_write_handler(ev, fde, flags, write_state->subreq);
	}
}
