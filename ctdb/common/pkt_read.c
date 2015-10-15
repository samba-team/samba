/*
   Reading packets using fixed and dynamic buffer

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

/* This is similar to read_packet abstraction.  The main different is that
 * tevent fd event is created only once.
 */

#include "replace.h"
#include "system/network.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/tevent_unix.h"

#include "pkt_read.h"

/*
 * Read a packet using fixed buffer
 */

struct pkt_read_state {
	int fd;
	uint8_t *buf;
	size_t buflen;
	size_t nread, total;
	bool use_fixed;
	ssize_t (*more)(uint8_t *buf, size_t buflen, void *private_data);
	void *private_data;
};

struct tevent_req *pkt_read_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 int fd, size_t initial,
				 uint8_t *buf, size_t buflen,
				 ssize_t (*more)(uint8_t *buf,
						 size_t buflen,
						 void *private_data),
				 void *private_data)
{
	struct tevent_req *req;
	struct pkt_read_state *state;

	req = tevent_req_create(mem_ctx, &state, struct pkt_read_state);
	if (req == NULL) {
		return NULL;
	}

	state->fd = fd;

	if (buf == NULL || buflen == 0) {
		state->use_fixed = false;
		state->buf = talloc_array(state, uint8_t, initial);
		if (state->buf == NULL) {
			talloc_free(req);
			return NULL;
		}
		state->buflen = initial;
	} else {
		state->use_fixed = true;
		state->buf = buf;
		state->buflen = buflen;
	}

	state->nread = 0;
	state->total = initial;

	state->more = more;
	state->private_data = private_data;

	return req;
}

void pkt_read_handler(struct tevent_context *ev, struct tevent_fd *fde,
		      uint16_t flags, struct tevent_req *req)
{
	struct pkt_read_state *state = tevent_req_data(
		req, struct pkt_read_state);
	ssize_t nread, more;
	uint8_t *tmp;

	nread = read(state->fd, state->buf + state->nread,
		     state->total - state->nread);
	if ((nread == -1) && (errno == EINTR)) {
		/* retry */
		return;
	}
	if (nread == -1) {
		tevent_req_error(req, errno);
		return;
	}
	if (nread == 0) {
		/* fd closed */
		tevent_req_error(req, EPIPE);
		return;
	}

	state->nread += nread;
	if (state->nread < state->total) {
		/* come back later */
		return;
	}

	/* Check if "more" asks for more data */
	if (state->more == NULL) {
		tevent_req_done(req);
		return;
	}

	more = state->more(state->buf, state->nread, state->private_data);
	if (more == -1) {
		/* invalid packet */
		tevent_req_error(req, EIO);
		return;
	}
	if (more == 0) {
		tevent_req_done(req);
		return;
	}

	if (state->total + more < state->total) {
		/* int wrapped */
		tevent_req_error(req, EMSGSIZE);
		return;
	}

	if (state->total + more < state->buflen) {
		/* continue using fixed buffer */
		state->total += more;
		return;
	}

	if (state->use_fixed) {
		/* switch to dynamic buffer */
		tmp = talloc_array(state, uint8_t, state->total + more);
		if (tevent_req_nomem(tmp, req)) {
			return;
		}

		memcpy(tmp, state->buf, state->total);
		state->use_fixed = false;
	} else {
		tmp = talloc_realloc(state, state->buf, uint8_t,
				     state->total + more);
		if (tevent_req_nomem(tmp, req)) {
			return;
		}
	}

	state->buf = tmp;
	state->buflen = state->total + more;
	state->total += more;
}

ssize_t pkt_read_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		      uint8_t **pbuf, bool *free_buf, int *perrno)
{
	struct pkt_read_state *state = tevent_req_data(
		req, struct pkt_read_state);

	if (tevent_req_is_unix_error(req, perrno)) {
		return -1;
	}

	if (state->use_fixed) {
		*pbuf = state->buf;
		*free_buf = false;
	} else {
		*pbuf = talloc_steal(mem_ctx, state->buf);
		*free_buf = true;
	}

	return state->total;
}
