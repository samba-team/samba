/*
   Write a packet

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

#include <talloc.h>
#include <tevent.h>

#include "lib/util/tevent_unix.h"

#include "pkt_write.h"

/*
 * Write a packet
 */

struct pkt_write_state {
	int fd;
	uint8_t *buf;
	size_t buflen, offset;
};

struct tevent_req *pkt_write_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  int fd, uint8_t *buf, size_t buflen)
{
	struct tevent_req *req;
	struct pkt_write_state *state;

	req = tevent_req_create(mem_ctx, &state, struct pkt_write_state);
	if (req == NULL) {
		return NULL;
	}

	state->fd = fd;
	state->buf = buf;
	state->buflen = buflen;
	state->offset = 0;

	return req;
}

void pkt_write_handler(struct tevent_context *ev, struct tevent_fd *fde,
		       uint16_t flags, struct tevent_req *req)
{
	struct pkt_write_state *state = tevent_req_data(
		req, struct pkt_write_state);
	ssize_t nwritten;

	nwritten = write(state->fd, state->buf + state->offset,
			 state->buflen - state->offset);
	if ((nwritten == -1) && (errno == EINTR)) {
		/* retry */
		return;
	}
	if (nwritten == -1) {
		tevent_req_error(req, errno);
		return;
	}
	if (nwritten == 0) {
		/* retry */
		return;
	}

	state->offset += nwritten;
	if (state->offset < state->buflen) {
		/* come back later */
		return;
	}

	tevent_req_done(req);
}

ssize_t pkt_write_recv(struct tevent_req *req, int *perrno)
{
	struct pkt_write_state *state = tevent_req_data(
		req, struct pkt_write_state);

	if (tevent_req_is_unix_error(req, perrno)) {
		return -1;
	}

	return state->offset;
}
