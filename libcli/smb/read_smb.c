/*
   Unix SMB/CIFS implementation.
   Infrastructure for async SMB client requests
   Copyright (C) Volker Lendecke 2008

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "system/network.h"
#include "lib/async_req/async_sock.h"
#include "read_smb.h"
#include "lib/util/tevent_unix.h"
#include "libcli/smb/smb_constants.h"

/*
 * Read an smb packet asynchronously, discard keepalives
 */

struct read_smb_state {
	struct tevent_context *ev;
	int fd;
	uint8_t *buf;
};

static ssize_t read_smb_more(uint8_t *buf, size_t buflen, void *private_data);
static void read_smb_done(struct tevent_req *subreq);

struct tevent_req *read_smb_send(TALLOC_CTX *mem_ctx,
				 struct tevent_context *ev,
				 int fd)
{
	struct tevent_req *result, *subreq;
	struct read_smb_state *state;

	result = tevent_req_create(mem_ctx, &state, struct read_smb_state);
	if (result == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fd = fd;

	subreq = read_packet_send(state, ev, fd, 4, read_smb_more, NULL);
	if (subreq == NULL) {
		goto fail;
	}
	tevent_req_set_callback(subreq, read_smb_done, result);
	return result;
 fail:
	TALLOC_FREE(result);
	return NULL;
}

static ssize_t read_smb_more(uint8_t *buf, size_t buflen, void *private_data)
{
	if (buflen > 4) {
		return 0;	/* We've been here, we're done */
	}
	return smb_len_tcp(buf);
}

static void read_smb_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct read_smb_state *state = tevent_req_data(
		req, struct read_smb_state);
	ssize_t len;
	int err;

	len = read_packet_recv(subreq, state, &state->buf, &err);
	TALLOC_FREE(subreq);
	if (len == -1) {
		tevent_req_error(req, err);
		return;
	}

	if (CVAL(state->buf, 0) == NBSSkeepalive) {
		subreq = read_packet_send(state, state->ev, state->fd, 4,
					  read_smb_more, NULL);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, read_smb_done, req);
		return;
	}
	tevent_req_done(req);
}

ssize_t read_smb_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
		      uint8_t **pbuf, int *perrno)
{
	struct read_smb_state *state = tevent_req_data(
		req, struct read_smb_state);

	if (tevent_req_is_unix_error(req, perrno)) {
		return -1;
	}
	*pbuf = talloc_move(mem_ctx, &state->buf);
	return talloc_get_size(*pbuf);
}
