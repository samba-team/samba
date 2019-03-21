/*
 * Unix SMB/CIFS implementation.
 *
 * Copyright (C) Volker Lendecke 2019
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "replace.h"
#include "system/filesys.h"
#include "tstream_u32_read.h"
#include "lib/util/byteorder.h"
#include "lib/util/tevent_unix.h"

struct tstream_u32_read_state {
	size_t max_msglen;
	size_t buflen;
	uint8_t *buf;
};

static int tstream_u32_read_next_vector(struct tstream_context *stream,
					void *private_data,
					TALLOC_CTX *mem_ctx,
					struct iovec **_vector,
					size_t *_count);
static void tstream_u32_read_done(struct tevent_req *subreq);

struct tevent_req *tstream_u32_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	uint32_t max_msglen,
	struct tstream_context *stream)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct tstream_u32_read_state *state = NULL;

	req = tevent_req_create(
		mem_ctx, &state, struct tstream_u32_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->max_msglen = max_msglen;

	subreq = tstream_readv_pdu_send(
		state,
		ev,
		stream,
		tstream_u32_read_next_vector,
		state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, tstream_u32_read_done, req);
	return req;
}

static int tstream_u32_read_next_vector(struct tstream_context *stream,
					void *private_data,
					TALLOC_CTX *mem_ctx,
					struct iovec **_vector,
					size_t *_count)
{
	struct tstream_u32_read_state *state = talloc_get_type_abort(
		private_data, struct tstream_u32_read_state);
	size_t buflen = talloc_get_size(state->buf);
	struct iovec *vector;
	uint32_t msg_len;
	size_t ofs = 0;
	size_t count;

	if (buflen == 0) {
		msg_len = 4;
		state->buf = talloc_array(state, uint8_t, msg_len);
		if (state->buf == NULL) {
			return -1;
		}
	} else if (buflen == 4) {

		ofs = 4;

		msg_len = RIVAL(state->buf, 0);
		if ((msg_len == 0) || (msg_len > state->max_msglen)) {
			errno = EMSGSIZE;
			return -1;
		}
		msg_len += ofs;
		if (msg_len < ofs) {
			errno = EMSGSIZE;
			return -1;
		}

		state->buf = talloc_realloc(
			state, state->buf, uint8_t, msg_len);
		if (state->buf == NULL) {
			return -1;
		}
	} else {
		*_vector = NULL;
		*_count = 0;
		return 0;
	}

	vector = talloc(mem_ctx, struct iovec);
	if (vector == NULL) {
		return -1;
	}
	*vector = (struct iovec) {
		.iov_base = state->buf + ofs, .iov_len = msg_len - ofs,
	};
	count = 1;

	*_vector = vector;
	*_count = count;
	return 0;
}

static void tstream_u32_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret, err;

	ret = tstream_readv_pdu_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		tevent_req_error(req, err);
		return;
	}
	tevent_req_done(req);
}

int tstream_u32_read_recv(
	struct tevent_req *req,
	TALLOC_CTX *mem_ctx,
	uint8_t **buf,
	size_t *buflen)
{
	struct tstream_u32_read_state *state = tevent_req_data(
		req, struct tstream_u32_read_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		return err;
	}
	*buflen = talloc_get_size(state->buf);
	*buf = talloc_move(mem_ctx, &state->buf);
	return 0;
}
