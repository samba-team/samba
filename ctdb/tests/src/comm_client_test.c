/*
   comm tests

   Copyright (C) Amitay Isaacs  2015

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

#include <assert.h>

#include "common/pkt_read.c"
#include "common/pkt_write.c"
#include "common/comm.c"


struct writer_state {
	struct tevent_context *ev;
	struct comm_context *comm;
	uint8_t *buf;
	size_t *pkt_size;
	size_t count, id;
};

static void writer_done(struct tevent_req *subreq);
static void read_handler(uint8_t *buf, size_t buflen, void *private_data);
static void dead_handler(void *private_data);

static struct tevent_req *writer_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      int fd, size_t *pkt_size,
				      size_t count)
{
	struct tevent_req *req, *subreq;
	struct writer_state *state;
	size_t max_size = 0, buflen;
	size_t i;
	int ret;

	for (i=0; i<count; i++) {
		if (pkt_size[i] > max_size) {
			max_size = pkt_size[i];
		}
	}

	req = tevent_req_create(mem_ctx, &state, struct writer_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->pkt_size = pkt_size;
	state->count = count;
	state->id = 0;

	ret = comm_setup(state, ev, fd, read_handler, req,
			 dead_handler, req, &state->comm);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	state->buf = talloc_array(state, uint8_t, max_size);
	if (state->buf == NULL) {
		talloc_free(req);
		return NULL;
	}
	for (i=0; i<max_size; i++) {
		state->buf[i] = i%256;
	}

	buflen = state->pkt_size[state->id];
	*(uint32_t *)state->buf = buflen;
	subreq = comm_write_send(state, state->ev, state->comm,
					 state->buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, writer_done, req);

	return req;
}

static void writer_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool ret;
	int err;

	ret = comm_write_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_error(req, err);
		return;
	}
}

static void read_handler(uint8_t *buf, size_t buflen, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct writer_state *state = tevent_req_data(
		req, struct writer_state);
	struct tevent_req *subreq;

	if (buflen != state->pkt_size[state->id]) {
		tevent_req_error(req, EIO);
		return;
	}

	state->id++;
	if (state->id >= state->count) {
		tevent_req_done(req);
		return;
	}

	buflen = state->pkt_size[state->id];
	*(uint32_t *)state->buf = buflen;
	subreq = comm_write_send(state, state->ev, state->comm,
				 state->buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, writer_done, req);
}

static void dead_handler(void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);

	tevent_req_error(req, EPIPE);
}

static void writer_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return;
	}
	*perr = 0;
}

static int socket_init(char *sockpath)
{
	struct sockaddr_un addr;
	int fd, ret, i;
	size_t len;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	len = strlcpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	assert(len < sizeof(addr.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(fd != -1);

	for (i=0; i<5; i++) {
		ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
		if (ret == 0) {
			break;
		}
		sleep(1);
	}
	assert(ret != -1);

	return fd;
}

int main(int argc, char *argv[])
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct tevent_req *req;
	int fd;
	size_t pkt_size[13] = { 100, 2048, 500, 4096, 1024, 8192,
				200, 16384, 300, 32768, 400, 65536,
				1024*1024 };
	int err;

	if (argc != 2) {
		printf("Usage: %s <sockpath>\n", argv[0]);
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	fd = socket_init(argv[1]);

	req = writer_send(mem_ctx, ev, fd, pkt_size, 13);
	assert(req != NULL);

	tevent_req_poll(req, ev);

	writer_recv(req, &err);
	assert(err == 0);

	exit(0);
}
