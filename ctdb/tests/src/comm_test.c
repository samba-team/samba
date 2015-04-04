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

static void dead_handler(void *private_data)
{
	int dead_data = *(int *)private_data;

	assert(dead_data == 1 || dead_data == 2);

	if (dead_data == 1) {
		/* reader */
		printf("writer closed pipe\n");
	} else {
		/* writer */
		printf("reader closed pipe\n");
	}
}

struct writer_state {
	struct tevent_context *ev;
	struct comm_context *comm;
	uint8_t *buf;
	size_t *pkt_size;
	int count, id;
};

static void writer_next(struct tevent_req *subreq);

static struct tevent_req *writer_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      struct comm_context *comm,
				      size_t *pkt_size, int count)
{
	struct tevent_req *req, *subreq;
	struct writer_state *state;
	size_t max_size = 0, buflen;
	int i;

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
	state->comm = comm;
	state->pkt_size = pkt_size;
	state->count = count;
	state->id = 0;

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

	tevent_req_set_callback(subreq, writer_next, req);
	return req;
}

static void writer_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct writer_state *state = tevent_req_data(
		req, struct writer_state);
	bool ret;
	int err;
	size_t buflen;

	ret = comm_write_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_error(req, err);
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

	tevent_req_set_callback(subreq, writer_next, req);
}

static void writer_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return;
	}
	*perr = 0;
}

static void writer(int fd, size_t *pkt_size, int count)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct comm_context *comm;
	struct tevent_req *req;
	int dead_data = 2;
	int err;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	err = comm_setup(mem_ctx, ev, fd, NULL, NULL,
			 dead_handler, &dead_data, &comm);
	assert(err == 0);
	assert(comm != NULL);

	req = writer_send(mem_ctx, ev, comm, pkt_size, count);
	assert(req != NULL);

	tevent_req_poll(req, ev);

	writer_recv(req, &err);
	assert(err == 0);

	talloc_free(mem_ctx);
}

struct reader_state {
	size_t *pkt_size;
	int count, received;
	bool done;
};

static void reader_handler(uint8_t *buf, size_t buflen, void *private_data)
{
	struct reader_state *state = talloc_get_type_abort(
		private_data, struct reader_state);

	assert(buflen == state->pkt_size[state->received]);
	printf("%zi ", buflen);
	state->received++;

	if (state->received == state->count) {
		printf("\n");
		state->done = true;
	}
}

static void reader(int fd, size_t *pkt_size, int count)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct comm_context *comm;
	struct reader_state *state;
	int dead_data = 1;
	int err;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	state = talloc_zero(mem_ctx, struct reader_state);
	assert(state != NULL);

	state->pkt_size = pkt_size;
	state->count = count;
	state->received = 0;
	state->done = false;

	err = comm_setup(mem_ctx, ev, fd, reader_handler, state,
			 dead_handler, &dead_data, &comm);
	assert(err == 0);
	assert(comm != NULL);

	while (!state->done) {
		tevent_loop_once(ev);
	}

	talloc_free(mem_ctx);
}

int main(void)
{
	int fd[2];
	int ret;
	pid_t pid;
	size_t pkt_size[13] = { 100, 2048, 500, 4096, 1024, 8192,
			      200, 16384, 300, 32768, 400, 65536,
			      1024*1024 };


	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		/* Child process */
		close(fd[0]);
		writer(fd[1], pkt_size, 13);
		close(fd[1]);
		exit(0);
	}

	close(fd[1]);
	reader(fd[0], pkt_size, 13);
	close(fd[0]);

	return 0;
}
