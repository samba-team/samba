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

/*
 * Test read_handler and dead_handler
 */

static void test1_read_handler(uint8_t *buf, size_t buflen,
			       void *private_data)
{
	int *result = (int *)private_data;

	*result = -1;
}

static void test1_dead_handler(void *private_data)
{
	int *result = (int *)private_data;

	*result = 1;
}

static void test1(void)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct comm_context *comm;
	int fd[2];
	int result = 0;
	uint32_t data[2];
	int ret;
	ssize_t n;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	ret = pipe(fd);
	assert(ret == 0);

	ret = comm_setup(ev, ev, fd[0], test1_read_handler, &result,
			 test1_dead_handler, &result, &comm);
	assert(ret == 0);

	data[0] = 2 * sizeof(uint32_t);
	data[1] = 0;

	n = write(fd[1], (void *)&data, data[0]);
	assert(n == data[0]);

	while (result == 0) {
		tevent_loop_once(ev);
	}

	assert(result == -1);

	result = 0;
	close(fd[1]);

	while (result == 0) {
		tevent_loop_once(ev);
	}

	assert(result == 1);

	talloc_free(mem_ctx);
}

/*
 * Test that the tevent_req returned by comm_write_send() can be free'd.
 */

struct test2_state {
	TALLOC_CTX *mem_ctx;
	bool done;
};

static void test2_read_handler(uint8_t *buf, size_t buflen,
			       void *private_data)
{
	struct test2_state *state = (struct test2_state *)private_data;

	TALLOC_FREE(state->mem_ctx);
}

static void test2_dead_handler(void *private_data)
{
	abort();
}

struct test2_write_state {
	int count;
};

static void test2_write_done(struct tevent_req *subreq);

static struct tevent_req *test2_write_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct comm_context *comm,
					   uint8_t *buf, size_t buflen)
{
	struct tevent_req *req, *subreq;
	struct test2_write_state *state;
	int i;

	req = tevent_req_create(mem_ctx, &state, struct test2_write_state);
	if (req == NULL) {
		return NULL;
	}

	state->count = 0;

	for (i=0; i<10; i++) {
		subreq = comm_write_send(state, ev, comm, buf, buflen);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, test2_write_done, req);
	}

	return req;
}

static void test2_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct test2_write_state *state = tevent_req_data(
		req, struct test2_write_state);
	bool status;
	int ret;

	status = comm_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	state->count += 1;

	if (state->count == 10) {
		tevent_req_done(req);
	}
}

static void test2_timer_handler(struct tevent_context *ev,
				struct tevent_timer *te,
				struct timeval cur_time,
				void *private_data)
{
	struct test2_state *state = (struct test2_state *)private_data;

	state->done = true;
}

static void test2(void)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct comm_context *comm_reader, *comm_writer;
	struct test2_state test2_state;
	struct tevent_req *req;
	struct tevent_timer *te;
	int fd[2];
	uint32_t data[2];
	int ret;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	test2_state.mem_ctx = talloc_new(mem_ctx);
	assert(test2_state.mem_ctx != NULL);

	test2_state.done = false;

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	ret = pipe(fd);
	assert(ret == 0);

	ret = comm_setup(ev, ev, fd[0], test2_read_handler, &test2_state,
			 test2_dead_handler, NULL, &comm_reader);
	assert(ret == 0);

	ret = comm_setup(ev, ev, fd[1], NULL, NULL, test2_dead_handler, NULL,
			 &comm_writer);
	assert(ret == 0);

	data[0] = 2 * sizeof(uint32_t);
	data[1] = 0;

	req = test2_write_send(test2_state.mem_ctx, ev, comm_writer,
			       (uint8_t *)data, data[0]);
	assert(req != NULL);

	te = tevent_add_timer(ev, ev, tevent_timeval_current_ofs(5,0),
			      test2_timer_handler, &test2_state);
	assert(te != NULL);

	while (! test2_state.done) {
		tevent_loop_once(ev);
	}

	talloc_free(mem_ctx);
}

/*
 * Test that data is written and read correctly.
 */

static void test3_dead_handler(void *private_data)
{
	int dead_data = *(int *)private_data;

	assert(dead_data == 1 || dead_data == 2);

	if (dead_data == 1) {
		/* reader */
		fprintf(stderr, "writer closed pipe\n");
	} else {
		/* writer */
		fprintf(stderr, "reader closed pipe\n");
	}
}

struct test3_writer_state {
	struct tevent_context *ev;
	struct comm_context *comm;
	uint8_t *buf;
	size_t *pkt_size;
	int count, id;
};

static void test3_writer_next(struct tevent_req *subreq);

static struct tevent_req *test3_writer_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct comm_context *comm,
					    size_t *pkt_size, size_t count)
{
	struct tevent_req *req, *subreq;
	struct test3_writer_state *state;
	size_t max_size = 0, buflen;
	size_t i;

	for (i=0; i<count; i++) {
		if (pkt_size[i] > max_size) {
			max_size = pkt_size[i];
		}
	}

	req = tevent_req_create(mem_ctx, &state, struct test3_writer_state);
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

	tevent_req_set_callback(subreq, test3_writer_next, req);
	return req;
}

static void test3_writer_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct test3_writer_state *state = tevent_req_data(
		req, struct test3_writer_state);
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

	tevent_req_set_callback(subreq, test3_writer_next, req);
}

static void test3_writer_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return;
	}
	*perr = 0;
}

static void test3_writer(int fd, size_t *pkt_size, size_t count)
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
			 test3_dead_handler, &dead_data, &comm);
	assert(err == 0);
	assert(comm != NULL);

	req = test3_writer_send(mem_ctx, ev, comm, pkt_size, count);
	assert(req != NULL);

	tevent_req_poll(req, ev);

	test3_writer_recv(req, &err);
	assert(err == 0);

	talloc_free(mem_ctx);
}

struct test3_reader_state {
	size_t *pkt_size;
	int count, received;
	bool done;
};

static void test3_reader_handler(uint8_t *buf, size_t buflen,
				 void *private_data)
{
	struct test3_reader_state *state = talloc_get_type_abort(
		private_data, struct test3_reader_state);

	assert(buflen == state->pkt_size[state->received]);
	printf("%zi ", buflen);
	state->received++;

	if (state->received == state->count) {
		printf("\n");
		state->done = true;
	}
}

static void test3_reader(int fd, size_t *pkt_size, int count)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct comm_context *comm;
	struct test3_reader_state *state;
	int dead_data = 1;
	int err;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	state = talloc_zero(mem_ctx, struct test3_reader_state);
	assert(state != NULL);

	state->pkt_size = pkt_size;
	state->count = count;
	state->received = 0;
	state->done = false;

	err = comm_setup(mem_ctx, ev, fd, test3_reader_handler, state,
			 test3_dead_handler, &dead_data, &comm);
	assert(err == 0);
	assert(comm != NULL);

	while (!state->done) {
		tevent_loop_once(ev);
	}

	talloc_free(mem_ctx);
}

static void test3(void)
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
		test3_writer(fd[1], pkt_size, 13);
		close(fd[1]);
		exit(0);
	}

	close(fd[1]);
	test3_reader(fd[0], pkt_size, 13);
	close(fd[0]);
}


int main(int argc, const char **argv)
{
	int num;

	if (argc != 2) {
		fprintf(stderr, "%s <testnum>\n", argv[0]);
		exit(1);
	}

	num = atoi(argv[1]);

	switch (num) {
	case 1:
		test1();
		break;

	case 2:
		test2();
		break;

	case 3:
		test3();
		break;

	default:
		fprintf(stderr, "Unknown test number %s\n", argv[1]);
	}

	return 0;
}
