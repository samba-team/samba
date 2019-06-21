/*
   packet write tests

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

#include "lib/util/blocking.h"

#include "common/pkt_read.c"
#include "common/pkt_write.c"

struct writer_state {
	struct tevent_context *ev;
	int fd;
	uint8_t *buf;
	size_t buflen;
	int  count;
	struct tevent_req *subreq;
};

static void writer_next(struct tevent_req *subreq);

static struct tevent_req *writer_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      int fd, uint8_t *buf, size_t buflen)
{
	struct tevent_req *req, *subreq;
	struct writer_state *state;

	req = tevent_req_create(mem_ctx, &state, struct writer_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->fd = fd;
	state->buf = buf;
	state->buflen = buflen;
	state->count = 0;

	subreq = pkt_write_send(state, state->ev, state->fd,
				state->buf, state->buflen);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	state->subreq = subreq;
	tevent_req_set_callback(subreq, writer_next, req);
	return req;
}

static void writer_next(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct writer_state *state = tevent_req_data(
		req, struct writer_state);
	ssize_t nwritten;
	int err = 0;

	nwritten = pkt_write_recv(subreq, &err);
	TALLOC_FREE(subreq);
	state->subreq = NULL;
	if (nwritten == -1) {
		tevent_req_error(req, err);
		return;
	}

	if ((size_t)nwritten != state->buflen) {
		tevent_req_error(req, EIO);
		return;
	}

	state->count++;
	if (state->count >= 1000) {
		tevent_req_done(req);
		return;
	}

	subreq = pkt_write_send(state, state->ev, state->fd,
				state->buf, state->buflen);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	state->subreq = subreq;
	tevent_req_set_callback(subreq, writer_next, req);
}

static void writer_recv(struct tevent_req *req, int *perr)
{
	struct writer_state *state = tevent_req_data(
		req, struct writer_state);
	int err = 0;

	if (state->subreq != NULL) {
		*perr = -1;
		return;
	}

	if (tevent_req_is_unix_error(req, &err)) {
		*perr = err;
		return;
	}

	*perr = 0;
}

static void writer_handler(struct tevent_context *ev, struct tevent_fd *fde,
			   uint16_t flags, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct writer_state *state = tevent_req_data(
		req, struct writer_state);

	assert(state->subreq != NULL);
	pkt_write_handler(ev, fde, flags, state->subreq);
}

static void writer(int fd)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct tevent_fd *fde;
	struct tevent_req *req;
	uint8_t buf[1024*1024];
	size_t buflen;
	size_t pkt_size[4] = { 100, 500, 1024, 1024*1024 };
	int i, err;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	for (i=0; i<1024*1024; i++) {
		buf[i] = i%256;
	}

	for (i=0; i<4; i++) {
		buflen = pkt_size[i];
		memcpy(buf, &buflen, sizeof(buflen));

		req = writer_send(mem_ctx, ev, fd, buf, buflen);
		assert(req != NULL);

		fde = tevent_add_fd(ev, mem_ctx, fd, TEVENT_FD_WRITE,
				    writer_handler, req);
		assert(fde != NULL);

		tevent_req_poll(req, ev);

		writer_recv(req, &err);
		assert(err == 0);

		talloc_free(fde);
		talloc_free(req);
	}

	close(fd);

	talloc_free(mem_ctx);
}

struct reader_state {
	struct tevent_context *ev;
	int fd;
	uint8_t buf[1024];
	struct tevent_req *subreq;
};

static ssize_t reader_more(uint8_t *buf, size_t buflen, void *private_data);
static void reader_done(struct tevent_req *subreq);

static struct tevent_req *reader_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      int fd)
{
	struct tevent_req *req, *subreq;
	struct reader_state *state;

	req = tevent_req_create(mem_ctx, &state, struct reader_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->fd = fd;

	subreq = pkt_read_send(state, state->ev, state->fd, 4,
			       state->buf, 1024, reader_more, NULL);
	if (tevent_req_nomem(subreq, req)) {
		tevent_req_post(req, ev);
	}

	state->subreq = subreq;
	tevent_req_set_callback(subreq, reader_done, req);
	return req;
}

static ssize_t reader_more(uint8_t *buf, size_t buflen, void *private_data)
{
	uint32_t pkt_len;

	if (buflen < sizeof(pkt_len)) {
		return sizeof(pkt_len) - buflen;
	}

	pkt_len = *(uint32_t *)buf;
	return pkt_len - buflen;
}

static void reader_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct reader_state *state = tevent_req_data(
		req, struct reader_state);
	ssize_t nread;
	uint8_t *buf;
	bool free_buf;
	int err = 0;

	nread = pkt_read_recv(subreq, state, &buf, &free_buf, &err);
	TALLOC_FREE(subreq);
	state->subreq = NULL;
	if (nread == -1) {
		if (err == EPIPE) {
			tevent_req_done(req);
		} else {
			tevent_req_error(req, err);
		}
		return;
	}

	if (free_buf) {
		talloc_free(buf);
	}

	subreq = pkt_read_send(state, state->ev, state->fd, 4,
			       state->buf, 1024, reader_more, NULL);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}

	state->subreq = subreq;
	tevent_req_set_callback(subreq, reader_done, req);
}

static void reader_recv(struct tevent_req *req, int *perr)
{
	struct reader_state *state = tevent_req_data(
		req, struct reader_state);
	int err = 0;

	if (state->subreq != NULL) {
		*perr = -1;
	}

	if (tevent_req_is_unix_error(req, &err)) {
		*perr = err;
		return;
	}

	*perr = 0;
}

static void reader_handler(struct tevent_context *ev, struct tevent_fd *fde,
			   uint16_t flags, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct reader_state *state = tevent_req_data(
		req, struct reader_state);

	assert(state->subreq != NULL);
	pkt_read_handler(ev, fde, flags, state->subreq);
}

static void reader(int fd)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct tevent_fd *fde;
	struct tevent_req *req;
	int err;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	req = reader_send(mem_ctx, ev, fd);
	assert(req != NULL);

	fde = tevent_add_fd(ev, mem_ctx, fd, TEVENT_FD_READ,
			    reader_handler, req);
	assert(fde != NULL);

	tevent_req_poll(req, ev);

	reader_recv(req, &err);
	assert(err == 0);

	close(fd);

	talloc_free(mem_ctx);
}

int main(void)
{
	int fd[2];
	int ret;
	pid_t pid;

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		/* Child process */
		close(fd[0]);
		writer(fd[1]);
		exit(0);
	}

	close(fd[1]);
	ret = set_blocking(fd[0], false);
	if (ret == -1) {
		exit(1);
	}

	reader(fd[0]);

	return 0;
}
