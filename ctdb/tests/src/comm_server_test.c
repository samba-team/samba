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

#include "lib/async_req/async_sock.h"

#include "common/pkt_read.c"
#include "common/pkt_write.c"
#include "common/comm.c"

struct echo_state {
	struct tevent_context *ev;
	int fd;
	struct comm_context *comm;
	uint8_t *data;
};

static void read_handler(uint8_t *buf, size_t buflen, void *private_data);
static void read_failed(void *private_data);
static void write_done(struct tevent_req *subreq);

static struct tevent_req *echo_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev, int fd)
{
	struct tevent_req *req;
	struct echo_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct echo_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->fd = fd;

	ret = comm_setup(state, ev, fd, read_handler, req,
			 read_failed, req, &state->comm);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void read_handler(uint8_t *buf, size_t buflen, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct echo_state *state = tevent_req_data(
		req, struct echo_state);
	struct tevent_req *subreq;

	state->data = talloc_memdup(state, buf, buflen);
	if (tevent_req_nomem(state->data, req)) {
		return;
	}

	subreq = comm_write_send(state, state->ev, state->comm,
				 state->data, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, write_done, req);
}

static void read_failed(void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);

	tevent_req_done(req);
}

static void write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct echo_state *state = tevent_req_data(
		req, struct echo_state);
	bool ret;
	int err;

	TALLOC_FREE(state->data);

	ret = comm_write_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_error(req, err);
		return;
	}
}

static bool echo_recv(struct tevent_req *req, int *perr)
{
	struct echo_state *state = tevent_req_data(
		req, struct echo_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return false;
	}

	close(state->fd);
	return true;
}


struct socket_process_state {
	struct tevent_context *ev;
	int fd;
	int max_clients;
	int num_clients;
};

static void socket_process_client(struct tevent_req *subreq);
static void socket_process_client_done(struct tevent_req *subreq);

static struct tevent_req *socket_process_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      int fd, int max_clients)
{
	struct tevent_req *req, *subreq;
	struct socket_process_state *state;

	req = tevent_req_create(mem_ctx, &state, struct socket_process_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->fd = fd;
	state->max_clients = max_clients;
	state->num_clients = 0;

	subreq = accept_send(state, ev, fd);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, socket_process_client, req);

	return req;
}

static void socket_process_client(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct socket_process_state *state = tevent_req_data(
		req, struct socket_process_state);
	int client_fd;
	int err = 0;

	client_fd = accept_recv(subreq, NULL, NULL, &err);
	TALLOC_FREE(subreq);

	state->num_clients++;

	if (client_fd == -1) {
		tevent_req_error(req, err);
		return;
	}

	subreq = echo_send(state, state->ev, client_fd);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, socket_process_client_done, req);

	if (state->num_clients == state->max_clients) {
		/* Stop accepting any more clients */
		return;
	}

	subreq = accept_send(state, state->ev, state->fd);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, socket_process_client, req);
}

static void socket_process_client_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct socket_process_state *state = tevent_req_data(
		req, struct socket_process_state);
	bool ret;
	int err = 0;

	ret = echo_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!ret) {
		tevent_req_error(req, EIO);
		return;
	}

	if (state->num_clients == state->max_clients) {
		tevent_req_done(req);
	}
}

static void socket_process_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
	}
}

static int socket_init(char *sockpath)
{
	struct sockaddr_un addr;
	int fd, ret;
	size_t len;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;

	len = strlcpy(addr.sun_path, sockpath, sizeof(addr.sun_path));
	assert(len < sizeof(addr.sun_path));

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	assert(fd != -1);

	ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	assert(ret != -1);

	ret = listen(fd, 10);
	assert(ret != -1);

	return fd;
}

int main(int argc, char *argv[])
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct tevent_req *req;
	int fd, err = 0;
	int num_clients;

	if (argc != 3) {
		printf("Usage: %s <sockpath> <num_clients>\n", argv[0]);
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	fd = socket_init(argv[1]);
	num_clients = atoi(argv[2]);
	assert(num_clients > 0);

	req = socket_process_send(mem_ctx, ev, fd, num_clients);
	assert(req != NULL);

	tevent_req_poll(req, ev);

	socket_process_recv(req, &err);
	return err;
}
