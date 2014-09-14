/**
 ** NOTE! The following liberal license applies to this sample file only.
 ** This does NOT imply that all of Samba is released under this license.
 **
 ** This file is meant as a starting point for libtevent users to be used
 ** in any program linking against the LGPL licensed libtevent.
 **/

/*
 * This file is being made available by the Samba Team under the following
 * license:
 *
 * Permission to use, copy, modify, and distribute this sample file for any
 * purpose is hereby granted without fee.
 *
 * This work is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#include "tevent.h"
#include "talloc.h"

/**
 * @brief Helper function to get a useful unix error from tevent_req
 */

static bool tevent_req_is_unix_error(struct tevent_req *req, int *perrno)
{
	enum tevent_req_state state;
	uint64_t err;

	if (!tevent_req_is_error(req, &state, &err)) {
		return false;
	}
	switch (state) {
	case TEVENT_REQ_TIMED_OUT:
		*perrno = ETIMEDOUT;
		break;
	case TEVENT_REQ_NO_MEMORY:
		*perrno = ENOMEM;
		break;
	case TEVENT_REQ_USER_ERROR:
		*perrno = err;
		break;
	default:
		*perrno = EINVAL;
		break;
	}
	return true;
}

/**
 * @brief Wrapper around accept(2)
 */

struct accept_state {
	struct tevent_fd *fde;
	int listen_sock;
	socklen_t addrlen;
	struct sockaddr addr;
	int sock;
};

static void accept_handler(struct tevent_context *ev, struct tevent_fd *fde,
			   uint16_t flags, void *private_data);

static struct tevent_req *accept_send(TALLOC_CTX *mem_ctx,
				      struct tevent_context *ev,
				      int listen_sock)
{
	struct tevent_req *req;
	struct accept_state *state;

	req = tevent_req_create(mem_ctx, &state, struct accept_state);
	if (req == NULL) {
		return NULL;
	}

	state->listen_sock = listen_sock;

	state->fde = tevent_add_fd(ev, state, listen_sock, TEVENT_FD_READ,
				   accept_handler, req);
	if (tevent_req_nomem(state->fde, req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void accept_handler(struct tevent_context *ev, struct tevent_fd *fde,
			   uint16_t flags, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct accept_state *state = tevent_req_data(req, struct accept_state);
	int ret;

	TALLOC_FREE(state->fde);

	if ((flags & TEVENT_FD_READ) == 0) {
		tevent_req_error(req, EIO);
		return;
	}
	state->addrlen = sizeof(state->addr);

	ret = accept(state->listen_sock, &state->addr, &state->addrlen);
	if (ret == -1) {
		tevent_req_error(req, errno);
		return;
	}
	state->sock = ret;
	tevent_req_done(req);
}

static int accept_recv(struct tevent_req *req, struct sockaddr *paddr,
		       socklen_t *paddrlen, int *perr)
{
	struct accept_state *state = tevent_req_data(req, struct accept_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return -1;
	}
	if (paddr != NULL) {
		*paddr = state->addr;
	}
	if (paddrlen != NULL) {
		*paddrlen = state->addrlen;
	}
	return state->sock;
}

/**
 * @brief Wrapper around read(2)
 */

struct read_state {
	struct tevent_fd *fde;
	int fd;
	void *buf;
	size_t count;

	ssize_t nread;
};

static void read_handler(struct tevent_context *ev, struct tevent_fd *fde,
			 uint16_t flags, void *private_data);

static struct tevent_req *read_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    int fd, void *buf, size_t count)
{
	struct tevent_req *req;
	struct read_state *state;

	req = tevent_req_create(mem_ctx, &state, struct read_state);
	if (req == NULL) {
		return NULL;
	}

	state->fd = fd;
	state->buf = buf;
	state->count = count;

	state->fde = tevent_add_fd(ev, state, fd, TEVENT_FD_READ,
				   read_handler, req);
	if (tevent_req_nomem(state->fde, req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void read_handler(struct tevent_context *ev, struct tevent_fd *fde,
			 uint16_t flags, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct read_state *state = tevent_req_data(req, struct read_state);
	ssize_t ret;

	TALLOC_FREE(state->fde);

	if ((flags & TEVENT_FD_READ) == 0) {
		tevent_req_error(req, EIO);
		return;
	}

	ret = read(state->fd, state->buf, state->count);
	if (ret == -1) {
		tevent_req_error(req, errno);
		return;
	}
	state->nread = ret;
	tevent_req_done(req);
}

static ssize_t read_recv(struct tevent_req *req, int *perr)
{
	struct read_state *state = tevent_req_data(req, struct read_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return -1;
	}
	return state->nread;
}

/**
 * @brief Wrapper around write(2)
 */

struct write_state {
	struct tevent_fd *fde;
	int fd;
	const void *buf;
	size_t count;

	ssize_t nwritten;
};

static void write_handler(struct tevent_context *ev, struct tevent_fd *fde,
			 uint16_t flags, void *private_data);

static struct tevent_req *write_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    int fd, const void *buf, size_t count)
{
	struct tevent_req *req;
	struct write_state *state;

	req = tevent_req_create(mem_ctx, &state, struct write_state);
	if (req == NULL) {
		return NULL;
	}

	state->fd = fd;
	state->buf = buf;
	state->count = count;

	state->fde = tevent_add_fd(ev, state, fd, TEVENT_FD_WRITE,
				   write_handler, req);
	if (tevent_req_nomem(state->fde, req)) {
		return tevent_req_post(req, ev);
	}
	return req;
}

static void write_handler(struct tevent_context *ev, struct tevent_fd *fde,
			 uint16_t flags, void *private_data)
{
	struct tevent_req *req = talloc_get_type_abort(
		private_data, struct tevent_req);
	struct write_state *state = tevent_req_data(req, struct write_state);
	ssize_t ret;

	TALLOC_FREE(state->fde);

	if ((flags & TEVENT_FD_WRITE) == 0) {
		tevent_req_error(req, EIO);
		return;
	}

	ret = write(state->fd, state->buf, state->count);
	if (ret == -1) {
		tevent_req_error(req, errno);
		return;
	}
	state->nwritten = ret;
	tevent_req_done(req);
}

static ssize_t write_recv(struct tevent_req *req, int *perr)
{
	struct write_state *state = tevent_req_data(req, struct write_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return -1;
	}
	return state->nwritten;
}

/**
 * @brief Wrapper function that deals with short writes
 */

struct writeall_state {
	struct tevent_context *ev;
	int fd;
	const void *buf;
	size_t count;
	size_t nwritten;
};

static void writeall_done(struct tevent_req *subreq);

static struct tevent_req *writeall_send(TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					int fd, const void *buf, size_t count)
{
	struct tevent_req *req, *subreq;
	struct writeall_state *state;

	req = tevent_req_create(mem_ctx, &state, struct writeall_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fd = fd;
	state->buf = buf;
	state->count = count;
	state->nwritten = 0;

	subreq = write_send(state, state->ev, state->fd,
			    ((char *)state->buf)+state->nwritten,
			    state->count - state->nwritten);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, writeall_done, req);
	return req;
}

static void writeall_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct writeall_state *state = tevent_req_data(
		req, struct writeall_state);
	ssize_t nwritten;
	int err = 0;

	nwritten = write_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		tevent_req_error(req, err);
		return;
	}

	state->nwritten += nwritten;

	if (state->nwritten < state->count) {
		subreq = write_send(state, state->ev, state->fd,
				    ((char *)state->buf)+state->nwritten,
				    state->count - state->nwritten);
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq, writeall_done, req);
		return;
	}
	tevent_req_done(req);
}

static ssize_t writeall_recv(struct tevent_req *req, int *perr)
{
	struct writeall_state *state = tevent_req_data(
		req, struct writeall_state);
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		if (perr != NULL) {
			*perr = err;
		}
		return -1;
	}
	return state->nwritten;
}

/**
 * @brief Async echo handler code dealing with one client
 */

struct echo_state {
	struct tevent_context *ev;
	int fd;
	uint8_t *buf;
};

static int echo_state_destructor(struct echo_state *s);
static void echo_read_done(struct tevent_req *subreq);
static void echo_writeall_done(struct tevent_req *subreq);

static struct tevent_req *echo_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    int fd, size_t bufsize)
{
	struct tevent_req *req, *subreq;
	struct echo_state *state;

	req = tevent_req_create(mem_ctx, &state, struct echo_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->fd = fd;

	talloc_set_destructor(state, echo_state_destructor);

	state->buf = talloc_array(state, uint8_t, bufsize);
	if (tevent_req_nomem(state->buf, req)) {
		return tevent_req_post(req, ev);
	}

	subreq = read_send(state, state->ev, state->fd,
			   state->buf, talloc_get_size(state->buf));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, echo_read_done, req);
	return req;
}

static int echo_state_destructor(struct echo_state *s)
{
	if (s->fd != -1) {
		printf("Closing client fd %d\n", s->fd);
		close(s->fd);
		s->fd = -1;
	}
	return 0;
}

static void echo_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct echo_state *state = tevent_req_data(
		req, struct echo_state);
	ssize_t nread;
	int err;

	nread = read_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nread == -1) {
		tevent_req_error(req, err);
		return;
	}
	if (nread == 0) {
		tevent_req_done(req);
		return;
	}

	subreq = writeall_send(state, state->ev, state->fd, state->buf, nread);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, echo_writeall_done, req);
}

static void echo_writeall_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct echo_state *state = tevent_req_data(
		req, struct echo_state);
	ssize_t nwritten;
	int err;

	nwritten = writeall_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		if (err == EPIPE) {
			tevent_req_done(req);
			return;
		}
		tevent_req_error(req, err);
		return;
	}

	subreq = read_send(state, state->ev, state->fd,
			   state->buf, talloc_get_size(state->buf));
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, echo_read_done, req);
}

static bool echo_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		*perr = err;
		return false;
	}
	return true;
}

/**
 * @brief Full echo handler code accepting and handling clients
 */

struct echo_server_state {
	struct tevent_context *ev;
	int listen_sock;
};

static void echo_server_accepted(struct tevent_req *subreq);
static void echo_server_client_done(struct tevent_req *subreq);

static struct tevent_req *echo_server_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   int listen_sock)
{
	struct tevent_req *req, *subreq;
	struct echo_server_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct echo_server_state);
	if (req == NULL) {
		return NULL;
	}
	state->ev = ev;
	state->listen_sock = listen_sock;

	subreq = accept_send(state, state->ev, state->listen_sock);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, echo_server_accepted, req);
	return req;
}

static void echo_server_accepted(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct echo_server_state *state = tevent_req_data(
		req, struct echo_server_state);
	int sock, err;

	sock = accept_recv(subreq, NULL, NULL, &err);
	TALLOC_FREE(subreq);
	if (sock == -1) {
		tevent_req_error(req, err);
		return;
	}

	printf("new client fd %d\n", sock);

	subreq = echo_send(state, state->ev, sock, 100);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, echo_server_client_done, req);

	subreq = accept_send(state, state->ev, state->listen_sock);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, echo_server_accepted, req);
}

static void echo_server_client_done(struct tevent_req *subreq)
{
	bool ret;
	int err;

	ret = echo_recv(subreq, &err);
	TALLOC_FREE(subreq);

	if (ret) {
		printf("Client done\n");
	} else {
		printf("Client failed: %s\n", strerror(err));
	}
}

static bool echo_server_recv(struct tevent_req *req, int *perr)
{
	int err;

	if (tevent_req_is_unix_error(req, &err)) {
		*perr = err;
		return false;
	}
	return true;
}

int main(int argc, const char **argv)
{
	int ret, port, listen_sock, err;
	struct tevent_context *ev;
	struct sockaddr_in addr;
	struct tevent_req *req;
	bool result;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <port>\n", argv[0]);
		exit(1);
	}

	port = atoi(argv[1]);

	printf("listening on port %d\n", port);

	listen_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (listen_sock == -1) {
		perror("socket() failed");
		exit(1);
	}

	addr = (struct sockaddr_in) {
		.sin_family = AF_INET,
		.sin_port = htons(port)
	};

	ret = bind(listen_sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret == -1) {
		perror("bind() failed");
		exit(1);
	}

	ret = listen(listen_sock, 5);
	if (ret == -1) {
		perror("listen() failed");
		exit(1);
	}

	ev = tevent_context_init(NULL);
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init failed\n");
		exit(1);
	}

	req = echo_server_send(ev, ev, listen_sock);
	if (req == NULL) {
		fprintf(stderr, "echo_server_send failed\n");
		exit(1);
	}

	if (!tevent_req_poll(req, ev)) {
		perror("tevent_req_poll() failed");
		exit(1);
	}

	result = echo_server_recv(req, &err);
	TALLOC_FREE(req);
	if (!result) {
		fprintf(stderr, "echo_server failed: %s\n", strerror(err));
		exit(1);
	}

	return 0;
}
