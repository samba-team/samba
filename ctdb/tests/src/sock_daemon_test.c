/*
   sock daemon tests

   Copyright (C) Amitay Isaacs  2016

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
#include "system/network.h"
#include "system/wait.h"

#include <assert.h>

#include "common/logging.c"
#include "common/pkt_read.c"
#include "common/pkt_write.c"
#include "common/comm.c"
#include "common/pidfile.c"
#include "common/sock_daemon.c"
#include "common/sock_io.c"

static struct tevent_req *dummy_read_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct sock_client_context *client,
					  uint8_t *buf, size_t buflen,
					  void *private_data)
{
	return NULL;
}

static bool dummy_read_recv(struct tevent_req *req, int *perr)
{
	if (perr != NULL) {
		*perr = EINVAL;
	}
	return false;
}

static struct sock_socket_funcs dummy_socket_funcs = {
	.read_send = dummy_read_send,
	.read_recv = dummy_read_recv,
};

static void test1(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	struct sock_daemon_context *sockd;
	struct stat st;
	int ret;

	ret = sock_daemon_setup(mem_ctx, "test1", "file:", "NOTICE", pidfile,
				NULL, NULL, &sockd);
	assert(ret == 0);
	assert(sockd != NULL);

	ret = stat(pidfile, &st);
	assert(ret == 0);
	assert(S_ISREG(st.st_mode));

	ret = sock_daemon_add_unix(sockd, sockpath, &dummy_socket_funcs, NULL);
	assert(ret == 0);

	ret = stat(sockpath, &st);
	assert(ret == 0);
	assert(S_ISSOCK(st.st_mode));

	talloc_free(sockd);

	ret = stat(pidfile, &st);
	assert(ret == -1);

	ret = stat(sockpath, &st);
	assert(ret == -1);
}

static void test2_startup(void *private_data)
{
	int fd = *(int *)private_data;
	int ret = 1;
	ssize_t nwritten;

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
}

static void test2_reconfigure(void *private_data)
{
	int fd = *(int *)private_data;
	int ret = 2;
	ssize_t nwritten;

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
}

static void test2_shutdown(void *private_data)
{
	int fd = *(int *)private_data;
	int ret = 3;
	ssize_t nwritten;

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
}

static struct sock_daemon_funcs test2_funcs = {
	.startup = test2_startup,
	.reconfigure = test2_reconfigure,
	.shutdown = test2_shutdown,
};

static void test2(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	struct stat st;
	int fd[2];
	pid_t pid, pid2;
	int ret;
	ssize_t n;

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		struct tevent_context *ev;
		struct sock_daemon_context *sockd;

		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test2", "file:", "NOTICE",
					pidfile, &test2_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &dummy_socket_funcs, NULL);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	ret = kill(pid, SIGHUP);
	assert(ret == 0);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 2);

	ret = kill(pid, SIGUSR1);
	assert(ret == 0);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 2);

	ret = kill(pid, SIGTERM);
	assert(ret == 0);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 3);

	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);
	assert(WEXITSTATUS(ret) == 0);

	close(fd[0]);

	ret = stat(pidfile, &st);
	assert(ret == -1);

	ret = stat(sockpath, &st);
	assert(ret == -1);
}

static void test3(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	struct stat st;
	pid_t pid_watch, pid, pid2;
	int ret;

	pid_watch = fork();
	assert(pid_watch != -1);

	if (pid_watch == 0) {
		sleep(10);
		exit(0);
	}

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		struct tevent_context *ev;
		struct sock_daemon_context *sockd;

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test3", "file:", "NOTICE",
					NULL, NULL, NULL, &sockd);
		assert(ret == 0);

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &dummy_socket_funcs, NULL);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pid_watch);
		assert(ret == ESRCH);

		exit(0);
	}

	pid2 = waitpid(pid_watch, &ret, 0);
	assert(pid2 == pid_watch);
	assert(WEXITSTATUS(ret) == 0);

	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);
	assert(WEXITSTATUS(ret) == 0);

	ret = stat(pidfile, &st);
	assert(ret == -1);

	ret = stat(sockpath, &st);
	assert(ret == -1);
}

static void test4_handler(struct tevent_context *ev,
			  struct tevent_timer *te,
			  struct timeval curtime,
			  void *private_data)
{
	struct sock_daemon_context *sockd = talloc_get_type_abort(
		private_data, struct sock_daemon_context);

	talloc_free(sockd);
}

static void test4(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	struct stat st;
	pid_t pid, pid2;
	int ret;

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		struct tevent_context *ev;
		struct sock_daemon_context *sockd;
		struct tevent_timer *te;

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test4", "file:", "NOTICE",
					NULL, NULL, NULL, &sockd);
		assert(ret == 0);

		te = tevent_add_timer(ev, ev, tevent_timeval_current_ofs(10,0),
				      test4_handler, sockd);
		assert(te != NULL);

		ret = sock_daemon_run(ev, sockd, -1);
		assert(ret == 0);

		exit(0);
	}

	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);
	assert(WEXITSTATUS(ret) == 0);

	ret = stat(pidfile, &st);
	assert(ret == -1);

	ret = stat(sockpath, &st);
	assert(ret == -1);
}

#define TEST5_MAX_CLIENTS	10

struct test5_pkt {
	uint32_t len;
	int data;
};

struct test5_client_state {
	int id;
	int fd;
	bool done;
};

static void test5_client_callback(uint8_t *buf, size_t buflen,
				  void *private_data)
{
	struct test5_client_state *state =
		(struct test5_client_state *)private_data;
	struct test5_pkt *pkt;
	ssize_t n;
	int ret;

	if (buf == NULL) {
		assert(buflen == 0);

		ret = 0;
	} else {
		assert(buflen == sizeof(struct test5_pkt));
		pkt = (struct test5_pkt *)buf;
		assert(pkt->len == sizeof(struct test5_pkt));

		ret = pkt->data;
	}

	assert(state->fd != -1);

	n = write(state->fd, (void *)&ret, sizeof(int));
	assert(n == sizeof(int));

	state->done = true;
}

static int test5_client(const char *sockpath, int id)
{
	pid_t pid;
	int fd[2];
	int ret;
	ssize_t n;

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		struct tevent_context *ev;
		struct test5_client_state state;
		struct sock_queue *queue;
		struct test5_pkt pkt;
		int conn;

		close(fd[0]);

		ev = tevent_context_init(NULL);
		assert(ev != NULL);

		conn = sock_connect(sockpath);
		assert(conn != -1);

		state.id = id;
		state.fd = fd[1];
		state.done = false;

		queue = sock_queue_setup(ev, ev, conn,
					 test5_client_callback, &state);
		assert(queue != NULL);

		pkt.len = 8;
		pkt.data = 0xbaba;

		ret = sock_queue_write(queue, (uint8_t *)&pkt,
				       sizeof(struct test5_pkt));
		assert(ret == 0);

		while (! state.done) {
			tevent_loop_once(ev);
		}

		close(fd[0]);
		state.fd = -1;

		sleep(10);
		exit(0);
	}

	close(fd[1]);

	ret = 0;
	n = read(fd[0], &ret, sizeof(ret));
	if (n == 0) {
		fprintf(stderr, "client id %d read 0 bytes\n", id);
	}
	assert(n == 0 || n == sizeof(ret));

	close(fd[0]);

	return ret;
}

struct test5_server_state {
	int num_clients;
};

static bool test5_connect(struct sock_client_context *client,
			  void *private_data)
{
	struct test5_server_state *state =
		(struct test5_server_state *)private_data;

	if (state->num_clients == TEST5_MAX_CLIENTS) {
		return false;
	}

	state->num_clients += 1;
	assert(state->num_clients <= TEST5_MAX_CLIENTS);
	return true;
}

static void test5_disconnect(struct sock_client_context *client,
			     void *private_data)
{
	struct test5_server_state *state =
		(struct test5_server_state *)private_data;

	state->num_clients -= 1;
	assert(state->num_clients >= 0);
}

struct test5_read_state {
	struct test5_pkt reply;
};

static void test5_read_done(struct tevent_req *subreq);

static struct tevent_req *test5_read_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct sock_client_context *client,
					  uint8_t *buf, size_t buflen,
					  void *private_data)
{
	struct test5_server_state *server_state =
		(struct test5_server_state *)private_data;
	struct tevent_req *req, *subreq;
	struct test5_read_state *state;
	struct test5_pkt *pkt;

	req = tevent_req_create(mem_ctx, &state, struct test5_read_state);
	assert(req != NULL);

	assert(buflen == sizeof(struct test5_pkt));

	pkt = (struct test5_pkt *)buf;
	assert(pkt->data == 0xbaba);

	state->reply.len = sizeof(struct test5_pkt);
	state->reply.data = server_state->num_clients;

	subreq = sock_socket_write_send(state, ev, client,
					(uint8_t *)&state->reply,
					state->reply.len);
	assert(subreq != NULL);

	tevent_req_set_callback(subreq, test5_read_done, req);

	return req;
}

static void test5_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool status;

	status = sock_socket_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static bool test5_read_recv(struct tevent_req *req, int *perr)
{
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	return true;
}

static struct sock_socket_funcs test5_client_funcs = {
	.connect = test5_connect,
	.disconnect = test5_disconnect,
	.read_send = test5_read_send,
	.read_recv = test5_read_recv,
};

static void test5_startup(void *private_data)
{
	int fd = *(int *)private_data;
	int ret = 1;
	ssize_t nwritten;

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
	close(fd);
}

static struct sock_daemon_funcs test5_funcs = {
	.startup = test5_startup,
};

static void test5(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	pid_t pid_server, pid;
	int fd[2], ret, i;
	ssize_t n;

	pid = getpid();

	ret = pipe(fd);
	assert(ret == 0);

	pid_server = fork();
	assert(pid_server != -1);

	if (pid_server == 0) {
		struct tevent_context *ev;
		struct sock_daemon_context *sockd;
		struct test5_server_state state;

		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test5", "file:", "NOTICE",
					pidfile, &test5_funcs, &fd[1], &sockd);
		assert(ret == 0);

		state.num_clients = 0;

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &test5_client_funcs, &state);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pid);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	close(fd[0]);

	for (i=0; i<100; i++) {
		ret = test5_client(sockpath, i);
		if (i < TEST5_MAX_CLIENTS) {
			assert(ret == i+1);
		} else {
			assert(ret == 0);
		}
	}

	for (i=0; i<100; i++) {
		pid = wait(&ret);
		assert(pid != -1);
	}

	ret = kill(pid_server, SIGTERM);
	assert(ret == 0);
}

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	const char *pidfile, *sockpath;

	if (argc != 3) {
		fprintf(stderr, "%s <pidfile> <sockpath>\n", argv[0]);
		exit(1);
	}

	pidfile = argv[1];
	sockpath = argv[2];

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	test1(mem_ctx, pidfile, sockpath);
	test2(mem_ctx, pidfile, sockpath);
	test3(mem_ctx, pidfile, sockpath);
	test4(mem_ctx, pidfile, sockpath);
	test5(mem_ctx, pidfile, sockpath);

	return 0;
}
