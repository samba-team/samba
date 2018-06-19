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

struct dummy_wait_state {
};

static struct tevent_req *dummy_wait_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  void *private_data)
{
	struct tevent_req *req;
	struct dummy_wait_state *state;
	const char *sockpath = (const char *)private_data;
	struct stat st;
	int ret;

	ret = stat(sockpath, &st);
	assert(ret == 0);
	assert(S_ISSOCK(st.st_mode));

	req = tevent_req_create(mem_ctx, &state, struct dummy_wait_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool dummy_wait_recv(struct tevent_req *req, int *perr)
{
	return true;
}

static int test1_startup_fail(void *private_data)
{
	return 1;
}

static int test1_startup(void *private_data)
{
	const char *sockpath = (const char *)private_data;
	struct stat st;
	int ret;

	ret = stat(sockpath, &st);
	assert(ret == -1);

	return 0;
}

struct test1_startup_state {
};

static struct tevent_req *test1_startup_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     void *private_data)
{
	struct tevent_req *req;
	struct test1_startup_state *state;

	req = tevent_req_create(mem_ctx, &state, struct test1_startup_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_error(req, 2);
	return tevent_req_post(req, ev);
}

static bool test1_startup_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

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

/*
 * test1
 *
 * Check setup without actually running daemon
 */

static void test1(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	struct tevent_context *ev;
	struct sock_daemon_context *sockd;
	struct sock_daemon_funcs test1_funcs;
	struct stat st;
	int ret;

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	test1_funcs = (struct sock_daemon_funcs){
		.startup = test1_startup_fail,
	};

	ret = sock_daemon_setup(mem_ctx, "test1", "file:", "NOTICE",
				&test1_funcs, NULL, &sockd);
	assert(ret == 0);
	assert(sockd != NULL);

	ret = stat(pidfile, &st);
	assert(ret == -1);

	ret = sock_daemon_run(ev, sockd, NULL, false, false, -1);
	assert(ret == EIO);
	talloc_free(sockd);

	test1_funcs = (struct sock_daemon_funcs){
		.startup_send = test1_startup_send,
		.startup_recv = test1_startup_recv,
	};

	ret = sock_daemon_setup(mem_ctx, "test1", "file:", "NOTICE",
				&test1_funcs, NULL, &sockd);
	assert(ret == 0);
	assert(sockd != NULL);

	ret = stat(pidfile, &st);
	assert(ret == -1);

	ret = sock_daemon_run(ev, sockd, NULL, false, false, -1);
	assert(ret == EIO);
	talloc_free(sockd);

	test1_funcs = (struct sock_daemon_funcs){
		.startup = test1_startup,
		.wait_send = dummy_wait_send,
		.wait_recv = dummy_wait_recv,
	};

	ret = sock_daemon_setup(mem_ctx, "test1", "file:", "NOTICE",
				&test1_funcs, discard_const(sockpath), &sockd);
	assert(ret == 0);
	assert(sockd != NULL);

	ret = sock_daemon_add_unix(sockd, sockpath, &dummy_socket_funcs, NULL);
	assert(ret == 0);

	ret = stat(sockpath, &st);
	assert(ret == -1);

	ret = sock_daemon_run(ev, sockd, NULL, false, false, -1);
	assert(ret == 0);

	talloc_free(mem_ctx);
}

/*
 * test2
 *
 * Start daemon, check PID file, sock daemon functions, termination,
 * exit code
 */

static int test2_startup(void *private_data)
{
	int fd = *(int *)private_data;
	int ret = 1;
	ssize_t nwritten;

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
	return 0;
}

static int test2_reconfigure(void *private_data)
{
	static bool first_time = true;
	int fd = *(int *)private_data;
	int ret = 2;
	ssize_t nwritten;

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));

	if (first_time) {
		first_time = false;
		return 1;
	}

	return 0;
}

struct test2_reconfigure_state {
	int fd;
};

static struct tevent_req *test2_reconfigure_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 void *private_data)
{
	struct tevent_req *req;
	struct test2_reconfigure_state *state;
	static bool first_time = true;

	req = tevent_req_create(mem_ctx, &state,
				struct test2_reconfigure_state);
	if (req == NULL) {
		return NULL;
	}

	state->fd = *(int *)private_data;

	if (first_time) {
		first_time = false;
		tevent_req_error(req, 2);
	} else {
		tevent_req_done(req);
	}

	return tevent_req_post(req, ev);
}

static bool test2_reconfigure_recv(struct tevent_req *req, int *perr)
{
	struct test2_reconfigure_state *state = tevent_req_data(
		req, struct test2_reconfigure_state);
	int ret = 2;
	ssize_t nwritten;

	nwritten = write(state->fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));

	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

static void test2_shutdown(void *private_data)
{
	int fd = *(int *)private_data;
	int ret = 3;
	ssize_t nwritten;

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
}

struct test2_shutdown_state {
	int fd;
};

static struct tevent_req *test2_shutdown_send(TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      void *private_data)
{
	struct tevent_req *req;
	struct test2_shutdown_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct test2_shutdown_state);
	if (req == NULL) {
		return NULL;
	}

	state->fd = *(int *)private_data;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void test2_shutdown_recv(struct tevent_req *req)
{
	struct test2_shutdown_state *state = tevent_req_data(
		req, struct test2_shutdown_state);
	int ret = 3;
	ssize_t nwritten;

	nwritten = write(state->fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
}

static void test2(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	struct stat st;
	int fd[2];
	pid_t pid, pid2;
	int ret;
	ssize_t n;
	int pidfile_fd;
	char pidstr[20] = { 0 };

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		struct tevent_context *ev;
		struct sock_daemon_context *sockd;
		struct sock_daemon_funcs test2_funcs = {
			.startup = test2_startup,
			.reconfigure = test2_reconfigure,
			.shutdown = test2_shutdown,
		};

		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test2", "file:", "NOTICE",
					&test2_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &dummy_socket_funcs, NULL);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	pidfile_fd = open(pidfile, O_RDONLY, 0644);
	assert(pidfile_fd != -1);
	ret = fstat(pidfile_fd, &st);
	assert(ret == 0);
	assert(S_ISREG(st.st_mode));
	n = read(pidfile_fd, pidstr, sizeof(pidstr)-1);
	assert(n != -1);
	pid2 = (pid_t)atoi(pidstr);
	assert(pid == pid2);
	close(pidfile_fd);

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

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		struct tevent_context *ev;
		struct sock_daemon_context *sockd;
		struct sock_daemon_funcs test2_funcs = {
			.startup = test2_startup,
			.reconfigure_send = test2_reconfigure_send,
			.reconfigure_recv = test2_reconfigure_recv,
			.shutdown_send = test2_shutdown_send,
			.shutdown_recv = test2_shutdown_recv,
		};

		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test2", "file:", "NOTICE",
					&test2_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &dummy_socket_funcs, NULL);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	ret = kill(pid, SIGUSR1);
	assert(ret == 0);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 2);

	ret = kill(pid, SIGHUP);
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
}

/*
 * test3
 *
 * Start daemon, test watching of (parent) PID
 */

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
					NULL, NULL, &sockd);
		assert(ret == 0);

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &dummy_socket_funcs, NULL);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, NULL, false, false, pid_watch);
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

/*
 * test4
 *
 * Start daemon, test termination via wait_send function
 */

struct test4_wait_state {
};

static void test4_wait_done(struct tevent_req *subreq);

static struct tevent_req *test4_wait_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  void *private_data)
{
	struct tevent_req *req, *subreq;
	struct test4_wait_state *state;

	req = tevent_req_create(mem_ctx, &state, struct test4_wait_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = tevent_wakeup_send(state, ev,
				    tevent_timeval_current_ofs(10,0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, test4_wait_done, req);

	return req;
}

static void test4_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);

	if (! status) {
		tevent_req_error(req, EIO);
	} else {
		tevent_req_done(req);
	}
}

static bool test4_wait_recv(struct tevent_req *req, int *perr)
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

static struct sock_daemon_funcs test4_funcs = {
	.wait_send = test4_wait_send,
	.wait_recv = test4_wait_recv,
};

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

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test4", "file:", "NOTICE",
					&test4_funcs, NULL, &sockd);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, -1);
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

/*
 * test5
 *
 * Start daemon, multiple client connects, requests, disconnects
 */

#define TEST5_VALID_CLIENTS	10
#define TEST5_MAX_CLIENTS	100

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

static int test5_client(const char *sockpath, int id, pid_t pid_server,
			pid_t *client_pid)
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

		close(fd[1]);
		state.fd = -1;

		while (kill(pid_server, 0) == 0 || errno != ESRCH) {
			sleep(1);
		}
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

	*client_pid = pid;
	return ret;
}

struct test5_server_state {
	int num_clients;
};

static bool test5_connect(struct sock_client_context *client,
			  pid_t pid,
			  void *private_data)
{
	struct test5_server_state *state =
		(struct test5_server_state *)private_data;

	if (state->num_clients == TEST5_VALID_CLIENTS) {
		return false;
	}

	state->num_clients += 1;
	assert(state->num_clients <= TEST5_VALID_CLIENTS);
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

struct test5_wait_state {
};

static struct tevent_req *test5_wait_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  void *private_data)
{
	struct tevent_req *req;
	struct test5_wait_state *state;
	int fd = *(int *)private_data;
	int ret = 1;
	ssize_t nwritten;

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
	close(fd);

	req = tevent_req_create(mem_ctx, &state, struct test5_wait_state);
	if (req == NULL) {
		return NULL;
	}

	return req;
}

static bool test5_wait_recv(struct tevent_req *req, int *perr)
{
	return true;
}

static struct sock_daemon_funcs test5_funcs = {
	.wait_send = test5_wait_send,
	.wait_recv = test5_wait_recv,
};

static void test5(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	pid_t pid_server, pid;
	int fd[2], ret, i;
	ssize_t n;
	pid_t client_pid[TEST5_MAX_CLIENTS];

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
					&test5_funcs, &fd[1], &sockd);
		assert(ret == 0);

		state.num_clients = 0;

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &test5_client_funcs, &state);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, pid);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	close(fd[0]);

	for (i=0; i<TEST5_MAX_CLIENTS; i++) {
		ret = test5_client(sockpath, i, pid_server, &client_pid[i]);
		if (i < TEST5_VALID_CLIENTS) {
			assert(ret == i+1);
		} else {
			assert(ret == 0);
		}
	}

	for (i=TEST5_MAX_CLIENTS-1; i>=0; i--) {
		kill(client_pid[i], SIGKILL);

		pid = wait(&ret);
		assert(pid != -1);
	}

	ret = kill(pid_server, SIGTERM);
	assert(ret == 0);

	pid = waitpid(pid_server, &ret, 0);
	assert(pid == pid_server);
	assert(WEXITSTATUS(ret) == 0);
}

/*
 * test6
 *
 * Start daemon, test client connects, requests, replies, disconnects
 */

struct test6_pkt {
	uint32_t len;
	uint32_t data;
};

struct test6_client_state {
	bool done;
};

static void test6_client_callback(uint8_t *buf, size_t buflen,
				  void *private_data)
{
	struct test6_client_state *state =
		(struct test6_client_state *)private_data;
	struct test6_pkt *pkt;

	assert(buflen == sizeof(struct test6_pkt));
	pkt = (struct test6_pkt *)buf;
	assert(pkt->len == sizeof(struct test6_pkt));
	assert(pkt->data == 0xffeeddcc);

	state->done = true;
}

static void test6_client(const char *sockpath)
{
	struct tevent_context *ev;
	struct test6_client_state state;
	struct sock_queue *queue;
	struct test6_pkt pkt;
	int conn, ret;

	ev = tevent_context_init(NULL);
	assert(ev != NULL);

	conn = sock_connect(sockpath);
	assert(conn != -1);

	state.done = false;

	queue = sock_queue_setup(ev, ev, conn,
				 test6_client_callback, &state);
	assert(queue != NULL);

	pkt.len = 8;
	pkt.data = 0xaabbccdd;

	ret = sock_queue_write(queue, (uint8_t *)&pkt,
			       sizeof(struct test6_pkt));
	assert(ret == 0);

	while (! state.done) {
		tevent_loop_once(ev);
	}

	talloc_free(ev);
}

struct test6_server_state {
	struct sock_daemon_context *sockd;
	int fd, done;
};

struct test6_read_state {
	struct test6_server_state *server_state;
	struct test6_pkt reply;
};

static void test6_read_done(struct tevent_req *subreq);

static struct tevent_req *test6_read_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct sock_client_context *client,
					  uint8_t *buf, size_t buflen,
					  void *private_data)
{
	struct test6_server_state *server_state =
		(struct test6_server_state *)private_data;
	struct tevent_req *req, *subreq;
	struct test6_read_state *state;
	struct test6_pkt *pkt;

	req = tevent_req_create(mem_ctx, &state, struct test6_read_state);
	assert(req != NULL);

	state->server_state = server_state;

	assert(buflen == sizeof(struct test6_pkt));

	pkt = (struct test6_pkt *)buf;
	assert(pkt->data == 0xaabbccdd);

	state->reply.len = sizeof(struct test6_pkt);
	state->reply.data = 0xffeeddcc;

	subreq = sock_socket_write_send(state, ev, client,
					(uint8_t *)&state->reply,
					state->reply.len);
	assert(subreq != NULL);

	tevent_req_set_callback(subreq, test6_read_done, req);

	return req;
}

static void test6_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct test6_read_state *state = tevent_req_data(
		req, struct test6_read_state);
	int ret;
	bool status;

	status = sock_socket_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	state->server_state->done = 1;
	tevent_req_done(req);
}

static bool test6_read_recv(struct tevent_req *req, int *perr)
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

static struct sock_socket_funcs test6_client_funcs = {
	.read_send = test6_read_send,
	.read_recv = test6_read_recv,
};

struct test6_wait_state {
	struct test6_server_state *server_state;
};

static void test6_wait_done(struct tevent_req *subreq);

static struct tevent_req *test6_wait_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  void *private_data)
{
	struct test6_server_state *server_state =
		(struct test6_server_state *)private_data;
	struct tevent_req *req, *subreq;
	struct test6_wait_state *state;
	ssize_t nwritten;
	int ret = 1;

	nwritten = write(server_state->fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
	close(server_state->fd);
	server_state->fd = -1;

	req = tevent_req_create(mem_ctx, &state, struct test6_wait_state);
	if (req == NULL) {
		return NULL;
	}

	state->server_state = (struct test6_server_state *)private_data;

	subreq = tevent_wakeup_send(state, ev,
				    tevent_timeval_current_ofs(10,0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, test6_wait_done, req);

	return req;
}

static void test6_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct test6_wait_state *state = tevent_req_data(
		req, struct test6_wait_state);
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	if (state->server_state->done == 0) {
		tevent_req_error(req, EIO);
		return;
	}

	tevent_req_done(req);
}

static bool test6_wait_recv(struct tevent_req *req, int *perr)
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

static struct sock_daemon_funcs test6_funcs = {
	.wait_send = test6_wait_send,
	.wait_recv = test6_wait_recv,
};

static void test6(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	pid_t pid_server, pid;
	int fd[2], ret;
	ssize_t n;

	pid = getpid();

	ret = pipe(fd);
	assert(ret == 0);

	pid_server = fork();
	assert(pid_server != -1);

	if (pid_server == 0) {
		struct tevent_context *ev;
		struct sock_daemon_context *sockd;
		struct test6_server_state server_state = { 0 };

		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		server_state.fd = fd[1];

		ret = sock_daemon_setup(mem_ctx, "test6", "file:", "NOTICE",
					&test6_funcs, &server_state,
					&sockd);
		assert(ret == 0);

		server_state.sockd = sockd;
		server_state.done = 0;

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &test6_client_funcs, &server_state);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, pid);
		assert(ret == 0);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	close(fd[0]);

	test6_client(sockpath);

	pid = waitpid(pid_server, &ret, 0);
	assert(pid == pid_server);
	assert(WEXITSTATUS(ret) == 0);
}

/*
 * test7
 *
 * Start daemon twice, confirm PID file contention
 */

static void test7(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	struct sock_daemon_funcs test7_funcs;
	struct stat st;
	int fd[2];
	pid_t pid, pid2;
	int ret;
	struct tevent_context *ev;
	struct sock_daemon_context *sockd;
	ssize_t n;

	/* Reuse test2 funcs for the startup synchronisation */
	test7_funcs = (struct sock_daemon_funcs) {
		.startup = test2_startup,
		.reconfigure = test2_reconfigure,
		.shutdown = test2_shutdown,
	};

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test7", "file:", "NOTICE",
					&test7_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	ret = stat(pidfile, &st);
	assert(ret == 0);
	assert(S_ISREG(st.st_mode));

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	ret = sock_daemon_setup(mem_ctx, "test7-parent", "file:", "NOTICE",
				&test7_funcs, &fd[1], &sockd);
	assert(ret == 0);

	ret = sock_daemon_run(ev, sockd, pidfile, false, false, -1);
	assert(ret == EEXIST);

	ret = kill(pid, SIGTERM);
	assert(ret == 0);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 3);

	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);
	assert(WEXITSTATUS(ret) == 0);

	close(fd[0]);
}

/*
 * test8
 *
 * Start daemon, confirm that create_session argument works as expected
 */

static void test8(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	int fd[2];
	pid_t pid, pid2, sid;
	int ret;
	struct tevent_context *ev;
	struct sock_daemon_context *sockd;
	ssize_t n;

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		/* Reuse test2 funcs for the startup synchronisation */
		struct sock_daemon_funcs test8_funcs = {
			.startup = test2_startup,
		};

		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test8", "file:", "NOTICE",
					&test8_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	/* create_session false above, so pid != sid */
	sid = getsid(pid);
	assert(pid != sid);

	ret = kill(pid, SIGTERM);
	assert(ret == 0);

	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);
	assert(WEXITSTATUS(ret) == 0);

	close(fd[0]);

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		/* Reuse test2 funcs for the startup synchronisation */
		struct sock_daemon_funcs test8_funcs = {
			.startup = test2_startup,
		};

		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test8", "file:", "NOTICE",
					&test8_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, true, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	/* create_session true above, so pid == sid */
	sid = getsid(pid);
	assert(pid == sid);

	ret = kill(pid, SIGTERM);
	assert(ret == 0);

	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);
	assert(WEXITSTATUS(ret) == 0);

	close(fd[0]);
}

/*
 * test9
 *
 * Confirm that do_fork causes the daemon to be forked as a separate child
 */

static void test9(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	int fd[2];
	pid_t pid, pid2;
	int ret;
	struct tevent_context *ev;
	struct sock_daemon_context *sockd;
	ssize_t n;
	int pidfile_fd;
	char pidstr[20] = { 0 };
	struct stat st;

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		/* Reuse test2 funcs for the startup synchronisation */
		struct sock_daemon_funcs test9_funcs = {
			.startup = test2_startup,
		};

		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test9", "file:", "NOTICE",
					&test9_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	/* do_fork false above, so pid should be active */
	ret = kill(pid, 0);
	assert(ret == 0);

	ret = kill(pid, SIGTERM);
	assert(ret == 0);

	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);
	assert(WEXITSTATUS(ret) == 0);

	close(fd[0]);

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		/* Reuse test2 funcs for the startup synchronisation */
		struct sock_daemon_funcs test9_funcs = {
			.startup = test2_startup,
			.shutdown = test2_shutdown,
		};

		close(fd[0]);

		ev = tevent_context_init(mem_ctx);
		assert(ev != NULL);

		ret = sock_daemon_setup(mem_ctx, "test9", "file:", "NOTICE",
					&test9_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, true, false, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	/* do_fork true above, so pid should have exited */
	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);
	assert(WEXITSTATUS(ret) == 0);

	pidfile_fd = open(pidfile, O_RDONLY, 0644);
	assert(pidfile_fd != -1);
	n = read(pidfile_fd, pidstr, sizeof(pidstr)-1);
	assert(n != -1);
	pid2 = (pid_t)atoi(pidstr);
	assert(pid != pid2);
	close(pidfile_fd);

	ret = kill(pid2, SIGTERM);
	assert(ret == 0);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 3);

	/*
	 * pid2 isn't our child, so can't call waitpid().  kill(pid2, 0)
	 * is unreliable - pid2 may have been recycled.  Above indicates
	 * that the shutdown function was called, so just do 1 final
	 * check to see if pidfile has been removed.
	 */
	ret = stat(sockpath, &st);
	assert(ret == -1);

	close(fd[0]);
}

static void test10_shutdown(void *private_data)
{
	int fd = *(int *)private_data;
	int ret = 3;
	ssize_t nwritten;

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));
}

struct test10_wait_state {
};

static void test10_wait_done(struct tevent_req *subreq);

static struct tevent_req *test10_wait_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   void *private_data)
{
	int fd = *(int *)private_data;
	struct tevent_req *req, *subreq;
	struct test10_wait_state *state;
	size_t nwritten;
	int ret = 1;

	req = tevent_req_create(mem_ctx, &state, struct test10_wait_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = tevent_wakeup_send(state, ev,
				    tevent_timeval_current_ofs(10, 0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, test10_wait_done, req);

	nwritten = write(fd, &ret, sizeof(ret));
	assert(nwritten == sizeof(ret));

	return req;
}

static void test10_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;

	status = tevent_wakeup_recv(subreq);
	if (! status) {
		tevent_req_error(req, EIO);
		return;
	}

	tevent_req_done(req);
}

static bool test10_wait_recv(struct tevent_req *req, int *perr)
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

static struct sock_daemon_funcs test10_funcs = {
	.shutdown = test10_shutdown,
	.wait_send = test10_wait_send,
	.wait_recv = test10_wait_recv,
};

/*
 * test10
 *
 * Confirm that the daemon starts successfully if there is a stale socket
 */

static void test10(TALLOC_CTX *mem_ctx, const char *pidfile,
		  const char *sockpath)
{
	struct stat st;
	int fd[2];
	pid_t pid, pid2;
	int ret;
	ssize_t n;
	int pidfile_fd;
	char pidstr[20] = { 0 };

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

		ret = sock_daemon_setup(mem_ctx, "test10", "file:", "NOTICE",
					&test10_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &dummy_socket_funcs, NULL);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	/* KILL will leave PID file and socket behind */
	ret = kill (pid, SIGKILL);
	assert(ret == 0);

	pid2 = waitpid(pid, &ret, 0);
	assert(pid2 == pid);
	assert(WEXITSTATUS(ret) == 0);

	ret = stat(sockpath, &st);
	assert(ret == 0);

	close(fd[0]);

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

		ret = sock_daemon_setup(mem_ctx, "test10", "file:", "NOTICE",
					&test10_funcs, &fd[1], &sockd);
		assert(ret == 0);

		ret = sock_daemon_add_unix(sockd, sockpath,
					   &dummy_socket_funcs, NULL);
		assert(ret == 0);

		ret = sock_daemon_run(ev, sockd, pidfile, false, false, -1);
		assert(ret == EINTR);

		exit(0);
	}

	close(fd[1]);

	n = read(fd[0], &ret, sizeof(ret));
	assert(n == sizeof(ret));
	assert(ret == 1);

	pidfile_fd = open(pidfile, O_RDONLY, 0644);
	assert(pidfile_fd != -1);
	n = read(pidfile_fd, pidstr, sizeof(pidstr)-1);
	assert(n != -1);
	pid2 = (pid_t)atoi(pidstr);
	assert(pid == pid2);
	close(pidfile_fd);

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

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	const char *pidfile, *sockpath;
	int num;

	if (argc != 4) {
		fprintf(stderr, "%s <pidfile> <sockpath> <testnum>\n", argv[0]);
		exit(1);
	}

	pidfile = argv[1];
	sockpath = argv[2];
	num = atoi(argv[3]);

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	switch (num) {
	case 1:
		test1(mem_ctx, pidfile, sockpath);
		break;

	case 2:
		test2(mem_ctx, pidfile, sockpath);
		break;

	case 3:
		test3(mem_ctx, pidfile, sockpath);
		break;

	case 4:
		test4(mem_ctx, pidfile, sockpath);
		break;

	case 5:
		test5(mem_ctx, pidfile, sockpath);
		break;

	case 6:
		test6(mem_ctx, pidfile, sockpath);
		break;

	case 7:
		test7(mem_ctx, pidfile, sockpath);
		break;

	case 8:
		test8(mem_ctx, pidfile, sockpath);
		break;

	case 9:
		test9(mem_ctx, pidfile, sockpath);
		break;

	case 10:
		test10(mem_ctx, pidfile, sockpath);
		break;

	default:
		fprintf(stderr, "Unknown test number %d\n", num);
	}

	return 0;
}
