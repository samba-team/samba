/*
   sock I/O tests

   Copyright (C) Amitay Isaacs  2017

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

#include "common/sock_io.c"

static int socket_init(const char *sockpath)
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

static void test1_writer(int fd)
{
	uint8_t buf[1024];
	ssize_t nwritten;
	uint32_t len;

	for (len = 10; len < 1000; len += 10) {
		int value = len / 10;
		uint32_t buflen = len + sizeof(uint32_t);

		memset(buf,  value, buflen);
		memcpy(buf, &buflen, sizeof(uint32_t));

		nwritten = sys_write(fd, buf, buflen);
		assert(nwritten == buflen);
	}
}

struct test1_reader_state {
	size_t pkt_len;
	bool done;
};

static void test1_reader(uint8_t *buf, size_t buflen, void *private_data)
{
	struct test1_reader_state *state =
		(struct test1_reader_state *)private_data;

	if (buflen == 0) {
		state->done = true;
		return;
	}

	assert(buflen == state->pkt_len);

	state->pkt_len += 10;
}

static void test1(TALLOC_CTX *mem_ctx, const char *sockpath)
{
	struct test1_reader_state state;
	struct tevent_context *ev;
	struct sock_queue *queue;
	pid_t pid;
	int pfd[2], fd, ret;
	ssize_t n;

	ret = pipe(pfd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		int newfd;

		close(pfd[0]);

		fd = socket_init(sockpath);
		assert(fd != -1);

		ret = 1;
		n = sys_write(pfd[1], &ret, sizeof(int));
		assert(n == sizeof(int));

		newfd = accept(fd, NULL, NULL);
		assert(newfd != -1);

		test1_writer(newfd);
		close(newfd);
		unlink(sockpath);

		exit(0);
	}

	close(pfd[1]);

	n = sys_read(pfd[0], &ret, sizeof(int));
	assert(n == sizeof(int));
	assert(ret == 1);

	close(pfd[0]);

	fd = sock_connect(sockpath);
	assert(fd != -1);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	state.pkt_len = 10 + sizeof(uint32_t);
	state.done = false;

	queue = sock_queue_setup(mem_ctx, ev, fd, test1_reader, &state);
	assert(queue != NULL);

	while (! state.done) {
		tevent_loop_once(ev);
	}

	talloc_free(queue);
	talloc_free(ev);

	pid = wait(&ret);
	assert(pid != -1);
}

static void test2_reader(int fd)
{
	uint8_t buf[1024];
	size_t pkt_len = 10 + sizeof(uint32_t);
	ssize_t n;

	while (1) {
		n = sys_read(fd, buf, 1024);
		assert(n != -1);

		if (n == 0) {
			return;
		}

		assert((size_t)n == pkt_len);
		pkt_len += 10;
	}
}

static void test2_dummy_reader(uint8_t *buf, size_t buflen,
			       void *private_data)
{
	abort();
}

static void test2_writer(struct sock_queue *queue)
{
	uint8_t buf[1024];
	uint32_t len;
	int ret;

	for (len = 10; len < 1000; len += 10) {
		int value = len / 10;
		uint32_t buflen = len + sizeof(uint32_t);

		memset(buf,  value, buflen);
		memcpy(buf, &buflen, sizeof(uint32_t));

		ret = sock_queue_write(queue, buf, buflen);
		assert(ret == 0);
	}
}

static void test2(TALLOC_CTX *mem_ctx, const char *sockpath)
{
	struct tevent_context *ev;
	struct sock_queue *queue;
	pid_t pid;
	int pfd[2], fd, ret;
	ssize_t n;

	ret = pipe(pfd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		int newfd;

		close(pfd[0]);

		fd = socket_init(sockpath);
		assert(fd != -1);

		ret = 1;
		n = sys_write(pfd[1], &ret, sizeof(int));
		assert(n == sizeof(int));

		newfd = accept(fd, NULL, NULL);
		assert(newfd != -1);

		test2_reader(newfd);
		close(newfd);
		unlink(sockpath);

		exit(0);
	}

	close(pfd[1]);

	n = sys_read(pfd[0], &ret, sizeof(int));
	assert(n == sizeof(int));
	assert(ret == 1);

	close(pfd[0]);

	fd = sock_connect(sockpath);
	assert(fd != -1);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	queue = sock_queue_setup(mem_ctx, ev, fd, test2_dummy_reader, NULL);
	assert(queue != NULL);

	test2_writer(queue);

	talloc_free(queue);
	talloc_free(ev);

	pid = wait(&ret);
	assert(pid != -1);
}

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	const char *sockpath;

	if (argc != 2) {
		fprintf(stderr, "%s <sockpath>\n", argv[0]);
		exit(1);
	}

	sockpath = argv[1];

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	test1(mem_ctx, sockpath);
	test2(mem_ctx, sockpath);

	return 0;
}
