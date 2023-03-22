/*
   Test trivial FD monitoring

   Copyright (C) Martin Schwenke, DataDirect Networks  2022

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
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>
#include <assert.h>
#include <ctype.h>

#include "lib/util/tevent_unix.h"

#include "common/tmon.h"

#include "tests/src/test_backtrace.h"

struct test_write_state {
	const char *write_data;
	size_t write_data_len;
	unsigned int offset;
	struct tevent_req *req;
};

static int test_write_callback(void *private_data, struct tmon_pkt *pkt)
{
	struct test_write_state *state = talloc_get_type_abort(
		private_data, struct test_write_state);
	bool status;
	size_t len;
	char *end;
	int err;
	char c;
	const char *t;

	assert(state->write_data != NULL);

	len = strlen(state->write_data);
	if (state->offset >= len) {
		return TMON_STATUS_EXIT;
	}

	c = state->write_data[state->offset];
	state->offset++;

	if (isdigit(c)) {
		err = c - '0';

		if (err == 0) {
			status = tmon_set_exit(pkt);
		} else {
			status = tmon_set_errno(pkt, err);
		}
	} else if (ispunct(c)) {
		switch (c) {
		case '.':
			return TMON_STATUS_SKIP;
			break;
		case '!':
			status = tmon_set_ping(pkt);
			break;
		case '#':
			/* Additional errno syntax: #nnn[;] */
			t = &state->write_data[state->offset];
			err = (int)strtol(t, &end, 10);
			state->offset += (end - t);
			if (state->write_data[state->offset] == ';') {
				state->offset++;
			}
			status = tmon_set_errno(pkt, err);
			break;
		default:
			status = false;
		}
	} else if (isascii(c) && !isspace(c)) {
		status = tmon_set_ascii(pkt, c);
	} else {
		status = tmon_set_custom(pkt, (uint16_t)c);
	}

	if (!status) {
		return EDOM;
	}

	t = getenv("CTDB_TEST_TMON_WRITE_SKIP_MODE");
	if (t == NULL) {
		return 0;
	}

	/*
	 * This is write-skip mode: tmon_write() is called directly
	 * here in the callback and TMON_WRITE_SKIP is returned.  This
	 * allows tmon_write() to be exercised by reusing test cases
	 * rather than writing extra test code and test cases.
	 */

	status = tmon_write(state->req, pkt);
	if (!status) {
		return EIO;
	}

	return TMON_STATUS_SKIP;
}

static void test_tmon_done(struct tevent_req *subreq);

static struct tevent_req *test_write_send(TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  int fd,
					  const char *write_data)
{
	struct tevent_req *req, *subreq;
	struct test_write_state *state;
	struct tmon_actions actions = {
		.write_callback = test_write_callback,
	};

	req = tevent_req_create(mem_ctx, &state, struct test_write_state);
	if (req == NULL) {
		return NULL;
	}

	state->write_data = write_data;
	state->offset = 0;

	subreq = tmon_send(state,
			   ev,
			   fd,
			   TMON_FD_WRITE,
			   0,
			   1,
			   &actions,
			   state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, test_tmon_done, req);

	/* Nasty hack, but OK to cheapen testing - see test_write_callback() */
	state->req = subreq;

	return req;
}

static void test_tmon_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	bool status;
	int err;

	status = tmon_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!status) {
		tevent_req_error(req, err);
		return;
	}

	tevent_req_done(req);
}

static bool test_write_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

static int test_timeout_ok_callback(void *private_data)
{
	return 0;
}

static int test_read_callback(void *private_data, struct tmon_pkt *pkt)
{
	bool status;
	char c;
	uint16_t val;

	status = tmon_parse_ping(pkt);
	if (status) {
		printf("PING\n");
		fflush(stdout);
		return 0;
	}

	status = tmon_parse_ascii(pkt, &c);
	if (status) {
		printf("ASCII %c\n", c);
		fflush(stdout);
		return 0;
	}

	status = tmon_parse_custom(pkt, &val);
	if (status) {
		printf("CUSTOM 0x%"PRIx16"\n", val);
		fflush(stdout);
		return 0;
	}

	return 0;
}

static int test_close_ok_callback(void *private_data)
{
	return 0;
}

struct test_read_state {
};

static struct tevent_req *test_read_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 int fd,
					 bool close_ok,
					 unsigned long timeout,
					 bool timeout_ok)
{
	struct tevent_req *req, *subreq;
	struct test_read_state *state;
	struct tmon_actions actions = {
		.read_callback = test_read_callback,
	};

	req = tevent_req_create(mem_ctx, &state, struct test_read_state);
	if (req == NULL) {
		return NULL;
	}

	if (timeout_ok) {
		actions.timeout_callback = test_timeout_ok_callback;
	}
	if (close_ok) {
		actions.close_callback = test_close_ok_callback;
	}

	subreq = tmon_send(state,
			   ev,
			   fd,
			   TMON_FD_READ,
			   timeout,
			   0,
			   &actions,
			   state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, test_tmon_done, req);

	return req;
}

static bool test_read_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

static void test(const char *write_data,
		 bool close_ok,
		 unsigned long timeout,
		 bool timeout_ok)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct tevent_req *req;
	int fd[2];
	pid_t pid;
	int wstatus;
	bool status;
	int err;
	int ret;

	mem_ctx = talloc_new(NULL);
	assert(mem_ctx != NULL);

	ev = tevent_context_init(mem_ctx);
	assert(ev != NULL);

	ret = pipe(fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		/* child */
		close(fd[1]);

		req = test_read_send(mem_ctx,
				     ev,
				     fd[0],
				     close_ok,
				     timeout,
				     timeout_ok);
		assert(req != NULL);

		status = tevent_req_poll(req, ev);
		assert(status);

		status = test_read_recv(req, &err);
		if (status) {
			err = 0;
			printf("READER OK\n");
		} else {
			printf("READER ERR=%d\n", err);
		}
		fflush(stdout);

		_exit(ret);
	}

	/* Parent */
	close(fd[0]);

	req = test_write_send(mem_ctx,
			      ev,
			      fd[1],
			      write_data);
	assert(req != NULL);

	status = tevent_req_poll(req, ev);
	assert(status);

	status = test_write_recv(req, &err);
	if (status) {
		err = 0;
		printf("WRITER OK\n");
	} else {
		printf("WRITER ERR=%d\n", err);
	}
	fflush(stdout);

	/* Close to mimic exit, so child status can be checked below */
	close(fd[1]);

	waitpid(pid, &wstatus, 0);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s <write_data> <close_ok> <timeout> <timeout_ok>\n\n"
		"  <write_data> is processed by test_write_callback(), "
		"1 character per second:\n"
		"                0: write EXIT\n"
		"              1-9: write ERRNO 1-9\n"
		"                .: skip write\n"
		"          <space>: write CUSTOM containing <space>\n"
		"    other <ascii>: write ASCII containing <ascii>\n"
		"            other: write CUSTOM\n"
		"  See test_write_callback() for more details\n"
		,
		prog);
	exit(1);
}

int main(int argc, const char **argv)
{
	bool close_ok, timeout_ok;
	unsigned long timeout;

	if (argc != 5) {
		usage(argv[0]);
	}

	test_backtrace_setup();

	close_ok = (strcmp(argv[2], "true") == 0);
	timeout = strtoul(argv[3], NULL, 0);
	if (timeout == 0) {
		/*
		 * Default timeout that should not come into play but
		 * will cause tests to fail after a reasonable amount
		 * of time, if something unexpected happens.
		 */
		timeout = 20;
	}
	timeout_ok = (strcmp(argv[4], "true") == 0);

	test(argv[1], close_ok, timeout, timeout_ok);

	return 0;
}
