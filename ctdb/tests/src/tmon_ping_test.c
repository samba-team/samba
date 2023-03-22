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
#include "system/network.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>
#include <assert.h>

#include "lib/util/tevent_unix.h"

#include "common/tmon.h"

#include "tests/src/test_backtrace.h"

struct test_state {
	const char *label;
	unsigned long async_wait_time;
	unsigned long blocking_sleep_time;
};

static void test_tmon_ping_done(struct tevent_req *subreq);
static void test_async_wait_done(struct tevent_req *subreq);

static struct tevent_req *test_send(TALLOC_CTX *mem_ctx,
				    struct tevent_context *ev,
				    const char *label,
				    int fd,
				    int direction,
				    unsigned long timeout,
				    unsigned long interval,
				    unsigned long async_wait_time,
				    unsigned long blocking_sleep_time)
{
	struct tevent_req *req, *subreq;
	struct test_state *state;

	req = tevent_req_create(mem_ctx, &state, struct test_state);
	if (req == NULL) {
		return NULL;
	}

	state->label = label;
	state->async_wait_time = async_wait_time;
	state->blocking_sleep_time = blocking_sleep_time;

	subreq = tmon_ping_send(state,
				ev,
				fd,
				direction,
				timeout,
				interval);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, test_tmon_ping_done, req);

	if (state->async_wait_time != 0) {
		fprintf(stderr,
			"%s: async wait start %lu\n",
			state->label,
			state->async_wait_time);
	}
	subreq = tevent_wakeup_send(state,
				    ev,
				    tevent_timeval_current_ofs(
					    (uint32_t)async_wait_time, 0));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, test_async_wait_done, req);

	return req;
}

static void test_tmon_ping_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct test_state *state = tevent_req_data(req, struct test_state);
	bool status;
	int err;

	status = tmon_ping_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (!status) {
		switch(err) {
		case EPIPE:
			fprintf(stderr, "%s: pipe closed\n", state->label);
			break;
		case ETIMEDOUT:
			fprintf(stderr, "%s: ping timeout\n", state->label);
			break;
		default:
			fprintf(stderr, "%s: error (%d)\n", state->label, err);
		}
		tevent_req_error(req, err);
		return;
	}

	fprintf(stderr, "%s: done\n", state->label);
	tevent_req_done(req);
}

static void test_async_wait_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct test_state *state = tevent_req_data(req, struct test_state);
	unsigned int left;
	bool status;

	status = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!status) {
		fprintf(stderr,
			"%s: tevent_wakeup_recv() failed\n",
			state->label);
		/* Ignore error */
	}
	if (state->async_wait_time != 0) {
		fprintf(stderr, "%s: async wait end\n", state->label);
	}

	if (state->blocking_sleep_time == 0) {
		goto done;
	}

	fprintf(stderr,
		"%s: blocking sleep start %lu\n",
		state->label,
		state->blocking_sleep_time);
	left = sleep((unsigned int)state->blocking_sleep_time);
	fprintf(stderr,
		"%s: blocking sleep end\n",
		state->label);
	if (left != 0) {
		tevent_req_error(req, EINTR);
		return;
	}

done:
	tevent_req_done(req);
}

static bool test_recv(struct tevent_req *req, int *perr)
{
	if (tevent_req_is_unix_error(req, perr)) {
		return false;
	}

	return true;
}

static int test_one(bool is_parent,
		    int sync_fd,
		    int fd,
		    int direction,
		    unsigned long timeout,
		    unsigned long interval,
		    unsigned long async_wait_time,
		    unsigned long blocking_sleep_time)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct tevent_req *req;
	bool status;
	char buf[1] = "";
	ssize_t count;
	int err;
	int ret;

	if (!is_parent) {
		count = read(sync_fd, buf, sizeof(buf));
		assert(count == 1);
		assert(buf[0] == '\0');
		close(sync_fd);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		ret = ENOMEM;
		goto done;
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		ret = ENOMEM;
		goto done;
	}

	req = test_send(mem_ctx,
			ev,
			is_parent ? "parent" : "child",
			fd,
			direction,
			timeout,
			interval,
			async_wait_time,
			blocking_sleep_time);
	if (req == NULL) {
		ret = ENOMEM;
		goto done;
	}

	if (is_parent) {
		count = write(sync_fd, buf, sizeof(buf));
		assert(count == 1);
	}

	status = tevent_req_poll(req, ev);
	if (!status) {
		ret = EIO;
		goto done;
	}

	status = test_recv(req, &err);
	ret = status ? 0 : err;

done:
	return ret;
}

static void test(unsigned long parent_timeout,
		 unsigned long parent_interval,
		 unsigned long parent_async_wait_time,
		 unsigned long parent_blocking_sleep_time,
		 int parent_result,
		 unsigned long child_timeout,
		 unsigned long child_interval,
		 unsigned long child_async_wait_time,
		 unsigned long child_blocking_sleep_time,
		 int child_result)
{
	int sync[2];
	int fd[2];
	pid_t pid;
	int wstatus;
	int ret;

	/* Pipe for synchronisation */
	ret = pipe(sync);
	assert(ret == 0);

	ret = socketpair(AF_UNIX, SOCK_STREAM, 0, fd);
	assert(ret == 0);

	pid = fork();
	assert(pid != -1);

	if (pid == 0) {
		/* child */
		close(sync[1]);
		close(fd[0]);

		ret = test_one(false,
			       sync[0],
			       fd[1],
			       TMON_FD_BOTH,
			       child_timeout,
			       child_interval,
			       child_async_wait_time,
			       child_blocking_sleep_time);
		_exit(ret);
	}

	/* Parent */
	close(sync[0]);
	close(fd[1]);

	ret = test_one(true,
		       sync[1],
		       fd[0],
		       TMON_FD_BOTH,
		       parent_timeout,
		       parent_interval,
		       parent_async_wait_time,
		       parent_blocking_sleep_time);
	assert(ret == parent_result);

	/* Close to mimic exit, so child status can be checked below */
	close(fd[0]);

	/* Abort if child failed */
	waitpid(pid, &wstatus, 0);
	if (WIFEXITED(wstatus)) {
		assert(WEXITSTATUS(wstatus) == child_result);
	}
}

struct test_inputs {
	unsigned int timeout;
	unsigned int interval;
	unsigned int async_wait_time;
	unsigned int blocking_sleep_time;
	int expected_result;
};

static void get_test_inputs(const char **args, struct test_inputs *inputs)
{
	if (strcmp(args[0], "false") == 0) {
		inputs->interval = 0;
	} else if (strcmp(args[0], "true") == 0) {
		inputs->interval = 1;
	} else {
		inputs->interval = strtoul(args[0], NULL, 0);
	}

	inputs->timeout = strtoul(args[1], NULL, 0);
	inputs->async_wait_time = (unsigned int)strtoul(args[2], NULL, 0);
	inputs->blocking_sleep_time = (unsigned int)strtoul(args[3], NULL, 0);
	inputs->expected_result = (int)strtoul(args[4], NULL, 0);
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s "
		"\\\n\t"
		"<parent_send_pings> "
		"<parent_ping_timeout> "
		"<parent_async_wait_time> "
		"<parent_blocking_sleep_time> "
		"<parent_expected_result> "
		"\\\n\t"
		"<child_send_pings> "
		"<child_ping_timeout> "
		"<child_async_wait_time> "
		"<child_blocking_sleep_time> "
		"<child_expected_result> "
		"\n",
		prog);
	exit(1);
}

int main(int argc, const char **argv)
{
	struct test_inputs parent;
	struct test_inputs child;

	if (argc != 11) {
		usage(argv[0]);
	}

	test_backtrace_setup();

	get_test_inputs(&argv[1], &parent);
	get_test_inputs(&argv[6], &child);

	test(parent.timeout,
	     parent.interval,
	     parent.async_wait_time,
	     parent.blocking_sleep_time,
	     parent.expected_result,
	     child.timeout,
	     child.interval,
	     child.async_wait_time,
	     child.blocking_sleep_time,
	     child.expected_result);

	return 0;
}
