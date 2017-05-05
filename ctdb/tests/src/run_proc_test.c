/*
   run_proc test wrapper

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

#include <talloc.h>
#include <tevent.h>

#include "common/db_hash.c"
#include "common/run_proc.c"

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct tevent_req *req;
	struct run_proc_context *run_ctx;
	struct timeval tv;
	char *output;
	struct run_proc_result result;
	pid_t pid;
	int timeout, ret, fd;
	bool status;

	if (argc < 4) {
		fprintf(stderr,
			"Usage: %s <timeout> <stdin-fd> <program> <args>\n",
			argv[0]);
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "talloc_new() failed\n");
		exit(1);
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		fprintf(stderr, "tevent_context_init() failed\n");
		exit(1);
	}

	timeout = atoi(argv[1]);
	if (timeout <= 0) {
		tv = tevent_timeval_zero();
	} else {
		tv = tevent_timeval_current_ofs(timeout, 0);
	}

	fd = atoi(argv[2]);
	if (fd < 0) {
		fd = -1;
	}

	ret = run_proc_init(mem_ctx, ev, &run_ctx);
	if (ret != 0) {
		fprintf(stderr, "run_proc_init() failed, ret=%d\n", ret);
		exit(1);
	}

	req = run_proc_send(mem_ctx, ev, run_ctx, argv[3], &argv[3], fd, tv);
	if (req == NULL) {
		fprintf(stderr, "run_proc_send() failed\n");
		exit(1);
	}

	tevent_req_poll(req, ev);

	status = run_proc_recv(req, &ret, &result, &pid, mem_ctx, &output);
	if (! status) {
		fprintf(stderr, "run_proc_recv() failed, ret=%d\n", ret);
		exit(1);
	}

	if (result.sig > 0) {
		printf("Process exited with signal %d\n", result.sig);
	} else if (result.err > 0) {
		printf("Process exited with error %d\n", result.err);
	} else {
		printf("Process exited with status %d\n", result.status);
	}

	if (pid != -1) {
		printf("Child = %d\n", pid);
	}

	if (output != NULL) {
		printf("Output = (%s)\n", output);
	}

	talloc_free(mem_ctx);

	exit(0);
}
