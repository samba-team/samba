/*
   run_event test wrapper

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

#include <talloc.h>
#include <tevent.h>

#include "common/db_hash.c"
#include "common/run_proc.c"
#include "common/event_script.c"
#include "common/run_event.c"

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s <scriptdir> run|list|enable|disable <options>\n", prog);
	fprintf(stderr, "       %s <scriptdir> run <timeout> <event> [<args>]\n", prog);
	fprintf(stderr, "       %s <scriptdir> list\n", prog);
	fprintf(stderr, "       %s <scriptdir> enable <scriptname>\n", prog);
	fprintf(stderr, "       %s <scriptdir> disable <scriptname>\n", prog);
}

static char *compact_args(const char **argv, int argc, int from)
{
	char *arg_str = NULL;
	int i;

	for (i = from; i < argc; i++) {
		arg_str = talloc_asprintf_append(arg_str, "%s ", argv[i]);
		if (arg_str == NULL) {
			fprintf(stderr, "talloc_asprintf_append() failed\n");
			exit(1);
		}
	}

	return arg_str;
}

static void run_done(struct tevent_req *req)
{
	struct run_event_script_list **script_list =
		tevent_req_callback_data_void(req);
	bool status;
	int ret;

	status = run_event_recv(req, &ret, NULL, script_list);
	if (!status) {
		fprintf(stderr, "run_event_recv() failed, ret=%d\n", ret);
	}
}

static void do_run(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		   struct run_event_context *run_ctx,
		   int argc, const char **argv)
{
	struct tevent_req *req;
	struct timeval timeout;
	struct run_event_script_list *script_list = NULL;
	char *arg_str;
	unsigned int i;
	int t;
	bool wait_for_signal = false;

	if (argc < 5) {
		usage(argv[0]);
		exit(1);
	}

	t = atoi(argv[3]);
	if (t > 0) {
		timeout = tevent_timeval_current_ofs(t, 0);
	} else {
		timeout = tevent_timeval_zero();
	}

	arg_str = compact_args(argv, argc, 5);

	req = run_event_send(mem_ctx,
			     ev,
			     run_ctx,
			     argv[4],
			     arg_str,
			     timeout,
			     false);
	if (req == NULL) {
		fprintf(stderr, "run_event_send() failed\n");
		return;
	}

	tevent_req_set_callback(req, run_done, &script_list);

	tevent_req_poll(req, ev);

	if (script_list == NULL || script_list->num_scripts == 0) {
		printf("No event scripts found\n");
		return;
	}

	printf("Event %s completed with result=%d\n",
	       argv[4], script_list->summary);
	for (i=0; i<script_list->num_scripts; i++) {
		struct run_event_script *s = &script_list->script[i];
		printf("%s result=%d\n", s->name, s->summary);

		if (s->summary == -ETIMEDOUT) {
			wait_for_signal = true;
		}
	}

	TALLOC_FREE(script_list);
	TALLOC_FREE(req);

	if (!wait_for_signal) {
		return;
	}

	req = tevent_wakeup_send(
		ev, ev, tevent_timeval_current_ofs(10, 0));
	if (req == NULL) {
		fprintf(stderr, "Could not wait for signal\n");
		return;
	}

	tevent_req_poll(req, ev);
	TALLOC_FREE(req);
}

static void do_list(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		    struct run_event_context *run_ctx,
		    int argc, const char **argv)
{
	struct run_event_script_list *script_list = NULL;
	unsigned int i;
	int ret;

	ret = run_event_list(run_ctx, mem_ctx, &script_list);
	if (ret != 0) {
		printf("Script list failed with result=%d\n", ret);
		return;
	}

	if (script_list == NULL || script_list->num_scripts == 0) {
		printf("No event scripts found\n");
		return;
	}

	for (i=0; i<script_list->num_scripts; i++) {
		printf("%s\n", script_list->script[i].name);
	}
}

static void do_enable(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		      struct run_event_context *run_ctx,
		      int argc, const char **argv)
{
	int ret;

	if (argc != 4) {
		usage(argv[0]);
		exit(1);
	}

	ret = run_event_script_enable(run_ctx, argv[3]);
	printf("Script enable %s completed with result=%d\n", argv[3], ret);
}

static void do_disable(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
		       struct run_event_context *run_ctx,
		       int argc, const char **argv)
{
	int ret;

	if (argc != 4) {
		usage(argv[0]);
		exit(1);
	}

	ret = run_event_script_disable(run_ctx, argv[3]);
	printf("Script disable %s completed with result=%d\n", argv[3], ret);
}

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct run_proc_context *run_proc_ctx = NULL;
	struct run_event_context *run_ctx = NULL;
	int ret;

	if (argc < 3) {
		usage(argv[0]);
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

	ret = run_proc_init(mem_ctx, ev, &run_proc_ctx);
	if (ret != 0) {
		fprintf(stderr, "run_proc_init() failed, ret=%d\n", ret);
		exit(1);
	}

	ret = run_event_init(mem_ctx, run_proc_ctx, argv[1], NULL, &run_ctx);
	if (ret != 0) {
		fprintf(stderr, "run_event_init() failed, ret=%d\n", ret);
		exit(1);
	}

	if (strcmp(argv[2], "run") == 0) {
		do_run(mem_ctx, ev, run_ctx, argc, argv);
	} else if (strcmp(argv[2], "list") == 0) {
		do_list(mem_ctx, ev, run_ctx, argc, argv);
	} else if (strcmp(argv[2], "enable") == 0) {
		do_enable(mem_ctx, ev, run_ctx, argc, argv);
	} else if (strcmp(argv[2], "disable") == 0) {
		do_disable(mem_ctx, ev, run_ctx, argc, argv);
	} else {
		fprintf(stderr, "Invalid command %s\n", argv[2]);
		usage(argv[0]);
	}

	talloc_free(mem_ctx);
	exit(0);
}

