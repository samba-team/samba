/*
   CTDB event daemon control tool

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
#include "system/network.h"
#include "system/time.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"

#include "protocol/protocol_api.h"
#include "client/client.h"
#include "common/logging.h"

struct tool_context {
	struct tevent_context *ev;
	struct ctdb_event_context *eclient;
};

static void usage(void);

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

static int command_run(TALLOC_CTX *mem_ctx, struct tool_context *tctx,
		       int argc, const char **argv)
{
	struct tevent_req *req;
	enum ctdb_event event;
	const char *arg_str;
	int timeout;
	int eargs;
	int ret, result;
	bool status;

	if (argc < 2) {
		usage();
	}

	event = ctdb_event_from_string(argv[0]);
	if (event == CTDB_EVENT_MAX) {
		fprintf(stderr, "Invalid event '%s'\n", argv[0]);
		return 1;
	}

	timeout = atoi(argv[1]);
	if (timeout < 0) {
		timeout = 0;
	}

	switch (event) {
		case CTDB_EVENT_INIT:
		case CTDB_EVENT_SETUP:
		case CTDB_EVENT_STARTUP:
		case CTDB_EVENT_MONITOR:
		case CTDB_EVENT_IPREALLOCATED:
			eargs = 0;
			break;

		case CTDB_EVENT_TAKE_IP:
		case CTDB_EVENT_RELEASE_IP:
			eargs = 3;
			break;

		case CTDB_EVENT_UPDATE_IP:
			eargs = 4;
			break;

		default:
			eargs = -1;
			break;
	}

	if (eargs < 0) {
		fprintf(stderr, "Cannot run event %s\n", argv[0]);
		return 1;
	}

	if (argc != 2 + eargs) {
		fprintf(stderr, "Insufficient arguments for event %s\n",
			argv[0]);
		return 1;
	}

	arg_str = compact_args(argv, argc, 2);

	req = ctdb_event_run_send(mem_ctx, tctx->ev, tctx->eclient,
				  event, timeout, arg_str);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, tctx->ev);

	status = ctdb_event_run_recv(req, &ret, &result);
	talloc_free(req);
	if (! status) {
		fprintf(stderr, "Failed to run event %s, ret=%d\n",
			argv[0], ret);
		return ret;
	}

	if (result == -ETIME) {
		fprintf(stderr, "Event %s timed out\n", argv[0]);
	} else if (result == -ECANCELED) {
		fprintf(stderr, "Event %s got cancelled\n", argv[0]);
	} else if (result != 0) {
		fprintf(stderr, "Failed to run event %s, result=%d\n",
			argv[0], result);
	}

	ret = (result < 0) ? -result : result;
	return ret;
}

static double timeval_delta(struct timeval *tv2, struct timeval *tv)
{
        return (tv2->tv_sec - tv->tv_sec) +
               (tv2->tv_usec - tv->tv_usec) * 1.0e-6;
}

static void print_status_one(struct ctdb_script *script)
{
	if (script->status == -ETIME) {
		printf("%-20s %-10s %s", script->name, "TIMEDOUT",
		       ctime(&script->start.tv_sec));
	} else if (script->status == -ENOEXEC) {
		printf("%-20s %-10s\n", script->name, "DISABLED");
	} else if (script->status < 0) {
		printf("%-20s %-10s (%s)\n", script->name, "CANNOT RUN",
		       strerror(-script->status));
	} else if (script->status == 0) {
		printf("%-20s %-10s %.3lf %s", script->name, "OK",
		       timeval_delta(&script->finished, &script->start),
		       ctime(&script->start.tv_sec));
	} else {
		printf("%-20s %-10s %.3lf %s", script->name, "ERROR",
		       timeval_delta(&script->finished, &script->start),
		       ctime(&script->start.tv_sec));
	}

	if (script->status != 0 && script->status != -ENOEXEC) {
		printf("  OUTPUT: %s\n", script->output);
	}
}

static int command_status(TALLOC_CTX *mem_ctx, struct tool_context *tctx,
			  int argc, const char **argv)
{
	struct tevent_req *req;
	struct ctdb_script_list *script_list;
	enum ctdb_event event;
	uint32_t state;
	int ret, result, event_status, i;
	bool status;

	if (argc < 1) {
		event = CTDB_EVENT_MONITOR;
	} else {
		event = ctdb_event_from_string(argv[0]);
		if (event == CTDB_EVENT_MAX) {
			fprintf(stderr, "Invalid event '%s'\n", argv[0]);
			return EINVAL;
		}
	}

	if (argc < 2) {
		state = CTDB_EVENT_LAST_RUN;
	} else {
		if (strcmp(argv[1], "lastrun") == 0) {
			state = CTDB_EVENT_LAST_RUN;
		} else if (strcmp(argv[1], "lastpass") == 0) {
			state = CTDB_EVENT_LAST_PASS;
		} else if (strcmp(argv[1], "lastfail") == 0) {
			state = CTDB_EVENT_LAST_FAIL;
		} else {
			fprintf(stderr, "Invalid state %s\n", argv[1]);
			return EINVAL;
		}
	}

	req = ctdb_event_status_send(mem_ctx, tctx->ev, tctx->eclient,
				     event, state);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, tctx->ev);

	status = ctdb_event_status_recv(req, &ret, &result, &event_status,
					mem_ctx, &script_list);
	talloc_free(req);
	if (! status) {
		fprintf(stderr, "Failed to get event %s status, ret=%d\n",
			ctdb_event_to_string(event), ret);
		return ret;
	}

	if (result != 0) {
		fprintf(stderr, "Failed to get event %s status, result=%d\n",
			ctdb_event_to_string(event), result);
		return result;
	}

	if (script_list == NULL) {
		if (state == CTDB_EVENT_LAST_RUN) {
			printf("Event %s has never run\n",
			       ctdb_event_to_string(event));
		} else if (state == CTDB_EVENT_LAST_PASS) {
			printf("Event %s has never passed\n",
				ctdb_event_to_string(event));
		} else if (state == CTDB_EVENT_LAST_FAIL) {
			printf("Event %s has never failed\n",
				ctdb_event_to_string(event));
		}
	} else {
		for (i=0; i<script_list->num_scripts; i++) {
			print_status_one(&script_list->script[i]);
		}
		talloc_free(script_list);
	}

	return event_status;
}

static int command_script_list(TALLOC_CTX *mem_ctx, struct tool_context *tctx,
			       int argc, const char **argv)
{
	struct tevent_req *req;
	struct ctdb_script_list *script_list = NULL;
	int ret, result, i;
	bool status;

	if (argc != 0) {
		usage();
	}

	req = ctdb_event_script_list_send(mem_ctx, tctx->ev, tctx->eclient);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, tctx->ev);

	status = ctdb_event_script_list_recv(req, &ret, &result,
					     mem_ctx, &script_list);
	talloc_free(req);
	if (! status) {
		fprintf(stderr, "Failed to get script list, ret=%d\n", ret);
		return ret;
	}

	if (result != 0) {
		fprintf(stderr, "Failed to get script list, result=%d\n",
			result);
		return result;
	}

	if (script_list == NULL || script_list->num_scripts == 0) {
		printf("No event scripts found\n");
	} else {
		for (i=0; i<script_list->num_scripts; i++) {
			struct ctdb_script *s;

			s = &script_list->script[i];

			if (s->status == -ENOEXEC) {
				printf("%-20s DISABLED\n", s->name);
			} else {
				printf("%-20s\n", s->name);
			}
		}
		talloc_free(script_list);
	}

	return 0;
}

static int command_script_enable(TALLOC_CTX *mem_ctx,
				 struct tool_context *tctx,
				 int argc, const char **argv)
{
	struct tevent_req *req;
	int ret, result;
	bool status;

	if (argc != 1) {
		usage();
	}

	req = ctdb_event_script_enable_send(mem_ctx, tctx->ev, tctx->eclient,
					    argv[0]);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, tctx->ev);

	status = ctdb_event_script_enable_recv(req, &ret, &result);
	talloc_free(req);
	if (! status) {
		fprintf(stderr, "Failed to enable script %s, ret=%d\n",
			argv[0], ret);
		return ret;
	}

	if (result == -ENOENT) {
		fprintf(stderr, "Script %s does not exist\n", argv[0]);
	} else if (result == -EINVAL) {
		fprintf(stderr, "Script name %s is invalid\n", argv[0]);
	} else if (result != 0) {
		fprintf(stderr, "Failed to enable script %s, result=%d\n",
			argv[0], result);
	}

	ret = (result < 0) ? -result : result;
	return ret;
}

static int command_script_disable(TALLOC_CTX *mem_ctx,
				  struct tool_context *tctx,
				  int argc, const char **argv)
{
	struct tevent_req *req;
	int ret, result;
	bool status;

	if (argc != 1) {
		usage();
	}

	req = ctdb_event_script_disable_send(mem_ctx, tctx->ev, tctx->eclient,
					     argv[0]);
	if (req == NULL) {
		return ENOMEM;
	}

	tevent_req_poll(req, tctx->ev);

	status = ctdb_event_script_disable_recv(req, &ret, &result);
	talloc_free(req);
	if (! status) {
		fprintf(stderr, "Failed to disable script %s, ret=%d\n",
			argv[0], ret);
		return ret;
	}

	if (result == -ENOENT) {
		fprintf(stderr, "Script %s does not exist\n", argv[0]);
	} else if (result == -EINVAL) {
		fprintf(stderr, "Script name %s is invalid\n", argv[0]);
	} else if (result != 0) {
		fprintf(stderr, "Failed to disable script %s, result=%d\n",
			argv[0], result);
	}

	ret = (result < 0) ? -result : result;
	return ret;
}

static const struct ctdb_event_cmd {
	const char *name;
	const char *str1;
	const char *str2;
	int (*fn)(TALLOC_CTX *, struct tool_context *, int, const char **);
	const char *msg;
	const char *args;
} ctdb_event_commands[] = {
	{ "run", "run", NULL, command_run,
		"Run an event", "<event> <timeout> <args>" },
	{ "status", "status", NULL, command_status,
		"Get last status of an event",
		"[<event>] [lastrun|lastpass|lastfail]" },
	{ "script list", "script", "list", command_script_list,
		"Get list of event scripts", NULL },
	{ "script enable", "script", "enable", command_script_enable,
		"Enable an event script", "<script>" },
	{ "script disable", "script", "disable", command_script_disable,
		"Disable an event script", "<script>" },
};

static void usage(void)
{
	const struct ctdb_event_cmd *cmd;
	int i;

	printf("Usage: ctdb_event <command> <args>\n");
	printf("Commands:\n");
	for (i=0; i<ARRAY_SIZE(ctdb_event_commands); i++) {
		cmd = &ctdb_event_commands[i];

		printf("  %-15s %-37s  %s\n",
		       cmd->name, cmd->args ? cmd->args : "", cmd->msg);
	}

	exit(1);
}

static const struct ctdb_event_cmd *match_command(const char *str1,
						  const char *str2)
{
	const struct ctdb_event_cmd *cmd;
	bool match = false;
	int i;

	for (i=0; i<ARRAY_SIZE(ctdb_event_commands); i++) {
		cmd = &ctdb_event_commands[i];
		if (strlen(str1) == strlen(cmd->str1) &&
		    strcmp(str1, cmd->str1) == 0) {
			match = true;
		}
		if (cmd->str2 != NULL) {
			if (str2 == NULL) {
				match = false;
			} else {
				if (strcmp(str2, cmd->str2) == 0) {
					match = true;
				} else {
					match = false;
				}
			}
		}

		if (match) {
			return cmd;
		}
	}

	return NULL;
}

static int process_command(const char *sockpath,
			   const struct ctdb_event_cmd *cmd,
			   int argc, const char **argv)
{
	TALLOC_CTX *tmp_ctx;
	struct tool_context *tctx;
	int ret;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		goto fail;
	}

	tctx = talloc_zero(tmp_ctx, struct tool_context);
	if (tctx == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		goto fail;
	}

	tctx->ev = tevent_context_init(tctx);
	if (tctx->ev == NULL) {
		fprintf(stderr, "Failed to initialize tevent\n");
		goto fail;
	}

	ret = ctdb_event_init(tmp_ctx, tctx->ev, sockpath, &tctx->eclient);
	if (ret != 0) {
		fprintf(stderr, "ctdb_event_init() failed, ret=%d\n", ret);
		goto fail;
	}

	if (cmd->str2 == NULL) {
		ret = cmd->fn(tmp_ctx, tctx, argc-1, &argv[1]);
	} else {
		ret = cmd->fn(tmp_ctx, tctx, argc-2, &argv[2]);
	}

	talloc_free(tmp_ctx);
	return ret;

fail:
	TALLOC_FREE(tmp_ctx);
	return 1;
}

int main(int argc, const char **argv)
{
	const struct ctdb_event_cmd *cmd;
	const char *eventd_socket;
	const char *t;

	if (argc < 3) {
		usage();
	}

	eventd_socket = argv[1];

	cmd = match_command(argv[2], argv[3]);
	if (cmd == NULL) {
		fprintf(stderr, "Unknown command '%s %s'", argv[2], argv[3]);
		exit(1);
	}

	/* Enable logging */
	setup_logging("ctdb_event", DEBUG_STDERR);
	t = getenv("CTDB_DEBUGLEVEL");
	if (t == NULL || ! debug_level_parse(t, &DEBUGLEVEL)) {
		DEBUGLEVEL = DEBUG_ERR;
	}

	return process_command(eventd_socket, cmd, argc-2, &argv[2]);
}
