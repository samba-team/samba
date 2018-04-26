/*
   CTDB event daemon utility code

   Copyright (C) Amitay Isaacs  2018

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
#include "system/time.h"

#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"

#include "common/cmdline.h"
#include "common/logging.h"
#include "common/path.h"

#include "event/event_protocol_api.h"
#include "event/event.h"
#include "event/event_tool.h"

struct event_tool_context {
	struct cmdline_context *cmdline;
	struct tevent_context *ev;
	struct ctdb_event_context *eclient;
};

static int compact_args(TALLOC_CTX *mem_ctx,
			const char **argv,
			int argc,
			int from,
			const char **result)
{
	char *arg_str;
	int i;

	if (argc <= from) {
		*result = NULL;
		return 0;
	}

	arg_str = talloc_strdup(mem_ctx, argv[from]);
	if (arg_str == NULL) {
		return ENOMEM;
	}

	for (i = from+1; i < argc; i++) {
		arg_str = talloc_asprintf_append(arg_str, " %s", argv[i]);
		if (arg_str == NULL) {
			return ENOMEM;
		}
	}

	*result = arg_str;
	return 0;
}

static int event_command_run(TALLOC_CTX *mem_ctx,
			     int argc,
			     const char **argv,
			     void *private_data)
{
	struct event_tool_context *ctx = talloc_get_type_abort(
		private_data, struct event_tool_context);
	struct tevent_req *req;
	struct ctdb_event_request_run request_run;
	const char *arg_str = NULL;
	const char *t;
	int timeout, ret = 0, result = 0;
	bool ok;

	if (argc < 3) {
		cmdline_usage(ctx->cmdline, "run");
		return 1;
	}

	timeout = atoi(argv[0]);
	if (timeout < 0) {
		timeout = 0;
	}

	ret = compact_args(mem_ctx, argv, argc, 3, &arg_str);
	if (ret != 0) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	request_run.component = argv[1];
	request_run.event = argv[2];
	request_run.args = arg_str;
	request_run.timeout = timeout;
	request_run.flags = 0;

	t = getenv("CTDB_TEST_MODE");
	if (t != NULL) {
		t = getenv("CTDB_EVENT_RUN_ALL");
		if (t != NULL) {
			request_run.flags = CTDB_EVENT_RUN_ALL;
		}
	}

	req = ctdb_event_run_send(mem_ctx,
				  ctx->ev,
				  ctx->eclient,
				  &request_run);
	if (req == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	tevent_req_poll(req, ctx->ev);

	ok = ctdb_event_run_recv(req, &ret, &result);
	if (!ok) {
		D_ERR("Failed to run event %s in %s, ret=%d\n",
		      argv[2],
		      argv[1],
		      ret);
		return 1;
	}

	D_NOTICE("Command run finished with result=%d\n", result);

	if (result == ENOENT) {
		printf("Event dir for %s does not exist\n", argv[1]);
	} else if (result == ETIME) {
		printf("Event %s in %s timed out\n", argv[2], argv[1]);
	} else if (result == ECANCELED) {
		printf("Event %s in %s got cancelled\n", argv[2], argv[1]);
	} else if (result == ENOEXEC) {
		printf("Event %s in %s failed\n", argv[2], argv[1]);
	} else if (result != 0) {
		printf("Failed to run event %s in %s, result=%d\n",
		       argv[2],
		       argv[1],
		       result);
	}

	ret = (result < 0) ? -result : result;
	return ret;
}

static double timeval_delta(struct timeval *tv2, struct timeval *tv)
{
        return (tv2->tv_sec - tv->tv_sec) +
               (tv2->tv_usec - tv->tv_usec) * 1.0e-6;
}

static void print_status_one(struct ctdb_event_script *script)
{
	if (script->result == -ETIME) {
		printf("%-20s %-10s %s",
		       script->name,
		       "TIMEDOUT",
		       ctime(&script->begin.tv_sec));
	} else if (script->result == -ENOEXEC) {
		printf("%-20s %-10s\n", script->name, "DISABLED");
	} else if (script->result < 0) {
		printf("%-20s %-10s (%s)\n",
		       script->name,
		       "CANNOT RUN",
		       strerror(-script->result));
	} else if (script->result == 0) {
		printf("%-20s %-10s %.3lf %s",
		       script->name,
		       "OK",
		       timeval_delta(&script->end, &script->begin),
		       ctime(&script->begin.tv_sec));
	} else {
		printf("%-20s %-10s %.3lf %s",
		       script->name,
		       "ERROR",
		       timeval_delta(&script->end, &script->begin),
		       ctime(&script->begin.tv_sec));
	}

	if (script->result != 0 && script->result != -ENOEXEC) {
		printf("  OUTPUT: %s\n",
		       script->output == NULL ? "" : script->output);
	}
}

static void print_status(const char *component,
			 const char *event,
			 int result,
			 struct ctdb_event_reply_status *status)
{
	int i;

	if (result != 0) {
		if (result == ENOENT) {
			printf("Event dir for %s does not exist\n", component);
		} else if (result == EINVAL) {
			printf("Event %s has never run in %s\n",
			       event,
			       component);
		} else {
			printf("Unknown error (%d) for event %s in %s\n",
			       result,
			       event,
			       component);
		}
		return;
	}

	for (i=0; i<status->script_list->num_scripts; i++) {
		print_status_one(&status->script_list->script[i]);
	}
}

static int event_command_status(TALLOC_CTX *mem_ctx,
				int argc,
				const char **argv,
				void *private_data)
{
	struct event_tool_context *ctx = talloc_get_type_abort(
		private_data, struct event_tool_context);
	struct tevent_req *req;
	struct ctdb_event_request_status request_status;
	struct ctdb_event_reply_status *reply_status;
	int ret = 0, result = 0;
	bool ok;

	if (argc != 2) {
		cmdline_usage(ctx->cmdline, "run");
		return 1;
	}

	request_status.component = argv[0];
	request_status.event = argv[1];

	req = ctdb_event_status_send(mem_ctx,
				     ctx->ev,
				     ctx->eclient,
				     &request_status);
	if (req == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	tevent_req_poll(req, ctx->ev);

	ok = ctdb_event_status_recv(req,
				    &ret,
				    &result,
				    mem_ctx,
				    &reply_status);
	if (!ok) {
		D_ERR("Failed to get status for event %s in %s, ret=%d\n",
		      argv[1],
		      argv[0],
		      ret);
		return 1;
	}

	D_NOTICE("Command status finished with result=%d\n", result);

	print_status(argv[0], argv[1], result, reply_status);

	if (reply_status == NULL) {
		ret = result;
	} else {
		ret = reply_status->summary;
		ret = (ret < 0) ? -ret : ret;
	}
	return ret;
}

static int event_command_script(TALLOC_CTX *mem_ctx,
				struct event_tool_context *ctx,
				const char *component,
				const char *script,
				enum ctdb_event_script_action action)
{
	struct tevent_req *req;
	struct ctdb_event_request_script request_script;
	int ret = 0, result = 0;
	bool ok;

	request_script.component = component;
	request_script.script = script;
	request_script.action = action;

	req = ctdb_event_script_send(mem_ctx,
				     ctx->ev,
				     ctx->eclient,
				     &request_script);
	if (req == NULL) {
		D_ERR("Memory allocation error\n");
		return 1;
	}

	tevent_req_poll(req, ctx->ev);

	ok = ctdb_event_script_recv(req, &ret, &result);
	if (!ok) {
		D_ERR("Failed to %s script, ret=%d\n",
		      (action == CTDB_EVENT_SCRIPT_DISABLE ?
		       "disable" :
		       "enable"),
		      ret);
		return 1;
	}

	D_NOTICE("Command script finished with result=%d\n", result);

	if (result == EINVAL) {
		printf("Script %s is invalid in %s\n", script, component);
	} else if (result == ENOENT) {
		printf("Script %s does not exist in %s\n", script, component);
	}

	return result;
}

static int event_command_script_enable(TALLOC_CTX *mem_ctx,
				       int argc,
				       const char **argv,
				       void *private_data)
{
	struct event_tool_context *ctx = talloc_get_type_abort(
		private_data, struct event_tool_context);

	if (argc != 2) {
		cmdline_usage(ctx->cmdline, "script enable");
		return 1;
	}

	return event_command_script(mem_ctx,
				    ctx,
				    argv[0],
				    argv[1],
				    CTDB_EVENT_SCRIPT_ENABLE);
}

static int event_command_script_disable(TALLOC_CTX *mem_ctx,
					int argc,
					const char **argv,
					void *private_data)
{
	struct event_tool_context *ctx = talloc_get_type_abort(
		private_data, struct event_tool_context);

	if (argc != 2) {
		cmdline_usage(ctx->cmdline, "script disable");
		return 1;
	}

	return event_command_script(mem_ctx,
				    ctx,
				    argv[0],
				    argv[1],
				    CTDB_EVENT_SCRIPT_DISABLE);
}

struct cmdline_command event_commands[] = {
	{ "run", event_command_run,
		"Run an event", "<timeout> <component> <event> <args>" },
	{ "status", event_command_status,
		"Get status of an event", "<component> <event>" },
	{ "script enable", event_command_script_enable,
		"Enable an event script", "<component> <script>" },
	{ "script disable", event_command_script_disable,
		"Disable an event script", "<component> <script>" },
	CMDLINE_TABLEEND
};

int event_tool_init(TALLOC_CTX *mem_ctx,
		    const char *prog,
		    struct poptOption *options,
		    int argc,
		    const char **argv,
		    bool parse_options,
		    struct event_tool_context **result)
{
	struct event_tool_context *ctx;
	int ret;

	ctx = talloc_zero(mem_ctx, struct event_tool_context);
	if (ctx == NULL) {
		D_ERR("Memory allocation error\n");
		return ENOMEM;
	}

	ret = cmdline_init(mem_ctx,
			   prog,
			   options,
			   event_commands,
			   &ctx->cmdline);
	if (ret != 0) {
		D_ERR("Failed to initialize cmdline, ret=%d\n", ret);
		talloc_free(ctx);
		return ret;
	}

	ret = cmdline_parse(ctx->cmdline, argc, argv, parse_options);
	if (ret != 0) {
		cmdline_usage(ctx->cmdline, NULL);
		talloc_free(ctx);
		return ret;
	}

	*result = ctx;
	return 0;
}

int event_tool_run(struct event_tool_context *ctx, int *result)
{
	int ret;

	ctx->ev = tevent_context_init(ctx);
	if (ctx->ev == NULL) {
		D_ERR("Failed to initialize tevent\n");
		return ENOMEM;
	}

	ret = ctdb_event_init(ctx, ctx->ev, &ctx->eclient);
	if (ret != 0) {
		D_ERR("Failed to initialize event client, ret=%d\n", ret);
		return ret;
	}

	ret = cmdline_run(ctx->cmdline, ctx, result);
	return ret;
}

#ifdef CTDB_EVENT_TOOL

static struct {
	const char *debug;
} event_data = {
	.debug = "ERROR",
};

struct poptOption event_options[] = {
	{ "debug", 'd', POPT_ARG_STRING, &event_data.debug, 0,
		"debug level", "ERROR|WARNING|NOTICE|INFO|DEBUG" },
	POPT_TABLEEND
};

int main(int argc, const char **argv)
{
	TALLOC_CTX *mem_ctx;
	struct event_tool_context *ctx;
	int ret, result = 0;
	bool ok;

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		fprintf(stderr, "Memory allocation error\n");
		exit(1);
	}

	ret = event_tool_init(mem_ctx,
			      "ctdb-event",
			      event_options,
			      argc,
			      argv,
			      true,
			      &ctx);
	if (ret != 0) {
		talloc_free(mem_ctx);
		exit(1);
	}

	setup_logging("ctdb-event", DEBUG_STDERR);
	ok = debug_level_parse(event_data.debug, &DEBUGLEVEL);
	if (!ok) {
		DEBUGLEVEL = DEBUG_ERR;
	}

	ret = event_tool_run(ctx, &result);
	if (ret != 0) {
		exit(1);
	}

	talloc_free(mem_ctx);
	exit(result);
}

#endif /* CTDB_EVENT_TOOL */
