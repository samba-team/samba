/*
   Run scripts in a directory with specific event arguments

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
#include "system/dir.h"
#include "system/glob.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/tevent_unix.h"
#include "lib/util/debug.h"

#include "common/logging.h"
#include "common/run_proc.h"
#include "common/event_script.h"

#include "common/run_event.h"

/*
 * Utility functions
 */

static int get_script_list(TALLOC_CTX *mem_ctx,
			   const char *script_dir,
			   struct run_event_script_list **out)
{
	struct event_script_list *s_list;
	struct run_event_script_list *script_list;
	unsigned int i;
	int ret;

	ret = event_script_get_list(mem_ctx, script_dir, &s_list);
	if (ret != 0) {
		if (ret == ENOENT) {
			D_WARNING("event script dir %s removed\n", script_dir);
		} else {
			D_WARNING("failed to get script list for %s, ret=%d\n",
				  script_dir, ret);
		}
		return ret;
	}

	if (s_list->num_scripts == 0) {
		*out = NULL;
		talloc_free(s_list);
		return 0;
	}

	script_list = talloc_zero(mem_ctx, struct run_event_script_list);
	if (script_list == NULL) {
		talloc_free(s_list);
		return ENOMEM;
	}

	script_list->num_scripts = s_list->num_scripts;
	script_list->script = talloc_zero_array(script_list,
						struct run_event_script,
						script_list->num_scripts);
	if (script_list->script == NULL) {
		talloc_free(s_list);
		talloc_free(script_list);
		return ENOMEM;
	}

	for (i = 0; i < s_list->num_scripts; i++) {
		struct event_script *s = s_list->script[i];
		struct run_event_script *script = &script_list->script[i];

		script->name = talloc_steal(script_list->script, s->name);

		if (! s->enabled) {
			script->summary = -ENOEXEC;
		}
	}

	talloc_free(s_list);
	*out = script_list;
	return 0;
}

static int script_args(TALLOC_CTX *mem_ctx, const char *event_str,
		       const char *arg_str, const char ***out)
{
	const char **argv;
	size_t argc;
	size_t len;

	/* Preallocate argv array to avoid reallocation. */
	len = 8;
	argv = talloc_array(mem_ctx, const char *, len);
	if (argv == NULL) {
		return ENOMEM;
	}

	argv[0] = NULL; /* script name */
	argv[1] = event_str;
	argc = 2;

	if (arg_str != NULL) {
		char *str, *t, *tok;

		str = talloc_strdup(argv, arg_str);
		if (str == NULL) {
			return ENOMEM;
		}

		t = str;
		while ((tok = strtok(t, " ")) != NULL) {
			argv[argc] = talloc_strdup(argv, tok);
			if (argv[argc] == NULL) {
				talloc_free(argv);
				return ENOMEM;
			}
			argc += 1;
			if (argc >= len) {
				argv = talloc_realloc(mem_ctx, argv,
						      const char *, len + 8);
				if (argv == NULL) {
					return ENOMEM;
				}
				len += 8;
			}
			t = NULL;
		}

		talloc_free(str);
	}

	argv[argc] = NULL;
	/* argc += 1 */

	*out = argv;
	return 0;
}

struct run_event_context {
	struct run_proc_context *run_proc_ctx;
	const char *script_dir;
	const char *debug_prog;
	bool debug_running;

	struct tevent_queue *queue;
	struct tevent_req *current_req;
	bool monitor_running;
};


int run_event_init(TALLOC_CTX *mem_ctx, struct run_proc_context *run_proc_ctx,
		   const char *script_dir, const char *debug_prog,
		   struct run_event_context **out)
{
	struct run_event_context *run_ctx;
	struct stat st;
	int ret;

	run_ctx = talloc_zero(mem_ctx, struct run_event_context);
	if (run_ctx == NULL) {
		return ENOMEM;
	}

	run_ctx->run_proc_ctx = run_proc_ctx;

	ret = stat(script_dir, &st);
	if (ret != 0) {
		ret = errno;
		talloc_free(run_ctx);
		return ret;
	}

	if (! S_ISDIR(st.st_mode)) {
		talloc_free(run_ctx);
		return ENOTDIR;
	}

	run_ctx->script_dir = talloc_strdup(run_ctx, script_dir);
	if (run_ctx->script_dir == NULL) {
		talloc_free(run_ctx);
		return ENOMEM;
	}

	if (debug_prog != NULL) {
		run_ctx->debug_prog = talloc_strdup(run_ctx, debug_prog);
		if (run_ctx->debug_prog == NULL) {
			talloc_free(run_ctx);
			return ENOMEM;
		}
	}

	run_ctx->debug_running = false;

	run_ctx->queue = tevent_queue_create(run_ctx, "run event queue");
	if (run_ctx->queue == NULL) {
		talloc_free(run_ctx);
		return ENOMEM;
	}

	run_ctx->monitor_running = false;

	*out = run_ctx;
	return 0;
}

static struct run_proc_context *
run_event_run_proc_context(struct run_event_context *run_ctx)
{
	return run_ctx->run_proc_ctx;
}

static const char *run_event_script_dir(struct run_event_context *run_ctx)
{
	return run_ctx->script_dir;
}

static const char *run_event_debug_prog(struct run_event_context *run_ctx)
{
	return run_ctx->debug_prog;
}

static struct tevent_queue *run_event_queue(struct run_event_context *run_ctx)
{
	return run_ctx->queue;
}

static void run_event_start_running(struct run_event_context *run_ctx,
				    struct tevent_req *req, bool is_monitor)
{
	run_ctx->current_req = req;
	run_ctx->monitor_running = is_monitor;
}

static void run_event_stop_running(struct run_event_context *run_ctx)
{
	run_ctx->current_req = NULL;
	run_ctx->monitor_running = false;
}

static struct tevent_req *run_event_get_running(
				struct run_event_context *run_ctx,
				bool *is_monitor)
{
	*is_monitor = run_ctx->monitor_running;
	return run_ctx->current_req;
}

static int run_event_script_status(struct run_event_script *script)
{
	int ret;

	if (script->result.sig > 0) {
		ret = -EINTR;
	} else if (script->result.err > 0) {
		if (script->result.err == EACCES) {
			/* Map EACCESS to ENOEXEC */
			ret = -ENOEXEC;
		} else {
			ret = -script->result.err;
		}
	} else {
		ret = script->result.status;
	}

	return ret;
}

int run_event_list(struct run_event_context *run_ctx,
		   TALLOC_CTX *mem_ctx,
		   struct run_event_script_list **output)
{
	struct event_script_list *s_list = NULL;
	struct run_event_script_list *script_list = NULL;
	unsigned int i;
	int ret;

	ret = event_script_get_list(mem_ctx,
				    run_event_script_dir(run_ctx),
				    &s_list);
	if (ret != 0) {
		return ret;
	}

	if (s_list->num_scripts == 0) {
		*output = NULL;
		talloc_free(s_list);
		return 0;
	}

	script_list = talloc_zero(mem_ctx, struct run_event_script_list);
	if (script_list == NULL) {
		return ENOMEM;
	}

	script_list->num_scripts = s_list->num_scripts;
	script_list->script = talloc_zero_array(script_list,
						struct run_event_script,
						script_list->num_scripts);
	if (script_list->script == NULL) {
		talloc_free(s_list);
		talloc_free(script_list);
		return ENOMEM;
	}

	for (i=0; i < s_list->num_scripts; i++) {
		struct event_script *s = s_list->script[i];
		struct run_event_script *script = &script_list->script[i];

		script->name = talloc_steal(script_list->script, s->name);

		if (! s->enabled) {
			script->summary = -ENOEXEC;
		}
	}


	talloc_free(s_list);
	*output = script_list;
	return 0;
}

int run_event_script_enable(struct run_event_context *run_ctx,
			    const char *script_name)
{
	return event_script_chmod(run_event_script_dir(run_ctx),
				  script_name,
				  true);
}

int run_event_script_disable(struct run_event_context *run_ctx,
			     const char *script_name)
{
	return event_script_chmod(run_event_script_dir(run_ctx),
				  script_name,
				  false);
}

/*
 * Run debug program to diagnose hung scripts
 */

static int debug_args(TALLOC_CTX *mem_ctx, const char *path,
		      const char *event_str, pid_t pid, const char ***out)
{
	const char **argv;

	argv = talloc_array(mem_ctx, const char *, 4);
	if (argv == NULL) {
		return ENOMEM;
	}

	argv[0] = path;
	argv[1] = talloc_asprintf(argv, "%d", pid);
	argv[2] = event_str;
	if (argv[1] == NULL) {
		talloc_free(argv);
		return ENOMEM;
	}
	argv[3] = NULL;

	*out = argv;
	return 0;
}

static void debug_log(int loglevel, const char *output, const char *log_prefix)
{
	char *line, *s;

	s = strdup(output);
	if (s == NULL) {
		DEBUG(loglevel, ("%s: %s\n", log_prefix, output));
		return;
	}

	line = strtok(s, "\n");
	while (line != NULL) {
		DEBUG(loglevel, ("%s: %s\n", log_prefix, line));
		line = strtok(NULL, "\n");
	}
	free(s);
}

struct run_debug_state {
	struct run_event_context *run_ctx;
	pid_t pid;
};

static void run_debug_done(struct tevent_req *subreq);

static struct tevent_req *run_debug_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct run_event_context *run_ctx,
					 const char *event_str, pid_t pid)
{
	struct tevent_req *req, *subreq;
	struct run_debug_state *state;
	const char **argv;
	const char *debug_prog;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct run_debug_state);
	if (req == NULL) {
		return NULL;
	}

	state->run_ctx = run_ctx;
	state->pid = pid;

	debug_prog = run_event_debug_prog(run_ctx);
	if (debug_prog == NULL) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (run_ctx->debug_running) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (pid == -1) {
		D_DEBUG("Event script terminated, nothing to debug\n");
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	ret = debug_args(state, debug_prog, event_str, pid, &argv);
	if (ret != 0) {
		D_ERR("debug_args() failed\n");
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	D_DEBUG("Running debug %s with args \"%s %s\"\n",
		debug_prog, argv[1], argv[2]);

	subreq = run_proc_send(state, ev, run_event_run_proc_context(run_ctx),
			       debug_prog, argv, -1, tevent_timeval_zero());
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, run_debug_done, req);

	run_ctx->debug_running = true;

	talloc_free(argv);
	return req;
}

static void run_debug_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct run_debug_state *state = tevent_req_data(
		req, struct run_debug_state);
	char *output;
	int ret;
	bool status;

	state->run_ctx->debug_running = false;

	status = run_proc_recv(subreq, &ret, NULL, NULL, state, &output);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("Running debug failed, ret=%d\n", ret);
	}

	/* Log output */
	if (output != NULL) {
		debug_log(DEBUG_ERR, output, "event_debug");
		talloc_free(output);
	}

	kill(-state->pid, SIGTERM);
	tevent_req_done(req);
}

static bool run_debug_recv(struct tevent_req *req, int *perr)
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

/*
 * Run a single event
 */

struct run_event_state {
	struct tevent_context *ev;
	struct run_event_context *run_ctx;
	const char *event_str;
	const char *arg_str;
	struct timeval timeout;
	bool continue_on_failure;

	struct run_event_script_list *script_list;
	const char **argv;
	struct tevent_req *script_subreq;
	unsigned int index;
	bool cancelled;
};

static void run_event_cancel(struct tevent_req *req);
static void run_event_trigger(struct tevent_req *req, void *private_data);
static struct tevent_req *run_event_run_script(struct tevent_req *req);
static void run_event_next_script(struct tevent_req *subreq);
static void run_event_debug(struct tevent_req *req, pid_t pid);
static void run_event_debug_done(struct tevent_req *subreq);

struct tevent_req *run_event_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct run_event_context *run_ctx,
				  const char *event_str,
				  const char *arg_str,
				  struct timeval timeout,
				  bool continue_on_failure)
{
	struct tevent_req *req, *current_req;
	struct run_event_state *state;
	bool monitor_running, status;

	req = tevent_req_create(mem_ctx, &state, struct run_event_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->run_ctx = run_ctx;
	state->event_str = talloc_strdup(state, event_str);
	if (tevent_req_nomem(state->event_str, req)) {
		return tevent_req_post(req, ev);
	}
	if (arg_str != NULL) {
		state->arg_str = talloc_strdup(state, arg_str);
		if (tevent_req_nomem(state->arg_str, req)) {
			return tevent_req_post(req, ev);
		}
	}
	state->timeout = timeout;
	state->continue_on_failure = continue_on_failure;
	state->cancelled = false;

	state->script_list = talloc_zero(state, struct run_event_script_list);
	if (tevent_req_nomem(state->script_list, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * If monitor event is running,
	 *   cancel the running monitor event and run new event
	 *
	 * If any other event is running,
	 *   if new event is monitor, cancel that event
	 *   else add new event to the queue
	 */

	current_req = run_event_get_running(run_ctx, &monitor_running);
	if (current_req != NULL) {
		if (monitor_running) {
			run_event_cancel(current_req);
		} else if (strcmp(event_str, "monitor") == 0) {
			state->script_list->summary = -ECANCELED;
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}
	}

	status = tevent_queue_add(run_event_queue(run_ctx), ev, req,
				  run_event_trigger, NULL);
	if (! status) {
		tevent_req_error(req, ENOMEM);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void run_event_cancel(struct tevent_req *req)
{
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);

	run_event_stop_running(state->run_ctx);

	state->script_list->summary = -ECANCELED;
	state->cancelled = true;

	TALLOC_FREE(state->script_subreq);

	tevent_req_done(req);
}

static void run_event_trigger(struct tevent_req *req, void *private_data)
{
	struct tevent_req *subreq;
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);
	struct run_event_script_list *script_list;
	int ret;
	bool is_monitor = false;

	D_DEBUG("Running event %s with args \"%s\"\n", state->event_str,
		state->arg_str == NULL ? "(null)" : state->arg_str);

	ret = get_script_list(state,
			      run_event_script_dir(state->run_ctx),
			      &script_list);
	if (ret != 0) {
		D_ERR("get_script_list() failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	/* No scripts */
	if (script_list == NULL || script_list->num_scripts == 0) {
		tevent_req_done(req);
		return;
	}

	talloc_free(state->script_list);
	state->script_list = script_list;

	ret = script_args(state, state->event_str, state->arg_str,
			  &state->argv);
	if (ret != 0) {
		D_ERR("script_args() failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return;
	}

	state->index = 0;

	subreq = run_event_run_script(req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, run_event_next_script, req);

	state->script_subreq = subreq;

	if (strcmp(state->event_str, "monitor") == 0) {
		is_monitor = true;
	}
	run_event_start_running(state->run_ctx, req, is_monitor);
}

static struct tevent_req *run_event_run_script(struct tevent_req *req)
{
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);
	struct run_event_script *script;
	struct tevent_req *subreq;
	char *path;

	script = &state->script_list->script[state->index];

	path = talloc_asprintf(state, "%s/%s.script",
			       run_event_script_dir(state->run_ctx),
			       script->name);
	if (path == NULL) {
		return NULL;
	}

	state->argv[0] = script->name;
	script->begin = tevent_timeval_current();

	D_DEBUG("Running %s with args \"%s %s\"\n",
		path, state->argv[0], state->argv[1]);

	subreq = run_proc_send(state, state->ev,
			       run_event_run_proc_context(state->run_ctx),
			       path, state->argv, -1, state->timeout);

	talloc_free(path);

	return subreq;
}

static void run_event_next_script(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);
	struct run_event_script *script;
	pid_t pid;
	int ret;
	bool status;

	script = &state->script_list->script[state->index];
	script->end = tevent_timeval_current();

	status = run_proc_recv(subreq, &ret, &script->result, &pid,
			       state->script_list, &script->output);
	TALLOC_FREE(subreq);
	state->script_subreq = NULL;
	if (! status) {
		D_ERR("run_proc failed for %s, ret=%d\n", script->name, ret);
		run_event_stop_running(state->run_ctx);
		tevent_req_error(req, ret);
		return;
	}

	if (state->cancelled) {
		return;
	}

	/* Log output */
	if (script->output != NULL) {
		debug_log(DEBUG_ERR, script->output, script->name);
	}

	D_DEBUG("Script %s finished sig=%d, err=%d, status=%d\n",
		script->name, script->result.sig, script->result.err,
		script->result.status);


	/* If a script fails, stop running */
	script->summary = run_event_script_status(script);
	if (script->summary != 0 && script->summary != -ENOEXEC) {
		state->script_list->summary = script->summary;

		if (! state->continue_on_failure) {
			state->script_list->num_scripts = state->index + 1;

			if (script->summary == -ETIMEDOUT && pid != -1) {
				run_event_debug(req, pid);
			}
			D_NOTICE("%s event %s\n", state->event_str,
				 (script->summary == -ETIMEDOUT) ?
				  "timed out" :
				  "failed");
			run_event_stop_running(state->run_ctx);
			tevent_req_done(req);
			return;
		}
	}

	state->index += 1;

	/* All scripts executed */
	if (state->index >= state->script_list->num_scripts) {
		run_event_stop_running(state->run_ctx);
		tevent_req_done(req);
		return;
	}

	subreq = run_event_run_script(req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, run_event_next_script, req);

	state->script_subreq = subreq;
}

static void run_event_debug(struct tevent_req *req, pid_t pid)
{
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);
	struct tevent_req *subreq;

	/* Debug script is run with ectx as the memory context */
	subreq = run_debug_send(state->run_ctx, state->ev, state->run_ctx,
				state->event_str, pid);
	if (subreq == NULL) {
		/* If run debug fails, it's not an error */
		D_NOTICE("Failed to run event debug\n");
		return;
	}
	tevent_req_set_callback(subreq, run_event_debug_done, NULL);
}

static void run_event_debug_done(struct tevent_req *subreq)
{
	int ret = 0;
	bool status;

	status = run_debug_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		D_NOTICE("run_debug() failed, ret=%d\n", ret);
	}
}

bool run_event_recv(struct tevent_req *req, int *perr,
		    TALLOC_CTX *mem_ctx,
		    struct run_event_script_list **script_list)
{
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (script_list != NULL) {
		*script_list = talloc_steal(mem_ctx, state->script_list);
	}
	return true;
}

