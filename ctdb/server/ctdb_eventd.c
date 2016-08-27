/*
   Event script running daemon

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
#include "system/dir.h"
#include "system/wait.h"
#include "system/locale.h"

#include <popt.h>
#include <talloc.h>
#include <tevent.h>

#include "lib/util/debug.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/blocking.h"
#include "lib/util/sys_rw.h"
#include "lib/util/dlinklist.h"
#include "lib/async_req/async_sock.h"

#include "protocol/protocol_api.h"

#include "common/comm.h"
#include "common/logging.h"
#include "common/run_proc.h"
#include "common/sock_daemon.h"

struct pending_event {
	struct pending_event *prev, *next;

	struct tevent_req *req;
};

struct eventd_client {
	struct eventd_client *prev, *next;

	struct sock_client_context *client_ctx;
	struct pending_event *pending_list;
};

struct eventd_context {
	const char *script_dir;
	const char *debug_script;
	struct run_proc_context *run_ctx;
	struct tevent_queue *queue;

	/* current state */
	bool running;
	enum ctdb_event event;
	struct tevent_req *req;

	/* result of last execution */
	int result_run;
	int result_fail;
	struct ctdb_script_list *status_run[CTDB_EVENT_MAX];
	struct ctdb_script_list *status_pass[CTDB_EVENT_MAX];
	struct ctdb_script_list *status_fail[CTDB_EVENT_MAX];

	struct eventd_client *client_list;
};

/*
 * Global state manipulation functions
 */

static int eventd_context_init(TALLOC_CTX *mem_ctx,
			       struct tevent_context *ev,
			       const char *script_dir,
			       const char *debug_script,
			       struct eventd_context **result)
{
	struct eventd_context *ectx;
	int ret;

	ectx = talloc_zero(mem_ctx, struct eventd_context);
	if (ectx == NULL) {
		return ENOMEM;
	}

	ectx->script_dir = talloc_strdup(ectx, script_dir);
	if (ectx->script_dir == NULL) {
		talloc_free(ectx);
		return ENOMEM;
	}

	if (debug_script != NULL) {
		ectx->debug_script = talloc_strdup(ectx, debug_script);
		if (ectx->debug_script == NULL) {
			talloc_free(ectx);
			return ENOMEM;
		}
	}

	ret = run_proc_init(ectx, ev, &ectx->run_ctx);
	if (ret != 0) {
		talloc_free(ectx);
		return ret;
	}

	ectx->queue = tevent_queue_create(ectx, "run event queue");
	if (ectx->queue == NULL) {
		talloc_free(ectx);
		return ENOMEM;
	}

	ectx->running = false;
	ectx->event = CTDB_EVENT_INIT;

	*result = ectx;
	return 0;
}

static const char *eventd_script_dir(struct eventd_context *ectx)
{
	return ectx->script_dir;
}

static const char *eventd_debug_script(struct eventd_context *ectx)
{
	return ectx->debug_script;
}

static struct tevent_queue *eventd_queue(struct eventd_context *ectx)
{
	return ectx->queue;
}

static void eventd_start_running(struct eventd_context *ectx,
				 enum ctdb_event event,
				 struct tevent_req *req)
{
	ectx->running = true;
	ectx->event = event;
	ectx->req = req;
}

static void eventd_stop_running(struct eventd_context *ectx)
{
	ectx->running = false;
	ectx->req = NULL;
}

static void eventd_cancel_running(struct eventd_context *ectx)
{
	if (ectx->req != NULL) {
		tevent_req_error(ectx->req, ECANCELED);
	}

	eventd_stop_running(ectx);
}

static bool eventd_is_running(struct eventd_context *ectx,
			      enum ctdb_event *event)
{
	if (event != NULL && ectx->running) {
		*event = ectx->event;
	}

	return ectx->running;
}

static struct ctdb_script_list *script_list_copy(TALLOC_CTX *mem_ctx,
						 struct ctdb_script_list *s)
{
	struct ctdb_script_list *s2;

	s2 = talloc_zero(mem_ctx, struct ctdb_script_list);
	if (s2 == NULL) {
		return NULL;
	}

	s2->num_scripts = s->num_scripts;
	s2->script = talloc_memdup(s2, s->script,
				   s->num_scripts * sizeof(struct ctdb_script));
	if (s2->script == NULL) {
		talloc_free(s2);
		return NULL;
	}

	return s2;
}

static void eventd_set_result(struct eventd_context *ectx,
			      enum ctdb_event event,
			      struct ctdb_script_list *script_list,
			      int result)
{
	struct ctdb_script_list *s;

	/* Avoid negative values, they represent -errno */
	result = (result < 0) ? -result : result;

	ectx->result_run = result;
	if (script_list == NULL) {
		return;
	}

	TALLOC_FREE(ectx->status_run[event]);
	ectx->status_run[event] = talloc_steal(ectx, script_list);

	s = script_list_copy(ectx, script_list);
	if (s == NULL) {
		return;
	}

	if (result == 0) {
		TALLOC_FREE(ectx->status_pass[event]);
		ectx->status_pass[event] = s;
	} else {
		TALLOC_FREE(ectx->status_fail[event]);
		ectx->status_fail[event] = s;
		ectx->result_fail = result;
	}
}

static int eventd_get_result(struct eventd_context *ectx,
			     enum ctdb_event event,
			     enum ctdb_event_status_state state,
			     struct ctdb_script_list **out)
{
	struct ctdb_script_list *s = NULL;
	int result = 0;

	switch (state) {
		case CTDB_EVENT_LAST_RUN:
			s = ectx->status_run[event];
			result = ectx->result_run;
			break;

		case CTDB_EVENT_LAST_PASS:
			s = ectx->status_pass[event];
			result = 0;
			break;

		case CTDB_EVENT_LAST_FAIL:
			s = ectx->status_fail[event];
			result = ectx->result_fail;
			break;
	}

	*out = s;
	return result;
}

/*
 * Run debug script to dianose hung scripts
 */

static int debug_args(TALLOC_CTX *mem_ctx, const char *path,
		      enum ctdb_event event, pid_t pid, const char ***out)
{
	const char **argv;

	argv = talloc_array(mem_ctx, const char *, 4);
	if (argv == NULL) {
		return ENOMEM;
	}

	argv[0] = path;
	argv[1] = talloc_asprintf(argv, "%d", pid);
	argv[2] = ctdb_event_to_string(event);
	if (argv[1] == NULL) {
		talloc_free(argv);
		return ENOMEM;
	}
	argv[3] = NULL;

	*out = argv;
	return 0;
}

static void debug_log(int loglevel, char *output, const char *log_prefix)
{
	char *line;

	line = strtok(output, "\n");
	while (line != NULL) {
		DEBUG(loglevel, ("%s: %s\n", log_prefix, line));
		line = strtok(NULL, "\n");
	}
}

struct run_debug_state {
	pid_t pid;
};

static void run_debug_done(struct tevent_req *subreq);

static struct tevent_req *run_debug_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct eventd_context *ectx,
					 enum ctdb_event event, pid_t pid)
{
	struct tevent_req *req, *subreq;
	struct run_debug_state *state;
	const char **argv;
	const char *debug_script;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct run_debug_state);
	if (req == NULL) {
		return NULL;
	}

	state->pid = pid;

	debug_script = eventd_debug_script(ectx);
	if (debug_script == NULL) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (pid == -1) {
		D_DEBUG("Script terminated, nothing to debug\n");
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	ret = debug_args(state, debug_script, event, pid, &argv);
	if (ret != 0) {
		D_ERR("debug_args() failed\n");
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	D_DEBUG("Running debug %s with args \"%s %s\"\n",
		debug_script, argv[1], argv[2]);

	subreq = run_proc_send(state, ev, ectx->run_ctx, debug_script, argv,
			       tevent_timeval_zero());
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, run_debug_done, req);

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
 * Utility functions for running a single event
 */

static int script_filter(const struct dirent *de)
{
	size_t namelen = strlen(de->d_name);
	char *ptr;

	/* Ignore . and .. */
	if (namelen < 3) {
		return 0;
	}

	/* Skip filenames with ~ */
	ptr = strchr(de->d_name, '~');
	if (ptr != NULL) {
		return 0;
	}

	/* Filename should start with [0-9][0-9]. */
	if ((! isdigit(de->d_name[0])) ||
	    (! isdigit(de->d_name[1])) ||
	    (de->d_name[2] != '.')) {
		return 0;
	}

	/* Ignore file names longer than MAX_SCRIPT_NAME */
	if (namelen > MAX_SCRIPT_NAME) {
		return 0;
	}

	return 1;
}

static int get_script_list(TALLOC_CTX *mem_ctx,
			   const char *script_dir,
			   struct ctdb_script_list **out)
{
	struct dirent **namelist = NULL;
	struct ctdb_script_list *script_list;
	int count, ret;
	int i;

	script_list = talloc_zero(mem_ctx, struct ctdb_script_list);
	if (script_list == NULL) {
		return ENOMEM;
	}

	count = scandir(script_dir, &namelist, script_filter, alphasort);
	if (count == -1) {
		ret = errno;
		if (ret == ENOENT) {
			D_WARNING("event script dir %s removed\n", script_dir);
		} else {
			D_WARNING("scandir() failed on %s, ret=%d\n",
				  script_dir, ret);
		}
		*out = script_list;
		ret = 0;
		goto done;
	}

	if (count == 0) {
		*out = script_list;
		ret = 0;
		goto done;
	}

	script_list->num_scripts = count;
	script_list->script = talloc_zero_array(script_list,
						struct ctdb_script,
						count);
	if (script_list->script == NULL) {
		ret = ENOMEM;
		talloc_free(script_list);
		goto done;
	}

	for (i=0; i<count; i++) {
		struct ctdb_script *s = &script_list->script[i];
		size_t len;

		len = strlcpy(s->name, namelist[i]->d_name, sizeof(s->name));
		if (len >= sizeof(s->name)) {
			ret = EIO;
			talloc_free(script_list);
			goto done;
		}
	}

	*out = script_list;
	ret = 0;

done:
	if (namelist != NULL && count != -1) {
		for (i=0; i<count; i++) {
			free(namelist[i]);
		}
		free(namelist);
	}
	return ret;
}

static int script_chmod(TALLOC_CTX *mem_ctx, const char *script_dir,
			const char *script_name, bool enable)
{
	DIR *dirp;
	struct dirent *de;
	int ret, new_mode;
	char *filename;
	struct stat st;
	bool found;

	dirp = opendir(script_dir);
	if (dirp == NULL) {
		return errno;
	}

	found = false;
	while ((de = readdir(dirp)) != NULL) {
		if (strcmp(de->d_name, script_name) == 0) {

			/* check for valid script names */
			ret = script_filter(de);
			if (ret == 0) {
				closedir(dirp);
				return EINVAL;
			}

			found = true;
			break;
		}
	}
	closedir(dirp);

	if (! found) {
		return ENOENT;
	}

	filename = talloc_asprintf(mem_ctx, "%s/%s", script_dir, script_name);
	if (filename == NULL) {
		return ENOMEM;
	}

	ret = stat(filename, &st);
	if (ret != 0) {
		ret = errno;
		goto done;
	}

	if (enable) {
		new_mode = st.st_mode | S_IXUSR;
	} else {
		new_mode = st.st_mode & ~(S_IXUSR | S_IXGRP | S_IXOTH);
	}

	ret = chmod(filename, new_mode);
	if (ret != 0) {
		ret = errno;
		goto done;
	}

done:
	talloc_free(filename);
	return ret;
}

static int script_args(TALLOC_CTX *mem_ctx, enum ctdb_event event,
		       const char *arg_str, const char ***out)
{
	const char **argv;
	int argc;

	argv = talloc_array(mem_ctx, const char *, 7);
	if (argv == NULL) {
		return ENOMEM;
	}

	argv[0] = NULL; /* script name */
	argv[1] = ctdb_event_to_string(event);
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
			if (argc >= 7) {
				talloc_free(argv);
				return EINVAL;
			}
			t = NULL;
		}

		talloc_free(str);
	}

	argv[argc] = NULL;
	argc += 1;

	*out = argv;
	return 0;
}

/*
 * Run a single event
 */

struct run_event_state {
	struct tevent_context *ev;
	struct eventd_context *ectx;
	struct timeval timeout;
	enum ctdb_event event;

	struct ctdb_script_list *script_list;
	const char **argv;
	int index;
	int status;
};

static struct tevent_req *run_event_run_script(struct tevent_req *req);
static void run_event_next_script(struct tevent_req *subreq);
static void run_event_debug(struct tevent_req *req, pid_t pid);
static void run_event_debug_done(struct tevent_req *subreq);

static struct tevent_req *run_event_send(TALLOC_CTX *mem_ctx,
					 struct tevent_context *ev,
					 struct eventd_context *ectx,
					 enum ctdb_event event,
					 const char *arg_str,
					 uint32_t timeout)
{
	struct tevent_req *req, *subreq;
	struct run_event_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct run_event_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->ectx = ectx;
	state->event = event;

	ret = get_script_list(state, eventd_script_dir(ectx),
			      &state->script_list);
	if (ret != 0) {
		D_ERR("get_script_list() failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	/* No scripts */
	if (state->script_list->num_scripts == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	ret = script_args(state, event, arg_str, &state->argv);
	if (ret != 0) {
		D_ERR("script_args() failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	if (timeout > 0) {
		state->timeout = tevent_timeval_current_ofs(timeout, 0);
	}
	state->index = 0;
	eventd_start_running(ectx, event, req);

	subreq = run_event_run_script(req);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, run_event_next_script, req);

	return req;
}

static struct tevent_req *run_event_run_script(struct tevent_req *req)
{
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);
	struct ctdb_script *script;
	struct tevent_req *subreq;
	char *path;

	script = &state->script_list->script[state->index];

	path = talloc_asprintf(state, "%s/%s",
			       eventd_script_dir(state->ectx), script->name);
	if (path == NULL) {
		return NULL;
	}

	state->argv[0] = script->name;
	script->start = tevent_timeval_current();

	D_DEBUG("Running %s with args \"%s %s\"\n",
		path, state->argv[0], state->argv[1]);

	subreq = run_proc_send(state, state->ev, state->ectx->run_ctx,
			       path, state->argv, state->timeout);

	talloc_free(path);

	return subreq;
}

static void run_event_next_script(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);
	struct ctdb_script *script;
	char *output;
	struct run_proc_result result;
	pid_t pid;
	int ret;
	bool status;

	script = &state->script_list->script[state->index];
	script->finished = tevent_timeval_current();

	status = run_proc_recv(subreq, &ret, &result, &pid, state, &output);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("run_proc failed for %s, ret=%d\n", script->name, ret);
		tevent_req_error(req, ret);
		return;
	}

	D_DEBUG("Script %s finished sig=%d, err=%d, status=%d\n",
		script->name, result.sig, result.err, result.status);

	if (output != NULL) {
		debug_log(DEBUG_ERR, output, script->name);
	}

	if (result.sig > 0) {
		script->status = -EINTR;
	} else if (result.err > 0) {
		if (result.err == EACCES) {
			/* Map EACCESS to ENOEXEC */
			script->status = -ENOEXEC;
		} else {
			script->status = -result.err;
		}
	} else {
		script->status = result.status;
	}

	if (script->status != 0 && output != NULL) {
		size_t n;

		n = strlcpy(script->output, output, MAX_SCRIPT_OUTPUT);
		if (n >= MAX_SCRIPT_OUTPUT) {
			script->output[MAX_SCRIPT_OUTPUT] = '\0';
		}
	}

	/* If a script fails, stop running */
	if (script->status != 0 && script->status != -ENOEXEC) {
		state->status = script->status;
		eventd_stop_running(state->ectx);
		state->script_list->num_scripts = state->index + 1;
		eventd_set_result(state->ectx, state->event,
				  state->script_list, state->status);

		if (state->status == -ETIME && pid != -1) {
			run_event_debug(req, pid);
		}

		D_ERR("%s event %s\n", ctdb_event_to_string(state->event),
		      (state->status == -ETIME) ? "timed out" : "failed");

		tevent_req_done(req);
		return;
	}

	state->index += 1;

	/* All scripts executed */
	if (state->index >= state->script_list->num_scripts) {
		eventd_stop_running(state->ectx);
		eventd_set_result(state->ectx, state->event,
				  state->script_list, state->status);
		tevent_req_done(req);
		return;
	}

	subreq = run_event_run_script(req);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, run_event_next_script, req);
}

static void run_event_debug(struct tevent_req *req, pid_t pid)
{
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);
	struct tevent_req *subreq;

	/* Debug script is run with ectx as the memory context */
	subreq = run_debug_send(state->ectx, state->ev, state->ectx,
				state->event, pid);
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

static bool run_event_recv(struct tevent_req *req, int *perr, int *status)
{
	struct run_event_state *state = tevent_req_data(
		req, struct run_event_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (ret == ECANCELED) {
			if (status != NULL) {
				*status = -ECANCELED;
			}
			return true;
		}

		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (status != NULL) {
		*status = state->status;
	}
	return true;
}

/*
 * Process RUN command
 */

struct command_run_state {
	struct tevent_context *ev;
	struct eventd_context *ectx;
	struct eventd_client *client;

	enum ctdb_event event;
	uint32_t timeout;
	const char *arg_str;
	struct ctdb_event_reply *reply;
};

static void command_run_trigger(struct tevent_req *req, void *private_data);
static void command_run_done(struct tevent_req *subreq);

static struct tevent_req *command_run_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct eventd_context *ectx,
					   struct eventd_client *client,
					   struct ctdb_event_request *request)
{
	struct tevent_req *req;
	struct command_run_state *state;
	struct pending_event *pending;
	enum ctdb_event running_event;
	bool running, status;

	req = tevent_req_create(mem_ctx, &state, struct command_run_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;
	state->ectx = ectx;
	state->client = client;

	state->event = request->rdata.data.run->event;
	state->timeout = request->rdata.data.run->timeout;
	state->arg_str = talloc_steal(state, request->rdata.data.run->arg_str);

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;

	/*
	 * If monitor event is running,
	 *   Cancel the running monitor event and run new event
	 *
	 * If any other event is running,
	 *   If new event is monitor, cancel that event
	 *   Else add new event to the queue
	 */

	running = eventd_is_running(ectx, &running_event);
	if (running) {
		if (running_event == CTDB_EVENT_MONITOR) {
			eventd_cancel_running(ectx);
		} else if (state->event == CTDB_EVENT_MONITOR) {
			state->reply->rdata.result = -ECANCELED;
			tevent_req_done(req);
			return tevent_req_post(req, ev);
		}
	}

	pending = talloc_zero(state, struct pending_event);
	if (tevent_req_nomem(pending, req)) {
		return tevent_req_post(req, ev);
	}

	pending->req = req;
	DLIST_ADD(client->pending_list, pending);

	status = tevent_queue_add(eventd_queue(ectx), ev, req,
				  command_run_trigger, pending);
	if (! status) {
		tevent_req_error(req, ENOMEM);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void command_run_trigger(struct tevent_req *req, void *private_data)
{
	struct pending_event *pending = talloc_get_type_abort(
		private_data, struct pending_event);
	struct command_run_state *state = tevent_req_data(
		req, struct command_run_state);
	struct tevent_req *subreq;

	DLIST_REMOVE(state->client->pending_list, pending);

	if (pending->req != req) {
		tevent_req_error(req, EIO);
		return;
	}

	talloc_free(pending);

	D_DEBUG("Running event %s with args \"%s\"\n",
		ctdb_event_to_string(state->event), state->arg_str);

	subreq = run_event_send(state, state->ev, state->ectx,
				state->event, state->arg_str, state->timeout);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, command_run_done, req);
}

static void command_run_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct command_run_state *state = tevent_req_data(
		req, struct command_run_state);
	int ret, result;
	bool status;

	status = run_event_recv(subreq, &ret, &result);
	if (! status) {
		tevent_req_error(req, ret);
		return;
	}

	state->reply->rdata.result = result;
	tevent_req_done(req);
}

static bool command_run_recv(struct tevent_req *req, int *perr,
			     TALLOC_CTX *mem_ctx,
			     struct ctdb_event_reply **reply)
{
	struct command_run_state *state = tevent_req_data(
		req, struct command_run_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process STATUS command
 */

struct command_status_state {
	struct ctdb_event_reply *reply;
};

static struct tevent_req *command_status_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct eventd_context *ectx,
					struct eventd_client *client,
					struct ctdb_event_request *request)
{
	struct tevent_req *req;
	struct command_status_state *state;
	enum ctdb_event event;
	enum ctdb_event_status_state estate;

	req = tevent_req_create(mem_ctx, &state, struct command_status_state);
	if (req == NULL) {
		return NULL;
	}

	event = request->rdata.data.status->event;
	estate = request->rdata.data.status->state;

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.data.status =
		talloc(state->reply, struct ctdb_event_reply_status);
	if (tevent_req_nomem(state->reply->rdata.data.status, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;
	state->reply->rdata.result = 0;
	state->reply->rdata.data.status->status =
		eventd_get_result(ectx, event, estate,
				&state->reply->rdata.data.status->script_list);

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool command_status_recv(struct tevent_req *req, int *perr,
				TALLOC_CTX *mem_ctx,
				struct ctdb_event_reply **reply)
{
	struct command_status_state *state = tevent_req_data(
		req, struct command_status_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process SCRIPT_LIST command
 */

struct command_script_list_state {
	struct ctdb_event_reply *reply;
};

static struct tevent_req *command_script_list_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct eventd_context *ectx,
					struct eventd_client *client,
					struct ctdb_event_request *request)
{
	struct tevent_req *req;
	struct command_script_list_state *state;
	struct ctdb_script_list *script_list;
	int ret, i;

	req = tevent_req_create(mem_ctx, &state,
				struct command_script_list_state);
	if (req == NULL) {
		return NULL;
	}

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.data.script_list =
		talloc(state->reply, struct ctdb_event_reply_script_list);
	if (tevent_req_nomem(state->reply->rdata.data.script_list, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;

	ret = get_script_list(state, eventd_script_dir(ectx), &script_list);
	if (ret != 0) {
		state->reply->rdata.result = -ret;
		state->reply->rdata.data.script_list->script_list = NULL;

		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	for (i=0; i<script_list->num_scripts; i++) {
		struct ctdb_script *script = &script_list->script[i];
		struct stat st;
		char *path = NULL;

		path = talloc_asprintf(state, "%s/%s",
				       eventd_script_dir(ectx), script->name);
		if (tevent_req_nomem(path, req)) {
			continue;
		}

		ret = stat(path, &st);
		if (ret != 0) {
			TALLOC_FREE(path);
			continue;
		}

		if (! (st.st_mode & S_IXUSR)) {
			script->status = -ENOEXEC;
		}

		TALLOC_FREE(path);
	}

	state->reply->rdata.data.script_list->script_list =
		talloc_steal(state->reply, script_list);

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool command_script_list_recv(struct tevent_req *req, int *perr,
				     TALLOC_CTX *mem_ctx,
				     struct ctdb_event_reply **reply)
{
	struct command_script_list_state *state = tevent_req_data(
		req, struct command_script_list_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process SCRIPT_ENABLE command
 */

struct command_script_enable_state {
	struct ctdb_event_reply *reply;
};

static struct tevent_req *command_script_enable_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct eventd_context *ectx,
					struct eventd_client *client,
					struct ctdb_event_request *request)
{
	struct tevent_req *req;
	struct command_script_enable_state *state;
	const char *script_name;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct command_script_enable_state);
	if (req == NULL) {
		return NULL;
	}

	script_name = request->rdata.data.script_enable->script_name;

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;

	ret = script_chmod(state, eventd_script_dir(ectx), script_name, true);
	state->reply->rdata.result = -ret;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool command_script_enable_recv(struct tevent_req *req, int *perr,
				       TALLOC_CTX *mem_ctx,
				       struct ctdb_event_reply **reply)
{
	struct command_script_enable_state *state = tevent_req_data(
		req, struct command_script_enable_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process SCRIPT_DISABLE command
 */

struct command_script_disable_state {
	struct ctdb_event_reply *reply;
};

static struct tevent_req *command_script_disable_send(
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					struct eventd_context *ectx,
					struct eventd_client *client,
					struct ctdb_event_request *request)
{
	struct tevent_req *req;
	struct command_script_disable_state *state;
	const char *script_name;
	int ret;

	req = tevent_req_create(mem_ctx, &state,
				struct command_script_disable_state);
	if (req == NULL) {
		return NULL;
	}

	script_name = request->rdata.data.script_disable->script_name;

	state->reply = talloc_zero(state, struct ctdb_event_reply);
	if (tevent_req_nomem(state->reply, req)) {
		return tevent_req_post(req, ev);
	}

	state->reply->rdata.command = request->rdata.command;

	ret = script_chmod(state, eventd_script_dir(ectx), script_name, false);
	state->reply->rdata.result = -ret;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static bool command_script_disable_recv(struct tevent_req *req, int *perr,
					TALLOC_CTX *mem_ctx,
					struct ctdb_event_reply **reply)
{
	struct command_script_disable_state *state = tevent_req_data(
		req, struct command_script_disable_state);
	int ret;

	if (tevent_req_is_unix_error(req, &ret)) {
		if (perr != NULL) {
			*perr = ret;
		}
		return false;
	}

	if (reply != NULL) {
		*reply = talloc_steal(mem_ctx, state->reply);
	}
	return true;
}

/*
 * Process clients
 */

static struct eventd_client *client_find(struct eventd_context *ectx,
					 struct sock_client_context *client_ctx)
{
	struct eventd_client *client;

	for (client = ectx->client_list;
	     client != NULL;
	     client = client->next) {
		if (client->client_ctx == client_ctx) {
			return client;
		}
	}

	return NULL;
}

static bool client_connect(struct sock_client_context *client_ctx,
			   void *private_data)
{
	struct eventd_context *ectx = talloc_get_type_abort(
		private_data, struct eventd_context);
	struct eventd_client *client;

	client = talloc_zero(ectx, struct eventd_client);
	if (client == NULL) {
		return false;
	}

	client->client_ctx = client_ctx;

	DLIST_ADD(ectx->client_list, client);
	return true;
}

static void client_disconnect(struct sock_client_context *client_ctx,
			      void *private_data)
{
	struct eventd_context *ectx = talloc_get_type_abort(
		private_data, struct eventd_context);
	struct eventd_client *client;
	struct pending_event *pe;

	client = client_find(ectx, client_ctx);
	if (client == NULL) {
		return;
	}

	/* Get rid of pending events */
	while ((pe = client->pending_list) != NULL) {
		DLIST_REMOVE(client->pending_list, pe);
		talloc_free(pe->req);
	}
}

struct client_process_state {
	struct tevent_context *ev;

	struct eventd_client *client;
	struct ctdb_event_request request;
};

static void client_run_done(struct tevent_req *subreq);
static void client_status_done(struct tevent_req *subreq);
static void client_script_list_done(struct tevent_req *subreq);
static void client_script_enable_done(struct tevent_req *subreq);
static void client_script_disable_done(struct tevent_req *subreq);
static void client_process_reply(struct tevent_req *req,
				 struct ctdb_event_reply *reply);
static void client_process_reply_done(struct tevent_req *subreq);

static struct tevent_req *client_process_send(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct sock_client_context *client_ctx,
				uint8_t *buf, size_t buflen,
				void *private_data)
{
	struct eventd_context *ectx = talloc_get_type_abort(
		private_data, struct eventd_context);
	struct tevent_req *req, *subreq;
	struct client_process_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct client_process_state);
	if (req == NULL) {
		return NULL;
	}

	state->ev = ev;

	state->client = client_find(ectx, client_ctx);
	if (state->client == NULL) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	ret = ctdb_event_request_pull(buf, buflen, state, &state->request);
	if (ret != 0) {
		tevent_req_error(req, EPROTO);
		return tevent_req_post(req, ev);
	}

	switch (state->request.rdata.command) {
	case CTDB_EVENT_COMMAND_RUN:
		subreq = command_run_send(state, ev, ectx, state->client,
					  &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_run_done, req);
		break;

	case CTDB_EVENT_COMMAND_STATUS:
		subreq = command_status_send(state, ev, ectx, state->client,
					     &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_status_done, req);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_LIST:
		subreq = command_script_list_send(state, ev, ectx,
						  state->client,
						  &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_script_list_done, req);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_ENABLE:
		subreq = command_script_enable_send(state, ev, ectx,
						    state->client,
						    &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_script_enable_done,
					req);
		break;

	case CTDB_EVENT_COMMAND_SCRIPT_DISABLE:
		subreq = command_script_disable_send(state, ev, ectx,
						     state->client,
						     &state->request);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, client_script_disable_done,
					req);
		break;
	}

	return req;
}

static void client_run_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_run_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_RUN failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_status_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_status_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_STATUS failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_script_list_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_script_list_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_SCRIPT_LIST failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_script_enable_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_script_enable_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_SCRIPT_ENABLE failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_script_disable_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct ctdb_event_reply *reply = NULL;
	int ret = 0;
	bool status;

	status = command_script_disable_recv(subreq, &ret, state, &reply);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("COMMAND_SCRIPT_DISABLE failed\n");
		tevent_req_error(req, ret);
		return;
	}

	client_process_reply(req, reply);
	talloc_free(reply);
}

static void client_process_reply(struct tevent_req *req,
				 struct ctdb_event_reply *reply)
{
	struct client_process_state *state = tevent_req_data(
		req, struct client_process_state);
	struct tevent_req *subreq;
	uint8_t *buf;
	size_t buflen;
	int ret;

	ctdb_event_header_fill(&reply->header, state->request.header.reqid);

	buflen = ctdb_event_reply_len(reply);
	buf = talloc_zero_size(state, buflen);
	if (tevent_req_nomem(buf, req)) {
		return;
	}

	ret = ctdb_event_reply_push(reply, buf, &buflen);
	if (ret != 0) {
		talloc_free(buf);
		tevent_req_error(req, ret);
		return;
	}

	subreq = sock_socket_write_send(state, state->ev,
					state->client->client_ctx,
					buf, buflen);
	if (tevent_req_nomem(subreq, req)) {
		return;
	}
	tevent_req_set_callback(subreq, client_process_reply_done, req);
}

static void client_process_reply_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	int ret;
	bool status;

	status = sock_socket_write_recv(subreq, &ret);
	TALLOC_FREE(subreq);
	if (! status) {
		D_ERR("Sending reply failed\n");
		tevent_req_error(req, ret);
		return;
	}

	tevent_req_done(req);
}

static bool client_process_recv(struct tevent_req *req, int *perr)
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
 * Event daemon
 */

static void eventd_shutdown(void *private_data)
{
	struct eventd_context *ectx = talloc_get_type_abort(
		private_data, struct eventd_context);
	struct eventd_client *client;

	while ((client = ectx->client_list) != NULL) {
		DLIST_REMOVE(ectx->client_list, client);
		talloc_free(client);
	}
}

static struct {
	const char *debug_script;
	const char *script_dir;
	const char *logging;
	const char *debug_level;
	const char *pidfile;
	const char *socket;
	int pid;
} options = {
	.debug_level = "ERR",
};

struct poptOption cmdline_options[] = {
	POPT_AUTOHELP
	{ "debug_script", 'D', POPT_ARG_STRING, &options.debug_script, 0,
		"debug script", "FILE" },
	{ "pid", 'P', POPT_ARG_INT, &options.pid, 0,
		"pid to wait for", "PID" },
	{ "event_script_dir", 'e', POPT_ARG_STRING, &options.script_dir, 0,
		"event script dir", "DIRECTORY" },
	{ "logging", 'l', POPT_ARG_STRING, &options.logging, 0,
		"logging specification" },
	{ "debug", 'd', POPT_ARG_STRING, &options.debug_level, 0,
		"debug level" },
	{ "pidfile", 'p', POPT_ARG_STRING, &options.pidfile, 0,
		"eventd pid file", "FILE" },
	{ "socket", 's', POPT_ARG_STRING, &options.socket, 0,
		"eventd socket path", "FILE" },
	POPT_TABLEEND
};

int main(int argc, const char **argv)
{
	poptContext pc;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	struct eventd_context *ectx;
	struct sock_daemon_context *sockd;
	struct sock_daemon_funcs daemon_funcs;
	struct sock_socket_funcs socket_funcs;
	struct stat statbuf;
	int opt, ret;

	/* Set default options */
	options.pid = -1;

	pc = poptGetContext(argv[0], argc, argv, cmdline_options,
			    POPT_CONTEXT_KEEP_FIRST);
	while ((opt = poptGetNextOpt(pc)) != -1) {
		fprintf(stderr, "Invalid options %s: %s\n",
			poptBadOption(pc, 0), poptStrerror(opt));
		exit(1);
	}

	if (options.socket == NULL) {
		fprintf(stderr, "Please specify eventd socket (--socket)\n");
		exit(1);
	}

	if (options.script_dir == NULL) {
		fprintf(stderr,
			"Please specify script dir (--event_script_dir)\n");
		exit(1);
	}

	if (options.logging == NULL) {
		fprintf(stderr,
			"Please specify logging (--logging)\n");
		exit(1);
	}

	ret = stat(options.script_dir, &statbuf);
	if (ret != 0) {
		ret = errno;
		fprintf(stderr, "Error reading script_dir %s, ret=%d\n",
			options.script_dir, ret);
		exit(1);
	}
	if (! S_ISDIR(statbuf.st_mode)) {
		fprintf(stderr, "script_dir %s is not a directory\n",
			options.script_dir);
		exit(1);
	}

	mem_ctx = talloc_new(NULL);
	if (mem_ctx == NULL) {
		exit(1);
	}

	ev = tevent_context_init(mem_ctx);
	if (ev == NULL) {
		ret = 1;
		goto fail;
	}

	ret = eventd_context_init(mem_ctx, ev, options.script_dir,
				  options.debug_script, &ectx);
	if (ret != 0) {
		goto fail;
	}

	daemon_funcs = (struct sock_daemon_funcs) {
		.shutdown = eventd_shutdown,
	};

	ret = sock_daemon_setup(mem_ctx, "ctdb-eventd", options.logging,
				options.debug_level, options.pidfile,
				&daemon_funcs, ectx, &sockd);
	if (ret != 0) {
		goto fail;
	}

	socket_funcs = (struct sock_socket_funcs) {
		.connect = client_connect,
		.disconnect = client_disconnect,
		.read_send = client_process_send,
		.read_recv = client_process_recv,
	};

	ret = sock_daemon_add_unix(sockd, options.socket, &socket_funcs, ectx);
	if (ret != 0) {
		goto fail;
	}

	ret = sock_daemon_run(ev, sockd, options.pid);
	if (ret == EINTR) {
		ret = 0;
	}

fail:
	talloc_free(mem_ctx);
	(void)poptFreeContext(pc);
	exit(ret);
}
