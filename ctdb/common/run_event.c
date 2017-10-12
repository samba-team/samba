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
#include "system/locale.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/util/tevent_unix.h"
#include "lib/util/debug.h"

#include "common/logging.h"
#include "common/run_proc.h"
#include "common/run_event.h"

/*
 * Utility functions
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

	/* Ignore filenames with multiple '.'s */
	ptr = index(&de->d_name[3], '.');
	if (ptr != NULL) {
		return 0;
	}

	return 1;
}

static int get_script_list(TALLOC_CTX *mem_ctx,
			   const char *script_dir,
			   struct run_event_script_list **out)
{
	struct dirent **namelist = NULL;
	struct run_event_script_list *script_list;
	int count, ret;
	int i;

	count = scandir(script_dir, &namelist, script_filter, alphasort);
	if (count == -1) {
		ret = errno;
		if (ret == ENOENT) {
			D_WARNING("event script dir %s removed\n", script_dir);
		} else {
			D_WARNING("scandir() failed on %s, ret=%d\n",
				  script_dir, ret);
		}
		*out = NULL;
		ret = 0;
		goto done;
	}

	if (count == 0) {
		*out = NULL;
		ret = 0;
		goto done;
	}

	script_list = talloc_zero(mem_ctx, struct run_event_script_list);
	if (script_list == NULL) {
		return ENOMEM;
	}

	script_list->num_scripts = count;
	script_list->script = talloc_zero_array(script_list,
						struct run_event_script,
						count);
	if (script_list->script == NULL) {
		ret = ENOMEM;
		talloc_free(script_list);
		goto done;
	}

	for (i=0; i<count; i++) {
		struct run_event_script *s = &script_list->script[i];

		s->name = talloc_strdup(script_list, namelist[i]->d_name);
		if (s->name == NULL) {
			ret = ENOMEM;
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
	int fd = -1;

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

	fd = open(filename, O_RDWR);
	if (fd == -1) {
		ret = errno;
		goto done;
	}

	ret = fstat(fd, &st);
	if (ret != 0) {
		ret = errno;
		goto done;
	}

	if (enable) {
		new_mode = st.st_mode | (S_IXUSR | S_IXGRP | S_IXOTH);
	} else {
		new_mode = st.st_mode & ~(S_IXUSR | S_IXGRP | S_IXOTH);
	}

	ret = fchmod(fd, new_mode);
	if (ret != 0) {
		ret = errno;
		goto done;
	}

done:
	if (fd != -1) {
		close(fd);
	}
	talloc_free(filename);
	return ret;
}

static int script_args(TALLOC_CTX *mem_ctx, const char *event_str,
		       const char *arg_str, const char ***out)
{
	const char **argv;
	int argc;
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
	argc += 1;

	*out = argv;
	return 0;
}

struct run_event_context {
	struct run_proc_context *run_proc_ctx;
	const char *script_dir;
	const char *debug_prog;
	bool debug_running;
};


int run_event_init(TALLOC_CTX *mem_ctx, struct tevent_context *ev,
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

	ret = run_proc_init(run_ctx, ev, &run_ctx->run_proc_ctx);
	if (ret != 0) {
		talloc_free(run_ctx);
		return ret;
	}

	ret = stat(script_dir, &st);
	if (ret != 0) {
		ret = errno;
		talloc_free(run_ctx);
		return ret;
	}

	if (! S_ISDIR(st.st_mode)) {
		talloc_free(run_ctx);
		return EINVAL;
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

int run_event_script_list(struct run_event_context *run_ctx,
			  TALLOC_CTX *mem_ctx,
			  struct run_event_script_list **output)
{
	struct run_event_script_list *script_list;
	int ret, i;

	ret = get_script_list(mem_ctx, run_event_script_dir(run_ctx),
			      &script_list);
	if (ret != 0) {
		return ret;
	}

	if (script_list == NULL) {
		*output = NULL;
		return 0;
	}

	for (i=0; i<script_list->num_scripts; i++) {
		struct run_event_script *script = &script_list->script[i];
		struct stat st;
		char *path = NULL;

		path = talloc_asprintf(mem_ctx, "%s/%s",
				       run_event_script_dir(run_ctx),
				       script->name);
		if (path == NULL) {
			continue;
		}

		ret = stat(path, &st);
		if (ret != 0) {
			TALLOC_FREE(path);
			continue;
		}

		if (! (st.st_mode & S_IXUSR)) {
			script->summary = -ENOEXEC;
		}

		TALLOC_FREE(path);
	}

	*output = script_list;
	return 0;
}

int run_event_script_enable(struct run_event_context *run_ctx,
			    const char *script_name)
{
	return script_chmod(run_ctx, run_event_script_dir(run_ctx),
			    script_name, true);
}

int run_event_script_disable(struct run_event_context *run_ctx,
			     const char *script_name)
{
	return script_chmod(run_ctx, run_event_script_dir(run_ctx),
			    script_name, false);
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
	struct timeval timeout;

	struct run_event_script_list *script_list;
	const char **argv;
	int index;
	int status;
};

static struct tevent_req *run_event_run_script(struct tevent_req *req);
static void run_event_next_script(struct tevent_req *subreq);
static void run_event_debug(struct tevent_req *req, pid_t pid);
static void run_event_debug_done(struct tevent_req *subreq);

struct tevent_req *run_event_send(TALLOC_CTX *mem_ctx,
				  struct tevent_context *ev,
				  struct run_event_context *run_ctx,
				  const char *event_str,
				  const char *arg_str,
				  struct timeval timeout)
{
	struct tevent_req *req, *subreq;
	struct run_event_state *state;
	int ret;

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
	state->timeout = timeout;

	ret = get_script_list(state, run_event_script_dir(run_ctx),
			      &state->script_list);
	if (ret != 0) {
		D_ERR("get_script_list() failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	/* No scripts */
	if (state->script_list == NULL ||
	    state->script_list->num_scripts == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	ret = script_args(state, event_str, arg_str, &state->argv);
	if (ret != 0) {
		D_ERR("script_args() failed, ret=%d\n", ret);
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}

	state->index = 0;

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
	struct run_event_script *script;
	struct tevent_req *subreq;
	char *path;

	script = &state->script_list->script[state->index];

	path = talloc_asprintf(state, "%s/%s",
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
	if (! status) {
		D_ERR("run_proc failed for %s, ret=%d\n", script->name, ret);
		tevent_req_error(req, ret);
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
		state->script_list->num_scripts = state->index + 1;

		if (script->summary == -ETIME && pid != -1) {
			run_event_debug(req, pid);
		}

		state->script_list->summary = script->summary;
		D_NOTICE("%s event %s\n", state->event_str,
			 (script->summary == -ETIME) ? "timed out" : "failed");

		tevent_req_done(req);
		return;
	}

	state->index += 1;

	/* All scripts executed */
	if (state->index >= state->script_list->num_scripts) {
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

