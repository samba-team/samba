/* 
   event script handling

   Copyright (C) Andrew Tridgell  2007

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

#include "includes.h"
#include <time.h>
#include "system/filesys.h"
#include "system/wait.h"
#include "system/dir.h"
#include "system/locale.h"
#include "../include/ctdb_private.h"
#include "../common/rb_tree.h"
#include "lib/util/dlinklist.h"

static void ctdb_event_script_timeout(struct event_context *ev, struct timed_event *te, struct timeval t, void *p);

/* This is attached to the event script state. */
struct event_script_callback {
	struct event_script_callback *next, *prev;
	struct ctdb_context *ctdb;

	/* Warning: this can free us! */
	void (*fn)(struct ctdb_context *, int, void *);
	void *private_data;
};
	

struct ctdb_event_script_state {
	struct ctdb_context *ctdb;
	struct event_script_callback *callback;
	pid_t child;
	int fd[2];
	enum ctdb_eventscript_call call;
	const char *options;
	struct timeval timeout;
	
	unsigned int current;
	struct ctdb_scripts_wire *scripts;
};

static struct ctdb_script_wire *get_current_script(struct ctdb_event_script_state *state)
{
	return &state->scripts->scripts[state->current];
}

/* called from ctdb_logging when we have received output on STDERR from
 * one of the eventscripts
 */
static void log_event_script_output(const char *str, uint16_t len, void *p)
{
	struct ctdb_event_script_state *state
		= talloc_get_type(p, struct ctdb_event_script_state);
	struct ctdb_script_wire *current;
	unsigned int slen, min;

	/* We may have been aborted to run something else.  Discard */
	if (state->scripts == NULL) {
		return;
	}

	current = get_current_script(state);

	/* Append, but don't overfill buffer.  It starts zero-filled. */
	slen = strlen(current->output);
	min = MIN(len, sizeof(current->output) - slen - 1);

	memcpy(current->output + slen, str, min);
}

int32_t ctdb_control_get_event_script_status(struct ctdb_context *ctdb,
					     uint32_t call_type,
					     TDB_DATA *outdata)
{
	if (call_type >= CTDB_EVENT_MAX) {
		return -1;
	}

	if (ctdb->last_status[call_type] == NULL) {
		/* If it's never been run, return nothing so they can tell. */
		outdata->dsize = 0;
	} else {
		outdata->dsize = talloc_get_size(ctdb->last_status[call_type]);
		outdata->dptr  = (uint8_t *)ctdb->last_status[call_type];
	}
	return 0;
}

/* To ignore directory entry return 0, else return non-zero */
static int script_filter(const struct dirent *de)
{
	int namelen = strlen(de->d_name);

	/* Ignore . and .. */
	if (namelen < 3) {
		return 0;
	}

	/* Skip temporary files left behind by emacs */
	if (de->d_name[namelen-1] == '~') {
		return 0;
	}

	/* Filename should start with [0-9][0-9]. */
	if (!isdigit(de->d_name[0]) || !isdigit(de->d_name[1]) ||
	    de->d_name[2] != '.') {
		return 0;
	}

	if (namelen > MAX_SCRIPT_NAME) {
		return 0;
	}

	return 1;
}

/* Return true if OK, otherwise set errno. */
static bool check_executable(const char *dir, const char *name)
{
	char *full;
	struct stat st;

	full = talloc_asprintf(NULL, "%s/%s", dir, name);
	if (!full)
		return false;

	if (stat(full, &st) != 0) {
		DEBUG(DEBUG_ERR,("Could not stat event script %s: %s\n",
				 full, strerror(errno)));
		talloc_free(full);
		return false;
	}

	if (!(st.st_mode & S_IXUSR)) {
		DEBUG(DEBUG_DEBUG,("Event script %s is not executable. Ignoring this event script\n", full));
		errno = ENOEXEC;
		talloc_free(full);
		return false;
	}

	talloc_free(full);
	return true;
}

static struct ctdb_scripts_wire *ctdb_get_script_list(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx)
{
	struct dirent **namelist;
	struct ctdb_scripts_wire *scripts;
	int i, count;

	/* scan all directory entries and insert all valid scripts into the 
	   tree
	*/
	count = scandir(ctdb->event_script_dir, &namelist, script_filter, alphasort);
	if (count == -1) {
		DEBUG(DEBUG_CRIT, ("Failed to read event script directory '%s' - %s\n",
				   ctdb->event_script_dir, strerror(errno)));
		return NULL;
	}

	/* Overallocates by one, but that's OK */
	scripts = talloc_zero_size(mem_ctx,
				   sizeof(*scripts)
				   + sizeof(scripts->scripts[0]) * count);
	if (scripts == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to allocate scripts\n"));
		goto done;
	}
	scripts->num_scripts = count;

	for (i = 0; i < count; i++) {
		struct ctdb_script_wire *s = &scripts->scripts[i];

		if (strlcpy(s->name, namelist[i]->d_name, sizeof(s->name)) >=
		    sizeof(s->name)) {
			s->status = -ENAMETOOLONG;
			continue;
		}

		s->status = 0;
		if (!check_executable(ctdb->event_script_dir,
				      namelist[i]->d_name)) {
			s->status = -errno;
		}
	}

done:
	for (i=0; i<count; i++) {
		free(namelist[i]);
	}
	free(namelist);
	return scripts;
}


/* There cannot be more than 10 arguments to command helper. */
#define MAX_HELPER_ARGS		(10)

static bool child_helper_args(TALLOC_CTX *mem_ctx, struct ctdb_context *ctdb,
			      enum ctdb_eventscript_call call,
			      const char *options,
			      struct ctdb_script_wire *current, int fd,
			      int *argc, const char ***argv)
{
	const char **tmp;
	int n, i;
	char *t, *saveptr, *opt;

	tmp = talloc_array(mem_ctx, const char *, 10+1);
	if (tmp == NULL)  goto failed;

	tmp[0] = talloc_asprintf(tmp, "%d", fd);
	tmp[1] = talloc_asprintf(tmp, "%s/%s", ctdb->event_script_dir, current->name);
	tmp[2] = talloc_asprintf(tmp, "%s", ctdb_eventscript_call_names[call]);
	n = 3;

	/* Split options into individual arguments */
	opt = talloc_strdup(mem_ctx, options);
	if (opt == NULL) {
		goto failed;
	}

	t = strtok_r(opt, " ", &saveptr);
	while (t != NULL) {
		tmp[n++] = talloc_strdup(tmp, t);
		if (n > MAX_HELPER_ARGS) {
			goto args_failed;
		}
		t = strtok_r(NULL, " ", &saveptr);
	}

	for (i=0; i<n; i++) {
		if (tmp[i] == NULL) {
			goto failed;
		}
	}

	/* Last argument should be NULL */
	tmp[n++] = NULL;

	*argc = n;
	*argv = tmp;
	return true;


args_failed:
	DEBUG(DEBUG_ERR, (__location__ " too many arguments '%s' to eventscript '%s'\n",
			  options, ctdb_eventscript_call_names[call]));

failed:
	if (tmp) {
		talloc_free(tmp);
	}
	return false;

}

static void ctdb_event_script_handler(struct event_context *ev, struct fd_event *fde,
				      uint16_t flags, void *p);

static const char *helper_prog = NULL;

static int fork_child_for_script(struct ctdb_context *ctdb,
				 struct ctdb_event_script_state *state)
{
	int r;
	struct tevent_fd *fde;
	struct ctdb_script_wire *current = get_current_script(state);
	int argc;
	const char **argv;
	static const char *helper = CTDB_HELPER_BINDIR "/ctdb_event_helper";

	if (helper_prog == NULL) {
		const char *t = getenv("CTDB_EVENT_HELPER");
		if (t != NULL) {
			helper_prog = t;
		} else {
			helper_prog = helper;
		}
	}

	current->start = timeval_current();

	r = pipe(state->fd);
	if (r != 0) {
		DEBUG(DEBUG_ERR, (__location__ " pipe failed for child eventscript process\n"));
		return -errno;
	}

	/* Arguments for helper */
	if (!child_helper_args(state, ctdb, state->call, state->options, current,
			       state->fd[1], &argc, &argv)) {
		DEBUG(DEBUG_ERR, (__location__ " failed to create arguments for eventscript helper\n"));
		r = -ENOMEM;
		close(state->fd[0]);
		close(state->fd[1]);
		return r;
	}

	if (!ctdb_vfork_with_logging(state, ctdb, current->name,
				     helper_prog, argc, argv,
				     log_event_script_output,
				     state, &state->child)) {
		talloc_free(argv);
		r = -errno;
		close(state->fd[0]);
		close(state->fd[1]);
		return r;
	}

	talloc_free(argv);

	close(state->fd[1]);
	set_close_on_exec(state->fd[0]);

	/* Set ourselves up to be called when that's done. */
	fde = event_add_fd(ctdb->ev, state, state->fd[0], EVENT_FD_READ,
			   ctdb_event_script_handler, state);
	tevent_fd_set_auto_close(fde);

	return 0;
}

/*
 Summarize status of this run of scripts.
 */
static int script_status(struct ctdb_scripts_wire *scripts)
{
	unsigned int i;

	for (i = 0; i < scripts->num_scripts; i++) {
		switch (scripts->scripts[i].status) {
		case -ENAMETOOLONG:
		case -ENOENT:
		case -ENOEXEC:
			/* Disabled or missing; that's OK. */
			break;
		case 0:
			/* No problem. */
			break;
		default:
			return scripts->scripts[i].status;
		}
	}

	/* All OK! */
	return 0;
}

/* called when child is finished */
static void ctdb_event_script_handler(struct event_context *ev, struct fd_event *fde, 
				      uint16_t flags, void *p)
{
	struct ctdb_event_script_state *state = 
		talloc_get_type(p, struct ctdb_event_script_state);
	struct ctdb_script_wire *current = get_current_script(state);
	struct ctdb_context *ctdb = state->ctdb;
	int r, status;

	if (ctdb == NULL) {
		DEBUG(DEBUG_ERR,("Eventscript finished but ctdb is NULL\n"));
		return;
	}

	r = sys_read(state->fd[0], &current->status, sizeof(current->status));
	if (r < 0) {
		current->status = -errno;
	} else if (r != sizeof(current->status)) {
		current->status = -EIO;
	}

	current->finished = timeval_current();
	/* valgrind gets overloaded if we run next script as it's still doing
	 * post-execution analysis, so kill finished child here. */
	if (ctdb->valgrinding) {
		ctdb_kill(ctdb, state->child, SIGKILL);
	}

	state->child = 0;

	status = script_status(state->scripts);

	/* Aborted or finished all scripts?  We're done. */
	if (status != 0 || state->current+1 == state->scripts->num_scripts) {
		DEBUG(DEBUG_INFO,(__location__ " Eventscript %s %s finished with state %d\n",
				  ctdb_eventscript_call_names[state->call], state->options, status));

		ctdb->event_script_timeouts = 0;
		talloc_free(state);
		return;
	}

	/* Forget about that old fd. */
	talloc_free(fde);

	/* Next script! */
	state->current++;
	current++;
	current->status = fork_child_for_script(ctdb, state);
	if (current->status != 0) {
		/* This calls the callback. */
		talloc_free(state);
	}
}

struct debug_hung_script_state {
	struct ctdb_context *ctdb;
	pid_t child;
	enum ctdb_eventscript_call call;
};

static int debug_hung_script_state_destructor(struct debug_hung_script_state *state)
{
	if (state->child) {
		ctdb_kill(state->ctdb, state->child, SIGKILL);
	}
	return 0;
}

static void debug_hung_script_timeout(struct tevent_context *ev, struct tevent_timer *te,
				      struct timeval t, void *p)
{
	struct debug_hung_script_state *state =
		talloc_get_type(p, struct debug_hung_script_state);

	talloc_free(state);
}

static void debug_hung_script_done(struct tevent_context *ev, struct tevent_fd *fde,
				   uint16_t flags, void *p)
{
	struct debug_hung_script_state *state =
		talloc_get_type(p, struct debug_hung_script_state);

	talloc_free(state);
}

static void ctdb_run_debug_hung_script(struct ctdb_context *ctdb, struct debug_hung_script_state *state)
{
	pid_t pid;
	const char * debug_hung_script = CTDB_ETCDIR "/debug-hung-script.sh";
	int fd[2];
	struct tevent_timer *ttimer;
	struct tevent_fd *tfd;
	const char **argv;
	int i;

	if (pipe(fd) < 0) {
		DEBUG(DEBUG_ERR,("Failed to create pipe fd for debug hung script\n"));
		return;
	}

	if (getenv("CTDB_DEBUG_HUNG_SCRIPT") != NULL) {
		debug_hung_script = getenv("CTDB_DEBUG_HUNG_SCRIPT");
	}

	argv = talloc_array(state, const char *, 5);

	argv[0] = talloc_asprintf(argv, "%d", fd[1]);
	argv[1] = talloc_strdup(argv, debug_hung_script);
	argv[2] = talloc_asprintf(argv, "%d", state->child);
	argv[3] = talloc_strdup(argv, ctdb_eventscript_call_names[state->call]);
	argv[4] = NULL;

	for (i=0; i<4; i++) {
		if (argv[i] == NULL) {
			close(fd[0]);
			close(fd[1]);
			talloc_free(argv);
			return;
		}
	}


	if (!ctdb_vfork_with_logging(state, ctdb, "Hung-script",
				     helper_prog, 5, argv, NULL, NULL, &pid)) {
		DEBUG(DEBUG_ERR,("Failed to fork a child to track hung event script\n"));
		talloc_free(argv);
		close(fd[0]);
		close(fd[1]);
		return;
	}

	talloc_free(argv);
	close(fd[1]);

	ttimer = tevent_add_timer(ctdb->ev, state,
				  timeval_current_ofs(ctdb->tunable.script_timeout, 0),
				  debug_hung_script_timeout, state);
	if (ttimer == NULL) {
		close(fd[0]);
		return;
	}

	tfd = tevent_add_fd(ctdb->ev, state, fd[0], EVENT_FD_READ,
			    debug_hung_script_done, state);
	if (tfd == NULL) {
		talloc_free(ttimer);
		close(fd[0]);
		return;
	}
	tevent_fd_set_auto_close(tfd);
}

/* called when child times out */
static void ctdb_event_script_timeout(struct event_context *ev, struct timed_event *te, 
				      struct timeval t, void *p)
{
	struct ctdb_event_script_state *state = talloc_get_type(p, struct ctdb_event_script_state);
	struct ctdb_context *ctdb = state->ctdb;
	struct ctdb_script_wire *current = get_current_script(state);
	struct debug_hung_script_state *debug_state;

	DEBUG(DEBUG_ERR,("Event script '%s %s %s' timed out after %.1fs, count: %u, pid: %d\n",
			 current->name, ctdb_eventscript_call_names[state->call], state->options,
			 timeval_elapsed(&current->start),
			 ctdb->event_script_timeouts, state->child));

	/* ignore timeouts for these events */
	switch (state->call) {
	case CTDB_EVENT_START_RECOVERY:
	case CTDB_EVENT_RECOVERED:
	case CTDB_EVENT_TAKE_IP:
	case CTDB_EVENT_RELEASE_IP:
		state->scripts->scripts[state->current].status = 0;
		DEBUG(DEBUG_ERR,("Ignoring hung script for %s call %d\n", state->options, state->call));
		break;
        default:
		state->scripts->scripts[state->current].status = -ETIME;
	}

	debug_state = talloc_zero(ctdb, struct debug_hung_script_state);
	if (debug_state == NULL) {
		talloc_free(state);
		return;
	}

	/* Save information useful for running debug hung script, so
	 * eventscript state can be freed.
	 */
	debug_state->ctdb = ctdb;
	debug_state->child = state->child;
	debug_state->call = state->call;

	/* This destructor will actually kill the hung event script */
	talloc_set_destructor(debug_state, debug_hung_script_state_destructor);

	state->child = 0;
	talloc_free(state);

	ctdb_run_debug_hung_script(ctdb, debug_state);
}

/*
  destroy an event script: kill it if ->child != 0.
 */
static int event_script_destructor(struct ctdb_event_script_state *state)
{
	int status;
	struct event_script_callback *callback;

	if (state->child) {
		DEBUG(DEBUG_ERR,(__location__ " Sending SIGTERM to child pid:%d\n", state->child));

		if (ctdb_kill(state->ctdb, state->child, SIGTERM) != 0) {
			DEBUG(DEBUG_ERR,("Failed to kill child process for eventscript, errno %s(%d)\n", strerror(errno), errno));
		}
	}

	/* If we were the current monitor, we no longer are. */
	if (state->ctdb->current_monitor == state) {
		state->ctdb->current_monitor = NULL;
	}

	/* Save our scripts as the last executed status, if we have them.
	 * See ctdb_event_script_callback_v where we abort monitor event. */
	if (state->scripts) {
		talloc_free(state->ctdb->last_status[state->call]);
		state->ctdb->last_status[state->call] = state->scripts;
		if (state->current < state->ctdb->last_status[state->call]->num_scripts) {
			state->ctdb->last_status[state->call]->num_scripts = state->current+1;
		}
	}

	/* Use last status as result, or "OK" if none. */
	if (state->ctdb->last_status[state->call]) {
		status = script_status(state->ctdb->last_status[state->call]);
	} else {
		status = 0;
	}

	state->ctdb->active_events--;
	if (state->ctdb->active_events < 0) {
		ctdb_fatal(state->ctdb, "Active events < 0");
	}

	/* This is allowed to free us; talloc will prevent double free anyway,
	 * but beware if you call this outside the destructor!
	 * the callback hangs off a different context so we walk the list
	 * of "active" callbacks until we find the one state points to.
	 * if we cant find it it means the callback has been removed.
	 */
	for (callback = state->ctdb->script_callbacks; callback != NULL; callback = callback->next) {
		if (callback == state->callback) {
			break;
		}
	}
	
	state->callback = NULL;

	if (callback) {
		/* Make sure destructor doesn't free itself! */
		talloc_steal(NULL, callback);
		callback->fn(state->ctdb, status, callback->private_data);
		talloc_free(callback);
	}

	return 0;
}

static unsigned int count_words(const char *options)
{
	unsigned int words = 0;

	options += strspn(options, " \t");
	while (*options) {
		words++;
		options += strcspn(options, " \t");
		options += strspn(options, " \t");
	}
	return words;
}

static bool check_options(enum ctdb_eventscript_call call, const char *options)
{
	switch (call) {
	/* These all take no arguments. */
	case CTDB_EVENT_INIT:
	case CTDB_EVENT_SETUP:
	case CTDB_EVENT_STARTUP:
	case CTDB_EVENT_START_RECOVERY:
	case CTDB_EVENT_RECOVERED:
	case CTDB_EVENT_MONITOR:
	case CTDB_EVENT_SHUTDOWN:
	case CTDB_EVENT_IPREALLOCATED:
		return count_words(options) == 0;

	case CTDB_EVENT_TAKE_IP: /* interface, IP address, netmask bits. */
	case CTDB_EVENT_RELEASE_IP:
		return count_words(options) == 3;

	case CTDB_EVENT_UPDATE_IP: /* old interface, new interface, IP address, netmask bits. */
		return count_words(options) == 4;

	default:
		DEBUG(DEBUG_ERR,(__location__ "Unknown ctdb_eventscript_call %u\n", call));
		return false;
	}
}

static int remove_callback(struct event_script_callback *callback)
{
	DLIST_REMOVE(callback->ctdb->script_callbacks, callback);
	return 0;
}

/*
  run the event script in the background, calling the callback when 
  finished
 */
static int ctdb_event_script_callback_v(struct ctdb_context *ctdb,
					const void *mem_ctx,
					void (*callback)(struct ctdb_context *, int, void *),
					void *private_data,
					enum ctdb_eventscript_call call,
					const char *fmt, va_list ap)
{
	struct ctdb_event_script_state *state;

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		/* we guarantee that only some specifically allowed event scripts are run
		   while in recovery */
		const enum ctdb_eventscript_call allowed_calls[] = {
			CTDB_EVENT_INIT,
			CTDB_EVENT_SETUP,
			CTDB_EVENT_START_RECOVERY,
			CTDB_EVENT_SHUTDOWN,
			CTDB_EVENT_RELEASE_IP,
			CTDB_EVENT_IPREALLOCATED,
		};
		int i;
		for (i=0;i<ARRAY_SIZE(allowed_calls);i++) {
			if (call == allowed_calls[i]) break;
		}
		if (i == ARRAY_SIZE(allowed_calls)) {
			DEBUG(DEBUG_ERR,("Refusing to run event scripts call '%s' while in recovery\n",
				 ctdb_eventscript_call_names[call]));
			return -1;
		}
	}

	/* Do not run new monitor events if some event is already running */
	if (call == CTDB_EVENT_MONITOR && ctdb->active_events > 0) {
		if (callback != NULL) {
			callback(ctdb, -ECANCELED, private_data);
		}
		return 0;
	}

	/* Kill off any running monitor events to run this event. */
	if (ctdb->current_monitor) {
		struct ctdb_event_script_state *ms = talloc_get_type(ctdb->current_monitor, struct ctdb_event_script_state);

		/* Cancel current monitor callback state only if monitoring
		 * context ctdb->monitor->monitor_context has not been freed */
		if (ms->callback != NULL && !ctdb_stopped_monitoring(ctdb)) {
			ms->callback->fn(ctdb, -ECANCELED, ms->callback->private_data);
			talloc_free(ms->callback);
		}

		/* Discard script status so we don't save to last_status */
		talloc_free(ctdb->current_monitor->scripts);
		ctdb->current_monitor->scripts = NULL;
		talloc_free(ctdb->current_monitor);
		ctdb->current_monitor = NULL;
	}

	state = talloc(ctdb->event_script_ctx, struct ctdb_event_script_state);
	CTDB_NO_MEMORY(ctdb, state);

	/* The callback isn't done if the context is freed. */
	state->callback = talloc(mem_ctx, struct event_script_callback);
	CTDB_NO_MEMORY(ctdb, state->callback);
	DLIST_ADD(ctdb->script_callbacks, state->callback);
	talloc_set_destructor(state->callback, remove_callback);
	state->callback->ctdb         = ctdb;
	state->callback->fn           = callback;
	state->callback->private_data = private_data;

	state->ctdb = ctdb;
	state->call = call;
	state->options = talloc_vasprintf(state, fmt, ap);
	state->timeout = timeval_set(ctdb->tunable.script_timeout, 0);
	state->scripts = NULL;
	if (state->options == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " could not allocate state->options\n"));
		talloc_free(state);
		return -1;
	}
	if (!check_options(state->call, state->options)) {
		DEBUG(DEBUG_ERR, ("Bad eventscript options '%s' for '%s'\n",
				  state->options,
				  ctdb_eventscript_call_names[state->call]));
		talloc_free(state);
		return -1;
	}

	DEBUG(DEBUG_INFO,(__location__ " Starting eventscript %s %s\n",
			  ctdb_eventscript_call_names[state->call],
			  state->options));

	/* This is not a child of state, since we save it in destructor. */
	state->scripts = ctdb_get_script_list(ctdb, ctdb);
	if (state->scripts == NULL) {
		talloc_free(state);
		return -1;
	}
	state->current = 0;
	state->child = 0;

	if (call == CTDB_EVENT_MONITOR) {
		ctdb->current_monitor = state;
	}

	talloc_set_destructor(state, event_script_destructor);

	ctdb->active_events++;

	/* Nothing to do? */
	if (state->scripts->num_scripts == 0) {
		talloc_free(state);
		return 0;
	}

 	state->scripts->scripts[0].status = fork_child_for_script(ctdb, state);
 	if (state->scripts->scripts[0].status != 0) {
 		/* Callback is called from destructor, with fail result. */
 		talloc_free(state);
 		return 0;
 	}

	if (!timeval_is_zero(&state->timeout)) {
		event_add_timed(ctdb->ev, state, timeval_current_ofs(state->timeout.tv_sec, state->timeout.tv_usec), ctdb_event_script_timeout, state);
	} else {
		DEBUG(DEBUG_ERR, (__location__ " eventscript %s %s called with no timeout\n",
				  ctdb_eventscript_call_names[state->call],
				  state->options));
	}

	return 0;
}


/*
  run the event script in the background, calling the callback when 
  finished.  If mem_ctx is freed, callback will never be called.
 */
int ctdb_event_script_callback(struct ctdb_context *ctdb, 
			       TALLOC_CTX *mem_ctx,
			       void (*callback)(struct ctdb_context *, int, void *),
			       void *private_data,
			       enum ctdb_eventscript_call call,
			       const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = ctdb_event_script_callback_v(ctdb, mem_ctx, callback, private_data, call, fmt, ap);
	va_end(ap);

	return ret;
}


struct callback_status {
	bool done;
	int status;
};

/*
  called when ctdb_event_script() finishes
 */
static void event_script_callback(struct ctdb_context *ctdb, int status, void *private_data)
{
	struct callback_status *s = (struct callback_status *)private_data;
	s->done = true;
	s->status = status;
}

/*
  run the event script, waiting for it to complete. Used when the caller
  doesn't want to continue till the event script has finished.
 */
int ctdb_event_script_args(struct ctdb_context *ctdb, enum ctdb_eventscript_call call,
			   const char *fmt, ...)
{
	va_list ap;
	int ret;
	struct callback_status status;

	va_start(ap, fmt);
	ret = ctdb_event_script_callback_v(ctdb, ctdb,
			event_script_callback, &status, call, fmt, ap);
	va_end(ap);
	if (ret != 0) {
		return ret;
	}

	status.status = -1;
	status.done = false;

	while (status.done == false && event_loop_once(ctdb->ev) == 0) /* noop */;

	if (status.status == -ETIME) {
		DEBUG(DEBUG_ERR, (__location__ " eventscript for '%s' timedout."
				  " Immediately banning ourself for %d seconds\n",
				  ctdb_eventscript_call_names[call],
				  ctdb->tunable.recovery_ban_period));

		/* Don't ban self if CTDB is starting up or shutting down */
		if (call != CTDB_EVENT_INIT && call != CTDB_EVENT_SHUTDOWN) {
			ctdb_ban_self(ctdb);
		}
	}

	return status.status;
}

int ctdb_event_script(struct ctdb_context *ctdb, enum ctdb_eventscript_call call)
{
	/* GCC complains about empty format string, so use %s and "". */
	return ctdb_event_script_args(ctdb, call, "%s", "");
}

struct eventscript_callback_state {
	struct ctdb_req_control *c;
};

/*
  called when a forced eventscript run has finished
 */
static void run_eventscripts_callback(struct ctdb_context *ctdb, int status, 
				 void *private_data)
{
	struct eventscript_callback_state *state = 
		talloc_get_type(private_data, struct eventscript_callback_state);

	if (status != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to run eventscripts\n"));
	}

	ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
	/* This will free the struct ctdb_event_script_state we are in! */
	talloc_free(state);
	return;
}


/* Returns rest of string, or NULL if no match. */
static const char *get_call(const char *p, enum ctdb_eventscript_call *call)
{
	unsigned int len;

	/* Skip any initial whitespace. */
	p += strspn(p, " \t");

	/* See if we match any. */
	for (*call = 0; *call < CTDB_EVENT_MAX; (*call)++) {
		len = strlen(ctdb_eventscript_call_names[*call]);
		if (strncmp(p, ctdb_eventscript_call_names[*call], len) == 0) {
			/* If end of string or whitespace, we're done. */
			if (strcspn(p + len, " \t") == 0) {
				return p + len;
			}
		}
	}
	return NULL;
}

/*
  A control to force running of the eventscripts from the ctdb client tool
*/
int32_t ctdb_run_eventscripts(struct ctdb_context *ctdb,
		struct ctdb_req_control *c,
		TDB_DATA indata, bool *async_reply)
{
	int ret;
	struct eventscript_callback_state *state;
	const char *options;
	enum ctdb_eventscript_call call;

	/* Figure out what call they want. */
	options = get_call((const char *)indata.dptr, &call);
	if (!options) {
		DEBUG(DEBUG_ERR, (__location__ " Invalid event name \"%s\"\n", (const char *)indata.dptr));
		return -1;
	}

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_ERR, (__location__ " Aborted running eventscript \"%s\" while in RECOVERY mode\n", indata.dptr));
		return -1;
	}

	state = talloc(ctdb->event_script_ctx, struct eventscript_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(state, c);

	DEBUG(DEBUG_NOTICE,("Running eventscripts with arguments %s\n", indata.dptr));

	ret = ctdb_event_script_callback(ctdb, 
			 state, run_eventscripts_callback, state,
			 call, "%s", options);

	if (ret != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to run eventscripts with arguments %s\n", indata.dptr));
		talloc_free(state);
		return -1;
	}

	/* tell ctdb_control.c that we will be replying asynchronously */
	*async_reply = true;

	return 0;
}



int32_t ctdb_control_enable_script(struct ctdb_context *ctdb, TDB_DATA indata)
{
	const char *script;
	struct stat st;
	char *filename;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);

	script = (char *)indata.dptr;
	if (indata.dsize == 0) {
		DEBUG(DEBUG_ERR,(__location__ " No script specified.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}
	if (indata.dptr[indata.dsize - 1] != '\0') {
		DEBUG(DEBUG_ERR,(__location__ " String is not null terminated.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}
	if (index(script,'/') != NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Script name contains '/'. Failed to enable script %s\n", script));
		talloc_free(tmp_ctx);
		return -1;
	}


	if (stat(ctdb->event_script_dir, &st) != 0 && 
	    errno == ENOENT) {
		DEBUG(DEBUG_CRIT,("No event script directory found at '%s'\n", ctdb->event_script_dir));
		talloc_free(tmp_ctx);
		return -1;
	}


	filename = talloc_asprintf(tmp_ctx, "%s/%s", ctdb->event_script_dir, script);
	if (filename == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to create script path\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (stat(filename, &st) != 0) {
		DEBUG(DEBUG_ERR,("Could not stat event script %s. Failed to enable script.\n", filename));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (chmod(filename, st.st_mode | S_IXUSR) == -1) {
		DEBUG(DEBUG_ERR,("Could not chmod %s. Failed to enable script.\n", filename));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}

int32_t ctdb_control_disable_script(struct ctdb_context *ctdb, TDB_DATA indata)
{
	const char *script;
	struct stat st;
	char *filename;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);

	script = (char *)indata.dptr;
	if (indata.dsize == 0) {
		DEBUG(DEBUG_ERR,(__location__ " No script specified.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}
	if (indata.dptr[indata.dsize - 1] != '\0') {
		DEBUG(DEBUG_ERR,(__location__ " String is not null terminated.\n"));
		talloc_free(tmp_ctx);
		return -1;
	}
	if (index(script,'/') != NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Script name contains '/'. Failed to disable script %s\n", script));
		talloc_free(tmp_ctx);
		return -1;
	}


	if (stat(ctdb->event_script_dir, &st) != 0 && 
	    errno == ENOENT) {
		DEBUG(DEBUG_CRIT,("No event script directory found at '%s'\n", ctdb->event_script_dir));
		talloc_free(tmp_ctx);
		return -1;
	}


	filename = talloc_asprintf(tmp_ctx, "%s/%s", ctdb->event_script_dir, script);
	if (filename == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to create script path\n"));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (stat(filename, &st) != 0) {
		DEBUG(DEBUG_ERR,("Could not stat event script %s. Failed to disable script.\n", filename));
		talloc_free(tmp_ctx);
		return -1;
	}

	if (chmod(filename, st.st_mode & ~(S_IXUSR|S_IXGRP|S_IXOTH)) == -1) {
		DEBUG(DEBUG_ERR,("Could not chmod %s. Failed to disable script.\n", filename));
		talloc_free(tmp_ctx);
		return -1;
	}

	talloc_free(tmp_ctx);
	return 0;
}
