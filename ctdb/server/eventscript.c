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
#include "lib/events/events.h"
#include "../common/rb_tree.h"

static struct {
	struct timeval start;
	const char *script_running;
} child_state;

static void ctdb_event_script_timeout(struct event_context *ev, struct timed_event *te, struct timeval t, void *p);

/*
  ctdbd sends us a SIGTERM when we should time out the current script
 */
static void sigterm(int sig)
{
	char tbuf[100], buf[200];
	time_t t;

	DEBUG(DEBUG_ERR,("Timed out running script '%s' after %.1f seconds pid :%d\n", 
		 child_state.script_running, timeval_elapsed(&child_state.start), getpid()));

	t = time(NULL);

	strftime(tbuf, sizeof(tbuf)-1, "%Y%m%d%H%M%S", 	localtime(&t));
	sprintf(buf, "{ pstree -p; cat /proc/locks; ls -li /var/ctdb/ /var/ctdb/persistent; }"
		" >/tmp/ctdb.event.%s.%d", tbuf, getpid());
	system(buf);

	DEBUG(DEBUG_ERR,("Logged timedout eventscript : %s\n", buf));

	/* all the child processes will be running in the same process group */
	kill(-getpgrp(), SIGKILL);
	_exit(1);
}

struct ctdb_event_script_state {
	struct ctdb_context *ctdb;
	pid_t child;
	/* Warning: this can free us! */
	void (*callback)(struct ctdb_context *, int, void *);
	int cb_status;
	int fd[2];
	void *private_data;
	bool from_user;
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
	struct ctdb_script_wire *current = get_current_script(state);
	unsigned int slen, min;

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

struct ctdb_script_tree_item {
	const char *name;
	int error;
};

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
		DEBUG(DEBUG_INFO,("Event script %s is not executable. Ignoring this event script\n", full));
		errno = ENOEXEC;
		talloc_free(full);
		return false;
	}

	talloc_free(full);
	return true;
}

static struct ctdb_scripts_wire *ctdb_get_script_list(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx)
{
	DIR *dir;
	struct dirent *de;
	struct stat st;
	trbt_tree_t *tree;
	struct ctdb_scripts_wire *scripts;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_script_tree_item *tree_item;
	int count;

	/*
	  the service specific event scripts 
	*/
	if (stat(ctdb->event_script_dir, &st) != 0 && 
	    errno == ENOENT) {
		DEBUG(DEBUG_CRIT,("No event script directory found at '%s'\n", ctdb->event_script_dir));
		talloc_free(tmp_ctx);
		return NULL;
	}

	/* create a tree to store all the script names in */
	tree = trbt_create(tmp_ctx, 0);

	/* scan all directory entries and insert all valid scripts into the 
	   tree
	*/
	dir = opendir(ctdb->event_script_dir);
	if (dir == NULL) {
		DEBUG(DEBUG_CRIT,("Failed to open event script directory '%s'\n", ctdb->event_script_dir));
		talloc_free(tmp_ctx);
		return NULL;
	}

	count = 0;
	while ((de=readdir(dir)) != NULL) {
		int namlen;
		unsigned num;

		namlen = strlen(de->d_name);

		if (namlen < 3) {
			continue;
		}

		if (de->d_name[namlen-1] == '~') {
			/* skip files emacs left behind */
			continue;
		}

		if (de->d_name[2] != '.') {
			continue;
		}

		if (sscanf(de->d_name, "%02u.", &num) != 1) {
			continue;
		}

		if (strlen(de->d_name) > MAX_SCRIPT_NAME) {
			DEBUG(DEBUG_ERR,("Script name %s too long! %u chars max",
					 de->d_name, MAX_SCRIPT_NAME));
			continue;
		}

		tree_item = talloc(tree, struct ctdb_script_tree_item);
		if (tree_item == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to allocate new tree item\n"));
			talloc_free(tmp_ctx);
			return NULL;
		}
	
		tree_item->error = 0;
		if (!check_executable(ctdb->event_script_dir, de->d_name)) {
			tree_item->error = errno;
		}

		tree_item->name = talloc_strdup(tree_item, de->d_name);
		if (tree_item->name == NULL) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to allocate script name.\n"));
			talloc_free(tmp_ctx);
			return NULL;
		}

		/* store the event script in the tree */
		trbt_insert32(tree, (num<<16)|count++, tree_item);
	}
	closedir(dir);

	/* Overallocates by one, but that's OK */
	scripts = talloc_zero_size(tmp_ctx,
				   sizeof(*scripts)
				   + sizeof(scripts->scripts[0]) * count);
	if (scripts == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " Failed to allocate scripts\n"));
		talloc_free(tmp_ctx);
		return NULL;
	}
	scripts->num_scripts = count;

	for (count = 0; count < scripts->num_scripts; count++) {
		tree_item = trbt_findfirstarray32(tree, 1);

		strcpy(scripts->scripts[count].name, tree_item->name);
		scripts->scripts[count].status = -tree_item->error;

		/* remove this script from the tree */
		talloc_free(tree_item);
	}

	talloc_steal(mem_ctx, scripts);
	talloc_free(tmp_ctx);
	return scripts;
}

static int child_setup(struct ctdb_context *ctdb)
{
	if (setpgid(0,0) != 0) {
		int ret = -errno;
		DEBUG(DEBUG_ERR,("Failed to create process group for event scripts - %s\n",
			 strerror(errno)));
		return ret;
	}

	signal(SIGTERM, sigterm);
	return 0;
}

static char *child_command_string(struct ctdb_context *ctdb,
				       TALLOC_CTX *ctx,
				       bool from_user,
				       const char *scriptname,
				       enum ctdb_eventscript_call call,
				       const char *options)
{
	const char *str = from_user ? "CTDB_CALLED_BY_USER=1 " : "";

	/* Allow a setting where we run the actual monitor event
	   from an external source and replace it with
	   a "status" event that just picks up the actual
	   status of the event asynchronously.
	*/
	if ((ctdb->tunable.use_status_events_for_monitoring != 0)
	    &&  (call == CTDB_EVENT_MONITOR)
	    &&  !from_user) {
		return talloc_asprintf(ctx, "%s%s/%s %s",
				       str,
				       ctdb->event_script_dir,
				       scriptname, "status");
	} else {
		return talloc_asprintf(ctx, "%s%s/%s %s %s",
				       str,
				       ctdb->event_script_dir,
				       scriptname,
				       ctdb_eventscript_call_names[call],
				       options);
	}
}

static int child_run_one(struct ctdb_context *ctdb,
			 const char *scriptname, const char *cmdstr)
{
	int ret;

	ret = system(cmdstr);
	/* if the system() call was successful, translate ret into the
	   return code from the command
	*/
	if (ret != -1) {
		ret = WEXITSTATUS(ret);
	} else {
		ret = -errno;
	}

	/* 127 could mean it does not exist, 126 non-executable. */
	if (ret == 127 || ret == 126) {
		/* Re-check it... */
		if (!check_executable(ctdb->event_script_dir, scriptname)) {
			DEBUG(DEBUG_ERR,("Script %s returned status %u. Someone just deleted it?\n",
					 cmdstr, ret));
			ret = -errno;
		}
	}
	return ret;
}

/*
  Actually run one event script
  this function is called and run in the context of a forked child
  which allows it to do blocking calls such as system()
 */
static int child_run_script(struct ctdb_context *ctdb,
			    bool from_user,
			    enum ctdb_eventscript_call call,
			    const char *options,
			    struct ctdb_script_wire *current)
{
	char *cmdstr;
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);

	child_state.start = timeval_current();
	ret = child_setup(ctdb);
	if (ret != 0)
		goto out;

	cmdstr = child_command_string(ctdb, tmp_ctx, from_user,
				      current->name, call, options);
	CTDB_NO_MEMORY(ctdb, cmdstr);
	child_state.script_running = cmdstr;

	DEBUG(DEBUG_INFO,("Executing event script %s\n",cmdstr));

	if (current->status) {
		ret = current->status;
		goto out;
	}

	ret = child_run_one(ctdb, current->name, cmdstr);
out:
	talloc_free(tmp_ctx);
	return ret;
}

static void ctdb_event_script_handler(struct event_context *ev, struct fd_event *fde,
				      uint16_t flags, void *p);

static int fork_child_for_script(struct ctdb_context *ctdb,
				 struct ctdb_event_script_state *state)
{
	int r;
	struct ctdb_script_wire *current = get_current_script(state);

	current->start = timeval_current();

	r = pipe(state->fd);
	if (r != 0) {
		DEBUG(DEBUG_ERR, (__location__ " pipe failed for child eventscript process\n"));
		return -errno;
	}

 	if (!ctdb_fork_with_logging(state, ctdb, log_event_script_output,
				    state, &state->child)) {
		r = -errno;
		close(state->fd[0]);
		close(state->fd[1]);
		return r;
	}

	/* If we are the child, do the work. */
	if (state->child == 0) {
		int rt;

		close(state->fd[0]);
		set_close_on_exec(state->fd[1]);

		rt = child_run_script(ctdb, state->from_user, state->call, state->options, current);
		/* We must be able to write PIPEBUF bytes at least; if this
		   somehow fails, the read above will be short. */
		write(state->fd[1], &rt, sizeof(rt));
		close(state->fd[1]);
		_exit(rt);
	}

	close(state->fd[1]);
	set_close_on_exec(state->fd[0]);

	DEBUG(DEBUG_DEBUG, (__location__ " Created PIPE FD:%d to child eventscript process\n", state->fd[0]));

	/* Set ourselves up to be called when that's done. */
	event_add_fd(ctdb->ev, state, state->fd[0], EVENT_FD_READ|EVENT_FD_AUTOCLOSE,
		     ctdb_event_script_handler, state);
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
	int r;

	r = read(state->fd[0], &current->status, sizeof(current->status));
	if (r < 0) {
		current->status = -errno;
	} else if (r != sizeof(current->status)) {
		current->status = -EIO;
	}

	current->finished = timeval_current();

	/* update overall status based on this script. */
	state->cb_status = current->status;

	/* don't stop just because it vanished or was disabled. */
	if (current->status == -ENOENT || current->status == -ENOEXEC) {
		state->cb_status = 0;
	}

	/* valgrind gets overloaded if we run next script as it's still doing
	 * post-execution analysis, so kill finished child here. */
	if (ctdb->valgrinding) {
		kill(state->child, SIGKILL);
	}

	state->child = 0;

	/* Aborted or finished all scripts?  We're done. */
	if (state->cb_status != 0 || state->current+1 == state->scripts->num_scripts) {
		DEBUG(DEBUG_INFO,(__location__ " Eventscript %s %s finished with state %d\n",
				  ctdb_eventscript_call_names[state->call], state->options, state->cb_status));

		ctdb->event_script_timeouts = 0;
		talloc_free(state);
		return;
	}

	/* Forget about that old fd. */
	talloc_free(fde);

	/* Next script! */
	state->current++;
	state->cb_status = fork_child_for_script(ctdb, state);
	if (state->cb_status != 0) {
		/* This calls the callback. */
		talloc_free(state);
	}
}

/* called when child times out */
static void ctdb_event_script_timeout(struct event_context *ev, struct timed_event *te, 
				      struct timeval t, void *p)
{
	struct ctdb_event_script_state *state = talloc_get_type(p, struct ctdb_event_script_state);
	struct ctdb_context *ctdb = state->ctdb;

	DEBUG(DEBUG_ERR,("Event script timed out : %s %s count : %u  pid : %d\n",
			 ctdb_eventscript_call_names[state->call], state->options, ctdb->event_script_timeouts, state->child));

	state->cb_status = -ETIME;

	if (kill(state->child, 0) != 0) {
		DEBUG(DEBUG_ERR,("Event script child process already dead, errno %s(%d)\n", strerror(errno), errno));
		state->child = 0;
	}

	state->scripts->scripts[state->current].status = state->cb_status;

	talloc_free(state);
}

/*
  destroy an event script: kill it if ->child != 0.
 */
static int event_script_destructor(struct ctdb_event_script_state *state)
{
	if (state->child) {
		DEBUG(DEBUG_ERR,(__location__ " Sending SIGTERM to child pid:%d\n", state->child));

		if (kill(state->child, SIGTERM) != 0) {
			DEBUG(DEBUG_ERR,("Failed to kill child process for eventscript, errno %s(%d)\n", strerror(errno), errno));
		}
	}

	/* If we were the current monitor, we no longer are. */
	if (state->ctdb->current_monitor == state) {
		state->ctdb->current_monitor = NULL;
	}

	/* Save our scripts as the last executed status, if we have them. */
	if (state->scripts) {
		talloc_free(state->ctdb->last_status[state->call]);
		state->ctdb->last_status[state->call] = state->scripts;
		if (state->current < state->ctdb->last_status[state->call]->num_scripts) {
			state->ctdb->last_status[state->call]->num_scripts = state->current+1;
		}
	}

	/* This is allowed to free us; talloc will prevent double free anyway,
	 * but beware if you call this outside the destructor! */
	if (state->callback) {
		state->callback(state->ctdb, state->cb_status, state->private_data);
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
	case CTDB_EVENT_STARTUP:
	case CTDB_EVENT_START_RECOVERY:
	case CTDB_EVENT_RECOVERED:
	case CTDB_EVENT_STOPPED:
	case CTDB_EVENT_MONITOR:
	case CTDB_EVENT_STATUS:
	case CTDB_EVENT_SHUTDOWN:
	case CTDB_EVENT_RELOAD:
		return count_words(options) == 0;

	case CTDB_EVENT_TAKE_IP: /* interface, IP address, netmask bits. */
	case CTDB_EVENT_RELEASE_IP:
		return count_words(options) == 3;

	default:
		DEBUG(DEBUG_ERR,(__location__ "Unknown ctdb_eventscript_call %u\n", call));
		return false;
	}
}

/*
  run the event script in the background, calling the callback when 
  finished
 */
static int ctdb_event_script_callback_v(struct ctdb_context *ctdb, 
					void (*callback)(struct ctdb_context *, int, void *),
					void *private_data,
					bool from_user,
					enum ctdb_eventscript_call call,
					const char *fmt, va_list ap)
{
	struct ctdb_event_script_state *state;
	int ret;

	state = talloc(ctdb->event_script_ctx, struct ctdb_event_script_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->ctdb = ctdb;
	state->callback = callback;
	state->private_data = private_data;
	state->from_user = from_user;
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
		DEBUG(DEBUG_ERR, ("Bad eventscript options '%s' for %s\n",
				  ctdb_eventscript_call_names[state->call], state->options));
		talloc_free(state);
		return -1;
	}

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		/* we guarantee that only some specifically allowed event scripts are run
		   while in recovery */
		const enum ctdb_eventscript_call allowed_calls[] = {
			CTDB_EVENT_START_RECOVERY, CTDB_EVENT_SHUTDOWN, CTDB_EVENT_RELEASE_IP, CTDB_EVENT_STOPPED };
		int i;
		for (i=0;i<ARRAY_SIZE(allowed_calls);i++) {
			if (call == allowed_calls[i]) break;
		}
		if (i == ARRAY_SIZE(allowed_calls)) {
			DEBUG(DEBUG_ERR,("Refusing to run event scripts call '%s' while in recovery\n",
				 ctdb_eventscript_call_names[call]));
			talloc_free(state);
			return -1;
		}
	}

	/* Kill off any running monitor events to run this event. */
	if (ctdb->current_monitor) {
		/* Discard script status so we don't save to last_status */
		talloc_free(ctdb->current_monitor->scripts);
		ctdb->current_monitor->scripts = NULL;
		talloc_free(ctdb->current_monitor);
		ctdb->current_monitor = NULL;
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

	/* Nothing to do? */
	if (state->scripts->num_scripts == 0) {
		ctdb->event_script_timeouts = 0;
		talloc_free(state->scripts);
		talloc_free(state);
		return 0;
	}

	ret = fork_child_for_script(ctdb, state);
	if (ret != 0) {
		talloc_free(state->scripts);
		talloc_free(state);
		return -1;
	}

	if (!from_user && (call == CTDB_EVENT_MONITOR || call == CTDB_EVENT_STATUS)) {
		ctdb->current_monitor = state;
	}

	talloc_set_destructor(state, event_script_destructor);
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
  finished
 */
int ctdb_event_script_callback(struct ctdb_context *ctdb, 
			       TALLOC_CTX *mem_ctx,
			       void (*callback)(struct ctdb_context *, int, void *),
			       void *private_data,
			       bool from_user,
			       enum ctdb_eventscript_call call,
			       const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = ctdb_event_script_callback_v(ctdb, callback, private_data, from_user, call, fmt, ap);
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
	ret = ctdb_event_script_callback_v(ctdb,
			event_script_callback, &status, false, call, fmt, ap);
	if (ret != 0) {
		return ret;
	}
	va_end(ap);

	status.status = -1;
	status.done = false;

	while (status.done == false && event_loop_once(ctdb->ev) == 0) /* noop */;

	if (status.status == -ETIME) {
		DEBUG(DEBUG_ERR, (__location__ " eventscript for '%s' timedout."
				  " Immediately banning ourself for %d seconds\n",
				  ctdb_eventscript_call_names[call],
				  ctdb->tunable.recovery_ban_period));
		ctdb_ban_self(ctdb);
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

	ctdb_enable_monitoring(ctdb);

	if (status != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to forcibly run eventscripts\n"));
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
		DEBUG(DEBUG_ERR, (__location__ " Invalid forced \"%s\"\n", (const char *)indata.dptr));
		return -1;
	}

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_ERR, (__location__ " Aborted running eventscript \"%s\" while in RECOVERY mode\n", indata.dptr));
		return -1;
	}

	state = talloc(ctdb->event_script_ctx, struct eventscript_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(state, c);

	DEBUG(DEBUG_NOTICE,("Forced running of eventscripts with arguments %s\n", indata.dptr));

	ctdb_disable_monitoring(ctdb);

	ret = ctdb_event_script_callback(ctdb, 
			 state, run_eventscripts_callback, state,
			 true, call, "%s", options);

	if (ret != 0) {
		ctdb_enable_monitoring(ctdb);
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
