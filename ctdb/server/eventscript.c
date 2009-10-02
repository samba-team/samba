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

/*
  ctdbd sends us a SIGTERM when we should time out the current script
 */
static void sigterm(int sig)
{
	DEBUG(DEBUG_ERR,("Timed out running script '%s' after %.1f seconds\n", 
		 child_state.script_running, timeval_elapsed(&child_state.start)));
	/* all the child processes will be running in the same process group */
	kill(-getpgrp(), SIGKILL);
	exit(1);
}

struct ctdb_event_script_state {
	struct ctdb_context *ctdb;
	pid_t child;
	void (*callback)(struct ctdb_context *, int, void *);
	int fd[2];
	void *private_data;
	const char *options;
};


struct ctdb_monitor_script_status {
	struct ctdb_monitor_script_status *next;
	const char *name;
	struct timeval start;
	struct timeval finished;
	int32_t disabled;
	int32_t status;
	int32_t timedout;
	char *output;
};

struct ctdb_monitoring_status {
	struct timeval start;
	struct timeval finished;
	int32_t status;
	struct ctdb_monitor_script_status *scripts;
};


/* called from ctdb_logging when we have received output on STDERR from
 * one of the eventscripts
 */
int ctdb_log_event_script_output(struct ctdb_context *ctdb, char *str, uint16_t len)
{
	struct ctdb_monitoring_status *monitoring_status =
		talloc_get_type(ctdb->script_monitoring_ctx,
			struct ctdb_monitoring_status);
	struct ctdb_monitor_script_status *script;

	if (monitoring_status == NULL) {
		return -1;
	}

	script = monitoring_status->scripts;
	if (script == NULL) {
		return -1;
	}

	if (script->output == NULL) {
		script->output = talloc_asprintf(script, "%*.*s", len, len, str);
	} else {
		script->output = talloc_asprintf_append(script->output, "%*.*s", len, len, str);
	}

	return 0;
}

/* called from the event script child process when we are starting a new
 * monitor event
 */
int32_t ctdb_control_event_script_init(struct ctdb_context *ctdb)
{
	struct ctdb_monitoring_status *monitoring_status;

	DEBUG(DEBUG_INFO, ("event script init called\n"));
	if (ctdb->script_monitoring_ctx != NULL) {
		talloc_free(ctdb->script_monitoring_ctx);
		ctdb->script_monitoring_ctx = NULL;
	}

	monitoring_status = talloc_zero(ctdb, struct ctdb_monitoring_status);
	if (monitoring_status == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " ERROR: Failed to talloc script_monitoring context\n"));
		return -1;
	}

	ctdb->script_monitoring_ctx = monitoring_status;
	monitoring_status->start = timeval_current();	

	return 0;
}


/* called from the event script child process when we are star running
 * an eventscript
 */
int32_t ctdb_control_event_script_start(struct ctdb_context *ctdb, TDB_DATA indata)
{
	const char *name = (const char *)indata.dptr;
	struct ctdb_monitoring_status *monitoring_status =
		talloc_get_type(ctdb->script_monitoring_ctx,
			struct ctdb_monitoring_status);
	struct ctdb_monitor_script_status *script;

	DEBUG(DEBUG_INFO, ("event script start called : %s\n", name));

	if (monitoring_status == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " script_status is NULL when starting to run script %s\n", name));
		return -1;
	}

	script = talloc_zero(monitoring_status, struct ctdb_monitor_script_status);
	if (script == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to talloc ctdb_monitor_script_status for script %s\n", name));
		return -1;
	}

	script->next  = monitoring_status->scripts;
	script->name  = talloc_strdup(script, name);
	CTDB_NO_MEMORY(ctdb, script->name);
	script->start = timeval_current();
	monitoring_status->scripts = script;

	return 0;
}

/* called from the event script child process when we have finished running
 * an eventscript
 */
int32_t ctdb_control_event_script_stop(struct ctdb_context *ctdb, TDB_DATA indata)
{
	int32_t res = *((int32_t *)indata.dptr);
	struct ctdb_monitoring_status *monitoring_status =
		talloc_get_type(ctdb->script_monitoring_ctx,
			struct ctdb_monitoring_status);
	struct ctdb_monitor_script_status *script;

	DEBUG(DEBUG_INFO, ("event script stop called : %d\n", (int)res));

	if (monitoring_status == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " script_status is NULL when script finished.\n"));
		return -1;
	}

	script = monitoring_status->scripts;
	if (script == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " script is NULL when the script had finished\n"));
		return -1;
	}

	script->finished = timeval_current();
	script->status   = res;

	return 0;
}

/* called from the event script child process when we have a disabled script
 */
int32_t ctdb_control_event_script_disabled(struct ctdb_context *ctdb, TDB_DATA indata)
{
	int32_t res = *((int32_t *)indata.dptr);
	struct ctdb_monitoring_status *monitoring_status =
		talloc_get_type(ctdb->script_monitoring_ctx,
			struct ctdb_monitoring_status);
	struct ctdb_monitor_script_status *script;

	DEBUG(DEBUG_INFO, ("event script disabed called : %d\n", (int)res));

	if (monitoring_status == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " script_status is NULL when script finished.\n"));
		return -1;
	}

	script = monitoring_status->scripts;
	if (script == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " script is NULL when the script had finished\n"));
		return -1;
	}

	script->finished = timeval_current();
	script->status   = res;
	script->disabled = 1;

	return 0;
}

/* called from the event script child process when we have completed a
 * monitor event
 */
int32_t ctdb_control_event_script_finished(struct ctdb_context *ctdb)
{
	struct ctdb_monitoring_status *monitoring_status =
		talloc_get_type(ctdb->script_monitoring_ctx,
			struct ctdb_monitoring_status);

	DEBUG(DEBUG_INFO, ("event script finished called\n"));

	if (monitoring_status == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " script_status is NULL when monitoring event finished\n"));
		return -1;
	}

	monitoring_status->finished = timeval_current();	
	monitoring_status->status   = MONITOR_SCRIPT_OK;
	if (ctdb->last_monitoring_ctx) {
		talloc_free(ctdb->last_monitoring_ctx);
	}
	ctdb->last_monitoring_ctx = ctdb->script_monitoring_ctx;
	ctdb->script_monitoring_ctx = NULL;

	return 0;
}

static struct ctdb_monitoring_wire *marshall_monitoring_scripts(TALLOC_CTX *mem_ctx, struct ctdb_monitoring_wire *monitoring_scripts, struct ctdb_monitor_script_status *script)
{
	struct ctdb_monitoring_script_wire script_wire;
	size_t size;

	if (script == NULL) {
		return monitoring_scripts;
	}
	monitoring_scripts = marshall_monitoring_scripts(mem_ctx, monitoring_scripts, script->next);
	if (monitoring_scripts == NULL) {
		return NULL;
	}

	bzero(&script_wire, sizeof(struct ctdb_monitoring_script_wire));
	strncpy(script_wire.name, script->name, MAX_SCRIPT_NAME);
	script_wire.start    = script->start;
	script_wire.finished = script->finished;
	script_wire.disabled = script->disabled;
	script_wire.status   = script->status;
	script_wire.timedout = script->timedout;
	if (script->output != NULL) {
		strncpy(script_wire.output, script->output, MAX_SCRIPT_OUTPUT);
	}

	size = talloc_get_size(monitoring_scripts);
	monitoring_scripts = talloc_realloc_size(mem_ctx, monitoring_scripts, size + sizeof(struct ctdb_monitoring_script_wire));
	if (monitoring_scripts == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to talloc_resize monitoring_scripts blob\n"));
		return NULL;
	}

	memcpy(&monitoring_scripts->scripts[monitoring_scripts->num_scripts], &script_wire, sizeof(script_wire));
	monitoring_scripts->num_scripts++;
	
	return monitoring_scripts;
}

int32_t ctdb_control_get_event_script_status(struct ctdb_context *ctdb, TDB_DATA *outdata)
{
	struct ctdb_monitoring_status *monitoring_status =
		talloc_get_type(ctdb->last_monitoring_ctx,
			struct ctdb_monitoring_status);
	struct ctdb_monitoring_wire *monitoring_scripts;

	if (monitoring_status == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " last_monitor_ctx is NULL when reading status\n"));
		return -1;
	}

	monitoring_scripts = talloc_size(outdata, offsetof(struct ctdb_monitoring_wire, scripts));
	if (monitoring_scripts == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " failed to talloc monitoring_scripts structure\n"));
		return -1;
	}
	
	monitoring_scripts->num_scripts = 0;
	monitoring_scripts = marshall_monitoring_scripts(outdata, monitoring_scripts, monitoring_status->scripts);
	if (monitoring_scripts == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " Monitoring scritps is NULL. can not return data to client\n"));
		return -1;
	}

	outdata->dsize = talloc_get_size(monitoring_scripts);
	outdata->dptr  = (uint8_t *)monitoring_scripts;

	return 0;
}

struct ctdb_script_tree_item {
	const char *name;
	int32_t is_enabled;
};

struct ctdb_script_list {
	struct ctdb_script_list *next;
	const char *name;
	int32_t is_enabled;
};

static struct ctdb_script_list *ctdb_get_script_list(struct ctdb_context *ctdb, TALLOC_CTX *mem_ctx)
{
	DIR *dir;
	struct dirent *de;
	struct stat st;
	trbt_tree_t *tree;
	struct ctdb_script_list *head, *tail, *new_item;
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
		char *str;

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

		/* Make sure the event script is executable */
		str = talloc_asprintf(tree, "%s/%s", ctdb->event_script_dir, de->d_name);
		if (stat(str, &st) != 0) {
			DEBUG(DEBUG_ERR,("Could not stat event script %s. Ignoring this event script\n", str));
			continue;
		}


		tree_item = talloc(tree, struct ctdb_script_tree_item);
		if (tree_item == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to allocate new tree item\n"));
			talloc_free(tmp_ctx);
			return NULL;
		}
	
		tree_item->is_enabled = 1;
		if (!(st.st_mode & S_IXUSR)) {
			DEBUG(DEBUG_INFO,("Event script %s is not executable. Ignoring this event script\n", str));
			tree_item->is_enabled = 0;
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


	head = NULL;
	tail = NULL;

	/* fetch the scripts from the tree one by one and add them to the linked
	   list
	 */
	while ((tree_item=trbt_findfirstarray32(tree, 1)) != NULL) {

		new_item = talloc(tmp_ctx, struct ctdb_script_list);
		if (new_item == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to allocate new list item\n"));
			talloc_free(tmp_ctx);
			return NULL;
		}

		new_item->next = NULL;
		new_item->name = talloc_steal(new_item, tree_item->name);
		new_item->is_enabled = tree_item->is_enabled;

		if (head == NULL) {
			head = new_item;
			tail = new_item;
		} else {
			tail->next = new_item;
			tail = new_item;
		}

		talloc_steal(mem_ctx, new_item);

		/* remove this script from the tree */
		talloc_free(tree_item);
	}	

	talloc_free(tmp_ctx);
	return head;
}



/*
  run the event script - varargs version
  this function is called and run in the context of a forked child
  which allows it to do blocking calls such as system()
 */
static int ctdb_event_script_v(struct ctdb_context *ctdb, const char *options)
{
	char *cmdstr;
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct ctdb_script_list *scripts, *current;
	int is_monitor = 0;

	if (!strcmp(options, "monitor")) {
		is_monitor = 1;
	}

	if (is_monitor == 1) {
		/* This is running in the forked child process. At this stage
		 * we want to switch from being a ctdb daemon into being a
		 * client and connect to the real local daemon.
		 */
		if (switch_from_server_to_client(ctdb) != 0) {
			DEBUG(DEBUG_CRIT, (__location__ "ERROR: failed to switch eventscript child into client mode. shutting down.\n"));
			_exit(1);
		}

		if (ctdb_ctrl_event_script_init(ctdb) != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to init event script monitoring\n"));
			talloc_free(tmp_ctx);
			return -1;
		}
	}

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		/* we guarantee that only some specifically allowed event scripts are run
		   while in recovery */
	  const char *allowed_scripts[] = {"startrecovery", "shutdown", "releaseip", "stopped" };
		int i;
		for (i=0;i<ARRAY_SIZE(allowed_scripts);i++) {
			if (strncmp(options, allowed_scripts[i], strlen(allowed_scripts[i])) == 0) break;
		}
		if (i == ARRAY_SIZE(allowed_scripts)) {
			DEBUG(DEBUG_ERR,("Refusing to run event scripts with option '%s' while in recovery\n",
				 options));
			talloc_free(tmp_ctx);
			return -1;
		}
	}

	if (setpgid(0,0) != 0) {
		DEBUG(DEBUG_ERR,("Failed to create process group for event scripts - %s\n",
			 strerror(errno)));
		talloc_free(tmp_ctx);
		return -1;		
	}

	signal(SIGTERM, sigterm);

	child_state.start = timeval_current();
	child_state.script_running = "startup";

	scripts = ctdb_get_script_list(ctdb, tmp_ctx);

	/* fetch the scripts from the tree one by one and execute
	   them
	 */
	for (current=scripts; current; current=current->next) {
		/* we dont run disabled scripts, we just report they are disabled */
		cmdstr = talloc_asprintf(tmp_ctx, "%s/%s %s", 
				ctdb->event_script_dir,
				current->name, options);
		CTDB_NO_MEMORY(ctdb, cmdstr);

		DEBUG(DEBUG_INFO,("Executing event script %s\n",cmdstr));

		child_state.start = timeval_current();
		child_state.script_running = cmdstr;

		if (is_monitor == 1) {
			if (ctdb_ctrl_event_script_start(ctdb, current->name) != 0) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to start event script monitoring\n"));
				talloc_free(tmp_ctx);
				return -1;
			}

			if (!current->is_enabled) {
				if (ctdb_ctrl_event_script_disabled(ctdb, current->name) != 0) {
					DEBUG(DEBUG_ERR,(__location__ " Failed to report disabled eventscript\n"));
					talloc_free(tmp_ctx);
					return -1;
				}
			}

		}

		if (!current->is_enabled) {
			continue;
		}

		ret = system(cmdstr);
		/* if the system() call was successful, translate ret into the
		   return code from the command
		*/
		if (ret != -1) {
			ret = WEXITSTATUS(ret);
		}
		if (is_monitor == 1) {
			if (ctdb_ctrl_event_script_stop(ctdb, ret) != 0) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to stop event script monitoring\n"));
				talloc_free(tmp_ctx);
				return -1;
			}
		}

		/* return an error if the script failed */
		if (ret != 0) {
			DEBUG(DEBUG_ERR,("Event script %s failed with error %d\n", cmdstr, ret));
			if (is_monitor == 1) {
				if (ctdb_ctrl_event_script_finished(ctdb) != 0) {
					DEBUG(DEBUG_ERR,(__location__ " Failed to finish event script monitoring\n"));
					talloc_free(tmp_ctx);
					return -1;
				}
			}

			talloc_free(tmp_ctx);
			return ret;
		}
	}

	child_state.start = timeval_current();
	child_state.script_running = "finished";
	
	if (is_monitor == 1) {
		if (ctdb_ctrl_event_script_finished(ctdb) != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to finish event script monitoring\n"));
			talloc_free(tmp_ctx);
			return -1;
		}
	}

	talloc_free(tmp_ctx);
	return 0;
}

/* called when child is finished */
static void ctdb_event_script_handler(struct event_context *ev, struct fd_event *fde, 
				      uint16_t flags, void *p)
{
	struct ctdb_event_script_state *state = 
		talloc_get_type(p, struct ctdb_event_script_state);
	void (*callback)(struct ctdb_context *, int, void *) = state->callback;
	void *private_data = state->private_data;
	struct ctdb_context *ctdb = state->ctdb;
	signed char rt = -1;

	read(state->fd[0], &rt, sizeof(rt));

	DEBUG(DEBUG_INFO,(__location__ " Eventscript %s finished with state %d\n", state->options, rt));

	talloc_set_destructor(state, NULL);
	talloc_free(state);
	callback(ctdb, rt, private_data);

	ctdb->event_script_timeouts = 0;
}

static void ctdb_ban_self(struct ctdb_context *ctdb, uint32_t ban_period)
{
	TDB_DATA data;
	struct ctdb_ban_time bantime;

	bantime.pnn  = ctdb->pnn;
	bantime.time = ban_period;

	data.dsize = sizeof(bantime);
	data.dptr  = (uint8_t *)&bantime;

	ctdb_control_set_ban_state(ctdb, data);
}


/* called when child times out */
static void ctdb_event_script_timeout(struct event_context *ev, struct timed_event *te, 
				      struct timeval t, void *p)
{
	struct ctdb_event_script_state *state = talloc_get_type(p, struct ctdb_event_script_state);
	void (*callback)(struct ctdb_context *, int, void *) = state->callback;
	void *private_data = state->private_data;
	struct ctdb_context *ctdb = state->ctdb;
	char *options;
	struct ctdb_monitoring_status *monitoring_status =
		talloc_get_type(ctdb->script_monitoring_ctx,
			struct ctdb_monitoring_status);

	DEBUG(DEBUG_ERR,("Event script timed out : %s count : %u\n", state->options, ctdb->event_script_timeouts));

	options = talloc_strdup(ctdb, state->options);
	CTDB_NO_MEMORY_VOID(ctdb, options);

	talloc_free(state);
	if (!strcmp(options, "monitor")) {
		/* if it is a monitor event, we allow it to "hang" a few times
		   before we declare it a failure and ban ourself (and make
		   ourself unhealthy)
		*/
		DEBUG(DEBUG_ERR, (__location__ " eventscript for monitor event timedout.\n"));

		ctdb->event_script_timeouts++;
		if (ctdb->event_script_timeouts > ctdb->tunable.script_ban_count) {
			ctdb->event_script_timeouts = 0;
			DEBUG(DEBUG_ERR, ("Maximum timeout count %u reached for eventscript. Banning self for %d seconds\n", ctdb->tunable.script_ban_count, ctdb->tunable.recovery_ban_period));
			ctdb_ban_self(ctdb, ctdb->tunable.recovery_ban_period);
			callback(ctdb, -1, private_data);
		} else {
		  	callback(ctdb, 0, private_data);
		}
	} else if (!strcmp(options, "startup")) {
		DEBUG(DEBUG_ERR, (__location__ " eventscript for startup event timedout.\n"));
		callback(ctdb, -1, private_data);
	} else {
		/* if it is not a monitor event we ban ourself immediately */
		DEBUG(DEBUG_ERR, (__location__ " eventscript for NON-monitor/NON-startup event timedout. Immediately banning ourself for %d seconds\n", ctdb->tunable.recovery_ban_period));
		ctdb_ban_self(ctdb, ctdb->tunable.recovery_ban_period);
		callback(ctdb, -1, private_data);
	}

	if (monitoring_status != NULL) {
		struct ctdb_monitor_script_status *script;

		script = monitoring_status->scripts;
		if (script != NULL) {
			script->timedout = 1;
		}
		monitoring_status->status = MONITOR_SCRIPT_TIMEOUT;
		if (ctdb->last_monitoring_ctx) {
			talloc_free(ctdb->last_monitoring_ctx);
			ctdb->last_monitoring_ctx = ctdb->script_monitoring_ctx;
			ctdb->script_monitoring_ctx = NULL;
		}
	}

	talloc_free(options);
}

/*
  destroy a running event script
 */
static int event_script_destructor(struct ctdb_event_script_state *state)
{
	DEBUG(DEBUG_ERR,(__location__ " Sending SIGTERM to child pid:%d\n", state->child));
	kill(state->child, SIGTERM);
	return 0;
}

/*
  run the event script in the background, calling the callback when 
  finished
 */
static int ctdb_event_script_callback_v(struct ctdb_context *ctdb, 
					struct timeval timeout,
					TALLOC_CTX *mem_ctx,
					void (*callback)(struct ctdb_context *, int, void *),
					void *private_data,
					const char *fmt, va_list ap)
{
	struct ctdb_event_script_state *state;
	int ret;

	state = talloc(mem_ctx, struct ctdb_event_script_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->ctdb = ctdb;
	state->callback = callback;
	state->private_data = private_data;
	state->options = talloc_vasprintf(state, fmt, ap);
	CTDB_NO_MEMORY(ctdb, state->options);

	DEBUG(DEBUG_INFO,(__location__ " Starting eventscript %s\n", state->options));
	
	ret = pipe(state->fd);
	if (ret != 0) {
		talloc_free(state);
		return -1;
	}

	state->child = fork();

	if (state->child == (pid_t)-1) {
		close(state->fd[0]);
		close(state->fd[1]);
		talloc_free(state);
		return -1;
	}

	if (state->child == 0) {
		signed char rt;

		close(state->fd[0]);
		set_close_on_exec(state->fd[1]);

		rt = ctdb_event_script_v(ctdb, state->options);
		while ((ret = write(state->fd[1], &rt, sizeof(rt))) != sizeof(rt)) {
			sleep(1);
		}
		_exit(rt);
	}

	talloc_set_destructor(state, event_script_destructor);

	close(state->fd[1]);
	set_close_on_exec(state->fd[0]);

	event_add_fd(ctdb->ev, state, state->fd[0], EVENT_FD_READ|EVENT_FD_AUTOCLOSE,
		     ctdb_event_script_handler, state);

	if (!timeval_is_zero(&timeout)) {
		event_add_timed(ctdb->ev, state, timeout, ctdb_event_script_timeout, state);
	} else {
		DEBUG(DEBUG_ERR, (__location__ " eventscript %s called with no timeout\n", state->options));
	}

	return 0;
}


/*
  run the event script in the background, calling the callback when 
  finished
 */
int ctdb_event_script_callback(struct ctdb_context *ctdb, 
			       struct timeval timeout,
			       TALLOC_CTX *mem_ctx,
			       void (*callback)(struct ctdb_context *, int, void *),
			       void *private_data,
			       const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = ctdb_event_script_callback_v(ctdb, timeout, mem_ctx, callback, private_data, fmt, ap);
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
  run the event script, waiting for it to complete. Used when the caller doesn't want to 
  continue till the event script has finished.
 */
int ctdb_event_script(struct ctdb_context *ctdb, const char *fmt, ...)
{
	va_list ap;
	int ret;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	struct callback_status status;

	va_start(ap, fmt);
	ret = ctdb_event_script_callback_v(ctdb, 
			timeval_current_ofs(ctdb->tunable.script_timeout, 0),
			tmp_ctx, event_script_callback, &status, fmt, ap);
	va_end(ap);

	if (ret != 0) {
		talloc_free(tmp_ctx);
		return ret;
	}

	status.status = -1;
	status.done = false;

	while (status.done == false && event_loop_once(ctdb->ev) == 0) /* noop */;

	talloc_free(tmp_ctx);

	return status.status;
}


struct eventscript_callback_state {
	struct ctdb_req_control *c;
};

/*
  called when takeip event finishes
 */
static void run_eventscripts_callback(struct ctdb_context *ctdb, int status, 
				 void *private_data)
{
	struct eventscript_callback_state *state = 
		talloc_get_type(private_data, struct eventscript_callback_state);

	ctdb_enable_monitoring(ctdb);

	if (status != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to forcibly run eventscripts\n"));
		ctdb_request_control_reply(ctdb, state->c, NULL, status, NULL);
		talloc_free(state);
		return;
	}

	/* the control succeeded */
	ctdb_request_control_reply(ctdb, state->c, NULL, 0, NULL);
	talloc_free(state);
	return;
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

	/* kill off any previous invokations of forced eventscripts */
	if (ctdb->eventscripts_ctx) {
		talloc_free(ctdb->eventscripts_ctx);
	}
	ctdb->eventscripts_ctx = talloc_new(ctdb);
	CTDB_NO_MEMORY(ctdb, ctdb->eventscripts_ctx);

	state = talloc(ctdb->eventscripts_ctx, struct eventscript_callback_state);
	CTDB_NO_MEMORY(ctdb, state);

	state->c = talloc_steal(state, c);

	DEBUG(DEBUG_NOTICE,("Forced running of eventscripts with arguments %s\n", indata.dptr));

	if (ctdb->recovery_mode != CTDB_RECOVERY_NORMAL) {
		DEBUG(DEBUG_ERR, (__location__ " Aborted running eventscript \"%s\" while in RECOVERY mode\n", indata.dptr));
		return -1;
	}

	ctdb_disable_monitoring(ctdb);

	ret = ctdb_event_script_callback(ctdb, 
			 timeval_current_ofs(ctdb->tunable.script_timeout, 0),
			 state, run_eventscripts_callback, state,
			 (const char *)indata.dptr);

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
