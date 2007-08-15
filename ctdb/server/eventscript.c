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
#include "../include/ctdb_private.h"
#include "lib/events/events.h"
#include "../common/rb_tree.h"
#include <dirent.h>
#include <ctype.h>

/*
  run the event script - varargs version
  this function is called and run in the context of a forked child
  which allows it to do blocking calls such as system()
 */
static int ctdb_event_script_v(struct ctdb_context *ctdb, const char *fmt, va_list ap)
{
	char *options, *cmdstr;
	int ret;
	va_list ap2;
	struct stat st;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb);
	trbt_tree_t *tree;
	DIR *dir;
	struct dirent *de;
	char *script;

	/*
	  the service specific event scripts 
	*/
	if (stat(ctdb->takeover.event_script_dir, &st) != 0 && 
	    errno == ENOENT) {
		DEBUG(0,("No event script directory found at '%s'\n", ctdb->takeover.event_script_dir));
		talloc_free(tmp_ctx);
		return 0;
	}

	/* create a tree to store all the script names in */
	tree = trbt_create(tmp_ctx, 0);

	/* scan all directory entries and insert all valid scripts into the 
	   tree
	*/
	dir = opendir(ctdb->takeover.event_script_dir);
	if (dir == NULL) {
		DEBUG(0,("Failed to open event script directory '%s'\n", ctdb->takeover.event_script_dir));
		talloc_free(tmp_ctx);
		return 0;
	}
	while ((de=readdir(dir)) != NULL) {
		int namlen;
		int num;

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

		if ( (!isdigit(de->d_name[0])) || (!isdigit(de->d_name[1])) ) {
			continue;
		}

		sscanf(de->d_name, "%2d.", &num);
		
		/* store the event script in the tree */		
		script = trbt_insert32(tree, num, talloc_strdup(tmp_ctx, de->d_name));
		if (script != NULL) {
			DEBUG(0,("CONFIG ERROR: Multiple event scripts with the same prefix : %s and %s. Each event script MUST have a unique prefix\n", script, de->d_name));
			talloc_free(tmp_ctx);
			closedir(dir);
			return -1;
		}
	}
	closedir(dir);


	/* fetch the scripts from the tree one by one and execute
	   them
	 */
	while ((script=trbt_findfirstarray32(tree, 1)) != NULL) {
		va_copy(ap2, ap);
		options  = talloc_vasprintf(tmp_ctx, fmt, ap2);
		va_end(ap2);
		CTDB_NO_MEMORY(ctdb, options);

		cmdstr = talloc_asprintf(tmp_ctx, "%s/%s %s", 
				ctdb->takeover.event_script_dir,
				script, options);
		CTDB_NO_MEMORY(ctdb, cmdstr);

		DEBUG(1,("Executing event script %s\n",cmdstr));

		ret = system(cmdstr);
		/* if the system() call was successful, translate ret into the
		   return code from the command
		*/
		if (ret != -1) {
			ret = WEXITSTATUS(ret);
		}
		/* return an error if the script failed */
		if (ret != 0) {
			DEBUG(0,("Event script %s failed with error %d\n", cmdstr, ret));
			talloc_free(tmp_ctx);
			return ret;
		}

		/* remove this script from the tree */
		talloc_free(script);
	}
	
	talloc_free(tmp_ctx);
	return 0;
}

struct ctdb_event_script_state {
	struct ctdb_context *ctdb;
	pid_t child;
	void (*callback)(struct ctdb_context *, int, void *);
	int fd[2];
	void *private_data;
};

/* called when child is finished */
static void ctdb_event_script_handler(struct event_context *ev, struct fd_event *fde, 
				      uint16_t flags, void *p)
{
	struct ctdb_event_script_state *state = 
		talloc_get_type(p, struct ctdb_event_script_state);
	int status = -1;
	void (*callback)(struct ctdb_context *, int, void *) = state->callback;
	void *private_data = state->private_data;
	struct ctdb_context *ctdb = state->ctdb;

	waitpid(state->child, &status, 0);
	if (status != -1) {
		status = WEXITSTATUS(status);
	}
	talloc_set_destructor(state, NULL);
	talloc_free(state);
	callback(ctdb, status, private_data);
}


/* called when child times out */
static void ctdb_event_script_timeout(struct event_context *ev, struct timed_event *te, 
				      struct timeval t, void *p)
{
	struct ctdb_event_script_state *state = talloc_get_type(p, struct ctdb_event_script_state);
	void (*callback)(struct ctdb_context *, int, void *) = state->callback;
	void *private_data = state->private_data;
	struct ctdb_context *ctdb = state->ctdb;

	DEBUG(0,("event script timed out. Increase debuglevel to 1 or higher to see which script timedout.\n"));
	talloc_free(state);
	callback(ctdb, -1, private_data);
}

/*
  destroy a running event script
 */
static int event_script_destructor(struct ctdb_event_script_state *state)
{
	kill(state->child, SIGKILL);
	waitpid(state->child, NULL, 0);
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
		close(state->fd[0]);
		if (ctdb->do_setsched) {
			ctdb_restore_scheduler(ctdb);
		}
		set_close_on_exec(state->fd[1]);
		ret = ctdb_event_script_v(ctdb, fmt, ap);
		_exit(ret);
	}

	talloc_set_destructor(state, event_script_destructor);

	close(state->fd[1]);

	event_add_fd(ctdb->ev, state, state->fd[0], EVENT_FD_READ|EVENT_FD_AUTOCLOSE,
		     ctdb_event_script_handler, state);

	if (!timeval_is_zero(&timeout)) {
		event_add_timed(ctdb->ev, state, timeout, ctdb_event_script_timeout, state);
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
	ret = ctdb_event_script_callback_v(ctdb, timeval_zero(), tmp_ctx, event_script_callback, &status, fmt, ap);
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
