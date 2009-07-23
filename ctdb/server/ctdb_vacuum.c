/*
   ctdb vacuuming events

   Copyright (C) Ronnie Sahlberg  2009

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
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/dir.h"
#include "../include/ctdb_private.h"
#include "db_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/events/events.h"
#include "../include/ctdb_private.h"


enum vacuum_child_status { VACUUM_RUNNING, VACUUM_OK, VACUUM_ERROR, VACUUM_TIMEOUT};

struct ctdb_vacuum_child_context {
	struct ctdb_vacuum_handle *vacuum_handle;
	int fd[2];
	pid_t child_pid;
	enum vacuum_child_status status;
	struct timeval start_time;
};

struct ctdb_vacuum_handle {
	struct ctdb_db_context *ctdb_db;
	struct ctdb_vacuum_child_context *child_ctx;
};

static void ctdb_vacuum_event(struct event_context *ev, struct timed_event *te, struct timeval t, void *private_data);

static int vacuum_child_destructor(struct ctdb_vacuum_child_context *child_ctx)
{
	double l = timeval_elapsed(&child_ctx->start_time);
	struct ctdb_db_context *ctdb_db = child_ctx->vacuum_handle->ctdb_db;
	struct ctdb_context *ctdb = ctdb_db->ctdb;

	DEBUG(DEBUG_ERR,("Vacuuming took %.3f seconds for database %s\n", l, ctdb_db->db_name));

	if (child_ctx->child_pid != -1) {
		kill(child_ctx->child_pid, SIGKILL);
	}

	/* here calculate a new interval */
	/* child_ctx->status */

	DEBUG(DEBUG_ERR, ("Start new vacuum event for %s\n", ctdb_db->db_name));

	event_add_timed(ctdb->ev, child_ctx->vacuum_handle, timeval_current_ofs(ctdb->tunable.vacuum_default_interval, 0), ctdb_vacuum_event, child_ctx->vacuum_handle);

	return 0;
}

/*
 * this event is generated when a vacuum child process times out
 */
static void vacuum_child_timeout(struct event_context *ev, struct timed_event *te,
					 struct timeval t, void *private_data)
{
	struct ctdb_vacuum_child_context *child_ctx = talloc_get_type(private_data, struct ctdb_vacuum_child_context);

	DEBUG(DEBUG_ERR,("Vacuuming child process timed out for db %s\n", child_ctx->vacuum_handle->ctdb_db->db_name));

	child_ctx->status = VACUUM_TIMEOUT;

	talloc_free(child_ctx);
}


/*
 * this event is generated when a vacuum child process has completed
 */
static void vacuum_child_handler(struct event_context *ev, struct fd_event *fde,
			     uint16_t flags, void *private_data)
{
	struct ctdb_vacuum_child_context *child_ctx = talloc_get_type(private_data, struct ctdb_vacuum_child_context);
	char c = 0;
	int ret;

	DEBUG(DEBUG_ERR,("Vacuuming child finished for db %s\n", child_ctx->vacuum_handle->ctdb_db->db_name));

	child_ctx->child_pid = -1;

	ret = read(child_ctx->fd[0], &c, 1);
	if (ret != 1 || c != 0) {
		child_ctx->status = VACUUM_ERROR;
		DEBUG(DEBUG_ERR, ("A vacuum child process failed with an error for database %s. ret=%d c=%d\n", child_ctx->vacuum_handle->ctdb_db->db_name, ret, c));
	} else {
		child_ctx->status = VACUUM_OK;
	}

	talloc_free(child_ctx);
}

/*
 * this event is called every time we need to start a new vacuum process
 */
static void
ctdb_vacuum_event(struct event_context *ev, struct timed_event *te,
			       struct timeval t, void *private_data)
{
	struct ctdb_vacuum_handle *vacuum_handle = talloc_get_type(private_data, struct ctdb_vacuum_handle);
	struct ctdb_db_context *ctdb_db = vacuum_handle->ctdb_db;
	struct ctdb_context *ctdb = ctdb_db->ctdb;
	struct ctdb_vacuum_child_context *child_ctx;
	int ret;

	DEBUG(DEBUG_ERR,("Start a vacuuming child process for db %s\n", ctdb_db->db_name));

	/* we dont vacuum if we are in recovery mode */
	if (ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE) {
		event_add_timed(ctdb->ev, vacuum_handle, timeval_current_ofs(ctdb->tunable.vacuum_default_interval, 0), ctdb_vacuum_event, vacuum_handle);
		return;
	}


	child_ctx = talloc(vacuum_handle, struct ctdb_vacuum_child_context);
	if (child_ctx == NULL) {
		DEBUG(DEBUG_CRIT, (__location__ " Failed to allocate child context for vacuuming of %s\n", ctdb_db->db_name));
		ctdb_fatal(ctdb, "Out of memory when crating vacuum child context. Shutting down\n");
	}


	ret = pipe(child_ctx->fd);
	if (ret != 0) {
		talloc_free(child_ctx);
		DEBUG(DEBUG_ERR, ("Failed to create pipe for vacuum child process.\n"));
		event_add_timed(ctdb->ev, vacuum_handle, timeval_current_ofs(ctdb->tunable.vacuum_default_interval, 0), ctdb_vacuum_event, vacuum_handle);
		return;
	}

	child_ctx->child_pid = fork();
	if (child_ctx->child_pid == (pid_t)-1) {
		close(child_ctx->fd[0]);
		close(child_ctx->fd[1]);
		talloc_free(child_ctx);
		DEBUG(DEBUG_ERR, ("Failed to fork vacuum child process.\n"));
		event_add_timed(ctdb->ev, vacuum_handle, timeval_current_ofs(ctdb->tunable.vacuum_default_interval, 0), ctdb_vacuum_event, vacuum_handle);
		return;
	}


	if (child_ctx->child_pid == 0) {
		char cc = 0;
		close(child_ctx->fd[0]);

		DEBUG(DEBUG_ERR,("Child process doing vacuuming stuff on db %s\n", ctdb_db->db_name));

		write(child_ctx->fd[1], &cc, 1);
		_exit(0);
	}

	set_close_on_exec(child_ctx->fd[0]);
	close(child_ctx->fd[1]);

	child_ctx->status = VACUUM_RUNNING;
	child_ctx->start_time = timeval_current();

	talloc_set_destructor(child_ctx, vacuum_child_destructor);

	event_add_timed(ctdb->ev, child_ctx,
		timeval_current_ofs(ctdb->tunable.vacuum_max_run_time, 0),
		vacuum_child_timeout, child_ctx);

	event_add_fd(ctdb->ev, child_ctx, child_ctx->fd[0],
		EVENT_FD_READ|EVENT_FD_AUTOCLOSE,
		vacuum_child_handler,
		child_ctx);

	vacuum_handle->child_ctx = child_ctx;
	child_ctx->vacuum_handle = vacuum_handle;
}


/* this function initializes the vacuuming context for a database
 * starts the vacuuming events
 */
int ctdb_vacuum_init(struct ctdb_db_context *ctdb_db)
{
	struct ctdb_context *ctdb = ctdb_db->ctdb;

	DEBUG(DEBUG_ERR,("Start vacuuming process for database %s\n", ctdb_db->db_name));

	ctdb_db->vacuum_handle = talloc(ctdb_db, struct ctdb_vacuum_handle);
	CTDB_NO_MEMORY(ctdb, ctdb_db->vacuum_handle);

	ctdb_db->vacuum_handle->ctdb_db = ctdb_db;

	event_add_timed(ctdb->ev, ctdb_db->vacuum_handle, timeval_current_ofs(ctdb->tunable.vacuum_default_interval, 0), ctdb_vacuum_event, ctdb_db->vacuum_handle);

	return 0;
}
