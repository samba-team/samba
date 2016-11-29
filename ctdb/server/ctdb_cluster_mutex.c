/*
   CTDB cluster mutex handling

   Copyright (C) Andrew Tridgell  2007
   Copyright (C) Ronnie Sahlberg  2007
   Copyright (C) Martin Schwenke  2016

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

#include <tevent.h>

#include "replace.h"
#include "system/network.h"

#include "lib/util/debug.h"
#include "lib/util/time.h"
#include "lib/util/strv.h"
#include "lib/util/strv_util.h"
#include "lib/util/sys_rw.h"
#include "lib/util/blocking.h"

#include "ctdb_private.h"
#include "common/common.h"
#include "common/logging.h"

#include "ctdb_cluster_mutex.h"

struct ctdb_cluster_mutex_handle {
	struct ctdb_context *ctdb;
	cluster_mutex_handler_t handler;
	void *private_data;
	cluster_mutex_lost_handler_t lost_handler;
	void *lost_data;
	int fd[2];
	struct tevent_timer *te;
	struct tevent_fd *fde;
	pid_t child;
	struct timeval start_time;
	bool have_response;
};

static void cluster_mutex_timeout(struct tevent_context *ev,
				  struct tevent_timer *te,
				  struct timeval t, void *private_data)
{
	struct ctdb_cluster_mutex_handle *h =
		talloc_get_type(private_data, struct ctdb_cluster_mutex_handle);
	double latency = timeval_elapsed(&h->start_time);

	if (h->handler != NULL) {
		h->handler('2', latency, h->private_data);
	}
}


/* When the handle is freed it causes any child holding the mutex to
 * be killed, thus freeing the mutex */
static int cluster_mutex_destructor(struct ctdb_cluster_mutex_handle *h)
{
	if (h->fd[0] != -1) {
		h->fd[0] = -1;
	}
	ctdb_kill(h->ctdb, h->child, SIGTERM);
	return 0;
}

/* this is called when the client process has completed ctdb_recovery_lock()
   and has written data back to us through the pipe.
*/
static void cluster_mutex_handler(struct tevent_context *ev,
				  struct tevent_fd *fde,
				  uint16_t flags, void *private_data)
{
	struct ctdb_cluster_mutex_handle *h=
		talloc_get_type(private_data, struct ctdb_cluster_mutex_handle);
	double latency = timeval_elapsed(&h->start_time);
	char c = '0';
	int ret;

	/* Got response from child process so abort timeout */
	TALLOC_FREE(h->te);

	ret = sys_read(h->fd[0], &c, 1);

	/* Don't call the handler more than once.  It only exists to
	 * process the initial response from the helper. */
	if (h->have_response) {
		/* Only deal with EOF due to process exit.  Silently
		 * ignore any other output. */
		if (ret == 0) {
			if (h->lost_handler != NULL) {
				h->lost_handler(h->lost_data);
			}
		}
		return;
	}
	h->have_response = true;

	/* If the child wrote status then just pass it to the handler.
	 * If no status was written then this is an unexpected error
	 * so pass generic error code to handler. */
	if (h->handler != NULL) {
		h->handler(ret == 1 ? c : '3', latency, h->private_data);
	}
}

static char cluster_mutex_helper[PATH_MAX+1] = "";

static bool cluster_mutex_helper_args(TALLOC_CTX *mem_ctx,
				      const char *argstring, char ***argv)
{
	int nargs, i, ret, n;
	bool is_command = false;
	char **args = NULL;
	char *strv = NULL;
	char *t = NULL;

	if (argstring != NULL && argstring[0] == '!') {
		/* This is actually a full command */
		is_command = true;
		t = discard_const(&argstring[1]);
	} else {
		is_command = false;
		t = discard_const(argstring);
	}

	ret = strv_split(mem_ctx, &strv, t, " \t");
	if (ret != 0) {
		DEBUG(DEBUG_ERR,
		      ("Unable to parse mutex helper string \"%s\" (%s)\n",
		       argstring, strerror(ret)));
		return false;
	}
	n = strv_count(strv);

	args = talloc_array(mem_ctx, char *, n + (is_command ? 1 : 2));

	if (args == NULL) {
		DEBUG(DEBUG_ERR,(__location__ " out of memory\n"));
		return false;
	}

	nargs = 0;

	if (! is_command) {
		if (!ctdb_set_helper("cluster mutex helper",
				     cluster_mutex_helper,
				     sizeof(cluster_mutex_helper),
				     "CTDB_CLUSTER_MUTEX_HELPER",
				     CTDB_HELPER_BINDIR,
				     "ctdb_mutex_fcntl_helper")) {
			DEBUG(DEBUG_ERR,("ctdb exiting with error: %s\n",
					 __location__
					 " Unable to set cluster mutex helper\n"));
			exit(1);
		}

		args[nargs++] = cluster_mutex_helper;
	}

	t = NULL;
	for (i = 0; i < n; i++) {
		/* Don't copy, just keep cmd_args around */
		t = strv_next(strv, t);
		args[nargs++] = t;
	}

	/* Make sure last argument is NULL */
	args[nargs] = NULL;

	*argv = args;
	return true;
}

struct ctdb_cluster_mutex_handle *
ctdb_cluster_mutex(TALLOC_CTX *mem_ctx,
		   struct ctdb_context *ctdb,
		   const char *argstring,
		   int timeout,
		   cluster_mutex_handler_t handler,
		   void *private_data,
		   cluster_mutex_lost_handler_t lost_handler,
		   void *lost_data)
{
	struct ctdb_cluster_mutex_handle *h;
	char **args;
	int ret;

	h = talloc(mem_ctx, struct ctdb_cluster_mutex_handle);
	if (h == NULL) {
		DEBUG(DEBUG_ERR, (__location__ " out of memory\n"));
		return NULL;
	}

	h->start_time = timeval_current();
	h->fd[0] = -1;
	h->fd[1] = -1;
	h->have_response = false;

	ret = pipe(h->fd);
	if (ret != 0) {
		talloc_free(h);
		DEBUG(DEBUG_ERR, (__location__ " Failed to open pipe\n"));
		return NULL;
	}
	set_close_on_exec(h->fd[0]);

	/* Create arguments for lock helper */
	if (!cluster_mutex_helper_args(h, argstring, &args)) {
		close(h->fd[0]);
		close(h->fd[1]);
		talloc_free(h);
		return NULL;
	}

	h->child = ctdb_fork(ctdb);
	if (h->child == (pid_t)-1) {
		close(h->fd[0]);
		close(h->fd[1]);
		talloc_free(h);
		return NULL;
	}

	if (h->child == 0) {
		/* Make stdout point to the pipe */
		close(STDOUT_FILENO);
		dup2(h->fd[1], STDOUT_FILENO);
		close(h->fd[1]);

		execv(args[0], args);

		/* Only happens on error */
		DEBUG(DEBUG_ERR, (__location__ "execv() failed\n"));
		_exit(1);
	}

	/* Parent */

	DEBUG(DEBUG_DEBUG, (__location__ " Created PIPE FD:%d\n", h->fd[0]));
	set_close_on_exec(h->fd[0]);

	close(h->fd[1]);
	h->fd[1] = -1;

	talloc_set_destructor(h, cluster_mutex_destructor);

	if (timeout != 0) {
		h->te = tevent_add_timer(ctdb->ev, h,
					 timeval_current_ofs(timeout, 0),
					 cluster_mutex_timeout, h);
	} else {
		h->te = NULL;
	}

	h->fde = tevent_add_fd(ctdb->ev, h, h->fd[0], TEVENT_FD_READ,
			       cluster_mutex_handler, (void *)h);

	if (h->fde == NULL) {
		talloc_free(h);
		return NULL;
	}
	tevent_fd_set_auto_close(h->fde);

	h->ctdb = ctdb;
	h->handler = handler;
	h->private_data = private_data;
	h->lost_handler = lost_handler;
	h->lost_data = lost_data;

	return h;
}
