/* 
   ctdb freeze handling

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
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "../include/ctdb_private.h"
#include "lib/util/dlinklist.h"
#include "db_wrap.h"


/*
  lock all databases
 */
static int ctdb_lock_all_databases(struct ctdb_context *ctdb)
{
	struct ctdb_db_context *ctdb_db;
	for (ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next) {
		if (tdb_lockall(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
	}
	return 0;
}

/*
  a list of control requests waiting for a freeze lock child to get
  the database locks
 */
struct ctdb_freeze_waiter {
	struct ctdb_freeze_waiter *next, *prev;
	struct ctdb_context *ctdb;
	struct ctdb_req_control *c;
	int32_t status;
};

/* a handle to a freeze lock child process */
struct ctdb_freeze_handle {
	struct ctdb_context *ctdb;
	pid_t child;
	int fd;
	struct ctdb_freeze_waiter *waiters;
};

/*
  destroy a freeze handle
 */	
static int ctdb_freeze_handle_destructor(struct ctdb_freeze_handle *h)
{
	h->ctdb->freeze_mode = CTDB_FREEZE_NONE;
	kill(h->child, SIGKILL);
	waitpid(h->child, NULL, 0);
	return 0;
}

/*
  called when the child writes its status to us
 */
static void ctdb_freeze_lock_handler(struct event_context *ev, struct fd_event *fde, 
				       uint16_t flags, void *private_data)
{
	struct ctdb_freeze_handle *h = talloc_get_type(private_data, struct ctdb_freeze_handle);
	int32_t status;
	struct ctdb_freeze_waiter *w;

	if (h->ctdb->freeze_mode == CTDB_FREEZE_FROZEN) {
		DEBUG(0,("freeze child died - unfreezing\n"));
		talloc_free(h);
		return;
	}

	if (read(h->fd, &status, sizeof(status)) != sizeof(status)) {
		DEBUG(0,("read error from freeze lock child\n"));
		status = -1;
	}

	if (status == -1) {
		DEBUG(0,("Failed to get locks in ctdb_freeze_child\n"));
		/* we didn't get the locks - destroy the handle */
		talloc_free(h);
		return;
	}

	h->ctdb->freeze_mode = CTDB_FREEZE_FROZEN;

	/* notify the waiters */
	while ((w = h->ctdb->freeze_handle->waiters)) {
		w->status = status;
		DLIST_REMOVE(h->ctdb->freeze_handle->waiters, w);
		talloc_free(w);
	}
}

/*
  create a child which gets locks on all the open databases, then calls the callback telling the parent
  that it is done
 */
static struct ctdb_freeze_handle *ctdb_freeze_lock(struct ctdb_context *ctdb)
{
	struct ctdb_freeze_handle *h;
	int fd[2];
	struct fd_event *fde;

	h = talloc_zero(ctdb, struct ctdb_freeze_handle);
	CTDB_NO_MEMORY_VOID(ctdb, h);

	h->ctdb = ctdb;

	/* use socketpair() instead of pipe() so we have bi-directional fds */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0) {
		DEBUG(0,("Failed to create pipe for ctdb_freeze_lock\n"));
		talloc_free(h);
		return NULL;
	}
	
	h->child = fork();
	if (h->child == -1) {
		DEBUG(0,("Failed to fork child for ctdb_freeze_lock\n"));
		talloc_free(h);
		return NULL;
	}

	if (h->child == 0) {
		int ret;
		/* in the child */
		close(fd[0]);
		ret = ctdb_lock_all_databases(ctdb);
		if (ret != 0) {
			_exit(0);
		}
		write(fd[1], &ret, sizeof(ret));
		/* the read here means we will die if the parent exits */
		read(fd[1], &ret, sizeof(ret));
		_exit(0);
	}

	talloc_set_destructor(h, ctdb_freeze_handle_destructor);

	close(fd[1]);

	h->fd = fd[0];

	fde = event_add_fd(ctdb->ev, h, h->fd, EVENT_FD_READ|EVENT_FD_AUTOCLOSE, 
			   ctdb_freeze_lock_handler, h);
	if (fde == NULL) {
		DEBUG(0,("Failed to setup fd event for ctdb_freeze_lock\n"));
		close(fd[0]);
		talloc_free(h);
		return NULL;
	}

	return h;
}

/*
  destroy a waiter for a freeze mode change
 */
static int ctdb_freeze_waiter_destructor(struct ctdb_freeze_waiter *w)
{
	DLIST_REMOVE(w->ctdb->freeze_handle->waiters, w);
	ctdb_request_control_reply(w->ctdb, w->c, NULL, w->status, NULL);
	return 0;
}

/*
  start the freeze process
 */
void ctdb_start_freeze(struct ctdb_context *ctdb)
{
	if (ctdb->freeze_mode == CTDB_FREEZE_FROZEN) {
		/* we're already frozen */
		return;
	}

	/* if there isn't a freeze lock child then create one */
	if (!ctdb->freeze_handle) {
		ctdb->freeze_handle = ctdb_freeze_lock(ctdb);
		CTDB_NO_MEMORY_VOID(ctdb, ctdb->freeze_handle);
		ctdb->freeze_mode = CTDB_FREEZE_PENDING;
	}
}

/*
  freeze the databases
 */
int32_t ctdb_control_freeze(struct ctdb_context *ctdb, struct ctdb_req_control *c, bool *async_reply)
{
	struct ctdb_freeze_waiter *w;

	if (ctdb->freeze_mode == CTDB_FREEZE_FROZEN) {
		/* we're already frozen */
		return 0;
	}

	ctdb_start_freeze(ctdb);

	/* add ourselves to list of waiters */
	w = talloc(ctdb->freeze_handle, struct ctdb_freeze_waiter);
	CTDB_NO_MEMORY(ctdb, w);
	w->ctdb   = ctdb;
	w->c      = talloc_steal(w, c);
	w->status = -1;
	talloc_set_destructor(w, ctdb_freeze_waiter_destructor);
	DLIST_ADD(ctdb->freeze_handle->waiters, w);

	/* we won't reply till later */
	*async_reply = True;
	return 0;
}


/*
  block until we are frozen, used during daemon startup
 */
bool ctdb_blocking_freeze(struct ctdb_context *ctdb)
{
	ctdb_start_freeze(ctdb);

	/* block until frozen */
	while (ctdb->freeze_mode == CTDB_FREEZE_PENDING) {
		event_loop_once(ctdb->ev);
	}

	return ctdb->freeze_mode == CTDB_FREEZE_FROZEN;
}



/*
  thaw the databases
 */
int32_t ctdb_control_thaw(struct ctdb_context *ctdb)
{
	talloc_free(ctdb->freeze_handle);
	ctdb->freeze_handle = NULL;
	ctdb_call_resend_all(ctdb);
	return 0;
}
