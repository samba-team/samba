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
		DEBUG(DEBUG_INFO,("locking database 0x%08x priority:%u %s\n", ctdb_db->db_id, ctdb_db->priority, ctdb_db->db_name));
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
	bool transaction_started;
	uint32_t transaction_id;
};

/*
  destroy a freeze handle
 */	
static int ctdb_freeze_handle_destructor(struct ctdb_freeze_handle *h)
{
	struct ctdb_context *ctdb = h->ctdb;
	struct ctdb_db_context *ctdb_db;

	/* cancel any pending transactions */
	if (ctdb->freeze_handle && ctdb->freeze_handle->transaction_started) {
		for (ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next) {
			tdb_add_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
			if (tdb_transaction_cancel(ctdb_db->ltdb->tdb) != 0) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to cancel transaction for db '%s'\n",
					 ctdb_db->db_name));
			}
			tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
		}
		ctdb->freeze_handle->transaction_started = false;
	}

	ctdb->freeze_mode = CTDB_FREEZE_NONE;
	ctdb->freeze_handle = NULL;

	kill(h->child, SIGKILL);
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
		DEBUG(DEBUG_INFO,("freeze child died - unfreezing\n"));
		if (h->ctdb->freeze_handle == h) {
			h->ctdb->freeze_handle = NULL;
		}
		talloc_free(h);
		return;
	}

	if (read(h->fd, &status, sizeof(status)) != sizeof(status)) {
		DEBUG(DEBUG_ERR,("read error from freeze lock child\n"));
		status = -1;
	}

	if (status == -1) {
		DEBUG(DEBUG_ERR,("Failed to get locks in ctdb_freeze_child\n"));
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
	CTDB_NO_MEMORY_NULL(ctdb, h);

	h->ctdb = ctdb;

	/* use socketpair() instead of pipe() so we have bi-directional fds */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) != 0) {
		DEBUG(DEBUG_ERR,("Failed to create pipe for ctdb_freeze_lock\n"));
		talloc_free(h);
		return NULL;
	}
	
	h->child = fork();
	if (h->child == -1) {
		DEBUG(DEBUG_ERR,("Failed to fork child for ctdb_freeze_lock\n"));
		talloc_free(h);
		return NULL;
	}

	if (h->child == 0) {
		int ret;
		int count = 0;
		/* in the child */
		close(fd[0]);
		ret = ctdb_lock_all_databases(ctdb);
		if (ret != 0) {
			_exit(0);
		}

		alarm(30);

		while (count++ < 30) {
			ret = write(fd[1], &ret, sizeof(ret));
			if (ret == sizeof(ret)) {
				break;
			}
			DEBUG(DEBUG_ERR, (__location__ " Failed to write to socket from freeze child. ret:%d errno:%u\n", ret, errno));
			sleep (1);
		}
		if (count >= 30) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to write to socket from freeze child. Aborting freeze child\n"));
			_exit(0);
		}

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
		DEBUG(DEBUG_ERR,("Failed to setup fd event for ctdb_freeze_lock\n"));
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
	/* cancel any pending transactions */
	if (ctdb->freeze_handle && ctdb->freeze_handle->transaction_started) {
		struct ctdb_db_context *ctdb_db;

		for (ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next) {
			tdb_add_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
			if (tdb_transaction_cancel(ctdb_db->ltdb->tdb) != 0) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to cancel transaction for db '%s'\n",
					 ctdb_db->db_name));
			}
			tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
		}
	}

#if 0
	/* this hack can be used to get a copy of the databases at the end of a recovery */
	system("mkdir -p /var/ctdb.saved; /usr/bin/rsync --delete -a /var/ctdb/ /var/ctdb.saved/$$ 2>&1 > /dev/null");
#endif

#if 0
	/* and this one for local testing */
	system("mkdir -p test.db.saved; /usr/bin/rsync --delete -a test.db/ test.db.saved/$$ 2>&1 > /dev/null");
#endif


	talloc_free(ctdb->freeze_handle);
	ctdb->freeze_handle = NULL;
	ctdb_call_resend_all(ctdb);
	return 0;
}


/*
  start a transaction on all databases - used for recovery
 */
int32_t ctdb_control_transaction_start(struct ctdb_context *ctdb, uint32_t id)
{
	struct ctdb_db_context *ctdb_db;

	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR,(__location__ " Failed transaction_start while not frozen\n"));
		return -1;
	}


	for (ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next) {
		int ret;

		tdb_add_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);

		if (ctdb->freeze_handle->transaction_started) {
			if (tdb_transaction_cancel(ctdb_db->ltdb->tdb) != 0) {
				DEBUG(DEBUG_ERR,(__location__ " Failed to cancel transaction for db '%s'\n",
					 ctdb_db->db_name));
				/* not a fatal error */
			}
		}

		ret = tdb_transaction_start(ctdb_db->ltdb->tdb);

		tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);

		if (ret != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to start transaction for db '%s'\n",
				 ctdb_db->db_name));
			return -1;
		}
	}

	ctdb->freeze_handle->transaction_started = true;
	ctdb->freeze_handle->transaction_id = id;

	return 0;
}

/*
  commit transactions on all databases
 */
int32_t ctdb_control_transaction_commit(struct ctdb_context *ctdb, uint32_t id)
{
	struct ctdb_db_context *ctdb_db;

	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR,(__location__ " Failed transaction_start while not frozen\n"));
		return -1;
	}

	if (!ctdb->freeze_handle->transaction_started) {
		DEBUG(DEBUG_ERR,(__location__ " transaction not started\n"));
		return -1;
	}

	if (id != ctdb->freeze_handle->transaction_id) {
		DEBUG(DEBUG_ERR,(__location__ " incorrect transaction id 0x%x in commit\n", id));
		return -1;
	}

	for (ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next) {
		tdb_add_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
		if (tdb_transaction_commit(ctdb_db->ltdb->tdb) != 0) {
			DEBUG(DEBUG_ERR,(__location__ " Failed to commit transaction for db '%s'. Cancel all transactions and resetting transaction_started to false.\n",
				 ctdb_db->db_name));

			/* cancel any pending transactions */
			for (ctdb_db=ctdb->db_list;ctdb_db;ctdb_db=ctdb_db->next) {
				tdb_add_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
				if (tdb_transaction_cancel(ctdb_db->ltdb->tdb) != 0) {
					DEBUG(DEBUG_ERR,(__location__ " Failed to cancel transaction for db '%s'\n",
						 ctdb_db->db_name));
				}
				tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
			}
			ctdb->freeze_handle->transaction_started = false;

			return -1;
		}
		tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
	}

	ctdb->freeze_handle->transaction_started = false;
	ctdb->freeze_handle->transaction_id = 0;

	return 0;
}

/*
  wipe a database - only possible when in a frozen transaction
 */
int32_t ctdb_control_wipe_database(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_control_wipe_database w = *(struct ctdb_control_wipe_database *)indata.dptr;
	struct ctdb_db_context *ctdb_db;

	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR,(__location__ " Failed transaction_start while not frozen\n"));
		return -1;
	}

	if (!ctdb->freeze_handle->transaction_started) {
		DEBUG(DEBUG_ERR,(__location__ " transaction not started\n"));
		return -1;
	}

	if (w.transaction_id != ctdb->freeze_handle->transaction_id) {
		DEBUG(DEBUG_ERR,(__location__ " incorrect transaction id 0x%x in commit\n", w.transaction_id));
		return -1;
	}

	ctdb_db = find_ctdb_db(ctdb, w.db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%x\n", w.db_id));
		return -1;
	}

	if (tdb_wipe_all(ctdb_db->ltdb->tdb) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to wipe database for db '%s'\n",
			 ctdb_db->db_name));
		return -1;
	}

	return 0;
}
