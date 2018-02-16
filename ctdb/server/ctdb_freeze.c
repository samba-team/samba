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
#include "replace.h"
#include "system/network.h"
#include "system/filesys.h"
#include "system/wait.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"

#include "ctdb_private.h"

#include "common/rb_tree.h"
#include "common/common.h"
#include "common/logging.h"

/**
 * Cancel a transaction on database
 */
static int db_transaction_cancel_handler(struct ctdb_db_context *ctdb_db,
					 void *private_data)
{
	int ret;

	tdb_add_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
	ret = tdb_transaction_cancel(ctdb_db->ltdb->tdb);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to cancel transaction for db %s\n",
				  ctdb_db->db_name));
	}
	tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
	return 0;
}

/**
 * Start a transaction on database
 */
static int db_transaction_start_handler(struct ctdb_db_context *ctdb_db,
					void *private_data)
{
	bool freeze_transaction_started = *(bool *)private_data;
	int ret;

	tdb_add_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
	if (freeze_transaction_started) {
		ret = tdb_transaction_cancel(ctdb_db->ltdb->tdb);
		if (ret != 0) {
			DEBUG(DEBUG_ERR,
			      ("Failed to cancel transaction for db %s\n",
			       ctdb_db->db_name));
		}
	}
	ret = tdb_transaction_start(ctdb_db->ltdb->tdb);
	tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to start transaction for db %s\n",
				  ctdb_db->db_name));
		return -1;
	}
	return 0;
}

/**
 * Commit a transaction on database
 */
static int db_transaction_commit_handler(struct ctdb_db_context *ctdb_db,
					 void *private_data)
{
	unsigned int healthy_nodes = *(unsigned int *)private_data;
	int ret;

	tdb_add_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
	ret = tdb_transaction_commit(ctdb_db->ltdb->tdb);
	tdb_remove_flags(ctdb_db->ltdb->tdb, TDB_NOLOCK);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to commit transaction for db %s\n",
				  ctdb_db->db_name));
		return -1;
	}

	ret = ctdb_update_persistent_health(ctdb_db->ctdb, ctdb_db, NULL,
					    healthy_nodes);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to update persistent health for db %s\n",
				  ctdb_db->db_name));
	}
	return ret;
}

/* a list of control requests waiting for db freeze */
struct ctdb_db_freeze_waiter {
	struct ctdb_db_freeze_waiter *next, *prev;
	struct ctdb_context *ctdb;
	void *private_data;
	int32_t status;
};

/* a handle to a db freeze lock child process */
struct ctdb_db_freeze_handle {
	struct ctdb_db_context *ctdb_db;
	struct lock_request *lreq;
	struct ctdb_db_freeze_waiter *waiters;
};

/**
 * Called when freeing database freeze handle
 */
static int ctdb_db_freeze_handle_destructor(struct ctdb_db_freeze_handle *h)
{
	struct ctdb_db_context *ctdb_db = h->ctdb_db;

	DEBUG(DEBUG_ERR, ("Release freeze handle for db %s\n",
			  ctdb_db->db_name));

	/* Cancel any pending transactions */
	if (ctdb_db->freeze_transaction_started) {
		db_transaction_cancel_handler(ctdb_db, NULL);
		ctdb_db->freeze_transaction_started = false;
	}
	ctdb_db->freeze_mode = CTDB_FREEZE_NONE;
	ctdb_db->freeze_handle = NULL;

	/* Clear invalid records flag */
	ctdb_db->invalid_records = false;

	talloc_free(h->lreq);
	return 0;
}

/**
 * Called when a database is frozen
 */
static void ctdb_db_freeze_handler(void *private_data, bool locked)
{
	struct ctdb_db_freeze_handle *h = talloc_get_type_abort(
		private_data, struct ctdb_db_freeze_handle);
	struct ctdb_db_freeze_waiter *w;

	if (h->ctdb_db->freeze_mode == CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR, ("Freeze db child died - unfreezing\n"));
		h->ctdb_db->freeze_mode = CTDB_FREEZE_NONE;
		talloc_free(h);
		return;
	}

	if (!locked) {
		DEBUG(DEBUG_ERR, ("Failed to get db lock for %s\n",
				  h->ctdb_db->db_name));
		h->ctdb_db->freeze_mode = CTDB_FREEZE_NONE;
		talloc_free(h);
		return;
	}

	h->ctdb_db->freeze_mode = CTDB_FREEZE_FROZEN;

	/* notify the waiters */
	while ((w = h->waiters) != NULL) {
		w->status = 0;
		DLIST_REMOVE(h->waiters, w);
		talloc_free(w);
	}
}

/**
 * Start freeze process for a database
 */
static void ctdb_start_db_freeze(struct ctdb_db_context *ctdb_db)
{
	struct ctdb_db_freeze_handle *h;

	if (ctdb_db->freeze_mode == CTDB_FREEZE_FROZEN) {
		return;
	}

	if (ctdb_db->freeze_handle != NULL) {
		return;
	}

	DEBUG(DEBUG_ERR, ("Freeze db: %s\n", ctdb_db->db_name));

	ctdb_stop_vacuuming(ctdb_db->ctdb);

	h = talloc_zero(ctdb_db, struct ctdb_db_freeze_handle);
	CTDB_NO_MEMORY_FATAL(ctdb_db->ctdb, h);

	h->ctdb_db = ctdb_db;
	h->lreq = ctdb_lock_db(h, ctdb_db, false, ctdb_db_freeze_handler, h);
	CTDB_NO_MEMORY_FATAL(ctdb_db->ctdb, h->lreq);
	talloc_set_destructor(h, ctdb_db_freeze_handle_destructor);

	ctdb_db->freeze_handle = h;
	ctdb_db->freeze_mode = CTDB_FREEZE_PENDING;
}

/**
 * Reply to a waiter for db freeze
 */
static int ctdb_db_freeze_waiter_destructor(struct ctdb_db_freeze_waiter *w)
{
	/* 'c' pointer is talloc_memdup(), so cannot use talloc_get_type */
	struct ctdb_req_control_old *c =
		(struct ctdb_req_control_old *)w->private_data;

	ctdb_request_control_reply(w->ctdb, c, NULL, w->status, NULL);
	return 0;
}

/**
 * freeze a database
 */
int32_t ctdb_control_db_freeze(struct ctdb_context *ctdb,
			       struct ctdb_req_control_old *c,
			       uint32_t db_id,
			       bool *async_reply)
{
	struct ctdb_db_context *ctdb_db;
	struct ctdb_db_freeze_waiter *w;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR, ("Freeze db for unknown dbid 0x%08x\n", db_id));
		return -1;
	}

	if (ctdb_db->freeze_mode == CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR, ("Freeze db: %s frozen\n", ctdb_db->db_name));
		return 0;
	}

	ctdb_start_db_freeze(ctdb_db);

	/* add ourselves to the list of waiters */
	w = talloc(ctdb_db->freeze_handle, struct ctdb_db_freeze_waiter);
	CTDB_NO_MEMORY(ctdb, w);
	w->ctdb = ctdb;
	w->private_data = talloc_steal(w, c);
	w->status = -1;
	talloc_set_destructor(w, ctdb_db_freeze_waiter_destructor);
	DLIST_ADD(ctdb_db->freeze_handle->waiters, w);

	*async_reply = true;
	return 0;
}

/**
 * Thaw a database
 */
int32_t ctdb_control_db_thaw(struct ctdb_context *ctdb, uint32_t db_id)
{
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR, ("Thaw db for unknown dbid 0x%08x\n", db_id));
		return -1;
	}

	DEBUG(DEBUG_ERR, ("Thaw db: %s generation %u\n", ctdb_db->db_name,
			  ctdb_db->generation));

	TALLOC_FREE(ctdb_db->freeze_handle);
	ctdb_call_resend_db(ctdb_db);
	return 0;
}


/*
  a list of control requests waiting for a freeze lock child to get
  the database locks
 */
struct ctdb_freeze_waiter {
	struct ctdb_freeze_waiter *next, *prev;
	struct ctdb_context *ctdb;
	struct ctdb_req_control_old *c;
	int32_t status;
};

/* a handle to a freeze lock child process */
struct ctdb_freeze_handle {
	struct ctdb_context *ctdb;
	unsigned int num_total, num_locked, num_failed;
	struct ctdb_freeze_waiter *waiters;
};

static int db_thaw(struct ctdb_db_context *ctdb_db, void *private_data)
{
	talloc_free(ctdb_db->freeze_handle);
	return 0;
}

/*
  destroy a freeze handle
 */
static int ctdb_freeze_handle_destructor(struct ctdb_freeze_handle *h)
{
	struct ctdb_context *ctdb = h->ctdb;

	DEBUG(DEBUG_ERR,("Release freeze handle\n"));

	/* cancel any pending transactions */
	if (ctdb->freeze_transaction_started) {
		ctdb_db_iterator(ctdb, db_transaction_cancel_handler, NULL);
		ctdb->freeze_transaction_started = false;
	}

	ctdb_db_iterator(ctdb, db_thaw, NULL);

	ctdb->freeze_mode   = CTDB_FREEZE_NONE;
	ctdb->freeze_handle = NULL;

	return 0;
}

/*
  called when the child writes its status to us
 */
static void ctdb_freeze_lock_handler(void *private_data, bool locked)
{
	struct ctdb_freeze_handle *h = talloc_get_type_abort(private_data,
							     struct ctdb_freeze_handle);
	struct ctdb_freeze_waiter *w;

	if (h->ctdb->freeze_mode == CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_INFO,("freeze child died - unfreezing\n"));
		talloc_free(h);
		return;
	}

	if (!locked) {
		DEBUG(DEBUG_ERR,("Failed to get locks in ctdb_freeze_child\n"));
		/* we didn't get the locks - destroy the handle */
		talloc_free(h);
		return;
	}

	h->ctdb->freeze_mode = CTDB_FREEZE_FROZEN;

	/* notify the waiters */
	if (h != h->ctdb->freeze_handle) {
		DEBUG(DEBUG_ERR,("lockwait finished but h is not linked\n"));
	}
	while ((w = h->waiters)) {
		w->status = 0;
		DLIST_REMOVE(h->waiters, w);
		talloc_free(w);
	}
}

/**
 * When single database is frozen
 */
static int db_freeze_waiter_destructor(struct ctdb_db_freeze_waiter *w)
{
	struct ctdb_freeze_handle *h = talloc_get_type_abort(
		w->private_data, struct ctdb_freeze_handle);

	if (w->status == 0) {
		h->num_locked += 1;
	} else {
		h->num_failed += 1;
	}

	/* Call ctdb_freeze_lock_handler() only when the status of all
	 * databases is known.
	 */
	if (h->num_locked + h->num_failed == h->num_total) {
		bool locked;

		if (h->num_locked == h->num_total) {
			locked = true;
		} else {
			locked = false;
		}
		ctdb_freeze_lock_handler(h, locked);
	}
	return 0;
}

/**
 * Invalidate the records in the database.
 * This only applies to volatile databases.
 */
static int db_invalidate(struct ctdb_db_context *ctdb_db, void *private_data)
{
	if (ctdb_db_volatile(ctdb_db)) {
		ctdb_db->invalid_records = true;
	}

	return 0;
}

/**
 * Count the number of databases
 */
static int db_count(struct ctdb_db_context *ctdb_db, void *private_data)
{
	unsigned int *count = (unsigned int *)private_data;

	*count += 1;

	return 0;
}

/**
 * Freeze a single database
 */
static int db_freeze(struct ctdb_db_context *ctdb_db, void *private_data)
{
	struct ctdb_freeze_handle *h = talloc_get_type_abort(
		private_data, struct ctdb_freeze_handle);
	struct ctdb_db_freeze_waiter *w;

	ctdb_start_db_freeze(ctdb_db);

	w = talloc(ctdb_db->freeze_handle, struct ctdb_db_freeze_waiter);
	CTDB_NO_MEMORY(h->ctdb, w);
	w->ctdb = h->ctdb;
	w->private_data = h;
	w->status = -1;
	talloc_set_destructor(w, db_freeze_waiter_destructor);

	if (ctdb_db->freeze_mode == CTDB_FREEZE_FROZEN) {
		/* Early return if already frozen */
		w->status = 0;
		talloc_free(w);
		return 0;
	}

	DLIST_ADD(ctdb_db->freeze_handle->waiters, w);

	return 0;
}

/*
  start the freeze process for all databases
  This is only called from ctdb_control_freeze(), which is called
  only on node becoming INACTIVE.  So mark the records invalid.
 */
static void ctdb_start_freeze(struct ctdb_context *ctdb)
{
	struct ctdb_freeze_handle *h;
	int ret;

	ctdb_db_iterator(ctdb, db_invalidate, NULL);

	if (ctdb->freeze_mode == CTDB_FREEZE_FROZEN) {
		unsigned int count = 0;

		/*
		 * Check if all the databases are frozen
		 *
		 * It's possible that the databases can get attached after
		 * initial freeze. This typically happens during startup as
		 * CTDB will only attach persistent databases and go in to
		 * startup freeze.  The recovery master during recovery will
		 * attach all the missing databases.
		 */

		h = ctdb->freeze_handle;
		if (h == NULL) {
			ctdb->freeze_mode = CTDB_FREEZE_NONE;
			return;
		}

		ret = ctdb_db_iterator(ctdb, db_count, &count);
		if (ret != 0) {
			TALLOC_FREE(ctdb->freeze_handle);
			ctdb->freeze_mode = CTDB_FREEZE_NONE;
			return;
		}

		if (count != h->num_total) {
			DEBUG(DEBUG_ERR, ("Freeze all: incremental\n"));

			h->num_total = count;
			h->num_locked = 0;
			h->num_failed = 0;

			ctdb->freeze_mode = CTDB_FREEZE_PENDING;

			ret = ctdb_db_iterator(ctdb, db_freeze, h);
			if (ret != 0) {
				TALLOC_FREE(ctdb->freeze_handle);
				ctdb->freeze_mode = CTDB_FREEZE_NONE;
			}
		}
		return;
	}

	if (ctdb->freeze_handle != NULL) {
		/* already trying to freeze */
		return;
	}

	DEBUG(DEBUG_ERR, ("Freeze all\n"));

	/* Stop any vacuuming going on: we don't want to wait. */
	ctdb_stop_vacuuming(ctdb);

	/* create freeze lock children for each database */
	h = talloc_zero(ctdb, struct ctdb_freeze_handle);
	CTDB_NO_MEMORY_FATAL(ctdb, h);
	h->ctdb = ctdb;
	talloc_set_destructor(h, ctdb_freeze_handle_destructor);
	ctdb->freeze_handle = h;

	ret = ctdb_db_iterator(ctdb, db_count, &h->num_total);
	if (ret != 0) {
		talloc_free(h);
		return;
	}

	ctdb->freeze_mode = CTDB_FREEZE_PENDING;

	ret = ctdb_db_iterator(ctdb, db_freeze, h);
	if (ret != 0) {
		talloc_free(h);
		return;
	}

	if (h->num_total == 0) {
		ctdb->freeze_mode = CTDB_FREEZE_FROZEN;
	}
}

/*
  destroy a waiter for a freeze mode change
 */
static int ctdb_freeze_waiter_destructor(struct ctdb_freeze_waiter *w)
{
	ctdb_request_control_reply(w->ctdb, w->c, NULL, w->status, NULL);
	return 0;
}

/*
  freeze all the databases
  This control is only used when freezing database on node becoming INACTIVE.
  So mark the records invalid in ctdb_start_freeze().
 */
int32_t ctdb_control_freeze(struct ctdb_context *ctdb,
			    struct ctdb_req_control_old *c, bool *async_reply)
{
	struct ctdb_freeze_waiter *w;

	ctdb_start_freeze(ctdb);

	if (ctdb->freeze_mode == CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR, ("Freeze all: frozen\n"));
		/* we're already frozen */
		return 0;
	}

	if (ctdb->freeze_handle == NULL) {
		DEBUG(DEBUG_ERR,("No freeze lock handle when adding a waiter\n"));
		return -1;
	}

	/* If there are no databases, we are done. */
	if (ctdb->freeze_handle->num_total == 0) {
		return 0;
	}

	/* add ourselves to list of waiters */
	w = talloc(ctdb->freeze_handle, struct ctdb_freeze_waiter);
	CTDB_NO_MEMORY(ctdb, w);
	w->ctdb     = ctdb;
	w->c        = talloc_steal(w, c);
	w->status   = -1;
	talloc_set_destructor(w, ctdb_freeze_waiter_destructor);
	DLIST_ADD(ctdb->freeze_handle->waiters, w);

	/* we won't reply till later */
	*async_reply = true;
	return 0;
}


static int db_freeze_block(struct ctdb_db_context *ctdb_db, void *private_data)
{
	struct tevent_context *ev = (struct tevent_context *)private_data;

	ctdb_start_db_freeze(ctdb_db);

	while (ctdb_db->freeze_mode == CTDB_FREEZE_PENDING) {
		tevent_loop_once(ev);
	}

	if (ctdb_db->freeze_mode != CTDB_FREEZE_FROZEN) {
		return -1;
	}

	return 0;
}

/*
  block until we are frozen, used during daemon startup
 */
bool ctdb_blocking_freeze(struct ctdb_context *ctdb)
{
	int ret;

	ret = ctdb_db_iterator(ctdb, db_freeze_block, ctdb->ev);
	if (ret != 0) {
		return false;
	}

	return true;
}

/*
  thaw the databases
 */
int32_t ctdb_control_thaw(struct ctdb_context *ctdb, bool check_recmode)
{
	if (check_recmode && ctdb->recovery_mode == CTDB_RECOVERY_ACTIVE) {
		DEBUG(DEBUG_ERR, ("Failing to thaw databases while "
				  "recovery is active\n"));
		return -1;
	}

	DEBUG(DEBUG_ERR,("Thawing all\n"));

	/* cancel any pending transactions */
	if (ctdb->freeze_transaction_started) {
		ctdb_db_iterator(ctdb, db_transaction_cancel_handler, NULL);
		ctdb->freeze_transaction_started = false;
	}

	ctdb_db_iterator(ctdb, db_thaw, NULL);
	TALLOC_FREE(ctdb->freeze_handle);

	ctdb_call_resend_all(ctdb);
	return 0;
}

/**
 * Database transaction wrappers
 *
 * These functions are wrappers around transaction start/cancel/commit handlers.
 */

struct db_start_transaction_state {
	uint32_t transaction_id;
	bool transaction_started;
};

static int db_start_transaction(struct ctdb_db_context *ctdb_db,
				void *private_data)
{
	struct db_start_transaction_state *state =
		(struct db_start_transaction_state *)private_data;
	int ret;
	bool transaction_started;

	if (ctdb_db->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR,
		      ("Database %s not frozen, cannot start transaction\n",
		       ctdb_db->db_name));
		return -1;
	}

	transaction_started = state->transaction_started &
			      ctdb_db->freeze_transaction_started;

	ret = db_transaction_start_handler(ctdb_db,
					   &transaction_started);
	if (ret != 0) {
		return -1;
	}

	ctdb_db->freeze_transaction_started = true;
	ctdb_db->freeze_transaction_id = state->transaction_id;

	return 0;
}

static int db_cancel_transaction(struct ctdb_db_context *ctdb_db,
				 void *private_data)
{
	int ret;

	ret = db_transaction_cancel_handler(ctdb_db, private_data);
	if (ret != 0) {
		return ret;
	}

	ctdb_db->freeze_transaction_started = false;

	return 0;
}

struct db_commit_transaction_state {
	uint32_t transaction_id;
	unsigned int healthy_nodes;
};

static int db_commit_transaction(struct ctdb_db_context *ctdb_db,
				 void *private_data)
{
	struct db_commit_transaction_state *state =
		(struct db_commit_transaction_state *)private_data;
	int ret;

	if (ctdb_db->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR,
		      ("Database %s not frozen, cannot commit transaction\n",
		       ctdb_db->db_name));
		return -1;
	}

	if (!ctdb_db->freeze_transaction_started) {
		DEBUG(DEBUG_ERR, ("Transaction not started on %s\n",
				  ctdb_db->db_name));
		return -1;
	}

	if (ctdb_db->freeze_transaction_id != state->transaction_id) {
		DEBUG(DEBUG_ERR,
		      ("Incorrect transaction commit id 0x%08x for %s\n",
		       state->transaction_id, ctdb_db->db_name));
		return -1;
	}

	ret = db_transaction_commit_handler(ctdb_db, &state->healthy_nodes);
	if (ret != 0) {
		return -1;
	}

	ctdb_db->freeze_transaction_started = false;
	ctdb_db->freeze_transaction_id = 0;
	ctdb_db->generation = state->transaction_id;
	return 0;
}

/**
 * Start a transaction on a database - used for db recovery
 */
int32_t ctdb_control_db_transaction_start(struct ctdb_context *ctdb,
					  TDB_DATA indata)
{
	struct ctdb_transdb *w =
		(struct ctdb_transdb *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	struct db_start_transaction_state state;

	ctdb_db = find_ctdb_db(ctdb, w->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,
		      ("Transaction start for unknown dbid 0x%08x\n",
		       w->db_id));
		return -1;
	}

	state.transaction_id = w->tid;
	state.transaction_started = true;

	return db_start_transaction(ctdb_db, &state);
}

/**
 * Cancel a transaction on a database - used for db recovery
 */
int32_t ctdb_control_db_transaction_cancel(struct ctdb_context *ctdb,
					   TDB_DATA indata)
{
	uint32_t db_id = *(uint32_t *)indata.dptr;
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,
		      ("Transaction cancel for unknown dbid 0x%08x\n", db_id));
		return -1;
	}

	DEBUG(DEBUG_ERR, ("Recovery db transaction cancelled for %s\n",
			  ctdb_db->db_name));

	return db_cancel_transaction(ctdb_db, NULL);
}

/**
 * Commit a transaction on a database - used for db recovery
 */
int32_t ctdb_control_db_transaction_commit(struct ctdb_context *ctdb,
					   TDB_DATA indata)
{
	struct ctdb_transdb *w =
		(struct ctdb_transdb *)indata.dptr;
	struct ctdb_db_context *ctdb_db;
	struct db_commit_transaction_state state;
	unsigned int healthy_nodes, i;

	ctdb_db = find_ctdb_db(ctdb, w->db_id);
	if (ctdb_db == NULL) {
		DEBUG(DEBUG_ERR,
		      ("Transaction commit for unknown dbid 0x%08x\n",
		       w->db_id));
		return -1;
	}

	healthy_nodes = 0;
	for (i=0; i < ctdb->num_nodes; i++) {
		if (ctdb->nodes[i]->flags == 0) {
			healthy_nodes += 1;
		}
	}

	state.transaction_id = w->tid;
	state.healthy_nodes = healthy_nodes;

	return db_commit_transaction(ctdb_db, &state);
}

/*
  wipe a database - only possible when in a frozen transaction
 */
int32_t ctdb_control_wipe_database(struct ctdb_context *ctdb, TDB_DATA indata)
{
	struct ctdb_transdb w = *(struct ctdb_transdb *)indata.dptr;
	struct ctdb_db_context *ctdb_db;

	ctdb_db = find_ctdb_db(ctdb, w.db_id);
	if (!ctdb_db) {
		DEBUG(DEBUG_ERR,(__location__ " Unknown db 0x%x\n", w.db_id));
		return -1;
	}

	if (ctdb_db->freeze_mode != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR,(__location__ " Failed transaction_start while not frozen\n"));
		return -1;
	}

	if (!ctdb_db->freeze_transaction_started) {
		DEBUG(DEBUG_ERR,(__location__ " transaction not started\n"));
		return -1;
	}

	if (w.tid != ctdb_db->freeze_transaction_id) {
		DEBUG(DEBUG_ERR,(__location__ " incorrect transaction id 0x%x in commit\n", w.tid));
		return -1;
	}

	if (tdb_wipe_all(ctdb_db->ltdb->tdb) != 0) {
		DEBUG(DEBUG_ERR,(__location__ " Failed to wipe database for db '%s'\n",
			 ctdb_db->db_name));
		return -1;
	}

	if (ctdb_db_volatile(ctdb_db)) {
		talloc_free(ctdb_db->delete_queue);
		talloc_free(ctdb_db->fetch_queue);
		ctdb_db->delete_queue = trbt_create(ctdb_db, 0);
		if (ctdb_db->delete_queue == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to re-create "
					  "the delete queue.\n"));
			return -1;
		}
		ctdb_db->fetch_queue = trbt_create(ctdb_db, 0);
		if (ctdb_db->fetch_queue == NULL) {
			DEBUG(DEBUG_ERR, (__location__ " Failed to re-create "
					  "the fetch queue.\n"));
			return -1;
		}
	}

	return 0;
}

bool ctdb_db_frozen(struct ctdb_db_context *ctdb_db)
{
	if (ctdb_db->freeze_mode != CTDB_FREEZE_FROZEN) {
		return false;
	}

	return true;
}

bool ctdb_db_all_frozen(struct ctdb_context *ctdb)
{
	if (ctdb->freeze_mode != CTDB_FREEZE_FROZEN) {
		return false;
	}
	return true;
}

bool ctdb_db_allow_access(struct ctdb_db_context *ctdb_db)
{
	if (ctdb_db->freeze_mode == CTDB_FREEZE_NONE) {
		/* If database is not frozen, then allow access. */
		return true;
	} else if (ctdb_db->freeze_transaction_started) {
		/* If database is frozen, allow access only if the
		 * transaction is started.  This is required during
		 * recovery.
		 *
		 * If a node is inactive, then transaction is not started.
		 */
		return true;
	}

	return false;
}
