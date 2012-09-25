/*
   ctdb lock handling
   provide API to do non-blocking locks for single or all databases

   Copyright (C) Amitay Isaacs  2012

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
#include "include/ctdb_private.h"
#include "include/ctdb_protocol.h"
#include "tevent.h"
#include "tdb.h"
#include "db_wrap.h"
#include "system/filesys.h"
#include "lib/util/dlinklist.h"

/*
 * Non-blocking Locking API
 *
 * 1. Create a child process to do blocking locks.
 * 2. Once the locks are obtained, signal parent process via fd.
 * 3. Invoke registered callback routine with locking status.
 * 4. If the child process cannot get locks within certain time,
 *    diagnose using /proc/locks and log warning message
 *
 * ctdb_lock_record()      - get a lock on a record
 * ctdb_lock_db()          - get a lock on a DB
 * ctdb_lock_alldb_prio()  - get a lock on all DBs with given priority
 * ctdb_lock_alldb()       - get a lock on all DBs
 *
 *  auto_mark              - whether to mark/unmark DBs in before/after callback
 */

/* FIXME: Add a tunable max_lock_processes_per_db */
#define MAX_LOCK_PROCESSES_PER_DB		(100)

enum lock_type {
	LOCK_RECORD,
	LOCK_DB,
	LOCK_ALLDB_PRIO,
	LOCK_ALLDB,
};

struct lock_request;

/* lock_context is the common part for a lock request */
struct lock_context {
	struct lock_context *next, *prev;
	enum lock_type type;
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	TDB_DATA key;
	uint32_t priority;
	bool auto_mark;
	struct lock_request *req_queue;
	pid_t child;
	int fd[2];
	struct tevent_fd *tfd;
	struct tevent_timer *ttimer;
	pid_t block_child;
	int block_fd[2];
	struct timeval start_time;
};

/* lock_request is the client specific part for a lock request */
struct lock_request {
	struct lock_request *next, *prev;
	struct lock_context *lctx;
	void (*callback)(void *, bool);
	void *private_data;
};


/*
 * Support samba 3.6.x (and older) versions which do not set db priority.
 *
 * By default, all databases are set to priority 1. So only when priority
 * is set to 1, check for databases that need higher priority.
 */
static bool later_db(const char *name)
{
	if (strstr(name, "brlock") ||
	    strstr(name, "g_lock") ||
	    strstr(name, "notify_onelevel") ||
	    strstr(name, "serverid") ||
	    strstr(name, "xattr_tdb")) {
		return true;
	}

	return false;
}

/*
 * lock all databases
 */
int ctdb_lockall_prio(struct ctdb_context *ctdb, uint32_t priority)
{
	struct ctdb_db_context *ctdb_db;

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->priority != priority) {
			continue;
		}
		if (later_db(ctdb_db->db_name)) {
			continue;
		}
		DEBUG(DEBUG_INFO, ("locking database %s, priority:%u\n",
				   ctdb_db->db_name, priority));
		if (tdb_lockall(ctdb_db->ltdb->tdb) != 0) {
			DEBUG(DEBUG_ERR, ("Failed to lock database %s\n",
					  ctdb_db->db_name));
			return -1;
		}
	}

	/* If priority != 1, later_db check is not required and can return */
	if (priority != 1) {
		return 0;
	}

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (!later_db(ctdb_db->db_name)) {
			continue;
		}
		DEBUG(DEBUG_INFO, ("locking database %s, priority:%u\n",
				   ctdb_db->db_name, priority));
		if (tdb_lockall(ctdb_db->ltdb->tdb) != 0) {
			DEBUG(DEBUG_ERR, ("Failed to lock database %s\n",
					  ctdb_db->db_name));
			return -1;
		}
	}

	return 0;
}

static int ctdb_lockall(struct ctdb_context *ctdb)
{
	uint32_t priority;

	for (priority=1; priority<=NUM_DB_PRIORITIES; priority++) {
		if (ctdb_lockall_prio(ctdb, priority) != 0) {
			return -1;
		}
	}

	return 0;
}


/*
 * unlock all databases
 */
int ctdb_unlockall_prio(struct ctdb_context *ctdb, uint32_t priority)
{
	struct ctdb_db_context *ctdb_db;

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->priority != priority) {
			continue;
		}
		DEBUG(DEBUG_INFO, ("unlocking database %s, priority:%u\n",
				   ctdb_db->db_name, priority));
		if (tdb_unlockall(ctdb_db->ltdb->tdb) != 0) {
			DEBUG(DEBUG_ERR, ("Failed to unlock database %s\n",
					  ctdb_db->db_name));
			return -1;
		}
	}

	return 0;
}

static int ctdb_unlockall(struct ctdb_context *ctdb)
{
	uint32_t priority;

	for (priority=NUM_DB_PRIORITIES; priority>=0; priority--) {
		if (ctdb_unlockall_prio(ctdb, priority) != 0) {
			return -1;
		}
	}

	return 0;
}


/*
 * lock all databases - mark only
 */
int ctdb_lockall_mark_prio(struct ctdb_context *ctdb, uint32_t priority)
{
	struct ctdb_db_context *ctdb_db;
	int tdb_transaction_write_lock_mark(struct tdb_context *);

	/*
	 * This function is only used by the main dameon during recovery.
	 * At this stage, the databases have already been locked, by a
	 * dedicated child process. The freeze_mode variable is used to track
	 * whether the actual locks are held by the child process or not.
	 */

	if (ctdb->freeze_mode[priority] != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR, ("Attempt to mark all databases locked when not frozen\n"));
		return -1;
	}

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->priority != priority) {
			continue;
		}
		if (later_db(ctdb_db->db_name)) {
			continue;
		}
		if (tdb_transaction_write_lock_mark(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
		if (tdb_lockall_mark(ctdb_db->ltdb->tdb) != 0) {
			/* FIXME: Shouldn't we unmark here? */
			return -1;
		}
	}

	/* If priority != 1, later_db check is not required and can return */
	if (priority != 1) {
		return 0;
	}

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (!later_db(ctdb_db->db_name)) {
			continue;
		}
		if (tdb_transaction_write_lock_mark(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
		if (tdb_lockall_mark(ctdb_db->ltdb->tdb) != 0) {
			/* FIXME: Shouldn't we unmark here? */
			return -1;
		}
	}

	return 0;
}

static int ctdb_lockall_mark(struct ctdb_context *ctdb)
{
	uint32_t priority;

	for (priority=1; priority<=NUM_DB_PRIORITIES; priority++) {
		if (ctdb_lockall_mark_prio(ctdb, priority) != 0) {
			return -1;
		}
	}

	return 0;
}


/*
 * lock all databases - unmark only
 */
int ctdb_lockall_unmark_prio(struct ctdb_context *ctdb, uint32_t priority)
{
	struct ctdb_db_context *ctdb_db;
	int tdb_transaction_write_lock_unmark(struct tdb_context *);

	/*
	 * This function is only used by the main dameon during recovery.
	 * At this stage, the databases have already been locked, by a
	 * dedicated child process. The freeze_mode variable is used to track
	 * whether the actual locks are held by the child process or not.
	 */

	if (ctdb->freeze_mode[priority] != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR, ("Attempt to unmark all databases locked when not frozen\n"));
		return -1;
	}

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->priority != priority) {
			continue;
		}
		if (tdb_transaction_write_lock_unmark(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
		if (tdb_lockall_unmark(ctdb_db->ltdb->tdb) != 0) {
			return -1;
		}
	}

	return 0;
}

static int ctdb_lockall_unmark(struct ctdb_context *ctdb)
{
	uint32_t priority;

	for (priority=NUM_DB_PRIORITIES; priority>=0; priority--) {
		if (ctdb_lockall_unmark_prio(ctdb, priority) != 0) {
			return -1;
		}
	}

	return 0;
}


/*
 * Lock record / db depending on lock_ctx->type
 * Called from child context.
 */
static bool ctdb_lock_item(struct lock_context *lock_ctx)
{
	bool status = false;

	switch (lock_ctx->type) {
	case LOCK_RECORD:
		if (tdb_chainlock(lock_ctx->ctdb_db->ltdb->tdb, lock_ctx->key) == 0) {
			status = true;
		}
		break;

	case LOCK_DB:
		if (tdb_lockall(lock_ctx->ctdb_db->ltdb->tdb) == 0) {
			status = true;
		}
		break;

	case LOCK_ALLDB_PRIO:
		if (ctdb_lockall_prio(lock_ctx->ctdb, lock_ctx->priority) == 0) {
			status = true;
		}
		break;

	case LOCK_ALLDB:
		if (ctdb_lockall(lock_ctx->ctdb) == 0) {
			status = true;
		}
		break;
	}

	return status;
}


/*
 * Unlock record / db depending on lock_ctx->type
 */
void ctdb_unlock_item(struct lock_context *lock_ctx)
{
	switch (lock_ctx->type) {
	case LOCK_RECORD:
		tdb_chainunlock(lock_ctx->ctdb_db->ltdb->tdb, lock_ctx->key);
		break;

	case LOCK_DB:
		tdb_unlockall(lock_ctx->ctdb_db->ltdb->tdb);
		break;

	case LOCK_ALLDB_PRIO:
		ctdb_unlockall_prio(lock_ctx->ctdb, lock_ctx->priority);
		break;

	case LOCK_ALLDB:
		ctdb_unlockall(lock_ctx->ctdb);
		break;
	}
}

static void ctdb_lock_schedule(struct ctdb_context *ctdb);

/*
 * Destructor to kill the child locking process
 */
static int ctdb_lock_context_destructor(struct lock_context *lock_ctx)
{
	if (lock_ctx->child > 0) {
		ctdb_kill(lock_ctx->ctdb, lock_ctx->child, SIGKILL);
		DLIST_REMOVE(lock_ctx->ctdb->lock_current, lock_ctx);
		lock_ctx->ctdb->lock_num_current--;
		CTDB_DECREMENT_STAT(lock_ctx->ctdb, locks.num_current);
		if (lock_ctx->type == LOCK_RECORD || lock_ctx->type == LOCK_DB) {
			CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_current);
		}
	} else {
		DLIST_REMOVE(lock_ctx->ctdb->lock_pending, lock_ctx);
		lock_ctx->ctdb->lock_num_pending--;
		CTDB_DECREMENT_STAT(lock_ctx->ctdb, locks.num_pending);
		if (lock_ctx->type == LOCK_RECORD || lock_ctx->type == LOCK_DB) {
			CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_pending);
		}
	}

	ctdb_lock_schedule(lock_ctx->ctdb);

	return 0;
}


/*
 * Destructor to remove lock request
 */
static int ctdb_lock_request_destructor(struct lock_request *lock_request)
{
	DLIST_REMOVE(lock_request->lctx->req_queue, lock_request);
	return 0;
}


void ctdb_lock_free_request_context(struct lock_request *lock_req)
{
	struct lock_context *lock_ctx;

	lock_ctx = lock_req->lctx;
	talloc_free(lock_req);
	talloc_free(lock_ctx);
}


/*
 * Process all the callbacks waiting for lock
 *
 * If lock has failed, callback is executed with locked=false
 */
static void process_callbacks(struct lock_context *lock_ctx, bool locked)
{
	struct lock_request *request, *next;

	if (lock_ctx->auto_mark && locked) {
		switch (lock_ctx->type) {
		case LOCK_RECORD:
			tdb_chainlock_mark(lock_ctx->ctdb_db->ltdb->tdb, lock_ctx->key);
			break;

		case LOCK_DB:
			tdb_lockall_mark(lock_ctx->ctdb_db->ltdb->tdb);
			break;

		case LOCK_ALLDB_PRIO:
			ctdb_lockall_mark_prio(lock_ctx->ctdb, lock_ctx->priority);
			break;

		case LOCK_ALLDB:
			ctdb_lockall_mark(lock_ctx->ctdb);
			break;
		}
	}

	/* Iterate through all callbacks */
	request = lock_ctx->req_queue;
	while (request) {
		if (lock_ctx->auto_mark) {
			/* Reset the destructor, so request is not removed from the list */
			talloc_set_destructor(request, NULL);
		}

		/* In case, callback frees the request, store next */
		next = request->next;
		request->callback(request->private_data, locked);
		request = next;
	}

	if (lock_ctx->auto_mark && locked) {
		switch (lock_ctx->type) {
		case LOCK_RECORD:
			tdb_chainlock_unmark(lock_ctx->ctdb_db->ltdb->tdb, lock_ctx->key);
			break;

		case LOCK_DB:
			tdb_lockall_unmark(lock_ctx->ctdb_db->ltdb->tdb);
			break;

		case LOCK_ALLDB_PRIO:
			ctdb_lockall_unmark_prio(lock_ctx->ctdb, lock_ctx->priority);
			break;

		case LOCK_ALLDB:
			ctdb_lockall_unmark(lock_ctx->ctdb);
			break;
		}
	}
}


static int lock_bucket_id(double t)
{
	double us = 1.e-6, ms = 1.e-3, s = 1;
	int id;

	if (t < 1*us) {
		id = 0;
	} else if (t < 10*us) {
		id = 1;
	} else if (t < 100*us) {
		id = 2;
	} else if (t < 1*ms) {
		id = 3;
	} else if (t < 10*ms) {
		id = 4;
	} else if (t < 100*ms) {
		id = 5;
	} else if (t < 1*s) {
		id = 6;
	} else if (t < 10*s) {
		id = 7;
	} else {
		id = 8;
	}

	return id;
}

/*
 * Callback routine when the required locks are obtained.
 * Called from parent context
 */
static void ctdb_lock_handler(struct tevent_context *ev,
			    struct tevent_fd *tfd,
			    uint16_t flags,
			    void *private_data)
{
	struct lock_context *lock_ctx;
	TALLOC_CTX *tmp_ctx;
	char c;
	bool locked;
	double t;
	int id;

	lock_ctx = talloc_get_type_abort(private_data, struct lock_context);

	/* cancel the timeout event */
	if (lock_ctx->ttimer) {
		TALLOC_FREE(lock_ctx->ttimer);
	}

	t = timeval_elapsed(&lock_ctx->start_time);
	id = lock_bucket_id(t);

	if (lock_ctx->auto_mark) {
		tmp_ctx = talloc_new(ev);
		talloc_steal(tmp_ctx, lock_ctx);
	}

	/* Read the status from the child process */
	read(lock_ctx->fd[0], &c, 1);
	locked = (c == 0 ? true : false);

	/* Update statistics */
	CTDB_DECREMENT_STAT(lock_ctx->ctdb, locks.num_pending);
	CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.num_calls);
	if (lock_ctx->ctdb_db) {
		CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_pending);
		CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_calls);
	}

	if (locked) {
		CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.num_current);
		CTDB_UPDATE_RECLOCK_LATENCY(lock_ctx->ctdb, "lock()", locks.latency, t);
		CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.buckets[id]);
		if (lock_ctx->ctdb_db) {
			CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_current);
			CTDB_UPDATE_DB_RECLOCK_LATENCY(lock_ctx->ctdb_db, "lock()", locks.latency, t);
			CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.buckets[id]);
		}
	} else {
		CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.num_failed);
		if (lock_ctx->ctdb_db) {
			CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_failed);
		}
	}

	process_callbacks(lock_ctx, locked);

	if (lock_ctx->auto_mark) {
		talloc_free(tmp_ctx);
	}
}


static void ctdb_lock_find_blocker(struct lock_context *lock_ctx);

/*
 * Callback routine when required locks are not obtained within timeout
 * Called from parent context
 */
static void ctdb_lock_timeout_handler(struct tevent_context *ev,
				    struct tevent_timer *ttimer,
				    struct timeval current_time,
				    void *private_data)
{
	struct lock_context *lock_ctx;
	struct ctdb_context *ctdb;

	lock_ctx = talloc_get_type_abort(private_data, struct lock_context);
	ctdb = lock_ctx->ctdb;

	/* fire a child process to find the blocking process */
	if (lock_ctx->block_child == -1) {
		ctdb_lock_find_blocker(lock_ctx);
	}

	/* reset the timeout timer */
	// talloc_free(lock_ctx->ttimer);
	lock_ctx->ttimer = tevent_add_timer(ctdb->ev,
					    lock_ctx,
					    timeval_current_ofs(10, 0),
					    ctdb_lock_timeout_handler,
					    (void *)lock_ctx);
}


static char *lock_child_log_prefix(struct lock_context *lock_ctx)
{
	char *prefix;
	pid_t pid;

	pid = getpid();

	switch (lock_ctx->type) {
	case LOCK_RECORD:
		prefix = talloc_asprintf(NULL, "lockR(%d): ", pid);
		break;

	case LOCK_DB:
		prefix = talloc_asprintf(NULL, "lockD(%d): ", pid);
		break;

	case LOCK_ALLDB_PRIO:
		prefix = talloc_asprintf(NULL, "lockP(%d): ", pid);
		break;

	case LOCK_ALLDB:
		prefix = talloc_asprintf(NULL, "lockA(%d): ", pid);
		break;
	}

	return prefix;
}


/*
 * Schedule a new lock child process
 * Set up callback handler and timeout handler
 */
static void ctdb_lock_schedule(struct ctdb_context *ctdb)
{
	struct lock_context *lock_ctx, *next_ctx;
	int ret;
	pid_t parent;

	if (ctdb->lock_num_current >= MAX_LOCK_PROCESSES_PER_DB) {
		return;
	}

	if (ctdb->lock_pending == NULL) {
		return;
	}

	/* Find a lock context with requests */
	lock_ctx = ctdb->lock_pending;
	while (lock_ctx != NULL) {
		if (! lock_ctx->req_queue) {
			next_ctx = lock_ctx->next;
			DEBUG(DEBUG_INFO, ("Removing lock context without lock requests\n"));
			DLIST_REMOVE(ctdb->lock_pending, lock_ctx);
			ctdb->lock_num_pending--;
			CTDB_DECREMENT_STAT(ctdb, locks.num_pending);
			if (lock_ctx->ctdb_db) {
				CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_pending);
			}
			talloc_free(lock_ctx);
			lock_ctx = next_ctx;
			continue;
		} else {
			/* Found a lock context with lock requests */
			break;
		}
	}

	if (lock_ctx == NULL) {
		return;
	}

	lock_ctx->child = -1;
	ret = pipe(lock_ctx->fd);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to create pipe in ctdb_lock_schedule\n"));
		return;
	}

	parent = getpid();
	lock_ctx->child = ctdb_fork(ctdb);

	if (lock_ctx->child == (pid_t)-1) {
		DEBUG(DEBUG_ERR, ("Failed to create a child in ctdb_lock_schedule\n"));
		close(lock_ctx->fd[0]);
		close(lock_ctx->fd[1]);
		return;
	}

	/* Child process */
	if (lock_ctx->child == 0) {
		char c;
		close(lock_ctx->fd[0]);
		debug_extra = lock_child_log_prefix(lock_ctx);
		if (ctdb_lock_item(lock_ctx)) {
			c = 0;
		} else {
			c = 1;
		}
		write(lock_ctx->fd[1], &c, 1);

		/* Hang around, but if parent dies, terminate */
		while (kill(parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
		}
		_exit(0);
	}

	/* Parent process */
	close(lock_ctx->fd[1]);
	set_close_on_exec(lock_ctx->fd[0]);

	talloc_set_destructor(lock_ctx, ctdb_lock_context_destructor);

	/* Set up timeout handler */
	lock_ctx->ttimer = tevent_add_timer(ctdb->ev,
					    lock_ctx,
					    timeval_current_ofs(10, 0),
					    ctdb_lock_timeout_handler,
					    (void *)lock_ctx);
	if (lock_ctx->ttimer == NULL) {
		ctdb_kill(ctdb, lock_ctx->child, SIGKILL);
		lock_ctx->child = -1;
		talloc_set_destructor(lock_ctx, NULL);
		close(lock_ctx->fd[0]);
		return;
	}

	/* Set up callback */
	lock_ctx->tfd = tevent_add_fd(ctdb->ev,
				      lock_ctx,
				      lock_ctx->fd[0],
				      EVENT_FD_READ,
				      ctdb_lock_handler,
				      (void *)lock_ctx);
	if (lock_ctx->tfd == NULL) {
		TALLOC_FREE(lock_ctx->ttimer);
		ctdb_kill(ctdb, lock_ctx->child, SIGKILL);
		lock_ctx->child = -1;
		talloc_set_destructor(lock_ctx, NULL);
		close(lock_ctx->fd[0]);
		return;
	}
	tevent_fd_set_auto_close(lock_ctx->tfd);

	/* Move the context from pending to current */
	DLIST_REMOVE(ctdb->lock_pending, lock_ctx);
	ctdb->lock_num_pending--;
	DLIST_ADD_END(ctdb->lock_current, lock_ctx, NULL);
	ctdb->lock_num_current++;
}


/*
 * Find the lock context of a given type
 */
static struct lock_context *find_lock_context(struct lock_context *lock_list,
					      struct ctdb_db_context *ctdb_db,
					      TDB_DATA key,
					      uint32_t priority,
					      enum lock_type type)
{
	struct lock_context *lock_ctx;

	/* Search active locks */
	for (lock_ctx=lock_list; lock_ctx; lock_ctx=lock_ctx->next) {
		if (lock_ctx->type != type) {
			continue;
		}

		switch (lock_ctx->type) {
		case LOCK_RECORD:
			if (ctdb_db == lock_ctx->ctdb_db &&
			    key.dsize == lock_ctx->key.dsize &&
			    memcmp(key.dptr, lock_ctx->key.dptr, key.dsize) == 0) {
				goto done;
			}
			break;

		case LOCK_DB:
			if (ctdb_db == lock_ctx->ctdb_db) {
				goto done;
			}
			break;

		case LOCK_ALLDB_PRIO:
			if (priority == lock_ctx->priority) {
				goto done;
			}
			break;

		case LOCK_ALLDB:
			goto done;
			break;
		}
	}

	/* Did not find the lock context we are searching for */
	lock_ctx = NULL;

done:
	return lock_ctx;

}


/*
 * Lock record / db depending on type
 */
static struct lock_request *ctdb_lock_internal(struct ctdb_context *ctdb,
					       struct ctdb_db_context *ctdb_db,
					       TDB_DATA key,
					       uint32_t priority,
					       void (*callback)(void *, bool),
					       void *private_data,
					       enum lock_type type,
					       bool auto_mark)
{
	struct lock_context *lock_ctx;
	struct lock_request *request;

	if (callback == NULL) {
		DEBUG(DEBUG_WARNING, ("No callback function specified, not locking"));
		return NULL;
	}

	/* get a context for this key - search only the pending contexts,
	 * current contexts might in the middle of processing callbacks */
	lock_ctx = find_lock_context(ctdb->lock_pending, ctdb_db, key, priority, type);

	/* No existing context, create one */
	if (lock_ctx == NULL) {
		lock_ctx = talloc_zero(ctdb, struct lock_context);
		if (lock_ctx == NULL) {
			DEBUG(DEBUG_ERR, ("Failed to create a new lock context"));
			return NULL;
		}

		lock_ctx->type = type;
		lock_ctx->ctdb = ctdb;
		lock_ctx->ctdb_db = ctdb_db;
		lock_ctx->key.dsize = key.dsize;
		if (key.dsize > 0) {
			lock_ctx->key.dptr = talloc_memdup(lock_ctx, key.dptr, key.dsize);
		} else {
			lock_ctx->key.dptr = NULL;
		}
		lock_ctx->priority = priority;
		lock_ctx->auto_mark = auto_mark;

		lock_ctx->child = -1;
		lock_ctx->block_child = -1;

		DLIST_ADD_END(ctdb->lock_pending, lock_ctx, NULL);
		ctdb->lock_num_pending++;
		CTDB_INCREMENT_STAT(ctdb, locks.num_pending);
		if (ctdb_db) {
			CTDB_INCREMENT_DB_STAT(ctdb_db, locks.num_pending);
		}

		/* Start the timer when we activate the context */
		lock_ctx->start_time = timeval_current();
	}

	if ((request = talloc_zero(lock_ctx, struct lock_request)) == NULL) {
		return NULL;
	}

	request->lctx = lock_ctx;
	request->callback = callback;
	request->private_data = private_data;

	talloc_set_destructor(request, ctdb_lock_request_destructor);
	DLIST_ADD_END(lock_ctx->req_queue, request, NULL);

	ctdb_lock_schedule(ctdb);

	return request;
}


/*
 * obtain a lock on a record in a database
 */
struct lock_request *ctdb_lock_record(struct ctdb_db_context *ctdb_db,
				      TDB_DATA key,
				      bool auto_mark,
				      void (*callback)(void *, bool),
				      void *private_data)
{
	return ctdb_lock_internal(ctdb_db->ctdb,
				  ctdb_db,
				  key,
				  0,
				  callback,
				  private_data,
				  LOCK_RECORD,
				  auto_mark);
}


/*
 * obtain a lock on a database
 */
struct lock_request *ctdb_lock_db(struct ctdb_db_context *ctdb_db,
				  bool auto_mark,
				  void (*callback)(void *, bool),
				  void *private_data)
{
	return ctdb_lock_internal(ctdb_db->ctdb,
				  ctdb_db,
				  tdb_null,
				  0,
				  callback,
				  private_data,
				  LOCK_DB,
				  auto_mark);
}


/*
 * obtain locks on all databases of specified priority
 */
struct lock_request *ctdb_lock_alldb_prio(struct ctdb_context *ctdb,
					  uint32_t priority,
					  bool auto_mark,
					  void (*callback)(void *, bool),
					  void *private_data)
{
	if (priority < 0 || priority > NUM_DB_PRIORITIES) {
		DEBUG(DEBUG_ERR, ("Invalid db priority: %u\n", priority));
		return NULL;
	}

	return ctdb_lock_internal(ctdb,
				  NULL,
				  tdb_null,
				  priority,
				  callback,
				  private_data,
				  LOCK_ALLDB_PRIO,
				  auto_mark);
}


/*
 * obtain locks on all databases
 */
struct lock_request *ctdb_lock_alldb(struct ctdb_context *ctdb,
				     bool auto_mark,
				     void (*callback)(void *, bool),
				     void *private_data)
{
	return ctdb_lock_internal(ctdb,
				  NULL,
				  tdb_null,
				  0,
				  callback,
				  private_data,
				  LOCK_ALLDB,
				  auto_mark);
}

/*
 * Callback routine to read the PID of blocking process from the child and log
 *
 */
void ctdb_lock_blocked_handler(struct tevent_context *ev,
				struct tevent_fd *tfd,
				uint16_t flags,
				void *private_data)
{
	struct lock_context *lock_ctx;
	pid_t blocker_pid = -1;
	char *process_name = NULL;
	const char *db_name = NULL;
	ino_t inode;
	struct ctdb_db_context *ctdb_db;
	int fd;
	struct stat stat_buf;

	lock_ctx = talloc_get_type_abort(private_data, struct lock_context);

	if (read(lock_ctx->block_fd[0], &blocker_pid, sizeof(blocker_pid)) != sizeof(blocker_pid)) {
		DEBUG(DEBUG_ERR, ("Error reading blocker process pid from child\n"));
		goto failed;
	}
	if (read(lock_ctx->block_fd[0], &inode, sizeof(inode)) != sizeof(inode)) {
		DEBUG(DEBUG_ERR, ("Error reading blocked inode from child\n"));
		goto failed;
	}

	if (blocker_pid < 0) {
		goto failed;
	}

	process_name = ctdb_get_process_name(blocker_pid);

	if (lock_ctx->type == LOCK_RECORD || lock_ctx->type == LOCK_DB) {
		db_name = lock_ctx->ctdb_db->ltdb->name;
	} else {
		for (ctdb_db = lock_ctx->ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
			fd = tdb_fd(ctdb_db->ltdb->tdb);
			if (fstat(fd, &stat_buf) == 0) {
				if (stat_buf.st_ino == inode) {
					db_name = ctdb_db->ltdb->name;
					break;
				}
			}
		}
	}

	if (db_name) {
		DEBUG(DEBUG_WARNING,
		      ("Process (pid=%d) blocked in locking\n", lock_ctx->child));
		DEBUG(DEBUG_WARNING,
		      ("Process %s (pid=%d) locked database %s (inode %lu) for %.0lf seconds\n",
		       (process_name ? process_name : "unknown"),
		       blocker_pid, db_name, inode,
		       timeval_elapsed(&lock_ctx->start_time)));
	} else {
		DEBUG(DEBUG_WARNING,
		      ("Process %s (pid=%d) locked database (inode %lu) for %.0lf seconds\n",
		       (process_name ? process_name : "unknown"),
		       blocker_pid, inode,
		       timeval_elapsed(&lock_ctx->start_time)));
	}

	/*
	 * If ctdb is blocked by smbd for deadlock_interval, detect it as a deadlock
	 * and kill smbd process.
	 */
	if (lock_ctx->ctdb->tunable.deadlock_timeout > 0 &&
	    timeval_elapsed(&lock_ctx->start_time) > lock_ctx->ctdb->tunable.deadlock_timeout &&
	    process_name && strstr(process_name, "smbd")) {
		DEBUG(DEBUG_WARNING,
		      ("Deadlock detected. Killing smbd process (pid=%d)", blocker_pid));
		kill(blocker_pid, SIGKILL);
	}

	free(process_name);

failed:
	if (lock_ctx->block_child > 0) {
		ctdb_kill(lock_ctx->ctdb, lock_ctx->block_child, SIGKILL);
	}
	lock_ctx->block_child = -1;
	talloc_free(tfd);
}


/*
 * Find processes that holds lock we are interested in
 */
void ctdb_lock_find_blocker(struct lock_context *lock_ctx)
{
	struct tevent_fd *tfd;
	pid_t parent;

	if (pipe(lock_ctx->block_fd) < 0) {
		return;
	}

	parent = getpid();

	lock_ctx->block_child = ctdb_fork(lock_ctx->ctdb);
	if (lock_ctx->block_child == -1) {
		close(lock_ctx->block_fd[0]);
		close(lock_ctx->block_fd[1]);
		return;
	}

	/* Child process */
	if (lock_ctx->block_child == 0) {
		struct ctdb_lock_info reqlock;
		pid_t blocker_pid = -1;
		bool status;

		close(lock_ctx->block_fd[0]);
		if (ctdb_get_lock_info(lock_ctx->child, &reqlock)) {
			status = ctdb_get_blocker_pid(&reqlock, &blocker_pid);
			if (!status) {
				/* Could not find blocker pid */
				blocker_pid = -2;
			}
		}
		write(lock_ctx->block_fd[1], &blocker_pid, sizeof(blocker_pid));
		write(lock_ctx->block_fd[1], &reqlock.inode, sizeof(reqlock.inode));

		/* Hang around till parent dies */
		while (kill(parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
		}
		_exit(0);
	}

	/* Parent process */
	close(lock_ctx->block_fd[1]);
	set_close_on_exec(lock_ctx->block_fd[0]);

	tfd = tevent_add_fd(lock_ctx->ctdb->ev,
				lock_ctx,
				lock_ctx->block_fd[0],
				EVENT_FD_READ,
				ctdb_lock_blocked_handler,
				(void *)lock_ctx);
	if (tfd == NULL) {
		ctdb_kill(lock_ctx->ctdb, lock_ctx->block_child, SIGKILL);
		close(lock_ctx->block_fd[0]);
	}
}
