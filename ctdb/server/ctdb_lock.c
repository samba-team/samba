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
#include "lib/tdb_wrap/tdb_wrap.h"
#include "system/filesys.h"
#include "lib/util/dlinklist.h"

/*
 * Non-blocking Locking API
 *
 * 1. Create a child process to do blocking locks.
 * 2. Once the locks are obtained, signal parent process via fd.
 * 3. Invoke registered callback routine with locking status.
 * 4. If the child process cannot get locks within certain time,
 *    execute an external script to debug.
 *
 * ctdb_lock_record()      - get a lock on a record
 * ctdb_lock_db()          - get a lock on a DB
 * ctdb_lock_alldb_prio()  - get a lock on all DBs with given priority
 * ctdb_lock_alldb()       - get a lock on all DBs
 *
 *  auto_mark              - whether to mark/unmark DBs in before/after callback
 */

enum lock_type {
	LOCK_RECORD,
	LOCK_DB,
	LOCK_ALLDB_PRIO,
	LOCK_ALLDB,
};

static const char * const lock_type_str[] = {
	"lock_record",
	"lock_db",
	"lock_alldb_prio",
	"lock_alldb",
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
	struct lock_request *request;
	pid_t child;
	int fd[2];
	struct tevent_fd *tfd;
	struct tevent_timer *ttimer;
	struct timeval start_time;
	uint32_t key_hash;
	bool can_schedule;
};

/* lock_request is the client specific part for a lock request */
struct lock_request {
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
static bool later_db(struct ctdb_context *ctdb, const char *name)
{
	if (ctdb->tunable.samba3_hack == 0) {
		return false;
	}

	if (strstr(name, "brlock") ||
	    strstr(name, "g_lock") ||
	    strstr(name, "notify_onelevel") ||
	    strstr(name, "serverid") ||
	    strstr(name, "xattr_tdb")) {
		return true;
	}

	return false;
}

typedef int (*db_handler_t)(struct ctdb_db_context *ctdb_db,
			    uint32_t priority,
			    void *private_data);

static int ctdb_db_iterator(struct ctdb_context *ctdb, uint32_t priority,
			    db_handler_t handler, void *private_data)
{
	struct ctdb_db_context *ctdb_db;
	int ret;

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->priority != priority) {
			continue;
		}
		if (later_db(ctdb, ctdb_db->db_name)) {
			continue;
		}
		ret = handler(ctdb_db, priority, private_data);
		if (ret != 0) {
			return -1;
		}
	}

	/* If priority != 1, later_db check is not required and can return */
	if (priority != 1) {
		return 0;
	}

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (!later_db(ctdb, ctdb_db->db_name)) {
			continue;
		}
		ret = handler(ctdb_db, priority, private_data);
		if (ret != 0) {
			return -1;
		}
	}

	return 0;
}


/*
 * lock all databases - mark only
 */
static int db_lock_mark_handler(struct ctdb_db_context *ctdb_db, uint32_t priority,
				void *private_data)
{
	int tdb_transaction_write_lock_mark(struct tdb_context *);

	DEBUG(DEBUG_INFO, ("marking locked database %s, priority:%u\n",
			   ctdb_db->db_name, priority));

	if (tdb_transaction_write_lock_mark(ctdb_db->ltdb->tdb) != 0) {
		DEBUG(DEBUG_ERR, ("Failed to mark (transaction lock) database %s\n",
				  ctdb_db->db_name));
		return -1;
	}

	if (tdb_lockall_mark(ctdb_db->ltdb->tdb) != 0) {
		DEBUG(DEBUG_ERR, ("Failed to mark (all lock) database %s\n",
				  ctdb_db->db_name));
		return -1;
	}

	return 0;
}

int ctdb_lockall_mark_prio(struct ctdb_context *ctdb, uint32_t priority)
{
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

	return ctdb_db_iterator(ctdb, priority, db_lock_mark_handler, NULL);
}

static int ctdb_lockall_mark(struct ctdb_context *ctdb)
{
	uint32_t priority;

	for (priority=1; priority<=NUM_DB_PRIORITIES; priority++) {
		if (ctdb_db_iterator(ctdb, priority, db_lock_mark_handler, NULL) != 0) {
			return -1;
		}
	}

	return 0;
}


/*
 * lock all databases - unmark only
 */
static int db_lock_unmark_handler(struct ctdb_db_context *ctdb_db, uint32_t priority,
				  void *private_data)
{
	int tdb_transaction_write_lock_unmark(struct tdb_context *);

	DEBUG(DEBUG_INFO, ("unmarking locked database %s, priority:%u\n",
			   ctdb_db->db_name, priority));

	if (tdb_transaction_write_lock_unmark(ctdb_db->ltdb->tdb) != 0) {
		DEBUG(DEBUG_ERR, ("Failed to unmark (transaction lock) database %s\n",
				  ctdb_db->db_name));
		return -1;
	}

	if (tdb_lockall_unmark(ctdb_db->ltdb->tdb) != 0) {
		DEBUG(DEBUG_ERR, ("Failed to unmark (all lock) database %s\n",
				  ctdb_db->db_name));
		return -1;
	}

	return 0;
}

int ctdb_lockall_unmark_prio(struct ctdb_context *ctdb, uint32_t priority)
{
	/*
	 * This function is only used by the main daemon during recovery.
	 * At this stage, the databases have already been locked, by a
	 * dedicated child process. The freeze_mode variable is used to track
	 * whether the actual locks are held by the child process or not.
	 */

	if (ctdb->freeze_mode[priority] != CTDB_FREEZE_FROZEN) {
		DEBUG(DEBUG_ERR, ("Attempt to unmark all databases locked when not frozen\n"));
		return -1;
	}

	return ctdb_db_iterator(ctdb, priority, db_lock_unmark_handler, NULL);
}

static int ctdb_lockall_unmark(struct ctdb_context *ctdb)
{
	uint32_t priority;

	for (priority=NUM_DB_PRIORITIES; priority>0; priority--) {
		if (ctdb_db_iterator(ctdb, priority, db_lock_unmark_handler, NULL) != 0) {
			return -1;
		}
	}

	return 0;
}


static void ctdb_lock_schedule(struct ctdb_context *ctdb);

/*
 * Destructor to kill the child locking process
 */
static int ctdb_lock_context_destructor(struct lock_context *lock_ctx)
{
	if (lock_ctx->request) {
		lock_ctx->request->lctx = NULL;
	}
	if (lock_ctx->child > 0) {
		ctdb_kill(lock_ctx->ctdb, lock_ctx->child, SIGKILL);
		if (lock_ctx->type == LOCK_RECORD) {
			DLIST_REMOVE(lock_ctx->ctdb_db->lock_current, lock_ctx);
		} else {
			DLIST_REMOVE(lock_ctx->ctdb->lock_current, lock_ctx);
		}
		if (lock_ctx->ctdb_db) {
			lock_ctx->ctdb_db->lock_num_current--;
		}
		CTDB_DECREMENT_STAT(lock_ctx->ctdb, locks.num_current);
		if (lock_ctx->ctdb_db) {
			CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_current);
		}
	} else {
		if (lock_ctx->type == LOCK_RECORD) {
			DLIST_REMOVE(lock_ctx->ctdb_db->lock_pending, lock_ctx);
		} else {
			DLIST_REMOVE(lock_ctx->ctdb->lock_pending, lock_ctx);
		}
		CTDB_DECREMENT_STAT(lock_ctx->ctdb, locks.num_pending);
		if (lock_ctx->ctdb_db) {
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
	TALLOC_FREE(lock_request->lctx);
	return 0;
}

/*
 * Process all the callbacks waiting for lock
 *
 * If lock has failed, callback is executed with locked=false
 */
static void process_callbacks(struct lock_context *lock_ctx, bool locked)
{
	struct lock_request *request;

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

	request = lock_ctx->request;
	if (lock_ctx->auto_mark) {
		/* Reset the destructor, so request is not removed from the list */
		talloc_set_destructor(request, NULL);
	}
	request->callback(request->private_data, locked);

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
	double ms = 1.e-3, s = 1;
	int id;

	if (t < 1*ms) {
		id = 0;
	} else if (t < 10*ms) {
		id = 1;
	} else if (t < 100*ms) {
		id = 2;
	} else if (t < 1*s) {
		id = 3;
	} else if (t < 2*s) {
		id = 4;
	} else if (t < 4*s) {
		id = 5;
	} else if (t < 8*s) {
		id = 6;
	} else if (t < 16*s) {
		id = 7;
	} else if (t < 32*s) {
		id = 8;
	} else if (t < 64*s) {
		id = 9;
	} else {
		id = 10;
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
	TALLOC_CTX *tmp_ctx = NULL;
	char c;
	bool locked;
	double t;
	int id;

	lock_ctx = talloc_get_type_abort(private_data, struct lock_context);

	/* cancel the timeout event */
	TALLOC_FREE(lock_ctx->ttimer);

	t = timeval_elapsed(&lock_ctx->start_time);
	id = lock_bucket_id(t);

	if (lock_ctx->auto_mark) {
		tmp_ctx = talloc_new(ev);
		talloc_steal(tmp_ctx, lock_ctx);
	}

	/* Read the status from the child process */
	if (sys_read(lock_ctx->fd[0], &c, 1) != 1) {
		locked = false;
	} else {
		locked = (c == 0 ? true : false);
	}

	/* Update statistics */
	CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.num_calls);
	if (lock_ctx->ctdb_db) {
		CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_calls);
	}

	if (locked) {
		if (lock_ctx->ctdb_db) {
			CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.buckets[id]);
			CTDB_UPDATE_LATENCY(lock_ctx->ctdb, lock_ctx->ctdb_db,
					    lock_type_str[lock_ctx->type], locks.latency,
					    lock_ctx->start_time);

			CTDB_UPDATE_DB_LATENCY(lock_ctx->ctdb_db, lock_type_str[lock_ctx->type], locks.latency, t);
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


/*
 * Callback routine when required locks are not obtained within timeout
 * Called from parent context
 */
static void ctdb_lock_timeout_handler(struct tevent_context *ev,
				    struct tevent_timer *ttimer,
				    struct timeval current_time,
				    void *private_data)
{
	static const char * debug_locks = NULL;
	struct lock_context *lock_ctx;
	struct ctdb_context *ctdb;
	pid_t pid;

	lock_ctx = talloc_get_type_abort(private_data, struct lock_context);
	ctdb = lock_ctx->ctdb;

	/* If a node stopped/banned, don't spam the logs */
	if (ctdb->nodes[ctdb->pnn]->flags & NODE_FLAGS_INACTIVE) {
		lock_ctx->ttimer = NULL;
		return;
	}
	if (lock_ctx->ctdb_db) {
		DEBUG(DEBUG_WARNING,
		      ("Unable to get %s lock on database %s for %.0lf seconds\n",
		       (lock_ctx->type == LOCK_RECORD ? "RECORD" : "DB"),
		       lock_ctx->ctdb_db->db_name,
		       timeval_elapsed(&lock_ctx->start_time)));
	} else {
		DEBUG(DEBUG_WARNING,
		      ("Unable to get ALLDB locks for %.0lf seconds\n",
		       timeval_elapsed(&lock_ctx->start_time)));
	}

	/* Fire a child process to find the blocking process. */
	if (debug_locks == NULL) {
		debug_locks = getenv("CTDB_DEBUG_LOCKS");
		if (debug_locks == NULL) {
			debug_locks = talloc_asprintf(ctdb,
						      "%s/debug_locks.sh",
						      getenv("CTDB_BASE"));
		}
	}
	if (debug_locks != NULL) {
		pid = vfork();
		if (pid == 0) {
			execl(debug_locks, debug_locks, NULL);
			_exit(0);
		}
		ctdb_track_child(ctdb, pid);
	} else {
		DEBUG(DEBUG_WARNING,
		      (__location__
		       " Unable to setup lock debugging - no memory?\n"));
	}

	/* reset the timeout timer */
	// talloc_free(lock_ctx->ttimer);
	lock_ctx->ttimer = tevent_add_timer(ctdb->ev,
					    lock_ctx,
					    timeval_current_ofs(10, 0),
					    ctdb_lock_timeout_handler,
					    (void *)lock_ctx);
}


static int db_count_handler(struct ctdb_db_context *ctdb_db, uint32_t priority,
			    void *private_data)
{
	int *count = (int *)private_data;

	(*count) += 2;

	return 0;
}

static int db_flags(struct ctdb_db_context *ctdb_db)
{
	int tdb_flags = TDB_DEFAULT;

#ifdef TDB_MUTEX_LOCKING
	if (!ctdb_db->persistent && ctdb_db->ctdb->tunable.mutex_enabled) {
		tdb_flags = (TDB_MUTEX_LOCKING | TDB_CLEAR_IF_FIRST);
	}
#endif
	return tdb_flags;
}

struct db_namelist {
	const char **names;
	int n;
};

static int db_name_handler(struct ctdb_db_context *ctdb_db, uint32_t priority,
			   void *private_data)
{
	struct db_namelist *list = (struct db_namelist *)private_data;

	list->names[list->n] = talloc_strdup(list->names, ctdb_db->db_path);
	list->names[list->n+1] = talloc_asprintf(list->names, "0x%x",
						 db_flags(ctdb_db));
	list->n += 2;

	return 0;
}

static bool lock_helper_args(TALLOC_CTX *mem_ctx,
			     struct lock_context *lock_ctx, int fd,
			     int *argc, const char ***argv)
{
	struct ctdb_context *ctdb = lock_ctx->ctdb;
	const char **args = NULL;
	int nargs, i;
	int priority;
	struct db_namelist list;

	switch (lock_ctx->type) {
	case LOCK_RECORD:
		nargs = 6;
		break;

	case LOCK_DB:
		nargs = 5;
		break;

	case LOCK_ALLDB_PRIO:
		nargs = 3;
		ctdb_db_iterator(ctdb, lock_ctx->priority, db_count_handler, &nargs);
		break;

	case LOCK_ALLDB:
		nargs = 3;
		for (priority=1; priority<NUM_DB_PRIORITIES; priority++) {
			ctdb_db_iterator(ctdb, priority, db_count_handler, &nargs);
		}
		break;
	}

	/* Add extra argument for null termination */
	nargs++;

	args = talloc_array(mem_ctx, const char *, nargs);
	if (args == NULL) {
		return false;
	}

	args[0] = talloc_asprintf(args, "%d", getpid());
	args[1] = talloc_asprintf(args, "%d", fd);

	switch (lock_ctx->type) {
	case LOCK_RECORD:
		args[2] = talloc_strdup(args, "RECORD");
		args[3] = talloc_strdup(args, lock_ctx->ctdb_db->db_path);
		args[4] = talloc_asprintf(args, "0x%x",
					  db_flags(lock_ctx->ctdb_db));
		if (lock_ctx->key.dsize == 0) {
			args[5] = talloc_strdup(args, "NULL");
		} else {
			args[5] = hex_encode_talloc(args, lock_ctx->key.dptr, lock_ctx->key.dsize);
		}
		break;

	case LOCK_DB:
		args[2] = talloc_strdup(args, "DB");
		args[3] = talloc_strdup(args, lock_ctx->ctdb_db->db_path);
		args[4] = talloc_asprintf(args, "0x%x",
					  db_flags(lock_ctx->ctdb_db));
		break;

	case LOCK_ALLDB_PRIO:
		args[2] = talloc_strdup(args, "DB");
		list.names = args;
		list.n = 3;
		ctdb_db_iterator(ctdb, lock_ctx->priority, db_name_handler, &list);
		break;

	case LOCK_ALLDB:
		args[2] = talloc_strdup(args, "DB");
		list.names = args;
		list.n = 3;
		for (priority=1; priority<NUM_DB_PRIORITIES; priority++) {
			ctdb_db_iterator(ctdb, priority, db_name_handler, &list);
		}
		break;
	}

	/* Make sure last argument is NULL */
	args[nargs-1] = NULL;

	for (i=0; i<nargs-1; i++) {
		if (args[i] == NULL) {
			talloc_free(args);
			return false;
		}
	}

	*argc = nargs;
	*argv = args;
	return true;
}

/*
 * Find a lock request that can be scheduled
 */
static struct lock_context *ctdb_find_lock_context(struct ctdb_context *ctdb)
{
	struct lock_context *lock_ctx, *next_ctx;
	struct ctdb_db_context *ctdb_db;

	/* First check if there are database lock requests */

	for (lock_ctx = ctdb->lock_pending; lock_ctx != NULL;
	     lock_ctx = next_ctx) {

		if (lock_ctx->request != NULL) {
			/* Found a lock context with a request */
			return lock_ctx;
		}

		next_ctx = lock_ctx->next;

		DEBUG(DEBUG_INFO, ("Removing lock context without lock "
				   "request\n"));
		DLIST_REMOVE(ctdb->lock_pending, lock_ctx);
		CTDB_DECREMENT_STAT(ctdb, locks.num_pending);
		if (lock_ctx->ctdb_db) {
			CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db,
					       locks.num_pending);
		}
		talloc_free(lock_ctx);
	}

	/* Next check database queues */
	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		if (ctdb_db->lock_num_current ==
		    ctdb->tunable.lock_processes_per_db) {
			continue;
		}

		for (lock_ctx = ctdb_db->lock_pending; lock_ctx != NULL;
		     lock_ctx = next_ctx) {

			next_ctx = lock_ctx->next;

			if (lock_ctx->request != NULL) {
				return lock_ctx;
			}

			DEBUG(DEBUG_INFO, ("Removing lock context without "
					   "lock request\n"));
			DLIST_REMOVE(ctdb_db->lock_pending, lock_ctx);
			CTDB_DECREMENT_STAT(ctdb, locks.num_pending);
			CTDB_DECREMENT_DB_STAT(ctdb_db, locks.num_pending);
			talloc_free(lock_ctx);
		}
	}

	return NULL;
}

/*
 * Schedule a new lock child process
 * Set up callback handler and timeout handler
 */
static void ctdb_lock_schedule(struct ctdb_context *ctdb)
{
	struct lock_context *lock_ctx;
	int ret, argc;
	TALLOC_CTX *tmp_ctx;
	const char *helper = CTDB_HELPER_BINDIR "/ctdb_lock_helper";
	static const char *prog = NULL;
	const char **args;

	if (prog == NULL) {
		const char *t;

		t = getenv("CTDB_LOCK_HELPER");
		if (t != NULL) {
			prog = talloc_strdup(ctdb, t);
		} else {
			prog = talloc_strdup(ctdb, helper);
		}
		CTDB_NO_MEMORY_VOID(ctdb, prog);
	}

	/* Find a lock context with requests */
	lock_ctx = ctdb_find_lock_context(ctdb);
	if (lock_ctx == NULL) {
		return;
	}

	lock_ctx->child = -1;
	ret = pipe(lock_ctx->fd);
	if (ret != 0) {
		DEBUG(DEBUG_ERR, ("Failed to create pipe in ctdb_lock_schedule\n"));
		return;
	}

	set_close_on_exec(lock_ctx->fd[0]);

	/* Create data for child process */
	tmp_ctx = talloc_new(lock_ctx);
	if (tmp_ctx == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to allocate memory for helper args\n"));
		close(lock_ctx->fd[0]);
		close(lock_ctx->fd[1]);
		return;
	}

	/* Create arguments for lock helper */
	if (!lock_helper_args(tmp_ctx, lock_ctx, lock_ctx->fd[1],
			      &argc, &args)) {
		DEBUG(DEBUG_ERR, ("Failed to create lock helper args\n"));
		close(lock_ctx->fd[0]);
		close(lock_ctx->fd[1]);
		talloc_free(tmp_ctx);
		return;
	}

	if (!ctdb_vfork_with_logging(lock_ctx, ctdb, "lock_helper",
				     prog, argc, (const char **)args,
				     NULL, NULL, &lock_ctx->child)) {
		DEBUG(DEBUG_ERR, ("Failed to create a child in ctdb_lock_schedule\n"));
		close(lock_ctx->fd[0]);
		close(lock_ctx->fd[1]);
		talloc_free(tmp_ctx);
		return;
	}

	/* Parent process */
	close(lock_ctx->fd[1]);

	talloc_set_destructor(lock_ctx, ctdb_lock_context_destructor);

	talloc_free(tmp_ctx);

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
	if (lock_ctx->type == LOCK_RECORD) {
		DLIST_REMOVE(lock_ctx->ctdb_db->lock_pending, lock_ctx);
		DLIST_ADD_END(lock_ctx->ctdb_db->lock_current, lock_ctx, NULL);
	} else {
		DLIST_REMOVE(ctdb->lock_pending, lock_ctx);
		DLIST_ADD_END(ctdb->lock_current, lock_ctx, NULL);
	}
	CTDB_DECREMENT_STAT(lock_ctx->ctdb, locks.num_pending);
	CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.num_current);
	if (lock_ctx->ctdb_db) {
		lock_ctx->ctdb_db->lock_num_current++;
		CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_pending);
		CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_current);
	}
}


/*
 * Lock record / db depending on type
 */
static struct lock_request *ctdb_lock_internal(TALLOC_CTX *mem_ctx,
					       struct ctdb_context *ctdb,
					       struct ctdb_db_context *ctdb_db,
					       TDB_DATA key,
					       uint32_t priority,
					       void (*callback)(void *, bool),
					       void *private_data,
					       enum lock_type type,
					       bool auto_mark)
{
	struct lock_context *lock_ctx = NULL;
	struct lock_request *request;

	if (callback == NULL) {
		DEBUG(DEBUG_WARNING, ("No callback function specified, not locking\n"));
		return NULL;
	}

	lock_ctx = talloc_zero(ctdb, struct lock_context);
	if (lock_ctx == NULL) {
		DEBUG(DEBUG_ERR, ("Failed to create a new lock context\n"));
		return NULL;
	}

	if ((request = talloc_zero(mem_ctx, struct lock_request)) == NULL) {
		talloc_free(lock_ctx);
		return NULL;
	}

	lock_ctx->type = type;
	lock_ctx->ctdb = ctdb;
	lock_ctx->ctdb_db = ctdb_db;
	lock_ctx->key.dsize = key.dsize;
	if (key.dsize > 0) {
		lock_ctx->key.dptr = talloc_memdup(lock_ctx, key.dptr, key.dsize);
		if (lock_ctx->key.dptr == NULL) {
			DEBUG(DEBUG_ERR, (__location__ "Memory allocation error\n"));
			talloc_free(lock_ctx);
			return NULL;
		}
		lock_ctx->key_hash = ctdb_hash(&key);
	} else {
		lock_ctx->key.dptr = NULL;
	}
	lock_ctx->priority = priority;
	lock_ctx->auto_mark = auto_mark;

	lock_ctx->request = request;
	lock_ctx->child = -1;

	/* Non-record locks are required by recovery and should be scheduled
	 * immediately, so keep them at the head of the pending queue.
	 */
	if (lock_ctx->type == LOCK_RECORD) {
		DLIST_ADD_END(ctdb_db->lock_pending, lock_ctx, NULL);
	} else {
		DLIST_ADD_END(ctdb->lock_pending, lock_ctx, NULL);
	}
	CTDB_INCREMENT_STAT(ctdb, locks.num_pending);
	if (ctdb_db) {
		CTDB_INCREMENT_DB_STAT(ctdb_db, locks.num_pending);
	}

	/* Start the timer when we activate the context */
	lock_ctx->start_time = timeval_current();

	request->lctx = lock_ctx;
	request->callback = callback;
	request->private_data = private_data;

	talloc_set_destructor(request, ctdb_lock_request_destructor);

	ctdb_lock_schedule(ctdb);

	return request;
}


/*
 * obtain a lock on a record in a database
 */
struct lock_request *ctdb_lock_record(TALLOC_CTX *mem_ctx,
				      struct ctdb_db_context *ctdb_db,
				      TDB_DATA key,
				      bool auto_mark,
				      void (*callback)(void *, bool),
				      void *private_data)
{
	return ctdb_lock_internal(mem_ctx,
				  ctdb_db->ctdb,
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
struct lock_request *ctdb_lock_db(TALLOC_CTX *mem_ctx,
				  struct ctdb_db_context *ctdb_db,
				  bool auto_mark,
				  void (*callback)(void *, bool),
				  void *private_data)
{
	return ctdb_lock_internal(mem_ctx,
				  ctdb_db->ctdb,
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
struct lock_request *ctdb_lock_alldb_prio(TALLOC_CTX *mem_ctx,
					  struct ctdb_context *ctdb,
					  uint32_t priority,
					  bool auto_mark,
					  void (*callback)(void *, bool),
					  void *private_data)
{
	if (priority < 1 || priority > NUM_DB_PRIORITIES) {
		DEBUG(DEBUG_ERR, ("Invalid db priority: %u\n", priority));
		return NULL;
	}

	return ctdb_lock_internal(mem_ctx,
				  ctdb,
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
struct lock_request *ctdb_lock_alldb(TALLOC_CTX *mem_ctx,
				     struct ctdb_context *ctdb,
				     bool auto_mark,
				     void (*callback)(void *, bool),
				     void *private_data)
{
	return ctdb_lock_internal(mem_ctx,
				  ctdb,
				  NULL,
				  tdb_null,
				  0,
				  callback,
				  private_data,
				  LOCK_ALLDB,
				  auto_mark);
}

