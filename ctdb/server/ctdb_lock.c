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
#include "replace.h"
#include "system/filesys.h"
#include "system/network.h"

#include <talloc.h>
#include <tevent.h>

#include "lib/tdb_wrap/tdb_wrap.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "lib/util/samba_util.h"
#include "lib/util/sys_rw.h"

#include "ctdb_private.h"

#include "common/common.h"
#include "common/logging.h"

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
 *
 *  auto_mark              - whether to mark/unmark DBs in before/after callback
 *                           = false is used for freezing databases for
 *                           recovery since the recovery cannot start till
 *                           databases are locked on all the nodes.
 *                           = true is used for record locks.
 */

enum lock_type {
	LOCK_RECORD,
	LOCK_DB,
};

static const char * const lock_type_str[] = {
	"lock_record",
	"lock_db",
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


int ctdb_db_iterator(struct ctdb_context *ctdb, ctdb_db_handler_t handler,
		     void *private_data)
{
	struct ctdb_db_context *ctdb_db;
	int ret;

	for (ctdb_db = ctdb->db_list; ctdb_db; ctdb_db = ctdb_db->next) {
		ret = handler(ctdb_db, private_data);
		if (ret != 0) {
			return -1;
		}
	}

	return 0;
}

/*
 * lock all databases - mark only
 */
static int db_lock_mark_handler(struct ctdb_db_context *ctdb_db,
				void *private_data)
{
	int tdb_transaction_write_lock_mark(struct tdb_context *);

	DEBUG(DEBUG_INFO, ("marking locked database %s\n", ctdb_db->db_name));

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

int ctdb_lockdb_mark(struct ctdb_db_context *ctdb_db)
{
	if (!ctdb_db_frozen(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("Attempt to mark database locked when not frozen\n"));
		return -1;
	}

	return db_lock_mark_handler(ctdb_db, NULL);
}

/*
 * lock all databases - unmark only
 */
static int db_lock_unmark_handler(struct ctdb_db_context *ctdb_db,
				  void *private_data)
{
	int tdb_transaction_write_lock_unmark(struct tdb_context *);

	DEBUG(DEBUG_INFO, ("unmarking locked database %s\n", ctdb_db->db_name));

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

int ctdb_lockdb_unmark(struct ctdb_db_context *ctdb_db)
{
	if (!ctdb_db_frozen(ctdb_db)) {
		DEBUG(DEBUG_ERR,
		      ("Attempt to unmark database locked when not frozen\n"));
		return -1;
	}

	return db_lock_unmark_handler(ctdb_db, NULL);
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
		ctdb_kill(lock_ctx->ctdb, lock_ctx->child, SIGTERM);
		if (lock_ctx->type == LOCK_RECORD) {
			DLIST_REMOVE(lock_ctx->ctdb_db->lock_current, lock_ctx);
		} else {
			DLIST_REMOVE(lock_ctx->ctdb->lock_current, lock_ctx);
		}
		if (lock_ctx->ctdb_db->lock_num_current == 0) {
			ctdb_fatal(NULL, "Lock count is 0 before decrement\n");
		}
		lock_ctx->ctdb_db->lock_num_current--;
		CTDB_DECREMENT_STAT(lock_ctx->ctdb, locks.num_current);
		CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_current);
	} else {
		if (lock_ctx->type == LOCK_RECORD) {
			DLIST_REMOVE(lock_ctx->ctdb_db->lock_pending, lock_ctx);
		} else {
			DLIST_REMOVE(lock_ctx->ctdb->lock_pending, lock_ctx);
		}
		CTDB_DECREMENT_STAT(lock_ctx->ctdb, locks.num_pending);
		CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_pending);
	}

	ctdb_lock_schedule(lock_ctx->ctdb);

	return 0;
}


/*
 * Destructor to remove lock request
 */
static int ctdb_lock_request_destructor(struct lock_request *lock_request)
{
	if (lock_request->lctx == NULL) {
		return 0;
	}

	lock_request->lctx->request = NULL;
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
	bool auto_mark = lock_ctx->auto_mark;

	if (auto_mark && locked) {
		switch (lock_ctx->type) {
		case LOCK_RECORD:
			tdb_chainlock_mark(lock_ctx->ctdb_db->ltdb->tdb, lock_ctx->key);
			break;

		case LOCK_DB:
			(void)ctdb_lockdb_mark(lock_ctx->ctdb_db);
			break;
		}
	}

	request = lock_ctx->request;
	if (auto_mark) {
		/* Since request may be freed in the callback, unset the lock
		 * context, so request destructor will not free lock context.
		 */
		request->lctx = NULL;
	}

	/* Since request may be freed in the callback, unset the request */
	lock_ctx->request = NULL;

	request->callback(request->private_data, locked);

	if (!auto_mark) {
		return;
	}

	if (locked) {
		switch (lock_ctx->type) {
		case LOCK_RECORD:
			tdb_chainlock_unmark(lock_ctx->ctdb_db->ltdb->tdb, lock_ctx->key);
			break;

		case LOCK_DB:
			ctdb_lockdb_unmark(lock_ctx->ctdb_db);
			break;
		}
	}

	talloc_free(lock_ctx);
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
	char c;
	bool locked;
	double t;
	int id;

	lock_ctx = talloc_get_type_abort(private_data, struct lock_context);

	/* cancel the timeout event */
	TALLOC_FREE(lock_ctx->ttimer);

	t = timeval_elapsed(&lock_ctx->start_time);
	id = lock_bucket_id(t);

	/* Read the status from the child process */
	if (sys_read(lock_ctx->fd[0], &c, 1) != 1) {
		locked = false;
	} else {
		locked = (c == 0 ? true : false);
	}

	/* Update statistics */
	CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.num_calls);
	CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_calls);

	if (locked) {
		CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.buckets[id]);
		CTDB_UPDATE_LATENCY(lock_ctx->ctdb, lock_ctx->ctdb_db,
				    lock_type_str[lock_ctx->type], locks.latency,
				    lock_ctx->start_time);

		CTDB_UPDATE_DB_LATENCY(lock_ctx->ctdb_db, lock_type_str[lock_ctx->type], locks.latency, t);
		CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.buckets[id]);
	} else {
		CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.num_failed);
		CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_failed);
	}

	process_callbacks(lock_ctx, locked);
}

struct lock_log_entry {
	struct db_hash_context *lock_log;
	TDB_DATA key;
	unsigned long log_sec;
	struct tevent_timer *timer;
};

static int lock_log_fetch_parser(uint8_t *keybuf, size_t keylen,
				 uint8_t *databuf, size_t datalen,
				 void *private_data)
{
	struct lock_log_entry **entry =
		(struct lock_log_entry **)private_data;

	if (datalen != sizeof(struct lock_log_entry *)) {
		return EINVAL;
	}

	*entry = talloc_get_type_abort(*(void **)databuf,
				       struct lock_log_entry);
	return 0;
}

static void lock_log_cleanup(struct tevent_context *ev,
			     struct tevent_timer *ttimer,
			     struct timeval current_time,
			     void *private_data)
{
	struct lock_log_entry *entry = talloc_get_type_abort(
		private_data, struct lock_log_entry);
	int ret;

	entry->timer = NULL;

	ret = db_hash_delete(entry->lock_log, entry->key.dptr,
			     entry->key.dsize);
	if (ret != 0) {
		return;
	}
	talloc_free(entry);
}

static bool lock_log_skip(struct tevent_context *ev,
			  struct db_hash_context *lock_log,
			  TDB_DATA key, unsigned long elapsed_sec)
{
	struct lock_log_entry *entry = NULL;
	int ret;

	ret = db_hash_fetch(lock_log, key.dptr, key.dsize,
			    lock_log_fetch_parser, &entry);
	if (ret == ENOENT) {

		entry = talloc_zero(lock_log, struct lock_log_entry);
		if (entry == NULL) {
			goto fail;
		}

		entry->lock_log = lock_log;

		entry->key.dptr = talloc_memdup(entry, key.dptr, key.dsize);
		if (entry->key.dptr == NULL) {
			talloc_free(entry);
			goto fail;
		}
		entry->key.dsize = key.dsize;

		entry->log_sec = elapsed_sec;
		entry->timer = tevent_add_timer(ev, entry,
						timeval_current_ofs(30, 0),
						lock_log_cleanup, entry);
		if (entry->timer == NULL) {
			talloc_free(entry);
			goto fail;
		}

		ret = db_hash_add(lock_log, key.dptr, key.dsize,
				  (uint8_t *)&entry,
				  sizeof(struct lock_log_entry *));
		if (ret != 0) {
			talloc_free(entry);
			goto fail;
		}

		return false;

	} else if (ret == EINVAL) {

		ret = db_hash_delete(lock_log, key.dptr, key.dsize);
		if (ret != 0) {
			goto fail;
		}

		return false;

	} else if (ret == 0) {

		if (elapsed_sec <= entry->log_sec) {
			return true;
		}

		entry->log_sec = elapsed_sec;

		TALLOC_FREE(entry->timer);
		entry->timer = tevent_add_timer(ev, entry,
						timeval_current_ofs(30, 0),
						lock_log_cleanup, entry);
		if (entry->timer == NULL) {
			ret = db_hash_delete(lock_log, key.dptr, key.dsize);
			if (ret != 0) {
				goto fail;
			}
			talloc_free(entry);
		}

		return false;
	}


fail:
	return false;

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
	static char debug_locks[PATH_MAX+1] = "";
	struct lock_context *lock_ctx;
	struct ctdb_context *ctdb;
	pid_t pid;
	double elapsed_time;
	bool skip;
	char *keystr;

	lock_ctx = talloc_get_type_abort(private_data, struct lock_context);
	ctdb = lock_ctx->ctdb;

	elapsed_time = timeval_elapsed(&lock_ctx->start_time);

	/* For database locks, always log */
	if (lock_ctx->type == LOCK_DB) {
		DEBUG(DEBUG_WARNING,
		      ("Unable to get DB lock on database %s for "
		       "%.0lf seconds\n",
		       lock_ctx->ctdb_db->db_name, elapsed_time));
		goto lock_debug;
	}

	/* For record locks, check if we have already logged */
	skip = lock_log_skip(ev, lock_ctx->ctdb_db->lock_log,
			     lock_ctx->key, (unsigned long)elapsed_time);
	if (skip) {
		goto skip_lock_debug;
	}

	keystr = hex_encode_talloc(lock_ctx, lock_ctx->key.dptr,
				   lock_ctx->key.dsize);
	DEBUG(DEBUG_WARNING,
	      ("Unable to get RECORD lock on database %s for %.0lf seconds"
	       " (key %s)\n",
	       lock_ctx->ctdb_db->db_name, elapsed_time,
	       keystr ? keystr : ""));
	TALLOC_FREE(keystr);

	/* If a node stopped/banned, don't spam the logs */
	if (ctdb->nodes[ctdb->pnn]->flags & NODE_FLAGS_INACTIVE) {
		goto skip_lock_debug;
	}

lock_debug:

	if (ctdb_set_helper("lock debugging helper",
			    debug_locks, sizeof(debug_locks),
			    "CTDB_DEBUG_LOCKS",
			    getenv("CTDB_BASE"), "debug_locks.sh")) {
		pid = vfork();
		if (pid == 0) {
			execl(debug_locks, debug_locks, NULL);
			_exit(0);
		}
		ctdb_track_child(ctdb, pid);
	} else {
		DEBUG(DEBUG_WARNING,
		      (__location__
		       " Unable to setup lock debugging\n"));
	}

skip_lock_debug:

	/* reset the timeout timer */
	// talloc_free(lock_ctx->ttimer);
	lock_ctx->ttimer = tevent_add_timer(ctdb->ev,
					    lock_ctx,
					    timeval_current_ofs(10, 0),
					    ctdb_lock_timeout_handler,
					    (void *)lock_ctx);
}

static bool lock_helper_args(TALLOC_CTX *mem_ctx,
			     struct lock_context *lock_ctx, int fd,
			     int *argc, const char ***argv)
{
	const char **args = NULL;
	int nargs = 0, i;

	switch (lock_ctx->type) {
	case LOCK_RECORD:
		nargs = 6;
		break;

	case LOCK_DB:
		nargs = 5;
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
				tdb_get_flags(lock_ctx->ctdb_db->ltdb->tdb));
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
				tdb_get_flags(lock_ctx->ctdb_db->ltdb->tdb));
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
		CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_pending);
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
	static char prog[PATH_MAX+1] = "";
	const char **args;

	if (!ctdb_set_helper("lock helper",
			     prog, sizeof(prog),
			     "CTDB_LOCK_HELPER",
			     CTDB_HELPER_BINDIR, "ctdb_lock_helper")) {
		ctdb_die(ctdb, __location__
			 " Unable to set lock helper\n");
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

	if (! ctdb->do_setsched) {
		ret = setenv("CTDB_NOSETSCHED", "1", 1);
		if (ret != 0) {
			DEBUG(DEBUG_WARNING,
			      ("Failed to set CTDB_NOSETSCHED variable\n"));
		}
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

	lock_ctx->child = ctdb_vfork_exec(lock_ctx, ctdb, prog, argc,
					  (const char **)args);
	if (lock_ctx->child == -1) {
		DEBUG(DEBUG_ERR, ("Failed to create a child in ctdb_lock_schedule\n"));
		close(lock_ctx->fd[0]);
		close(lock_ctx->fd[1]);
		talloc_free(tmp_ctx);
		return;
	}

	/* Parent process */
	close(lock_ctx->fd[1]);

	talloc_free(tmp_ctx);

	/* Set up timeout handler */
	lock_ctx->ttimer = tevent_add_timer(ctdb->ev,
					    lock_ctx,
					    timeval_current_ofs(10, 0),
					    ctdb_lock_timeout_handler,
					    (void *)lock_ctx);
	if (lock_ctx->ttimer == NULL) {
		ctdb_kill(ctdb, lock_ctx->child, SIGTERM);
		lock_ctx->child = -1;
		close(lock_ctx->fd[0]);
		return;
	}

	/* Set up callback */
	lock_ctx->tfd = tevent_add_fd(ctdb->ev,
				      lock_ctx,
				      lock_ctx->fd[0],
				      TEVENT_FD_READ,
				      ctdb_lock_handler,
				      (void *)lock_ctx);
	if (lock_ctx->tfd == NULL) {
		TALLOC_FREE(lock_ctx->ttimer);
		ctdb_kill(ctdb, lock_ctx->child, SIGTERM);
		lock_ctx->child = -1;
		close(lock_ctx->fd[0]);
		return;
	}
	tevent_fd_set_auto_close(lock_ctx->tfd);

	/* Move the context from pending to current */
	if (lock_ctx->type == LOCK_RECORD) {
		DLIST_REMOVE(lock_ctx->ctdb_db->lock_pending, lock_ctx);
		DLIST_ADD_END(lock_ctx->ctdb_db->lock_current, lock_ctx);
	} else {
		DLIST_REMOVE(ctdb->lock_pending, lock_ctx);
		DLIST_ADD_END(ctdb->lock_current, lock_ctx);
	}
	CTDB_DECREMENT_STAT(lock_ctx->ctdb, locks.num_pending);
	CTDB_INCREMENT_STAT(lock_ctx->ctdb, locks.num_current);
	lock_ctx->ctdb_db->lock_num_current++;
	CTDB_DECREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_pending);
	CTDB_INCREMENT_DB_STAT(lock_ctx->ctdb_db, locks.num_current);
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
			talloc_free(request);
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
		DLIST_ADD_END(ctdb_db->lock_pending, lock_ctx);
	} else {
		DLIST_ADD_END(ctdb->lock_pending, lock_ctx);
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
	talloc_set_destructor(lock_ctx, ctdb_lock_context_destructor);

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
