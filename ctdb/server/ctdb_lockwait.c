/* 
   wait for a tdb chain lock

   Copyright (C) Andrew Tridgell  2006

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
#include "db_wrap.h"
#include "lib/tdb/include/tdb.h"
#include "lib/util/dlinklist.h"
#include "../include/ctdb_private.h"


struct lockwait_handle {
	struct lockwait_handle *next, *prev;
	struct ctdb_context *ctdb;
	struct ctdb_db_context *ctdb_db;
	struct fd_event *fde;
	int fd[2];
	pid_t child;
	void *private_data;
	void (*callback)(void *);
	TDB_DATA key;
	struct timeval start_time;
};

/* If we managed to obtain a lock, find any overflow records which wanted the
 * same one and do all the callbacks at once. */
static void do_overflow(struct ctdb_db_context *ctdb_db,
			TDB_DATA key)
{
	struct lockwait_handle *i, *next;
	TALLOC_CTX *tmp_ctx = talloc_new(ctdb_db);

	for (i = ctdb_db->lockwait_overflow; i; i = next) {
		/* Careful: destructor removes it from list! */
		next = i->next;
		if (key.dsize == i->key.dsize
		    && memcmp(key.dptr, i->key.dptr, key.dsize) == 0) {
			/* Callback might free them, so reparent. */
			talloc_steal(tmp_ctx, i);
			i->callback(i->private_data);
		}
	}

	/* This will free them if callback didn't. */
	talloc_free(tmp_ctx);

	/* Remove one from the overflow queue if there is one. */
	if (ctdb_db->lockwait_overflow) {
		i = ctdb_db->lockwait_overflow;
		ctdb_lockwait(ctdb_db, i->key, i->callback, i->private_data);
		talloc_free(i);
	}
}

static int lockwait_destructor(struct lockwait_handle *h)
{
	CTDB_DECREMENT_STAT(h->ctdb, pending_lockwait_calls);
	ctdb_kill(h->ctdb, h->child, SIGKILL);
	h->ctdb_db->pending_requests--;
	DLIST_REMOVE(h->ctdb_db->lockwait_active, h);
	return 0;
}

static void lockwait_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private_data)
{
	struct lockwait_handle *h = talloc_get_type(private_data, 
						     struct lockwait_handle);
	void (*callback)(void *) = h->callback;
	void *p = h->private_data;
	TDB_DATA key = h->key;
	struct tdb_context *tdb = h->ctdb_db->ltdb->tdb;
	TALLOC_CTX *tmp_ctx = talloc_new(ev);

	key.dptr = talloc_memdup(tmp_ctx, key.dptr, key.dsize);
	h->ctdb_db->pending_requests--;

	CTDB_UPDATE_LATENCY(h->ctdb, h->ctdb_db, "lockwait", lockwait_latency, h->start_time);

	/* the handle needs to go away when the context is gone - when
	   the handle goes away this implicitly closes the pipe, which
	   kills the child holding the lock */
	talloc_steal(tmp_ctx, h);

	if (h->ctdb->flags & CTDB_FLAG_TORTURE) {
		if (tdb_chainlock_nonblock(tdb, key) == 0) {
			ctdb_fatal(h->ctdb, "got chain lock while lockwait child active");
		}
	}

	tdb_chainlock_mark(tdb, key);
	callback(p);
	if (h->ctdb_db->lockwait_overflow) {
		do_overflow(h->ctdb_db, key);
	}
	tdb_chainlock_unmark(tdb, key);

	talloc_free(tmp_ctx);
}


static int overflow_lockwait_destructor(struct lockwait_handle *h)
{
	CTDB_DECREMENT_STAT(h->ctdb, pending_lockwait_calls);
	DLIST_REMOVE(h->ctdb_db->lockwait_overflow, h);
	return 0;
}

/*
  setup a non-blocking chainlock on a tdb record. If this function
  returns NULL then it could not get the chainlock. Otherwise it
  returns a opaque handle, and will call callback() once it has
  managed to get the chainlock. You can cancel it by using talloc_free
  on the returned handle.

  It is the callers responsibility to unlock the chainlock once
  acquired
 */
struct lockwait_handle *ctdb_lockwait(struct ctdb_db_context *ctdb_db,
				      TDB_DATA key,
				      void (*callback)(void *private_data),
				      void *private_data)
{
	struct lockwait_handle *result, *i;
	int ret;
	pid_t parent = getpid();

	CTDB_INCREMENT_STAT(ctdb_db->ctdb, lockwait_calls);
	CTDB_INCREMENT_STAT(ctdb_db->ctdb, pending_lockwait_calls);

	if (!(result = talloc_zero(private_data, struct lockwait_handle))) {
		CTDB_DECREMENT_STAT(ctdb_db->ctdb, pending_lockwait_calls);
		return NULL;
	}

	result->callback = callback;
	result->private_data = private_data;
	result->ctdb = ctdb_db->ctdb;
	result->ctdb_db = ctdb_db;
	result->key = key;

	/* If we already have a lockwait child for this request, then put this
	   request on the overflow queue straight away
	 */
	for (i = ctdb_db->lockwait_active; i; i = i->next) {
		if (key.dsize == i->key.dsize
		    && memcmp(key.dptr, i->key.dptr, key.dsize) == 0) {
			DLIST_ADD_END(ctdb_db->lockwait_overflow, result, NULL);
			talloc_set_destructor(result, overflow_lockwait_destructor);
			return result;
		}
	}

	/* Don't fire off too many children at once! */
	if (ctdb_db->pending_requests > 200) {
		DLIST_ADD_END(ctdb_db->lockwait_overflow, result, NULL);
		talloc_set_destructor(result, overflow_lockwait_destructor);
		DEBUG(DEBUG_DEBUG, (__location__ " Created overflow for %s\n",
				    ctdb_db->db_name));
		return result;
	}

	ret = pipe(result->fd);

	if (ret != 0) {
		talloc_free(result);
		CTDB_DECREMENT_STAT(ctdb_db->ctdb, pending_lockwait_calls);
		return NULL;
	}

	result->child = ctdb_fork(ctdb_db->ctdb);

	if (result->child == (pid_t)-1) {
		close(result->fd[0]);
		close(result->fd[1]);
		talloc_free(result);
		CTDB_DECREMENT_STAT(ctdb_db->ctdb, pending_lockwait_calls);
		return NULL;
	}

	if (result->child == 0) {
		char c = 0;
		close(result->fd[0]);
		debug_extra = talloc_asprintf(NULL, "chainlock-%s:", ctdb_db->db_name);
		tdb_chainlock(ctdb_db->ltdb->tdb, key);
		write(result->fd[1], &c, 1);
		/* make sure we die when our parent dies */
		while (ctdb_kill(ctdb_db->ctdb, parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
		}
		_exit(0);
	}

	close(result->fd[1]);
	set_close_on_exec(result->fd[0]);

	/* This is an active lockwait child process */
	DLIST_ADD_END(ctdb_db->lockwait_active, result, NULL);

	DEBUG(DEBUG_DEBUG, (__location__ " Created PIPE FD:%d to child lockwait process\n", result->fd[0]));

	ctdb_db->pending_requests++;
	talloc_set_destructor(result, lockwait_destructor);

	result->fde = event_add_fd(ctdb_db->ctdb->ev, result, result->fd[0],
				   EVENT_FD_READ, lockwait_handler,
				   (void *)result);
	if (result->fde == NULL) {
		talloc_free(result);
		CTDB_DECREMENT_STAT(ctdb_db->ctdb, pending_lockwait_calls);
		return NULL;
	}
	tevent_fd_set_auto_close(result->fde);

	result->start_time = timeval_current();
	return result;
}
