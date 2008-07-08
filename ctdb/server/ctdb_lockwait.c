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
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "db_wrap.h"
#include "lib/tdb/include/tdb.h"
#include "../include/ctdb_private.h"


struct lockwait_handle {
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

static void lockwait_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private_data)
{
	struct lockwait_handle *h = talloc_get_type(private_data, 
						     struct lockwait_handle);
	void (*callback)(void *) = h->callback;
	void *p = h->private_data;
	pid_t child = h->child;
	TDB_DATA key = h->key;
	struct tdb_context *tdb = h->ctdb_db->ltdb->tdb;
	TALLOC_CTX *tmp_ctx = talloc_new(ev);

	key.dptr = talloc_memdup(tmp_ctx, key.dptr, key.dsize);

	talloc_set_destructor(h, NULL);
	ctdb_latency(&h->ctdb->statistics.max_lockwait_latency, h->start_time);
	h->ctdb->statistics.pending_lockwait_calls--;

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
	tdb_chainlock_unmark(tdb, key);

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	talloc_free(tmp_ctx);
}

static int lockwait_destructor(struct lockwait_handle *h)
{
	h->ctdb->statistics.pending_lockwait_calls--;
	kill(h->child, SIGKILL);
	waitpid(h->child, NULL, 0);
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
	struct lockwait_handle *result;
	int ret;
	pid_t parent = getpid();

	ctdb_db->ctdb->statistics.lockwait_calls++;
	ctdb_db->ctdb->statistics.pending_lockwait_calls++;

	if (!(result = talloc_zero(private_data, struct lockwait_handle))) {
		ctdb_db->ctdb->statistics.pending_lockwait_calls--;
		return NULL;
	}

	ret = pipe(result->fd);

	if (ret != 0) {
		talloc_free(result);
		ctdb_db->ctdb->statistics.pending_lockwait_calls--;
		return NULL;
	}

	result->child = fork();

	if (result->child == (pid_t)-1) {
		close(result->fd[0]);
		close(result->fd[1]);
		talloc_free(result);
		ctdb_db->ctdb->statistics.pending_lockwait_calls--;
		return NULL;
	}

	result->callback = callback;
	result->private_data = private_data;
	result->ctdb = ctdb_db->ctdb;
	result->ctdb_db = ctdb_db;
	result->key = key;

	if (result->child == 0) {
		char c = 0;
		close(result->fd[0]);
		tdb_chainlock(ctdb_db->ltdb->tdb, key);
		write(result->fd[1], &c, 1);
		/* make sure we die when our parent dies */
		while (kill(parent, 0) == 0 || errno != ESRCH) {
			sleep(5);
		}
		_exit(0);
	}

	close(result->fd[1]);
	talloc_set_destructor(result, lockwait_destructor);

	result->fde = event_add_fd(ctdb_db->ctdb->ev, result, result->fd[0],
				   EVENT_FD_READ|EVENT_FD_AUTOCLOSE, lockwait_handler,
				   (void *)result);
	if (result->fde == NULL) {
		talloc_free(result);
		ctdb_db->ctdb->statistics.pending_lockwait_calls--;
		return NULL;
	}

	result->start_time = timeval_current();

	return result;
}
