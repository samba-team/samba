/* 
   wait for a tdb chain lock

   Copyright (C) Andrew Tridgell  2006

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "includes.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/wait.h"
#include "popt.h"
#include "../include/ctdb_private.h"
#include "db_wrap.h"
#include "lib/tdb/include/tdb.h"


struct lockwait_handle {
	struct fd_event *fde;
	int fd[2];
	pid_t child;
	void *private_data;
	void (*callback)(void *);
};

static void lockwait_handler(struct event_context *ev, struct fd_event *fde, 
			     uint16_t flags, void *private_data)
{
	struct lockwait_handle *h = talloc_get_type(private_data, 
						     struct lockwait_handle);
	void (*callback)(void *) = h->callback;
	void *p = h->private_data;
	pid_t child = h->child;
	talloc_set_destructor(h, NULL);
	close(h->fd[0]);
	talloc_free(h);	
	callback(p);
	waitpid(child, NULL, 0);
}

static int lockwait_destructor(struct lockwait_handle *h)
{
	close(h->fd[0]);
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
				      void (*callback)(void *), void *private_data)
{
	struct lockwait_handle *h;
	int ret;

	h = talloc_zero(ctdb_db, struct lockwait_handle);
	if (h == NULL) {
		return NULL;
	}

	ret = pipe(h->fd);
	if (ret != 0) {
		talloc_free(h);
		return NULL;
	}

	h->child = fork();
	if (h->child == (pid_t)-1) {
		close(h->fd[0]);
		close(h->fd[1]);
		talloc_free(h);
		return NULL;
	}

	h->callback = callback;
	h->private_data = private_data;

	if (h->child == 0) {
		struct tdb_context *tdb = ctdb_db->ltdb->tdb;
		/* in child */
		tdb_chainlock(tdb, key);
		_exit(0);
	}

	close(h->fd[1]);
	talloc_set_destructor(h, lockwait_destructor);

	h->fde = event_add_fd(ctdb_db->ctdb->ev, h, h->fd[0], EVENT_FD_READ, lockwait_handler, h);
	if (h->fde == NULL) {
		talloc_free(h);
		return NULL;
	}

	return h;
}
