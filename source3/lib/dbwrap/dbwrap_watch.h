/*
   Unix SMB/CIFS implementation.
   Watch dbwrap record changes
   Copyright (C) Volker Lendecke 2012

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __DBWRAP_WATCH_H__
#define __DBWRAP_WATCH_H__

#include <tevent.h>
#include "dbwrap/dbwrap.h"
#include "messages.h"

struct db_context *db_open_watched(TALLOC_CTX *mem_ctx,
				   struct db_context **backend,
				   struct messaging_context *msg);
struct tevent_req *dbwrap_watched_watch_send(TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct db_record *rec,
					     struct server_id blocker);
NTSTATUS dbwrap_watched_watch_recv(struct tevent_req *req,
				   bool *blockerdead,
				   struct server_id *blocker);

/*
 * Wake up watchers without having modified the record value. One
 * usecase at the time of this commit is: We have lease break waiters
 * waiting on a locking.tdb record. They should be woken up when a
 * lease is broken, which does not modify the locking.tdb record.
 */
void dbwrap_watched_wakeup(struct db_record *rec);

#endif /* __DBWRAP_WATCH_H__ */
