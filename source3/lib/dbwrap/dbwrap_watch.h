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

void dbwrap_watch_db(struct db_context *db, struct messaging_context *msg);

struct tevent_req *dbwrap_record_watch_send(TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct db_record *rec,
					    struct messaging_context *msg);
NTSTATUS dbwrap_record_watch_recv(struct tevent_req *req,
				  TALLOC_CTX *mem_ctx,
				  struct db_record **prec);

void dbwrap_watchers_traverse_read(
	int (*fn)(const uint8_t *db_id, size_t db_id_len, const TDB_DATA key,
		  const struct server_id *watchers, size_t num_watchers,
		  void *private_data),
	void *private_data);

void dbwrap_watchers_wakeall(struct messaging_context *msg);


#endif /* __DBWRAP_WATCH_H__ */
