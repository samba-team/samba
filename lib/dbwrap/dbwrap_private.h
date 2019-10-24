/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper around tdb - private header

   Copyright (C) Volker Lendecke 2005-2007
   Copyright (C) Gregor Beck 2011
   Copyright (C) Michael Adam 2011

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

#ifndef __DBWRAP_PRIVATE_H__
#define __DBWRAP_PRIVATE_H__

struct tevent_context;
struct tevent_req;

struct db_record {
	struct db_context *db;
	TDB_DATA key, value;
	bool value_valid;
	NTSTATUS (*storev)(struct db_record *rec, const TDB_DATA *dbufs,
			   int num_dbufs, int flag);
	NTSTATUS (*delete_rec)(struct db_record *rec);
	void *private_data;
};

struct db_context {
	struct db_record *(*fetch_locked)(struct db_context *db,
					  TALLOC_CTX *mem_ctx,
					  TDB_DATA key);
	struct db_record *(*try_fetch_locked)(struct db_context *db,
					      TALLOC_CTX *mem_ctx,
					      TDB_DATA key);
	int (*traverse)(struct db_context *db,
			int (*f)(struct db_record *rec,
				 void *private_data),
			void *private_data);
	int (*traverse_read)(struct db_context *db,
			     int (*f)(struct db_record *rec,
				      void *private_data),
			     void *private_data);
	int (*get_seqnum)(struct db_context *db);
	int (*transaction_start)(struct db_context *db);
	NTSTATUS (*transaction_start_nonblock)(struct db_context *db);
	int (*transaction_commit)(struct db_context *db);
	int (*transaction_cancel)(struct db_context *db);
	NTSTATUS (*parse_record)(struct db_context *db, TDB_DATA key,
				 void (*parser)(TDB_DATA key, TDB_DATA data,
						void *private_data),
				 void *private_data);
	struct tevent_req *(*parse_record_send)(
		TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct db_context *db,
		TDB_DATA key,
		void (*parser)(TDB_DATA key, TDB_DATA data, void *private_data),
		void *private_data,
		enum dbwrap_req_state *req_state);
	NTSTATUS (*parse_record_recv)(struct tevent_req *req);
	NTSTATUS (*do_locked)(struct db_context *db, TDB_DATA key,
			      void (*fn)(struct db_record *rec,
					 TDB_DATA value,
					 void *private_data),
			      void *private_data);
	int (*exists)(struct db_context *db,TDB_DATA key);
	int (*wipe)(struct db_context *db);
	int (*check)(struct db_context *db);
	size_t (*id)(struct db_context *db, uint8_t *id, size_t idlen);

	const char *name;
	void *private_data;
	enum dbwrap_lock_order lock_order;
	bool persistent;
};

#define DBWRAP_LOCK_ORDER_MIN DBWRAP_LOCK_ORDER_1
#define DBWRAP_LOCK_ORDER_MAX DBWRAP_LOCK_ORDER_4

#define DBWRAP_LOCK_ORDER_VALID(order) \
	(((order) >= DBWRAP_LOCK_ORDER_MIN) && \
	 ((order) <= DBWRAP_LOCK_ORDER_MAX))

#endif /* __DBWRAP_PRIVATE_H__ */

