/* 
   Unix SMB/CIFS implementation.
   Database interface wrapper around tdb
   Copyright (C) Volker Lendecke 2005-2007

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

#ifndef __DBWRAP_H__
#define __DBWRAP_H__

#include "replace.h"
#include <talloc.h>
#include <tevent.h>
#include "libcli/util/ntstatus.h"
#include "tdb.h"

struct db_record;
struct db_context;

enum dbwrap_lock_order {
	DBWRAP_LOCK_ORDER_NONE = 0, /* Don't check lock orders for this db. */
	DBWRAP_LOCK_ORDER_1 = 1,
	DBWRAP_LOCK_ORDER_2 = 2,
	DBWRAP_LOCK_ORDER_3 = 3,
	DBWRAP_LOCK_ORDER_4 = 4
};

#define DBWRAP_FLAG_NONE                     0x0000000000000000ULL
#define DBWRAP_FLAG_OPTIMIZE_READONLY_ACCESS 0x0000000000000001ULL

enum dbwrap_req_state {
	/**
	 * We are creating the request
	 */
	DBWRAP_REQ_INIT,
	/**
	 * The request is queued and waiting to be dispatched
	 */
	DBWRAP_REQ_QUEUED,
	/**
	 * We are waiting to receive the reply
	 */
	DBWRAP_REQ_DISPATCHED,
	/**
	 * The request is finished
	 */
	DBWRAP_REQ_DONE,
	/**
	 * The request errored out
	 */
	DBWRAP_REQ_ERROR
};

/* The following definitions come from lib/dbwrap.c  */

TDB_DATA dbwrap_record_get_key(const struct db_record *rec);
TDB_DATA dbwrap_record_get_value(const struct db_record *rec);
NTSTATUS dbwrap_record_store(struct db_record *rec, TDB_DATA data, int flags);
NTSTATUS dbwrap_record_storev(struct db_record *rec,
			      const TDB_DATA *dbufs, int num_dbufs, int flags);
NTSTATUS dbwrap_record_delete(struct db_record *rec);
struct db_record *dbwrap_fetch_locked(struct db_context *db,
				      TALLOC_CTX *mem_ctx,
				      TDB_DATA key);
struct db_record *dbwrap_try_fetch_locked(struct db_context *db,
					  TALLOC_CTX *mem_ctx,
					  TDB_DATA key);
struct db_context *dbwrap_record_get_db(struct db_record *rec);

void dbwrap_lock_order_lock(const char *db_name,
			    enum dbwrap_lock_order lock_order);
void dbwrap_lock_order_unlock(const char *db_name,
			      enum dbwrap_lock_order lock_order);

NTSTATUS dbwrap_do_locked(struct db_context *db, TDB_DATA key,
			  void (*fn)(struct db_record *rec,
				     TDB_DATA value,
				     void *private_data),
			  void *private_data);

NTSTATUS dbwrap_delete(struct db_context *db, TDB_DATA key);
NTSTATUS dbwrap_store(struct db_context *db, TDB_DATA key,
		      TDB_DATA data, int flags);
NTSTATUS dbwrap_fetch(struct db_context *db, TALLOC_CTX *mem_ctx,
		      TDB_DATA key, TDB_DATA *value);
bool dbwrap_exists(struct db_context *db, TDB_DATA key);
NTSTATUS dbwrap_traverse(struct db_context *db,
			 int (*f)(struct db_record*, void*),
			 void *private_data,
			 int *count);
NTSTATUS dbwrap_traverse_read(struct db_context *db,
			      int (*f)(struct db_record*, void*),
			      void *private_data,
			      int *count);
NTSTATUS dbwrap_parse_record(struct db_context *db, TDB_DATA key,
			     void (*parser)(TDB_DATA key, TDB_DATA data,
					    void *private_data),
			     void *private_data);
/**
 * Async implementation of dbwrap_parse_record
 *
 * @param[in]  mem_ctx      talloc memory context to use.
 *
 * @param[in]  ev           tevent context to use
 *
 * @param[in]  db           Database to query
 *
 * @param[in]  key          Record key, the function makes a copy of this
 *
 * @param[in]  parser       Parser callback function
 *
 * @param[in]  private_data Private data for the callback function
 *
 * @param[out] req_state    Pointer to a enum dbwrap_req_state variable
 *
 * @note req_state is updated in the send function. To determine the final
 * result of the request the caller should therefor not rely on req_state. The
 * primary use case is to give the caller an indication whether the request is
 * already sent to ctdb (DBWRAP_REQ_DISPATCHED) or if it's still stuck in the
 * sendqueue (DBWRAP_REQ_QUEUED).
 **/
struct tevent_req *dbwrap_parse_record_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct db_context *db,
	TDB_DATA key,
	void (*parser)(TDB_DATA key, TDB_DATA data, void *private_data),
	void *private_data,
	enum dbwrap_req_state *req_state);
NTSTATUS dbwrap_parse_record_recv(struct tevent_req *req);
int dbwrap_wipe(struct db_context *db);
int dbwrap_check(struct db_context *db);
int dbwrap_get_seqnum(struct db_context *db);
/* Returns 0 if unknown. */
int dbwrap_transaction_start(struct db_context *db);
NTSTATUS dbwrap_transaction_start_nonblock(struct db_context *db);
int dbwrap_transaction_commit(struct db_context *db);
int dbwrap_transaction_cancel(struct db_context *db);
size_t dbwrap_db_id(struct db_context *db, uint8_t *id, size_t idlen);
bool dbwrap_is_persistent(struct db_context *db);
const char *dbwrap_name(struct db_context *db);

/* The following definitions come from lib/dbwrap_util.c  */

NTSTATUS dbwrap_purge(struct db_context *db, TDB_DATA key);
NTSTATUS dbwrap_purge_bystring(struct db_context *db, const char *key);
NTSTATUS dbwrap_delete_bystring(struct db_context *db, const char *key);
NTSTATUS dbwrap_store_bystring(struct db_context *db, const char *key,
			       TDB_DATA data, int flags);
NTSTATUS dbwrap_fetch_bystring(struct db_context *db, TALLOC_CTX *mem_ctx,
			       const char *key, TDB_DATA *value);

NTSTATUS dbwrap_fetch_int32(struct db_context *db, TDB_DATA key,
			    int32_t *result);
NTSTATUS dbwrap_fetch_int32_bystring(struct db_context *db, const char *keystr,
				     int32_t *result);
NTSTATUS dbwrap_store_int32_bystring(struct db_context *db, const char *keystr,
				     int32_t v);
NTSTATUS dbwrap_fetch_uint32_bystring(struct db_context *db,
				      const char *keystr, uint32_t *val);
NTSTATUS dbwrap_store_uint32_bystring(struct db_context *db,
				      const char *keystr, uint32_t v);
NTSTATUS dbwrap_change_uint32_atomic_bystring(struct db_context *db,
					      const char *keystr,
					      uint32_t *oldval,
					      uint32_t change_val);
NTSTATUS dbwrap_trans_change_uint32_atomic_bystring(struct db_context *db,
						    const char *keystr,
						    uint32_t *oldval,
						    uint32_t change_val);
NTSTATUS dbwrap_change_int32_atomic(struct db_context *db,
				    TDB_DATA key,
				    int32_t *oldval,
				    int32_t change_val);
NTSTATUS dbwrap_change_int32_atomic_bystring(struct db_context *db,
					     const char *keystr,
					     int32_t *oldval,
					     int32_t change_val);
NTSTATUS dbwrap_trans_change_int32_atomic_bystring(struct db_context *db,
						   const char *keystr,
						   int32_t *oldval,
						   int32_t change_val);
NTSTATUS dbwrap_trans_store(struct db_context *db, TDB_DATA key, TDB_DATA dbuf,
			    int flag);
NTSTATUS dbwrap_trans_delete(struct db_context *db, TDB_DATA key);
NTSTATUS dbwrap_trans_store_int32_bystring(struct db_context *db,
					   const char *keystr,
					   int32_t v);
NTSTATUS dbwrap_trans_store_uint32_bystring(struct db_context *db,
					    const char *keystr,
					    uint32_t v);
NTSTATUS dbwrap_trans_store_bystring(struct db_context *db, const char *key,
				     TDB_DATA data, int flags);
NTSTATUS dbwrap_trans_delete_bystring(struct db_context *db, const char *key);
NTSTATUS dbwrap_trans_do(struct db_context *db,
			 NTSTATUS (*action)(struct db_context *, void *),
			 void *private_data);
NTSTATUS dbwrap_trans_traverse(struct db_context *db,
			       int (*f)(struct db_record*, void*),
			       void *private_data);

NTSTATUS dbwrap_delete_bystring_upper(struct db_context *db, const char *key);
NTSTATUS dbwrap_store_bystring_upper(struct db_context *db, const char *key,
				     TDB_DATA data, int flags);
NTSTATUS dbwrap_fetch_bystring_upper(struct db_context *db, TALLOC_CTX *mem_ctx,
				     const char *key, TDB_DATA *value);

size_t dbwrap_marshall(struct db_context *db, uint8_t *buf, size_t bufsize);
NTSTATUS dbwrap_parse_marshall_buf(const uint8_t *buf, size_t buflen,
				   bool (*fn)(TDB_DATA key, TDB_DATA value,
					      void *private_data),
				   void *private_data);
NTSTATUS dbwrap_unmarshall(struct db_context *db, const uint8_t *buf,
			   size_t buflen);

TDB_DATA dbwrap_merge_dbufs(TALLOC_CTX *mem_ctx,
			    const TDB_DATA *dbufs, int num_dbufs);


/**
 * This opens a tdb file
 */
struct db_context *dbwrap_local_open(TALLOC_CTX *mem_ctx,
				     const char *name,
				     int hash_size, int tdb_flags,
				     int open_flags, mode_t mode,
				     enum dbwrap_lock_order lock_order,
				     uint64_t dbwrap_flags);

#endif /* __DBWRAP_H__ */
