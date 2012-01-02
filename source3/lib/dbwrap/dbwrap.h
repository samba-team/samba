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

#include "tdb_compat.h"

struct db_record;
struct db_context;

/* The following definitions come from lib/dbwrap.c  */

TDB_DATA dbwrap_record_get_key(const struct db_record *rec);
TDB_DATA dbwrap_record_get_value(const struct db_record *rec);
NTSTATUS dbwrap_record_store(struct db_record *rec, TDB_DATA data, int flags);
NTSTATUS dbwrap_record_delete(struct db_record *rec);
struct db_record *dbwrap_fetch_locked(struct db_context *db,
				      TALLOC_CTX *mem_ctx,
				      TDB_DATA key);
struct db_record *dbwrap_try_fetch_locked(struct db_context *db,
					  TALLOC_CTX *mem_ctx,
					  TDB_DATA key);
struct db_context *dbwrap_record_get_db(struct db_record *rec);

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
int dbwrap_wipe(struct db_context *db);
int dbwrap_get_seqnum(struct db_context *db);
int dbwrap_get_flags(struct db_context *db);
int dbwrap_transaction_start(struct db_context *db);
int dbwrap_transaction_commit(struct db_context *db);
int dbwrap_transaction_cancel(struct db_context *db);
void dbwrap_db_id(struct db_context *db, const uint8_t **id, size_t *idlen);


/* The following definitions come from lib/dbwrap_util.c  */

NTSTATUS dbwrap_delete_bystring(struct db_context *db, const char *key);
NTSTATUS dbwrap_store_bystring(struct db_context *db, const char *key,
			       TDB_DATA data, int flags);
NTSTATUS dbwrap_fetch_bystring(struct db_context *db, TALLOC_CTX *mem_ctx,
			       const char *key, TDB_DATA *value);

NTSTATUS dbwrap_fetch_int32(struct db_context *db, const char *keystr,
			    int32_t *result);
NTSTATUS dbwrap_store_int32(struct db_context *db, const char *keystr,
			    int32_t v);
NTSTATUS dbwrap_fetch_uint32(struct db_context *db, const char *keystr,
			     uint32_t *val);
NTSTATUS dbwrap_store_uint32(struct db_context *db, const char *keystr,
			     uint32_t v);
NTSTATUS dbwrap_change_uint32_atomic(struct db_context *db, const char *keystr,
				     uint32_t *oldval, uint32_t change_val);
NTSTATUS dbwrap_trans_change_uint32_atomic(struct db_context *db,
					   const char *keystr,
					   uint32_t *oldval,
					   uint32_t change_val);
NTSTATUS dbwrap_change_int32_atomic(struct db_context *db, const char *keystr,
				    int32_t *oldval, int32_t change_val);
NTSTATUS dbwrap_trans_change_int32_atomic(struct db_context *db,
					  const char *keystr,
					  int32_t *oldval,
					  int32_t change_val);
NTSTATUS dbwrap_trans_store(struct db_context *db, TDB_DATA key, TDB_DATA dbuf,
			    int flag);
NTSTATUS dbwrap_trans_delete(struct db_context *db, TDB_DATA key);
NTSTATUS dbwrap_trans_store_int32(struct db_context *db, const char *keystr,
				  int32_t v);
NTSTATUS dbwrap_trans_store_uint32(struct db_context *db, const char *keystr,
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

#endif /* __DBWRAP_H__ */
