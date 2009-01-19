/* 
   Unix SMB/CIFS implementation.
   tdb utility functions
   Copyright (C) Andrew Tridgell 1999
   
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

#ifndef __TDBUTIL_H__
#define __TDBUTIL_H__

#include "tdb.h"

#include "talloc.h" /* for tdb_wrap_open() */
#include "../libcli/util/ntstatus.h" /* for map_nt_error_from_tdb() */

struct tdb_wrap {
	struct tdb_context *tdb;
	const char *name;
	struct tdb_wrap *next, *prev;
};

struct tdb_validation_status {
	bool tdb_error;
	bool bad_freelist;
	bool bad_entry;
	bool unknown_key;
	bool success;
};

typedef int (*tdb_validate_data_func)(TDB_CONTEXT *the_tdb, TDB_DATA kbuf, TDB_DATA dbuf, void *state);

TDB_DATA make_tdb_data(const uint8_t *dptr, size_t dsize);
TDB_DATA string_tdb_data(const char *string);
TDB_DATA string_term_tdb_data(const char *string);

int tdb_chainlock_with_timeout( struct tdb_context *tdb, TDB_DATA key,
				unsigned int timeout);
int tdb_lock_bystring(struct tdb_context *tdb, const char *keyval);
int tdb_lock_bystring_with_timeout(struct tdb_context *tdb, const char *keyval,
				   int timeout);
void tdb_unlock_bystring(struct tdb_context *tdb, const char *keyval);
int tdb_read_lock_bystring_with_timeout(TDB_CONTEXT *tdb, const char *keyval,
					unsigned int timeout);
void tdb_read_unlock_bystring(struct tdb_context *tdb, const char *keyval);

int32_t tdb_fetch_int32_byblob(struct tdb_context *tdb, TDB_DATA key);
int32_t tdb_fetch_int32(struct tdb_context *tdb, const char *keystr);
bool tdb_store_uint32_byblob(struct tdb_context *tdb, TDB_DATA key, uint32_t value);
bool tdb_store_uint32(struct tdb_context *tdb, const char *keystr, uint32_t value);
int tdb_store_int32_byblob(struct tdb_context *tdb, TDB_DATA key, int32_t v);
int tdb_store_int32(struct tdb_context *tdb, const char *keystr, int32_t v);
bool tdb_fetch_uint32_byblob(struct tdb_context *tdb, TDB_DATA key, uint32_t *value);
bool tdb_fetch_uint32(struct tdb_context *tdb, const char *keystr, uint32_t *value);
int32_t tdb_change_int32_atomic(struct tdb_context *tdb, const char *keystr, int32_t *oldval, int32_t change_val);
bool tdb_change_uint32_atomic(struct tdb_context *tdb, const char *keystr,
			      uint32_t *oldval, uint32_t change_val);

int tdb_store_bystring(struct tdb_context *tdb, const char *keystr, TDB_DATA data, int flags);
int tdb_trans_store_bystring(TDB_CONTEXT *tdb, const char *keystr,
			     TDB_DATA data, int flags);
TDB_DATA tdb_fetch_bystring(struct tdb_context *tdb, const char *keystr);
int tdb_delete_bystring(struct tdb_context *tdb, const char *keystr);
int tdb_trans_store(struct tdb_context *tdb, TDB_DATA key, TDB_DATA dbuf,
		    int flag);
int tdb_trans_delete(struct tdb_context *tdb, TDB_DATA key);

int tdb_unpack(const uint8 *buf, int bufsize, const char *fmt, ...);
size_t tdb_pack(uint8 *buf, int bufsize, const char *fmt, ...);
bool tdb_pack_append(TALLOC_CTX *mem_ctx, uint8 **buf, size_t *len,
		     const char *fmt, ...);

struct tdb_context *tdb_open_log(const char *name, int hash_size,
				 int tdb_flags, int open_flags, mode_t mode);

struct tdb_wrap *tdb_wrap_open(TALLOC_CTX *mem_ctx,
			       const char *name, int hash_size, int tdb_flags,
			       int open_flags, mode_t mode);

NTSTATUS map_nt_error_from_tdb(enum TDB_ERROR err);

int tdb_validate(struct tdb_context *tdb, tdb_validate_data_func validate_fn);
int tdb_validate_open(const char *tdb_path, tdb_validate_data_func validate_fn);
int tdb_validate_and_backup(const char *tdb_path,
			    tdb_validate_data_func validate_fn);

#endif /* __TDBUTIL_H__ */
