/* 
   Unix SMB/CIFS implementation.
   tdb utility functions
   Copyright (C) Andrew Tridgell 1999
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#ifndef __TDBUTIL_H__
#define __TDBUTIL_H__

#include "tdb.h"

/* single node of a list returned by tdb_search_keys */
typedef struct keys_node 
{
	struct keys_node *prev, *next;
	TDB_DATA node_key;
} TDB_LIST_NODE;


TDB_LIST_NODE *tdb_search_keys(struct tdb_context*, const char*);
void tdb_search_list_free(TDB_LIST_NODE*);
int32_t tdb_change_int32_atomic(struct tdb_context *tdb, const char *keystr, int32_t *oldval, int32_t change_val);
int tdb_lock_bystring(struct tdb_context *tdb, const char *keyval);
void tdb_unlock_bystring(struct tdb_context *tdb, const char *keyval);
int32_t tdb_fetch_int32(struct tdb_context *tdb, const char *keystr);
BOOL tdb_store_uint32(struct tdb_context *tdb, const char *keystr, uint32_t value);
int tdb_store_int32(struct tdb_context *tdb, const char *keystr, int32_t v);
BOOL tdb_fetch_uint32(struct tdb_context *tdb, const char *keystr, uint32_t *value);
int tdb_traverse_delete_fn(struct tdb_context *the_tdb, TDB_DATA key, TDB_DATA dbuf,
                     void *state);
int tdb_store_bystring(struct tdb_context *tdb, const char *keystr, TDB_DATA data, int flags);
TDB_DATA tdb_fetch_bystring(struct tdb_context *tdb, const char *keystr);
int tdb_delete_bystring(struct tdb_context *tdb, const char *keystr);
int tdb_unpack(struct tdb_context *tdb, char *buf, int bufsize, const char *fmt, ...);
size_t tdb_pack(struct tdb_context *tdb, char *buf, int bufsize, const char *fmt, ...);

#endif /* __TDBUTIL_H__ */
