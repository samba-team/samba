/*
   Unix SMB/CIFS implementation.

   tdb utility functions

   Copyright (C) Rusty Russell 2012

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

#ifndef _____LIB_UTIL_UTIL_NTDB_H__
#define _____LIB_UTIL_UTIL_NTDB_H__
#include <ntdb.h>
#include <talloc.h>
#include "libcli/util/ntstatus.h"

struct loadparm_context;
union ntdb_attribute;

/* You only need this on databases with NTDB_CLEAR_IF_FIRST */
int ntdb_reopen(struct ntdb_context *ntdb);

/* You only need to do this if you have NTDB_CLEAR_IF_FIRST databases, and
 * the parent will go away before this child. */
int ntdb_reopen_all(void);

/*
 * This is like TDB_CLEAR_IF_FIRST, for use with ntdb_new.
 *
 * It's a bad idea for new code.
 */
#define NTDB_CLEAR_IF_FIRST 1048576

/***************************************************************
 Open an NTDB using talloc: it will be allocated off the context, and
 all NTDB_DATA.dptr are allocated as children of the ntdb context.
 Sets up a logging function for you, and uses lp_ctx to decide whether
 to disable mmap.

 Any extra ntdb attributes can be handed through attr; usually it's
 NULL, ntdb_new provides logging and allocator attributes.

 The destructor for the struct ntdb_context will do ntdb_close()
 for you.
****************************************************************/
struct ntdb_context *ntdb_new(TALLOC_CTX *ctx,
			      const char *name, int ntdb_flags,
			      int open_flags, mode_t mode,
			      union ntdb_attribute *attr,
			      struct loadparm_context *lp_ctx);

/****************************************************************************
 Lock a chain by string.
****************************************************************************/
enum NTDB_ERROR ntdb_lock_bystring(struct ntdb_context *ntdb,
				   const char *keyval);

/****************************************************************************
 Unlock a chain by string.
****************************************************************************/
void ntdb_unlock_bystring(struct ntdb_context *ntdb, const char *keyval);

/****************************************************************************
 Delete an entry using a null terminated string key.
****************************************************************************/
enum NTDB_ERROR ntdb_delete_bystring(struct ntdb_context *ntdb,
				     const char *keystr);

/****************************************************************************
 Store a buffer by a null terminated string key.  Return 0 on success, -ve
 on failure.
****************************************************************************/
enum NTDB_ERROR ntdb_store_bystring(struct ntdb_context *ntdb,
				    const char *keystr,
				    NTDB_DATA data, int nflags);

/****************************************************************************
 Fetch a buffer using a null terminated string key.  Don't forget to call
 free() on the result dptr (unless the ntdb is from ntdb_new, in which case
 it will be a child of ntdb).
****************************************************************************/
enum NTDB_ERROR ntdb_fetch_bystring(struct ntdb_context *ntdb,
				    const char *keystr,
				    NTDB_DATA *data);


/****************************************************************************
 Fetch a int32_t value by a string key.  *val is int32_t in native byte order.
 ntdb must have been created with ntdb_new() (as it uses talloc_free).
****************************************************************************/
enum NTDB_ERROR ntdb_fetch_int32(struct ntdb_context *ntdb,
				 const char *keystr, int32_t *val);

/****************************************************************************
 Store a int32_t value by a string key.  val is int32_t in native byte order.
****************************************************************************/
enum NTDB_ERROR ntdb_store_int32(struct ntdb_context *ntdb,
				 const char *keystr, int32_t val);


/****************************************************************************
 Atomic integer add; reads the old value into *oldval (if found), then stores
 *oldval + addval back for next time.  Uses chainlock to do this atomically.

 Thus the first time this is ever called, oldval will be unchanged.
****************************************************************************/
enum NTDB_ERROR ntdb_add_int32_atomic(struct ntdb_context *ntdb,
				      const char *keystr,
				      int32_t *oldval, int32_t addval);

/****************************************************************************
 Turn a nul-terminated string into an NTDB_DATA.
****************************************************************************/
static inline NTDB_DATA string_term_ntdb_data(const char *string)
{
	return ntdb_mkdata(string, string ? strlen(string) + 1 : 0);
}


/****************************************************************************
 Return an NTSTATUS from a NTDB_ERROR
****************************************************************************/
NTSTATUS map_nt_error_from_ntdb(enum NTDB_ERROR err);
#endif /* _____LIB_UTIL_UTIL_NTDB_H__ */
