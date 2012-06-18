/*
   Unix SMB/CIFS implementation.

   Compatibility layer for TDB1 vs TDB2.

   Copyright (C) Rusty Russell 2011

     ** NOTE! The following LGPL license applies to the tdb_compat
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/
#ifndef TDB_COMPAT_H
#define TDB_COMPAT_H

#include "replace.h"
#include <ccan/typesafe_cb/typesafe_cb.h>
#include <tdb.h>

/* FIXME: Inlining this is a bit lazy, but eases S3 build. */
static inline struct tdb_context *
tdb_open_compat(const char *name, int hash_size,
		int tdb_flags, int open_flags, mode_t mode,
		tdb_log_func log_fn, void *log_private)
{
	struct tdb_logging_context lctx;
	lctx.log_fn = log_fn;
	lctx.log_private = log_private;

	if (log_fn)
		return tdb_open_ex(name, hash_size, tdb_flags, open_flags,
				   mode, &lctx, NULL);
	else
		return tdb_open(name, hash_size, tdb_flags, open_flags, mode);
}

#define tdb_firstkey_compat tdb_firstkey
/* Note: this frees the old key.dptr. */
static inline TDB_DATA tdb_nextkey_compat(struct tdb_context *tdb, TDB_DATA k)
{
	TDB_DATA next = tdb_nextkey(tdb, k);
	free(k.dptr);
	return next;
}
#define tdb_errorstr_compat(tdb) tdb_errorstr(tdb)
#define tdb_fetch_compat tdb_fetch

#endif /* TDB_COMPAT_H */
