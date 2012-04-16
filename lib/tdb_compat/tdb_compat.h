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
#if BUILD_TDB2
#include <tdb2.h>
#include <fcntl.h>
#include <unistd.h>

extern TDB_DATA tdb_null;

/* Old-style tdb_fetch. */
static inline TDB_DATA tdb_fetch_compat(struct tdb_context *tdb, TDB_DATA k)
{
	TDB_DATA dbuf;
	if (tdb_fetch(tdb, k, &dbuf) != TDB_SUCCESS) {
		return tdb_null;
	}
	return dbuf;
}

static inline TDB_DATA tdb_firstkey_compat(struct tdb_context *tdb)
{
	TDB_DATA k;
	if (tdb_firstkey(tdb, &k) != TDB_SUCCESS) {
		return tdb_null;
	}
	return k;
}

/* Note: this frees the old key.dptr. */
static inline TDB_DATA tdb_nextkey_compat(struct tdb_context *tdb, TDB_DATA k)
{
	if (tdb_nextkey(tdb, &k) != TDB_SUCCESS) {
		return tdb_null;
	}
	return k;
}

#define tdb_traverse_read(tdb, fn, p)					\
	tdb_traverse_read_(tdb, typesafe_cb_preargs(int, void *, (fn), (p), \
						    struct tdb_context *, \
						    TDB_DATA, TDB_DATA), (p))
int64_t tdb_traverse_read_(struct tdb_context *tdb,
			   int (*fn)(struct tdb_context *,
				     TDB_DATA, TDB_DATA, void *), void *p);

/* Old-style tdb_errorstr */
#define tdb_errorstr_compat(tdb) tdb_errorstr(tdb_error(tdb))

/* This typedef doesn't exist in TDB2. */
typedef struct tdb_context TDB_CONTEXT;

/* We only need these for the CLEAR_IF_FIRST lock. */
int tdb_reopen(struct tdb_context *tdb);
int tdb_reopen_all(int parent_longlived);

/* These no longer exist in tdb2. */
#define TDB_CLEAR_IF_FIRST 1048576
#define TDB_INCOMPATIBLE_HASH 2097152
#define TDB_VOLATILE 4194304

/* tdb2 does nonblocking functions via attibutes. */
enum TDB_ERROR tdb_transaction_start_nonblock(struct tdb_context *tdb);
enum TDB_ERROR tdb_chainlock_nonblock(struct tdb_context *tdb, TDB_DATA key);


/* Convenient (typesafe) wrapper for tdb open with logging */
#define tdb_open_compat(name, hsize, tdb_fl, open_fl, mode, log_fn, log_data) \
	tdb_open_compat_((name), (hsize), (tdb_fl), (open_fl), (mode),	\
			 typesafe_cb_preargs(void, void *,		\
					     (log_fn), (log_data),	\
					     struct tdb_context *,	\
					     enum tdb_log_level,	\
					     enum TDB_ERROR,	        \
					     const char *),		\
			 (log_data))

struct tdb_context *
tdb_open_compat_(const char *name, int hash_size,
		 int tdb_flags, int open_flags, mode_t mode,
		 void (*log_fn)(struct tdb_context *,
				enum tdb_log_level,
				enum TDB_ERROR ecode,
				const char *message,
				void *data),
		 void *log_data);
#else
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
#endif

#endif /* TDB_COMPAT_H */
