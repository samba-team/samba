/*
   Unix SMB/CIFS implementation.

   ntdb utility functions

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
#include "includes.h"
#include "util_ntdb.h"
#include "lib/param/param.h"

static void *ntdb_talloc(const void *owner, size_t len, void *priv_data)
{
	return talloc_size(owner, len);
}

static void *ntdb_expand(void *old, size_t newlen, void *priv_data)
{
	return talloc_realloc_size(NULL, old, newlen);
}

static void ntdb_free(void *old, void *priv_data)
{
	talloc_free(old);
}

static int ntdb_destroy(struct ntdb_context *ntdb)
{
	ntdb_close(ntdb);
	return 0;
}

static void ntdb_log(struct ntdb_context *ntdb,
		     enum ntdb_log_level level,
		     enum NTDB_ERROR ecode,
		     const char *message,
		     void *unused)
{
	int dl;
	const char *name = ntdb_name(ntdb);

	switch (level) {
	case NTDB_LOG_USE_ERROR:
	case NTDB_LOG_ERROR:
		dl = 0;
		break;
	case NTDB_LOG_WARNING:
		dl = 2;
		break;
	default:
		dl = 0;
	}

	DEBUG(dl, ("ntdb(%s):%s: %s\n", name ? name : "unnamed",
		   ntdb_errorstr(ecode), message));
}

struct ntdb_context *ntdb_new(TALLOC_CTX *ctx,
			      const char *name, int ntdb_flags,
			      int open_flags, mode_t mode,
			      union ntdb_attribute *attr,
			      struct loadparm_context *lp_ctx)
{
	union ntdb_attribute log_attr, alloc_attr;
	struct ntdb_context *ntdb;

	if (lp_ctx && !lpcfg_use_mmap(lp_ctx)) {
		ntdb_flags |= NTDB_NOMMAP;
	}

	/* Great hack for speeding testing! */
	if (getenv("TDB_NO_FSYNC")) {
		ntdb_flags |= NTDB_NOSYNC;
	}

	log_attr.base.next = attr;
	log_attr.base.attr = NTDB_ATTRIBUTE_LOG;
	log_attr.log.fn = ntdb_log;

	alloc_attr.base.next = &log_attr;
	alloc_attr.base.attr = NTDB_ATTRIBUTE_ALLOCATOR;
	alloc_attr.alloc.alloc = ntdb_talloc;
	alloc_attr.alloc.expand = ntdb_expand;
	alloc_attr.alloc.free = ntdb_free;

	ntdb = ntdb_open(name, ntdb_flags, open_flags, mode, &alloc_attr);
	if (!ntdb) {
		return NULL;
	}

	/* We can re-use the tdb's path name for the talloc name */
	name = ntdb_name(ntdb);
	if (name) {
		talloc_set_name_const(ntdb, name);
	} else {
		talloc_set_name_const(ntdb, "unnamed ntdb");
	}
	talloc_set_destructor(ntdb, ntdb_destroy);

	return talloc_steal(ctx, ntdb);
}
