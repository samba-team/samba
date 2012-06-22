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
#include "replace.h"
#include "system/filesys.h"

/*
 * This handles NTDB_CLEAR_IF_FIRST.
 *
 * It's a bad idea for new code, but S3 uses it quite a bit.
 */
static enum NTDB_ERROR clear_if_first(int fd, void *unused)
{
	/* We hold a lock offset 4 always, so we can tell if anyone else is. */
	struct flock fl;

	fl.l_type = F_WRLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 4; /* ACTIVE_LOCK */
	fl.l_len = 1;

	if (fcntl(fd, F_SETLK, &fl) == 0) {
		/* We must be first ones to open it w/ NTDB_CLEAR_IF_FIRST! */
		if (ftruncate(fd, 0) != 0) {
			return NTDB_ERR_IO;
		}
	}
	fl.l_type = F_RDLCK;
	if (fcntl(fd, F_SETLKW, &fl) != 0) {
		return NTDB_ERR_IO;
	}
	return NTDB_SUCCESS;
}

/* We only need these for the CLEAR_IF_FIRST lock. */
static int reacquire_cif_lock(struct ntdb_context *ntdb, bool *fail)
{
	struct flock fl;
	union ntdb_attribute cif;

	cif.openhook.base.attr = NTDB_ATTRIBUTE_OPENHOOK;
	cif.openhook.base.next = NULL;

	if (ntdb_get_attribute(ntdb, &cif) != NTDB_SUCCESS
	    || cif.openhook.fn != clear_if_first) {
		return 0;
	}

	/* We hold a lock offset 4 always, so we can tell if anyone else is. */
	fl.l_type = F_RDLCK;
	fl.l_whence = SEEK_SET;
	fl.l_start = 4; /* ACTIVE_LOCK */
	fl.l_len = 1;
	if (fcntl(ntdb_fd(ntdb), F_SETLKW, &fl) != 0) {
		*fail = true;
		return -1;
	}
	return 0;
}

/* You only need this on databases with NTDB_CLEAR_IF_FIRST */
int ntdb_reopen(struct ntdb_context *ntdb)
{
	bool unused;
	return reacquire_cif_lock(ntdb, &unused);
}

/* You only need to do this if you have NTDB_CLEAR_IF_FIRST databases, and
 * the parent will go away before this child. */
int ntdb_reopen_all(void)
{
	bool fail = false;

	ntdb_foreach(reacquire_cif_lock, &fail);
	if (fail)
		return -1;
	return 0;
}

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
	union ntdb_attribute log_attr, alloc_attr, open_attr;
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

	if (ntdb_flags & NTDB_CLEAR_IF_FIRST) {
		log_attr.base.next = &open_attr;
		open_attr.openhook.base.attr = NTDB_ATTRIBUTE_OPENHOOK;
		open_attr.openhook.base.next = attr;
		open_attr.openhook.fn = clear_if_first;
		ntdb_flags &= ~NTDB_CLEAR_IF_FIRST;
	}

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
