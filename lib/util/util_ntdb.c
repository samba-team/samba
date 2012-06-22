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

enum NTDB_ERROR ntdb_lock_bystring(struct ntdb_context *ntdb,
				   const char *keyval)
{
	NTDB_DATA key = string_term_ntdb_data(keyval);

	return ntdb_chainlock(ntdb, key);
}

void ntdb_unlock_bystring(struct ntdb_context *ntdb, const char *keyval)
{
	NTDB_DATA key = string_term_ntdb_data(keyval);

	ntdb_chainunlock(ntdb, key);
}

enum NTDB_ERROR ntdb_delete_bystring(struct ntdb_context *ntdb,
				     const char *keystr)
{
	NTDB_DATA key = string_term_ntdb_data(keystr);

	return ntdb_delete(ntdb, key);
}

enum NTDB_ERROR ntdb_store_bystring(struct ntdb_context *ntdb,
				    const char *keystr,
				    NTDB_DATA data, int nflags)
{
	NTDB_DATA key = string_term_ntdb_data(keystr);

	return ntdb_store(ntdb, key, data, nflags);
}

enum NTDB_ERROR ntdb_fetch_bystring(struct ntdb_context *ntdb,
				    const char *keystr,
				    NTDB_DATA *data)
{
	NTDB_DATA key = string_term_ntdb_data(keystr);

	return ntdb_fetch(ntdb, key, data);
}

enum NTDB_ERROR ntdb_fetch_int32(struct ntdb_context *ntdb,
				 const char *keystr, int32_t *val)
{
	NTDB_DATA data;
	enum NTDB_ERROR err;

	err = ntdb_fetch(ntdb, string_term_ntdb_data(keystr), &data);
	if (err == NTDB_SUCCESS) {
		if (data.dsize != sizeof(*val)) {
			err = NTDB_ERR_CORRUPT;
		} else {
			*val = IVAL(data.dptr,0);
		}
		talloc_free(data.dptr);
	}
	return NTDB_SUCCESS;
}

enum NTDB_ERROR ntdb_store_int32(struct ntdb_context *ntdb,
				 const char *keystr, int32_t val)
{
	NTDB_DATA data, key;
	int32_t v_store;

	SIVAL(&v_store, 0, val);
	data = ntdb_mkdata(&v_store, sizeof(v_store));
	key = string_term_ntdb_data(keystr);

	return ntdb_store(ntdb, key, data, NTDB_REPLACE);
}

enum NTDB_ERROR ntdb_add_int32_atomic(struct ntdb_context *ntdb,
				      const char *keystr,
				      int32_t *oldval, int32_t addval)
{
	int32_t val;
	enum NTDB_ERROR err;

	err = ntdb_lock_bystring(ntdb, keystr);
	if (err) {
		return err;
	}

	err = ntdb_fetch_int32(ntdb, keystr, &val);
	if (err) {
		if (err == NTDB_ERR_NOEXIST) {
			/* Start with 'old' value */
			val = *oldval;
		} else {
			goto err_out;
		}
	} else {
		/* It worked, set return value (oldval) to tdb data */
		*oldval = val;
	}

	/* Increase value and store for next time. */
	val += addval;
	err = ntdb_store_int32(ntdb, keystr, val);

  err_out:
	ntdb_unlock_bystring(ntdb, keystr);
	return err;
}

NTSTATUS map_nt_error_from_ntdb(enum NTDB_ERROR err)
{
	NTSTATUS result = NT_STATUS_INTERNAL_ERROR;

	switch (err) {
	case NTDB_SUCCESS:
		result = NT_STATUS_OK;
		break;
	case NTDB_ERR_CORRUPT:
		result = NT_STATUS_INTERNAL_DB_CORRUPTION;
		break;
	case NTDB_ERR_IO:
		result = NT_STATUS_UNEXPECTED_IO_ERROR;
		break;
	case NTDB_ERR_OOM:
		result = NT_STATUS_NO_MEMORY;
		break;
	case NTDB_ERR_EXISTS:
		result = NT_STATUS_OBJECT_NAME_COLLISION;
		break;

	case NTDB_ERR_LOCK:
		/*
		 * NTDB_ERR_LOCK is very broad, we could for example
		 * distinguish between fcntl locks and invalid lock
		 * sequences. So NT_STATUS_FILE_LOCK_CONFLICT is a
		 * compromise.
		 */
		result = NT_STATUS_FILE_LOCK_CONFLICT;
		break;
	case NTDB_ERR_NOEXIST:
		result = NT_STATUS_NOT_FOUND;
		break;
	case NTDB_ERR_EINVAL:
		result = NT_STATUS_INVALID_PARAMETER;
		break;
	case NTDB_ERR_RDONLY:
		result = NT_STATUS_ACCESS_DENIED;
		break;
	};
	return result;
}
