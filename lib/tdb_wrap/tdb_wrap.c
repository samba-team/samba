/*
   Unix SMB/CIFS implementation.
   TDB wrap functions

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Jelmer Vernooij <jelmer@samba.org> 2007

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

#include "replace.h"
#include "lib/util/dlinklist.h"
#include "lib/util/debug.h"
#include "tdb_wrap.h"

/*
 Log tdb messages via DEBUG().
*/
static void tdb_wrap_log(TDB_CONTEXT *tdb, enum tdb_debug_level level,
			 const char *format, ...) PRINTF_ATTRIBUTE(3,4);

static void tdb_wrap_log(TDB_CONTEXT *tdb, enum tdb_debug_level level,
			 const char *format, ...)
{
	va_list ap;
	char *ptr = NULL;
	int debuglevel = 0;
	int ret;

	switch (level) {
	case TDB_DEBUG_FATAL:
		debuglevel = 0;
		break;
	case TDB_DEBUG_ERROR:
		debuglevel = 1;
		break;
	case TDB_DEBUG_WARNING:
		debuglevel = 2;
		break;
	case TDB_DEBUG_TRACE:
		debuglevel = 5;
		break;
	default:
		debuglevel = 0;
	}

	va_start(ap, format);
	ret = vasprintf(&ptr, format, ap);
	va_end(ap);

	if (ret != -1) {
		const char *name = tdb_name(tdb);
		DEBUG(debuglevel, ("tdb(%s): %s", name ? name : "unnamed", ptr));
		free(ptr);
	}
}

struct tdb_wrap_private {
	struct tdb_context *tdb;
	const char *name;
	struct tdb_wrap_private *next, *prev;
};

static struct tdb_wrap_private *tdb_list;

/* destroy the last connection to a tdb */
static int tdb_wrap_private_destructor(struct tdb_wrap_private *w)
{
	tdb_close(w->tdb);
	DLIST_REMOVE(tdb_list, w);
	return 0;
}

static struct tdb_wrap_private *tdb_wrap_private_open(TALLOC_CTX *mem_ctx,
						      const char *name,
						      int hash_size,
						      int tdb_flags,
						      int open_flags,
						      mode_t mode)
{
	struct tdb_wrap_private *result;
	struct tdb_logging_context lctx = { .log_fn = tdb_wrap_log };

	result = talloc_pooled_object(mem_ctx, struct tdb_wrap_private,
				      1, strlen(name)+1);
	if (result == NULL) {
		return NULL;
	}
	/* Doesn't fail, see talloc_pooled_object */
	result->name = talloc_strdup(result, name);

	result->tdb = tdb_open_ex(name, hash_size, tdb_flags,
				  open_flags, mode, &lctx, NULL);
	if (result->tdb == NULL) {
		goto fail;
	}
	talloc_set_destructor(result, tdb_wrap_private_destructor);
	DLIST_ADD(tdb_list, result);
	return result;

fail:
	TALLOC_FREE(result);
	return NULL;
}

/*
  wrapped connection to a tdb database
  to close just talloc_free() the tdb_wrap pointer
 */
struct tdb_wrap *tdb_wrap_open(TALLOC_CTX *mem_ctx,
			       const char *name, int hash_size, int tdb_flags,
			       int open_flags, mode_t mode)
{
	struct tdb_wrap *result;
	struct tdb_wrap_private *w;

	if (name == NULL) {
		errno = EINVAL;
		return NULL;
	}

	result = talloc(mem_ctx, struct tdb_wrap);
	if (result == NULL) {
		return NULL;
	}

	for (w=tdb_list;w;w=w->next) {
		if (strcmp(name, w->name) == 0) {
			break;
		}
	}

	if (w == NULL) {

		if (tdb_flags & TDB_MUTEX_LOCKING) {
			if (!tdb_runtime_check_for_robust_mutexes()) {
				tdb_flags &= ~TDB_MUTEX_LOCKING;
			}
		}

		w = tdb_wrap_private_open(result, name, hash_size, tdb_flags,
					  open_flags, mode);
	} else {
		/*
		 * Correctly use talloc_reference: The tdb will be
		 * closed when "w" is being freed. The caller never
		 * sees "w", so an incorrect use of talloc_free(w)
		 * instead of calling talloc_unlink is not possible.
		 * To avoid having to refcount ourselves, "w" will
		 * have multiple parents that hang off all the
		 * tdb_wrap's being returned from here. Those parents
		 * can be freed without problem.
		 */
		if (talloc_reference(result, w) == NULL) {
			goto fail;
		}
	}
	if (w == NULL) {
		goto fail;
	}
	result->tdb = w->tdb;
	return result;
fail:
	TALLOC_FREE(result);
	return NULL;
}
