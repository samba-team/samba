/* 
   Unix SMB/CIFS implementation.

   database wrap functions

   Copyright (C) Andrew Tridgell 2004
   
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

/*
  the stupidity of the unix fcntl locking design forces us to never
  allow a database file to be opened twice in the same process. These
  wrappers provide convenient access to a tdb or ldb, taking advantage
  of talloc destructors to ensure that only a single open is done
*/

#include "includes.h"
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "lib/ldb/include/ldb.h"
#include "db_wrap.h"

static struct tdb_wrap *tdb_list;

/*
  this is used to catch debug messages from ldb
*/
static void ldb_wrap_debug(void *context, enum ldb_debug_level level, 
			   const char *fmt, va_list ap)  PRINTF_ATTRIBUTE(3,0);

static void ldb_wrap_debug(void *context, enum ldb_debug_level level, 
			   const char *fmt, va_list ap)
{
	char *s = NULL;
	if (DEBUGLEVEL < 4 && level > LDB_DEBUG_WARNING) {
		return;
	}
	if (DEBUGLEVEL < 2 && level > LDB_DEBUG_ERROR) {
		return;
	}
	vasprintf(&s, fmt, ap);
	if (!s) return;
	DEBUG(level, ("ldb: %s\n", s));
	free(s);
}

int wrap_caseless_cmp(void *context, const char *s1, const char *s2)
{
	return strcasecmp_m(s1, s2);
}

char *wrap_casefold(void *context, void *mem_ctx, const char *s)
{
	return strupper_talloc(mem_ctx, s);
}

/*
  wrapped connection to a ldb database
  to close just talloc_free() the returned ldb_context
 */
struct ldb_context *ldb_wrap_connect(TALLOC_CTX *mem_ctx,
				     const char *url,
				     struct auth_session_info *session_info,
				     struct cli_credentials *credentials,
				     unsigned int flags,
				     const char *options[])
{
	struct ldb_context *ldb;
	int ret;
	struct event_context *ev;
	char *real_url = NULL;

	ldb = ldb_init(mem_ctx);
	if (ldb == NULL) {
		return NULL;
	}

	/* we want to use the existing event context if possible. This
	   relies on the fact that in smbd, everything is a child of
	   the main event_context */
	ev = event_context_find(ldb);

	if (ldb_set_opaque(ldb, "EventContext", ev)) {
		talloc_free(ldb);
		return NULL;
	}

	if (ldb_set_opaque(ldb, "sessionInfo", session_info)) {
		talloc_free(ldb);
		return NULL;
	}

	if (ldb_set_opaque(ldb, "credentials", credentials)) {
		talloc_free(ldb);
		return NULL;
	}

	ret = ldb_register_samba_handlers(ldb);
	if (ret == -1) {
		talloc_free(ldb);
		return NULL;
	}

	real_url = private_path(ldb, url);
	if (real_url == NULL) {
		talloc_free(ldb);
		return NULL;
	}

	/* allow admins to force non-sync ldb for all databases */
	if (lp_parm_bool(-1, "ldb", "nosync", False)) {
		flags |= LDB_FLG_NOSYNC;
	}
	
	ret = ldb_connect(ldb, real_url, flags, options);
	if (ret == -1) {
		talloc_free(ldb);
		return NULL;
	}

	talloc_free(real_url);

	ldb_set_debug(ldb, ldb_wrap_debug, NULL);

	ldb_set_utf8_fns(ldb, NULL, wrap_casefold);

	return ldb;
}


/*
 Log tdb messages via DEBUG().
*/
static void tdb_wrap_log(TDB_CONTEXT *tdb, int level, 
			 const char *format, ...) PRINTF_ATTRIBUTE(3,4);

static void tdb_wrap_log(TDB_CONTEXT *tdb, int level, 
			 const char *format, ...)
{
	va_list ap;
	char *ptr = NULL;

	va_start(ap, format);
	vasprintf(&ptr, format, ap);
	va_end(ap);
	
	if (ptr != NULL) {
		const char *name = tdb_name(tdb);
		DEBUG(level, ("tdb(%s): %s", name ? name : "unnamed", ptr));
		free(ptr);
	}
}


/* destroy the last connection to a tdb */
static int tdb_wrap_destructor(void *ctx)
{
	struct tdb_wrap *w = ctx;
	tdb_close(w->tdb);
	DLIST_REMOVE(tdb_list, w);
	return 0;
}				 

/*
  wrapped connection to a tdb database
  to close just talloc_free() the tdb_wrap pointer
 */
struct tdb_wrap *tdb_wrap_open(TALLOC_CTX *mem_ctx,
			       const char *name, int hash_size, int tdb_flags,
			       int open_flags, mode_t mode)
{
	struct tdb_wrap *w;

	for (w=tdb_list;w;w=w->next) {
		if (strcmp(name, w->name) == 0) {
			return talloc_reference(mem_ctx, w);
		}
	}

	w = talloc(mem_ctx, struct tdb_wrap);
	if (w == NULL) {
		return NULL;
	}

	w->name = talloc_strdup(w, name);

	w->tdb = tdb_open_ex(name, hash_size, tdb_flags, 
			     open_flags, mode, tdb_wrap_log, NULL);
	if (w->tdb == NULL) {
		talloc_free(w);
		return NULL;
	}

	talloc_set_destructor(w, tdb_wrap_destructor);

	DLIST_ADD(tdb_list, w);

	return w;
}
