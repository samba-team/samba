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
#include "lib/util/dlinklist.h"
#include "lib/events/events.h"
#include "lib/tdb/include/tdb.h"
#include "lib/ldb/include/ldb.h"
#include "lib/ldb/include/ldb_errors.h"
#include "lib/ldb/samba/ldif_handlers.h"
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

char *wrap_casefold(void *context, void *mem_ctx, const char *s)
{
	return strupper_talloc(mem_ctx, s);
}

/* check for memory leaks on the ldb context */
static int ldb_wrap_destructor(struct ldb_context *ldb)
{
	size_t *startup_blocks = (size_t *)ldb_get_opaque(ldb, "startup_blocks");
	if (startup_blocks &&
	    talloc_total_blocks(ldb) > *startup_blocks + 100) {
		DEBUG(0,("WARNING: probable memory leak in ldb %s - %lu blocks (startup %lu) %lu bytes\n",
			 (char *)ldb_get_opaque(ldb, "wrap_url"), 
			 (unsigned long)talloc_total_blocks(ldb), 
			 (unsigned long)*startup_blocks,
			 (unsigned long)talloc_total_size(ldb)));
#if 0
		talloc_report_full(ldb, stdout);
#endif
	}
	return 0;
}				 

/*
  wrapped connection to a ldb database
  to close just talloc_free() the returned ldb_context

  TODO:  We need an error_string parameter
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
	size_t *startup_blocks;

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

	/* we usually want Samba databases to be private. If we later
	   find we need one public, we will need to add a parameter to
	   ldb_wrap_connect() */
	ldb_set_create_perms(ldb, 0600);
	
	ret = ldb_connect(ldb, real_url, flags, options);
	if (ret != LDB_SUCCESS) {
		talloc_free(ldb);
		return NULL;
	}

	ldb_set_debug(ldb, ldb_wrap_debug, NULL);

	ldb_set_utf8_fns(ldb, NULL, wrap_casefold);

	/* setup for leak detection */
	ldb_set_opaque(ldb, "wrap_url", real_url);
	startup_blocks = talloc(ldb, size_t);
	*startup_blocks = talloc_total_blocks(ldb);
	ldb_set_opaque(ldb, "startup_blocks", startup_blocks);
	
	talloc_set_destructor(ldb, ldb_wrap_destructor);

	return ldb;
}


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
	int debug_level;

	va_start(ap, format);
	vasprintf(&ptr, format, ap);
	va_end(ap);
	
	switch (level) {
	case TDB_DEBUG_FATAL:
		debug_level = 0;
		break;
	case TDB_DEBUG_ERROR:
		debug_level = 1;
		break;
	case TDB_DEBUG_WARNING:
		debug_level = 2;
		break;
	case TDB_DEBUG_TRACE:
		debug_level = 5;
		break;
	default:
		debug_level = 0;
	}		

	if (ptr != NULL) {
		const char *name = tdb_name(tdb);
		DEBUG(debug_level, ("tdb(%s): %s", name ? name : "unnamed", ptr));
		free(ptr);
	}
}


/* destroy the last connection to a tdb */
static int tdb_wrap_destructor(struct tdb_wrap *w)
{
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
	struct tdb_logging_context log_ctx;
	log_ctx.log_fn = tdb_wrap_log;

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
			     open_flags, mode, &log_ctx, NULL);
	if (w->tdb == NULL) {
		talloc_free(w);
		return NULL;
	}

	talloc_set_destructor(w, tdb_wrap_destructor);

	DLIST_ADD(tdb_list, w);

	return w;
}
