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

static struct ldb_wrap *ldb_list;
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
	vasprintf(&s, fmt, ap);
	if (!s) return;
	DEBUG(level, ("ldb: %s\n", s));
	free(s);
}


/* destroy the last connection to a ldb */
static int ldb_wrap_destructor(void *ctx)
{
	struct ldb_wrap *w = ctx;
	ldb_close(w->ldb);
	DLIST_REMOVE(ldb_list, w);
	return 0;
}				 

/*
  wrapped connection to a ldb database
  to close just talloc_free() the ldb_wrap pointer
 */
struct ldb_wrap *ldb_wrap_connect(TALLOC_CTX *mem_ctx,
				  const char *url,
				  unsigned int flags,
				  const char *options[])
{
	struct ldb_wrap *w;

	for (w=ldb_list;w;w=w->next) {
		if (strcmp(url, w->url) == 0) {
			return talloc_reference(mem_ctx, w);
		}
	}

	w = talloc_p(mem_ctx, struct ldb_wrap);
	if (w == NULL) {
		return NULL;
	}

	w->url = talloc_strdup(w, url);

	w->ldb = ldb_connect(url, flags, options);
	if (w->ldb == NULL) {
		talloc_free(w);
		return NULL;
	}

	talloc_set_destructor(w, ldb_wrap_destructor);
	ldb_set_debug(w->ldb, ldb_wrap_debug, NULL);

	DLIST_ADD(ldb_list, w);

	return w;
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
		DEBUG(level, ("tdb(%s): %s", tdb->name ? tdb->name : "unnamed", ptr));
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

	w = talloc_p(mem_ctx, struct tdb_wrap);
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
