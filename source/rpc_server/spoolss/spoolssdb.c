/* 
   Unix SMB/CIFS implementation.

   interface functions for the spoolss database

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Tim Potter 2004
   
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

#include "includes.h"
#include "lib/ldb/include/ldb.h"

struct spoolssdb_context {
	struct ldb_context *ldb;
};

/*
  this is used to catch debug messages from ldb
*/
static void spoolssdb_debug(void *context, enum ldb_debug_level level, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(3, 0);
static void spoolssdb_debug(void *context, enum ldb_debug_level level, const char *fmt, va_list ap)
{
	char *s = NULL;
	if (DEBUGLEVEL < 4 && level > LDB_DEBUG_WARNING) {
		return;
	}
	vasprintf(&s, fmt, ap);
	if (!s) return;
	DEBUG(level, ("spoolssdb: %s\n", s));
	free(s);
}

/*
  connect to the spoolss database
  return an opaque context pointer on success, or NULL on failure
 */
void *spoolssdb_connect(void)
{
	struct spoolssdb_context *ctx;
	/*
	  the way that unix fcntl locking works forces us to have a
	  static ldb handle here rather than a much more sensible
	  approach of having the ldb handle as part of the
	  spoolss_OpenPrinter() pipe state. Otherwise we would try to open
	  the ldb more than once, and tdb would rightly refuse the
	  second open due to the broken nature of unix locking.
	*/
	static struct ldb_context *static_spoolss_db;

	if (static_spoolss_db == NULL) {
		static_spoolss_db = ldb_connect(lp_spoolss_url(), 0, NULL);
		if (static_spoolss_db == NULL) {
			return NULL;
		}
	}

	ldb_set_debug(static_spoolss_db, spoolssdb_debug, NULL);

	ctx = malloc_p(struct spoolssdb_context);
	if (!ctx) {
		errno = ENOMEM;
		return NULL;
	}

	ctx->ldb = static_spoolss_db;

	return ctx;
}

/* close a connection to the spoolss db */
void spoolssdb_close(void *ctx)
{
	struct spoolssdb_context *spoolss_ctx = ctx;
	/* we don't actually close due to broken posix locking semantics */
	spoolss_ctx->ldb = NULL;
	free(spoolss_ctx);
}

/*
  search the db for the specified attributes - varargs variant
*/
int spoolssdb_search(void *ctx,
		 TALLOC_CTX *mem_ctx, 
		 const char *basedn,
		 struct ldb_message ***res,
		 const char * const *attrs,
		 const char *format, ...) _PRINTF_ATTRIBUTE(6,7)
{
	struct spoolssdb_context *spoolss_ctx = ctx;
	va_list ap;
	int count;

	va_start(ap, format);
	count = gendb_search_v(spoolss_ctx->ldb, mem_ctx, basedn, res, attrs, format, ap);
	va_end(ap);

	return count;
}

