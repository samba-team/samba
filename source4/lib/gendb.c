/* 
   Unix SMB/CIFS implementation.

   common share info functions

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
#include "lib/ldb/include/ldb_errors.h"

/*
  search the sam for the specified attributes - va_list variant
*/
int gendb_search_v(struct ldb_context *ldb, 
		   TALLOC_CTX *mem_ctx,
		   struct ldb_dn *basedn,
		   struct ldb_message ***msgs,
		   const char * const *attrs,
		   const char *format, 
		   va_list ap)  _PRINTF_ATTRIBUTE(6,0)
{
	enum ldb_scope scope = LDB_SCOPE_SUBTREE;
	struct ldb_result *res;
	char *expr = NULL;
	int ret;

	if (format) {
		expr = talloc_vasprintf(mem_ctx, format, ap);
		if (expr == NULL) {
			return -1;
		}
	} else {
		scope = LDB_SCOPE_BASE;
	}

	res = NULL;

	ret = ldb_search(ldb, basedn, scope, expr, attrs, &res);

	if (ret == LDB_SUCCESS) {
		talloc_steal(mem_ctx, res->msgs);

		DEBUG(6,("gendb_search_v: %s %s -> %d\n", 
			 basedn?ldb_dn_get_linearized(basedn):"NULL",
			 expr?expr:"NULL", res->count));

		ret = res->count;
		*msgs = res->msgs;
		talloc_free(res);
	} else {
		DEBUG(4,("gendb_search_v: search failed: %s", ldb_errstring(ldb)));
		ret = -1;
	}

	talloc_free(expr);

	return ret;
}

/*
  search the LDB for the specified attributes - varargs variant
*/
int gendb_search(struct ldb_context *ldb,
		 TALLOC_CTX *mem_ctx, 
		 struct ldb_dn *basedn,
		 struct ldb_message ***res,
		 const char * const *attrs,
		 const char *format, ...) _PRINTF_ATTRIBUTE(6,7)
{
	va_list ap;
	int count;

	va_start(ap, format);
	count = gendb_search_v(ldb, mem_ctx, basedn, res, attrs, format, ap);
	va_end(ap);

	return count;
}

/*
  search the LDB for a specified record (by DN)
*/

int gendb_search_dn(struct ldb_context *ldb,
		 TALLOC_CTX *mem_ctx, 
		 struct ldb_dn *dn,
		 struct ldb_message ***res,
		 const char * const *attrs)
{
	return gendb_search(ldb, mem_ctx, dn, res, attrs, NULL);
}

/*
  setup some initial ldif in a ldb
*/
int gendb_add_ldif(struct ldb_context *ldb, const char *ldif_string)
{
	struct ldb_ldif *ldif;
	int ret;
	ldif = ldb_ldif_read_string(ldb, &ldif_string);
	if (ldif == NULL) return -1;
	ret = ldb_add(ldb, ldif->msg);
	talloc_free(ldif);
	return ret;
}
