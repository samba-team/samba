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

/*
  search the sam for the specified attributes - va_list variant
*/
int gendb_search_v(struct ldb_context *ldb, 
		   TALLOC_CTX *mem_ctx,
		   const char *basedn,
		   struct ldb_message ***res,
		   const char * const *attrs,
		   const char *format, 
		   va_list ap)
{
	char *expr = NULL;
	int count;

	vasprintf(&expr, format, ap);
	if (expr == NULL) {
		return -1;
	}

	ldb_set_alloc(ldb, talloc_ldb_alloc, mem_ctx);

	count = ldb_search(ldb, basedn, LDB_SCOPE_SUBTREE, expr, attrs, res);

	DEBUG(4,("gendb_search_v: %s %s -> %d  (%s)\n", 
		 basedn?basedn:"NULL", expr, count,
		 count==-1?ldb_errstring(ldb):"OK"));

	free(expr);

	return count;
}
