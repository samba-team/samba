/* 
   Unix SMB/CIFS implementation.

   interface functions for the sam database

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

#include "includes.h"


/*
  the way that unix fcntl locking works forces us to have a static ldb
  handle here rather than a much more sensible approach of having the
  ldb handle as part of the samr_Connect() pipe state. Otherwise we
  would try to open the ldb more than once, and tdb would rightly
  refuse the second open due to the broken nature of unix locking.
*/
static struct ldb_context *sam_db;

/*
  connect to the SAM database
  return 0 on success, -1 on failure
 */
int samdb_connect(void)
{
	if (sam_db != NULL) {
		return 0;
	}
	sam_db = ldb_connect(lp_sam_url(), 0, NULL);

	if (sam_db == NULL) {
		return -1;
	}

	return 0;
}

/*
  a alloc function for ldb
*/
static void *samdb_alloc(void *context, void *ptr, size_t size)
{
	return talloc_realloc((TALLOC_CTX *)context, ptr, size);
}

/*
  search the sam for the specified attributes - va_list varient
*/
int samdb_search_v(TALLOC_CTX *mem_ctx,
		   struct ldb_message ***res,
		   char * const *attrs,
		   const char *format, 
		   va_list ap)
{
	char *expr = NULL;
	int count;

	vasprintf(&expr, format, ap);
	if (expr == NULL) {
		return -1;
	}

	ldb_set_alloc(sam_db, samdb_alloc, mem_ctx);

	count = ldb_search(sam_db, NULL, LDB_SCOPE_SUBTREE, expr, attrs, res);

	free(expr);

	return count;
}
				 

/*
  search the sam for the specified attributes - varargs varient
*/
int samdb_search(TALLOC_CTX *mem_ctx, 
		 struct ldb_message ***res,
		 char * const *attrs,
		 const char *format, ...)
{
	va_list ap;
	int count;

	va_start(ap, format);
	count = samdb_search_v(mem_ctx, res, attrs, format, ap);
	va_end(ap);

	return count;
}

/*
  free up a search result
*/
int samdb_search_free(TALLOC_CTX *mem_ctx, struct ldb_message **res)
{
	ldb_set_alloc(sam_db, samdb_alloc, mem_ctx);
	return ldb_search_free(sam_db, res);
}
				 

/*
  search the sam for a single string attribute in exactly 1 record
*/
char *samdb_search_string(TALLOC_CTX *mem_ctx,
			  const char *attr_name,
			  const char *format, ...)
{
	va_list ap;
	int count;
	char * const attrs[2] = { attr_name, NULL };
	struct ldb_message **res = NULL;
	char *str = NULL;

	va_start(ap, format);
	count = samdb_search_v(mem_ctx, &res, attrs, format, ap);
	va_end(ap);

	if (count == 0) {
		return NULL;
	}

	/* make sure its single valued */
	if (count != 1 ||
	    res[0]->num_elements != 1 ||
	    res[0]->elements[0].num_values != 1 ||
	    res[0]->elements[0].values[0].data == NULL) {
		DEBUG(1,("samdb: search for %s %s not single valued\n", 
			 attr_name, format));
		samdb_search_free(mem_ctx, res);
		return NULL;
	}

	str = talloc_strndup(mem_ctx, 
			     res[0]->elements[0].values[0].data,
			     res[0]->elements[0].values[0].length);

	samdb_search_free(mem_ctx, res);

	return str;
}
				 

/*
  search the sam for multipe records each giving a single string attribute
  return the number of matches, or -1 on error
*/
int samdb_search_string_multiple(TALLOC_CTX *mem_ctx,
				 char ***strs,
				 const char *attr_name,
				 const char *format, ...)
{
	va_list ap;
	int count, i;
	char * const attrs[2] = { attr_name, NULL };
	struct ldb_message **res = NULL;

	va_start(ap, format);
	count = samdb_search_v(mem_ctx, &res, attrs, format, ap);
	va_end(ap);

	if (count <= 0) {
		return count;
	}

	/* make sure its single valued */
	for (i=0;i<count;i++) {
		if (res[i]->num_elements != 1 ||
		    res[i]->elements[0].num_values != 1 ||
		    res[i]->elements[0].values[0].data == NULL) {
			DEBUG(1,("samdb: search for %s %s not single valued\n", 
				 attr_name, format));
			samdb_search_free(mem_ctx, res);
			return -1;
		}
	}

	*strs = talloc_array_p(mem_ctx, char *, count+1);
	if (! *strs) {
		samdb_search_free(mem_ctx, res);
		return -1;
	}

	for (i=0;i<count;i++) {
		(*strs)[i] = talloc_strndup(mem_ctx, 
					    res[i]->elements[0].values[0].data,
					    res[i]->elements[0].values[0].length);
	}
	(*strs)[count] = NULL;

	samdb_search_free(mem_ctx, res);

	return count;
}

/*
  pull a uint from a result set. 
*/
uint_t samdb_result_uint(struct ldb_message *msg, const char *attr, uint_t default_value)
{
	return ldb_msg_find_uint(msg, attr, default_value);
}
