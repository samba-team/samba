/* 
   ldb database library

   Copyright (C) Andrew Tridgell  2004

     ** NOTE! The following LGPL license applies to the ldb
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

/*
 *  Name: ldb
 *
 *  Component: ldb alloc
 *
 *  Description: functions for memory allocation
 *
 *  Author: Andrew Tridgell
 */

#include "includes.h"
#include "ldb/include/ldb.h"
#include "ldb/include/ldb_private.h"


/*
  this allows the user to choose their own allocation function
*/
int ldb_set_alloc(struct ldb_context *ldb,
		  void *(*alloc)(const void *context, void *ptr, size_t size),
		  void *context)
{
	ldb->alloc_ops.alloc = alloc;
	ldb->alloc_ops.context = context;
	return 0;
}

/*
  this is the default memory allocation function
*/
static void *ldb_default_alloc(const void *context, void *ptr, size_t size)
{
	/* by setting LDB_ALLOC_OFS to non-zero the test suite can
	   catch any places where we incorrectly use the libc alloc
	   funcitons directly */
#define LDB_ALLOC_OFS 4
	/* we don't assume a modern realloc function */
	if (ptr == NULL) {
		ptr = malloc(size+LDB_ALLOC_OFS);
		if (ptr) return ((char *)ptr)+LDB_ALLOC_OFS;
		return NULL;
	}
	if (size == 0) {
		free(((char *)ptr)-LDB_ALLOC_OFS);
		return NULL;
	}
	ptr = realloc(((char *)ptr)-LDB_ALLOC_OFS, size+LDB_ALLOC_OFS);
	if (ptr) {
		return ((char *)ptr)+LDB_ALLOC_OFS;
	}
	return NULL;
}

/*
  all memory allocation goes via this function
*/
void *ldb_realloc(struct ldb_context *ldb, void *ptr, size_t size)
{
	if (!ldb->alloc_ops.alloc) {
		ldb_set_alloc(ldb, ldb_default_alloc, NULL);
	}
	return ldb->alloc_ops.alloc(ldb->alloc_ops.context, ptr, size);
}

void *ldb_malloc(struct ldb_context *ldb, size_t size)
{
	return ldb_realloc(ldb, NULL, size);
}

void ldb_free(struct ldb_context *ldb, void *ptr)
{
	if (ptr != NULL) {
		ldb_realloc(ldb, ptr, 0);
	}
}

void *ldb_strndup(struct ldb_context *ldb, const char *str, size_t maxlen)
{
	size_t len = strnlen(str, maxlen);
	void *ret;
	ret = ldb_realloc(ldb, NULL, len+1);
	if (ret) {
		memcpy(ret, str, len);
		((char *)ret)[len] = 0;
	}
	return ret;
}

void *ldb_strdup(struct ldb_context *ldb, const char *str)
{
	size_t len = strlen(str);
	void *ret;
	ret = ldb_realloc(ldb, NULL, len+1);
	if (ret) {
		memcpy(ret, str, len+1);
	}
	return ret;
}

/*
  a ldb wrapper for asprintf(), using ldb_malloc()
*/
int ldb_asprintf(struct ldb_context *ldb, char **strp, const char *fmt, ...)
{
	int len, len2;
	va_list ap;
	
	*strp = NULL;

	va_start(ap, fmt);
	len = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (len < 0) {
		return len;
	}

	*strp = ldb_malloc(ldb, len+1);
	if (! *strp) {
		return -1;
	}

	va_start(ap, fmt);
	len2 = vsnprintf(*strp, len+1, fmt, ap);
	va_end(ap);

	if (len2 != len) {
		/* buggy (or non-C99) vsnprintf function */
		ldb_free(ldb, *strp);
		return -1;
	}

	return len;
}

/*
  realloc an array, checking for integer overflow in the array size
*/
void *ldb_realloc_array(struct ldb_context *ldb,
			void *ptr, size_t el_size, unsigned count)
{
#define MAX_MALLOC_SIZE 0x7fffffff

	if (count == 0 ||
	    count >= MAX_MALLOC_SIZE/el_size) {
		return NULL;
	}
	if (!ptr) {
		return ldb_malloc(ldb, el_size * count);
	}
	return ldb_realloc(ldb, ptr, el_size * count);
}

