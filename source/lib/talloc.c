/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba temporary memory allocation functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   
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

/**
   @defgroup talloc Simple memory allocator
   @{
   
   This is a very simple temporary memory allocator. To use it do the following:

   1) when you first want to allocate a pool of meomry use
   talloc_init() and save the resulting context pointer somewhere

   2) to allocate memory use talloc()

   3) when _all_ of the memory allocated using this context is no longer needed
   use talloc_destroy()

   talloc does not zero the memory. It guarantees memory of a
   TALLOC_ALIGN alignment
*/

/* TODO: We could allocate both the talloc_chunk structure, and the
 * memory it contains all in one allocation, which might be a bit
 * faster and perhaps use less memory overhead.
 *
 * That smells like a premature optimization, though.  -- mbp */

#include "includes.h"

/** Create a new talloc context. **/
TALLOC_CTX *talloc_init(void)
{
	TALLOC_CTX *t;

	t = (TALLOC_CTX *)malloc(sizeof(*t));
	if (!t) return NULL;

	t->list = NULL;
	t->total_alloc_size = 0;

	return t;
}



/**
 * Create a new talloc context, with a name specifying its purpose.
 * Please call this in preference to talloc_init().
 **/
 TALLOC_CTX *talloc_init_named(char const *fmt, ...) 
{
	TALLOC_CTX *t;
	va_list ap;

	t = talloc_init();
	va_start(ap, fmt);
	t->name = talloc_vasprintf(t, fmt, ap);
	va_end(ap);

	return t;
}


/** Allocate a bit of memory from the specified pool **/
void *talloc(TALLOC_CTX *t, size_t size)
{
	void *p;
	struct talloc_chunk *tc;

	if (size == 0) return NULL;

	p = malloc(size);
	if (!p) return p;

	tc = malloc(sizeof(*tc));
	if (!tc) {
		SAFE_FREE(p);
		return NULL;
	}

	tc->ptr = p;
	tc->size = size;
	tc->next = t->list;
	t->list = tc;
	t->total_alloc_size += size;

	return p;
}

/* a talloc version of realloc */
void *talloc_realloc(TALLOC_CTX *t, void *ptr, size_t size)
{
	struct talloc_chunk *tc;

	/* size zero is equivalent to free() */
	if (size == 0)
		return NULL;

	/* realloc(NULL) is equavalent to malloc() */
	if (ptr == NULL)
		return talloc(t, size);

	for (tc=t->list; tc; tc=tc->next) {
		if (tc->ptr == ptr) {
			ptr = Realloc(ptr, size);
			if (ptr) {
				t->total_alloc_size += (size - tc->size);
				tc->size = size;
				tc->ptr = ptr;
			}
			return ptr;
		}
	}
	return NULL;
}

/* destroy a whole pool */
void talloc_destroy_pool(TALLOC_CTX *t)
{
	struct talloc_chunk *c;
	
	if (!t)
		return;

	while (t->list) {
		c = t->list->next;
		SAFE_FREE(t->list->ptr);
		SAFE_FREE(t->list);
		t->list = c;
	}

	t->total_alloc_size = 0;
}

/* destroy a whole pool including the context */
void talloc_destroy(TALLOC_CTX *t)
{
	if (!t)
		return;
	talloc_destroy_pool(t);
	memset(t, 0, sizeof(*t));
	SAFE_FREE(t);
}

/* return the current total size of the pool. */
size_t talloc_pool_size(TALLOC_CTX *t)
{
	return t->total_alloc_size;
}

/* talloc and zero memory. */
void *talloc_zero(TALLOC_CTX *t, size_t size)
{
	void *p = talloc(t, size);

	if (p)
		memset(p, '\0', size);

	return p;
}

/* memdup with a talloc. */
void *talloc_memdup(TALLOC_CTX *t, const void *p, size_t size)
{
	void *newp = talloc(t,size);

	if (!newp)
		return 0;

	memcpy(newp, p, size);

	return newp;
}

/* strdup with a talloc */
char *talloc_strdup(TALLOC_CTX *t, const char *p)
{
	return talloc_memdup(t, p, strlen(p) + 1);
}

/**
 * Perform string formatting, and return a pointer to newly allocated
 * memory holding the result, inside a memory pool.
 **/
 char *talloc_asprintf(TALLOC_CTX *t, const char *fmt, ...)
{
	va_list ap;
	char *ret;

	/* work out how long it will be */
	va_start(ap, fmt);
	ret = talloc_vasprintf(t, fmt, ap);
	va_end(ap);
	return ret;
}


 char *talloc_vasprintf(TALLOC_CTX *t, const char *fmt, va_list ap)
{	
	int len;
	char *ret;
	
	len = vsnprintf(NULL, 0, fmt, ap);

	ret = talloc(t, len+1);
	if (!ret) return NULL;

	vsnprintf(ret, len+1, fmt, ap);

	return ret;
}


/** @} */
