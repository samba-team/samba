/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba temporary memory allocation functions
   Copyright (C) Andrew Tridgell 2000
   
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

/* this is a very simple temporary memory allocator. To use it do the following:

   1) when you first want to allocate a pool of meomry use
   talloc_init() and save the resulting context pointer somewhere

   2) to allocate memory use talloc()

   3) when _all_ of the memory allocated using this context is no longer needed
   use talloc_destroy()

   talloc does not zero the memory. It guarantees memory of a
   TALLOC_ALIGN alignment
*/

#include "includes.h"

/* initialise talloc context. */
TALLOC_CTX *talloc_init(void)
{
	TALLOC_CTX *t;

	t = (TALLOC_CTX *)malloc(sizeof(*t));
	if (!t) return NULL;

	t->list = NULL;
	t->total_alloc_size = 0;

	return t;
}

/* allocate a bit of memory from the specified pool */
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

	t->list = NULL;
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
void *talloc_memdup(TALLOC_CTX *t, void *p, size_t size)
{
	void *newp = talloc(t,size);

	if (!newp)
		return 0;

	memcpy(newp, p, size);

	return newp;
}

/* strdup with a talloc */
char *talloc_strdup(TALLOC_CTX *t, char *p)
{
	return talloc_memdup(t, p, strlen(p) + 1);
}
