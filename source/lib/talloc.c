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

#define TALLOC_ALIGN 32
#define TALLOC_CHUNK_SIZE (0x2000)

/* initialissa talloc context. */
TALLOC_CTX *talloc_init(void)
{
	TALLOC_CTX *t;

	t = (TALLOC_CTX *)malloc(sizeof(*t));
	if (!t) return NULL;

	t->list = NULL;

	return t;
}

/* allocate a bit of memory from the specified pool */
void *talloc(TALLOC_CTX *t, size_t size)
{
	void *p;
	if (size == 0)
	{
		/* debugging value used to track down
		   memory problems. BAD_PTR is defined
		   in talloc.h */
		p = BAD_PTR;
		return p;
	}

	/* normal code path */
	size = (size + (TALLOC_ALIGN-1)) & ~(TALLOC_ALIGN-1);

	if (!t->list || (t->list->total_size - t->list->alloc_size) < size) {
		struct talloc_chunk *c;
		size_t asize = (size + (TALLOC_CHUNK_SIZE-1)) & ~(TALLOC_CHUNK_SIZE-1);

		c = (struct talloc_chunk *)malloc(sizeof(*c));
		if (!c) return NULL;
		c->next = t->list;
		c->ptr = (void *)malloc(asize);
		if (!c->ptr) {
			free(c);
			return NULL;
		}
		c->alloc_size = 0;
		c->total_size = asize;
		t->list = c;
	}

	p = ((char *)t->list->ptr) + t->list->alloc_size;
	t->list->alloc_size += size;

	
	return p;
}

/* destroy a whole pool */
void talloc_destroy_pool(TALLOC_CTX *t)
{
	struct talloc_chunk *c;
	
	if (!t)
		return;

	while (t->list) {
		c = t->list->next;
		free(t->list->ptr);
		free(t->list);
		t->list = c;
	}

	t->list = NULL;
}

/* destroy a whole pool including the context */
void talloc_destroy(TALLOC_CTX *t)
{
	if (!t)
		return;
	talloc_destroy_pool(t);
	free(t);
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

