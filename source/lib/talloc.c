/* 
   Unix SMB/Netbios implementation.
   Version 3.0
   Samba temporary memory allocation functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) Jeremy Allison  2001
   
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
	t->total_alloc_size = 0;

	return t;
}

static int make_new_chunk(TALLOC_CTX *t, size_t size)
{
	struct talloc_chunk *c;
	size_t asize = (size + (TALLOC_CHUNK_SIZE-1)) & ~(TALLOC_CHUNK_SIZE-1);

	c = (struct talloc_chunk *)malloc(sizeof(*c));
	if (!c) return 0;
	c->next = t->list;
	c->ptr = (void *)malloc(asize);
	if (!c->ptr) {
		free(c);
		return 0;
	}
	c->alloc_size = 0;
	c->total_size = asize;
	t->list = c;
	t->total_alloc_size += asize;
	return 1;
}

/* allocate a bit of memory from the specified pool */
void *talloc(TALLOC_CTX *t, size_t size)
{
	void *p;
	char *prefix_p;
	if (size == 0)
	{
		/* debugging value used to track down
		   memory problems. BAD_PTR is defined
		   in talloc.h */
		p = BAD_PTR;
		return p;
	}

	/* Add in prefix of TALLOC_ALIGN, and ensure it's a multiple of TALLOC_ALIGN's */

	size = (size + TALLOC_ALIGN + (TALLOC_ALIGN-1)) & ~(TALLOC_ALIGN-1);

	if (!t->list || (t->list->total_size - t->list->alloc_size) < size) {
		if (!make_new_chunk(t, size))
			return NULL;
	}

	p = ((char *)t->list->ptr) + t->list->alloc_size;

	/* Ensure the prefix is recognisable. */

	prefix_p = (char *)p;

	memset(prefix_p + sizeof(size_t) + sizeof(t->list), 0xff, TALLOC_ALIGN - (sizeof(size_t) + sizeof(t->list)));

	/* Setup the legth and back pointer prefix. */

	memcpy(prefix_p, &size, sizeof(size_t));
	memcpy(prefix_p + sizeof(size_t), &t->list, sizeof(t->list));

	p = ((char *)t->list->ptr) + t->list->alloc_size + TALLOC_ALIGN;
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
	t->total_alloc_size = 0;
}

/* destroy a whole pool including the context */
void talloc_destroy(TALLOC_CTX *t)
{
	if (!t)
		return;
	talloc_destroy_pool(t);
	free(t);
}

/* return the current total size of the pool. */
size_t talloc_pool_size(TALLOC_CTX *t)
{
	if (!t->list)
		return 0;
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

/* simple talloc with realloc. */
void *talloc_realloc(TALLOC_CTX *t, void *p, size_t size)
{
	char *base_p;
	struct talloc_chunk *c;
	size_t internal_current_size;
	size_t internal_new_size;

	/* Freeing is easy. */

	if (size == 0)
		return NULL;

	/* An ordinary allocation. */

	if (!p)
		return talloc(t, size);

	/* Work with the real size including the TALLOC_ALIGN prefix. */

	internal_new_size = (size + TALLOC_ALIGN + (TALLOC_ALIGN-1)) & ~(TALLOC_ALIGN-1);

	/* Get the legth and back pointer prefix. */

	base_p = ((char *)p) - TALLOC_ALIGN;
	memcpy(&internal_current_size, base_p, sizeof(size_t));
	memcpy(&c, base_p + sizeof(size_t), sizeof(c));

	/* Don't do anything on shrink. */

	if (internal_new_size <= internal_current_size)
		return p;

	if (c->ptr == base_p && c->alloc_size == internal_current_size) {
		/* We are alone in this chunk. Use standard realloc. */
		c->ptr = realloc(c->ptr, internal_new_size);
		if (!c->ptr)
			return NULL;

		/* ensure this new chunk is not used for anything else. */
		c->alloc_size = internal_new_size;
		c->total_size = internal_new_size;
		memcpy(c->ptr, &internal_new_size, sizeof(size_t));

		t->total_alloc_size += (internal_new_size - internal_current_size);

		return ((char *)c->ptr) + TALLOC_ALIGN;
	}

	/* We are part of another chunk. Create a new chunk and move out. */
	if (!make_new_chunk(t, internal_new_size))
		return NULL;

	c = t->list;

	base_p = (char *)c->ptr;

	/* Ensure the prefix is recognisable. */

	memset(base_p + sizeof(size_t) + sizeof(t->list), 0xff, TALLOC_ALIGN - (sizeof(size_t) + sizeof(t->list)));

	/* Setup the legth and back pointer prefix. */

	memcpy(base_p, &internal_new_size, sizeof(size_t));
	memcpy(base_p + sizeof(size_t), &t->list, sizeof(t->list));

	/* Copy the old data. */
	memcpy(base_p + TALLOC_ALIGN, p, internal_current_size - TALLOC_ALIGN);

	p = base_p + TALLOC_ALIGN;
	c->alloc_size = internal_new_size;
	c->total_size = internal_new_size;

	return p;
}
