/* 
   Samba Unix SMB/CIFS implementation.

   Samba temporary memory allocation functions - new interface

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
  inspired by http://swapped.cc/halloc/
*/

#include "includes.h"

#define MAX_TALLOC_SIZE 0x10000000
#define TALLOC_MAGIC 0xe814ec4f
#define TALLOC_MAGIC_FREE 0x7faebef3

struct talloc_chunk {
	struct talloc_chunk *next, *prev;
	struct talloc_chunk *parent, *child;
	size_t size;
	uint_t magic;
	uint_t ref_count;
	int (*destructor)(void *);
	char *name;
};

/* panic if we get a bad magic value */
static struct talloc_chunk *talloc_chunk_from_ptr(void *ptr)
{
	struct talloc_chunk *tc = ((struct talloc_chunk *)ptr)-1;
	if (tc->magic != TALLOC_MAGIC) {
		if (tc->magic == TALLOC_MAGIC_FREE) {
			smb_panic("Bad talloc magic value - double free\n");
		} else {
			smb_panic("Bad talloc magic value\n");
		}
	}
	return tc;
}

/* 
   Allocate a bit of memory as a child of an existing pointer
*/
void *talloc(void *context, size_t size)
{
	struct talloc_chunk *tc;

	if (size >= MAX_TALLOC_SIZE) {
		return NULL;
	}

	tc = malloc(sizeof(*tc)+size);
	if (tc == NULL) {
		return NULL;
	}

	tc->size = size;
	tc->magic = TALLOC_MAGIC;
	tc->ref_count = 1;
	tc->destructor = NULL;
	tc->child = NULL;
	tc->name = NULL;

	if (context) {
		struct talloc_chunk *parent = talloc_chunk_from_ptr(context);

		tc->parent = parent;

		if (parent->child) {
			parent->child->parent = NULL;
		}

		DLIST_ADD(parent->child, tc);
	} else {
		tc->next = tc->prev = tc->parent = NULL;
	}

	return (void *)(tc+1);
}


/*
  setup a destructor to be called on free of a pointer
  the destructor should return 0 on success, or -1 on failure.
  if the destructor fails then the free is failed, and the memory can
  be continued to be used
*/
void talloc_set_destructor(void *ptr, int (*destructor)(void *))
{
	struct talloc_chunk *tc = talloc_chunk_from_ptr(ptr);
	tc->destructor = destructor;
}

/*
  increase the reference count on a piece of memory. To decrease the 
  reference count call talloc_free(), which will free the memory if 
  the reference count reaches zero
*/
void talloc_increase_ref_count(void *ptr)
{
	struct talloc_chunk *tc = talloc_chunk_from_ptr(ptr);
	tc->ref_count++;
}


/*
  add a name to an existing pointer - va_list version
*/
static void talloc_set_name_v(void *ptr, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(2,0);

static void talloc_set_name_v(void *ptr, const char *fmt, va_list ap)
{
	struct talloc_chunk *tc = talloc_chunk_from_ptr(ptr);
	vasprintf(&tc->name, fmt, ap);
}

/*
  add a name to an existing pointer
*/
void talloc_set_name(void *ptr, const char *fmt, ...) _PRINTF_ATTRIBUTE(2,3)
{
	va_list ap;
	va_start(ap, fmt);
	talloc_set_name_v(ptr, fmt, ap);
	va_end(ap);
}

/*
  create a named talloc pointer. Any talloc pointer can be named, and
  talloc_named() operates just like talloc() except that it allows you
  to name the pointer.
*/
void *talloc_named(void *context, size_t size, 
		   const char *fmt, ...) _PRINTF_ATTRIBUTE(3,4)
{
	va_list ap;
	void *ptr;

	ptr = talloc(context, size);
	if (ptr == NULL) {
		return NULL;
	}

	va_start(ap, fmt);
	talloc_set_name_v(ptr, fmt, ap);
	va_end(ap);

	return ptr;
}

/*
  this is for compatibility with older versions of talloc
*/
void *talloc_init(const char *fmt, ...) _PRINTF_ATTRIBUTE(1,2)
{
	va_list ap;
	void *ptr;

	ptr = talloc(NULL, 0);
	if (ptr == NULL) {
		return NULL;
	}

	va_start(ap, fmt);
	talloc_set_name_v(ptr, fmt, ap);
	va_end(ap);

	return ptr;
}



/* 
   free a talloc pointer. This also frees all child pointers of this 
   pointer recursively

   return 0 if the memory is actually freed, otherwise -1. The memory
   will not be freed if the ref_count is > 1 or the destructor (if
   any) returns non-zero
*/
int talloc_free(void *ptr)
{
	struct talloc_chunk *tc;

	if (ptr == NULL) {
		return -1;
	}

	tc = talloc_chunk_from_ptr(ptr);

	tc->ref_count--;
	if (tc->ref_count != 0) {
		return -1;
	}

	if (tc->destructor && tc->destructor(ptr) == -1) {
		tc->ref_count++;
		return -1;
	}

	while (tc->child) {
		if (talloc_free(tc->child + 1) != 0) {
			tc->child->parent = NULL;
			break;
		}
	}

	if (tc->parent) {
		DLIST_REMOVE(tc->parent->child, tc);
		if (tc->parent->child) {
			tc->parent->child->parent = tc->parent;
		}
	} else {
		if (tc->prev) tc->prev->next = tc->next;
		if (tc->next) tc->next->prev = tc->prev;
	}

	tc->magic = TALLOC_MAGIC_FREE;
	if (tc->name) free(tc->name);

	free(tc);
	return 0;
}



/*
  A talloc version of realloc 
*/
void *talloc_realloc(void *ptr, size_t size)
{
	struct talloc_chunk *tc;
	void *new_ptr;

	/* size zero is equivalent to free() */
	if (size == 0) {
		talloc_free(ptr);
		return NULL;
	}

	/* realloc(NULL) is equavalent to malloc() */
	if (ptr == NULL) {
		return talloc(NULL, size);
	}

	tc = talloc_chunk_from_ptr(ptr);

	/* by resetting magic we catch users of the old memory */
	tc->magic = TALLOC_MAGIC_FREE;

	new_ptr = realloc(tc, size + sizeof(*tc));
	if (!new_ptr) {
		tc->magic = TALLOC_MAGIC;
		return NULL;
	}

	tc = new_ptr;
	tc->magic = TALLOC_MAGIC;
	if (tc->parent) {
		tc->parent->child = new_ptr;
	}

	if (tc->prev) {
		tc->prev->next = tc;
	}
	if (tc->next) {
		tc->next->prev = tc;
	}

	tc->size = size;

	return (void *)(tc+1);
}

/* 
   move a lump of memory from one talloc context to another return the
   ptr on success, or NUL if it could not be transferred
*/
void *talloc_steal(void *new_ctx, void *ptr)
{
	struct talloc_chunk *tc, *new_tc;

	if (!ptr) {
		return NULL;
	}

	tc = talloc_chunk_from_ptr(ptr);
	new_tc = talloc_chunk_from_ptr(new_ctx);

	if (tc == new_tc) {
		return ptr;
	}

	if (tc->parent) {
		DLIST_REMOVE(tc->parent->child, tc);
		if (tc->parent->child) {
			tc->parent->child->parent = tc->parent;
		}
	} else {
		if (tc->prev) tc->prev->next = tc->next;
		if (tc->next) tc->next->prev = tc->prev;
	}

	tc->parent = new_tc;
	if (new_tc->child) new_tc->child->parent = NULL;
	DLIST_ADD(new_tc->child, tc);

	return ptr;
}

/*
  return the total size of a talloc pool (subtree)
*/
off_t talloc_total_size(void *ptr)
{
	off_t total = 0;
	struct talloc_chunk *c, *tc = talloc_chunk_from_ptr(ptr);

	total = tc->size;
	for (c=tc->child;c;c=c->next) {
		total += talloc_total_size(c+1);
	}
	return total;
}


/* 
   talloc and zero memory. 
*/
void *talloc_zero(void *t, size_t size)
{
	void *p = talloc(t, size);

	if (p) {
		memset(p, '\0', size);
	}

	return p;
}


/*
  memdup with a talloc. 
*/
void *talloc_memdup(void *t, const void *p, size_t size)
{
	void *newp = talloc(t,size);

	if (newp) {
		memcpy(newp, p, size);
	}

	return newp;
}

/*
  strdup with a talloc 
*/
char *talloc_strdup(void *t, const char *p)
{
	if (!p) {
		return NULL;
	}
	return talloc_memdup(t, p, strlen(p) + 1);
}

/*
  strndup with a talloc 
*/
char *talloc_strndup(void *t, const char *p, size_t n)
{
	size_t len = strnlen(p, n);
	char *ret;

	ret = talloc(t, len + 1);
	if (!ret) { return NULL; }
	memcpy(ret, p, len);
	ret[len] = 0;
	return ret;
}

static char *talloc_vasprintf(void *t, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(2,0);
static char *talloc_vasprintf(void *t, const char *fmt, va_list ap)
{	
	int len;
	char *ret;
	va_list ap2;
	
	VA_COPY(ap2, ap);

	len = vsnprintf(NULL, 0, fmt, ap2);

	ret = talloc(t, len+1);
	if (ret) {
		VA_COPY(ap2, ap);
		vsnprintf(ret, len+1, fmt, ap2);
	}

	return ret;
}


/*
  Perform string formatting, and return a pointer to newly allocated
  memory holding the result, inside a memory pool.
 */
char *talloc_asprintf(void *t, const char *fmt, ...) _PRINTF_ATTRIBUTE(2,3)
{
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = talloc_vasprintf(t, fmt, ap);
	va_end(ap);
	return ret;
}


/**
 * Realloc @p s to append the formatted result of @p fmt and @p ap,
 * and return @p s, which may have moved.  Good for gradually
 * accumulating output into a string buffer.
 **/

char *talloc_vasprintf_append(char *s,
			      const char *fmt, va_list ap) _PRINTF_ATTRIBUTE(2,0)

{	
	int len, s_len;
	va_list ap2;

	VA_COPY(ap2, ap);

	if (s) {
		s_len = strlen(s);
	} else {
		s_len = 0;
	}
	len = vsnprintf(NULL, 0, fmt, ap2);

	s = talloc_realloc(s, s_len + len+1);
	if (!s) return NULL;

	VA_COPY(ap2, ap);

	vsnprintf(s+s_len, len+1, fmt, ap2);

	return s;
}

/*
  Realloc @p s to append the formatted result of @p fmt and return @p
  s, which may have moved.  Good for gradually accumulating output
  into a string buffer.
 */
char *talloc_asprintf_append(char *s,
			     const char *fmt, ...) _PRINTF_ATTRIBUTE(2,3)
{
	va_list ap;

	va_start(ap, fmt);
	s = talloc_vasprintf_append(s, fmt, ap);
	va_end(ap);
	return s;
}

/*
  alloc an array, checking for integer overflow in the array size
*/
void *talloc_array(void *ctx, size_t el_size, uint_t count)
{
	if (count == 0 ||
	    count >= MAX_TALLOC_SIZE/el_size) {
		return NULL;
	}
	return talloc(ctx, el_size * count);
}


/*
  realloc an array, checking for integer overflow in the array size
*/
void *talloc_realloc_array(void *ptr, size_t el_size, uint_t count)
{
	if (count == 0 ||
	    count >= MAX_TALLOC_SIZE/el_size) {
		return NULL;
	}
	return talloc_realloc(ptr, el_size * count);
}

/*
  a alloc function for ldb that uses talloc
*/
void *talloc_ldb_alloc(void *context, void *ptr, size_t size)
{
	if (ptr == NULL) {
		return talloc(context, size);
	}
	if (size == 0) {
		talloc_free(ptr);
		return NULL;
	}
	return talloc_realloc(ptr, size);
}
