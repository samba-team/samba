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

static const void *null_context;

struct talloc_chunk {
	struct talloc_chunk *next, *prev;
	struct talloc_chunk *parent, *child;
	size_t size;
	uint_t magic;
	uint_t ref_count;
	int (*destructor)(void *);
	const char *name;
};

/* panic if we get a bad magic value */
static struct talloc_chunk *talloc_chunk_from_ptr(const void *ptr)
{
	struct talloc_chunk *tc = ((struct talloc_chunk *)discard_const(ptr))-1;
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
void *_talloc(const void *context, size_t size)
{
	struct talloc_chunk *tc;

	if (context == NULL) {
		context = null_context;
	}

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
void talloc_set_destructor(const void *ptr, int (*destructor)(void *))
{
	struct talloc_chunk *tc = talloc_chunk_from_ptr(ptr);
	tc->destructor = destructor;
}

/*
  increase the reference count on a piece of memory. To decrease the 
  reference count call talloc_free(), which will free the memory if 
  the reference count reaches zero
*/
void talloc_increase_ref_count(const void *ptr)
{
	struct talloc_chunk *tc = talloc_chunk_from_ptr(ptr);
	tc->ref_count++;
}

/*
  helper for talloc_reference()
*/
static int talloc_reference_destructor(void *ptr)
{
	void **handle = ptr;
	talloc_free(*handle);
	return 0;
}

/*
  make a secondary reference to a pointer, hanging off the given context.
  the pointer remains valid until both the original caller and this given
  context are freed.
  
  the major use for this is when two different structures need to reference the 
  same underlying data, and you want to be able to free the two instances separately,
  and in either order
*/
void *talloc_reference(const void *context, const void *ptr)
{
	void **handle;
	handle = talloc_named_const(context, sizeof(void *), ".reference");
	if (handle == NULL) {
		return NULL;
	}
	/* note that we hang the destructor off the handle, not the
	   main context as that allows the caller to still setup their
	   own destructor on the context if they want to */
	talloc_set_destructor(handle, talloc_reference_destructor);
	talloc_increase_ref_count(ptr);
	*handle = discard_const(ptr);
	return *handle;
}


/*
  add a name to an existing pointer - va_list version
*/
static void talloc_set_name_v(const void *ptr, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(2,0);

static void talloc_set_name_v(const void *ptr, const char *fmt, va_list ap)
{
	struct talloc_chunk *tc = talloc_chunk_from_ptr(ptr);
	tc->name = talloc_vasprintf(ptr, fmt, ap);
	if (tc->name) {
		talloc_set_name_const(tc->name, ".name");
	}
}

/*
  add a name to an existing pointer
*/
void talloc_set_name(const void *ptr, const char *fmt, ...) _PRINTF_ATTRIBUTE(2,3)
{
	va_list ap;
	va_start(ap, fmt);
	talloc_set_name_v(ptr, fmt, ap);
	va_end(ap);
}

/*
   more efficient way to add a name to a pointer - the name must point to a 
   true string constant
*/
void talloc_set_name_const(const void *ptr, const char *name)
{
	struct talloc_chunk *tc = talloc_chunk_from_ptr(ptr);
	tc->name = name;
}

/*
  create a named talloc pointer. Any talloc pointer can be named, and
  talloc_named() operates just like talloc() except that it allows you
  to name the pointer.
*/
void *talloc_named(const void *context, size_t size, 
		   const char *fmt, ...) _PRINTF_ATTRIBUTE(3,4)
{
	va_list ap;
	void *ptr;

	ptr = _talloc(context, size);
	if (ptr == NULL) {
		return NULL;
	}

	va_start(ap, fmt);
	talloc_set_name_v(ptr, fmt, ap);
	va_end(ap);

	return ptr;
}

/*
  create a named talloc pointer. Any talloc pointer can be named, and
  talloc_named() operates just like talloc() except that it allows you
  to name the pointer.
*/
void *talloc_named_const(const void *context, size_t size, const char *name)
{
	void *ptr;

	ptr = _talloc(context, size);
	if (ptr == NULL) {
		return NULL;
	}

	talloc_set_name_const(ptr, name);

	return ptr;
}

/*
  return the name of a talloc ptr, or "UNNAMED"
*/
const char *talloc_get_name(const void *ptr)
{
	struct talloc_chunk *tc = talloc_chunk_from_ptr(ptr);
	if (tc->name) {
		return tc->name;
	}
	return "UNNAMED";
}

/*
  this is for compatibility with older versions of talloc
*/
void *talloc_init(const char *fmt, ...) _PRINTF_ATTRIBUTE(1,2)
{
	va_list ap;
	void *ptr;

	ptr = _talloc(NULL, 0);
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
	struct talloc_chunk *tc, *tc2, *next;

	if (ptr == NULL) {
		return -1;
	}

	tc = talloc_chunk_from_ptr(ptr);

	if (tc->ref_count > 1) {
		tc->ref_count--;
		return -1;
	}

	/* while processing the free, increase the reference count
	   so we don't recurse into this function */
	tc->ref_count++;
	if (tc->destructor) {
		if (tc->destructor(ptr) == -1) {
			tc->ref_count--;
			return -1;
		}
	}

	for (tc2=tc->child;tc2;tc2=next) {
		next = tc2->next;
		talloc_free(tc2 + 1);
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

	if (tc->child) {
		tc->child->parent = tc->parent;
	}

	tc->magic = TALLOC_MAGIC_FREE;

	free(tc);
	return 0;
}



/*
  A talloc version of realloc. The context argument is only used if
  ptr is NULL
*/
void *_talloc_realloc(const void *context, void *ptr, size_t size, const char *name)
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
		return talloc_named_const(context, size, name);
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
	talloc_set_name_const(tc+1, name);

	return (void *)(tc+1);
}

/* 
   move a lump of memory from one talloc context to another return the
   ptr on success, or NUL if it could not be transferred
*/
void *talloc_steal(const void *new_ctx, const void *ptr)
{
	struct talloc_chunk *tc, *new_tc;

	if (!ptr) {
		return NULL;
	}

	tc = talloc_chunk_from_ptr(ptr);
	new_tc = talloc_chunk_from_ptr(new_ctx);

	if (tc == new_tc) {
		discard_const(ptr);
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

	return discard_const(ptr);
}

/*
  return the total size of a talloc pool (subtree)
*/
static off_t talloc_total_size(const void *ptr)
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
  return the total number of blocks in a talloc pool (subtree)
*/
static off_t talloc_total_blocks(const void *ptr)
{
	off_t total = 0;
	struct talloc_chunk *c, *tc = talloc_chunk_from_ptr(ptr);

	total++;
	for (c=tc->child;c;c=c->next) {
		total += talloc_total_blocks(c+1);
	}
	return total;
}

/*
  report on memory usage by all children of a pointer, giving a full tree view
*/
static void talloc_report_depth(const void *ptr, FILE *f, int depth)
{
	struct talloc_chunk *c, *tc = talloc_chunk_from_ptr(ptr);

	for (c=tc->child;c;c=c->next) {
		const char *name = talloc_get_name(c+1);
		if (strcmp(name, ".reference") == 0) {
			void **handle = (void *)(c+1);
			const char *name2 = talloc_get_name(*handle);
			fprintf(f, "%*sreference to: %s\n", depth*4, "", name2);
		} else {
			fprintf(f, "%*s%-30s contains %6lu bytes in %3lu blocks (ref %d)\n", 
				depth*4, "",
				name,
				(unsigned long)talloc_total_size(c+1),
				(unsigned long)talloc_total_blocks(c+1),
				c->ref_count);
			talloc_report_depth(c+1, f, depth+1);
		}
	}

}

/*
  report on memory usage by all children of a pointer, giving a full tree view
*/
void talloc_report_full(const void *ptr, FILE *f)
{
	if (ptr == NULL) {
		ptr = null_context;
	}
	if (ptr == NULL) return;

	fprintf(f,"full talloc report on '%s' (total %lu bytes in %lu blocks)\n", 
		talloc_get_name(ptr), 
		(unsigned long)talloc_total_size(ptr),
		(unsigned long)talloc_total_blocks(ptr));

	talloc_report_depth(ptr, f, 1);
}

/*
  report on memory usage by all children of a pointer
*/
void talloc_report(const void *ptr, FILE *f)
{
	struct talloc_chunk *c, *tc;

	if (ptr == NULL) {
		ptr = null_context;
	}
	if (ptr == NULL) return;
       
	fprintf(f,"talloc report on '%s' (total %lu bytes in %lu blocks)\n", 
		talloc_get_name(ptr), 
		(unsigned long)talloc_total_size(ptr),
		(unsigned long)talloc_total_blocks(ptr));

	tc = talloc_chunk_from_ptr(ptr);

	for (c=tc->child;c;c=c->next) {
		fprintf(f, "\t%-30s contains %6lu bytes in %3lu blocks\n", 
			talloc_get_name(c+1),
			(unsigned long)talloc_total_size(c+1),
			(unsigned long)talloc_total_blocks(c+1));
	}

}

/*
  report on any memory hanging off the null context
*/
static void talloc_report_null(void)
{
	if (talloc_total_size(null_context) == 0) {
		return;
	}
	talloc_report(null_context, stderr);
}

/*
  report on any memory hanging off the null context
*/
static void talloc_report_null_full(void)
{
	if (talloc_total_size(null_context) == 0) {
		return;
	}
	talloc_report_full(null_context, stderr);
}

/*
  enable leak reporting on exit
*/
void talloc_enable_leak_report(void)
{
	null_context = talloc_named_const(NULL, 0, "null_context");
	atexit(talloc_report_null);
}

/*
  enable full leak reporting on exit
*/
void talloc_enable_leak_report_full(void)
{
	null_context = talloc_named_const(NULL, 0, "null_context");
	atexit(talloc_report_null_full);
}

/* 
   talloc and zero memory. 
*/
void *talloc_zero(const void *ctx, size_t size)
{
	void *p = talloc(ctx, size);

	if (p) {
		memset(p, '\0', size);
	}

	return p;
}


/*
  memdup with a talloc. 
*/
void *_talloc_memdup(const void *t, const void *p, size_t size, const char *name)
{
	void *newp = talloc_named_const(t, size, name);

	if (newp) {
		memcpy(newp, p, size);
	}

	return newp;
}

/*
  strdup with a talloc 
*/
char *talloc_strdup(const void *t, const char *p)
{
	char *ret;
	if (!p) {
		return NULL;
	}
	ret = talloc_memdup(t, p, strlen(p) + 1);
	if (ret) {
		talloc_set_name_const(ret, ret);
	}
	return ret;
}

/*
  strndup with a talloc 
*/
char *talloc_strndup(const void *t, const char *p, size_t n)
{
	size_t len = strnlen(p, n);
	char *ret;

	ret = talloc(t, len + 1);
	if (!ret) { return NULL; }
	memcpy(ret, p, len);
	ret[len] = 0;
	return ret;
}

char *talloc_vasprintf(const void *t, const char *fmt, va_list ap) _PRINTF_ATTRIBUTE(2,0)
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
		talloc_set_name_const(ret, ret);
	}

	return ret;
}


/*
  Perform string formatting, and return a pointer to newly allocated
  memory holding the result, inside a memory pool.
 */
char *talloc_asprintf(const void *t, const char *fmt, ...) _PRINTF_ATTRIBUTE(2,3)
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

static char *talloc_vasprintf_append(char *s,
				     const char *fmt, va_list ap) PRINTF_ATTRIBUTE(2,0);

static char *talloc_vasprintf_append(char *s,
				     const char *fmt, va_list ap)
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

	s = talloc_realloc(NULL, s, s_len + len+1);
	if (!s) return NULL;

	VA_COPY(ap2, ap);

	vsnprintf(s+s_len, len+1, fmt, ap2);
	talloc_set_name_const(s, s);

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
void *talloc_array(const void *ctx, size_t el_size, uint_t count, const char *name)
{
	if (count == 0 ||
	    count >= MAX_TALLOC_SIZE/el_size) {
		return NULL;
	}
	return talloc_named_const(ctx, el_size * count, name);
}


/*
  realloc an array, checking for integer overflow in the array size
*/
void *talloc_realloc_array(const void *ctx, void *ptr, size_t el_size, uint_t count, const char *name)
{
	if (count == 0 ||
	    count >= MAX_TALLOC_SIZE/el_size) {
		return NULL;
	}
	ptr = talloc_realloc(ctx, ptr, el_size * count);
	if (ptr) {
		talloc_set_name_const(ptr, name);
	}
	return ptr;
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
	return talloc_realloc(context, ptr, size);
}
