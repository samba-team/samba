/* 
   Samba Unix SMB/CIFS implementation.
   Samba temporary memory allocation functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001, 2002 by Martin Pool <mbp@samba.org>
   
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

   @sa talloc.h
*/

/**
 * @todo We could allocate both the talloc_chunk structure, and the
 * memory it contains all in one allocation, which might be a bit
 * faster and perhaps use less memory overhead.
 *
 * That smells like a premature optimization, though.  -- mbp
 **/

/**
 * If you want testing for memory corruption, link with dmalloc or use
 * Insure++.  It doesn't seem useful to duplicate them here.
 **/

#include "includes.h"

struct talloc_chunk {
	struct talloc_chunk *next;
	size_t size;
	void *ptr;
};


struct talloc_ctx {
	struct talloc_chunk *list;
	size_t total_alloc_size;

	/** The name recorded for this pool, if any.  Should describe
	 * the purpose for which it was allocated.  The string is
	 * allocated within the pool. **/
	char *name;

	/** Pointer to the next allocate talloc pool, so that we can
	 * summarize all talloc memory usage. **/
	struct talloc_ctx *next_ctx;
};


/**
 * Start of linked list of all talloc pools.
 *
 * @todo We should turn the global list off when using Insure++,
 * otherwise all the memory will be seen as still reachable.
 **/
TALLOC_CTX *list_head = NULL;


/**
 * Add to the global list
 **/
static void talloc_enroll(TALLOC_CTX *t)
{
	t->next_ctx = list_head;
	list_head = t;
}


static void talloc_disenroll(TALLOC_CTX *t)
{
	TALLOC_CTX **ttmp;

	/* Use a double-* so that no special case is required for the
	 * list head. */
	for (ttmp = &list_head; *ttmp; ttmp = &((*ttmp)->next_ctx))
		if (*ttmp == t) {
			/* ttmp is the link that points to t, either
			 * list_head or the next_ctx link in its
			 * predecessor */
			*ttmp = t->next_ctx;
			t->next_ctx = NULL;	/* clobber */
			return;
		}
	abort();		/* oops, this talloc was already
				 * clobbered or something else went
				 * wrong. */
}


/** Create a new talloc context. **/
TALLOC_CTX *talloc_init(void)
{
	TALLOC_CTX *t;

	t = (TALLOC_CTX *)malloc(sizeof(TALLOC_CTX));
	if (t) {
		t->list = NULL;
		t->total_alloc_size = 0;
		t->name = NULL;
		talloc_enroll(t);
	}

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
	if (t && fmt) {
		va_start(ap, fmt);
		t->name = talloc_vasprintf(t, fmt, ap);
		va_end(ap);
	}
	
	return t;
}


/** Allocate a bit of memory from the specified pool **/
void *talloc(TALLOC_CTX *t, size_t size)
{
	void *p;
	struct talloc_chunk *tc;

	if (!t || size == 0) return NULL;

	p = malloc(size);
	if (p) {
		tc = malloc(sizeof(*tc));
		if (tc) {
			tc->ptr = p;
			tc->size = size;
			tc->next = t->list;
			t->list = tc;
			t->total_alloc_size += size;
		}
		else {
			SAFE_FREE(p);
		}
	}
	return p;
}

/** A talloc version of realloc */
void *talloc_realloc(TALLOC_CTX *t, void *ptr, size_t size)
{
	struct talloc_chunk *tc;
	void *new_ptr;

	/* size zero is equivalent to free() */
	if (!t || size == 0)
		return NULL;

	/* realloc(NULL) is equavalent to malloc() */
	if (ptr == NULL)
		return talloc(t, size);

	for (tc=t->list; tc; tc=tc->next) {
		if (tc->ptr == ptr) {
			new_ptr = Realloc(ptr, size);
			if (new_ptr) {
				t->total_alloc_size += (size - tc->size);
				tc->size = size;
				tc->ptr = new_ptr;
			}
			return new_ptr;
		}
	}
	return NULL;
}

/** Destroy all the memory allocated inside @p t, but not @p t
 * itself. */
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

/** Destroy a whole pool including the context */
void talloc_destroy(TALLOC_CTX *t)
{
	if (!t)
		return;

	talloc_destroy_pool(t);
	talloc_disenroll(t);
	memset(t, 0, sizeof(TALLOC_CTX));
	SAFE_FREE(t);
}

/** Return the current total size of the pool. */
size_t talloc_pool_size(TALLOC_CTX *t)
{
	if (t)
		return t->total_alloc_size;
	else
		return 0;
}

const char * talloc_pool_name(TALLOC_CTX const *t)
{
	if (t)
		return t->name;
	else
		return NULL;
}


/** talloc and zero memory. */
void *talloc_zero(TALLOC_CTX *t, size_t size)
{
	void *p = talloc(t, size);

	if (p)
		memset(p, '\0', size);

	return p;
}

/** memdup with a talloc. */
void *talloc_memdup(TALLOC_CTX *t, const void *p, size_t size)
{
	void *newp = talloc(t,size);

	if (newp)
		memcpy(newp, p, size);

	return newp;
}

/** strdup with a talloc */
char *talloc_strdup(TALLOC_CTX *t, const char *p)
{
	if (p)
		return talloc_memdup(t, p, strlen(p) + 1);
	else
		return NULL;
}

/**
 * Perform string formatting, and return a pointer to newly allocated
 * memory holding the result, inside a memory pool.
 **/
 char *talloc_asprintf(TALLOC_CTX *t, const char *fmt, ...)
{
	va_list ap;
	char *ret;

	va_start(ap, fmt);
	ret = talloc_vasprintf(t, fmt, ap);
	va_end(ap);
	return ret;
}


 char *talloc_vasprintf(TALLOC_CTX *t, const char *fmt, va_list ap)
{	
	int len;
	char *ret;
	va_list ap2;
	
	VA_COPY(ap2, ap);  /* for systems were va_list is a struct */
	len = vsnprintf(NULL, 0, fmt, ap2);

	ret = talloc(t, len+1);
	if (ret) {
		VA_COPY(ap2, ap);
		vsnprintf(ret, len+1, fmt, ap2);
	}

	return ret;
}


/**
 * Realloc @p s to append the formatted result of @p fmt and return @p
 * s, which may have moved.  Good for gradually accumulating output
 * into a string buffer.
 **/
 char *talloc_asprintf_append(TALLOC_CTX *t, char *s,
			      const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	s = talloc_vasprintf_append(t, s, fmt, ap);
	va_end(ap);
	return s;
}



/**
 * Realloc @p s to append the formatted result of @p fmt and @p ap,
 * and return @p s, which may have moved.  Good for gradually
 * accumulating output into a string buffer.
 **/
 char *talloc_vasprintf_append(TALLOC_CTX *t, char *s,
			       const char *fmt, va_list ap)
{	
	int len, s_len;
	va_list ap2;

	VA_COPY(ap2, ap);
	s_len = strlen(s);
	len = vsnprintf(NULL, 0, fmt, ap2);

	s = talloc_realloc(t, s, s_len + len+1);
	if (!s) return NULL;

	VA_COPY(ap2, ap);
	vsnprintf(s+s_len, len+1, fmt, ap2);

	return s;
}


/**
 * Return a human-readable description of all talloc memory usage.
 * The result is allocated from @p t.
 **/
char *talloc_describe_all(TALLOC_CTX *rt)
{
	int n_pools = 0, total_chunks = 0;
	size_t total_bytes = 0;
	TALLOC_CTX *it;
	char *s;

	if (!rt) return NULL;

	s = talloc_asprintf(rt, "global talloc allocations in pid: %u\n",
			    (unsigned) sys_getpid());
	s = talloc_asprintf_append(rt, s, "%-40s %8s %8s\n",
				   "name", "chunks", "bytes");
	s = talloc_asprintf_append(rt, s, "%-40s %8s %8s\n",
				   "----------------------------------------",
				   "--------",
				   "--------");	
	
	for (it = list_head; it; it = it->next_ctx) {
		size_t bytes;
		int n_chunks;
		fstring what;
		
		n_pools++;
		
		talloc_get_allocation(it, &bytes, &n_chunks);

		if (it->name)
			fstrcpy(what, it->name);
		else
			slprintf(what, sizeof what, "@%p", it);
		
		s = talloc_asprintf_append(rt, s, "%-40s %8u %8u\n",
					   what,
					   (unsigned) n_chunks,
					   (unsigned) bytes);
		total_bytes += bytes;
		total_chunks += n_chunks;
	}

	s = talloc_asprintf_append(rt, s, "%-40s %8s %8s\n",
				   "----------------------------------------",
				   "--------",
				   "--------");	

	s = talloc_asprintf_append(rt, s, "%-40s %8u %8u\n",
				   "TOTAL",
				   (unsigned) total_chunks, (unsigned) total_bytes);

	return s;
}



/**
 * Return an estimated memory usage for the specified pool.  This does
 * not include memory used by the underlying malloc implementation.
 **/
void talloc_get_allocation(TALLOC_CTX *t,
			   size_t *total_bytes,
			   int *n_chunks)
{
	struct talloc_chunk *chunk;

	if (t) {
		*total_bytes = 0;
		*n_chunks = 0;

		for (chunk = t->list; chunk; chunk = chunk->next) {
			n_chunks[0]++;
			*total_bytes += chunk->size;
		}
	}
}


/** @} */
