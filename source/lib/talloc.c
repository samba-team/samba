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

   talloc does not zero the memory. 

   @sa talloc.h
*/

/**
 * If you want testing for memory corruption use valgrind
 **/

#include "includes.h"

#define MAX_TALLOC_SIZE 0x10000000
#define TALLOC_MAGIC 0x06052004
#define TALLOC_MAGIC_FREE 0x3421abcd

struct talloc_chunk {
	struct talloc_chunk *next, *prev;
	TALLOC_CTX *context;
	size_t size;
	void *ptr;
	uint_t magic;
};


struct talloc_ctx {
	struct talloc_chunk *list;
	off_t total_alloc_size;

	/** The name recorded for this pool, if any.  Should describe
	 * the purpose for which it was allocated.  The string is
	 * allocated within the pool. **/
	char *name;

	/** Pointer to the next allocate talloc pool, so that we can
	 * summarize all talloc memory usage. **/
	struct talloc_ctx *next, *prev;
};


/**
 * Start of linked list of all talloc pools.
 *
 * @todo We should turn the global list off when using Insure++,
 * otherwise all the memory will be seen as still reachable.
 **/
static TALLOC_CTX *list_head;

/**
 * Add to the global list
 **/
static void talloc_enroll(TALLOC_CTX *t)
{
#if 0
	/* disabled enrole/disenrole until we have __thread support */
	MUTEX_LOCK_BY_ID(MUTEX_TALLOC);
	DLIST_ADD(list_head, t);
	MUTEX_UNLOCK_BY_ID(MUTEX_TALLOC);
#endif
}


static void talloc_disenroll(TALLOC_CTX *t)
{
#if 0
	/* disabled enrole/disenrole until we have __thread support */
	MUTEX_LOCK_BY_ID(MUTEX_TALLOC);
	DLIST_REMOVE(list_head, t);
	MUTEX_UNLOCK_BY_ID(MUTEX_TALLOC);
#endif
}


/** Create a new talloc context. **/
static TALLOC_CTX *talloc_init_internal(void)
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
 **/

 TALLOC_CTX *talloc_init(char const *fmt, ...) 
{
	TALLOC_CTX *t;
	va_list ap;

	t = talloc_init_internal();
	if (t && fmt) {
		/*
		 * t->name must not be talloced.
		 * as destroying the pool would destroy it. JRA.
		 */
		t->name = NULL;
		va_start(ap, fmt);
		vasprintf(&t->name, fmt, ap);
		va_end(ap);
		if (!t->name) {
			talloc_destroy(t);
			t = NULL;
		}
	}
	
	return t;
}


/** Allocate a bit of memory from the specified pool **/
void *talloc(TALLOC_CTX *t, size_t size)
{
	struct talloc_chunk *tc;

	if (!t || size == 0) {
		return NULL;
	}

	tc = malloc(sizeof(*tc)+size);
	if (!tc) {
		return NULL;
	}

	tc->context = t;
	tc->size = size;
	tc->magic = TALLOC_MAGIC;

	DLIST_ADD(t->list, tc);

	t->total_alloc_size += size;

	return (void *)(tc+1);
}

/** A talloc version of realloc */
void *talloc_realloc(TALLOC_CTX *t, void *ptr, size_t size)
{
	struct talloc_chunk *tc;
	void *new_ptr;

	/* size zero is equivalent to free() */
	if (!t) {
		return NULL;
	}

	if (size == 0) {
		talloc_free(t, ptr);
		return NULL;
	}

	/* realloc(NULL) is equavalent to malloc() */
	if (ptr == NULL) {
		return talloc(t, size);
	}

	tc = ((struct talloc_chunk *)ptr)-1;

	if (tc->context != t) {
		DEBUG(0,("Bad talloc context passed to talloc_realloc\n"));
		return NULL;
	}

	if (tc->magic != TALLOC_MAGIC) {
		DEBUG(0,("Bad talloc magic 0x%08x in talloc_realloc\n", tc->magic));
		return NULL;
	}

	/* by resetting magic we catch users of the old memory */
	tc->magic = TALLOC_MAGIC_FREE;

	new_ptr = realloc(tc, size + sizeof(*tc));
	if (!new_ptr) {
		tc->magic = TALLOC_MAGIC;
		return NULL;
	}

	if (tc == t->list) {
		t->list = new_ptr;
	}
	tc = new_ptr;
	tc->magic = TALLOC_MAGIC;

	if (tc->prev) {
		tc->prev->next = tc;
	}
	if (tc->next) {
		tc->next->prev = tc;
	}

	t->total_alloc_size += (size - tc->size);
	tc->size = size;

	return (void *)(tc+1);
}

/* 
   free a lump from a pool. Use sparingly please.
*/
void talloc_free(TALLOC_CTX *ctx, void *ptr)
{
	struct talloc_chunk *tc;

	if (!ptr || !ctx->list) return;

	tc = ((struct talloc_chunk *)ptr)-1;

	if (tc->context != ctx) {
		DEBUG(0,("Bad talloc context passed to talloc_free\n"));
	}

	if (tc->magic != TALLOC_MAGIC) {
		DEBUG(0,("Bad talloc magic 0x%08x in talloc_free\n", tc->magic));
	}

	DLIST_REMOVE(ctx->list, tc);

	ctx->total_alloc_size -= tc->size;
	tc->magic = TALLOC_MAGIC_FREE;

	free(tc);
}


/* 
   move a lump of memory from one talloc context to another
   return the ptr on success, or NULL if it could not be found
   in the old context or could not be transferred
*/
void *talloc_steal(TALLOC_CTX *old_ctx, TALLOC_CTX *new_ctx, void *ptr)
{
	struct talloc_chunk *tc;

	if (!ptr) {
		return NULL;
	}

	tc = ((struct talloc_chunk *)ptr)-1;

	if (tc->context != old_ctx) {
		DEBUG(0,("Bad talloc context passed to talloc_steal\n"));
		return NULL;
	}

	if (tc->magic != TALLOC_MAGIC) {
		DEBUG(0,("Bad talloc magic 0x%08x in talloc_steal\n", tc->magic));
		return NULL;
	}

	DLIST_REMOVE(old_ctx->list, tc);
	DLIST_ADD(new_ctx->list, tc);

	tc->context = new_ctx;

	old_ctx->total_alloc_size -= tc->size;
	new_ctx->total_alloc_size += tc->size;
	
	return ptr;
}



/** Destroy all the memory allocated inside @p t, but not @p t
 * itself. */
void talloc_destroy_pool(TALLOC_CTX *t)
{
	if (!t) {
		return;
	}

	while (t->list) {
		struct talloc_chunk *tc = t->list;
		if (tc->magic != TALLOC_MAGIC) {
			DEBUG(0,("Bad magic 0x%08x in talloc_destroy_pool\n", 
				 tc->magic));
			return;
		}
		DLIST_REMOVE(t->list, tc);
		tc->magic = TALLOC_MAGIC_FREE;
		free(tc);
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
	SAFE_FREE(t->name);
	SAFE_FREE(t);
}

/** Return the current total size of the pool. */
size_t talloc_pool_size(TALLOC_CTX *t)
{
	return t->total_alloc_size;
}

const char *talloc_pool_name(TALLOC_CTX const *t)
{
	if (t) return t->name;

	return NULL;
}


/** talloc and zero memory. */
void *talloc_zero(TALLOC_CTX *t, size_t size)
{
	void *p = talloc(t, size);

	if (p) {
		memset(p, '\0', size);
	}

	return p;
}


/** memdup with a talloc. */
void *talloc_memdup(TALLOC_CTX *t, const void *p, size_t size)
{
	void *newp = talloc(t,size);

	if (newp) {
		memcpy(newp, p, size);
	}

	return newp;
}

/** strdup with a talloc */
char *talloc_strdup(TALLOC_CTX *t, const char *p)
{
	return talloc_memdup(t, p, strlen(p) + 1);
}

/** strndup with a talloc */
char *talloc_strndup(TALLOC_CTX *t, const char *p, size_t n)
{
	size_t len = strnlen(p, n);
	char *ret;

	ret = talloc(t, len + 1);
	if (!ret) { return NULL; }
	memcpy(ret, p, len);
	ret[len] = 0;
	return ret;
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
	
	VA_COPY(ap2, ap);

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
			    (uint_t) getpid());
	s = talloc_asprintf_append(rt, s, "%-40s %8s %8s\n",
				   "name", "chunks", "bytes");
	s = talloc_asprintf_append(rt, s, "%-40s %8s %8s\n",
				   "----------------------------------------",
				   "--------",
				   "--------");	
	MUTEX_LOCK_BY_ID(MUTEX_TALLOC);
	
	for (it = list_head; it; it = it->next) {
		size_t bytes;
		int n_chunks;
		fstring what;
		
		n_pools++;
		
		talloc_get_allocation(it, &bytes, &n_chunks);

		if (it->name)
			fstrcpy(what, it->name);
		else
			slprintf(what, sizeof(what), "@%p", it);
		
		s = talloc_asprintf_append(rt, s, "%-40s %8u %8u\n",
					   what,
					   (uint_t) n_chunks,
					   (uint_t) bytes);
		total_bytes += bytes;
		total_chunks += n_chunks;
	}

	MUTEX_UNLOCK_BY_ID(MUTEX_TALLOC);

	s = talloc_asprintf_append(rt, s, "%-40s %8s %8s\n",
				   "----------------------------------------",
				   "--------",
				   "--------");	

	s = talloc_asprintf_append(rt, s, "%-40s %8u %8u\n",
				   "TOTAL",
				   (uint_t) total_chunks, (uint_t) total_bytes);

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
	struct talloc_chunk *tc;

	if (t) {
		*total_bytes = 0;
		*n_chunks = 0;

		for (tc = t->list; tc; tc = tc->next) {
			n_chunks[0]++;
			*total_bytes += tc->size;
		}
	}
}

/*
  realloc an array, checking for integer overflow in the array size
*/
void *talloc_realloc_array(TALLOC_CTX *ctx, void *ptr, size_t el_size, uint_t count)
{
	if (count == 0 ||
	    count >= MAX_TALLOC_SIZE/el_size) {
		return NULL;
	}
	return talloc_realloc(ctx, ptr, el_size * count);
}


/*
  we really should get rid of this
*/
void *talloc_strdup_w(TALLOC_CTX *mem_ctx, void *s)
{
	size_t len = strlen_w(s);
	return talloc_memdup(mem_ctx, s, (len+1)*2);
}

/** @} */
