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
 * If you want testing for memory corruption use valgrind
 **/

#include "includes.h"

#define MAX_TALLOC_SIZE 0x10000000

struct talloc_chunk {
	struct talloc_chunk *next;
	size_t size;
	void *ptr;
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
	if (!t) {
		return NULL;
	}

	if (size == 0) {
		talloc_free(t, ptr);
		return NULL;
	}

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

/** strdup_w with a talloc */
smb_ucs2_t *talloc_strdup_w(TALLOC_CTX *t, const smb_ucs2_t *p)
{
	if (p)
		return talloc_memdup(t, p, (strlen_w(p) + 1) * sizeof(smb_ucs2_t));
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
			    (unsigned) getpid());
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
					   (unsigned) n_chunks,
					   (unsigned) bytes);
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


/* 
   free a lump from a pool. Use sparingly please.
*/
void talloc_free(TALLOC_CTX *ctx, void *ptr)
{
	struct talloc_chunk *tc;

	if (!ptr || !ctx->list) return;

	/* as a special case, see if its the first element in the
	   list */
	if (ctx->list->ptr == ptr) {
		ctx->total_alloc_size -= ctx->list->size;
		ctx->list = ctx->list->next;
		free(ptr);
		return;
	}

	/* find it in the context */
	for (tc=ctx->list; tc->next; tc=tc->next) {
		if (tc->next->ptr == ptr) break;
	}

	if (tc->next) {
		ctx->total_alloc_size -= tc->next->size;
		tc->next = tc->next->next;
	} else {
		DEBUG(0,("Attempt to free non-allocated chunk in context '%s'\n", 
			 ctx->name));
	}
}


/* 
   move a lump of memory from one talloc context to another
   return the ptr on success, or NULL if it could not be found
   in the old context or could not be transferred
*/
const void *talloc_steal(TALLOC_CTX *old_ctx, TALLOC_CTX *new_ctx, const void *ptr)
{
	struct talloc_chunk *tc, *tc2;

	if (!ptr || !old_ctx->list) return NULL;

	/* as a special case, see if its the first element in the
	   list */
	if (old_ctx->list->ptr == ptr) {
		tc = old_ctx->list;
		old_ctx->list = old_ctx->list->next;
		tc->next = new_ctx->list;
		new_ctx->list = tc;
		old_ctx->total_alloc_size -= tc->size;
		new_ctx->total_alloc_size += tc->size;
		return ptr;
	}

	/* find it in the old context */
	for (tc=old_ctx->list; tc->next; tc=tc->next) {
		if (tc->next->ptr == ptr) break;
	}

	if (!tc->next) return NULL;

	/* move it to the new context */
	tc2 = tc->next;
	tc->next = tc->next->next;
	tc2->next = new_ctx->list;
	new_ctx->list = tc2;
	old_ctx->total_alloc_size -= tc2->size;
	new_ctx->total_alloc_size += tc2->size;
	
	return ptr;
}

/*
  realloc an array, checking for integer overflow in the array size
*/
void *talloc_realloc_array(TALLOC_CTX *ctx, void *ptr, size_t el_size, unsigned count)
{
	if (count == 0 ||
	    count >= MAX_TALLOC_SIZE/el_size) {
		return NULL;
	}
	return talloc_realloc(ctx, ptr, el_size * count);
}

/** @} */
