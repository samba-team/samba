/*
   Unix SMB/CIFS implementation.
   Implement a stack of talloc contexts
   Copyright (C) Volker Lendecke 2007
   Copyright (C) Jeremy Allison 2009 - made thread safe.

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
 * Implement a stack of talloc frames.
 *
 * When a new talloc stackframe is allocated with talloc_stackframe(), then
 * the TALLOC_CTX returned with talloc_tos() is reset to that new
 * frame. Whenever that stack frame is TALLOC_FREE()'ed, then the reverse
 * happens: The previous talloc_tos() is restored.
 *
 * This API is designed to be robust in the sense that if someone forgets to
 * TALLOC_FREE() a stackframe, then the next outer one correctly cleans up and
 * resets the talloc_tos().
 *
 * This robustness feature means that we can't rely on a linked list with
 * talloc destructors because in a hierarchy of talloc destructors the parent
 * destructor is called before its children destructors. The child destructor
 * called after the parent would set the talloc_tos() to the wrong value.
 */

#include "replace.h"
#include <pthread.h>
#include <talloc.h>
#include "lib/util/talloc_stack.h"
#include "lib/util/debug.h"
#include "lib/util/fault.h"

struct talloc_stackframe {
	int talloc_stacksize;
	int talloc_stack_arraysize;
	TALLOC_CTX **talloc_stack;
};

/* Variable to ensure TLS value is only initialized once. */
#ifdef HAVE_PTHREAD
static pthread_once_t ts_initialized = PTHREAD_ONCE_INIT;
static pthread_key_t ts_key;
#else /* ! HAVE_PTHREAD */
static struct talloc_stackframe *global_ts;
#endif

static void talloc_stackframe_destructor(void *ptr)
{
	struct talloc_stackframe *ts =
		(struct talloc_stackframe *)ptr;
	int i;

	for (i = 0; i < ts->talloc_stacksize; i++) {
		int idx = ts->talloc_stacksize - (i + 1);
		DEBUG(0, ("Dangling frame[%d] %s\n",
			  idx, talloc_get_name(ts->talloc_stack[idx])));
	}
	if (ts->talloc_stacksize > 0) {
#if 0 /* TODO ifdef DEVELOPER */
		smb_panic("Dangling frames.");
#endif
	}

	free(ts);
}

#ifdef HAVE_PTHREAD
static void talloc_stackframe_init_once(void)
{
	int ret = pthread_key_create(&ts_key, talloc_stackframe_destructor);
	SMB_ASSERT(ret == 0);
}

static void talloc_stackframe_init(void)
{
	pthread_once(&ts_initialized, talloc_stackframe_init_once);
}
#else /* ! HAVE_PTHREAD */
static void talloc_stackframe_atexit(void)
{
	talloc_stackframe_destructor(global_ts);
}

static void talloc_stackframe_init(void)
{
	static bool done;

	if (!done) {
		atexit(talloc_stackframe_atexit);
		done = true;
	}
}
#endif

static struct talloc_stackframe *talloc_stackframe_get_existing(void)
{
	struct talloc_stackframe *ts = NULL;

	talloc_stackframe_init();

#ifdef HAVE_PTHREAD
	ts = (struct talloc_stackframe *)pthread_getspecific(ts_key);
#else /* ! HAVE_PTHREAD */
	ts = global_ts;
#endif

	return ts;
}

static struct talloc_stackframe *talloc_stackframe_get(void)
{
	struct talloc_stackframe *ts = talloc_stackframe_get_existing();
#ifdef HAVE_PTHREAD
	int ret;
#endif /* ! HAVE_PTHREAD */

	if (ts != NULL) {
		return ts;
	}

#if defined(PARANOID_MALLOC_CHECKER)
#ifdef calloc
#undef calloc
#endif
#endif
	ts = (struct talloc_stackframe *)calloc(
		1, sizeof(struct talloc_stackframe));
#if defined(PARANOID_MALLOC_CHECKER)
#define calloc(n, s) __ERROR_DONT_USE_MALLOC_DIRECTLY
#endif
	if (!ts) {
		smb_panic("talloc_stackframe_init malloc failed");
	}

#ifdef HAVE_PTHREAD
	ret = pthread_setspecific(ts_key, ts);
	SMB_ASSERT(ret == 0);
#else /* ! HAVE_PTHREAD */
	global_ts = ts;
#endif

	return ts;
}

static int talloc_pop(TALLOC_CTX *frame)
{
	struct talloc_stackframe *ts = talloc_stackframe_get_existing();
	size_t blocks;
	int i;

	/* Catch lazy frame-freeing. */
	if (ts->talloc_stack[ts->talloc_stacksize-1] != frame) {
		DEBUG(0, ("Freed frame %s, expected %s.\n",
			  talloc_get_name(frame),
			  talloc_get_name(ts->talloc_stack
					  [ts->talloc_stacksize-1])));
#ifdef DEVELOPER
		smb_panic("Frame not freed in order.");
#endif
	}

	for (i=0; i<10; i++) {

		/*
		 * We have to free our children first, calling all
		 * destructors. If a destructor hanging deeply off
		 * "frame" uses talloc_tos() itself while freeing the
		 * toplevel frame, we panic because that nested
		 * talloc_tos() in the destructor does not find a
		 * stackframe anymore.
		 *
		 * Do it in a loop up to 10 times as the destructors
		 * might use more of talloc_tos().
		 */

		talloc_free_children(frame);

		blocks = talloc_total_blocks(frame);
		if (blocks == 1) {
			break;
		}
	}

	if (blocks != 1) {
		DBG_WARNING("Left %zu blocks after %i "
			    "talloc_free_children(frame) calls\n",
			    blocks, i);
	}

	for (i=ts->talloc_stacksize-1; i>0; i--) {
		if (frame == ts->talloc_stack[i]) {
			break;
		}
		TALLOC_FREE(ts->talloc_stack[i]);
	}

	ts->talloc_stack[i] = NULL;
	ts->talloc_stacksize = i;
	return 0;
}

/*
 * Create a new talloc stack frame.
 *
 * When free'd, it frees all stack frames that were created after this one and
 * not explicitly freed.
 */

static TALLOC_CTX *talloc_stackframe_internal(const char *location,
					      size_t poolsize)
{
	TALLOC_CTX **tmp, *top;
	struct talloc_stackframe *ts = talloc_stackframe_get();

	if (ts->talloc_stack_arraysize < ts->talloc_stacksize + 1) {
		tmp = talloc_realloc(NULL, ts->talloc_stack, TALLOC_CTX *,
					   ts->talloc_stacksize + 1);
		if (tmp == NULL) {
			goto fail;
		}
		ts->talloc_stack = tmp;
		ts->talloc_stack_arraysize = ts->talloc_stacksize + 1;
        }

	if (poolsize) {
		top = talloc_pool(ts->talloc_stack, poolsize);
	} else {
		TALLOC_CTX *parent;
		/* We chain parentage, so if one is a pool we draw from it. */
		if (ts->talloc_stacksize == 0) {
			parent = ts->talloc_stack;
		} else {
			parent = ts->talloc_stack[ts->talloc_stacksize-1];
		}
		top = talloc_new(parent);
	}

	if (top == NULL) {
		goto fail;
	}
	talloc_set_name_const(top, location);
	talloc_set_destructor(top, talloc_pop);

	ts->talloc_stack[ts->talloc_stacksize++] = top;
	return top;

 fail:
	smb_panic("talloc_stackframe failed");
	return NULL;
}

TALLOC_CTX *_talloc_stackframe(const char *location)
{
	return talloc_stackframe_internal(location, 0);
}

TALLOC_CTX *_talloc_stackframe_pool(const char *location, size_t poolsize)
{
	return talloc_stackframe_internal(location, poolsize);
}

/*
 * Get us the current top of the talloc stack.
 */

TALLOC_CTX *_talloc_tos(const char *location)
{
	struct talloc_stackframe *ts = talloc_stackframe_get_existing();

	if (ts == NULL || ts->talloc_stacksize == 0) {
		TALLOC_CTX *ret = _talloc_stackframe(location);
		DEBUG(0, ("no talloc stackframe at %s, leaking memory\n",
			  location));
#ifdef DEVELOPER
		smb_panic("No talloc stackframe");
#endif
		return ret;
	}

	return ts->talloc_stack[ts->talloc_stacksize-1];
}

/*
 * return true if a talloc stackframe exists
 * this can be used to prevent memory leaks for code that can
 * optionally use a talloc stackframe (eg. nt_errstr())
 */

bool talloc_stackframe_exists(void)
{
	struct talloc_stackframe *ts = talloc_stackframe_get_existing();

	if (ts == NULL || ts->talloc_stacksize == 0) {
		return false;
	}
	return true;
}
