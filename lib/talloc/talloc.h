#ifndef _TALLOC_H_
#define _TALLOC_H_
/* 
   Unix SMB/CIFS implementation.
   Samba temporary memory allocation functions

   Copyright (C) Andrew Tridgell 2004-2005
   Copyright (C) Stefan Metzmacher 2006
   
     ** NOTE! The following LGPL license applies to the talloc
     ** library. This does NOT imply that all of Samba is released
     ** under the LGPL
   
   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library; if not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

/** \mainpage
 *
 * \section intro_sec Introduction
 *
 * Talloc is a hierarchical, reference counted memory pool system with
 * destructors. Quite a mouthful really, but not too bad once you get used to
 * it.
 *
 * Perhaps the biggest difference from other memory pool systems is that there
 * is no distinction between a "talloc context" and a "talloc pointer". Any
 * pointer returned from talloc() is itself a valid talloc context. This means
 * you can do this:
 *
 * \code
 * struct foo *X = talloc(mem_ctx, struct foo);
 * X->name = talloc_strdup(X, "foo");
 * \endcode
 *
 * and the pointer X->name would be a "child" of the talloc context "X" which
 * is itself a child of mem_ctx. So if you do talloc_free(mem_ctx) then it is
 * all destroyed, whereas if you do talloc_free(X) then just X and X->name are
 * destroyed, and if you do talloc_free(X->name) then just the name element of
 * X is destroyed.
 *
 * If you think about this, then what this effectively gives you is an n-ary
 * tree, where you can free any part of the tree with talloc_free().
 *
 * To start, you should probably first look at the definitions of
 * ::TALLOC_CTX, talloc_init(), talloc() and talloc_free().
 *
 * \section named_blocks Named blocks
 *
 * Every talloc chunk has a name that can be used as a dynamic type-checking
 * system. If for some reason like a callback function you had to cast a
 * "struct foo *" to a "void *" variable, later you can safely reassign the
 * "void *" pointer to a "struct foo *" by using the talloc_get_type() or
 * talloc_get_type_abort() macros.
 *
 * \code
 * struct foo *X = talloc_get_type_abort(ptr, struct foo);
 * \endcode
 *
 * This will abort if "ptr" does not contain a pointer that has been created
 * with talloc(mem_ctx, struct foo).
 *
 * \section multi_threading Multi-Threading
 *
 * talloc itself does not deal with threads. It is thread-safe (assuming the
 * underlying "malloc" is), as long as each thread uses different memory
 * contexts.
 *
 * If two threads uses the same context then they need to synchronize in order
 * to be safe. In particular:
 *
 *
 * - when using talloc_enable_leak_report(), giving directly NULL as a
 *   parent context implicitly refers to a hidden "null context" global
 *   variable, so this should not be used in a multi-threaded environment
 *   without proper synchronization
 * - the context returned by talloc_autofree_context() is also global so
 *   shouldn't be used by several threads simultaneously without
 *   synchronization.
 */

/** \defgroup talloc_basic Basic Talloc Routines
 *
 * This module contains the basic talloc routines that are used in everyday
 * programming.
 */

/**
 * \defgroup talloc_ref Talloc References
 *
 * This module contains the definitions around talloc references
 */

/**
 * \defgroup talloc_array Array routines
 *
 * Talloc contains some handy helpers for handling Arrays conveniently
 */

/**
 * \defgroup talloc_string String handling routines
 *
 * Talloc contains some handy string handling functions
 */

/**
 * \defgroup talloc_debug Debugging support routines
 *
 * To aid memory debugging, talloc contains routines to inspect the currently
 * allocated memory hierarchy.
 */

/**
 * \defgroup talloc_undoc Default group of undocumented stuff
 *
 * This should be empty...
 */

/*\{*/

/**
 * \typedef TALLOC_CTX
 * \brief Define a talloc parent type
 * \ingroup talloc_basic
 *
 * As talloc is a hierarchial memory allocator, every talloc chunk is a
 * potential parent to other talloc chunks. So defining a separate type for a
 * talloc chunk is not strictly necessary. TALLOC_CTX is defined nevertheless,
 * as it provides an indicator for function arguments. You will frequently
 * write code like
 *
 * \code
 * struct foo *foo_create(TALLOC_CTX *mem_ctx)
 * {
 *	struct foo *result;
 *	result = talloc(mem_ctx, struct foo);
 *	if (result == NULL) return NULL;
 *	... initialize foo ...
 *	return result;
 * }
 * \endcode
 *
 * In this type of allocating functions it is handy to have a general
 * TALLOC_CTX type to indicate which parent to put allocated structures on.
 */
typedef void TALLOC_CTX;

/*
  this uses a little trick to allow __LINE__ to be stringified
*/
#ifndef __location__
#define __TALLOC_STRING_LINE1__(s)    #s
#define __TALLOC_STRING_LINE2__(s)   __TALLOC_STRING_LINE1__(s)
#define __TALLOC_STRING_LINE3__  __TALLOC_STRING_LINE2__(__LINE__)
#define __location__ __FILE__ ":" __TALLOC_STRING_LINE3__
#endif

#ifndef TALLOC_DEPRECATED
#define TALLOC_DEPRECATED 0
#endif

#ifndef PRINTF_ATTRIBUTE
#if (__GNUC__ >= 3)
/** Use gcc attribute to check printf fns.  a1 is the 1-based index of
 * the parameter containing the format, and a2 the index of the first
 * argument. Note that some gcc 2.x versions don't handle this
 * properly **/
#define PRINTF_ATTRIBUTE(a1, a2) __attribute__ ((format (__printf__, a1, a2)))
#else
#define PRINTF_ATTRIBUTE(a1, a2)
#endif
#endif

/**
 * \def talloc_set_destructor
 * \brief Assign a function to be called when a chunk is freed
 * \param ptr The talloc chunk to add a destructor to
 * \param function The destructor function to be called
 * \ingroup talloc_basic
 *
 * The function talloc_set_destructor() sets the "destructor" for the pointer
 * "ptr". A destructor is a function that is called when the memory used by a
 * pointer is about to be released. The destructor receives the pointer as an
 * argument, and should return 0 for success and -1 for failure.
 *
 * The destructor can do anything it wants to, including freeing other pieces
 * of memory. A common use for destructors is to clean up operating system
 * resources (such as open file descriptors) contained in the structure the
 * destructor is placed on.
 *
 * You can only place one destructor on a pointer. If you need more than one
 * destructor then you can create a zero-length child of the pointer and place
 * an additional destructor on that.
 *
 * To remove a destructor call talloc_set_destructor() with NULL for the
 * destructor.
 *
 * If your destructor attempts to talloc_free() the pointer that it is the
 * destructor for then talloc_free() will return -1 and the free will be
 * ignored. This would be a pointless operation anyway, as the destructor is
 * only called when the memory is just about to go away.
 */

/**
 * \def talloc_steal(ctx, ptr)
 * \brief Change a talloc chunk's parent
 * \param ctx The new parent context
 * \param ptr The talloc chunk to move
 * \return ptr
 * \ingroup talloc_basic
 *
 * The talloc_steal() function changes the parent context of a talloc
 * pointer. It is typically used when the context that the pointer is
 * currently a child of is going to be freed and you wish to keep the
 * memory for a longer time.
 *
 * The talloc_steal() function returns the pointer that you pass it. It
 * does not have any failure modes.
 *
 * NOTE: It is possible to produce loops in the parent/child relationship
 * if you are not careful with talloc_steal(). No guarantees are provided
 * as to your sanity or the safety of your data if you do this.
 *
 * To make the changed hierarchy less error-prone, you might consider to use
 * talloc_move().
 *
 * talloc_steal (ctx, NULL) will return NULL with no sideeffects.
 */

/* try to make talloc_set_destructor() and talloc_steal() type safe,
   if we have a recent gcc */
#if (__GNUC__ >= 3)
#define _TALLOC_TYPEOF(ptr) __typeof__(ptr)
#define talloc_set_destructor(ptr, function)				      \
	do {								      \
		int (*_talloc_destructor_fn)(_TALLOC_TYPEOF(ptr)) = (function);	      \
		_talloc_set_destructor((ptr), (int (*)(void *))_talloc_destructor_fn); \
	} while(0)
/* this extremely strange macro is to avoid some braindamaged warning
   stupidity in gcc 4.1.x */
#define talloc_steal(ctx, ptr) ({ _TALLOC_TYPEOF(ptr) __talloc_steal_ret = (_TALLOC_TYPEOF(ptr))_talloc_steal((ctx),(ptr)); __talloc_steal_ret; })
#else
#define talloc_set_destructor(ptr, function) \
	_talloc_set_destructor((ptr), (int (*)(void *))(function))
#define _TALLOC_TYPEOF(ptr) void *
#define talloc_steal(ctx, ptr) (_TALLOC_TYPEOF(ptr))_talloc_steal((ctx),(ptr))
#endif

/**
 * \def talloc_reference(ctx, ptr)
 * \brief Create an additional talloc parent to a pointer
 * \param ctx The additional parent
 * \param ptr The pointer you want to create an additional parent for
 * \return ptr
 * \ingroup talloc_ref
 *
 * The talloc_reference() function makes "context" an additional parent of
 * "ptr".
 *
 * The return value of talloc_reference() is always the original pointer
 * "ptr", unless talloc ran out of memory in creating the reference in which
 * case it will return NULL (each additional reference consumes around 48
 * bytes of memory on intel x86 platforms).
 *
 * If "ptr" is NULL, then the function is a no-op, and simply returns NULL.
 *
 * After creating a reference you can free it in one of the following ways:
 *
 * - you can talloc_free() any parent of the original pointer. That
 *   will reduce the number of parents of this pointer by 1, and will
 *   cause this pointer to be freed if it runs out of parents.
 *
 * - you can talloc_free() the pointer itself. That will destroy the
 *   most recently established parent to the pointer and leave the
 *   pointer as a child of its current parent.
 *
 * For more control on which parent to remove, see talloc_unlink()
 */
#define talloc_reference(ctx, ptr) (_TALLOC_TYPEOF(ptr))_talloc_reference((ctx),(ptr))


/**
 * \def talloc_move(ctx, ptr)
 * \brief Change a talloc chunk's parent
 * \param ctx The new parent context
 * \param ptr Pointer to the talloc chunk to move
 * \return ptr
 * \ingroup talloc_basic
 *
 * talloc_move() has the same effect as talloc_steal(), and additionally sets
 * the source pointer to NULL. You would use it like this:
 *
 * \code
 * struct foo *X = talloc(tmp_ctx, struct foo);
 * struct foo *Y;
 * Y = talloc_move(new_ctx, &X);
 * \endcode
 */
#define talloc_move(ctx, ptr) (_TALLOC_TYPEOF(*(ptr)))_talloc_move((ctx),(void *)(ptr))

/* useful macros for creating type checked pointers */

/**
 * \def talloc(ctx, type)
 * \brief Main entry point to allocate structures
 * \param ctx The talloc context to hang the result off
 * \param type The type that we want to allocate
 * \return Pointer to a piece of memory, properly cast to "type *"
 * \ingroup talloc_basic
 *
 * The talloc() macro is the core of the talloc library. It takes a memory
 * context and a type, and returns a pointer to a new area of memory of the
 * given type.
 *
 * The returned pointer is itself a talloc context, so you can use it as the
 * context argument to more calls to talloc if you wish.
 *
 * The returned pointer is a "child" of the supplied context. This means that
 * if you talloc_free() the context then the new child disappears as
 * well. Alternatively you can free just the child.
 *
 * The context argument to talloc() can be NULL, in which case a new top
 * level context is created.
 */
#define talloc(ctx, type) (type *)talloc_named_const(ctx, sizeof(type), #type)

/**
 * \def talloc_size(ctx, size)
 * \brief Untyped allocation
 * \param ctx The talloc context to hang the result off
 * \param size Number of char's that you want to allocate
 * \return The allocated memory chunk
 * \ingroup talloc_basic
 *
 * The function talloc_size() should be used when you don't have a convenient
 * type to pass to talloc(). Unlike talloc(), it is not type safe (as it
 * returns a void *), so you are on your own for type checking.
 */
#define talloc_size(ctx, size) talloc_named_const(ctx, size, __location__)

/**
 * \def talloc_ptrtype(ctx, ptr)
 * \brief Allocate into a typed pointer
 * \param ctx The talloc context to hang the result off
 * \param ptr The pointer you want to assign the result to
 * \result The allocated memory chunk, properly cast
 * \ingroup talloc_basic
 *
 * The talloc_ptrtype() macro should be used when you have a pointer and
 * want to allocate memory to point at with this pointer. When compiling
 * with gcc >= 3 it is typesafe. Note this is a wrapper of talloc_size()
 * and talloc_get_name() will return the current location in the source file.
 * and not the type.
 */
#define talloc_ptrtype(ctx, ptr) (_TALLOC_TYPEOF(ptr))talloc_size(ctx, sizeof(*(ptr)))

/**
 * \def talloc_new(ctx)
 * \brief Allocate a new 0-sized talloc chunk
 * \param ctx The talloc parent context
 * \return A new talloc chunk
 * \ingroup talloc_basic
 *
 * This is a utility macro that creates a new memory context hanging off an
 * exiting context, automatically naming it "talloc_new: __location__" where
 * __location__ is the source line it is called from. It is particularly
 * useful for creating a new temporary working context.
 */
#define talloc_new(ctx) talloc_named_const(ctx, 0, "talloc_new: " __location__)

/**
 * \def talloc_zero(ctx, type)
 * \brief Allocate a 0-initizialized structure
 * \param ctx The talloc context to hang the result off
 * \param type The type that we want to allocate
 * \return Pointer to a piece of memory, properly cast to "type *"
 * \ingroup talloc_basic
 *
 * The talloc_zero() macro is equivalent to:
 *
 * \code
 * ptr = talloc(ctx, type);
 * if (ptr) memset(ptr, 0, sizeof(type));
 * \endcode
 */
#define talloc_zero(ctx, type) (type *)_talloc_zero(ctx, sizeof(type), #type)

/**
 * \def talloc_zero_size(ctx, size)
 * \brief Untyped, 0-initialized allocation
 * \param ctx The talloc context to hang the result off
 * \param size Number of char's that you want to allocate
 * \return The allocated memory chunk
 * \ingroup talloc_basic
 *
 * The talloc_zero_size() macro is equivalent to:
 *
 * \code
 * ptr = talloc_size(ctx, size);
 * if (ptr) memset(ptr, 0, size);
 * \endcode
 */

#define talloc_zero_size(ctx, size) _talloc_zero(ctx, size, __location__)

#define talloc_zero_array(ctx, type, count) (type *)_talloc_zero_array(ctx, sizeof(type), count, #type)

/**
 * \def talloc_array(ctx, type, count)
 * \brief Allocate an array
 * \param ctx The talloc context to hang the result off
 * \param type The type that we want to allocate
 * \param count The number of "type" elements you want to allocate
 * \return The allocated result, properly cast to "type *"
 * \ingroup talloc_array
 *
 * The talloc_array() macro is equivalent to::
 *
 * \code
 * (type *)talloc_size(ctx, sizeof(type) * count);
 * \endcode
 *
 * except that it provides integer overflow protection for the multiply,
 * returning NULL if the multiply overflows.
 */
#define talloc_array(ctx, type, count) (type *)_talloc_array(ctx, sizeof(type), count, #type)

/**
 * \def talloc_array_size(ctx, size, count)
 * \brief Allocate an array
 * \param ctx The talloc context to hang the result off
 * \param size The size of an array element
 * \param count The number of "type" elements you want to allocate
 * \return The allocated result, properly cast to "type *"
 * \ingroup talloc_array
 *
 * The talloc_array_size() function is useful when the type is not
 * known. It operates in the same way as talloc_array(), but takes a size
 * instead of a type.
 */
#define talloc_array_size(ctx, size, count) _talloc_array(ctx, size, count, __location__)

/**
 * \def talloc_array_ptrtype(ctx, ptr, count)
 * \brief Allocate an array into a typed pointer
 * \param ctx The talloc context to hang the result off
 * \param ptr The pointer you want to assign the result to
 * \param count The number of elements you want to allocate
 * \result The allocated memory chunk, properly cast
 * \ingroup talloc_array
 *
 * The talloc_array_ptrtype() macro should be used when you have a pointer to
 * an array and want to allocate memory of an array to point at with this
 * pointer. When compiling with gcc >= 3 it is typesafe. Note this is a
 * wrapper of talloc_array_size() and talloc_get_name() will return the
 * current location in the source file.  and not the type.
 */
#define talloc_array_ptrtype(ctx, ptr, count) (_TALLOC_TYPEOF(ptr))talloc_array_size(ctx, sizeof(*(ptr)), count)

/**
 * \def talloc_array_length(ctx)
 * \brief Return the number of elements in a talloc'ed array
 * \param ctx The talloc'ed array
 * \return The number of elements in ctx
 * \ingroup talloc_array
 *
 * A talloc chunk carries its own size, so for talloc'ed arrays it is not
 * necessary to store the number of elements explicitly.
 */
#define talloc_array_length(ctx) ((ctx) ? talloc_get_size(ctx)/sizeof(*ctx) : 0)

/**
 * \def talloc_realloc(ctx, p, type, count)
 * \brief Change the size of a talloc array
 * \param ctx The parent context used if "p" is NULL
 * \param p The chunk to be resized
 * \param type The type of the array element inside p
 * \param count The intended number of array elements
 * \return The new array
 * \ingroup talloc_array
 *
 * The talloc_realloc() macro changes the size of a talloc
 * pointer. The "count" argument is the number of elements of type "type"
 * that you want the resulting pointer to hold.
 *
 * talloc_realloc() has the following equivalences::
 *
 * \code
 * talloc_realloc(context, NULL, type, 1) ==> talloc(context, type);
 * talloc_realloc(context, NULL, type, N) ==> talloc_array(context, type, N);
 * talloc_realloc(context, ptr, type, 0)  ==> talloc_free(ptr);
 * \endcode
 *
 * The "context" argument is only used if "ptr" is NULL, otherwise it is
 * ignored.
 *
 * talloc_realloc() returns the new pointer, or NULL on failure. The call
 * will fail either due to a lack of memory, or because the pointer has
 * more than one parent (see talloc_reference()).
 */
#define talloc_realloc(ctx, p, type, count) (type *)_talloc_realloc_array(ctx, p, sizeof(type), count, #type)

/**
 * \def talloc_realloc_size(ctx, ptr, size)
 * \brief Untyped realloc
 * \param ctx The parent context used if "ptr" is NULL
 * \param ptr The chunk to be resized
 * \param size The new chunk size
 * \return The new chunk
 * \ingroup talloc_array
 *
 * The talloc_realloc_size() function is useful when the type is not known so
 * the typesafe talloc_realloc() cannot be used.
 */
#define talloc_realloc_size(ctx, ptr, size) _talloc_realloc(ctx, ptr, size, __location__)

/**
 * \def talloc_memdup(t, p, size)
 * \brief Duplicate a memory area into a talloc chunk
 * \param t The talloc context to hang the result off
 * \param p The memory chunk you want to duplicate
 * \param size Number of char's that you want copy
 * \return The allocated memory chunk
 * \ingroup talloc_basic
 *
 * The talloc_memdup() function is equivalent to::
 *
 * \code
 * ptr = talloc_size(ctx, size);
 * if (ptr) memcpy(ptr, p, size);
 * \endcode
 */
#define talloc_memdup(t, p, size) _talloc_memdup(t, p, size, __location__)

/**
 * \def talloc_set_type(ptr, type)
 * \brief Assign a type to a talloc chunk
 * \param ptr The talloc chunk to assign the type to
 * \param type The type to assign
 * \ingroup talloc_basic
 *
 * This macro allows you to force the name of a pointer to be a
 * particular type. This can be used in conjunction with
 * talloc_get_type() to do type checking on void* pointers.
 *
 * It is equivalent to this::
 *
 * \code
 * talloc_set_name_const(ptr, #type)
 * \endcode
 */
#define talloc_set_type(ptr, type) talloc_set_name_const(ptr, #type)

/**
 * \def talloc_get_type(ptr, type)
 * \brief Get a typed pointer out of a talloc pointer
 * \param ptr The talloc pointer to check
 * \param type The type to check against
 * \return ptr, properly cast, or NULL
 * \ingroup talloc_basic
 *
 * This macro allows you to do type checking on talloc pointers. It is
 * particularly useful for void* private pointers. It is equivalent to
 * this:
 *
 * \code
 * (type *)talloc_check_name(ptr, #type)
 * \endcode
 */

#define talloc_get_type(ptr, type) (type *)talloc_check_name(ptr, #type)

/**
 * \def talloc_get_type_abort(ptr, type)
 * \brief Helper macro to safely turn a void * into a typed pointer
 * \param ptr The void * to convert
 * \param type The type that this chunk contains
 * \return Same value as ptr, type-checked and properly cast
 * \ingroup talloc_basic
 *
 * This macro is used together with talloc(mem_ctx, struct foo). If you had to
 * assing the talloc chunk pointer to some void * variable,
 * talloc_get_type_abort() is the recommended way to get the convert the void
 * pointer back to a typed pointer.
 */
#define talloc_get_type_abort(ptr, type) (type *)_talloc_get_type_abort(ptr, #type, __location__)

/**
 * \def talloc_find_parent_bytype(ptr, type)
 * \brief Find a parent context by type
 * \param ptr The talloc chunk to start from
 * \param type The type of the parent to look for
 * \ingroup talloc_basic
 *
 * Find a parent memory context of the current context that has the given
 * name. This can be very useful in complex programs where it may be
 * difficult to pass all information down to the level you need, but you
 * know the structure you want is a parent of another context.
 *
 * Like talloc_find_parent_byname() but takes a type, making it typesafe.
 */
#define talloc_find_parent_bytype(ptr, type) (type *)talloc_find_parent_byname(ptr, #type)

#if TALLOC_DEPRECATED
#define talloc_zero_p(ctx, type) talloc_zero(ctx, type)
#define talloc_p(ctx, type) talloc(ctx, type)
#define talloc_array_p(ctx, type, count) talloc_array(ctx, type, count)
#define talloc_realloc_p(ctx, p, type, count) talloc_realloc(ctx, p, type, count)
#define talloc_destroy(ctx) talloc_free(ctx)
#define talloc_append_string(c, s, a) (s?talloc_strdup_append(s,a):talloc_strdup(c, a))
#endif

#define TALLOC_FREE(ctx) do { talloc_free(ctx); ctx=NULL; } while(0)

/* The following definitions come from talloc.c  */
void *_talloc(const void *context, size_t size);
void *talloc_pool(const void *context, size_t size);
void _talloc_set_destructor(const void *ptr, int (*destructor)(void *));

/**
 * \brief Increase the reference count of a talloc chunk
 * \param ptr
 * \return success?
 * \ingroup talloc_ref
 *
 * The talloc_increase_ref_count(ptr) function is exactly equivalent to:
 *
 * \code
 * talloc_reference(NULL, ptr);
 * \endcode
 *
 * You can use either syntax, depending on which you think is clearer in
 * your code.
 *
 * It returns 0 on success and -1 on failure.
 */
int talloc_increase_ref_count(const void *ptr);

/**
 * \brief Return the number of references to a talloc chunk
 * \param ptr The chunk you are interested in
 * \return Number of refs
 * \ingroup talloc_ref
 */
size_t talloc_reference_count(const void *ptr);
void *_talloc_reference(const void *context, const void *ptr);

/**
 * \brief Remove a specific parent from a talloc chunk
 * \param context The talloc parent to remove
 * \param ptr The talloc ptr you want to remove the parent from
 * \ingroup talloc_ref
 *
 * The talloc_unlink() function removes a specific parent from ptr. The
 * context passed must either be a context used in talloc_reference() with
 * this pointer, or must be a direct parent of ptr.
 *
 * Note that if the parent has already been removed using talloc_free() then
 * this function will fail and will return -1.  Likewise, if "ptr" is NULL,
 * then the function will make no modifications and return -1.
 *
 * Usually you can just use talloc_free() instead of talloc_unlink(), but
 * sometimes it is useful to have the additional control on which parent is
 * removed.
 */
int talloc_unlink(const void *context, void *ptr);

/**
 * \brief Assign a name to a talloc chunk
 * \param ptr The talloc chunk to assign a name to
 * \param fmt Format string for the name
 * \param ... printf-style additional arguments
 * \return The assigned name
 * \ingroup talloc_basic
 *
 * Each talloc pointer has a "name". The name is used principally for
 * debugging purposes, although it is also possible to set and get the name on
 * a pointer in as a way of "marking" pointers in your code.
 *
 * The main use for names on pointer is for "talloc reports". See
 * talloc_report() and talloc_report_full() for details. Also see
 * talloc_enable_leak_report() and talloc_enable_leak_report_full().
 *
 * The talloc_set_name() function allocates memory as a child of the
 * pointer. It is logically equivalent to:
 *
 * \code
 * talloc_set_name_const(ptr, talloc_asprintf(ptr, fmt, ...));
 * \endcode
 *
 * Note that multiple calls to talloc_set_name() will allocate more memory
 * without releasing the name. All of the memory is released when the ptr is
 * freed using talloc_free().
 */
const char *talloc_set_name(const void *ptr, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);

/**
 * \brief Assign a name to a talloc chunk
 * \param ptr The talloc chunk to assign a name to
 * \param name Format string for the name
 * \ingroup talloc_basic
 *
 * The function talloc_set_name_const() is just like talloc_set_name(), but it
 * takes a string constant, and is much faster. It is extensively used by the
 * "auto naming" macros, such as talloc_p().
 *
 * This function does not allocate any memory. It just copies the supplied
 * pointer into the internal representation of the talloc ptr. This means you
 * must not pass a name pointer to memory that will disappear before the ptr
 * is freed with talloc_free().
 */
void talloc_set_name_const(const void *ptr, const char *name);

/**
 * \brief Create a named talloc chunk
 * \param context The talloc context to hang the result off
 * \param size Number of char's that you want to allocate
 * \param fmt Format string for the name
 * \param ... printf-style additional arguments
 * \return The allocated memory chunk
 * \ingroup talloc_basic
 *
 * The talloc_named() function creates a named talloc pointer. It is
 * equivalent to:
 *
 * \code
 * ptr = talloc_size(context, size);
 * talloc_set_name(ptr, fmt, ....);
 * \endcode
 *
 */
void *talloc_named(const void *context, size_t size, 
		   const char *fmt, ...) PRINTF_ATTRIBUTE(3,4);

/**
 * \brief Basic routine to allocate a chunk of memory
 * \param context The parent context
 * \param size The number of char's that we want to allocate
 * \param name The name the talloc block has
 * \return The allocated chunk
 * \ingroup talloc_basic
 *
 * This is equivalent to:
 *
 * \code
 * ptr = talloc_size(context, size);
 * talloc_set_name_const(ptr, name);
 * \endcode
 */
void *talloc_named_const(const void *context, size_t size, const char *name);

/**
 * \brief Return the name of a talloc chunk
 * \param ptr The talloc chunk
 * \return The name
 * \ingroup talloc_basic
 *
 * This returns the current name for the given talloc pointer. See
 * talloc_set_name() for details.
 */
const char *talloc_get_name(const void *ptr);

/**
 * \brief Verify that a talloc chunk carries a specified name
 * \param ptr The talloc chunk to check
 * \param name The name to check agains
 * \ingroup talloc_basic
 *
 * This function checks if a pointer has the specified name. If it does
 * then the pointer is returned. It it doesn't then NULL is returned.
 */
void *talloc_check_name(const void *ptr, const char *name);

void *_talloc_get_type_abort(const void *ptr, const char *name, const char *location);
void *talloc_parent(const void *ptr);
const char *talloc_parent_name(const void *ptr);

/**
 * \brief Create a new top level talloc context
 * \param fmt Format string for the name
 * \param ... printf-style additional arguments
 * \return The allocated memory chunk
 * \ingroup talloc_basic
 *
 * This function creates a zero length named talloc context as a top level
 * context. It is equivalent to:
 *
 * \code
 *   talloc_named(NULL, 0, fmt, ...);
 * \endcode
 */
void *talloc_init(const char *fmt, ...) PRINTF_ATTRIBUTE(1,2);

/**
 * \brief Free a chunk of talloc memory
 * \param ptr The chunk to be freed
 * \return success?
 * \ingroup talloc_basic
 *
 * The talloc_free() function frees a piece of talloc memory, and all its
 * children. You can call talloc_free() on any pointer returned by talloc().
 *
 * The return value of talloc_free() indicates success or failure, with 0
 * returned for success and -1 for failure. The only possible failure
 * condition is if the pointer had a destructor attached to it and the
 * destructor returned -1. See talloc_set_destructor() for details on
 * destructors.
 *
 * If this pointer has an additional parent when talloc_free() is called
 * then the memory is not actually released, but instead the most
 * recently established parent is destroyed. See talloc_reference() for
 * details on establishing additional parents.
 *
 * For more control on which parent is removed, see talloc_unlink()
 *
 * talloc_free() operates recursively on its children.
 */
int talloc_free(void *ptr);

/**
 * \brief Free a talloc chunk's children
 * \param ptr The chunk that you want to free the children of
 * \return success?
 * \ingroup talloc_basic
 *
 * The talloc_free_children() walks along the list of all children of a talloc
 * context and talloc_free()s only the children, not the context itself.
 */
void talloc_free_children(void *ptr);
void *_talloc_realloc(const void *context, void *ptr, size_t size, const char *name);
void *_talloc_steal(const void *new_ctx, const void *ptr);
void *_talloc_move(const void *new_ctx, const void *pptr);

/**
 * \brief Return the total size of a talloc chunk including its children
 * \param ptr The talloc chunk
 * \return The total size
 * \ingroup talloc_basic
 *
 * The talloc_total_size() function returns the total size in bytes used
 * by this pointer and all child pointers. Mostly useful for debugging.
 *
 * Passing NULL is allowed, but it will only give a meaningful result if
 * talloc_enable_leak_report() or talloc_enable_leak_report_full() has
 * been called.
 */
size_t talloc_total_size(const void *ptr);

/**
 * \brief Return the number of talloc chunks hanging off a chunk
 * \param ptr The talloc chunk
 * \return The total size
 * \ingroup talloc_basic
 *
 * The talloc_total_blocks() function returns the total memory block
 * count used by this pointer and all child pointers. Mostly useful for
 * debugging.
 *
 * Passing NULL is allowed, but it will only give a meaningful result if
 * talloc_enable_leak_report() or talloc_enable_leak_report_full() has
 * been called.
 */
size_t talloc_total_blocks(const void *ptr);

/**
 * \brief Walk a complete talloc hierarchy
 * \param ptr The talloc chunk
 * \param depth Internal parameter to control recursion. Call with 0.
 * \param max_depth Maximum recursion level.
 * \param callback Function to be called on every chunk
 * \param private_data Private pointer passed to callback
 * \ingroup talloc_debug
 *
 * This provides a more flexible reports than talloc_report(). It
 * will recursively call the callback for the entire tree of memory
 * referenced by the pointer. References in the tree are passed with
 * is_ref = 1 and the pointer that is referenced.
 *
 * You can pass NULL for the pointer, in which case a report is
 * printed for the top level memory context, but only if
 * talloc_enable_leak_report() or talloc_enable_leak_report_full()
 * has been called.
 *
 * The recursion is stopped when depth >= max_depth.
 * max_depth = -1 means only stop at leaf nodes.
 */
void talloc_report_depth_cb(const void *ptr, int depth, int max_depth,
			    void (*callback)(const void *ptr,
			  		     int depth, int max_depth,
					     int is_ref,
					     void *private_data),
			    void *private_data);

/**
 * \brief Print a talloc hierarchy
 * \param ptr The talloc chunk
 * \param depth Internal parameter to control recursion. Call with 0.
 * \param max_depth Maximum recursion level.
 * \param f The file handle to print to
 * \ingroup talloc_debug
 *
 * This provides a more flexible reports than talloc_report(). It
 * will let you specify the depth and max_depth.
 */
void talloc_report_depth_file(const void *ptr, int depth, int max_depth, FILE *f);

/**
 * \brief Print a summary report of all memory used by ptr
 * \param ptr The talloc chunk
 * \param f The file handle to print to
 * \ingroup talloc_debug
 *
 * This provides a more detailed report than talloc_report(). It will
 * recursively print the ensire tree of memory referenced by the
 * pointer. References in the tree are shown by giving the name of the
 * pointer that is referenced.
 *
 * You can pass NULL for the pointer, in which case a report is printed
 * for the top level memory context, but only if
 * talloc_enable_leak_report() or talloc_enable_leak_report_full() has
 * been called.
 */
void talloc_report_full(const void *ptr, FILE *f);

/**
 * \brief Print a summary report of all memory used by ptr
 * \param ptr The talloc chunk
 * \param f The file handle to print to
 * \ingroup talloc_debug
 *
 * The talloc_report() function prints a summary report of all memory
 * used by ptr. One line of report is printed for each immediate child of
 * ptr, showing the total memory and number of blocks used by that child.
 *
 * You can pass NULL for the pointer, in which case a report is printed
 * for the top level memory context, but only if
 * talloc_enable_leak_report() or talloc_enable_leak_report_full() has
 * been called.
 */
void talloc_report(const void *ptr, FILE *f);

/**
 * \brief Enable tracking the use of NULL memory contexts
 * \ingroup talloc_debug
 *
 * This enables tracking of the NULL memory context without enabling leak
 * reporting on exit. Useful for when you want to do your own leak
 * reporting call via talloc_report_null_full();
 */
void talloc_enable_null_tracking(void);

/**
 * \brief Disable tracking of the NULL memory context
 * \ingroup talloc_debug
 *
 * This disables tracking of the NULL memory context.
 */

void talloc_disable_null_tracking(void);

/**
 * \brief Enable calling of talloc_report(NULL, stderr) when a program exits
 * \ingroup talloc_debug
 *
 * This enables calling of talloc_report(NULL, stderr) when the program
 * exits. In Samba4 this is enabled by using the --leak-report command
 * line option.
 *
 * For it to be useful, this function must be called before any other
 * talloc function as it establishes a "null context" that acts as the
 * top of the tree. If you don't call this function first then passing
 * NULL to talloc_report() or talloc_report_full() won't give you the
 * full tree printout.
 *
 * Here is a typical talloc report:
 *
\verbatim
talloc report on 'null_context' (total 267 bytes in 15 blocks)
         libcli/auth/spnego_parse.c:55  contains     31 bytes in   2 blocks
         libcli/auth/spnego_parse.c:55  contains     31 bytes in   2 blocks
         iconv(UTF8,CP850)              contains     42 bytes in   2 blocks
         libcli/auth/spnego_parse.c:55  contains     31 bytes in   2 blocks
         iconv(CP850,UTF8)              contains     42 bytes in   2 blocks
         iconv(UTF8,UTF-16LE)           contains     45 bytes in   2 blocks
         iconv(UTF-16LE,UTF8)           contains     45 bytes in   2 blocks
\endverbatim
 */
void talloc_enable_leak_report(void);

/**
 * \brief Enable calling of talloc_report(NULL, stderr) when a program exits
 * \ingroup talloc_debug
 *
 * This enables calling of talloc_report_full(NULL, stderr) when the
 * program exits. In Samba4 this is enabled by using the
 * --leak-report-full command line option.
 *
 * For it to be useful, this function must be called before any other
 * talloc function as it establishes a "null context" that acts as the
 * top of the tree. If you don't call this function first then passing
 * NULL to talloc_report() or talloc_report_full() won't give you the
 * full tree printout.
 *
 * Here is a typical full report:
\verbatim
full talloc report on 'root' (total 18 bytes in 8 blocks)
    p1                             contains     18 bytes in   7 blocks (ref 0)
        r1                             contains     13 bytes in   2 blocks (ref 0)
            reference to: p2
        p2                             contains      1 bytes in   1 blocks (ref 1)
        x3                             contains      1 bytes in   1 blocks (ref 0)
        x2                             contains      1 bytes in   1 blocks (ref 0)
        x1                             contains      1 bytes in   1 blocks (ref 0)
\endverbatim
*/
void talloc_enable_leak_report_full(void);
void *_talloc_zero(const void *ctx, size_t size, const char *name);
void *_talloc_memdup(const void *t, const void *p, size_t size, const char *name);
void *_talloc_array(const void *ctx, size_t el_size, unsigned count, const char *name);
void *_talloc_zero_array(const void *ctx, size_t el_size, unsigned count, const char *name);
void *_talloc_realloc_array(const void *ctx, void *ptr, size_t el_size, unsigned count, const char *name);

/**
 * \brief Provide a function version of talloc_realloc_size
 * \param context The parent context used if "ptr" is NULL
 * \param ptr The chunk to be resized
 * \param size The new chunk size
 * \return The new chunk
 * \ingroup talloc_array
 *
 * This is a non-macro version of talloc_realloc(), which is useful as
 * libraries sometimes want a ralloc function pointer. A realloc()
 * implementation encapsulates the functionality of malloc(), free() and
 * realloc() in one call, which is why it is useful to be able to pass around
 * a single function pointer.
*/
void *talloc_realloc_fn(const void *context, void *ptr, size_t size);

/**
 * \brief Provide a talloc context that is freed at program exit
 * \return A talloc context
 * \ingroup talloc_basic
 *
 * This is a handy utility function that returns a talloc context
 * which will be automatically freed on program exit. This can be used
 * to reduce the noise in memory leak reports.
 */
void *talloc_autofree_context(void);

/**
 * \brief Get the size of a talloc chunk
 * \param ctx The talloc chunk
 * \return The size
 * \ingroup talloc_basic
 *
 * This function lets you know the amount of memory alloced so far by
 * this context. It does NOT account for subcontext memory.
 * This can be used to calculate the size of an array.
 */
size_t talloc_get_size(const void *ctx);

/**
 * \brief Find a parent context by name
 * \param ctx The talloc chunk to start from
 * \param name The name of the parent we look for
 * \ingroup talloc_basic
 *
 * Find a parent memory context of the current context that has the given
 * name. This can be very useful in complex programs where it may be
 * difficult to pass all information down to the level you need, but you
 * know the structure you want is a parent of another context.
 */
void *talloc_find_parent_byname(const void *ctx, const char *name);
void talloc_show_parents(const void *context, FILE *file);
int talloc_is_parent(const void *context, const void *ptr);

/**
 * \brief Duplicate a string into a talloc chunk
 * \param t The talloc context to hang the result off
 * \param p The string you want to duplicate
 * \return The duplicated string
 * \ingroup talloc_string
 *
 * The talloc_strdup() function is equivalent to:
 *
 * \code
 * ptr = talloc_size(ctx, strlen(p)+1);
 * if (ptr) memcpy(ptr, p, strlen(p)+1);
 * \endcode
 *
 * This functions sets the name of the new pointer to the passed
 * string. This is equivalent to:
 *
 * \code
 * talloc_set_name_const(ptr, ptr)
 * \endcode
 */
char *talloc_strdup(const void *t, const char *p);
char *talloc_strdup_append(char *s, const char *a);
char *talloc_strdup_append_buffer(char *s, const char *a);

/**
 * \brief Duplicate a length-limited string into a talloc chunk
 * \param t The talloc context to hang the result off
 * \param p The string you want to duplicate
 * \param n The maximum string length to duplicate
 * \return The duplicated string
 * \ingroup talloc_string
 *
 * The talloc_strndup() function is the talloc equivalent of the C
 * library function strndup()
 *
 * This functions sets the name of the new pointer to the passed
 * string. This is equivalent to:
 *
 * \code
 * talloc_set_name_const(ptr, ptr)
 * \endcode
 */
char *talloc_strndup(const void *t, const char *p, size_t n);
char *talloc_strndup_append(char *s, const char *a, size_t n);
char *talloc_strndup_append_buffer(char *s, const char *a, size_t n);

/**
 * \brief Format a string given a va_list
 * \param t The talloc context to hang the result off
 * \param fmt The format string
 * \param ap The parameters used to fill fmt
 * \return The formatted string
 * \ingroup talloc_string
 *
 * The talloc_vasprintf() function is the talloc equivalent of the C
 * library function vasprintf()
 *
 * This functions sets the name of the new pointer to the new
 * string. This is equivalent to:
 *
 * \code
 * talloc_set_name_const(ptr, ptr)
 * \endcode
 */
char *talloc_vasprintf(const void *t, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(2,0);
char *talloc_vasprintf_append(char *s, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(2,0);
char *talloc_vasprintf_append_buffer(char *s, const char *fmt, va_list ap) PRINTF_ATTRIBUTE(2,0);

/**
 * \brief Format a string
 * \param t The talloc context to hang the result off
 * \param fmt The format string
 * \param ... The parameters used to fill fmt
 * \return The formatted string
 * \ingroup talloc_string
 *
 * The talloc_asprintf() function is the talloc equivalent of the C
 * library function asprintf()
 *
 * This functions sets the name of the new pointer to the new
 * string. This is equivalent to:
 *
 * \code
 * talloc_set_name_const(ptr, ptr)
 * \endcode
 */
char *talloc_asprintf(const void *t, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);

/**
 * \brief Append a formatted string to another string
 * \param s The string to append to
 * \param fmt The format string
 * \param ... The parameters used to fill fmt
 * \return The formatted string
 * \ingroup talloc_string
 *
 * The talloc_asprintf_append() function appends the given formatted string to
 * the given string. Use this varient when the string in the current talloc
 * buffer may have been truncated in length.
 *
 * This functions sets the name of the new pointer to the new
 * string. This is equivalent to:
 *
 * \code
 * talloc_set_name_const(ptr, ptr)
 * \endcode
 */
char *talloc_asprintf_append(char *s, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);

/**
 * \brief Append a formatted string to another string
 * \param s The string to append to
 * \param fmt The format string
 * \param ... The parameters used to fill fmt
 * \return The formatted string
 * \ingroup talloc_string
 *
 * The talloc_asprintf_append() function appends the given formatted string to
 * the end of the currently allocated talloc buffer. This routine should be
 * used if you create a large string step by step. talloc_asprintf() or
 * talloc_asprintf_append() call strlen() at every
 * step. talloc_asprintf_append_buffer() uses the existing buffer size of the
 * talloc chunk to calculate where to append the string.
 *
 * This functions sets the name of the new pointer to the new
 * string. This is equivalent to:
 *
 * \code
 * talloc_set_name_const(ptr, ptr)
 * \endcode
 */
char *talloc_asprintf_append_buffer(char *s, const char *fmt, ...) PRINTF_ATTRIBUTE(2,3);

void talloc_set_abort_fn(void (*abort_fn)(const char *reason));

#endif

/*\}*/
