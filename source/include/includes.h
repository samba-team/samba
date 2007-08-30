#ifndef _INCLUDES_H
#define _INCLUDES_H
/* 
   Unix SMB/CIFS implementation.
   Machine customisation and include handling
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) 2002 by Martin Pool <mbp@samba.org>
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "lib/replace/replace.h"

/* make sure we have included the correct config.h */
#ifndef NO_CONFIG_H /* for some tests */
#ifndef CONFIG_H_IS_FROM_SAMBA
#error "make sure you have removed all config.h files from standalone builds!"
#error "the included config.h isn't from samba!"
#endif
#endif /* NO_CONFIG_H */

#include "local.h"

#ifdef __GNUC__
/** gcc attribute used on function parameters so that it does not emit
 * warnings about them being unused. **/
#  define UNUSED(param) param __attribute__ ((unused))
#else
#  define UNUSED(param) param
/** Feel free to add definitions for other compilers here. */
#endif

#ifndef _PUBLIC_
#ifdef HAVE_VISIBILITY_ATTR
#  define _PUBLIC_ __attribute__((visibility("default")))
#else
#  define _PUBLIC_
#endif
#endif

#ifndef PRINTF_ATTRIBUTE
#if __GNUC__ >= 3
/** Use gcc attribute to check printf fns.  a1 is the 1-based index of
 * the parameter containing the format, and a2 the index of the first
 * argument. Note that some gcc 2.x versions don't handle this
 * properly **/
#define PRINTF_ATTRIBUTE(a1, a2) __attribute__ ((format (__printf__, a1, a2)))
#else
#define PRINTF_ATTRIBUTE(a1, a2)
#endif
#endif

#ifndef _DEPRECATED_
#if (__GNUC__ >= 3) && (__GNUC_MINOR__ >= 1 )
#define _DEPRECATED_ __attribute__ ((deprecated))
#else
#define _DEPRECATED_
#endif
#endif

#ifndef _WARN_UNUSED_RESULT_
#if (__GNUC__ >= 3) && (__GNUC_MINOR__ >= 1 )
#define _WARN_UNUSED_RESULT_ __attribute__ ((warn_unused_result))
#else
#define _WARN_UNUSED_RESULT_
#endif
#endif

#ifndef _NORETURN_
#if (__GNUC__ >= 3) && (__GNUC_MINOR__ >= 1 )
#define _NORETURN_ __attribute__ ((noreturn))
#else
#define _NORETURN_
#endif
#endif

#ifndef _PURE_
#if (__GNUC__ >= 3) && (__GNUC_MINOR__ >= 1)
#define _PURE_ __attribute__((pure))
#else
#define _PURE_
#endif
#endif

#ifndef NONNULL
#if (__GNUC__ >= 3) && (__GNUC_MINOR__ >= 1)
#define NONNULL(param) param __attribute__((nonnull))
#else
#define NONNULL(param) param
#endif
#endif

#include "system/time.h"
#include "system/wait.h"

#ifndef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a1, a2) PRINTF_ATTRIBUTE(a1, a2)
#endif

/* Lists, trees, caching, database... */
#include <talloc.h>
#include "core.h"
#include <stdbool.h>
#include "charset/charset.h"
#include "util/util.h"
#include "param/param.h"
#include "librpc/gen_ndr/misc.h"

typedef bool BOOL;

#define False false
#define True true

struct smbcli_tree;
#include "libcli/util/error.h"

/* String routines */
#include "util/safe_string.h"

#if 0
/* darn, we can't do this now that we don't link the ldb tools to all the smb libs */
#define TALLOC_ABORT(reason) smb_panic(reason)
#endif

#endif /* _INCLUDES_H */
