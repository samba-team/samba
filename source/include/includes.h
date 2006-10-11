#ifndef _INCLUDES_H
#define _INCLUDES_H
/* 
   Unix SMB/CIFS implementation.
   Machine customisation and include handling
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) 2002 by Martin Pool <mbp@samba.org>
   
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

#ifndef NORETURN_ATTRIBUTE
#if (__GNUC__ >= 3)
#define NORETURN_ATTRIBUTE __attribute__ ((noreturn))
#else
#define NORETURN_ATTRIBUTE
#endif
#endif

/* mark smb_panic() as noreturn, so static analysers know that it is
   used like abort */
_PUBLIC_ void smb_panic(const char *why) NORETURN_ATTRIBUTE;

#include "system/time.h"
#include "system/wait.h"

#define _PRINTF_ATTRIBUTE(a1, a2) PRINTF_ATTRIBUTE(a1, a2)

/* Lists, trees, caching, database... */
#include "talloc/talloc.h"
#include "core.h"
#include "charset/charset.h"
#include "util/util.h"
#include "param/param.h"
#include "librpc/gen_ndr/misc.h"

struct smbcli_tree;
#include "libcli/util/error.h"

/* String routines */
#include "util/safe_string.h"

#if 0
/* darn, we can't do this now that we don't link the ldb tools to all the smb libs */
#define TALLOC_ABORT(reason) smb_panic(reason)
#endif

#endif /* _INCLUDES_H */
