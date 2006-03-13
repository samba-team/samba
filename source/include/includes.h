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

#ifndef NO_CONFIG_H /* for some tests */
#include "config.h"
#endif

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
#if !defined(NO_PRINTF_ATTRIBUTE) && (__GNUC__ >= 3)
/** Use gcc attribute to check printf fns.  a1 is the 1-based index of
 * the parameter containing the format, and a2 the index of the first
 * argument. Note that some gcc 2.x versions don't handle this
 * properly **/
#define PRINTF_ATTRIBUTE(a1, a2) __attribute__ ((format (__printf__, a1, a2)))
#else
#define PRINTF_ATTRIBUTE(a1, a2)
#endif
#endif

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/time.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <signal.h>
#include <errno.h>

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

/* protocol types. It assumes that higher protocols include lower protocols
   as subsets. FIXME: Move to one of the smb-specific headers */
enum protocol_types {
	PROTOCOL_NONE,
	PROTOCOL_CORE,
	PROTOCOL_COREPLUS,
	PROTOCOL_LANMAN1,
	PROTOCOL_LANMAN2,
	PROTOCOL_NT1,
	PROTOCOL_SMB2
};

/* passed to br lock code. FIXME: Move to one of the smb-specific headers */
enum brl_type {
	READ_LOCK,
	WRITE_LOCK,
	PENDING_READ_LOCK,
	PENDING_WRITE_LOCK
};

#define _PRINTF_ATTRIBUTE(a1, a2) PRINTF_ATTRIBUTE(a1, a2)
#include "lib/replace/replace.h"

/* Lists, trees, caching, database... */
#include "libcli/util/nt_status.h"
#include "talloc/talloc.h"
#include "core.h"
#include "charset/charset.h"
#include "structs.h"
#include "util/util.h"
#include "param/param.h"
#include "libcli/util/nterr.h"
#include "libcli/util/doserr.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/dcerpc.h"
#include "librpc/ndr/ndr_orpc.h"
#include "librpc/gen_ndr/orpc.h"
#include "librpc/rpc/dcerpc.h"
#include "auth/credentials/credentials.h"
#include "libcli/nbt/libnbt.h"
#include "libcli/util/proto.h"

#undef _PRINTF_ATTRIBUTE
#define _PRINTF_ATTRIBUTE(a1, a2)

/***** automatically generated prototypes *****/
#include "include/proto.h"

/* String routines */

#include "util/safe_string.h"

#if 0
/* darn, we can't do this now that we don't link the ldb tools to all the smb libs */
#define TALLOC_ABORT(reason) smb_panic(reason)
#endif

#endif /* _INCLUDES_H */
