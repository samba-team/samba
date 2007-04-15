/* 
   Unix SMB/CIFS implementation.
   Utility functions for Samba
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) Jelmer Vernooij 2005
    
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

#ifndef _SAMBA_UTIL_H_
#define _SAMBA_UTIL_H_

#include "charset/charset.h"

/**
 * @file
 * @brief Helpful macros
 */

struct substitute_context;
struct smbsrv_tcon;

extern const char *logfile;
extern const char *panic_action;

#include "util/xfile.h"
#include "util/debug.h"
#include "util/mutex.h"
#include "util/byteorder.h"
#include "lib/util/util_proto.h"

/** 
 * zero a structure 
 */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/** 
 * zero a structure given a pointer to the structure 
 */
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)

/** 
 * zero a structure given a pointer to the structure - no zero check 
 */
#define ZERO_STRUCTPN(x) memset((char *)(x), 0, sizeof(*(x)))

/** 
 * pointer difference macro 
 */
#define PTR_DIFF(p1,p2) ((ptrdiff_t)(((const char *)(p1)) - (const char *)(p2)))

/**
 * work out how many elements there are in a static array 
 */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/**
 * assert macros 
 */
#define SMB_ASSERT(b) do { if (!(b)) { \
	DEBUG(0,("PANIC: assert failed at %s(%d)\n", __FILE__, __LINE__)); \
	smb_panic("assert failed"); abort(); }} while (0)

#ifndef SAFE_FREE /* Oh no this is also defined in tdb.h */
/**
 * Free memory if the pointer and zero the pointer.
 *
 * @note You are explicitly allowed to pass NULL pointers -- they will
 * always be ignored.
 **/
#define SAFE_FREE(x) do { if ((x) != NULL) {free(discard_const_p(void *, (x))); (x)=NULL;} } while(0)
#endif

/** 
 * Type-safe version of malloc. Allocated one copy of the 
 * specified data type.
 */
#define malloc_p(type) (type *)malloc(sizeof(type))

/**
 * Allocate an array of elements of one data type. Does type-checking.
 */
#define malloc_array_p(type, count) (type *)realloc_array(NULL, sizeof(type), count)

/** 
 * Resize an array of elements of one data type. Does type-checking.
 */
#define realloc_p(p, type, count) (type *)realloc_array(p, sizeof(type), count)

#define data_blob(ptr, size) data_blob_named(ptr, size, "DATA_BLOB: "__location__)
#define data_blob_talloc(ctx, ptr, size) data_blob_talloc_named(ctx, ptr, size, "DATA_BLOB: "__location__)
#define data_blob_dup_talloc(ctx, blob) data_blob_talloc_named(ctx, (blob)->data, (blob)->length, "DATA_BLOB: "__location__)

#if defined(VALGRIND)
#define strlen(x) valgrind_strlen(x)
#endif

#endif /* _SAMBA_UTIL_H_ */
