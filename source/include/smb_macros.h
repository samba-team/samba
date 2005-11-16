/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup
   Copyright (C) Andrew Tridgell 1992-1999
   Copyright (C) John H Terpstra 1996-1999
   Copyright (C) Luke Kenneth Casson Leighton 1996-1999
   Copyright (C) Paul Ashton 1998 - 1999
   
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

#ifndef _SMB_MACROS_H
#define _SMB_MACROS_H

/* zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/* zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)

/* zero a structure given a pointer to the structure - no zero check */
#define ZERO_STRUCTPN(x) memset((char *)(x), 0, sizeof(*(x)))

/* pointer difference macro */
#define PTR_DIFF(p1,p2) ((ptrdiff_t)(((const char *)(p1)) - (const char *)(p2)))

/* work out how many elements there are in a static array */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/* assert macros */
#define SMB_ASSERT(b) do { if (!(b)) { \
	DEBUG(0,("PANIC: assert failed at %s(%d)\n", __FILE__, __LINE__)); \
	smb_panic("assert failed"); }} while (0)

#define smb_len(buf) (PVAL(buf,3)|(PVAL(buf,2)<<8)|(PVAL(buf,1)<<16))
#define _smb_setlen(buf,len) do {(buf)[0] = 0; (buf)[1] = ((len)&0x10000)>>16; \
        (buf)[2] = ((len)&0xFF00)>>8; (buf)[3] = (len)&0xFF;} while (0)
#define _smb_setlen2(buf,len) do {(buf)[0] = 0; (buf)[1] = ((len)&0xFF0000)>>16; \
        (buf)[2] = ((len)&0xFF00)>>8; (buf)[3] = (len)&0xFF;} while (0)

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#ifndef ABS
#define ABS(a) ((a)>0?(a):(-(a)))
#endif

#ifndef SAFE_FREE /* Oh no this is also defined in tdb.h */
/**
 * Free memory if the pointer and zero the pointer.
 *
 * @note You are explicitly allowed to pass NULL pointers -- they will
 * always be ignored.
 **/
#define SAFE_FREE(x) do { if ((x) != NULL) {free(discard_const_p(void *, (x))); (x)=NULL;} } while(0)
#endif

#define malloc_p(type) (type *)malloc(sizeof(type))
#define malloc_array_p(type, count) (type *)realloc_array(NULL, sizeof(type), count)
#define realloc_p(p, type, count) (type *)realloc_array(p, sizeof(type), count)

#endif /* _SMB_MACROS_H */
