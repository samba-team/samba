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

/* Misc bit macros */
#define BOOLSTR(b) ((b) ? "Yes" : "No")
#define BITSETB(ptr,bit) ((((char *)ptr)[0] & (1<<(bit)))!=0)
#define BITSETW(ptr,bit) ((SVAL(ptr,0) & (1<<(bit)))!=0)

/* for readability... */
#define IS_DOS_READONLY(test_mode) (((test_mode) & aRONLY) != 0)
#define IS_DOS_DIR(test_mode)      (((test_mode) & aDIR) != 0)
#define IS_DOS_ARCHIVE(test_mode)  (((test_mode) & aARCH) != 0)
#define IS_DOS_SYSTEM(test_mode)   (((test_mode) & aSYSTEM) != 0)
#define IS_DOS_HIDDEN(test_mode)   (((test_mode) & aHIDDEN) != 0)

#ifndef SAFE_FREE /* Oh no this is also defined in tdb.h */

/**
 * Free memory if the pointer and zero the pointer.
 *
 * @note You are explicitly allowed to pass NULL pointers -- they will
 * always be ignored.
 **/
#define SAFE_FREE(x) do { if ((x) != NULL) {free(x); (x)=NULL;} } while(0)
#endif

/* zero a structure */
#define ZERO_STRUCT(x) memset((char *)&(x), 0, sizeof(x))

/* zero a structure given a pointer to the structure */
#define ZERO_STRUCTP(x) do { if ((x) != NULL) memset((char *)(x), 0, sizeof(*(x))); } while(0)

/* zero a structure given a pointer to the structure - no zero check */
#define ZERO_STRUCTPN(x) memset((char *)(x), 0, sizeof(*(x)))

/* zero an array - note that sizeof(array) must work - ie. it must not be a 
   pointer */
#define ZERO_ARRAY(x) memset((char *)(x), 0, sizeof(x))

/* pointer difference macro */
#define PTR_DIFF(p1,p2) ((ptrdiff_t)(((const char *)(p1)) - (const char *)(p2)))

/* work out how many elements there are in a static array */
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(a[0]))

/* assert macros */
#define SMB_ASSERT(b) do { if (!(b)) { \
	DEBUG(0,("PANIC: assert failed at %s(%d)\n", __FILE__, __LINE__)); \
	smb_panic("assert failed"); }} while (0)

#define SMB_ASSERT_ARRAY(a,n) SMB_ASSERT((sizeof(a)/sizeof((a)[0])) >= (n))

/* the service number for the [globals] defaults */ 
#define GLOBAL_SECTION_SNUM	(-1)
/* translates a connection number into a service number */
#define SNUM(conn)         	((conn)?(conn)->service:GLOBAL_SECTION_SNUM)


/* access various service details */
#define SERVICE(snum)      (lp_servicename(snum))
#define PRINTERNAME_NOTUSED(snum)  (lp_printername(snum))
#define CAN_WRITE(conn)    (!conn->read_only)
#define VALID_SNUM(snum)   (lp_snum_ok(snum))
#define GUEST_OK(snum)     (VALID_SNUM(snum) && lp_guest_ok(snum))

/* these are the datagram types */
#define DGRAM_DIRECT_UNIQUE 0x10


/* REWRITE TODO: remove these smb_xxx macros */
#define smb_buf(buf) (((char *)(buf)) + MIN_SMB_SIZE + CVAL(buf,HDR_WCT+4)*2)

#define smb_len(buf) (PVAL(buf,3)|(PVAL(buf,2)<<8)|(PVAL(buf,1)<<16))
#define _smb_setlen(buf,len) do {(buf)[0] = 0; (buf)[1] = ((len)&0x10000)>>16; \
        (buf)[2] = ((len)&0xFF00)>>8; (buf)[3] = (len)&0xFF;} while (0)

/*******************************************************************
find the difference in milliseconds between two struct timeval
values
********************************************************************/

#define TvalDiff(tvalold,tvalnew) \
  (((tvalnew)->tv_sec - (tvalold)->tv_sec)*1000 +  \
	 ((int)(tvalnew)->tv_usec - (int)(tvalold)->tv_usec)/1000)

/****************************************************************************
true if two IP addresses are equal
****************************************************************************/

#define ip_equal(ip1,ip2) ((ip1).s_addr == (ip2).s_addr)
#define ipv4_equal(ip1,ip2) ((ip1).addr == (ip2).addr)

/*******************************************************************
copy an IP address from one buffer to another
********************************************************************/

#define putip(dest,src) memcpy(dest,src,4)


#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

#ifndef ABS
#define ABS(a) ((a)>0?(a):(-(a)))
#endif


#endif /* _SMB_MACROS_H */
