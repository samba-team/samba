/* 
   Unix SMB/CIFS implementation.
   NT error code constants
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) John H Terpstra              1996-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Paul Ashton                  1998-2000

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

#ifndef _NTSTATUS_H
#define _NTSTATUS_H

#include "libcli/util/ntstatus_gen.h"

/* the following rather strange looking definitions of NTSTATUS 
   are there in order to catch common coding errors where different error types
   are mixed up. This is especially important as we slowly convert Samba
   from using bool for internal functions 
*/

#if defined(HAVE_IMMEDIATE_STRUCTURES)
typedef struct {uint32_t v;} NTSTATUS;
#define NT_STATUS(x) ((NTSTATUS) { x })
#define NT_STATUS_V(x) ((x).v)
#else
typedef uint32_t NTSTATUS;
#define NT_STATUS(x) (x)
#define NT_STATUS_V(x) (x)
#endif

/* Win32 status codes. */
#define ERROR_INVALID_PARAMETER		  NT_STATUS(0x0057)
#define ERROR_INSUFFICIENT_BUFFER	  NT_STATUS(0x007a)
#define NT_STATUS_ERROR_DS_OBJ_STRING_NAME_EXISTS	NT_STATUS(0x2071)
#define NT_STATUS_ERROR_DS_INCOMPATIBLE_VERSION		NT_STATUS(0x2177)
#define NT_STATUS_SMB_NO_PREAUTH_INTEGRITY_HASH_OVERLAP	NT_STATUS(0xC05D0000)

/* Other error codes that aren't in the list we use */
#define NT_STATUS_OK			  NT_STATUS_SUCCESS

#define STATUS_MORE_ENTRIES		  NT_STATUS_MORE_ENTRIES
#define STATUS_BUFFER_OVERFLOW		  NT_STATUS_BUFFER_OVERFLOW
#define STATUS_NO_MORE_FILES		  NT_STATUS_NO_MORE_FILES
#define STATUS_INVALID_EA_NAME		  NT_STATUS_INVALID_EA_NAME
#define STATUS_SOME_UNMAPPED 		  NT_STATUS_SOME_NOT_MAPPED
#define NT_STATUS_INACCESSIBLE_SYSTEM_SHORTCUT		NT_STATUS(0x8000002d)

#define NT_STATUS_ABIOS_NOT_PRESENT 		NT_STATUS(0xC0000000 | 0x010f)
#define NT_STATUS_ABIOS_LID_NOT_EXIST 		NT_STATUS(0xC0000000 | 0x0110)
#define NT_STATUS_ABIOS_LID_ALREADY_OWNED 	NT_STATUS(0xC0000000 | 0x0111)
#define NT_STATUS_ABIOS_NOT_LID_OWNER 		NT_STATUS(0xC0000000 | 0x0112)
#define NT_STATUS_ABIOS_INVALID_COMMAND 	NT_STATUS(0xC0000000 | 0x0113)
#define NT_STATUS_ABIOS_INVALID_LID 		NT_STATUS(0xC0000000 | 0x0114)
#define NT_STATUS_ABIOS_SELECTOR_NOT_AVAILABLE 	NT_STATUS(0xC0000000 | 0x0115)
#define NT_STATUS_ABIOS_INVALID_SELECTOR 	NT_STATUS(0xC0000000 | 0x0116)

#define NT_STATUS_HANDLE_NOT_WAITABLE 		NT_STATUS(0xC0000000 | 0x0036)
#define NT_STATUS_DEVICE_POWER_FAILURE 		NT_STATUS(0xC0000000 | 0x009e)
#define NT_STATUS_VHD_SHARED			NT_STATUS(0xC05CFF0A)
#define NT_STATUS_SMB_BAD_CLUSTER_DIALECT	NT_STATUS(0xC05D0001)
#define NT_STATUS_NO_SUCH_JOB 			NT_STATUS(0xC0000000 | 0xEDE)

/*
                       --------------
                      /              \
                     /      REST      \
                    /        IN        \
                   /       PEACE        \
                  /                      \
                  | NT_STATUS_NOPROBLEMO |
                  |                      |
                  |                      |
                  |      4 September     |
                  |                      |
                  |         2001         |
                 *|     *  *  *          | *
        _________)/\\_//(\/(/\)/\//\/\///|_)_______
*/

/* I use NT_STATUS_FOOBAR when I have no idea what error code to use -
 * this means we need a torture test */
#define NT_STATUS_FOOBAR NT_STATUS_UNSUCCESSFUL

/*****************************************************************************
 returns an NT error message.  not amazingly helpful, but better than a number.
 *****************************************************************************/
const char *nt_errstr(NTSTATUS nt_code);

/************************************************************************
 Print friendler version fo NT error code
 ***********************************************************************/
const char *get_friendly_nt_error_msg(NTSTATUS nt_code);

/*****************************************************************************
 returns an NT_STATUS constant as a string for inclusion in autogen C code
 *****************************************************************************/
const char *get_nt_error_c_code(void *mem_ctx, NTSTATUS nt_code);

/*****************************************************************************
 returns the NT_STATUS constant matching the string supplied (as an NTSTATUS)
 *****************************************************************************/
NTSTATUS nt_status_string_to_code(const char *nt_status_str);

/* we need these here for openchange */
#ifndef likely
#define likely(x) (x)
#endif
#ifndef unlikely
#define unlikely(x) (x)
#endif

#define NT_STATUS_IS_OK(x) (likely(NT_STATUS_V(x) == 0))
#define NT_STATUS_IS_ERR(x) (unlikely((NT_STATUS_V(x) & 0xc0000000) == 0xc0000000))
#define NT_STATUS_EQUAL(x,y) (NT_STATUS_V(x) == NT_STATUS_V(y))

/*
 * These macros (with the embedded return) are considered poor coding
 * style per README.Coding
 *
 * Please do not use them in new code, and do not rely on them in
 * projects external to Samba as they will go away at some point.
 */

#define NT_STATUS_HAVE_NO_MEMORY(x) do { \
	if (unlikely(!(x))) {		\
		return NT_STATUS_NO_MEMORY;\
	}\
} while (0)

/* This varient is for when you want to free a local
   temporary memory context in the error path */
#define NT_STATUS_HAVE_NO_MEMORY_AND_FREE(x, ctx) do {	\
	if (!(x)) {\
		talloc_free(ctx); \
		return NT_STATUS_NO_MEMORY;\
	}\
} while (0)

#define NT_STATUS_IS_OK_RETURN(x) do { \
	if (NT_STATUS_IS_OK(x)) {\
		return x;\
	}\
} while (0)

#define NT_STATUS_NOT_OK_RETURN(x) do { \
	if (!NT_STATUS_IS_OK(x)) {\
		return x;\
	}\
} while (0)

#define NT_STATUS_NOT_OK_RETURN_AND_FREE(x, ctx) do {	\
	if (!NT_STATUS_IS_OK(x)) {\
		talloc_free(ctx); \
		return x;\
	}\
} while (0)

#define NT_STATUS_IS_ERR_RETURN(x) do { \
	if (NT_STATUS_IS_ERR(x)) {\
		return x;\
	}\
} while (0)

#define NT_STATUS_NOT_ERR_RETURN(x) do { \
	if (!NT_STATUS_IS_ERR(x)) {\
		return x;\
	}\
} while (0)

/* this defines special NTSTATUS codes to represent DOS errors.  I
   have chosen this macro to produce status codes in the invalid
   NTSTATUS range */
#define NT_STATUS_DOS(class, code) NT_STATUS(0xF1000000 | ((class)<<16) | code)
#define NT_STATUS_IS_DOS(status) ((NT_STATUS_V(status) & 0xFF000000) == 0xF1000000)
#define NT_STATUS_DOS_CLASS(status) ((NT_STATUS_V(status) >> 16) & 0xFF)
#define NT_STATUS_DOS_CODE(status) (NT_STATUS_V(status) & 0xFFFF)

/* define ldap error codes as NTSTATUS codes */
#define NT_STATUS_LDAP(code) NT_STATUS(0xF2000000 | code)
#define NT_STATUS_IS_LDAP(status) ((NT_STATUS_V(status) & 0xFF000000) == 0xF2000000)
#define NT_STATUS_LDAP_CODE(status) (NT_STATUS_V(status) & ~0xFF000000)

#define NT_STATUS_IS_RPC(status) \
	(((NT_STATUS_V(status) & 0xFFFF) == 0xC0020000) || \
	 ((NT_STATUS_V(status) & 0xFFFF) == 0xC0030000))

#endif /* _NTSTATUS_H */
