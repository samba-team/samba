/* 
   Unix SMB/CIFS implementation.
   SMB parameters and setup, plus a whole lot more.
   
   Copyright (C) Andrew Tridgell              2001
   
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

#ifndef _NT_STATUS_H
#define _NT_STATUS_H

/* the following rather strange looking definitions of NTSTATUS and WERROR
   and there in order to catch common coding errors where different error types
   are mixed up. This is especially important as we slowly convert Samba
   from using BOOL for internal functions 
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

#if defined(HAVE_IMMEDIATE_STRUCTURES)
typedef struct {uint32_t v;} WERROR;
#define W_ERROR(x) ((WERROR) { x })
#define W_ERROR_V(x) ((x).v)
#else
typedef uint32_t WERROR;
#define W_ERROR(x) (x)
#define W_ERROR_V(x) (x)
#endif

#define NT_STATUS_IS_OK(x) (NT_STATUS_V(x) == 0)
#define NT_STATUS_IS_ERR(x) ((NT_STATUS_V(x) & 0xc0000000) == 0xc0000000)
/* checking for DOS error mapping here is ugly, but unfortunately the
   alternative is a very intrusive rewrite of the torture code */
#define NT_STATUS_EQUAL(x,y) (NT_STATUS_IS_DOS(x)||NT_STATUS_IS_DOS(y)?ntstatus_dos_equal(x,y):NT_STATUS_V(x) == NT_STATUS_V(y))

#define NT_STATUS_HAVE_NO_MEMORY(x) do { \
	if (!(x)) {\
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

#define W_ERROR_IS_OK(x) (W_ERROR_V(x) == 0)
#define W_ERROR_EQUAL(x,y) (W_ERROR_V(x) == W_ERROR_V(y))

#define W_ERROR_HAVE_NO_MEMORY(x) do { \
	if (!(x)) {\
		return WERR_NOMEM;\
	}\
} while (0)

#define W_ERROR_IS_OK_RETURN(x) do { \
	if (W_ERROR_IS_OK(x)) {\
		return x;\
	}\
} while (0)

#define W_ERROR_NOT_OK_RETURN(x) do { \
	if (!W_ERROR_IS_OK(x)) {\
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

#endif
