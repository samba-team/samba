/* 
   samba -- Unix SMB/Netbios implementation.
   Safe standardized string types
   
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) John H Terpstra              1996-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Paul Ashton                  1998-2000
   Copyright (C) Martin Pool		      2002
   
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

#ifndef _PSTRING

#define PSTRING_LEN 1024
#define FSTRING_LEN 256

#ifdef PSTRING_SANCTIFY

/* If you define this, pstring and fstring become distinguished types,
 * so that it's harder to accidentally overflow them by for example
 * passing an fstring on the lhs of pstrcpy.
 *
 * To pass them to non-pstring-aware functions, use PSTR and check
 * that the function takes a const.  They should almost never be
 * modified except by special calls.  In those unusual cases, use
 * PSTR_MUTABLE.
 *
 * This is off by default so as not to produce too many warnings.  As
 * the code is vetted it can become the default. */

typedef union { char pstring_contents[PSTRING_LEN]; } pstring[1];
typedef union { char fstring_contents[FSTRING_LEN]; } fstring[1];

#  define PSTR(p) ((const char *) ((p)->pstring_contents))
#  define FSTR(f) ((const char *) ((f)->fstring_contents))

/* Please use the const functions instead if possible. */
#  define PSTR_MUTABLE(p) (((p)->pstring_contents))
#  define FSTR_MUTABLE(f) (((f)->fstring_contents))

#else /* ndef PSTRING_SANCTIFY */

/* Old interface. */

typedef char pstring[PSTRING_LEN];
typedef char fstring[FSTRING_LEN];

#define PSTR(p) ((const char *) p)
#define FSTR(f) ((const char *) f)
#define PSTR_MUTABLE(p) (p)
#define FSTR_MUTABLE(f) (f)

#endif /* ndef PSTRING_SANCTIFY */

#define _PSTRING

#endif /* ndef _PSTRING */
