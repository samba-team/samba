/* 
   Unix SMB/CIFS implementation.
   Safe string handling routines.
   Copyright (C) Andrew Tridgell 1994-1998
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2003
   
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

#ifndef _SAFE_STRING_H
#define _SAFE_STRING_H

#ifndef _SPLINT_ /* http://www.splint.org */

/* Some macros to ensure people don't use buffer overflow vulnerable string
   functions. */

#ifdef bcopy
#undef bcopy
#endif /* bcopy */
#define bcopy(src,dest,size) __ERROR__XX__NEVER_USE_BCOPY___;

#ifdef strcpy
#undef strcpy
#endif /* strcpy */
#define strcpy(dest,src) __ERROR__XX__NEVER_USE_STRCPY___;

#ifdef strcat
#undef strcat
#endif /* strcat */
#define strcat(dest,src) __ERROR__XX__NEVER_USE_STRCAT___;

#ifdef sprintf
#undef sprintf
#endif /* sprintf */
#define sprintf __ERROR__XX__NEVER_USE_SPRINTF__;

/*
 * strcasecmp/strncasecmp aren't an error, but it means you're not thinking about
 * multibyte. Don't use them. JRA.
 */
#ifdef strcasecmp
#undef strcasecmp
#endif
#define strcasecmp __ERROR__XX__NEVER_USE_STRCASECMP__;

#ifdef strncasecmp
#undef strncasecmp
#endif
#define strncasecmp __ERROR__XX__NEVER_USE_STRNCASECMP__;

#endif /* !_SPLINT_ */

/* We need a number of different prototypes for our 
   non-existant fuctions */
char * __unsafe_string_function_usage_here__(void);

size_t __unsafe_string_function_usage_here_size_t__(void);

size_t __unsafe_string_function_usage_here_char__(void);

#ifdef HAVE_COMPILER_WILL_OPTIMIZE_OUT_FNS

/* if the compiler will optimize out function calls, then use this to tell if we are 
   have the correct types (this works only where sizeof() returns the size of the buffer, not
   the size of the pointer). */

#define CHECK_STRING_SIZE(d, len) (sizeof(d) != (len) && sizeof(d) != sizeof(char *))

#else /* HAVE_COMPILER_WILL_OPTIMIZE_OUT_FNS */

#endif /* HAVE_COMPILER_WILL_OPTIMIZE_OUT_FNS */

#define safe_strcpy_base(dest, src, base, size) \
    safe_strcpy(dest, src, size-PTR_DIFF(dest,base)-1)

/* String copy functions - macro hell below adds 'type checking' (limited,
   but the best we can do in C) */

#define fstrcpy(d,s) safe_strcpy((d),(s),sizeof(fstring)-1)
#define fstrcat(d,s) safe_strcat((d),(s),sizeof(fstring)-1)
#define nstrcpy(d,s) safe_strcpy((d), (s),sizeof(nstring)-1)
#define unstrcpy(d,s) safe_strcpy((d), (s),sizeof(unstring)-1)

/* the addition of the DEVELOPER checks in safe_strcpy means we must
 * update a lot of code. To make this a little easier here are some
 * functions that provide the lengths with less pain */

/* overmalloc_safe_strcpy: DEPRECATED!  Used when you know the
 * destination buffer is longer than maxlength, but you don't know how
 * long.  This is not a good situation, because we can't do the normal
 * sanity checks. Don't use in new code! */

#define overmalloc_safe_strcpy(dest,src,maxlength) \
	safe_strcpy_fn(dest,src,maxlength)

#ifdef HAVE_COMPILER_WILL_OPTIMIZE_OUT_FNS

/* if the compiler will optimize out function calls, then use this to tell if we are 
   have the correct types (this works only where sizeof() returns the size of the buffer, not
   the size of the pointer). */

#define safe_strcpy(d, s, max_len) \
    (CHECK_STRING_SIZE(d, max_len+1) \
    ? __unsafe_string_function_usage_here__() \
    : safe_strcpy_fn((d), (s), (max_len)))

#define safe_strcat(d, s, max_len) \
    (CHECK_STRING_SIZE(d, max_len+1) \
    ? __unsafe_string_function_usage_here__() \
    : safe_strcat_fn((d), (s), (max_len)))

#define push_string_check(dest, src, dest_len, flags) \
    (CHECK_STRING_SIZE(dest, dest_len) \
    ? __unsafe_string_function_usage_here_size_t__() \
    : push_string_check_fn(dest, src, dest_len, flags))

#define pull_string_talloc(ctx, base_ptr, smb_flags2, dest, src, src_len, flags) \
    pull_string_talloc_fn(ctx, base_ptr, smb_flags2, dest, src, src_len, flags)

#define clistr_push(cli, dest, src, dest_len, flags) \
    (CHECK_STRING_SIZE(dest, dest_len) \
    ? __unsafe_string_function_usage_here_size_t__() \
    : clistr_push_fn(cli, dest, src, dest_len, flags))

#define clistr_pull(inbuf, dest, src, dest_len, srclen, flags) \
    (CHECK_STRING_SIZE(dest, dest_len) \
    ? __unsafe_string_function_usage_here_size_t__() \
    : clistr_pull_fn(inbuf, dest, src, dest_len, srclen, flags))

#define srvstr_push(base_ptr, smb_flags2, dest, src, dest_len, flags) \
    (CHECK_STRING_SIZE(dest, dest_len) \
    ? __unsafe_string_function_usage_here_size_t__() \
    : srvstr_push_fn(base_ptr, smb_flags2, dest, src, dest_len, flags))

#else

#define safe_strcpy safe_strcpy_fn
#define safe_strcat safe_strcat_fn
#define push_string_check push_string_check_fn
#define pull_string_talloc pull_string_talloc_fn
#define clistr_push clistr_push_fn
#define clistr_pull clistr_pull_fn
#define srvstr_push srvstr_push_fn

#endif

#endif
