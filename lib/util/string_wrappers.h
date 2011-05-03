/*
   Unix SMB/CIFS implementation.

   string wrappers, for checking string sizes

   Copyright (C) Andrew Tridgell 1994-2011
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

#ifndef _STRING_WRAPPERS_H
#define _STRING_WRAPPERS_H

/* We need a number of different prototypes for our
   non-existant fuctions */
char * __unsafe_string_function_usage_here__(void);

size_t __unsafe_string_function_usage_here_size_t__(void);

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

#define fstrcpy(d,s) strlcpy((d),(s) ? (s) : "",sizeof(fstring))
#define fstrcat(d,s) strlcpy((d),(s) ? (s) : "",sizeof(fstring))
#define nstrcpy(d,s) strlcpy((d), (s) ? (s) : "",sizeof(nstring))
#define unstrcpy(d,s) strlcpy((d), (s) ? (s) : "",sizeof(unstring))

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

/* This allows the developer to choose to check the arguments to
   strlcpy.  if the compiler will optimize out function calls, then
   use this to tell if we are have the correct size buffer (this works only
   where sizeof() returns the size of the buffer, not the size of the
   pointer), so stack and static variables only */

#define checked_strlcpy(dest, src, size) \
    (sizeof(dest) != (size) \
    ? __unsafe_string_function_usage_here_size_t__() \
     : strlcpy(dest, src, size))

#else

#define safe_strcpy safe_strcpy_fn
#define safe_strcat safe_strcat_fn
#define push_string_check push_string_check_fn
#define clistr_push clistr_push_fn
#define clistr_pull clistr_pull_fn
#define srvstr_push srvstr_push_fn
#define checked_strlcpy strlcpy

#endif

#endif
