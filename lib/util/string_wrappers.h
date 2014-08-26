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

#define strlcpy_base(dest, src, base, size) \
do { \
	const char *_strlcpy_base_src = (const char *)src; \
	strlcpy((dest), _strlcpy_base_src? _strlcpy_base_src : "", (size)-PTR_DIFF((dest),(base))); \
} while (0)

/* String copy functions - macro hell below adds 'type checking' (limited,
   but the best we can do in C) */

#define fstrcpy(d,s) \
do { \
	const char *_fstrcpy_src = (const char *)(s); \
	strlcpy((d),_fstrcpy_src ? _fstrcpy_src : "",sizeof(fstring)); \
} while (0)

#define fstrcat(d,s) \
do { \
	const char *_fstrcat_src = (const char *)(s); \
	strlcat((d),_fstrcat_src ? _fstrcat_src : "",sizeof(fstring)); \
} while (0)
#define unstrcpy(d,s) \
do { \
	const char *_unstrcpy_src = (const char *)(s); \
	strlcpy((d),_unstrcpy_src ? _unstrcpy_src : "",sizeof(unstring)); \
} while (0)

#ifdef HAVE_COMPILER_WILL_OPTIMIZE_OUT_FNS

/* We need a number of different prototypes for our
   non-existent fuctions */
char * __unsafe_string_function_usage_here__(void);

size_t __unsafe_string_function_usage_here_size_t__(void);

NTSTATUS __unsafe_string_function_usage_here_NTSTATUS__(void);

#define CHECK_STRING_SIZE(d, len) (sizeof(d) != (len) && sizeof(d) != sizeof(char *))

/* if the compiler will optimize out function calls, then use this to tell if we are
   have the correct types (this works only where sizeof() returns the size of the buffer, not
   the size of the pointer). */

#define push_string_check(dest, src, dest_len, flags) \
    (CHECK_STRING_SIZE(dest, dest_len) \
    ? __unsafe_string_function_usage_here_size_t__() \
    : push_string_check_fn(dest, src, dest_len, flags))

#define srvstr_push(base_ptr, smb_flags2, dest, src, dest_len, flags, ret_len) \
    (CHECK_STRING_SIZE(dest, dest_len) \
    ? __unsafe_string_function_usage_here_NTSTATUS__() \
    : srvstr_push_fn(base_ptr, smb_flags2, dest, src, dest_len, flags, ret_len))

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

#define push_string_check push_string_check_fn
#define srvstr_push srvstr_push_fn
#define checked_strlcpy strlcpy

#endif

#endif
