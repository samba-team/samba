/* 
   Unix SMB/CIFS implementation.
   Safe string handling routines.
   Copyright (C) Andrew Tridgell 1994-1998
   
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

char * __unsafe_string_function_usage_here__(void);

#if 0 && defined __GNUC__ && __GNUC__ >= 2 && defined __OPTIMIZE__

#define pstrcpy(d,s) ((sizeof(d) != sizeof(pstring) && sizeof(d) != sizeof(char *)) ? __unsafe_string_function_usage_here__() : safe_strcpy((d), (s),sizeof(pstring)-1))
#define pstrcat(d,s) ((sizeof(d) != sizeof(pstring) && sizeof(d) != sizeof(char *)) ? __unsafe_string_function_usage_here__() : safe_strcat((d), (s),sizeof(pstring)-1))
#define fstrcpy(d,s) ((sizeof(d) != sizeof(fstring) && sizeof(d) != sizeof(char *)) ? __unsafe_string_function_usage_here__() : safe_strcpy((d),(s),sizeof(fstring)-1))
#define fstrcat(d,s) ((sizeof(d) != sizeof(fstring) && sizeof(d) != sizeof(char *)) ? __unsafe_string_function_usage_here__() : safe_strcat((d),(s),sizeof(fstring)-1))

#define fstrterminate(d) ((sizeof(d) != sizeof(fstring) && sizeof(d) != sizeof(char *)) ? __unsafe_string_function_usage_here__() : (((d)[sizeof(fstring)-1]) = '\0'))
#define pstrterminate(d) ((sizeof(d) != sizeof(pstring) && sizeof(d) != sizeof(char *)) ? __unsafe_string_function_usage_here__() : (((d)[sizeof(pstring)-1]) = '\0'))

#define wpstrcpy(d,s) ((sizeof(d) != sizeof(wpstring) && sizeof(d) != sizeof(smb_ucs2_t *)) ? __unsafe_string_function_usage_here__() : safe_strcpy_w((d),(s),sizeof(wpstring)))
#define wpstrcat(d,s) ((sizeof(d) != sizeof(wpstring) && sizeof(d) != sizeof(smb_ucs2_t *)) ? __unsafe_string_function_usage_here__() : safe_strcat_w((d),(s),sizeof(wpstring)))
#define wfstrcpy(d,s) ((sizeof(d) != sizeof(wfstring) && sizeof(d) != sizeof(smb_ucs2_t *)) ? __unsafe_string_function_usage_here__() : safe_strcpy_w((d),(s),sizeof(wfstring)))
#define wfstrcat(d,s) ((sizeof(d) != sizeof(wfstring) && sizeof(d) != sizeof(smb_ucs2_t *)) ? __unsafe_string_function_usage_here__() : safe_strcat_w((d),(s),sizeof(wfstring)))

#else

#define pstrcpy(d,s) safe_strcpy((d), (s),sizeof(pstring)-1)
#define pstrcat(d,s) safe_strcat((d), (s),sizeof(pstring)-1)
#define fstrcpy(d,s) safe_strcpy((d),(s),sizeof(fstring)-1)
#define fstrcat(d,s) safe_strcat((d),(s),sizeof(fstring)-1)

#define fstrterminate(d) (((d)[sizeof(fstring)-1]) = '\0')
#define pstrterminate(d) (((d)[sizeof(pstring)-1]) = '\0')

#define wpstrcpy(d,s) safe_strcpy_w((d),(s),sizeof(wpstring))
#define wpstrcat(d,s) safe_strcat_w((d),(s),sizeof(wpstring))
#define wfstrcpy(d,s) safe_strcpy_w((d),(s),sizeof(wfstring))
#define wfstrcat(d,s) safe_strcat_w((d),(s),sizeof(wfstring))

#endif

/* replace some string functions with multi-byte
   versions */
#define strlower(s) strlower_m(s)
#define strupper(s) strupper_m(s)

/* the addition of the DEVELOPER checks in safe_strcpy means we must
 * update a lot of code. To make this a little easier here are some
 * functions that provide the lengths with less pain */
#define pstrcpy_base(dest, src, pstring_base) \
    safe_strcpy(dest, src, sizeof(pstring)-PTR_DIFF(dest,pstring_base)-1)

#define push_pstring_base(dest, src, pstring_base) \
    push_ascii(dest, src, sizeof(pstring)-PTR_DIFF(dest,pstring_base)-1, STR_TERMINATE)

#endif
