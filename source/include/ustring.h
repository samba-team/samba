/* 
   Dynamic Unicode Strings
   Copyright (C) Elrond                            2000
   
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

#ifndef _USTRING_H
#define _USTRING_H 

/*
 * dynamic Unicode strings
 *
 * these are length oriented, but also have
 * a terminating NUL.
 *
 * NUL-chars in the middle are okay and allowed
 *
 * if you modify these directly:
 * - alloc must always be >= len + 1
 *   (so the final NUL fits)
 *   call ustring_grow(str, new_alloc) if neccessary
 * - always keep len correct
 * - always keep a NUL-char at the end
 *   (i.e. str->str[str->len] = 0)
 *
 */

typedef struct
{
	size_t  len;
	uint16 *str;
	size_t  alloc; /* always >= len + 1 */
} UString;


UString  *ustring_new               (const char *init);
void      ustring_free              (UString *str);
UString  *ustring_grow              (UString *str, size_t new_alloc);
UString  *ustring_shrink            (UString *str);
UString  *ustring_assign            (UString *str,
				     const uint16 *src, size_t len);
UString  *ustring_assign_ascii      (UString *str,
				     const char *src, size_t len);
UString  *ustring_assign_ascii_str  (UString *str, const char *src);
UString  *ustring_dup               (const UString *str);
int       ustring_compare           (const UString *a, const UString *b);
int       ustring_compare_case      (const UString *a, const UString *b);
UString  *ustring_append_c          (UString *str, uint16 c);
UString  *ustring_sync_len          (UString *str);
UString  *ustring_upper             (UString *str);
UString  *ustring_lower             (UString *str);
BOOL      ustring_equal             (const UString *s1, const UString *s2);


#endif /* _USTRING_H */
