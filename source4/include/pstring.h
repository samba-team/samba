/* 
   samba -- Unix SMB/CIFS implementation.

   ugly string types from Samba3. Will be removed 
   with glee when we finally don't use them.
   
   Copyright (C) Andrew Tridgell              1992-2000
   Copyright (C) John H Terpstra              1996-2000
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000
   Copyright (C) Paul Ashton                  1998-2000
   Copyright (C) Martin Pool		      2002
   
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

#ifndef _PSTRING
#define _PSTRING

#define PSTRING_LEN 1024
#define FSTRING_LEN 256

_DEPRECATED_ typedef char pstring[PSTRING_LEN];
_DEPRECATED_ typedef char fstring[FSTRING_LEN];

#define pstrcpy(d,s) safe_strcpy((d),(s),sizeof(pstring)-1)
#define pstrcat(d,s) safe_strcat((d),(s),sizeof(pstring)-1)
#define fstrcpy(d,s) safe_strcpy((d),(s),sizeof(fstring)-1)
#define fstrcat(d,s) safe_strcat((d),(s),sizeof(fstring)-1)

#endif
