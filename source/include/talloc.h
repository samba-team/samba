#ifndef _TALLOC_H_
#define _TALLOC_H_
/* 
   Unix SMB/CIFS implementation.
   Samba temporary memory allocation functions
   Copyright (C) Andrew Tridgell 2000
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   
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

/**
 * @ingroup talloc
 * @{
 * @sa talloc.c
 */

/**
 * talloc allocation pool.  All allocated blocks can be freed in one go.
 **/
typedef struct talloc_ctx TALLOC_CTX;

TALLOC_CTX *talloc_init_named(char const *fmt, ...) PRINTF_ATTRIBUTE(1, 2);

char *talloc_vasprintf(TALLOC_CTX *t, const char *fmt, va_list ap)
	PRINTF_ATTRIBUTE(2, 0);

char *talloc_asprintf(TALLOC_CTX *t, const char *fmt, ...)
	PRINTF_ATTRIBUTE(2, 3);

char *talloc_vasprintf_append(TALLOC_CTX *t, char *, const char *, va_list ap)
	PRINTF_ATTRIBUTE(3, 0);

char *talloc_asprintf_append(TALLOC_CTX *t, char *, const char *, ...)
	PRINTF_ATTRIBUTE(3, 4);

/** @} */

#endif /* ndef _TALLOC_H_ */
