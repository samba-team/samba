#ifndef _TALLOC_H_
#define _TALLOC_H_
/* 
   Unix SMB/Netbios implementation.
   Version 3.0
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

struct talloc_chunk {
	struct talloc_chunk *next;
	size_t size;
	void *ptr;
};


/**
 * talloc allocation pool.  All allocated blocks can be freed in one go.
 **/
typedef struct {
	struct talloc_chunk *list;
	size_t total_alloc_size;

	/** The name recorded for this pool, if any.  Should describe
	 * the purpose for which it was allocated.  The string is
	 * allocated within the pool. **/
	char *name;
} TALLOC_CTX;

TALLOC_CTX *talloc_init_named(char const *fmt, ...) PRINTF_ATTRIBUTE(1, 2);

char *talloc_vasprintf(TALLOC_CTX *t, const char *fmt, va_list ap)
	PRINTF_ATTRIBUTE(2, 0);

char *talloc_asprintf(TALLOC_CTX *t, const char *fmt, ...)
	PRINTF_ATTRIBUTE(2, 3);

/** @} */

#endif /* ndef _TALLOC_H_ */
