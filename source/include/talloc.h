#ifndef _TALLOC_H_
#define _TALLOC_H_
/* 
   Unix SMB/CIFS implementation.
   Samba temporary memory allocation functions

   Copyright (C) Andrew Tridgell 2004
   
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

/* this is only needed for compatibility with the old talloc */
typedef void TALLOC_CTX;

/* useful macros for creating type checked pointers */
#define talloc_p(ctx, type) (type *)talloc(ctx, sizeof(type))
#define talloc_array_p(ctx, type, count) (type *)talloc_array(ctx, sizeof(type), count)
#define talloc_realloc_p(p, type, count) (type *)talloc_realloc_array(p, sizeof(type), count)

#define talloc_destroy(ctx) talloc_free(ctx)

#define malloc_p(type) (type *)malloc(sizeof(type))
#define malloc_array_p(type, count) (type *)realloc_array(NULL, sizeof(type), count)
#define realloc_p(p, type, count) (type *)realloc_array(p, sizeof(type), count)

#endif

