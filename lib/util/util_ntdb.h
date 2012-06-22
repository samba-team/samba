/*
   Unix SMB/CIFS implementation.

   tdb utility functions

   Copyright (C) Rusty Russell 2012

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

#ifndef _____LIB_UTIL_UTIL_NTDB_H__
#define _____LIB_UTIL_UTIL_NTDB_H__
#include <ntdb.h>
#include <talloc.h>

struct loadparm_context;
union ntdb_attribute;

/***************************************************************
 Open an NTDB using talloc: it will be allocated off the context, and
 all NTDB_DATA.dptr are allocated as children of the ntdb context.
 Sets up a logging function for you, and uses lp_ctx to decide whether
 to disable mmap.

 Any extra ntdb attributes can be handed through attr; usually it's
 NULL, ntdb_new provides logging and allocator attributes.

 The destructor for the struct ntdb_context will do ntdb_close()
 for you.
****************************************************************/
struct ntdb_context *ntdb_new(TALLOC_CTX *ctx,
			      const char *name, int ntdb_flags,
			      int open_flags, mode_t mode,
			      union ntdb_attribute *attr,
			      struct loadparm_context *lp_ctx);
#endif /* _____LIB_UTIL_UTIL_NTDB_H__ */
