/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - 8.3 name routines

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

#include "include/includes.h"
#include "vfs_posix.h"


/*
  return the short name for a given entry in a directory
*/
char *pvfs_short_name(struct pvfs_state *pvfs, TALLOC_CTX *mem_ctx, 
		      const char *unix_path, const char *name)
{
	return talloc_strndup(mem_ctx, name, 12);
}
