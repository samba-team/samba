/* 
   Unix SMB/CIFS implementation.

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
/*
  utility functions for posix backend
*/

#include "includes.h"
#include "vfs_posix.h"

/*
  return True if a string contains one of the CIFS wildcard characters
*/
BOOL pvfs_has_wildcard(const char *str)
{
	if (strpbrk(str, "*?<>\"")) {
		return True;
	}
	return False;
}

/*
  map a unix errno to a NTSTATUS
*/
NTSTATUS pvfs_map_errno(struct pvfs_state *pvfs, int unix_errno)
{
	return map_nt_error_from_unix(unix_errno);
}


/*
  check if a filename has an attribute matching the given attribute search value
  this is used by calls like unlink and search which take an attribute
  and only include special files if they match the given attribute
*/
BOOL pvfs_match_attrib(struct pvfs_state *pvfs, struct pvfs_filename *name, uint32_t attrib)
{
	/* TODO: add attribute conversion */
	return True;
}
