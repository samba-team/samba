/*
   Unix SMB/Netbios implementation.
   Version 1.9.
   SMB NT transaction handling
   Copyright (C) Jeremy Allison 1994-1998

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

#include "includes.h"
#include "rpc_parse.h"
#include "sids.h"



/****************************************************************************
 Reply to query a security descriptor from an fsp. If it succeeds it allocates
 the space for the return elements and returns True.
****************************************************************************/

size_t get_nt_acl(files_struct *fsp, SEC_DESC **ppdesc)
{
  SMB_STRUCT_STAT sbuf;
  mode_t mode;

    if(fsp->is_directory || fsp->fd == -1) {
      if(dos_stat(fsp->fsp_name, &sbuf) != 0) {
        return 0;
      }
    } else {
      if(fsp->conn->vfs_ops.fstat(fsp->fd,&sbuf) != 0) {
        return 0;
      }
    }

    if(fsp->is_directory) {
      /*
       * For directory ACLs we also add in the inherited permissions
       * ACE entries. These are the permissions a file would get when
       * being created in the directory.
       */
      mode = unix_mode( fsp->conn, FILE_ATTRIBUTE_ARCHIVE, fsp->fsp_name);
    }
    else
    {
	    mode = sbuf.st_mode;
    }
  return convertperms_unix_to_sd(&sbuf, fsp->is_directory, mode, ppdesc);
}

