/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - rename

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
  rename a set of files
*/
NTSTATUS pvfs_rename(struct ntvfs_module_context *ntvfs,
		     struct smbsrv_request *req, union smb_rename *ren)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	NTSTATUS status;
	struct pvfs_filename *name1, *name2;

	if (ren->generic.level != RAW_RENAME_RENAME) {
		return NT_STATUS_INVALID_LEVEL;
	}

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, ren->rename.in.pattern1, 0, &name1);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = pvfs_resolve_name(pvfs, req, ren->rename.in.pattern2, 0, &name2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (name1->has_wildcard || name2->has_wildcard) {
		DEBUG(3,("Rejecting wildcard rename '%s' -> '%s'\n", 
			 ren->rename.in.pattern1, ren->rename.in.pattern2));
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (!name1->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (name2->exists) {
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	if (rename(name1->full_name, name2->full_name) != 0) {
		return pvfs_map_errno(pvfs, errno);
	}
	
	return NT_STATUS_OK;
}
