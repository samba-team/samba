/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - mkdir and rmdir

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
  create a directory
*/
NTSTATUS pvfs_mkdir(struct ntvfs_module_context *ntvfs,
		    struct smbsrv_request *req, union smb_mkdir *md)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	NTSTATUS status;
	struct pvfs_filename *name;
	mode_t mode;

	if (md->generic.level != RAW_MKDIR_MKDIR) {
		return NT_STATUS_INVALID_LEVEL;
	}

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, md->mkdir.in.path, 
				   PVFS_RESOLVE_NO_WILDCARD, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (name->exists) {
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	mode = pvfs_fileperms(pvfs, FILE_ATTRIBUTE_DIRECTORY);

	if (mkdir(name->full_name, mode) == -1) {
		return pvfs_map_errno(pvfs, errno);
	}

	return NT_STATUS_OK;
}

/*
  remove a directory
*/
NTSTATUS pvfs_rmdir(struct ntvfs_module_context *ntvfs,
		    struct smbsrv_request *req, struct smb_rmdir *rd)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	NTSTATUS status;
	struct pvfs_filename *name;

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, rd->in.path, 
				   PVFS_RESOLVE_NO_WILDCARD, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (rmdir(name->full_name) == -1) {
		return pvfs_map_errno(pvfs, errno);
	}

	return NT_STATUS_OK;
}
