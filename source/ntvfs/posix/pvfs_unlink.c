/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - unlink

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
  unlink one file
*/
static NTSTATUS pvfs_unlink_one(struct pvfs_state *pvfs, TALLOC_CTX *mem_ctx,
				const char *unix_path, 
				const char *fname, uint32_t attrib)
{
	struct pvfs_filename *name;
	NTSTATUS status;

	/* get a pvfs_filename object */
	status = pvfs_resolve_partial(pvfs, mem_ctx, 
				      unix_path, fname, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* make sure its matches the given attributes */
	if (!pvfs_match_attrib(pvfs, name, attrib)) {
		talloc_free(name);
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* finally try the actual unlink */
	if (unlink(name->full_name) == -1) {
		status = pvfs_map_errno(pvfs, errno);
	}

	talloc_free(name);

	return status;
}

/*
  delete a file - the dirtype specifies the file types to include in the search. 
  The name can contain CIFS wildcards, but rarely does (except with OS/2 clients)
*/
NTSTATUS pvfs_unlink(struct ntvfs_module_context *ntvfs,
		     struct smbsrv_request *req, struct smb_unlink *unl)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_dir *dir;
	NTSTATUS status;
	uint32_t i, total_deleted=0;
	struct pvfs_filename *name;

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, unl->in.pattern, 0, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->exists && !name->has_wildcard) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (pvfs_is_open(pvfs, name)) {
		return NT_STATUS_SHARING_VIOLATION;
	}

	dir = talloc_p(req, struct pvfs_dir);
	if (dir == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* get list of matching files */
	status = pvfs_list(pvfs, name, dir);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (dir->count == 0) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	for (i=0;i<dir->count;i++) {
		status = pvfs_unlink_one(pvfs, req, dir->unix_path, 
					 dir->names[i], unl->in.attrib);
		if (NT_STATUS_IS_OK(status)) {
			total_deleted++;
		}
	}

	if (total_deleted == 0) {
		return status;
	}

	return NT_STATUS_OK;
}


