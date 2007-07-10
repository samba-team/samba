/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - unlink

   Copyright (C) Andrew Tridgell 2004

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

#include "includes.h"
#include "vfs_posix.h"
#include "system/dir.h"


/*
  unlink a stream
 */
static NTSTATUS pvfs_unlink_stream(struct pvfs_state *pvfs, 
				   struct ntvfs_request *req,
				   struct pvfs_filename *name, 
				   uint16_t attrib)
{
	NTSTATUS status;
	struct odb_lock *lck;

	if (!name->stream_exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* make sure its matches the given attributes */
	status = pvfs_match_attrib(pvfs, name, attrib, 0);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = pvfs_can_delete(pvfs, req, name, &lck);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	return pvfs_stream_delete(pvfs, name, -1);
}


/*
  unlink one file
*/
static NTSTATUS pvfs_unlink_one(struct pvfs_state *pvfs, 
				struct ntvfs_request *req,
				const char *unix_path, 
				const char *fname, uint32_t attrib)
{
	struct pvfs_filename *name;
	NTSTATUS status;
	struct odb_lock *lck;

	/* get a pvfs_filename object */
	status = pvfs_resolve_partial(pvfs, req, 
				      unix_path, fname, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* make sure its matches the given attributes */
	status = pvfs_match_attrib(pvfs, name, attrib, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(name);
		return status;
	}

	status = pvfs_can_delete(pvfs, req, name, &lck);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(name);
		return status;
	}

	if (name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY) {
		talloc_free(name);
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	}

	if (name->st.st_nlink == 1) {
		status = pvfs_xattr_unlink_hook(pvfs, name->full_name);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* finally try the actual unlink */
	if (unlink(name->full_name) == -1) {
		status = pvfs_map_errno(pvfs, errno);
	}

	if (NT_STATUS_IS_OK(status)) {
		notify_trigger(pvfs->notify_context, 
			       NOTIFY_ACTION_REMOVED, 
			       FILE_NOTIFY_CHANGE_FILE_NAME,
			       name->full_name);
	}

	talloc_free(name);

	return status;
}

/*
  delete a file - the dirtype specifies the file types to include in the search. 
  The name can contain CIFS wildcards, but rarely does (except with OS/2 clients)
*/
NTSTATUS pvfs_unlink(struct ntvfs_module_context *ntvfs,
		     struct ntvfs_request *req,
		     union smb_unlink *unl)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_dir *dir;
	NTSTATUS status;
	uint32_t total_deleted=0;
	struct pvfs_filename *name;
	const char *fname;
	off_t ofs;

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, unl->unlink.in.pattern, 
				   PVFS_RESOLVE_WILDCARD | PVFS_RESOLVE_STREAMS, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->exists && !name->has_wildcard) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (name->exists && 
	    (name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY)) {
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	}

	if (name->stream_name) {
		return pvfs_unlink_stream(pvfs, req, name, unl->unlink.in.attrib);
	}

	/* get list of matching files */
	status = pvfs_list_start(pvfs, name, req, &dir);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = NT_STATUS_NO_SUCH_FILE;

	ofs = 0;

	while ((fname = pvfs_list_next(dir, &ofs))) {
		/* this seems to be a special case */
		if ((unl->unlink.in.attrib & FILE_ATTRIBUTE_DIRECTORY) &&
		    (ISDOT(fname) || ISDOTDOT(fname))) {
			return NT_STATUS_OBJECT_NAME_INVALID;
		}

		status = pvfs_unlink_one(pvfs, req, pvfs_list_unix_path(dir), fname, unl->unlink.in.attrib);
		if (NT_STATUS_IS_OK(status)) {
			total_deleted++;
		}
	}

	if (total_deleted > 0) {
		status = NT_STATUS_OK;
	}

	return status;
}


