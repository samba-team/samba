/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - read

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
  approximately map a struct pvfs_filename to a generic fileinfo struct
*/
static NTSTATUS pvfs_map_fileinfo(struct pvfs_state *pvfs, TALLOC_CTX *mem_ctx,
				  struct pvfs_filename *name, union smb_fileinfo *info)
{
	info->generic.out.create_time = name->dos.create_time;
	info->generic.out.access_time = name->dos.access_time;
	info->generic.out.write_time = name->dos.write_time;
	info->generic.out.change_time = name->dos.change_time;

	info->generic.out.alloc_size = name->dos.alloc_size;
	info->generic.out.size = name->st.st_size;
	info->generic.out.attrib = name->dos.attrib;
	info->generic.out.nlink = name->dos.nlink;
	info->generic.out.directory = (name->dos.attrib&FILE_ATTRIBUTE_DIRECTORY)?1:0;
	info->generic.out.file_id = name->dos.file_id;

	/* REWRITE: TODO stuff in here */
	info->generic.out.delete_pending = 0;
	info->generic.out.ea_size = 0;
	info->generic.out.num_eas = 0;
	info->generic.out.fname.s = name->original_name;
	info->generic.out.alt_fname.s = pvfs_short_name(pvfs, name);
	info->generic.out.compressed_size = name->st.st_size;
	info->generic.out.format = 0;
	info->generic.out.unit_shift = 0;
	info->generic.out.chunk_shift = 0;
	info->generic.out.cluster_shift = 0;
	
	info->generic.out.access_flags = 0;
	info->generic.out.position = 0;
	info->generic.out.mode = 0;
	info->generic.out.alignment_requirement = 0;
	info->generic.out.reparse_tag = 0;

	/* setup a single data stream */
	info->generic.out.num_streams = 1;
	info->generic.out.streams = talloc_array_p(mem_ctx, 
						   struct stream_struct,
						   info->generic.out.num_streams);
	if (!info->generic.out.streams) {
		return NT_STATUS_NO_MEMORY;
	}
	info->generic.out.streams[0].size = name->st.st_size;
	info->generic.out.streams[0].alloc_size = name->st.st_size;
	info->generic.out.streams[0].stream_name.s = talloc_strdup(mem_ctx, "::$DATA");

	return NT_STATUS_OK;
}

/*
  return info on a pathname
*/
NTSTATUS pvfs_qpathinfo(struct smbsrv_request *req, union smb_fileinfo *info)
{
	NTVFS_GET_PRIVATE(pvfs_state, pvfs, req);
	struct pvfs_filename *name;
	NTSTATUS status;

	if (info->generic.level != RAW_FILEINFO_GENERIC) {
		return ntvfs_map_qpathinfo(req, info, pvfs->ops);
	}
	
	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, info->generic.in.fname, PVFS_RESOLVE_NO_WILDCARD, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	return pvfs_map_fileinfo(pvfs, req, name, info);
}

/*
  query info on a open file
*/
NTSTATUS pvfs_qfileinfo(struct smbsrv_request *req, union smb_fileinfo *info)
{
	NTVFS_GET_PRIVATE(pvfs_state, pvfs, req);
	struct pvfs_file *f;
	NTSTATUS status;

	if (info->generic.level != RAW_FILEINFO_GENERIC) {
		return ntvfs_map_qfileinfo(req, info, pvfs->ops);
	}

	f = pvfs_find_fd(req, info->generic.in.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* update the file information */
	status = pvfs_resolve_name_fd(pvfs, f->fd, f->name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	return pvfs_map_fileinfo(pvfs, req, f->name, info);
}
