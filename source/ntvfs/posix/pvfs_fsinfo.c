/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - fsinfo

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
  return filesystem space info
*/
NTSTATUS pvfs_fsinfo(struct ntvfs_module_context *ntvfs,
		     struct smbsrv_request *req, union smb_fsinfo *fs)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct stat st;

	if (fs->generic.level != RAW_QFS_GENERIC) {
		return ntvfs_map_fsinfo(req, fs, ntvfs);
	}

	if (sys_fsusage(pvfs->base_directory, 
			&fs->generic.out.blocks_free, 
			&fs->generic.out.blocks_total) == -1) {
		return pvfs_map_errno(pvfs, errno);
	}

	fs->generic.out.block_size = 512;

	if (stat(pvfs->base_directory, &st) != 0) {
		return NT_STATUS_DISK_CORRUPT_ERROR;
	}
	
	fs->generic.out.fs_id = st.st_ino;
	unix_to_nt_time(&fs->generic.out.create_time, st.st_ctime);
	fs->generic.out.serial_number = st.st_ino;
	fs->generic.out.fs_attr = 0;
	fs->generic.out.max_file_component_length = 255;
	fs->generic.out.device_type = 0;
	fs->generic.out.device_characteristics = 0;
	fs->generic.out.quota_soft = 0;
	fs->generic.out.quota_hard = 0;
	fs->generic.out.quota_flags = 0;
	fs->generic.out.volume_name = talloc_strdup(req, pvfs->share_name);
	fs->generic.out.fs_type = req->tcon->fs_type;

	return NT_STATUS_OK;
}
