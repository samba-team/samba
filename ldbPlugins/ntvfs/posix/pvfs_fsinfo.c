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

#include "includes.h"
#include "vfs_posix.h"


/*
  return filesystem space info
*/
NTSTATUS pvfs_fsinfo(struct ntvfs_module_context *ntvfs,
		     struct smbsrv_request *req, union smb_fsinfo *fs)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	uint64_t blocks_free, blocks_total;
	uint_t bpunit;
	struct stat st;
	const uint16_t block_size = 512;

	/* only some levels need the expensive sys_fsusage() call */
	switch (fs->generic.level) {
	case RAW_QFS_DSKATTR:
	case RAW_QFS_ALLOCATION:
	case RAW_QFS_SIZE_INFO:
	case RAW_QFS_SIZE_INFORMATION:
	case RAW_QFS_FULL_SIZE_INFORMATION:
		if (sys_fsusage(pvfs->base_directory, &blocks_free, &blocks_total) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	default:
		break;
	}

	if (stat(pvfs->base_directory, &st) != 0) {
		return NT_STATUS_DISK_CORRUPT_ERROR;
	}

	/* now fill in the out fields */
	switch (fs->generic.level) {
	case RAW_QFS_GENERIC:
		return NT_STATUS_INVALID_LEVEL;

	case RAW_QFS_DSKATTR:
		/* we need to scale the sizes to fit */
		for (bpunit=64; bpunit<0x10000; bpunit *= 2) {
			if (blocks_total * (double)block_size < bpunit * 512 * 65535.0) {
				break;
			}
		}
		fs->dskattr.out.blocks_per_unit = bpunit;
		fs->dskattr.out.block_size = block_size;
		fs->dskattr.out.units_total = (blocks_total * (double)block_size) / (bpunit * 512);
		fs->dskattr.out.units_free  = (blocks_free  * (double)block_size) / (bpunit * 512);

		/* we must return a maximum of 2G to old DOS systems, or they get very confused */
		if (bpunit > 64 && req->smb_conn->negotiate.protocol <= PROTOCOL_LANMAN2) {
			fs->dskattr.out.blocks_per_unit = 64;
			fs->dskattr.out.units_total = 0xFFFF;
			fs->dskattr.out.units_free = 0xFFFF;
		}
		return NT_STATUS_OK;

	case RAW_QFS_ALLOCATION:
		fs->allocation.out.fs_id = st.st_dev;
		fs->allocation.out.total_alloc_units = blocks_total;
		fs->allocation.out.avail_alloc_units = blocks_free;
		fs->allocation.out.sectors_per_unit = 1;
		fs->allocation.out.bytes_per_sector = block_size;
		return NT_STATUS_OK;

	case RAW_QFS_VOLUME:
		fs->volume.out.serial_number = st.st_ino;
		fs->volume.out.volume_name.s = pvfs->share_name;
		return NT_STATUS_OK;

	case RAW_QFS_VOLUME_INFO:
	case RAW_QFS_VOLUME_INFORMATION:
		unix_to_nt_time(&fs->volume_info.out.create_time, st.st_ctime);
		fs->volume_info.out.serial_number = st.st_ino;
		fs->volume_info.out.volume_name.s = pvfs->share_name;
		return NT_STATUS_OK;

	case RAW_QFS_SIZE_INFO:
	case RAW_QFS_SIZE_INFORMATION:
		fs->size_info.out.total_alloc_units = blocks_total;
		fs->size_info.out.avail_alloc_units = blocks_free;
		fs->size_info.out.sectors_per_unit = 1;
		fs->size_info.out.bytes_per_sector = block_size;
		return NT_STATUS_OK;

	case RAW_QFS_DEVICE_INFO:
	case RAW_QFS_DEVICE_INFORMATION:
		fs->device_info.out.device_type = 0;
		fs->device_info.out.characteristics = 0;
		return NT_STATUS_OK;

	case RAW_QFS_ATTRIBUTE_INFO:
	case RAW_QFS_ATTRIBUTE_INFORMATION:
		fs->attribute_info.out.fs_attr = 0;
		fs->attribute_info.out.max_file_component_length = 255;
		fs->attribute_info.out.fs_type.s = req->tcon->fs_type;
		return NT_STATUS_OK;

	case RAW_QFS_QUOTA_INFORMATION:
		ZERO_STRUCT(fs->quota_information.out.unknown);
		fs->quota_information.out.quota_soft = 0;
		fs->quota_information.out.quota_hard = 0;
		fs->quota_information.out.quota_flags = 0;
		return NT_STATUS_OK;

	case RAW_QFS_FULL_SIZE_INFORMATION:
		fs->full_size_information.out.total_alloc_units = blocks_total;
		fs->full_size_information.out.call_avail_alloc_units = blocks_free;
		fs->full_size_information.out.actual_avail_alloc_units = blocks_free;
		fs->full_size_information.out.sectors_per_unit = 1;
		fs->full_size_information.out.bytes_per_sector = block_size;
		return NT_STATUS_OK;

	case RAW_QFS_OBJECTID_INFORMATION:
		ZERO_STRUCT(fs->objectid_information.out);
		return NT_STATUS_OK;
	}

	return NT_STATUS_INVALID_LEVEL;
}
