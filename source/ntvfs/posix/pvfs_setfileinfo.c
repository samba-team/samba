/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - setfileinfo

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
  set info on a open file
*/
NTSTATUS pvfs_setfileinfo(struct ntvfs_module_context *ntvfs,
			  struct smbsrv_request *req, 
			  union smb_setfileinfo *info)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct utimbuf unix_times;
	struct pvfs_file *f;
	uint32_t create_options;
	struct pvfs_filename newstats;
	NTSTATUS status;

	f = pvfs_find_fd(pvfs, req, info->generic.file.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	/* update the file information */
	status = pvfs_resolve_name_fd(pvfs, f->fd, f->name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* we take a copy of the current file stats, then update
	   newstats in each of the elements below. At the end we
	   compare, and make any changes needed */
	newstats = *f->name;

	switch (info->generic.level) {
	case RAW_SFILEINFO_SETATTR:
		if (!null_time(info->setattr.in.write_time)) {
			unix_to_nt_time(&newstats.dos.write_time, info->setattr.in.write_time);
		}
		if (info->setattr.in.attrib != FILE_ATTRIBUTE_NORMAL) {
			newstats.dos.attrib = info->setattr.in.attrib;
		}
  		break;

	case RAW_SFILEINFO_SETATTRE:
	case RAW_SFILEINFO_STANDARD:
		if (!null_time(info->setattre.in.create_time)) {
			unix_to_nt_time(&newstats.dos.create_time, info->setattre.in.create_time);
		}
		if (!null_time(info->setattre.in.access_time)) {
			unix_to_nt_time(&newstats.dos.access_time, info->setattre.in.access_time);
		}
		if (!null_time(info->setattre.in.write_time)) {
			unix_to_nt_time(&newstats.dos.write_time, info->setattre.in.write_time);
		}
  		break;

	case RAW_SFILEINFO_BASIC_INFO:
	case RAW_SFILEINFO_BASIC_INFORMATION:
		if (info->basic_info.in.create_time) {
			newstats.dos.create_time = info->basic_info.in.create_time;
		}
		if (info->basic_info.in.access_time) {
			newstats.dos.access_time = info->basic_info.in.access_time;
		}
		if (info->basic_info.in.write_time) {
			newstats.dos.write_time = info->basic_info.in.write_time;
		}
		if (info->basic_info.in.change_time) {
			newstats.dos.change_time = info->basic_info.in.change_time;
		}
		if (info->basic_info.in.attrib != 0) {
			newstats.dos.attrib = info->basic_info.in.attrib;
		}
  		break;

	case RAW_SFILEINFO_DISPOSITION_INFO:
	case RAW_SFILEINFO_DISPOSITION_INFORMATION:
		if (!(f->access_mask & STD_RIGHT_DELETE_ACCESS)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		create_options = f->create_options;
		if (info->disposition_info.in.delete_on_close) {
			create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
		} else {
			create_options &= ~NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
		}
		return pvfs_change_create_options(pvfs, req, f, create_options);

	case RAW_SFILEINFO_ALLOCATION_INFO:
	case RAW_SFILEINFO_ALLOCATION_INFORMATION:
		newstats.dos.alloc_size = info->allocation_info.in.alloc_size;
		break;

	case RAW_SFILEINFO_END_OF_FILE_INFO:
	case RAW_SFILEINFO_END_OF_FILE_INFORMATION:
		newstats.st.st_size = info->end_of_file_info.in.size;
		break;

	case RAW_SFILEINFO_POSITION_INFORMATION:
		f->position = info->position_information.in.position;
		break;

	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	/* possibly change the file size */
	if (newstats.st.st_size != f->name->st.st_size) {
		if (f->name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY) {
			return NT_STATUS_FILE_IS_A_DIRECTORY;
		}
		if (ftruncate(f->fd, newstats.st.st_size) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	/* possibly change the file timestamps */
	ZERO_STRUCT(unix_times);
	if (newstats.dos.access_time != f->name->dos.access_time) {
		unix_times.actime = nt_time_to_unix(newstats.dos.access_time);
	}
	if (newstats.dos.write_time != f->name->dos.write_time) {
		unix_times.modtime = nt_time_to_unix(newstats.dos.write_time);
	}
	if (unix_times.actime != 0 || unix_times.modtime != 0) {
		if (utime(f->name->full_name, &unix_times) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	/* possibly change the attribute */
	if (newstats.dos.attrib != f->name->dos.attrib) {
		mode_t mode = pvfs_fileperms(pvfs, newstats.dos.attrib);
		if (f->name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY) {
			/* ignore on directories for now */
			return NT_STATUS_OK;
		}
		if (fchmod(f->fd, mode) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}


	return NT_STATUS_OK;
}


/*
  set info on a pathname
*/
NTSTATUS pvfs_setpathinfo(struct ntvfs_module_context *ntvfs,
			  struct smbsrv_request *req, union smb_setfileinfo *info)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_filename *name;
	struct pvfs_filename newstats;
	NTSTATUS status;
	struct utimbuf unix_times;

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, info->generic.file.fname, 
				   PVFS_RESOLVE_NO_WILDCARD, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}


	/* we take a copy of the current file stats, then update
	   newstats in each of the elements below. At the end we
	   compare, and make any changes needed */
	newstats = *name;

	switch (info->generic.level) {
	case RAW_SFILEINFO_SETATTR:
		if (!null_time(info->setattr.in.write_time)) {
			unix_to_nt_time(&newstats.dos.write_time, info->setattr.in.write_time);
		}
		if (info->setattr.in.attrib != FILE_ATTRIBUTE_NORMAL) {
			newstats.dos.attrib = info->setattr.in.attrib;
		}
  		break;

	case RAW_SFILEINFO_SETATTRE:
	case RAW_SFILEINFO_STANDARD:
		if (!null_time(info->setattre.in.create_time)) {
			unix_to_nt_time(&newstats.dos.create_time, info->setattre.in.create_time);
		}
		if (!null_time(info->setattre.in.access_time)) {
			unix_to_nt_time(&newstats.dos.access_time, info->setattre.in.access_time);
		}
		if (!null_time(info->setattre.in.write_time)) {
			unix_to_nt_time(&newstats.dos.write_time, info->setattre.in.write_time);
		}
  		break;

	case RAW_SFILEINFO_BASIC_INFO:
	case RAW_SFILEINFO_BASIC_INFORMATION:
		if (info->basic_info.in.create_time) {
			newstats.dos.create_time = info->basic_info.in.create_time;
		}
		if (info->basic_info.in.access_time) {
			newstats.dos.access_time = info->basic_info.in.access_time;
		}
		if (info->basic_info.in.write_time) {
			newstats.dos.write_time = info->basic_info.in.write_time;
		}
		if (info->basic_info.in.change_time) {
			newstats.dos.change_time = info->basic_info.in.change_time;
		}
		if (info->basic_info.in.attrib != 0) {
			newstats.dos.attrib = info->basic_info.in.attrib;
		}
  		break;

	case RAW_SFILEINFO_ALLOCATION_INFO:
	case RAW_SFILEINFO_ALLOCATION_INFORMATION:
		newstats.dos.alloc_size = info->allocation_info.in.alloc_size;
		break;

	case RAW_SFILEINFO_END_OF_FILE_INFO:
	case RAW_SFILEINFO_END_OF_FILE_INFORMATION:
		newstats.st.st_size = info->end_of_file_info.in.size;
		break;

	case RAW_SFILEINFO_DISPOSITION_INFO:
	case RAW_SFILEINFO_DISPOSITION_INFORMATION:
	case RAW_SFILEINFO_POSITION_INFORMATION:
		return NT_STATUS_OK;

	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	/* possibly change the file size */
	if (newstats.st.st_size != name->st.st_size) {
		if (truncate(name->full_name, newstats.st.st_size) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	/* possibly change the file timestamps */
	ZERO_STRUCT(unix_times);
	if (newstats.dos.access_time != name->dos.access_time) {
		unix_times.actime = nt_time_to_unix(newstats.dos.access_time);
	}
	if (newstats.dos.write_time != name->dos.write_time) {
		unix_times.modtime = nt_time_to_unix(newstats.dos.write_time);
	}
	if (unix_times.actime != 0 || unix_times.modtime != 0) {
		if (utime(name->full_name, &unix_times) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	/* possibly change the attribute */
	if (newstats.dos.attrib != name->dos.attrib) {
		mode_t mode = pvfs_fileperms(pvfs, newstats.dos.attrib);
		if (chmod(name->full_name, mode) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	return NT_STATUS_OK;
}

