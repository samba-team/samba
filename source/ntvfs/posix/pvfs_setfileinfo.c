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

#include "includes.h"
#include "vfs_posix.h"
#include "system/time.h"
#include "librpc/gen_ndr/ndr_xattr.h"


/*
  rename_information level
*/
static NTSTATUS pvfs_setfileinfo_rename(struct pvfs_state *pvfs, 
					struct smbsrv_request *req, 
					struct pvfs_filename *name,
					struct smb_rename_information *r)
{
	NTSTATUS status;
	struct pvfs_filename *name2;
	char *new_name, *p;

	/* renames are only allowed within a directory */
	if (strchr_m(r->new_name, '\\')) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY) {
		/* don't allow this for now */
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	}

	/* w2k3 does not appear to allow relative rename */
	if (r->root_fid != 0) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* construct the fully qualified windows name for the new file name */
	new_name = talloc_strdup(req, name->original_name);
	if (new_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	p = strrchr_m(new_name, '\\');
	if (p == NULL) {
		return NT_STATUS_OBJECT_NAME_INVALID;
	}
	*p = 0;

	new_name = talloc_asprintf(req, "%s\\%s", new_name, r->new_name);
	if (new_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* resolve the new name */
	status = pvfs_resolve_name(pvfs, name, new_name, PVFS_RESOLVE_NO_WILDCARD, &name2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* if the destination exists, then check the rename is allowed */
	if (name2->exists) {
		if (strcmp(name2->full_name, name->full_name) == 0) {
			/* rename to same name is null-op */
			return NT_STATUS_OK;
		}

		if (!r->overwrite) {
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}

		status = pvfs_can_delete(pvfs, name2);
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (rename(name->full_name, name2->full_name) == -1) {
		return map_nt_error_from_unix(errno);
	}

	name->full_name = talloc_steal(name, name2->full_name);
	name->original_name = talloc_steal(name, name2->original_name);

	return NT_STATUS_OK;
}

/*
  add a single DOS EA
*/
static NTSTATUS pvfs_setfileinfo_ea_set(struct pvfs_state *pvfs, 
					struct pvfs_filename *name,
					int fd, struct ea_struct *ea)
{
	struct xattr_DosEAs *ealist = talloc_p(pvfs, struct xattr_DosEAs);
	int i;
	NTSTATUS status;

	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	/* load the current list */
	status = pvfs_doseas_load(pvfs, name, fd, ealist);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* see if its already there */
	for (i=0;i<ealist->num_eas;i++) {
		if (StrCaseCmp(ealist->eas[i].name, ea->name.s) == 0) {
			ealist->eas[i].value = ea->value;
			goto save;
		}
	}

	/* add it */
	ealist->eas = talloc_realloc_p(ealist, ealist->eas, struct xattr_EA, ealist->num_eas+1);
	if (ealist->eas == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	ealist->eas[i].name = ea->name.s;
	ealist->eas[i].value = ea->value;
	ealist->num_eas++;
	
save:
	status = pvfs_doseas_save(pvfs, name, fd, ealist);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	name->dos.ea_size = 4;
	for (i=0;i<ealist->num_eas;i++) {
		name->dos.ea_size += 4 + strlen(ealist->eas[i].name)+1 + 
			ealist->eas[i].value.length;
	}

	/* update the ea_size attrib */
	return pvfs_dosattrib_save(pvfs, name, fd);
}

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
	struct pvfs_file_handle *h;
	uint32_t create_options;
	struct pvfs_filename newstats;
	NTSTATUS status;

	f = pvfs_find_fd(pvfs, req, info->generic.file.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	h = f->handle;

	/* update the file information */
	status = pvfs_resolve_name_fd(pvfs, h->fd, h->name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* we take a copy of the current file stats, then update
	   newstats in each of the elements below. At the end we
	   compare, and make any changes needed */
	newstats = *h->name;

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

	case RAW_SFILEINFO_EA_SET:
		return pvfs_setfileinfo_ea_set(pvfs, h->name, h->fd, 
					       &info->ea_set.in.ea);

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
		create_options = h->create_options;
		if (info->disposition_info.in.delete_on_close) {
			create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
		} else {
			create_options &= ~NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
		}
		return pvfs_change_create_options(pvfs, req, f, create_options);

	case RAW_SFILEINFO_ALLOCATION_INFO:
	case RAW_SFILEINFO_ALLOCATION_INFORMATION:
		newstats.dos.alloc_size = info->allocation_info.in.alloc_size;
		if (newstats.dos.alloc_size < newstats.st.st_size) {
			newstats.st.st_size = newstats.dos.alloc_size;
		}
		break;

	case RAW_SFILEINFO_END_OF_FILE_INFO:
	case RAW_SFILEINFO_END_OF_FILE_INFORMATION:
		newstats.st.st_size = info->end_of_file_info.in.size;
		break;

	case RAW_SFILEINFO_POSITION_INFORMATION:
		h->position = info->position_information.in.position;
		break;

	case RAW_SFILEINFO_MODE_INFORMATION:
		/* this one is a puzzle */
		if (info->mode_information.in.mode != 0 &&
		    info->mode_information.in.mode != 2 &&
		    info->mode_information.in.mode != 4 &&
		    info->mode_information.in.mode != 6) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		h->mode = info->mode_information.in.mode;
		break;

	case RAW_SFILEINFO_RENAME_INFORMATION:
		return pvfs_setfileinfo_rename(pvfs, req, h->name, 
					       &info->rename_information.in);

	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	/* possibly change the file size */
	if (newstats.st.st_size != h->name->st.st_size) {
		int ret;
		if (h->name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY) {
			return NT_STATUS_FILE_IS_A_DIRECTORY;
		}
		if (f->access_mask & SA_RIGHT_FILE_WRITE_APPEND) {
			ret = ftruncate(h->fd, newstats.st.st_size);
		} else {
			ret = truncate(h->name->full_name, newstats.st.st_size);
		}
		if (ret == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	/* possibly change the file timestamps */
	ZERO_STRUCT(unix_times);
	if (newstats.dos.access_time != h->name->dos.access_time) {
		unix_times.actime = nt_time_to_unix(newstats.dos.access_time);
	}
	if (newstats.dos.write_time != h->name->dos.write_time) {
		unix_times.modtime = nt_time_to_unix(newstats.dos.write_time);
	}
	if (unix_times.actime != 0 || unix_times.modtime != 0) {
		if (utime(h->name->full_name, &unix_times) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	/* possibly change the attribute */
	if (newstats.dos.attrib != h->name->dos.attrib) {
		mode_t mode = pvfs_fileperms(pvfs, newstats.dos.attrib);
		if (h->name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY) {
			/* ignore on directories for now */
			return NT_STATUS_OK;
		}
		if (fchmod(h->fd, mode) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	*h->name = newstats;

	return pvfs_dosattrib_save(pvfs, h->name, h->fd);
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

	case RAW_SFILEINFO_EA_SET:
		return pvfs_setfileinfo_ea_set(pvfs, name, -1, &info->ea_set.in.ea);

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
		if (info->allocation_info.in.alloc_size > newstats.dos.alloc_size) {
			/* strange. Increasing the allocation size via setpathinfo 
			   should be silently ignored */
			break;
		}
		newstats.dos.alloc_size = info->allocation_info.in.alloc_size;
		if (newstats.dos.alloc_size < newstats.st.st_size) {
			newstats.st.st_size = newstats.dos.alloc_size;
		}
		break;

	case RAW_SFILEINFO_END_OF_FILE_INFO:
	case RAW_SFILEINFO_END_OF_FILE_INFORMATION:
		newstats.st.st_size = info->end_of_file_info.in.size;
		break;

	case RAW_SFILEINFO_MODE_INFORMATION:
		if (info->mode_information.in.mode != 0 &&
		    info->mode_information.in.mode != 2 &&
		    info->mode_information.in.mode != 4 &&
		    info->mode_information.in.mode != 6) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		return NT_STATUS_OK;

	case RAW_SFILEINFO_RENAME_INFORMATION:
		return pvfs_setfileinfo_rename(pvfs, req, name, 
					       &info->rename_information.in);

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

	*name = newstats;

	return pvfs_dosattrib_save(pvfs, name, -1);
}

