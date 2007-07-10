/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - setfileinfo

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
#include "system/time.h"
#include "librpc/gen_ndr/xattr.h"


/*
  determine what access bits are needed for a call
*/
static uint32_t pvfs_setfileinfo_access(union smb_setfileinfo *info)
{
	uint32_t needed;

	switch (info->generic.level) {
	case RAW_SFILEINFO_EA_SET:
		needed = SEC_FILE_WRITE_EA;
		break;

	case RAW_SFILEINFO_DISPOSITION_INFO:
	case RAW_SFILEINFO_DISPOSITION_INFORMATION:
		needed = SEC_STD_DELETE;
		break;

	case RAW_SFILEINFO_END_OF_FILE_INFO:
		needed = SEC_FILE_WRITE_DATA;
		break;

	case RAW_SFILEINFO_POSITION_INFORMATION:
		needed = 0;
		break;

	case RAW_SFILEINFO_SEC_DESC:
		needed = 0;
		if (info->set_secdesc.in.secinfo_flags & (SECINFO_OWNER|SECINFO_GROUP)) {
			needed |= SEC_STD_WRITE_OWNER;
		}
		if (info->set_secdesc.in.secinfo_flags & SECINFO_DACL) {
			needed |= SEC_STD_WRITE_DAC;
		}
		if (info->set_secdesc.in.secinfo_flags & SECINFO_SACL) {
			needed |= SEC_FLAG_SYSTEM_SECURITY;
		}
		break;

	default:
		needed = SEC_FILE_WRITE_ATTRIBUTE;
		break;
	}

	return needed;
}

/*
  rename_information level
*/
static NTSTATUS pvfs_setfileinfo_rename(struct pvfs_state *pvfs, 
					struct ntvfs_request *req, 
					struct pvfs_filename *name,
					union smb_setfileinfo *info)
{
	NTSTATUS status;
	struct pvfs_filename *name2;
	char *new_name, *p;

	/* renames are only allowed within a directory */
	if (strchr_m(info->rename_information.in.new_name, '\\')) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	if (name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY) {
		/* don't allow this for now */
		return NT_STATUS_FILE_IS_A_DIRECTORY;
	}

	/* don't allow stream renames for now */
	if (name->stream_name) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	/* w2k3 does not appear to allow relative rename */
	if (info->rename_information.in.root_fid != 0) {
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

	new_name = talloc_asprintf(req, "%s\\%s", new_name,
				   info->rename_information.in.new_name);
	if (new_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* resolve the new name */
	status = pvfs_resolve_name(pvfs, name, new_name, 0, &name2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* if the destination exists, then check the rename is allowed */
	if (name2->exists) {
		struct odb_lock *lck;

		if (strcmp(name2->full_name, name->full_name) == 0) {
			/* rename to same name is null-op */
			return NT_STATUS_OK;
		}

		if (!info->rename_information.in.overwrite) {
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}

		status = pvfs_can_delete(pvfs, req, name2, &lck);
		if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION)) {
			return NT_STATUS_ACCESS_DENIED;
		}
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	status = pvfs_access_check_parent(pvfs, req, name2, SEC_DIR_ADD_FILE);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = pvfs_do_rename(pvfs, name, name2->full_name);
	if (NT_STATUS_IS_OK(status)) {
		name->full_name = talloc_steal(name, name2->full_name);
		name->original_name = talloc_steal(name, name2->original_name);
	}

	return NT_STATUS_OK;
}

/*
  add a single DOS EA
*/
NTSTATUS pvfs_setfileinfo_ea_set(struct pvfs_state *pvfs, 
				 struct pvfs_filename *name,
				 int fd, uint16_t num_eas,
				 struct ea_struct *eas)
{
	struct xattr_DosEAs *ealist;
	int i, j;
	NTSTATUS status;

	if (num_eas == 0) {
		return NT_STATUS_OK;
	}

	if (!(pvfs->flags & PVFS_FLAG_XATTR_ENABLE)) {
		return NT_STATUS_NOT_SUPPORTED;
	}

	ealist = talloc(name, struct xattr_DosEAs);

	/* load the current list */
	status = pvfs_doseas_load(pvfs, name, fd, ealist);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (j=0;j<num_eas;j++) {
		struct ea_struct *ea = &eas[j];
		/* see if its already there */
		for (i=0;i<ealist->num_eas;i++) {
			if (strcasecmp_m(ealist->eas[i].name, ea->name.s) == 0) {
				ealist->eas[i].value = ea->value;
				break;
			}
		}

		if (i==ealist->num_eas) {
			/* add it */
			ealist->eas = talloc_realloc(ealist, ealist->eas, 
						       struct xattr_EA, 
						       ealist->num_eas+1);
			if (ealist->eas == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			ealist->eas[i].name = ea->name.s;
			ealist->eas[i].value = ea->value;
			ealist->num_eas++;
		}
	}
	
	/* pull out any null EAs */
	for (i=0;i<ealist->num_eas;i++) {
		if (ealist->eas[i].value.length == 0) {
			memmove(&ealist->eas[i],
				&ealist->eas[i+1],
				(ealist->num_eas-(i+1)) * sizeof(ealist->eas[i]));
			ealist->num_eas--;
			i--;
		}
	}

	status = pvfs_doseas_save(pvfs, name, fd, ealist);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	notify_trigger(pvfs->notify_context, 
		       NOTIFY_ACTION_MODIFIED, 
		       FILE_NOTIFY_CHANGE_EA,
		       name->full_name);

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
			  struct ntvfs_request *req, 
			  union smb_setfileinfo *info)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct utimbuf unix_times;
	struct pvfs_file *f;
	struct pvfs_file_handle *h;
	struct pvfs_filename newstats;
	NTSTATUS status;
	uint32_t access_needed;
	uint32_t change_mask = 0;

	f = pvfs_find_fd(pvfs, req, info->generic.in.file.ntvfs);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	h = f->handle;

	access_needed = pvfs_setfileinfo_access(info);
	if ((f->access_mask & access_needed) != access_needed) {
		return NT_STATUS_ACCESS_DENIED;
	}

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
					       info->ea_set.in.num_eas,
					       info->ea_set.in.eas);

	case RAW_SFILEINFO_BASIC_INFO:
	case RAW_SFILEINFO_BASIC_INFORMATION:
		if (!null_nttime(info->basic_info.in.create_time)) {
			newstats.dos.create_time = info->basic_info.in.create_time;
		}
		if (!null_nttime(info->basic_info.in.access_time)) {
			newstats.dos.access_time = info->basic_info.in.access_time;
		}
		if (!null_nttime(info->basic_info.in.write_time)) {
			newstats.dos.write_time = info->basic_info.in.write_time;
			newstats.dos.flags |= XATTR_ATTRIB_FLAG_STICKY_WRITE_TIME;
			h->sticky_write_time = True;
		}
		if (!null_nttime(info->basic_info.in.change_time)) {
			newstats.dos.change_time = info->basic_info.in.change_time;
		}
		if (info->basic_info.in.attrib != 0) {
			newstats.dos.attrib = info->basic_info.in.attrib;
		}
  		break;

	case RAW_SFILEINFO_DISPOSITION_INFO:
	case RAW_SFILEINFO_DISPOSITION_INFORMATION:
		return pvfs_set_delete_on_close(pvfs, req, f, 
						info->disposition_info.in.delete_on_close);

	case RAW_SFILEINFO_ALLOCATION_INFO:
	case RAW_SFILEINFO_ALLOCATION_INFORMATION:
		newstats.dos.alloc_size = info->allocation_info.in.alloc_size;
		if (newstats.dos.alloc_size < newstats.st.st_size) {
			newstats.st.st_size = newstats.dos.alloc_size;
		}
		newstats.dos.alloc_size = pvfs_round_alloc_size(pvfs, 
								newstats.dos.alloc_size);
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
					       info);

	case RAW_SFILEINFO_SEC_DESC:
		notify_trigger(pvfs->notify_context, 
			       NOTIFY_ACTION_MODIFIED, 
			       FILE_NOTIFY_CHANGE_SECURITY,
			       h->name->full_name);
		return pvfs_acl_set(pvfs, req, h->name, h->fd, f->access_mask, info);

	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	/* possibly change the file size */
	if (newstats.st.st_size != h->name->st.st_size) {
		if (h->name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY) {
			return NT_STATUS_FILE_IS_A_DIRECTORY;
		}
		if (h->name->stream_name) {
			status = pvfs_stream_truncate(pvfs, h->name, h->fd, newstats.st.st_size);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
			
			change_mask |= FILE_NOTIFY_CHANGE_STREAM_SIZE;
		} else {
			int ret;
			if (f->access_mask & 
			    (SEC_FILE_WRITE_DATA|SEC_FILE_APPEND_DATA)) {
				ret = ftruncate(h->fd, newstats.st.st_size);
			} else {
				ret = truncate(h->name->full_name, newstats.st.st_size);
			}
			if (ret == -1) {
				return pvfs_map_errno(pvfs, errno);
			}
			change_mask |= FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_ATTRIBUTES;
		}
	}

	/* possibly change the file timestamps */
	ZERO_STRUCT(unix_times);
	if (newstats.dos.create_time != h->name->dos.create_time) {
		change_mask |= FILE_NOTIFY_CHANGE_CREATION;
	}
	if (newstats.dos.access_time != h->name->dos.access_time) {
		unix_times.actime = nt_time_to_unix(newstats.dos.access_time);
		change_mask |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
	}
	if (newstats.dos.write_time != h->name->dos.write_time) {
		unix_times.modtime = nt_time_to_unix(newstats.dos.write_time);
		change_mask |= FILE_NOTIFY_CHANGE_LAST_WRITE;
	}
	if (unix_times.actime != 0 || unix_times.modtime != 0) {
		if (utime(h->name->full_name, &unix_times) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	/* possibly change the attribute */
	if (newstats.dos.attrib != h->name->dos.attrib) {
		mode_t mode = pvfs_fileperms(pvfs, newstats.dos.attrib);
		if (!(h->name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY)) {
			if (fchmod(h->fd, mode) == -1) {
				return pvfs_map_errno(pvfs, errno);
			}
		}
		change_mask |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	}

	*h->name = newstats;

	notify_trigger(pvfs->notify_context, 
		       NOTIFY_ACTION_MODIFIED, 
		       change_mask,
		       h->name->full_name);

	return pvfs_dosattrib_save(pvfs, h->name, h->fd);
}


/*
  set info on a pathname
*/
NTSTATUS pvfs_setpathinfo(struct ntvfs_module_context *ntvfs,
			  struct ntvfs_request *req, union smb_setfileinfo *info)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_filename *name;
	struct pvfs_filename newstats;
	NTSTATUS status;
	struct utimbuf unix_times;
	uint32_t access_needed;
	uint32_t change_mask = 0;

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, info->generic.in.file.path, 
				   PVFS_RESOLVE_STREAMS, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	access_needed = pvfs_setfileinfo_access(info);
	status = pvfs_access_check_simple(pvfs, req, name, access_needed);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
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
		if (info->setattr.in.attrib == 0) {
			newstats.dos.attrib = FILE_ATTRIBUTE_NORMAL;
		} else if (info->setattr.in.attrib != FILE_ATTRIBUTE_NORMAL) {
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
		return pvfs_setfileinfo_ea_set(pvfs, name, -1, 
					       info->ea_set.in.num_eas,
					       info->ea_set.in.eas);

	case RAW_SFILEINFO_BASIC_INFO:
	case RAW_SFILEINFO_BASIC_INFORMATION:
		if (!null_nttime(info->basic_info.in.create_time)) {
			newstats.dos.create_time = info->basic_info.in.create_time;
		}
		if (!null_nttime(info->basic_info.in.access_time)) {
			newstats.dos.access_time = info->basic_info.in.access_time;
		}
		if (!null_nttime(info->basic_info.in.write_time)) {
			newstats.dos.write_time = info->basic_info.in.write_time;
		}
		if (!null_nttime(info->basic_info.in.change_time)) {
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
		newstats.dos.alloc_size = pvfs_round_alloc_size(pvfs, 
								newstats.dos.alloc_size);
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
					       info);

	case RAW_SFILEINFO_DISPOSITION_INFO:
	case RAW_SFILEINFO_DISPOSITION_INFORMATION:
	case RAW_SFILEINFO_POSITION_INFORMATION:
		return NT_STATUS_OK;

	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	/* possibly change the file size */
	if (newstats.st.st_size != name->st.st_size) {
		if (name->stream_name) {
			status = pvfs_stream_truncate(pvfs, name, -1, newstats.st.st_size);
			if (!NT_STATUS_IS_OK(status)) {
				return status;
			}
		} else if (truncate(name->full_name, newstats.st.st_size) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
		change_mask |= FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_ATTRIBUTES;
	}

	/* possibly change the file timestamps */
	ZERO_STRUCT(unix_times);
	if (newstats.dos.create_time != name->dos.create_time) {
		change_mask |= FILE_NOTIFY_CHANGE_CREATION;
	}
	if (newstats.dos.access_time != name->dos.access_time) {
		unix_times.actime = nt_time_to_unix(newstats.dos.access_time);
		change_mask |= FILE_NOTIFY_CHANGE_LAST_ACCESS;
	}
	if (newstats.dos.write_time != name->dos.write_time) {
		unix_times.modtime = nt_time_to_unix(newstats.dos.write_time);
		change_mask |= FILE_NOTIFY_CHANGE_LAST_WRITE;
	}
	if (unix_times.actime != 0 || unix_times.modtime != 0) {
		if (utime(name->full_name, &unix_times) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
	}

	/* possibly change the attribute */
	newstats.dos.attrib |= (name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY);
	if (newstats.dos.attrib != name->dos.attrib) {
		mode_t mode = pvfs_fileperms(pvfs, newstats.dos.attrib);
		if (chmod(name->full_name, mode) == -1) {
			return pvfs_map_errno(pvfs, errno);
		}
		change_mask |= FILE_NOTIFY_CHANGE_ATTRIBUTES;
	}

	*name = newstats;

	if (change_mask != 0) {
		notify_trigger(pvfs->notify_context, 
			       NOTIFY_ACTION_MODIFIED, 
			       change_mask,
			       name->full_name);
	}

	return pvfs_dosattrib_save(pvfs, name, -1);
}

