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

#include "includes.h"
#include "vfs_posix.h"
#include "librpc/gen_ndr/ndr_xattr.h"


/*
  determine what access bits are needed for a call
*/
static uint32_t pvfs_fileinfo_access(enum smb_fileinfo_level level)
{
	uint32_t needed;

	switch (level) {
	case RAW_FILEINFO_EA_LIST:
	case RAW_FILEINFO_ALL_EAS:
		needed = SEC_FILE_READ_EA;
		break;

	case RAW_FILEINFO_IS_NAME_VALID:
		needed = 0;
		break;

	default:
		needed = SEC_FILE_READ_ATTRIBUTE;
		break;
	}
	return needed;	
}

/*
  reply to a RAW_FILEINFO_EA_LIST call
*/
NTSTATUS pvfs_query_ea_list(struct pvfs_state *pvfs, TALLOC_CTX *mem_ctx, 
			    struct pvfs_filename *name, int fd, 
			    uint_t num_names,
			    struct ea_name *names,
			    struct smb_ea_list *eas)
{
	NTSTATUS status;
	int i;
	struct xattr_DosEAs *ealist = talloc_p(mem_ctx, struct xattr_DosEAs);

	ZERO_STRUCTP(eas);
	status = pvfs_doseas_load(pvfs, name, fd, ealist);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	eas->eas = talloc_array_p(mem_ctx, struct ea_struct, num_names);
	if (eas->eas == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	eas->num_eas = num_names;
	for (i=0;i<num_names;i++) {
		int j;
		eas->eas[i].flags = 0;
		eas->eas[i].name.s = names[i].name.s;
		eas->eas[i].value = data_blob(NULL, 0);
		for (j=0;j<ealist->num_eas;j++) {
			if (StrCaseCmp(eas->eas[i].name.s, 
				       ealist->eas[j].name) == 0) {
				eas->eas[i].value = ealist->eas[j].value;
				break;
			}
		}
	}
	return NT_STATUS_OK;
}

/*
  reply to a RAW_FILEINFO_ALL_EAS call
*/
static NTSTATUS pvfs_query_all_eas(struct pvfs_state *pvfs, TALLOC_CTX *mem_ctx, 
				   struct pvfs_filename *name, int fd, 
				   struct smb_ea_list *eas)
{
	NTSTATUS status;
	int i;
	struct xattr_DosEAs *ealist = talloc_p(mem_ctx, struct xattr_DosEAs);

	ZERO_STRUCTP(eas);
	status = pvfs_doseas_load(pvfs, name, fd, ealist);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	eas->eas = talloc_array_p(mem_ctx, struct ea_struct, ealist->num_eas);
	if (eas->eas == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	eas->num_eas = 0;
	for (i=0;i<ealist->num_eas;i++) {
		eas->eas[eas->num_eas].flags = 0;
		eas->eas[eas->num_eas].name.s = ealist->eas[i].name;
		eas->eas[eas->num_eas].value = ealist->eas[i].value;
		eas->num_eas++;
	}
	return NT_STATUS_OK;
}

/*
  approximately map a struct pvfs_filename to a generic fileinfo struct
*/
static NTSTATUS pvfs_map_fileinfo(struct pvfs_state *pvfs, 
				  struct smbsrv_request *req,
				  struct pvfs_filename *name, union smb_fileinfo *info, 
				  int fd)
{
	switch (info->generic.level) {
	case RAW_FILEINFO_GENERIC:
		return NT_STATUS_INVALID_LEVEL;

	case RAW_FILEINFO_GETATTR:
		info->getattr.out.attrib     = name->dos.attrib;
		info->getattr.out.size       = name->st.st_size;
		info->getattr.out.write_time = nt_time_to_unix(name->dos.write_time);
		return NT_STATUS_OK;

	case RAW_FILEINFO_GETATTRE:
	case RAW_FILEINFO_STANDARD:
		info->standard.out.create_time = nt_time_to_unix(name->dos.create_time);
		info->standard.out.access_time = nt_time_to_unix(name->dos.access_time);
		info->standard.out.write_time  = nt_time_to_unix(name->dos.write_time);
		info->standard.out.size        = name->st.st_size;
		info->standard.out.alloc_size  = name->dos.alloc_size;
		info->standard.out.attrib      = name->dos.attrib;
		return NT_STATUS_OK;

	case RAW_FILEINFO_EA_SIZE:
		info->ea_size.out.create_time = nt_time_to_unix(name->dos.create_time);
		info->ea_size.out.access_time = nt_time_to_unix(name->dos.access_time);
		info->ea_size.out.write_time  = nt_time_to_unix(name->dos.write_time);
		info->ea_size.out.size        = name->st.st_size;
		info->ea_size.out.alloc_size  = name->dos.alloc_size;
		info->ea_size.out.attrib      = name->dos.attrib;
		info->ea_size.out.ea_size     = name->dos.ea_size;
		return NT_STATUS_OK;

	case RAW_FILEINFO_EA_LIST:
		return pvfs_query_ea_list(pvfs, req, name, fd, 
					  info->ea_list.in.num_names,
					  info->ea_list.in.ea_names, 
					  &info->ea_list.out);

	case RAW_FILEINFO_ALL_EAS:
		return pvfs_query_all_eas(pvfs, req, name, fd, &info->all_eas.out);

	case RAW_FILEINFO_IS_NAME_VALID:
		return NT_STATUS_OK;

	case RAW_FILEINFO_BASIC_INFO:
	case RAW_FILEINFO_BASIC_INFORMATION:
		info->basic_info.out.create_time = name->dos.create_time;
		info->basic_info.out.access_time = name->dos.access_time;
		info->basic_info.out.write_time  = name->dos.write_time;
		info->basic_info.out.change_time = name->dos.change_time;
		info->basic_info.out.attrib      = name->dos.attrib;
		return NT_STATUS_OK;

	case RAW_FILEINFO_STANDARD_INFO:
	case RAW_FILEINFO_STANDARD_INFORMATION:
		info->standard_info.out.alloc_size     = name->dos.alloc_size;
		info->standard_info.out.size           = name->st.st_size;
		info->standard_info.out.nlink          = name->st.st_nlink;
		info->standard_info.out.delete_pending = 0;
		info->standard_info.out.directory   = 
			(name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY)? 1 : 0;
		return NT_STATUS_OK;

	case RAW_FILEINFO_EA_INFO:
	case RAW_FILEINFO_EA_INFORMATION:
		info->ea_info.out.ea_size = name->dos.ea_size;
		return NT_STATUS_OK;

	case RAW_FILEINFO_NAME_INFO:
	case RAW_FILEINFO_NAME_INFORMATION:
		info->name_info.out.fname.s = name->original_name;
		return NT_STATUS_OK;

	case RAW_FILEINFO_ALL_INFO:
	case RAW_FILEINFO_ALL_INFORMATION:
		info->all_info.out.create_time    = name->dos.create_time;
		info->all_info.out.access_time    = name->dos.access_time;
		info->all_info.out.write_time     = name->dos.write_time;
		info->all_info.out.change_time    = name->dos.change_time;
		info->all_info.out.attrib         = name->dos.attrib;
		info->all_info.out.alloc_size     = name->dos.alloc_size;
		info->all_info.out.size           = name->st.st_size;
		info->all_info.out.nlink          = name->st.st_nlink;
		info->all_info.out.delete_pending = 0;
		info->all_info.out.directory      = 
			(name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY)? 1 : 0;
		info->all_info.out.ea_size        = name->dos.ea_size;
		info->all_info.out.fname.s        = name->original_name;
		return NT_STATUS_OK;

	case RAW_FILEINFO_ALT_NAME_INFO:
	case RAW_FILEINFO_ALT_NAME_INFORMATION:
		info->name_info.out.fname.s = pvfs_short_name(pvfs, name, name);
		return NT_STATUS_OK;

	case RAW_FILEINFO_STREAM_INFO:
	case RAW_FILEINFO_STREAM_INFORMATION:
		return pvfs_stream_information(pvfs, req, name, fd, &info->stream_info.out);

	case RAW_FILEINFO_COMPRESSION_INFO:
	case RAW_FILEINFO_COMPRESSION_INFORMATION:
		info->compression_info.out.compressed_size = name->st.st_size;
		info->compression_info.out.format          = 0;
		info->compression_info.out.unit_shift      = 0;
		info->compression_info.out.chunk_shift     = 0;
		info->compression_info.out.cluster_shift   = 0;
		return NT_STATUS_OK;

	case RAW_FILEINFO_INTERNAL_INFORMATION:
		info->internal_information.out.file_id = name->dos.file_id;
		return NT_STATUS_OK;

	case RAW_FILEINFO_ACCESS_INFORMATION:
		info->access_information.out.access_flags = 0;
		return NT_STATUS_OK;

	case RAW_FILEINFO_POSITION_INFORMATION:
		info->position_information.out.position = 0;
		return NT_STATUS_OK;

	case RAW_FILEINFO_MODE_INFORMATION:
		info->mode_information.out.mode = 0;
		return NT_STATUS_OK;

	case RAW_FILEINFO_ALIGNMENT_INFORMATION:
		info->alignment_information.out.alignment_requirement = 0;
		return NT_STATUS_OK;

	case RAW_FILEINFO_NETWORK_OPEN_INFORMATION:
		info->network_open_information.out.create_time = name->dos.create_time;
		info->network_open_information.out.access_time = name->dos.access_time;
		info->network_open_information.out.write_time  = name->dos.write_time;
		info->network_open_information.out.change_time = name->dos.change_time;
		info->network_open_information.out.alloc_size  = name->dos.alloc_size;
		info->network_open_information.out.size        = name->st.st_size;
		info->network_open_information.out.attrib      = name->dos.attrib;
		return NT_STATUS_OK;

	case RAW_FILEINFO_ATTRIBUTE_TAG_INFORMATION:
		info->attribute_tag_information.out.attrib      = name->dos.attrib;
		info->attribute_tag_information.out.reparse_tag = 0;
		return NT_STATUS_OK;

	case RAW_FILEINFO_SEC_DESC:
		return pvfs_acl_query(pvfs, req, name, fd, info);
	}

	return NT_STATUS_INVALID_LEVEL;
}

/*
  return info on a pathname
*/
NTSTATUS pvfs_qpathinfo(struct ntvfs_module_context *ntvfs,
		        struct smbsrv_request *req, union smb_fileinfo *info)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_filename *name;
	NTSTATUS status;

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, info->generic.in.fname, PVFS_RESOLVE_STREAMS, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->stream_exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	status = pvfs_access_check_simple(pvfs, req, name, 
					  pvfs_fileinfo_access(info->generic.level));
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = pvfs_map_fileinfo(pvfs, req, name, info, -1);

	return status;
}

/*
  query info on a open file
*/
NTSTATUS pvfs_qfileinfo(struct ntvfs_module_context *ntvfs,
		        struct smbsrv_request *req, union smb_fileinfo *info)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f;
	struct pvfs_file_handle *h;
	NTSTATUS status;
	uint32_t access_needed;

	f = pvfs_find_fd(pvfs, req, info->generic.in.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}
	h = f->handle;

	access_needed = pvfs_fileinfo_access(info->generic.level);
	if (!(f->access_mask & access_needed)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/* update the file information */
	status = pvfs_resolve_name_fd(pvfs, h->fd, h->name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	status = pvfs_map_fileinfo(pvfs, req, h->name, info, h->fd);

	/* a qfileinfo can fill in a bit more info than a qpathinfo -
	   now modify the levels that need to be fixed up */
	switch (info->generic.level) {
	case RAW_FILEINFO_STANDARD_INFO:
	case RAW_FILEINFO_STANDARD_INFORMATION:
		if (h->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) {
			info->standard_info.out.delete_pending = 1;
			info->standard_info.out.nlink--;
		}
		break;

	case RAW_FILEINFO_ALL_INFO:
	case RAW_FILEINFO_ALL_INFORMATION:
		if (h->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) {
			info->all_info.out.delete_pending = 1;
			info->all_info.out.nlink--;
		}
		break;

	case RAW_FILEINFO_POSITION_INFORMATION:
		info->position_information.out.position = h->position;
		break;

	case RAW_FILEINFO_ACCESS_INFORMATION:
		info->access_information.out.access_flags = f->access_mask;
		break;

	case RAW_FILEINFO_MODE_INFORMATION:
		info->mode_information.out.mode = h->mode;
		break;

	default:
		break;
	}
	
	return status;
}
