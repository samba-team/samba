/* 
   Unix SMB/CIFS implementation.

   NTVFS generic level mapping code

   Copyright (C) Andrew Tridgell 2003-2004

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
/*
  this implements mappings between info levels for NTVFS backend calls

  the idea is that each of these functions implements one of the NTVFS
  backend calls in terms of the 'generic' call. All backends that use
  these functions must supply the generic call, but can if it wants to
  also implement other levels if the need arises

  this allows backend writers to only implement one variant of each
  call unless they need fine grained control of the calls.
*/

#include "includes.h"

/*
  see if a filename ends in EXE COM DLL or SYM. This is needed for the
  DENY_DOS mapping for OpenX
*/
static BOOL is_exe_file(const char *fname)
{
	char *p;
	p = strrchr(fname, '.');
	if (!p) {
		return False;
	}
	p++;
	if (strcasecmp(p, "EXE") == 0 ||
	    strcasecmp(p, "COM") == 0 ||
	    strcasecmp(p, "DLL") == 0 ||
	    strcasecmp(p, "SYM") == 0) {
		return True;
	}
	return False;
}


/* 
   NTVFS open generic to any mapper
*/
NTSTATUS ntvfs_map_open(struct smbsrv_request *req, union smb_open *io, 
			struct ntvfs_module_context *ntvfs)
{
	NTSTATUS status;
	union smb_open *io2;

	io2 = talloc_p(req, union smb_open);
	if (io2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* must be synchronous, or we won't be called to do the 
	   translation */
	req->control_flags &= ~REQ_CONTROL_MAY_ASYNC;

	switch (io->generic.level) {
	case RAW_OPEN_GENERIC:
		return NT_STATUS_INVALID_LEVEL;

	case RAW_OPEN_OPENX:
		ZERO_STRUCT(io2->generic.in);
		io2->generic.level = RAW_OPEN_GENERIC;
		if (io->openx.in.flags & OPENX_FLAGS_REQUEST_OPLOCK) {
			io2->generic.in.flags |= NTCREATEX_FLAGS_REQUEST_OPLOCK;
		}
		if (io->openx.in.flags & OPENX_FLAGS_REQUEST_BATCH_OPLOCK) {
			io2->generic.in.flags |= NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK;
		}

		switch (io->openx.in.open_mode & OPENX_MODE_ACCESS_MASK) {
		case OPENX_MODE_ACCESS_READ:
			io2->generic.in.access_mask = GENERIC_RIGHTS_FILE_READ;
			break;
		case OPENX_MODE_ACCESS_WRITE:
			io2->generic.in.access_mask = GENERIC_RIGHTS_FILE_WRITE;
			break;
		case OPENX_MODE_ACCESS_RDWR:
		case OPENX_MODE_ACCESS_FCB:
			io2->generic.in.access_mask = GENERIC_RIGHTS_FILE_READ | GENERIC_RIGHTS_FILE_WRITE;
			break;
		}

		switch (io->openx.in.open_mode & OPENX_MODE_DENY_MASK) {
		case OPENX_MODE_DENY_READ:
			io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_WRITE;
			break;
		case OPENX_MODE_DENY_WRITE:
			io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_READ;
			break;
		case OPENX_MODE_DENY_ALL:
			io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
			break;
		case OPENX_MODE_DENY_NONE:
			io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
			break;
		case OPENX_MODE_DENY_DOS:
			/* DENY_DOS is quite strange - it depends on the filename! */
			if (is_exe_file(io->openx.in.fname)) {
				io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
			} else {
				if ((io->openx.in.open_mode & OPENX_MODE_ACCESS_MASK) == 
				    OPENX_MODE_ACCESS_READ) {
					io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_READ;
				} else {
					io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
				}
			}
			break;
		case OPENX_MODE_DENY_FCB:
			io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
			break;
		}

		switch (io->openx.in.open_func) {
		case (OPENX_OPEN_FUNC_FAIL):
			io2->generic.in.open_disposition = NTCREATEX_DISP_CREATE;
			break;
		case (OPENX_OPEN_FUNC_OPEN):
			io2->generic.in.open_disposition = NTCREATEX_DISP_OPEN;
			break;
		case (OPENX_OPEN_FUNC_TRUNC):
			io2->generic.in.open_disposition = NTCREATEX_DISP_OVERWRITE;
			break;
		case (OPENX_OPEN_FUNC_FAIL | OPENX_OPEN_FUNC_CREATE):
			io2->generic.in.open_disposition = NTCREATEX_DISP_CREATE;
			break;
		case (OPENX_OPEN_FUNC_OPEN | OPENX_OPEN_FUNC_CREATE):
			io2->generic.in.open_disposition = NTCREATEX_DISP_OPEN_IF;
			break;
		case (OPENX_OPEN_FUNC_TRUNC | OPENX_OPEN_FUNC_CREATE):
			io2->generic.in.open_disposition = NTCREATEX_DISP_OVERWRITE_IF;
			break;			
		}
		io2->generic.in.alloc_size = io->openx.in.size;
		io2->generic.in.file_attr = io->openx.in.file_attrs;
		io2->generic.in.fname = io->openx.in.fname;

		status = ntvfs->ops->open(ntvfs, req, io2);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		
		ZERO_STRUCT(io->openx.out);
		io->openx.out.fnum = io2->generic.out.fnum;
		io->openx.out.attrib = io2->generic.out.attrib;
		io->openx.out.write_time = nt_time_to_unix(io2->generic.out.write_time);
		io->openx.out.size = io2->generic.out.size;
		
		return NT_STATUS_OK;


	case RAW_OPEN_OPEN:
		ZERO_STRUCT(io2->generic.in);
		io2->generic.level = RAW_OPEN_GENERIC;
		io2->generic.in.file_attr = io->open.in.search_attrs;
		io2->generic.in.fname = io->open.in.fname;
		io2->generic.in.open_disposition = NTCREATEX_DISP_OPEN;
		DEBUG(9,("ntvfs_map_open(OPEN): mapping flags=0x%x\n",
			io->open.in.flags));
		switch (io->open.in.flags & OPEN_FLAGS_MODE_MASK) {
			case OPEN_FLAGS_OPEN_READ:
				io2->generic.in.access_mask = GENERIC_RIGHTS_FILE_READ;
				io->open.out.rmode = DOS_OPEN_RDONLY;
				break;
			case OPEN_FLAGS_OPEN_WRITE:
				io2->generic.in.access_mask = GENERIC_RIGHTS_FILE_WRITE;
				io->open.out.rmode = DOS_OPEN_WRONLY;
				break;
			case OPEN_FLAGS_OPEN_RDWR:
			case 0xf: /* FCB mode */
				io2->generic.in.access_mask = GENERIC_RIGHTS_FILE_READ |
					GENERIC_RIGHTS_FILE_WRITE;
				io->open.out.rmode = DOS_OPEN_RDWR; /* assume we got r/w */
				break;
			default:
				DEBUG(2,("ntvfs_map_open(OPEN): invalid mode 0x%x\n",
					io->open.in.flags & OPEN_FLAGS_MODE_MASK));
				return NT_STATUS_INVALID_PARAMETER;
		}
		
		switch(io->open.in.flags & OPEN_FLAGS_DENY_MASK) {
			case OPEN_FLAGS_DENY_DOS:
				/* DENY_DOS is quite strange - it depends on the filename! */
				if (is_exe_file(io->open.in.fname)) {
					io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_WRITE;
				} else {
					if ((io->open.in.flags & OPEN_FLAGS_MODE_MASK) == 
					    OPEN_FLAGS_OPEN_READ) {
						io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_READ;
					} else {
						io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
					}
				}
				break;
			case OPEN_FLAGS_DENY_ALL:
				io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
				break;
			case OPEN_FLAGS_DENY_WRITE:
				io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_READ;
				break;
			case OPEN_FLAGS_DENY_READ:
				io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_WRITE;
				break;
			case OPEN_FLAGS_DENY_NONE:
				io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_WRITE |
						NTCREATEX_SHARE_ACCESS_READ | NTCREATEX_SHARE_ACCESS_DELETE;
				break;
			case 0x70: /* FCB mode */
				io2->generic.in.share_access = NTCREATEX_SHARE_ACCESS_NONE;
				break;
			default:
				DEBUG(2,("ntvfs_map_open(OPEN): invalid DENY 0x%x\n",
					io->open.in.flags & OPEN_FLAGS_DENY_MASK));
				return NT_STATUS_INVALID_PARAMETER;
		}
		DEBUG(9,("ntvfs_map_open(OPEN): mapped flags=0x%x to access_mask=0x%x and share_access=0x%x\n",
			io->open.in.flags, io2->generic.in.access_mask, io2->generic.in.share_access));

		status = ntvfs->ops->open(ntvfs, req, io2);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		
		ZERO_STRUCT(io->openx.out);
		io->open.out.fnum = io2->generic.out.fnum;
		io->open.out.attrib = io2->generic.out.attrib;
		io->open.out.write_time = nt_time_to_unix(io2->generic.out.write_time);
		io->open.out.size = io2->generic.out.size;
		io->open.out.rmode = DOS_OPEN_RDWR;
		
		return NT_STATUS_OK;
	}

	return NT_STATUS_INVALID_LEVEL;
}


/* 
   NTVFS fsinfo generic to any mapper
*/
NTSTATUS ntvfs_map_fsinfo(struct smbsrv_request *req, union smb_fsinfo *fs, 
			  struct ntvfs_module_context *ntvfs)
{
	NTSTATUS status;
	union smb_fsinfo *fs2;

	fs2 = talloc_p(req, union smb_fsinfo);
	if (fs2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (fs->generic.level == RAW_QFS_GENERIC) {
		return NT_STATUS_INVALID_LEVEL;
	}

	/* ask the backend for the generic info */
	fs2->generic.level = RAW_QFS_GENERIC;

	status = ntvfs->ops->fsinfo(ntvfs, req, fs2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* and convert it to the required level */
	switch (fs->generic.level) {
	case RAW_QFS_GENERIC:
		return NT_STATUS_INVALID_LEVEL;

	case RAW_QFS_DSKATTR: {
		/* map from generic to DSKATTR */
		uint_t bpunit = 64;

		/* we need to scale the sizes to fit */
		for (bpunit=64; bpunit<0x10000; bpunit *= 2) {
			if (fs2->generic.out.blocks_total * (double)fs2->generic.out.block_size < bpunit * 512 * 65535.0) {
				break;
			}
		}

		fs->dskattr.out.blocks_per_unit = bpunit;
		fs->dskattr.out.block_size = 512;
		fs->dskattr.out.units_total = 
			(fs2->generic.out.blocks_total * (double)fs2->generic.out.block_size) / (bpunit * 512);
		fs->dskattr.out.units_free  = 
			(fs2->generic.out.blocks_free  * (double)fs2->generic.out.block_size) / (bpunit * 512);

		/* we must return a maximum of 2G to old DOS systems, or they get very confused */
		if (bpunit > 64 && req->smb_conn->negotiate.protocol <= PROTOCOL_LANMAN2) {
			fs->dskattr.out.blocks_per_unit = 64;
			fs->dskattr.out.units_total = 0xFFFF;
			fs->dskattr.out.units_free = 0xFFFF;
		}
		return NT_STATUS_OK;
	}

	case RAW_QFS_ALLOCATION:
		fs->allocation.out.fs_id = fs2->generic.out.fs_id;
		fs->allocation.out.total_alloc_units = fs2->generic.out.blocks_total;
		fs->allocation.out.avail_alloc_units = fs2->generic.out.blocks_free;
		fs->allocation.out.sectors_per_unit = 1;
		fs->allocation.out.bytes_per_sector = fs2->generic.out.block_size;
		return NT_STATUS_OK;

	case RAW_QFS_VOLUME:
		fs->volume.out.serial_number = fs2->generic.out.serial_number;
		fs->volume.out.volume_name.s = fs2->generic.out.volume_name;
		return NT_STATUS_OK;

	case RAW_QFS_VOLUME_INFO:
	case RAW_QFS_VOLUME_INFORMATION:
		fs->volume_info.out.create_time = fs2->generic.out.create_time;
		fs->volume_info.out.serial_number = fs2->generic.out.serial_number;
		fs->volume_info.out.volume_name.s = fs2->generic.out.volume_name;
		return NT_STATUS_OK;

	case RAW_QFS_SIZE_INFO:
	case RAW_QFS_SIZE_INFORMATION:
		fs->size_info.out.total_alloc_units = fs2->generic.out.blocks_total;
		fs->size_info.out.avail_alloc_units = fs2->generic.out.blocks_free;
		fs->size_info.out.sectors_per_unit = 1;
		fs->size_info.out.bytes_per_sector = fs2->generic.out.block_size;
		return NT_STATUS_OK;

	case RAW_QFS_DEVICE_INFO:
	case RAW_QFS_DEVICE_INFORMATION:
		fs->device_info.out.device_type = fs2->generic.out.device_type;
		fs->device_info.out.characteristics = fs2->generic.out.device_characteristics;
		return NT_STATUS_OK;

	case RAW_QFS_ATTRIBUTE_INFO:
	case RAW_QFS_ATTRIBUTE_INFORMATION:
		fs->attribute_info.out.fs_attr = fs2->generic.out.fs_attr;
		fs->attribute_info.out.max_file_component_length = fs2->generic.out.max_file_component_length;
		fs->attribute_info.out.fs_type.s = fs2->generic.out.fs_type;
		return NT_STATUS_OK;

	case RAW_QFS_QUOTA_INFORMATION:
		ZERO_STRUCT(fs->quota_information.out.unknown);
		fs->quota_information.out.quota_soft = fs2->generic.out.quota_soft;
		fs->quota_information.out.quota_hard = fs2->generic.out.quota_hard;
		fs->quota_information.out.quota_flags = fs2->generic.out.quota_flags;
		return NT_STATUS_OK;

	case RAW_QFS_FULL_SIZE_INFORMATION:
		fs->full_size_information.out.total_alloc_units = fs2->generic.out.blocks_total;
		fs->full_size_information.out.call_avail_alloc_units = fs2->generic.out.blocks_free;
		fs->full_size_information.out.actual_avail_alloc_units = fs2->generic.out.blocks_free;
		fs->full_size_information.out.sectors_per_unit = 1;
		fs->full_size_information.out.bytes_per_sector = fs2->generic.out.block_size;
		return NT_STATUS_OK;

	case RAW_QFS_OBJECTID_INFORMATION:
		fs->objectid_information.out.guid = fs2->generic.out.guid;
		ZERO_STRUCT(fs->objectid_information.out.unknown);
		return NT_STATUS_OK;
	}


	return NT_STATUS_INVALID_LEVEL;
}


/* 
   NTVFS fileinfo generic to any mapper
*/
NTSTATUS ntvfs_map_fileinfo(struct smbsrv_request *req, union smb_fileinfo *info, 
			    union smb_fileinfo *info2)
{
	int i;
	/* and convert it to the required level using results in info2 */
	switch (info->generic.level) {
		case RAW_FILEINFO_GENERIC:
		return NT_STATUS_INVALID_LEVEL;
	case RAW_FILEINFO_GETATTR:
		info->getattr.out.attrib = info2->generic.out.attrib & 0xff;
		info->getattr.out.size = info2->generic.out.size;
		info->getattr.out.write_time = nt_time_to_unix(info2->generic.out.write_time);
		return NT_STATUS_OK;
		
	case RAW_FILEINFO_GETATTRE:
		info->getattre.out.attrib = info2->generic.out.attrib;
		info->getattre.out.size = info2->generic.out.size;
		info->getattre.out.write_time = nt_time_to_unix(info2->generic.out.write_time);
		info->getattre.out.create_time = nt_time_to_unix(info2->generic.out.create_time);
		info->getattre.out.access_time = nt_time_to_unix(info2->generic.out.access_time);
		info->getattre.out.alloc_size = info2->generic.out.alloc_size;
		return NT_STATUS_OK;
		
	case RAW_FILEINFO_NETWORK_OPEN_INFORMATION:
		info->network_open_information.out.create_time = info2->generic.out.create_time;
		info->network_open_information.out.access_time = info2->generic.out.access_time;
		info->network_open_information.out.write_time =  info2->generic.out.write_time;
		info->network_open_information.out.change_time = info2->generic.out.change_time;
		info->network_open_information.out.alloc_size = info2->generic.out.alloc_size;
		info->network_open_information.out.size = info2->generic.out.size;
		info->network_open_information.out.attrib = info2->generic.out.attrib;
		return NT_STATUS_OK;

	case RAW_FILEINFO_ALL_INFO:
	case RAW_FILEINFO_ALL_INFORMATION:
		info->all_info.out.create_time = info2->generic.out.create_time;
		info->all_info.out.access_time = info2->generic.out.access_time;
		info->all_info.out.write_time =  info2->generic.out.write_time;
		info->all_info.out.change_time = info2->generic.out.change_time;
		info->all_info.out.attrib = info2->generic.out.attrib;
		info->all_info.out.alloc_size = info2->generic.out.alloc_size;
		info->all_info.out.size = info2->generic.out.size;
		info->all_info.out.nlink = info2->generic.out.nlink;
		info->all_info.out.delete_pending = info2->generic.out.delete_pending;
		info->all_info.out.directory = info2->generic.out.directory;
		info->all_info.out.ea_size = info2->generic.out.ea_size;
		info->all_info.out.fname.s = info2->generic.out.fname.s;
		info->all_info.out.fname.private_length = info2->generic.out.fname.private_length;
		return NT_STATUS_OK;

	case RAW_FILEINFO_BASIC_INFO:
	case RAW_FILEINFO_BASIC_INFORMATION:
		info->basic_info.out.create_time = info2->generic.out.create_time;
		info->basic_info.out.access_time = info2->generic.out.access_time;
		info->basic_info.out.write_time = info2->generic.out.write_time;
		info->basic_info.out.change_time = info2->generic.out.change_time;
		info->basic_info.out.attrib = info2->generic.out.attrib;
		return NT_STATUS_OK;

	case RAW_FILEINFO_STANDARD:
		info->standard.out.create_time = nt_time_to_unix(info2->generic.out.create_time);
		info->standard.out.access_time = nt_time_to_unix(info2->generic.out.access_time);
		info->standard.out.write_time = nt_time_to_unix(info2->generic.out.write_time);
		info->standard.out.size = info2->generic.out.size;
		info->standard.out.alloc_size = info2->generic.out.alloc_size;
		info->standard.out.attrib = info2->generic.out.attrib;
		return NT_STATUS_OK;

	case RAW_FILEINFO_EA_SIZE:
		info->ea_size.out.create_time = nt_time_to_unix(info2->generic.out.create_time);
		info->ea_size.out.access_time = nt_time_to_unix(info2->generic.out.access_time);
		info->ea_size.out.write_time = nt_time_to_unix(info2->generic.out.write_time);
		info->ea_size.out.size = info2->generic.out.size;
		info->ea_size.out.alloc_size = info2->generic.out.alloc_size;
		info->ea_size.out.attrib = info2->generic.out.attrib;
		info->ea_size.out.ea_size = info2->generic.out.ea_size;
		return NT_STATUS_OK;

	case RAW_FILEINFO_STANDARD_INFO:
	case RAW_FILEINFO_STANDARD_INFORMATION:
		info->standard_info.out.alloc_size = info2->generic.out.alloc_size;
		info->standard_info.out.size = info2->generic.out.size;
		info->standard_info.out.nlink = info2->generic.out.nlink;
		info->standard_info.out.delete_pending = info2->generic.out.delete_pending;
		info->standard_info.out.directory = info2->generic.out.directory;
		return NT_STATUS_OK;

	case RAW_FILEINFO_INTERNAL_INFORMATION:
		info->internal_information.out.file_id = info2->generic.out.file_id;
		return NT_STATUS_OK;

	case RAW_FILEINFO_EA_INFO:
	case RAW_FILEINFO_EA_INFORMATION:
		info->ea_info.out.ea_size = info2->generic.out.ea_size;
		return NT_STATUS_OK;

	case RAW_FILEINFO_ATTRIBUTE_TAG_INFORMATION:
		info->attribute_tag_information.out.attrib = info2->generic.out.attrib;
		info->attribute_tag_information.out.reparse_tag = info2->generic.out.reparse_tag;
		return NT_STATUS_OK;

	case RAW_FILEINFO_STREAM_INFO:
	case RAW_FILEINFO_STREAM_INFORMATION:
		info->stream_info.out.num_streams = info2->generic.out.num_streams;
		if (info->stream_info.out.num_streams > 0) {
			info->stream_info.out.streams = talloc(req, 
				info->stream_info.out.num_streams * sizeof(struct stream_struct));
			if (!info->stream_info.out.streams) {
				DEBUG(2,("ntvfs_map_fileinfo: no memory for %d streams\n",
					info->stream_info.out.num_streams));
				return NT_STATUS_NO_MEMORY;
			}
			for (i=0; i < info->stream_info.out.num_streams; i++) {
				info->stream_info.out.streams[i] = info2->generic.out.streams[i];
				info->stream_info.out.streams[i].stream_name.s = 
					talloc_strdup(req, info2->generic.out.streams[i].stream_name.s);
				if (!info->stream_info.out.streams[i].stream_name.s) {
					DEBUG(2,("ntvfs_map_fileinfo: no memory for stream_name\n"));
					return NT_STATUS_NO_MEMORY;
				}
			}
		}
		return NT_STATUS_OK;

	case RAW_FILEINFO_NAME_INFO:
	case RAW_FILEINFO_NAME_INFORMATION:
		info->name_info.out.fname.s = talloc_strdup(req, info2->generic.out.fname.s);
		info->name_info.out.fname.private_length = info2->generic.out.fname.private_length;
		return NT_STATUS_OK;
		
	case RAW_FILEINFO_ALT_NAME_INFO:
	case RAW_FILEINFO_ALT_NAME_INFORMATION:
		info->alt_name_info.out.fname.s = talloc_strdup(req, info2->generic.out.alt_fname.s);
		info->alt_name_info.out.fname.private_length = info2->generic.out.alt_fname.private_length;
		return NT_STATUS_OK;
	
	case RAW_FILEINFO_POSITION_INFORMATION:
		info->position_information.out.position = info2->generic.out.position;
		return NT_STATUS_OK;
	
	case RAW_FILEINFO_ALL_EAS:
		info->all_eas.out.num_eas = info2->generic.out.num_eas;
		if (info->all_eas.out.num_eas > 0) {
			info->all_eas.out.eas = talloc(req, 
				info->all_eas.out.num_eas * sizeof(struct ea_struct));
			if (!info->all_eas.out.eas) {
				DEBUG(2,("ntvfs_map_fileinfo: no memory for %d eas\n",
					info->all_eas.out.num_eas));
				return NT_STATUS_NO_MEMORY;
			}
			for (i = 0; i < info->all_eas.out.num_eas; i++) {
				info->all_eas.out.eas[i] = info2->generic.out.eas[i];
				info->all_eas.out.eas[i].name.s = 
					talloc_strdup(req, info2->generic.out.eas[i].name.s);
				if (!info->all_eas.out.eas[i].name.s) {
					DEBUG(2,("ntvfs_map_fileinfo: no memory for stream_name\n"));
					return NT_STATUS_NO_MEMORY;
				}
				info->all_eas.out.eas[i].value.data = 
					talloc_memdup(req,
						info2->generic.out.eas[i].value.data,
						info2->generic.out.eas[i].value.length);
				if (!info->all_eas.out.eas[i].value.data) {
					DEBUG(2,("ntvfs_map_fileinfo: no memory for stream_name\n"));
					return NT_STATUS_NO_MEMORY;
				}
			}
		}
		return NT_STATUS_OK;
		
	case RAW_FILEINFO_IS_NAME_VALID:
		return NT_STATUS_OK;
		
	case RAW_FILEINFO_COMPRESSION_INFO:
	case RAW_FILEINFO_COMPRESSION_INFORMATION:
		info->compression_info.out.compressed_size = info2->generic.out.compressed_size;
		info->compression_info.out.format = info2->generic.out.format;
		info->compression_info.out.unit_shift = info2->generic.out.unit_shift;
		info->compression_info.out.chunk_shift = info2->generic.out.chunk_shift;
		info->compression_info.out.cluster_shift = info2->generic.out.cluster_shift;
		return NT_STATUS_OK;
		
	case RAW_FILEINFO_ACCESS_INFORMATION:
		info->access_information.out.access_flags = info2->generic.out.access_flags;
		return NT_STATUS_OK;
		
	case RAW_FILEINFO_MODE_INFORMATION:
		info->mode_information.out.mode = info2->generic.out.mode;
		return NT_STATUS_OK;
		
	case RAW_FILEINFO_ALIGNMENT_INFORMATION:
		info->alignment_information.out.alignment_requirement =
			info2->generic.out.alignment_requirement;
		return NT_STATUS_OK;
#if 0	
	case RAW_FILEINFO_UNIX_BASIC:
		info->unix_basic_info.out.end_of_file = info2->generic.out.end_of_file;
		info->unix_basic_info.out.num_bytes = info2->generic.out.size;
		info->unix_basic_info.out.status_change_time = info2->generic.out.change_time;
		info->unix_basic_info.out.access_time = info2->generic.out.access_time;
		info->unix_basic_info.out.change_time = info2->generic.out.change_time;
		info->unix_basic_info.out.uid = info2->generic.out.uid;
		info->unix_basic_info.out.gid = info2->generic.out.gid;
		info->unix_basic_info.out.file_type = info2->generic.out.file_type;
		info->unix_basic_info.out.dev_major = info2->generic.out.device;
		info->unix_basic_info.out.dev_minor = info2->generic.out.device;
		info->unix_basic_info.out.unique_id = info2->generic.out.inode;
		info->unix_basic_info.out.permissions = info2->generic.out.permissions;
		info->unix_basic_info.out.nlink = info2->generic.out.nlink;
		return NT_STATUS_OK;
		
	case RAW_FILEINFO_UNIX_LINK:
		info->unix_link_info.out.link_dest = info2->generic.out.link_dest;
		return NT_STATUS_OK;
#endif
	}

	return NT_STATUS_INVALID_LEVEL;
}

/* 
   NTVFS fileinfo generic to any mapper
*/
NTSTATUS ntvfs_map_qfileinfo(struct smbsrv_request *req, union smb_fileinfo *info, 
			     struct ntvfs_module_context *ntvfs)
{
	NTSTATUS status;
	union smb_fileinfo *info2;

	info2 = talloc_p(req, union smb_fileinfo);
	if (info2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (info->generic.level == RAW_FILEINFO_GENERIC) {
		return NT_STATUS_INVALID_LEVEL;
	}

	/* ask the backend for the generic info */
	info2->generic.level = RAW_FILEINFO_GENERIC;
	info2->generic.in.fnum = info->generic.in.fnum;

	status = ntvfs->ops->qfileinfo(ntvfs, req, info2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return ntvfs_map_fileinfo(req, info, info2);
}

/* 
   NTVFS pathinfo generic to any mapper
*/
NTSTATUS ntvfs_map_qpathinfo(struct smbsrv_request *req, union smb_fileinfo *info, 
			     struct ntvfs_module_context *ntvfs)
{
	NTSTATUS status;
	union smb_fileinfo *info2;

	info2 = talloc_p(req, union smb_fileinfo);
	if (info2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (info->generic.level == RAW_FILEINFO_GENERIC) {
		return NT_STATUS_INVALID_LEVEL;
	}

	/* ask the backend for the generic info */
	info2->generic.level = RAW_FILEINFO_GENERIC;
	info2->generic.in.fname = info->generic.in.fname;

	/* must be synchronous, or we won't be called to do the 
	   translation */
	req->control_flags &= ~REQ_CONTROL_MAY_ASYNC;

	status = ntvfs->ops->qpathinfo(ntvfs, req, info2);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return ntvfs_map_fileinfo(req, info, info2);
}


/* 
   NTVFS lock generic to any mapper
*/
NTSTATUS ntvfs_map_lock(struct smbsrv_request *req, union smb_lock *lck, 
			struct ntvfs_module_context *ntvfs)
{
	union smb_lock *lck2;
	struct smb_lock_entry *locks;

	lck2 = talloc_p(req, union smb_lock);
	if (lck2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	locks = talloc_array_p(lck2, struct smb_lock_entry, 1);
	if (locks == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (lck->generic.level) {
	case RAW_LOCK_LOCKX:
		return NT_STATUS_INVALID_LEVEL;

	case RAW_LOCK_LOCK:
		lck2->generic.in.ulock_cnt = 0;
		lck2->generic.in.lock_cnt = 1;
		break;

	case RAW_LOCK_UNLOCK:
		lck2->generic.in.ulock_cnt = 1;
		lck2->generic.in.lock_cnt = 0;
		break;
	}

	lck2->generic.level = RAW_LOCK_GENERIC;
	lck2->generic.in.fnum = lck->lock.in.fnum;
	lck2->generic.in.mode = 0;
	lck2->generic.in.timeout = 0;
	lck2->generic.in.locks = locks;
	locks->pid = req->smbpid;
	locks->offset = lck->lock.in.offset;
	locks->count = lck->lock.in.count;

	return ntvfs->ops->lock(ntvfs, req, lck2);
}


/* 
   NTVFS write generic to any mapper
*/
NTSTATUS ntvfs_map_write(struct smbsrv_request *req, union smb_write *wr, 
			 struct ntvfs_module_context *ntvfs)
{
	union smb_write *wr2;
	union smb_lock *lck;
	union smb_close *cl;
	NTSTATUS status;

	wr2 = talloc_p(req, union smb_write);
	if (wr2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	wr2->generic.level = RAW_WRITE_GENERIC;

	/* we can't map asynchronously */
	req->control_flags &= ~REQ_CONTROL_MAY_ASYNC;

	switch (wr->generic.level) {
	case RAW_WRITE_WRITEX:
		status = NT_STATUS_INVALID_LEVEL;
		break;

	case RAW_WRITE_WRITE:
		wr2->generic.in.fnum      = wr->write.in.fnum;
		wr2->generic.in.offset    = wr->write.in.offset;
		wr2->generic.in.wmode     = 0;
		wr2->generic.in.remaining = wr->write.in.remaining;
		wr2->generic.in.count     = wr->write.in.count;
		wr2->generic.in.data      = wr->write.in.data;
		status = ntvfs->ops->write(ntvfs, req, wr2);
		wr->write.out.nwritten    = wr2->generic.out.nwritten;
		break;

	case RAW_WRITE_WRITEUNLOCK:
		lck = talloc_p(wr2, union smb_lock);
		if (lck == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		wr2->generic.in.fnum      = wr->writeunlock.in.fnum;
		wr2->generic.in.offset    = wr->writeunlock.in.offset;
		wr2->generic.in.wmode     = 0;
		wr2->generic.in.remaining = wr->writeunlock.in.remaining;
		wr2->generic.in.count     = wr->writeunlock.in.count;
		wr2->generic.in.data      = wr->writeunlock.in.data;

		lck->unlock.level      = RAW_LOCK_UNLOCK;
		lck->unlock.in.fnum    = wr->writeunlock.in.fnum;
		lck->unlock.in.count   = wr->writeunlock.in.count;
		lck->unlock.in.offset  = wr->writeunlock.in.offset;

		status = ntvfs->ops->write(ntvfs, req, wr2);

		wr->writeunlock.out.nwritten = wr2->generic.out.nwritten;

		if (NT_STATUS_IS_OK(status) && 
		    lck->unlock.in.count != 0) {
			status = ntvfs->ops->lock(ntvfs, req, lck);
		}
		break;

	case RAW_WRITE_WRITECLOSE:
		cl = talloc_p(wr2, union smb_close);
		if (cl == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		wr2->generic.in.fnum      = wr->writeclose.in.fnum;
		wr2->generic.in.offset    = wr->writeclose.in.offset;
		wr2->generic.in.wmode     = 0;
		wr2->generic.in.remaining = 0;
		wr2->generic.in.count     = wr->writeclose.in.count;
		wr2->generic.in.data      = wr->writeclose.in.data;

		cl->close.level           = RAW_CLOSE_CLOSE;
		cl->close.in.fnum         = wr->writeclose.in.fnum;
		cl->close.in.write_time   = wr->writeclose.in.mtime;

		status = ntvfs->ops->write(ntvfs, req, wr2);
		wr->writeclose.out.nwritten    = wr2->generic.out.nwritten;

		if (NT_STATUS_IS_OK(status) &&
		    wr2->generic.in.count != 0) {
			status = ntvfs->ops->close(ntvfs, req, cl);
		}
		break;

	case RAW_WRITE_SPLWRITE:
		wr2->generic.in.fnum      = wr->splwrite.in.fnum;
		wr2->generic.in.offset    = 0;
		wr2->generic.in.wmode     = 0;
		wr2->generic.in.remaining = 0;
		wr2->generic.in.count     = wr->splwrite.in.count;
		wr2->generic.in.data      = wr->splwrite.in.data;
		status = ntvfs->ops->write(ntvfs, req, wr2);
		break;
	}


	return status;
}


/* 
   NTVFS read generic to any mapper
*/
NTSTATUS ntvfs_map_read(struct smbsrv_request *req, union smb_read *rd, 
			 struct ntvfs_module_context *ntvfs)
{
	union smb_read *rd2;
	union smb_lock *lck;
	NTSTATUS status;

	rd2 = talloc_p(req, union smb_read);
	if (rd2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	rd2->generic.level = RAW_READ_GENERIC;

	/* we can't map asynchronously */
	req->control_flags &= ~REQ_CONTROL_MAY_ASYNC;

	switch (rd->generic.level) {
	case RAW_READ_READX:
		status = NT_STATUS_INVALID_LEVEL;
		break;

	case RAW_READ_READ:
		rd2->generic.in.fnum      = rd->read.in.fnum;
		rd2->generic.in.offset    = rd->read.in.offset;
		rd2->generic.in.mincnt    = rd->read.in.count;
		rd2->generic.in.maxcnt    = rd->read.in.count;
		rd2->generic.in.remaining = rd->read.in.remaining;
		rd2->generic.out.data     = rd->read.out.data;
		status = ntvfs->ops->read(ntvfs, req, rd2);
		rd->read.out.nread        = rd2->generic.out.nread;
		break;

	case RAW_READ_READBRAW:
		rd2->generic.in.fnum      = rd->readbraw.in.fnum;
		rd2->generic.in.offset    = rd->readbraw.in.offset;
		rd2->generic.in.mincnt    = rd->readbraw.in.mincnt;
		rd2->generic.in.maxcnt    = rd->readbraw.in.maxcnt;
		rd2->generic.in.remaining = 0;
		rd2->generic.out.data     = rd->readbraw.out.data;
		status = ntvfs->ops->read(ntvfs, req, rd2);
		rd->readbraw.out.nread    = rd2->generic.out.nread;
		break;

	case RAW_READ_LOCKREAD:
		lck = talloc_p(rd2, union smb_lock);
		if (lck == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		rd2->generic.in.fnum      = rd->lockread.in.fnum;
		rd2->generic.in.offset    = rd->lockread.in.offset;
		rd2->generic.in.mincnt    = rd->lockread.in.count;
		rd2->generic.in.maxcnt    = rd->lockread.in.count;
		rd2->generic.in.remaining = rd->lockread.in.remaining;
		rd2->generic.out.data     = rd->lockread.out.data;

		lck->lock.level      = RAW_LOCK_LOCK;
		lck->lock.in.fnum    = rd->lockread.in.fnum;
		lck->lock.in.count   = rd->lockread.in.count;
		lck->lock.in.offset  = rd->lockread.in.offset;

		status = ntvfs->ops->lock(ntvfs, req, lck);

		if (NT_STATUS_IS_OK(status)) {
			status = ntvfs->ops->read(ntvfs, req, rd2);
			rd->lockread.out.nread = rd2->generic.out.nread;
		}
		break;
	}


	return status;
}


/* 
   NTVFS close generic to any mapper
*/
NTSTATUS ntvfs_map_close(struct smbsrv_request *req, union smb_close *cl, 
			 struct ntvfs_module_context *ntvfs)
{
	union smb_close *cl2;

	cl2 = talloc_p(req, union smb_close);
	if (cl2 == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (cl->generic.level) {
	case RAW_CLOSE_CLOSE:
		return NT_STATUS_INVALID_LEVEL;

	case RAW_CLOSE_SPLCLOSE:
		cl2->close.level   = RAW_CLOSE_CLOSE;
		cl2->close.in.fnum = cl->splclose.in.fnum;
		break;
	}

	return ntvfs->ops->close(ntvfs, req, cl2);
}
