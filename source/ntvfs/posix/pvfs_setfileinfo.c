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

	f = pvfs_find_fd(pvfs, req, info->generic.file.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	switch (info->generic.level) {
	case RAW_SFILEINFO_END_OF_FILE_INFO:
	case RAW_SFILEINFO_END_OF_FILE_INFORMATION:
		if (ftruncate(f->fd,
			      info->end_of_file_info.in.size) != 0) {
			return pvfs_map_errno(pvfs, errno);
		}
		break;
	case RAW_SFILEINFO_SETATTRE:
		unix_times.actime = info->setattre.in.access_time;
		unix_times.modtime = info->setattre.in.write_time;
	
		if (unix_times.actime == 0 && unix_times.modtime == 0) {
			break;
		} 

		/* set modify time = to access time if modify time was 0 */
		if (unix_times.actime != 0 && unix_times.modtime == 0) {
			unix_times.modtime = unix_times.actime;
		}

		/* Set the date on this file */
		if (utime(f->name->full_name, &unix_times) == -1) {
			return NT_STATUS_ACCESS_DENIED;
		}
  		break;
	}
	return NT_STATUS_OK;
}
