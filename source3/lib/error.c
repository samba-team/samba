/* 
 *  Unix SMB/Netbios implementation.
 *  Version 1.9
 *  Unix/DOS/NT error code conversions
 *  Copyright (C) Tim Potter 2000
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

/* Mapping between Unix, DOS and NT error numbers */

struct {
	int unix_error;
	int dos_error;
	uint32 nt_error;
} unix_dos_nt_errmap[] = {
	{ EPERM, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ EACCES, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ ENOENT, ERRbadfile, NT_STATUS_NO_SUCH_FILE },
	{ ENOTDIR, ERRbadpath, NT_STATUS_NOT_A_DIRECTORY },
	{ EIO, ERRgeneral, NT_STATUS_IO_DEVICE_ERROR },
	{ EBADF, ERRsrverror, NT_STATUS_INVALID_HANDLE },
	{ EINVAL, ERRsrverror, NT_STATUS_INVALID_HANDLE },
	{ EEXIST, ERRfilexists, NT_STATUS_ACCESS_DENIED},
	{ ENFILE, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES },
	{ EMFILE, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES },
	{ ENOSPC, ERRdiskfull, NT_STATUS_DISK_FULL },
#ifdef EDQUOT
	{ EDQUOT, ERRdiskfull, NT_STATUS_DISK_FULL },
#endif
#ifdef ENOTEMPTY
	{ ENOTEMPTY, ERRnoaccess, NT_STATUS_DIRECTORY_NOT_EMPTY },
#endif
#ifdef EXDEV
	{ EXDEV, ERRdiffdevice, NT_STATUS_NOT_SAME_DEVICE },
#endif
	{ EROFS, ERRnowrite, NT_STATUS_ACCESS_DENIED },

	{ 0, 0, 0 }
};

/* Map an NT error code from a Unix error code */
NTSTATUS map_nt_error_from_unix(int unix_error)
{
	int i = 0;

	if (unix_error == 0) return NT_STATUS_OK;

	/* Look through list */
	while(unix_dos_nt_errmap[i].unix_error != 0) {
		if (unix_dos_nt_errmap[i].unix_error == unix_error) {
			return unix_dos_nt_errmap[i].nt_error;
		}

		i++;
	}

	/* Default return */

	return NT_STATUS_ACCESS_DENIED;
}
