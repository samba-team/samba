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

struct unix_error_map unix_dos_nt_errmap[] = {
	{ EPERM, ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ EACCES, ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ ENOENT, ERRDOS, ERRbadfile, NT_STATUS_OBJECT_NAME_NOT_FOUND },
	{ ENOTDIR, ERRDOS, ERRbadpath,  NT_STATUS_OBJECT_PATH_NOT_FOUND },
	{ EIO, ERRHRD, ERRgeneral, NT_STATUS_IO_DEVICE_ERROR },
	{ EBADF, ERRSRV, ERRsrverror, NT_STATUS_INVALID_HANDLE },
	{ EINVAL, ERRSRV, ERRsrverror, NT_STATUS_INVALID_HANDLE },
	{ EEXIST, ERRDOS, ERRfilexists, NT_STATUS_OBJECT_NAME_COLLISION},
	{ ENFILE, ERRDOS, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES },
	{ EMFILE, ERRDOS, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES },
	{ ENOSPC, ERRHRD, ERRdiskfull, NT_STATUS_DISK_FULL },
#ifdef EDQUOT
	{ EDQUOT, ERRHRD, ERRdiskfull, NT_STATUS_DISK_FULL },
#endif
#ifdef ENOTEMPTY
	{ ENOTEMPTY, ERRDOS, ERRnoaccess, NT_STATUS_DIRECTORY_NOT_EMPTY },
#endif
#ifdef EXDEV
	{ EXDEV, ERRDOS, ERRdiffdevice, NT_STATUS_NOT_SAME_DEVICE },
#endif
#ifdef EROFS
	{ EROFS, ERRHRD, ERRnowrite, NT_STATUS_ACCESS_DENIED },
#endif
#ifdef ENAMETOOLONG
	{ ENAMETOOLONG, ERRDOS, 206, NT_STATUS_OBJECT_NAME_INVALID },
#endif
	{ 0, 0, 0, NT_STATUS_OK }
};

/*********************************************************************
 Map an NT error code from a Unix error code.
*********************************************************************/

NTSTATUS map_nt_error_from_unix(int unix_error)
{
	int i = 0;

	if (unix_error == 0)
		return NT_STATUS_OK;

	/* Look through list */
	while(unix_dos_nt_errmap[i].unix_error != 0) {
		if (unix_dos_nt_errmap[i].unix_error == unix_error)
			return unix_dos_nt_errmap[i].nt_error;
		i++;
	}

	/* Default return */
	return NT_STATUS_ACCESS_DENIED;
}
