/* 
 *  Unix SMB/CIFS implementation.
 *  map unix to NT errors, an excerpt of libsmb/errormap.c
 *  Copyright (C) Andrew Tridgell 2001
 *  Copyright (C) Andrew Bartlett 2001
 *  Copyright (C) Tim Potter 2000
 *  Copyright (C) Jeremy Allison 2007
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"

/* Mapping from Unix, to NT error numbers */

const struct unix_error_map unix_dos_nt_errmap[] = {
	{ EPERM, ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ EACCES, ERRDOS, ERRnoaccess, NT_STATUS_ACCESS_DENIED },
	{ ENOENT, ERRDOS, ERRbadfile, NT_STATUS_OBJECT_NAME_NOT_FOUND },
	{ ENOTDIR, ERRDOS, ERRbadpath,  NT_STATUS_NOT_A_DIRECTORY },
	{ EIO, ERRHRD, ERRgeneral, NT_STATUS_IO_DEVICE_ERROR },
	{ EBADF, ERRSRV, ERRsrverror, NT_STATUS_INVALID_HANDLE },
	{ EINVAL, ERRSRV, ERRsrverror, NT_STATUS_INVALID_HANDLE },
	{ EEXIST, ERRDOS, ERRfilexists, NT_STATUS_OBJECT_NAME_COLLISION},
	{ ENFILE, ERRDOS, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES },
	{ EMFILE, ERRDOS, ERRnofids, NT_STATUS_TOO_MANY_OPENED_FILES },
	{ ENOSPC, ERRHRD, ERRdiskfull, NT_STATUS_DISK_FULL },
	{ ENOMEM, ERRDOS, ERRnomem, NT_STATUS_NO_MEMORY },
	{ EISDIR, ERRDOS, ERRnoaccess, NT_STATUS_FILE_IS_A_DIRECTORY},
	{ EMLINK, ERRDOS, ERRgeneral, NT_STATUS_TOO_MANY_LINKS },
	{ EINTR,  ERRHRD, ERRgeneral, NT_STATUS_RETRY },
#ifdef ELOOP
	{ ELOOP, ERRDOS, ERRbadpath, NT_STATUS_OBJECT_PATH_NOT_FOUND },
#endif
#ifdef EDQUOT
	{ EDQUOT, ERRHRD, ERRdiskfull, NT_STATUS_DISK_FULL }, /* Windows apps need this, not NT_STATUS_QUOTA_EXCEEDED */
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
#ifdef EFBIG
	{ EFBIG, ERRHRD, ERRdiskfull, NT_STATUS_DISK_FULL },
#endif
#ifdef ENOBUFS
	{ ENOBUFS, ERRDOS, ERRnomem, NT_STATUS_INSUFFICIENT_RESOURCES },
#endif
	{ EAGAIN, ERRDOS, 111, NT_STATUS_NETWORK_BUSY },
#ifdef EADDRINUSE
	{ EADDRINUSE, ERRDOS, 52, NT_STATUS_ADDRESS_ALREADY_ASSOCIATED},
#endif
#ifdef ENETUNREACH
	{ ENETUNREACH, ERRHRD, ERRgeneral, NT_STATUS_NETWORK_UNREACHABLE},
#endif
#ifdef EHOSTUNREACH
		{ EHOSTUNREACH, ERRHRD, ERRgeneral, NT_STATUS_HOST_UNREACHABLE},
#endif
#ifdef ECONNREFUSED
	{ ECONNREFUSED, ERRHRD, ERRgeneral, NT_STATUS_CONNECTION_REFUSED},
#endif
#ifdef ETIMEDOUT
	{ ETIMEDOUT, ERRHRD, 121, NT_STATUS_IO_TIMEOUT},
#endif
#ifdef ECONNABORTED
	{ ECONNABORTED, ERRHRD, ERRgeneral, NT_STATUS_CONNECTION_ABORTED},
#endif
#ifdef ENODEV
	{ ENODEV, ERRDOS, 55, NT_STATUS_DEVICE_DOES_NOT_EXIST},
#endif
#ifdef EPIPE
	{ EPIPE, ERRDOS, 109, NT_STATUS_PIPE_BROKEN},
#endif
#ifdef EWOULDBLOCK
	{ EWOULDBLOCK, ERRDOS, 111, NT_STATUS_NETWORK_BUSY },
#endif
#ifdef ENOATTR
	{ ENOATTR, ERRDOS, ERRbadfile, NT_STATUS_NOT_FOUND },
#endif

	{ 0, 0, 0, NT_STATUS_OK }
};

/*********************************************************************
 Map an NT error code from a Unix error code.
*********************************************************************/

NTSTATUS map_nt_error_from_unix(int unix_error)
{
	int i = 0;

	if (unix_error == 0) {
		/* we map this to an error, not success, as this
		   function is only called in an error path. Lots of
		   our virtualised functions may fail without making a
		   unix system call that fails (such as when they are
		   checking for some handle existing), so unix_error
		   may be unset
		*/
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* Look through list */
	while(unix_dos_nt_errmap[i].unix_error != 0) {
		if (unix_dos_nt_errmap[i].unix_error == unix_error)
			return unix_dos_nt_errmap[i].nt_error;
		i++;
	}

	/* Default return */
	return NT_STATUS_ACCESS_DENIED;
}
