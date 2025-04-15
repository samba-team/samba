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

static const struct {
	int unix_error;
	NTSTATUS nt_error;
} unix_nt_errmap[] = {
	{ EAGAIN,       NT_STATUS_NETWORK_BUSY },
	{ EINTR,        NT_STATUS_RETRY },
#ifdef ENOBUFS
	{ ENOBUFS,      NT_STATUS_INSUFFICIENT_RESOURCES },
#endif
#ifdef EWOULDBLOCK
	{ EWOULDBLOCK,  NT_STATUS_NETWORK_BUSY },
#endif
	{ EPERM,        NT_STATUS_ACCESS_DENIED },
	{ EACCES,       NT_STATUS_ACCESS_DENIED },
	{ ENOENT,       NT_STATUS_OBJECT_NAME_NOT_FOUND },
	{ ENOTDIR,      NT_STATUS_NOT_A_DIRECTORY },
	{ EIO,          NT_STATUS_IO_DEVICE_ERROR },
	{ EBADF,        NT_STATUS_INVALID_HANDLE },
	{ EINVAL,       NT_STATUS_INVALID_PARAMETER },
	{ EEXIST,       NT_STATUS_OBJECT_NAME_COLLISION},
	{ ENFILE,       NT_STATUS_TOO_MANY_OPENED_FILES },
	{ EMFILE,       NT_STATUS_TOO_MANY_OPENED_FILES },
	{ ENOSPC,       NT_STATUS_DISK_FULL },
	{ ENOMEM,       NT_STATUS_NO_MEMORY },
	{ EISDIR,       NT_STATUS_FILE_IS_A_DIRECTORY},
	{ EMSGSIZE,	NT_STATUS_PORT_MESSAGE_TOO_LONG },
#ifdef EPIPE
	{ EPIPE,        NT_STATUS_CONNECTION_DISCONNECTED},
#endif
	{ EMLINK,       NT_STATUS_TOO_MANY_LINKS },
	{ ENOSYS,       NT_STATUS_NOT_SUPPORTED },
#ifdef ELOOP
	{ ELOOP,        NT_STATUS_OBJECT_PATH_NOT_FOUND },
#endif
#ifdef EFTYPE
	{ EFTYPE,       NT_STATUS_OBJECT_PATH_NOT_FOUND },
#endif
#ifdef EDQUOT
	{ EDQUOT,       NT_STATUS_DISK_FULL }, /* Windows apps need this, not NT_STATUS_QUOTA_EXCEEDED */
#endif
#ifdef ENOTEMPTY
	{ ENOTEMPTY,    NT_STATUS_DIRECTORY_NOT_EMPTY },
#endif
#ifdef EXDEV
	{ EXDEV,        NT_STATUS_NOT_SAME_DEVICE },
#endif
#ifdef EROFS
	{ EROFS,        NT_STATUS_MEDIA_WRITE_PROTECTED },
#endif
#ifdef ENAMETOOLONG
	{ ENAMETOOLONG, NT_STATUS_OBJECT_NAME_INVALID },
#endif
#ifdef EFBIG
	{ EFBIG,        NT_STATUS_DISK_FULL },
#endif
#ifdef EADDRINUSE
	{ EADDRINUSE,   NT_STATUS_ADDRESS_ALREADY_ASSOCIATED},
#endif
#ifdef ENETUNREACH
	{ ENETUNREACH,  NT_STATUS_NETWORK_UNREACHABLE},
#endif
#ifdef EHOSTUNREACH
        { EHOSTUNREACH, NT_STATUS_HOST_UNREACHABLE},
#endif
#ifdef ECONNREFUSED
	{ ECONNREFUSED, NT_STATUS_CONNECTION_REFUSED},
#endif
#ifdef ETIMEDOUT
	{ ETIMEDOUT,    NT_STATUS_IO_TIMEOUT},
#endif
#ifdef ECONNABORTED
	{ ECONNABORTED, NT_STATUS_CONNECTION_ABORTED},
#endif
#ifdef ECONNRESET
	{ ECONNRESET,   NT_STATUS_CONNECTION_RESET},
#endif
#ifdef ENODEV
	{ ENODEV,       NT_STATUS_DEVICE_DOES_NOT_EXIST},
#endif
#ifdef ENOATTR
	{ ENOATTR,      NT_STATUS_NOT_FOUND },
#endif
#ifdef ECANCELED
	{ ECANCELED,    NT_STATUS_CANCELLED},
#endif
#ifdef ENOTSUP
        { ENOTSUP,      NT_STATUS_NOT_SUPPORTED},
#endif
#ifdef ETXTBSY
	{ ETXTBSY,      NT_STATUS_SHARING_VIOLATION },
#endif
#ifdef EOVERFLOW
	{ EOVERFLOW,      NT_STATUS_ALLOTTED_SPACE_EXCEEDED },
#endif
	{ EINPROGRESS,	NT_STATUS_MORE_PROCESSING_REQUIRED },
#ifdef ERANGE
	{ ERANGE, NT_STATUS_INTEGER_OVERFLOW },
#endif
#ifdef ENXIO
	{ ENXIO, NT_STATUS_ILLEGAL_FUNCTION },
#endif
#ifdef EPROTONOSUPPORT
	{ EPROTONOSUPPORT, NT_STATUS_PROTOCOL_NOT_SUPPORTED },
#endif
};

/*********************************************************************
 Map an NT error code from a Unix error code.
*********************************************************************/

NTSTATUS map_nt_error_from_unix(int unix_error)
{
	size_t i = 0;

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
	for (i=0;i<ARRAY_SIZE(unix_nt_errmap);i++) {
		if (unix_nt_errmap[i].unix_error == unix_error) {
			return unix_nt_errmap[i].nt_error;
		}
	}

	/* Default return */
	return NT_STATUS_ACCESS_DENIED;
}
