/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - xattr support using filesystem xattrs

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
#include "system/filesys.h"
#include "vfs_posix.h"

/*
  pull a xattr as a blob, from either a file or a file descriptor
*/
NTSTATUS pull_xattr_blob_system(struct pvfs_state *pvfs,
				TALLOC_CTX *mem_ctx,
				const char *attr_name, 
				const char *fname, 
				int fd, 
				size_t estimated_size,
				DATA_BLOB *blob)
{
#if HAVE_XATTR_SUPPORT
	int ret;

	*blob = data_blob_talloc(mem_ctx, NULL, estimated_size);
	if (blob->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

again:
	if (fd != -1) {
		ret = fgetxattr(fd, attr_name, blob->data, estimated_size);
	} else {
		ret = getxattr(fname, attr_name, blob->data, estimated_size);
	}
	if (ret == -1 && errno == ERANGE) {
		estimated_size *= 2;
		blob->data = talloc_realloc(mem_ctx, blob->data, estimated_size);
		if (blob->data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		blob->length = estimated_size;
		goto again;
	}

	if (ret == -1) {
		data_blob_free(blob);
		return pvfs_map_errno(pvfs, errno);
	}

	blob->length = ret;

	return NT_STATUS_OK;
#else
	return NT_STATUS_NOT_SUPPORTED;
#endif
}

/*
  push a xattr as a blob, from either a file or a file descriptor
*/
NTSTATUS push_xattr_blob_system(struct pvfs_state *pvfs,
				const char *attr_name, 
				const char *fname, 
				int fd, 
				const DATA_BLOB *blob)
{
#if HAVE_XATTR_SUPPORT
	int ret;

	if (fd != -1) {
		ret = fsetxattr(fd, attr_name, blob->data, blob->length, 0);
	} else {
		ret = setxattr(fname, attr_name, blob->data, blob->length, 0);
	}
	if (ret == -1) {
		return pvfs_map_errno(pvfs, errno);
	}

	return NT_STATUS_OK;
#else
	return NT_STATUS_NOT_SUPPORTED;
#endif
}


/*
  delete a xattr
*/
NTSTATUS delete_xattr_system(struct pvfs_state *pvfs, const char *attr_name, 
			     const char *fname, int fd)
{
#if HAVE_XATTR_SUPPORT
	int ret;

	if (fd != -1) {
		ret = fremovexattr(fd, attr_name);
	} else {
		ret = removexattr(fname, attr_name);
	}
	if (ret == -1) {
		return pvfs_map_errno(pvfs, errno);
	}

	return NT_STATUS_OK;
#else
	return NT_STATUS_NOT_SUPPORTED;
#endif
}

/*
  unlink a file - cleanup any xattrs
*/
NTSTATUS unlink_xattr_system(struct pvfs_state *pvfs, const char *fname)
{
	/* nothing needs to be done for filesystem based xattrs */
	return NT_STATUS_OK;
}
