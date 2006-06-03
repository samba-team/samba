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
#include "vfs_posix.h"

#if defined(HAVE_XATTR_SUPPORT) && defined(XATTR_ADDITIONAL_OPTIONS)
static ssize_t _wrap_darwin_fgetxattr(int fd, const char *name, void *value, size_t size)
{
	return fgetxattr(fd, name, value, size, 0, 0);
}
static ssize_t _wrap_darwin_getxattr(const char *path, const char *name, void *value, size_t size)
{
	return getxattr(path, name, value, size, 0, 0);
}
static int _wrap_darwin_fsetxattr(int fd, const char *name, void *value, size_t size, int flags)
{
	return fsetxattr(fd, name, value, size, 0, flags);
}
static int _wrap_darwin_setxattr(const char *path, const char *name, void *value, size_t size, int flags)
{
	return setxattr(path, name, value, size, 0, flags);
}
static int _wrap_darwin_fremovexattr(int fd, const char *name)
{
	return fremovexattr(fd, name, 0);
}
static int _wrap_darwin_removexattr(const char *path, const char *name)
{
	return removexattr(path, name, 0);
}
#define fgetxattr	_wrap_darwin_fgetxattr
#define getxattr	_wrap_darwin_getxattr
#define fsetxattr	_wrap_darwin_fsetxattr
#define setxattr	_wrap_darwin_setxattr
#define fremovexattr	_wrap_darwin_fremovexattr
#define removexattr	_wrap_darwin_removexattr
#elif !defined(HAVE_XATTR_SUPPORT)
static ssize_t _none_fgetxattr(int fd, const char *name, void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}
static ssize_t _none_getxattr(const char *path, const char *name, void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}
static int _none_fsetxattr(int fd, const char *name, void *value, size_t size, int flags)
{
	errno = ENOSYS;
	return -1;
}
static int _none_setxattr(const char *path, const char *name, void *value, size_t size, int flags)
{
	errno = ENOSYS;
	return -1;
}
static int _none_fremovexattr(int fd, const char *name)
{
	errno = ENOSYS;
	return -1;
}
static int _none_removexattr(const char *path, const char *name)
{
	errno = ENOSYS;
	return -1;
}
#define fgetxattr	_none_fgetxattr
#define getxattr	_none_getxattr
#define fsetxattr	_none_fsetxattr
#define setxattr	_none_setxattr
#define fremovexattr	_none_fremovexattr
#define removexattr	_none_removexattr
#endif

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
	int ret;

	*blob = data_blob_talloc(mem_ctx, NULL, estimated_size+16);
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
		blob->data = talloc_realloc(mem_ctx, blob->data, 
					    uint8_t, estimated_size);
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
}


/*
  delete a xattr
*/
NTSTATUS delete_xattr_system(struct pvfs_state *pvfs, const char *attr_name, 
			     const char *fname, int fd)
{
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
}

/*
  unlink a file - cleanup any xattrs
*/
NTSTATUS unlink_xattr_system(struct pvfs_state *pvfs, const char *fname)
{
	/* nothing needs to be done for filesystem based xattrs */
	return NT_STATUS_OK;
}
