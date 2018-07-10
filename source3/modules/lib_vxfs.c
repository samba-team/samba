/*
 Unix SMB/CIFS implementation.
 Wrap VxFS xattr calls.

 Copyright (C) Veritas Technologies LLC <www.veritas.com> 2016

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
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "string.h"
#include "vfs_vxfs.h"

/*
 * Available under GPL at
 * http://www.veritas.com/community/downloads/vxfsmisc-library
 */
#define LIBVXFS "/usr/lib64/vxfsmisc.so"


static int (*vxfs_setxattr_fd_func) (int fd, const char *name,
				     const void *value, size_t len, int flags);
static int (*vxfs_getxattr_fd_func) (int fd, const char *name, void *value,
				     size_t *len);
static int (*vxfs_removexattr_fd_func) (int fd, const char *name);
static int (*vxfs_listxattr_fd_func) (int fd, void *value, size_t *len);
static int (*vxfs_setwxattr_fd_func) (int fd);
static int (*vxfs_clearwxattr_fd_func) (int fd);
static int (*vxfs_checkwxattr_fd_func) (int fd);

int vxfs_setxattr_fd(int fd, const char *name, const void *value,
		     size_t len, int flags)
{
	int ret = -1;

	if (vxfs_setxattr_fd_func == NULL) {
		errno = ENOSYS;
		return ret;
	}

	DEBUG(10, ("Calling vxfs_setxattr_fd\n"));
	ret = vxfs_setxattr_fd_func(fd, name, value, len, flags);
	if (ret) {
		errno = ret;
		ret = -1;
	}

	return ret;
}

int vxfs_setxattr_path(const char *path, const char *name, const void *value,
		       size_t len, int flags, bool is_dir)
{
	int ret, fd = -1;

	if (is_dir) {
		fd = open(path, O_RDONLY|O_DIRECTORY);
	} else {
		fd = open(path, O_WRONLY);
	}

	if (fd == -1) {
		DEBUG(10, ("error in vxfs_setxattr_path: %s\n",
		      strerror(errno)));
		return -1;
	}

	ret = vxfs_setxattr_fd(fd, name, value, len, flags);

	close(fd);

	return ret;
}

int vxfs_getxattr_fd(int fd, const char *name, void *value, size_t len)
{
	int ret;
	size_t size = len;

	if (vxfs_getxattr_fd_func == NULL) {
		errno = ENOSYS;
		return -1;
	}

	DEBUG(10, ("Calling vxfs_getxattr_fd with %s\n", name));
	ret = vxfs_getxattr_fd_func(fd, name, value, &size);
	if (ret) {
		errno = ret;
		if (ret == EFBIG) {
			errno = ERANGE;
		}
		return -1;
	}

	return size;
}

int vxfs_getxattr_path(const char *path, const char *name, void *value,
		       size_t len)
{
	int ret, fd = -1;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		DEBUG(10, ("file not opened: vxfs_getxattr_path for %s\n",
			   path));
		return -1;
	}

	ret = vxfs_getxattr_fd(fd, name, value, len);
	close(fd);

	return ret;
}

int vxfs_removexattr_fd(int fd, const char *name)
{
	int ret = 0;

	if (vxfs_removexattr_fd_func == NULL) {
		errno = ENOSYS;
		return -1;
	}

	DEBUG(10, ("Calling vxfs_removexattr_fd with %s\n", name));
	ret = vxfs_removexattr_fd_func(fd, name);
	if (ret) {
		errno = ret;
		ret = -1;
	}

	return ret;
}

int vxfs_removexattr_path(const char *path, const char *name, bool is_dir)
{
	int ret, fd = -1;

	if (is_dir) {
		fd = open(path, O_RDONLY|O_DIRECTORY);
	} else {
		fd = open(path, O_WRONLY);
	}
	if (fd == -1) {
		DEBUG(10, ("file not opened: vxfs_removexattr_path for %s\n",
			   path));
		return -1;
	}

	ret = vxfs_removexattr_fd(fd, name);
	close(fd);

	return ret;
}

int vxfs_listxattr_fd(int fd, char *list, size_t size)
{
	int ret;
	size_t len = size;

	if (vxfs_listxattr_fd_func == NULL) {
		errno = ENOSYS;
		return -1;
	}

	ret = vxfs_listxattr_fd_func(fd, list, &len);
	DEBUG(10, ("vxfs_listxattr_fd: returned ret = %d\n", ret));
	if (ret) {
		errno = ret;
		if (ret == EFBIG) {
			errno = ERANGE;
		}
		return -1;
	}

	return len;
}

int vxfs_listxattr_path(const char *path, char *list, size_t size)
{
	int ret, fd = -1;

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		DEBUG(10, ("file not opened: vxfs_listxattr_path for %s\n",
			   path));
		return -1;
	}

	ret = vxfs_listxattr_fd(fd, list, size);
	close(fd);

	return ret;
}

int vxfs_setwxattr_fd(int fd)
{
	int ret = 0;

	if (vxfs_setwxattr_fd_func == NULL) {
		errno = ENOSYS;
		return -1;
	}
	ret = vxfs_setwxattr_fd_func(fd);
	DBG_DEBUG("ret = %d\n", ret);
	if (ret != 0) {
		errno = ret;
		ret = -1;
	}

	return ret;
}

int vxfs_setwxattr_path(const char *path, bool is_dir)
{
	int ret, fd = -1;

	if (is_dir) {
		fd = open(path, O_RDONLY|O_DIRECTORY);
	} else {
		fd = open(path, O_WRONLY);
	}
	if (fd == -1) {
		DBG_DEBUG("file %s not opened, errno:%s\n",
			   path, strerror(errno));
		return -1;
	}

	ret = vxfs_setwxattr_fd(fd);
	DBG_DEBUG("ret = %d\n", ret);
	close(fd);

	return ret;
}

int vxfs_clearwxattr_fd(int fd)
{
	int ret;
	if (vxfs_clearwxattr_fd_func == NULL) {
		errno = ENOSYS;
		return -1;
	}
	ret = vxfs_clearwxattr_fd_func(fd);
	DBG_DEBUG("ret = %d\n", ret);
	if (ret != 0) {
		errno = ret;
		ret = -1;
	}

	return ret;
}

int vxfs_clearwxattr_path(const char *path, bool is_dir)
{
	int ret, fd = -1;

	if (is_dir) {
		fd = open(path, O_RDONLY|O_DIRECTORY);
	} else {
		fd = open(path, O_WRONLY);
	}

	if (fd == -1) {
		DBG_DEBUG("file %s not opened, errno:%s\n",
			   path, strerror(errno));
		return -1;
	}
	ret = vxfs_clearwxattr_fd(fd);
	DBG_DEBUG("ret = %d\n", ret);
	close(fd);

	return ret;
}

int vxfs_checkwxattr_fd(int fd)
{
	int ret;

	if (vxfs_checkwxattr_fd_func == NULL) {
		errno = ENOSYS;
		return -1;
	}
	ret = vxfs_checkwxattr_fd_func(fd);
	DBG_DEBUG("ret = %d\n", ret);
	if (ret != 0) {
		errno = ret;
		ret = -1;
	}
	return ret;
}

int vxfs_checkwxattr_path(const char *path)
{
	int ret, fd = -1;

	fd = open(path, O_RDONLY);

	if (fd == -1) {
		DBG_DEBUG("file %s not opened, errno:%s\n",
			   path, strerror(errno));
		return -1;
	}
	ret = vxfs_checkwxattr_fd(fd);
	close(fd);

	return ret;
}

static bool load_lib_vxfs_function(void *lib_handle, void *fn_ptr,
				   const char *fnc_name)
{
	void **vlib_handle = (void **)lib_handle;
	void **fn_pointer = (void **)fn_ptr;

	*fn_pointer = dlsym(*vlib_handle, fnc_name);
	if (*fn_pointer == NULL) {
		DEBUG(10, ("Cannot find symbol for %s\n", fnc_name));
		return true;
	}

	return false;
}

void vxfs_init()
{
	static void *lib_handle = NULL;

	if (lib_handle != NULL ) {
		return;
	}

	lib_handle = dlopen(LIBVXFS, RTLD_LAZY);
	if (lib_handle == NULL) {
		DEBUG(10, ("Cannot get lib handle\n"));
		return;
	}

	DEBUG(10, ("Calling vxfs_init\n"));
	load_lib_vxfs_function(&lib_handle, &vxfs_setxattr_fd_func,
			       "vxfs_nxattr_set");
	load_lib_vxfs_function(&lib_handle, &vxfs_getxattr_fd_func,
			       "vxfs_nxattr_get");
	load_lib_vxfs_function(&lib_handle, &vxfs_removexattr_fd_func,
			       "vxfs_nxattr_remove");
	load_lib_vxfs_function(&lib_handle, &vxfs_listxattr_fd_func,
			       "vxfs_nxattr_list");
	load_lib_vxfs_function(&lib_handle, &vxfs_setwxattr_fd_func,
			       "vxfs_wattr_set");
	load_lib_vxfs_function(&lib_handle, &vxfs_clearwxattr_fd_func,
			       "vxfs_wattr_clear");
	load_lib_vxfs_function(&lib_handle, &vxfs_checkwxattr_fd_func,
			       "vxfs_wattr_check");

}
