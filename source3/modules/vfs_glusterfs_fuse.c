/*
   Unix SMB/CIFS implementation.

   Copyright (c) 2019 Guenther Deschner <gd@samba.org>

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

#define GLUSTER_NAME_MAX 255

static int vfs_gluster_fuse_get_real_filename(struct vfs_handle_struct *handle,
					      const char *path,
					      const char *name,
					      TALLOC_CTX *mem_ctx,
					      char **_found_name)
{
	int ret;
	char key_buf[GLUSTER_NAME_MAX + 64];
	char val_buf[GLUSTER_NAME_MAX + 1];
	char *found_name = NULL;

	if (strlen(name) >= GLUSTER_NAME_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	snprintf(key_buf, GLUSTER_NAME_MAX + 64,
		 "glusterfs.get_real_filename:%s", name);

	ret = getxattr(path, key_buf, val_buf, GLUSTER_NAME_MAX + 1);
	if (ret == -1) {
		if (errno == ENOATTR) {
			errno = EOPNOTSUPP;
		}
		return -1;
	}

	found_name = talloc_strdup(mem_ctx, val_buf);
	if (found_name == NULL) {
		errno = ENOMEM;
		return -1;
	}
	*_found_name = found_name;
	return 0;
}

struct vfs_fn_pointers glusterfs_fuse_fns = {

	/* File Operations */
	.get_real_filename_fn = vfs_gluster_fuse_get_real_filename,
};

static_decl_vfs;
NTSTATUS vfs_glusterfs_fuse_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"glusterfs_fuse", &glusterfs_fuse_fns);
}
