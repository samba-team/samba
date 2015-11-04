/*
  Unix SMB/CIFS implementation.
  Samba VFS module for marking all files as offline.

  (c) Uri Simchoni, 2015

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

static uint32_t offline_fs_capabilities(struct vfs_handle_struct *handle,
					enum timestamp_set_resolution *p_ts_res)
{
	return SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res) |
	       FILE_SUPPORTS_REMOTE_STORAGE;
}

static bool offline_is_offline(struct vfs_handle_struct *handle,
			       const struct smb_filename *fname,
			       SMB_STRUCT_STAT *stbuf)
{
	return true;
}

static struct vfs_fn_pointers offline_fns = {
    .fs_capabilities_fn = offline_fs_capabilities,
    .is_offline_fn = offline_is_offline,
};

NTSTATUS vfs_offline_init(void);
NTSTATUS vfs_offline_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "offline",
				&offline_fns);
}
