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

static NTSTATUS offline_get_dos_attributes(struct vfs_handle_struct *handle,
					   struct smb_filename *smb_fname,
					   uint32_t *dosmode)
{
	*dosmode |= FILE_ATTRIBUTE_OFFLINE;
	return SMB_VFS_NEXT_GET_DOS_ATTRIBUTES(handle, smb_fname, dosmode);
}

static NTSTATUS offline_fget_dos_attributes(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    uint32_t *dosmode)
{
	*dosmode |= FILE_ATTRIBUTE_OFFLINE;
	return SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle, fsp, dosmode);
}

static struct vfs_fn_pointers offline_fns = {
    .fs_capabilities_fn = offline_fs_capabilities,
	.get_dos_attributes_fn = offline_get_dos_attributes,
	.get_dos_attributes_send_fn = vfs_not_implemented_get_dos_attributes_send,
	.get_dos_attributes_recv_fn = vfs_not_implemented_get_dos_attributes_recv,
	.fget_dos_attributes_fn = offline_fget_dos_attributes,
};

static_decl_vfs;
NTSTATUS vfs_offline_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "offline",
				&offline_fns);
}
