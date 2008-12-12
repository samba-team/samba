/*
 * Unix SMB/CIFS implementation.
 * Support for OneFS
 *
 * Copyright (C) Tim Prouty, 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "includes.h"
#include "onefs.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static int onefs_mkdir(vfs_handle_struct *handle, const char *path,
		       mode_t mode)
{
	/* SMB_VFS_MKDIR should never be called in vfs_onefs */
	SMB_ASSERT(false);
	return SMB_VFS_NEXT_MKDIR(handle, path, mode);
}

static int onefs_open(vfs_handle_struct *handle, const char *fname,
		      files_struct *fsp, int flags, mode_t mode)
{
	/* SMB_VFS_OPEN should never be called in vfs_onefs */
	SMB_ASSERT(false);
	return SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode);
}

static int onefs_statvfs(vfs_handle_struct *handle, const char *path,
			 vfs_statvfs_struct *statbuf)
{
	struct statvfs statvfs_buf;
	int result;

	DEBUG(5, ("Calling SMB_STAT_VFS \n"));
	result = statvfs(path, &statvfs_buf);
	ZERO_STRUCTP(statbuf);

	if (!result) {
		statbuf->OptimalTransferSize = statvfs_buf.f_iosize;
		statbuf->BlockSize = statvfs_buf.f_bsize;
		statbuf->TotalBlocks = statvfs_buf.f_blocks;
		statbuf->BlocksAvail = statvfs_buf.f_bfree;
		statbuf->UserBlocksAvail = statvfs_buf.f_bavail;
		statbuf->TotalFileNodes = statvfs_buf.f_files;
		statbuf->FreeFileNodes = statvfs_buf.f_ffree;
		statbuf->FsIdentifier =
		    (((uint64_t)statvfs_buf.f_fsid.val[0]<<32) &
			0xffffffff00000000LL) |
		    (uint64_t)statvfs_buf.f_fsid.val[1];
	}
        return result;
}

static uint32_t onefs_fs_capabilities(struct vfs_handle_struct *handle)
{
	return SMB_VFS_NEXT_FS_CAPABILITIES(handle) | FILE_NAMED_STREAMS;
}

static vfs_op_tuple onefs_ops[] = {
	{SMB_VFS_OP(onefs_fs_capabilities), SMB_VFS_OP_FS_CAPABILITIES,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_mkdir), SMB_VFS_OP_MKDIR,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_open), SMB_VFS_OP_OPEN,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_create_file), SMB_VFS_OP_CREATE_FILE,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_close), SMB_VFS_OP_CLOSE,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_rename), SMB_VFS_OP_RENAME,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_stat), SMB_VFS_OP_STAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_fstat), SMB_VFS_OP_FSTAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_lstat), SMB_VFS_OP_LSTAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_unlink), SMB_VFS_OP_UNLINK,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_chflags), SMB_VFS_OP_CHFLAGS,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_streaminfo), SMB_VFS_OP_STREAMINFO,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_fget_nt_acl), SMB_VFS_OP_FGET_NT_ACL,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_get_nt_acl), SMB_VFS_OP_GET_NT_ACL,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_fset_nt_acl), SMB_VFS_OP_FSET_NT_ACL,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_statvfs), SMB_VFS_OP_STATVFS,
	 SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_onefs_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "onefs",
				onefs_ops);
}
