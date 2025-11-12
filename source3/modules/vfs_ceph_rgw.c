/*
 * Bridge between Samba's VFS layer and Ceph-RGW.
 *
 * Copyright (c) 2025 Vinit Agnihotri <vagnihot@redhat.com>
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

/*
 * Add the following smb.conf parameter to each share that will be hosted on
 * Ceph with rgw:
 *
 *   vfs objects = ceph_rgw
 */
#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include <dirent.h>
#include "smbprofile.h"
#include "lib/util/tevent_unix.h"
#include <rados/librgw.h>
#include <rados/rgw_file.h>

static struct vfs_fn_pointers ceph_rgw_fns = {
	/* Disk operations */

	.connect_fn = vfs_not_implemented_connect,
	.disconnect_fn = vfs_not_implemented_disconnect,
	.disk_free_fn = vfs_not_implemented_disk_free,
	.get_quota_fn = vfs_not_implemented_get_quota,
	.set_quota_fn = vfs_not_implemented_set_quota,
	.fstatvfs_fn = vfs_not_implemented_fstatvfs,
	.fs_capabilities_fn = vfs_not_implemented_fs_capabilities,

	/* Directory operations */

	.fdopendir_fn = vfs_not_implemented_fdopendir,
	.readdir_fn = vfs_not_implemented_readdir,
	.rewind_dir_fn = vfs_not_implemented_rewind_dir,
	.mkdirat_fn = vfs_not_implemented_mkdirat,
	.closedir_fn = vfs_not_implemented_closedir,

	/* File operations */

	.create_dfs_pathat_fn = vfs_not_implemented_create_dfs_pathat,
	.read_dfs_pathat_fn = vfs_not_implemented_read_dfs_pathat,
	.openat_fn = vfs_not_implemented_openat,
	.close_fn = vfs_not_implemented_close_fn,
	.pread_fn = vfs_not_implemented_pread,
	.pread_send_fn = vfs_not_implemented_pread_send,
	.pread_recv_fn = vfs_not_implemented_pread_recv,
	.pwrite_fn = vfs_not_implemented_pwrite,
	.pwrite_send_fn = vfs_not_implemented_pwrite_send,
	.pwrite_recv_fn = vfs_not_implemented_pwrite_recv,
	.lseek_fn = vfs_not_implemented_lseek,
	.sendfile_fn = vfs_not_implemented_sendfile,
	.recvfile_fn = vfs_not_implemented_recvfile,
	.renameat_fn = vfs_not_implemented_renameat,
	.fsync_send_fn = vfs_not_implemented_fsync_send,
	.fsync_recv_fn = vfs_not_implemented_fsync_recv,
	.stat_fn = vfs_not_implemented_stat,
	.fstat_fn = vfs_not_implemented_fstat,
	.lstat_fn = vfs_not_implemented_lstat,
	.fstatat_fn = vfs_not_implemented_fstatat,
	.unlinkat_fn = vfs_not_implemented_unlinkat,
	.fchmod_fn = vfs_not_implemented_fchmod,
	.fchown_fn = vfs_not_implemented_fchown,
	.lchown_fn = vfs_not_implemented_lchown,
	.chdir_fn = vfs_not_implemented_chdir,
	.fntimes_fn = vfs_not_implemented_fntimes,
	.ftruncate_fn = vfs_not_implemented_ftruncate,
	.fallocate_fn = vfs_not_implemented_fallocate,
	.lock_fn = vfs_not_implemented_lock,
	.filesystem_sharemode_fn = vfs_not_implemented_filesystem_sharemode,
	.fcntl_fn = vfs_not_implemented_fcntl,
	.linux_setlease_fn = vfs_not_implemented_linux_setlease,
	.getlock_fn = vfs_not_implemented_getlock,
	.symlinkat_fn = vfs_not_implemented_symlinkat,
	.readlinkat_fn = vfs_not_implemented_vfs_readlinkat,
	.linkat_fn = vfs_not_implemented_linkat,
	.mknodat_fn = vfs_not_implemented_mknodat,
	.realpath_fn = vfs_not_implemented_realpath,
	.fchflags_fn = vfs_not_implemented_fchflags,
	.get_real_filename_at_fn = vfs_not_implemented_get_real_filename_at,
	.fget_dos_attributes_fn = vfs_not_implemented_fget_dos_attributes,
	.fset_dos_attributes_fn = vfs_not_implemented_fset_dos_attributes,

	/* EA operations. */
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = vfs_not_implemented_fgetxattr,
	.flistxattr_fn = vfs_not_implemented_flistxattr,
	.fremovexattr_fn = vfs_not_implemented_fremovexattr,
	.fsetxattr_fn = vfs_not_implemented_fsetxattr,

	/* Posix ACL Operations */
	.sys_acl_get_fd_fn = vfs_not_implemented_sys_acl_get_fd,
	.sys_acl_blob_get_fd_fn = vfs_not_implemented_sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = vfs_not_implemented_sys_acl_set_fd,
	.sys_acl_delete_def_fd_fn = vfs_not_implemented_sys_acl_delete_def_fd,

	/* aio operations */
	.aio_force_fn = vfs_not_implemented_aio_force,
};

NTSTATUS vfs_ceph_rgw_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph_rgw",
				&ceph_rgw_fns);
}
