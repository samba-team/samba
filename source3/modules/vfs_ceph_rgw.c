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

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

struct vfs_ceph_rgw_config {

	/* Module parameters */
	const char *bkt_name;
	const char *user_id;
	const char *access_key;
	const char *secret_access_key;
	const char *config_file;
	const char *keyring_file;
	bool debug;

	/* rgw objects */
	librgw_t rgw_lib_handle;
	struct rgw_fs *rgw_root_fs;
	struct rgw_file_handle *rgw_root_fh;
};

static bool vfs_ceph_rgw_mount_bucket(struct vfs_ceph_rgw_config *config)
{
	int rc = 0;
	bool ret = false;
	char **librgw_params = talloc_zero_array(talloc_tos(), char *, 2);

	if (librgw_params == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for librgw params\n");
		errno = ENOMEM;
		goto out;
	}

	/* Prepare parameters */
	librgw_params[0] = talloc_strdup(librgw_params, "vfs_ceph_rgw");
	if (librgw_params[0] == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for librgw params\n");
		errno = ENOMEM;
		goto out;
	}

	librgw_params[1] = talloc_asprintf(
		librgw_params,
		" --name=client.admin --cluster=ceph"
		" --conf=%s --keyring=%s",
		config->config_file,
		config->keyring_file);
	if (librgw_params[1] == NULL) {
		DBG_ERR("[CEPH_RGW] Not enough memory for librgw params\n");
		errno = ENOMEM;
		goto out;
	}

	if (config->debug) {
		talloc_asprintf_addbuf(librgw_params + 1,
				       " -d --debug-rgw=20");
	}

	rc = librgw_create(&config->rgw_lib_handle, 2, librgw_params);
	if (rc != 0) {
		DBG_ERR("[CEPH_RGW] Failed to init librgw. rc=%d\n", rc);
		goto out;
	}

	rc = rgw_mount2(config->rgw_lib_handle,
			config->user_id,
			config->access_key,
			config->secret_access_key,
			config->bkt_name,
			&config->rgw_root_fs,
			RGW_MOUNT_FLAG_NONE);
	if (rc != 0) {
		DBG_ERR("[CEPH_RGW] Unable to mount bucket=%s Error=[%s] "
			"rc=%d\n",
			config->bkt_name,
			((rc == -EINVAL) ? "Un-authorised user"
					 : "unknown error"),
			rc);
		librgw_shutdown(config->rgw_lib_handle);
		goto out;
	}

	config->rgw_root_fh = config->rgw_root_fs->root_fh;
	ret = true;

out:
	TALLOC_FREE(librgw_params);
	return ret;
}

static const char *vfs_ceph_rgw_parm(const struct vfs_handle_struct *handle,
				     const char *opt,
				     const char *def)
{
	const int snum = SNUM(handle->conn);
	const char *parm = NULL;

	parm = lp_parm_const_string(snum, "ceph_rgw", opt, def);
	if (parm == NULL) {
		DBG_ERR("[CEPH_RGW] missing config: '%s' for snum=%d\n",
			opt,
			snum);
	}
	return parm;
}

static bool vfs_ceph_rgw_load_config(struct vfs_handle_struct *handle,
				     struct vfs_ceph_rgw_config **config)
{
	bool ret = false;
	struct vfs_ceph_rgw_config *config_tmp = NULL;

	if (SMB_VFS_HANDLE_TEST_DATA(handle)) {
		SMB_VFS_HANDLE_GET_DATA(handle,
					config_tmp,
					struct vfs_ceph_rgw_config,
					goto out);
		ret = true;
		*config = config_tmp;
		goto out;
	}

	config_tmp = talloc_zero(handle->conn, struct vfs_ceph_rgw_config);
	if (config_tmp == NULL) {
		goto out;
	}

	config_tmp->config_file = vfs_ceph_rgw_parm(handle,
						    "config_file",
						    "/etc/ceph/ceph.conf");
	if (config_tmp->config_file == NULL) {
		goto out;
	}

	config_tmp->keyring_file = vfs_ceph_rgw_parm(
		handle, "keyring_file", "/etc/ceph/ceph.client.admin.keyring");
	if (config_tmp->keyring_file == NULL) {
		goto out;
	}

	config_tmp->user_id = vfs_ceph_rgw_parm(handle, "user_id", NULL);
	if (config_tmp->user_id == NULL) {
		goto out;
	}

	config_tmp->access_key = vfs_ceph_rgw_parm(handle, "access_key", NULL);
	if (config_tmp->access_key == NULL) {
		goto out;
	}

	config_tmp->secret_access_key = vfs_ceph_rgw_parm(handle,
							  "secret_access_key",
							  NULL);
	if (config_tmp->secret_access_key == NULL) {
		goto out;
	}

	config_tmp->bkt_name = vfs_ceph_rgw_parm(handle, "bucket", NULL);
	if (config_tmp->bkt_name == NULL) {
		goto out;
	}

	config_tmp->debug = lp_parm_bool(SNUM(handle->conn),
					 "ceph_rgw",
					 "debug",
					 false);
	SMB_VFS_HANDLE_SET_DATA(handle,
				config_tmp,
				NULL,
				struct vfs_ceph_rgw_config,
				goto out);

	*config = config_tmp;
	ret = true;
out:
	return ret;
}

static int vfs_ceph_rgw_connect(struct vfs_handle_struct *handle,
				const char *service,
				const char *user)
{
	struct vfs_ceph_rgw_config *config = NULL;
	bool ok = false;

	ok = vfs_ceph_rgw_load_config(handle, &config);
	if (!ok) {
		return -1;
	}

	/*
	 * librgw does not support directory renaming.
	 * This option ensures that samba do not use temporary names for
	 * directory creation and thereby preventing rename while creating
	 * directory.
	 */
	lp_do_parameter(SNUM(handle->conn), "vfs mkdir use tmp name", "no");

	/*
	 * librgw does not support random writes, therefore we do not implement
	 * async io write methods.
	 * This option ensures we always do sync writes.
	 */
	lp_do_parameter(SNUM(handle->conn), "aio write size", "0");

	ok = vfs_ceph_rgw_mount_bucket(config);
	if (!ok) {
		return -1;
	}

	return 0;
}

static void vfs_ceph_rgw_disconnect(struct vfs_handle_struct *handle)
{
	int ret = 0;
	struct vfs_ceph_rgw_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct vfs_ceph_rgw_config,
				return);

	ret = rgw_umount(config->rgw_root_fs, RGW_UMOUNT_FLAG_NONE);
	if (ret < 0) {
		DBG_ERR("[CEPH_RGW] failed to unmount: snum=%d ret=%d\n",
			SNUM(handle->conn),
			ret);
	}

	librgw_shutdown(config->rgw_lib_handle);

	TALLOC_FREE(config);
}

static struct vfs_fn_pointers ceph_rgw_fns = {
	/* Disk operations */

	.connect_fn = vfs_ceph_rgw_connect,
	.disconnect_fn = vfs_ceph_rgw_disconnect,
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
