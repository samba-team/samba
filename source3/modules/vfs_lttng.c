/*

 * Lttng VFS module for samba. Trace VFS functions using lttng userspace 
   tools

   Copyright (C) Dongmao Zhang <deanraccoon@gmail.com>

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

/*
 * This module enables lttng tracing for samba
 *
 * /etc/samba/smb.conf
 *
 * vfs objects = lttng
 * 
 * RUN smbd such as this:
 * LD_PRELOAD=/usr/lib64/liblttng-ust-fork.so.0 /usr/sbin/smbd --foreground --no-process-group
 *
 * lttng create
 * lttng enable-event -u vfs_lttng:*
 * lttng start
 *
 * RUN some performance test...
 *
 * lttng stop
 * lttng destroy
 *
 * Use babeltrace or some other tools(https://lttng.org)  to checkout the result
 *
 */

#define TRACEPOINT_CREATE_PROBES
/*
* The header containing our TRACEPOINT_EVENTs.
*/
#define TRACEPOINT_DEFINE


#include "includes.h"
#include "smbd/smbd.h"
#include "ntioctl.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"

#include "vfs_lttng_tp.h"

    

static int vfs_lttng_connect(vfs_handle_struct *handle,
				  const char *svc, const char *user)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_connect_enter );
        result = SMB_VFS_NEXT_CONNECT(handle, svc, user);
        tracepoint(vfs_lttng, vfs_lttng_connect_exit, result);
        return result;
}


static void vfs_lttng_disconnect(vfs_handle_struct *handle)

{
        tracepoint(vfs_lttng, vfs_lttng_disconnect_enter );
        SMB_VFS_NEXT_DISCONNECT(handle);
        tracepoint(vfs_lttng, vfs_lttng_disconnect_exit);
}


static uint64_t vfs_lttng_disk_free(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					uint64_t *bsize,
					uint64_t *dfree,
					uint64_t *dsize)

{
        uint64_t result;
        tracepoint(vfs_lttng, vfs_lttng_disk_free_enter , smb_fname);
        result = SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
        tracepoint(vfs_lttng, vfs_lttng_disk_free_exit, result);
        return result;
}


static int vfs_lttng_get_quota(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					enum SMB_QUOTA_TYPE qtype,
					unid_t id,
					SMB_DISK_QUOTA *qt)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_get_quota_enter , smb_fname);
        result = SMB_VFS_NEXT_GET_QUOTA(handle, smb_fname, qtype, id, qt);
        tracepoint(vfs_lttng, vfs_lttng_get_quota_exit, result);
        return result;
}


static int vfs_lttng_set_quota(struct vfs_handle_struct *handle,
				    enum SMB_QUOTA_TYPE qtype, unid_t id,
				    SMB_DISK_QUOTA *qt)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_set_quota_enter );
        result = SMB_VFS_NEXT_SET_QUOTA(handle, qtype, id, qt);
        tracepoint(vfs_lttng, vfs_lttng_set_quota_exit, result);
        return result;
}


static int vfs_lttng_get_shadow_copy_data(struct vfs_handle_struct *handle,
					       struct files_struct *fsp,
					       struct shadow_copy_data *shadow_copy_data,
					       bool labels)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_get_shadow_copy_data_enter , fsp);
        result = SMB_VFS_NEXT_GET_SHADOW_COPY_DATA(handle, fsp, shadow_copy_data, labels);
        tracepoint(vfs_lttng, vfs_lttng_get_shadow_copy_data_exit, result);
        return result;
}


static int vfs_lttng_statvfs(struct vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname,
				  struct vfs_statvfs_struct *statbuf)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_statvfs_enter , smb_fname);
        result = SMB_VFS_NEXT_STATVFS(handle, smb_fname, statbuf);
        tracepoint(vfs_lttng, vfs_lttng_statvfs_exit, result);
        return result;
}


static uint32_t vfs_lttng_fs_capabilities(struct vfs_handle_struct *handle,
					       enum timestamp_set_resolution *p_ts_res)

{
        uint32_t result;
        tracepoint(vfs_lttng, vfs_lttng_fs_capabilities_enter );
        result = SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res);
        tracepoint(vfs_lttng, vfs_lttng_fs_capabilities_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_get_dfs_referrals(
			struct vfs_handle_struct *handle,
			struct dfs_GetDFSReferral *r)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_get_dfs_referrals_enter );
        result = SMB_VFS_NEXT_GET_DFS_REFERRALS(handle, r);
        tracepoint(vfs_lttng, vfs_lttng_get_dfs_referrals_exit, result);
        return result;
}


static DIR *vfs_lttng_opendir(vfs_handle_struct *handle,
				   const struct smb_filename *smb_fname,
				   const char *mask, uint32_t attr)

{
        DIR * result;
        tracepoint(vfs_lttng, vfs_lttng_opendir_enter , smb_fname);
        result = SMB_VFS_NEXT_OPENDIR(handle, smb_fname, mask, attr);
        tracepoint(vfs_lttng, vfs_lttng_opendir_exit);
        return result;
}


static DIR *vfs_lttng_fdopendir(vfs_handle_struct *handle,
					      files_struct *fsp,
					      const char *mask, uint32_t attr)

{
        DIR * result;
        tracepoint(vfs_lttng, vfs_lttng_fdopendir_enter , fsp);
        result = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);
        tracepoint(vfs_lttng, vfs_lttng_fdopendir_exit);
        return result;
}


static struct dirent *vfs_lttng_readdir(vfs_handle_struct *handle,
						 DIR *dirp,
						 SMB_STRUCT_STAT *sbuf)

{
        struct dirent * result;
        tracepoint(vfs_lttng, vfs_lttng_readdir_enter );
        result = SMB_VFS_NEXT_READDIR(handle, dirp, sbuf);
        tracepoint(vfs_lttng, vfs_lttng_readdir_exit);
        return result;
}


static void vfs_lttng_seekdir(vfs_handle_struct *handle,
				   DIR *dirp, long offset)

{
        tracepoint(vfs_lttng, vfs_lttng_seekdir_enter , offset);
        SMB_VFS_NEXT_SEEKDIR(handle, dirp, offset);
        tracepoint(vfs_lttng, vfs_lttng_seekdir_exit);
}


static long vfs_lttng_telldir(vfs_handle_struct *handle,
				   DIR *dirp)

{
        long result;
        tracepoint(vfs_lttng, vfs_lttng_telldir_enter );
        result = SMB_VFS_NEXT_TELLDIR(handle, dirp);
        tracepoint(vfs_lttng, vfs_lttng_telldir_exit, result);
        return result;
}


static int vfs_lttng_mkdir(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				mode_t mode)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_mkdir_enter , smb_fname, mode);
        result = SMB_VFS_NEXT_MKDIR(handle, smb_fname, mode);
        tracepoint(vfs_lttng, vfs_lttng_mkdir_exit, result);
        return result;
}


static int vfs_lttng_rmdir(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_rmdir_enter , smb_fname);
        result = SMB_VFS_NEXT_RMDIR(handle, smb_fname);
        tracepoint(vfs_lttng, vfs_lttng_rmdir_exit, result);
        return result;
}


static int vfs_lttng_closedir(vfs_handle_struct *handle,
				   DIR *dirp)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_closedir_enter );
        result = SMB_VFS_NEXT_CLOSEDIR(handle, dirp);
        tracepoint(vfs_lttng, vfs_lttng_closedir_exit, result);
        return result;
}



static int vfs_lttng_open(vfs_handle_struct *handle,
			       struct smb_filename *fname,
			       files_struct *fsp,
			       int flags, mode_t mode)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_open_enter , fname, flags, mode);
        result = SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode);
        tracepoint(vfs_lttng, vfs_lttng_open_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_create_file(vfs_handle_struct *handle,
					   struct smb_request *req,
					   uint16_t root_dir_fid,
					   struct smb_filename *fname,
					   uint32_t access_mask,
					   uint32_t share_access,
					   uint32_t create_disposition,
					   uint32_t create_options,
					   uint32_t file_attributes,
					   uint32_t oplock_request,
					   struct smb2_lease *lease,
					   uint64_t allocation_size,
					   uint32_t private_flags,
					   struct security_descriptor *sd,
					   struct ea_list *ea_list,
					   files_struct **result_fsp,
					   int *pinfo,
					   const struct smb2_create_blobs *in_context_blobs,
					   struct smb2_create_blobs *out_context_blobs)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_create_file_enter , fname);
        result = SMB_VFS_NEXT_CREATE_FILE(handle, req, root_dir_fid, fname, access_mask, share_access, create_disposition, create_options, file_attributes, oplock_request, lease, allocation_size, private_flags, sd, ea_list, result_fsp, pinfo, in_context_blobs, out_context_blobs);
        tracepoint(vfs_lttng, vfs_lttng_create_file_exit, result);
        return result;
}


static int vfs_lttng_close(vfs_handle_struct *handle, files_struct *fsp)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_close_enter , fsp);
        result = SMB_VFS_NEXT_CLOSE(handle, fsp);
        tracepoint(vfs_lttng, vfs_lttng_close_exit, result);
        return result;
}




static ssize_t vfs_lttng_pread(vfs_handle_struct *handle,
				    files_struct *fsp,
				    void *data, size_t n, off_t offset)

{
        ssize_t result;
        tracepoint(vfs_lttng, vfs_lttng_pread_enter , fsp, n, offset);
        result = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
        tracepoint(vfs_lttng, vfs_lttng_pread_exit, result);
        return result;
}


static ssize_t vfs_lttng_pwrite(vfs_handle_struct *handle,
				     files_struct *fsp,
				     const void *data, size_t n,
				     off_t offset)

{
        ssize_t result;
        tracepoint(vfs_lttng, vfs_lttng_pwrite_enter , fsp, n, offset);
        result = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
        tracepoint(vfs_lttng, vfs_lttng_pwrite_exit, result);
        return result;
}


static off_t vfs_lttng_lseek(vfs_handle_struct *handle,
				      files_struct *fsp,
				      off_t offset, int whence)

{
        off_t result;
        tracepoint(vfs_lttng, vfs_lttng_lseek_enter , fsp, offset);
        result = SMB_VFS_NEXT_LSEEK(handle, fsp, offset, whence);
        tracepoint(vfs_lttng, vfs_lttng_lseek_exit, result);
        return result;
}


static ssize_t vfs_lttng_sendfile(vfs_handle_struct *handle, int tofd,
				       files_struct *fromfsp,
				       const DATA_BLOB *hdr, off_t offset,
				       size_t n)

{
        ssize_t result;
        tracepoint(vfs_lttng, vfs_lttng_sendfile_enter , tofd, offset, n);
        result = SMB_VFS_NEXT_SENDFILE(handle, tofd, fromfsp, hdr, offset, n);
        tracepoint(vfs_lttng, vfs_lttng_sendfile_exit, result);
        return result;
}


static ssize_t vfs_lttng_recvfile(vfs_handle_struct *handle, int fromfd,
				       files_struct *tofsp,
				       off_t offset,
				       size_t n)

{
        ssize_t result;
        tracepoint(vfs_lttng, vfs_lttng_recvfile_enter , offset, n);
        result = SMB_VFS_NEXT_RECVFILE(handle, fromfd, tofsp, offset, n);
        tracepoint(vfs_lttng, vfs_lttng_recvfile_exit, result);
        return result;
}


static int vfs_lttng_rename(vfs_handle_struct *handle,
				 const struct smb_filename *oldname,
				 const struct smb_filename *newname)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_rename_enter );
        result = SMB_VFS_NEXT_RENAME(handle, oldname, newname);
        tracepoint(vfs_lttng, vfs_lttng_rename_exit, result);
        return result;
}




static int vfs_lttng_stat(vfs_handle_struct *handle,
			       struct smb_filename *fname)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_stat_enter , fname);
        result = SMB_VFS_NEXT_STAT(handle, fname);
        tracepoint(vfs_lttng, vfs_lttng_stat_exit, result);
        return result;
}


static int vfs_lttng_fstat(vfs_handle_struct *handle, files_struct *fsp,
				SMB_STRUCT_STAT *sbuf)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_fstat_enter , fsp);
        result = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
        tracepoint(vfs_lttng, vfs_lttng_fstat_exit, result);
        return result;
}


static int vfs_lttng_lstat(vfs_handle_struct *handle,
				struct smb_filename *path)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_lstat_enter );
        result = SMB_VFS_NEXT_LSTAT(handle, path);
        tracepoint(vfs_lttng, vfs_lttng_lstat_exit, result);
        return result;
}


static uint64_t vfs_lttng_get_alloc_size(vfs_handle_struct *handle,
					      files_struct *fsp,
					      const SMB_STRUCT_STAT *sbuf)

{
        uint64_t result;
        tracepoint(vfs_lttng, vfs_lttng_get_alloc_size_enter);
        result = SMB_VFS_NEXT_GET_ALLOC_SIZE(handle, fsp, sbuf);
        tracepoint(vfs_lttng, vfs_lttng_get_alloc_size_exit, result);
        return result;
}


static int vfs_lttng_unlink(vfs_handle_struct *handle,
				 const struct smb_filename *path)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_unlink_enter );
        result = SMB_VFS_NEXT_UNLINK(handle, path);
        tracepoint(vfs_lttng, vfs_lttng_unlink_exit, result);
        return result;
}


static int vfs_lttng_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_chmod_enter , smb_fname, mode);
        result = SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
        tracepoint(vfs_lttng, vfs_lttng_chmod_exit, result);
        return result;
}


static int vfs_lttng_fchmod(vfs_handle_struct *handle, files_struct *fsp,
				 mode_t mode)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_fchmod_enter , fsp, mode);
        result = SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
        tracepoint(vfs_lttng, vfs_lttng_fchmod_exit, result);
        return result;
}


static int vfs_lttng_chown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_chown_enter , smb_fname);
        result = SMB_VFS_NEXT_CHOWN(handle, smb_fname, uid, gid);
        tracepoint(vfs_lttng, vfs_lttng_chown_exit, result);
        return result;
}


static int vfs_lttng_fchown(vfs_handle_struct *handle, files_struct *fsp,
				 uid_t uid, gid_t gid)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_fchown_enter , fsp);
        result = SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);
        tracepoint(vfs_lttng, vfs_lttng_fchown_exit, result);
        return result;
}


static int vfs_lttng_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_lchown_enter , smb_fname);
        result = SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);
        tracepoint(vfs_lttng, vfs_lttng_lchown_exit, result);
        return result;
}


static int vfs_lttng_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_chdir_enter , smb_fname);
        result = SMB_VFS_NEXT_CHDIR(handle, smb_fname);
        tracepoint(vfs_lttng, vfs_lttng_chdir_exit, result);
        return result;
}


static struct smb_filename *vfs_lttng_getwd(vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx)

{
        struct smb_filename * result;
        tracepoint(vfs_lttng, vfs_lttng_getwd_enter );
        result = SMB_VFS_NEXT_GETWD(handle, mem_ctx);
        tracepoint(vfs_lttng, vfs_lttng_getwd_exit);
        return result;
}


static int vfs_lttng_ntimes(vfs_handle_struct *handle,
				 const struct smb_filename *path,
				 struct smb_file_time *ft)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_ntimes_enter );
        result = SMB_VFS_NEXT_NTIMES(handle, path, ft);
        tracepoint(vfs_lttng, vfs_lttng_ntimes_exit, result);
        return result;
}


static int vfs_lttng_ftruncate(vfs_handle_struct *handle,
				    files_struct *fsp,
				    off_t len)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_ftruncate_enter , fsp);
        result = SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
        tracepoint(vfs_lttng, vfs_lttng_ftruncate_exit, result);
        return result;
}


static int vfs_lttng_fallocate(vfs_handle_struct *handle,
				    files_struct *fsp,
				    uint32_t mode,
				    off_t offset,
				    off_t len)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_fallocate_enter , fsp, mode, offset);
        result = SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
        tracepoint(vfs_lttng, vfs_lttng_fallocate_exit, result);
        return result;
}


static bool vfs_lttng_lock(vfs_handle_struct *handle, files_struct *fsp,
				int op, off_t offset, off_t count,
				int type)

{
        bool result;
        tracepoint(vfs_lttng, vfs_lttng_lock_enter , fsp, offset);
        result = SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type);
        tracepoint(vfs_lttng, vfs_lttng_lock_exit, result);
        return result;
}


static int vfs_lttng_kernel_flock(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       uint32_t share_mode, uint32_t access_mask)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_kernel_flock_enter , fsp);
        result = SMB_VFS_NEXT_KERNEL_FLOCK(handle, fsp, share_mode, access_mask);
        tracepoint(vfs_lttng, vfs_lttng_kernel_flock_exit, result);
        return result;
}


static int vfs_lttng_linux_setlease(vfs_handle_struct *handle,
					 files_struct *fsp,
					 int leasetype)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_linux_setlease_enter , fsp);
        result = SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype);
        tracepoint(vfs_lttng, vfs_lttng_linux_setlease_exit, result);
        return result;
}


static bool vfs_lttng_getlock(vfs_handle_struct *handle,
				   files_struct *fsp,
				   off_t *poffset, off_t *pcount,
				   int *ptype, pid_t *ppid)

{
        bool result;
        tracepoint(vfs_lttng, vfs_lttng_getlock_enter , fsp);
        result = SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset, pcount, ptype, ppid);
        tracepoint(vfs_lttng, vfs_lttng_getlock_exit, result);
        return result;
}


static int vfs_lttng_symlink(vfs_handle_struct *handle,
				const char *link_contents,
				const struct smb_filename *new_smb_fname)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_symlink_enter );
        result = SMB_VFS_NEXT_SYMLINK(handle, link_contents, new_smb_fname);
        tracepoint(vfs_lttng, vfs_lttng_symlink_exit, result);
        return result;
}


static int vfs_lttng_readlink(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *buf,
				size_t bufsiz)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_readlink_enter , smb_fname);
        result = SMB_VFS_NEXT_READLINK(handle, smb_fname, buf, bufsiz);
        tracepoint(vfs_lttng, vfs_lttng_readlink_exit, result);
        return result;
}


static int vfs_lttng_link(vfs_handle_struct *handle,
				const struct smb_filename *old_smb_fname,
				const struct smb_filename *new_smb_fname)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_link_enter );
        result = SMB_VFS_NEXT_LINK(handle, old_smb_fname, new_smb_fname);
        tracepoint(vfs_lttng, vfs_lttng_link_exit, result);
        return result;
}


static int vfs_lttng_mknod(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				mode_t mode,
				SMB_DEV_T dev)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_mknod_enter , smb_fname, mode);
        result = SMB_VFS_NEXT_MKNOD(handle, smb_fname, mode, dev);
        tracepoint(vfs_lttng, vfs_lttng_mknod_exit, result);
        return result;
}


static struct smb_filename *vfs_lttng_realpath(vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)

{
        struct smb_filename * result;
        tracepoint(vfs_lttng, vfs_lttng_realpath_enter , smb_fname);
        result = SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);
        tracepoint(vfs_lttng, vfs_lttng_realpath_exit);
        return result;
}


static int vfs_lttng_chflags(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				unsigned int flags)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_chflags_enter , smb_fname, flags);
        result = SMB_VFS_NEXT_CHFLAGS(handle, smb_fname, flags);
        tracepoint(vfs_lttng, vfs_lttng_chflags_exit, result);
        return result;
}


static struct file_id vfs_lttng_file_id_create(struct vfs_handle_struct *handle,
						    const SMB_STRUCT_STAT *sbuf)

{
        struct file_id result;
        tracepoint(vfs_lttng, vfs_lttng_file_id_create_enter );
        result = SMB_VFS_NEXT_FILE_ID_CREATE(handle, sbuf);
        tracepoint(vfs_lttng, vfs_lttng_file_id_create_exit);
        return result;
}


static struct tevent_req *vfs_lttng_offload_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct vfs_handle_struct *handle,
	struct files_struct *fsp,
	uint32_t fsctl,
	uint32_t ttl,
	off_t offset,
	size_t to_copy)

{
        struct tevent_req * result;
        tracepoint(vfs_lttng, vfs_lttng_offload_read_send_enter , fsp, offset);
        result = SMB_VFS_NEXT_OFFLOAD_READ_SEND(mem_ctx, ev, handle, fsp, fsctl, ttl, offset, to_copy);
        tracepoint(vfs_lttng, vfs_lttng_offload_read_send_exit);
        return result;
}


static NTSTATUS vfs_lttng_offload_read_recv(
	struct tevent_req *req,
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	DATA_BLOB *_token_blob)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_offload_read_recv_enter );
        result = SMB_VFS_NEXT_OFFLOAD_READ_RECV(req, handle, mem_ctx, _token_blob);
        tracepoint(vfs_lttng, vfs_lttng_offload_read_recv_exit, result);
        return result;
}


static struct tevent_req *vfs_lttng_offload_write_send(struct vfs_handle_struct *handle,
							 TALLOC_CTX *mem_ctx,
							 struct tevent_context *ev,
							 uint32_t fsctl,
							 DATA_BLOB *token,
							 off_t transfer_offset,
							 struct files_struct *dest_fsp,
							 off_t dest_off,
							 off_t num)

{
        struct tevent_req * result;
        tracepoint(vfs_lttng, vfs_lttng_offload_write_send_enter );
        result = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle, mem_ctx, ev, fsctl, token, transfer_offset, dest_fsp, dest_off, num);
        tracepoint(vfs_lttng, vfs_lttng_offload_write_send_exit);
        return result;
}


static NTSTATUS vfs_lttng_offload_write_recv(struct vfs_handle_struct *handle,
					       struct tevent_req *req,
					       off_t *copied)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_offload_write_recv_enter );
        result = SMB_VFS_NEXT_OFFLOAD_WRITE_RECV(handle, req, copied);
        tracepoint(vfs_lttng, vfs_lttng_offload_write_recv_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_get_compression(vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct files_struct *fsp,
					       struct smb_filename *smb_fname,
					       uint16_t *_compression_fmt)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_get_compression_enter , fsp);
        result = SMB_VFS_NEXT_GET_COMPRESSION(handle, mem_ctx, fsp, smb_fname, _compression_fmt);
        tracepoint(vfs_lttng, vfs_lttng_get_compression_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_set_compression(vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct files_struct *fsp,
					       uint16_t compression_fmt)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_set_compression_enter , fsp);
        result = SMB_VFS_NEXT_SET_COMPRESSION(handle, mem_ctx, fsp, compression_fmt);
        tracepoint(vfs_lttng, vfs_lttng_set_compression_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_snap_check_path(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       const char *service_path,
					       char **base_volume)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_snap_check_path_enter );
        result = SMB_VFS_NEXT_SNAP_CHECK_PATH(handle, mem_ctx, service_path, base_volume);
        tracepoint(vfs_lttng, vfs_lttng_snap_check_path_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_snap_create(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   const char *base_volume,
					   time_t *tstamp,
					   bool rw,
					   char **base_path,
					   char **snap_path)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_snap_create_enter );
        result = SMB_VFS_NEXT_SNAP_CREATE(handle, mem_ctx, base_volume, tstamp, rw, base_path, snap_path);
        tracepoint(vfs_lttng, vfs_lttng_snap_create_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_snap_delete(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   char *base_path,
					   char *snap_path)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_snap_delete_enter );
        result = SMB_VFS_NEXT_SNAP_DELETE(handle, mem_ctx, base_path, snap_path);
        tracepoint(vfs_lttng, vfs_lttng_snap_delete_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_streaminfo(vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  const struct smb_filename *smb_fname,
					  TALLOC_CTX *mem_ctx,
					  unsigned int *pnum_streams,
					  struct stream_struct **pstreams)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_streaminfo_enter , fsp);
        result = SMB_VFS_NEXT_STREAMINFO(handle, fsp, smb_fname, mem_ctx, pnum_streams, pstreams);
        tracepoint(vfs_lttng, vfs_lttng_streaminfo_exit, result);
        return result;
}


static int vfs_lttng_get_real_filename(struct vfs_handle_struct *handle,
					    const char *path,
					    const char *name,
					    TALLOC_CTX *mem_ctx,
					    char **found_name)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_get_real_filename_enter , name);
        result = SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name, mem_ctx, found_name);
        tracepoint(vfs_lttng, vfs_lttng_get_real_filename_exit, result);
        return result;
}


static const char *vfs_lttng_connectpath(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname)

{
        const char * result;
        tracepoint(vfs_lttng, vfs_lttng_connectpath_enter , smb_fname);
        result = SMB_VFS_NEXT_CONNECTPATH(handle, smb_fname);
        tracepoint(vfs_lttng, vfs_lttng_connectpath_exit);
        return result;
}


static NTSTATUS vfs_lttng_brl_lock_windows(struct vfs_handle_struct *handle,
						struct byte_range_lock *br_lck,
						struct lock_struct *plock,
						bool blocking_lock)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_brl_lock_windows_enter );
        result = SMB_VFS_NEXT_BRL_LOCK_WINDOWS(handle, br_lck, plock, blocking_lock);
        tracepoint(vfs_lttng, vfs_lttng_brl_lock_windows_exit, result);
        return result;
}


static bool vfs_lttng_brl_unlock_windows(struct vfs_handle_struct *handle,
					      struct messaging_context *msg_ctx,
					      struct byte_range_lock *br_lck,
					      const struct lock_struct *plock)

{
        bool result;
        tracepoint(vfs_lttng, vfs_lttng_brl_unlock_windows_enter );
        result = SMB_VFS_NEXT_BRL_UNLOCK_WINDOWS(handle, msg_ctx, br_lck, plock);
        tracepoint(vfs_lttng, vfs_lttng_brl_unlock_windows_exit, result);
        return result;
}


static bool vfs_lttng_brl_cancel_windows(struct vfs_handle_struct *handle,
					      struct byte_range_lock *br_lck,
					      struct lock_struct *plock)

{
        bool result;
        tracepoint(vfs_lttng, vfs_lttng_brl_cancel_windows_enter );
        result = SMB_VFS_NEXT_BRL_CANCEL_WINDOWS(handle, br_lck, plock);
        tracepoint(vfs_lttng, vfs_lttng_brl_cancel_windows_exit, result);
        return result;
}


static bool vfs_lttng_strict_lock_check(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     struct lock_struct *plock)

{
        bool result;
        tracepoint(vfs_lttng, vfs_lttng_strict_lock_check_enter , fsp);
        result = SMB_VFS_NEXT_STRICT_LOCK_CHECK(handle, fsp, plock);
        tracepoint(vfs_lttng, vfs_lttng_strict_lock_check_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_translate_name(struct vfs_handle_struct *handle,
					      const char *name,
					      enum vfs_translate_direction direction,
					      TALLOC_CTX *mem_ctx,
					      char **mapped_name)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_translate_name_enter , name);
        result = SMB_VFS_NEXT_TRANSLATE_NAME(handle, name, direction, mem_ctx, mapped_name);
        tracepoint(vfs_lttng, vfs_lttng_translate_name_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_fsctl(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				TALLOC_CTX *ctx,
				uint32_t function,
				uint16_t req_flags,
				const uint8_t *_in_data,
				uint32_t in_len,
				uint8_t **_out_data,
				uint32_t max_out_len,
				uint32_t *out_len)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_fsctl_enter , fsp);
        result = SMB_VFS_NEXT_FSCTL(handle, fsp, ctx, function, req_flags, _in_data, in_len, _out_data, max_out_len, out_len);
        tracepoint(vfs_lttng, vfs_lttng_fsctl_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_get_dos_attributes(struct vfs_handle_struct *handle,
					struct smb_filename *smb_fname,
					uint32_t *dosmode)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_get_dos_attributes_enter , smb_fname);
        result = SMB_VFS_NEXT_GET_DOS_ATTRIBUTES(handle, smb_fname, dosmode);
        tracepoint(vfs_lttng, vfs_lttng_get_dos_attributes_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_fget_dos_attributes(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32_t *dosmode)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_fget_dos_attributes_enter , fsp);
        result = SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle, fsp, dosmode);
        tracepoint(vfs_lttng, vfs_lttng_fget_dos_attributes_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_set_dos_attributes(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					uint32_t dosmode)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_set_dos_attributes_enter , smb_fname);
        result = SMB_VFS_NEXT_SET_DOS_ATTRIBUTES(handle, smb_fname, dosmode);
        tracepoint(vfs_lttng, vfs_lttng_set_dos_attributes_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_fset_dos_attributes(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32_t dosmode)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_fset_dos_attributes_enter , fsp);
        result = SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle, fsp, dosmode);
        tracepoint(vfs_lttng, vfs_lttng_fset_dos_attributes_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_fget_nt_acl(vfs_handle_struct *handle,
					   files_struct *fsp,
					   uint32_t security_info,
					   TALLOC_CTX *mem_ctx,
					   struct security_descriptor **ppdesc)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_fget_nt_acl_enter , fsp);
        result = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx, ppdesc);
        tracepoint(vfs_lttng, vfs_lttng_fget_nt_acl_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_get_nt_acl(vfs_handle_struct *handle,
					  const struct smb_filename *smb_fname,
					  uint32_t security_info,
					  TALLOC_CTX *mem_ctx,
					  struct security_descriptor **ppdesc)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_get_nt_acl_enter , smb_fname);
        result = SMB_VFS_NEXT_GET_NT_ACL(handle, smb_fname, security_info, mem_ctx, ppdesc);
        tracepoint(vfs_lttng, vfs_lttng_get_nt_acl_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_fset_nt_acl(vfs_handle_struct *handle,
					   files_struct *fsp,
					   uint32_t security_info_sent,
					   const struct security_descriptor *psd)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_fset_nt_acl_enter , fsp);
        result = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
        tracepoint(vfs_lttng, vfs_lttng_fset_nt_acl_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_audit_file(struct vfs_handle_struct *handle,
				struct smb_filename *smb_fname,
				struct security_acl *sacl,
				uint32_t access_requested,
				uint32_t access_denied)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_audit_file_enter , smb_fname);
        result = SMB_VFS_NEXT_AUDIT_FILE(handle, smb_fname, sacl, access_requested, access_denied);
        tracepoint(vfs_lttng, vfs_lttng_audit_file_exit, result);
        return result;
}


static SMB_ACL_T vfs_lttng_sys_acl_get_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					SMB_ACL_TYPE_T type,
					TALLOC_CTX *mem_ctx)

{
        SMB_ACL_T result;
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_get_file_enter , smb_fname);
        result = SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, smb_fname, type, mem_ctx);
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_get_file_exit, result);
        return result;
}


static SMB_ACL_T vfs_lttng_sys_acl_get_fd(vfs_handle_struct *handle,
					       files_struct *fsp,
					       TALLOC_CTX *mem_ctx)

{
        SMB_ACL_T result;
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_get_fd_enter , fsp);
        result = SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, mem_ctx);
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_get_fd_exit, result);
        return result;
}


static int vfs_lttng_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_blob_get_file_enter , smb_fname);
        result = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle, smb_fname, mem_ctx, blob_description, blob);
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_blob_get_file_exit, result);
        return result;
}


static int vfs_lttng_sys_acl_blob_get_fd(vfs_handle_struct *handle,
					      files_struct *fsp,
					      TALLOC_CTX *mem_ctx, 
					      char **blob_description,
					      DATA_BLOB *blob)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_blob_get_fd_enter , fsp);
        result = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx, blob_description, blob);
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_blob_get_fd_exit, result);
        return result;
}


static int vfs_lttng_sys_acl_set_file(vfs_handle_struct *handle,
					   const struct smb_filename *smb_fname,
					   SMB_ACL_TYPE_T acltype,
					   SMB_ACL_T theacl)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_set_file_enter , smb_fname);
        result = SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, smb_fname, acltype, theacl);
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_set_file_exit, result);
        return result;
}


static int vfs_lttng_sys_acl_set_fd(vfs_handle_struct *handle,
					 files_struct *fsp,
					 SMB_ACL_T theacl)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_set_fd_enter , fsp);
        result = SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl);
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_set_fd_exit, result);
        return result;
}


static int vfs_lttng_sys_acl_delete_def_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_delete_def_file_enter , smb_fname);
        result = SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, smb_fname);
        tracepoint(vfs_lttng, vfs_lttng_sys_acl_delete_def_file_exit, result);
        return result;
}


static ssize_t vfs_lttng_getxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)

{
        ssize_t result;
        tracepoint(vfs_lttng, vfs_lttng_getxattr_enter , smb_fname, name);
        result = SMB_VFS_NEXT_GETXATTR(handle, smb_fname, name, value, size);
        tracepoint(vfs_lttng, vfs_lttng_getxattr_exit, result);
        return result;
}


static ssize_t vfs_lttng_fgetxattr(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					const char *name, void *value,
					size_t size)

{
        ssize_t result;
        tracepoint(vfs_lttng, vfs_lttng_fgetxattr_enter , fsp, name);
        result = SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, value, size);
        tracepoint(vfs_lttng, vfs_lttng_fgetxattr_exit, result);
        return result;
}


static ssize_t vfs_lttng_listxattr(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					char *list,
					size_t size)

{
        ssize_t result;
        tracepoint(vfs_lttng, vfs_lttng_listxattr_enter , smb_fname);
        result = SMB_VFS_NEXT_LISTXATTR(handle, smb_fname, list, size);
        tracepoint(vfs_lttng, vfs_lttng_listxattr_exit, result);
        return result;
}


static ssize_t vfs_lttng_flistxattr(struct vfs_handle_struct *handle,
					 struct files_struct *fsp, char *list,
					 size_t size)

{
        ssize_t result;
        tracepoint(vfs_lttng, vfs_lttng_flistxattr_enter , fsp);
        result = SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);
        tracepoint(vfs_lttng, vfs_lttng_flistxattr_exit, result);
        return result;
}


static int vfs_lttng_removexattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_removexattr_enter , smb_fname, name);
        result = SMB_VFS_NEXT_REMOVEXATTR(handle, smb_fname, name);
        tracepoint(vfs_lttng, vfs_lttng_removexattr_exit, result);
        return result;
}


static int vfs_lttng_fremovexattr(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       const char *name)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_fremovexattr_enter , fsp, name);
        result = SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
        tracepoint(vfs_lttng, vfs_lttng_fremovexattr_exit, result);
        return result;
}


static int vfs_lttng_setxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				const void *value,
				size_t size,
				int flags)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_setxattr_enter , smb_fname, name, flags);
        result = SMB_VFS_NEXT_SETXATTR(handle, smb_fname, name, value, size, flags);
        tracepoint(vfs_lttng, vfs_lttng_setxattr_exit, result);
        return result;
}


static int vfs_lttng_fsetxattr(struct vfs_handle_struct *handle,
				    struct files_struct *fsp, const char *name,
				    const void *value, size_t size, int flags)

{
        int result;
        tracepoint(vfs_lttng, vfs_lttng_fsetxattr_enter , fsp, name, flags);
        result = SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value, size, flags);
        tracepoint(vfs_lttng, vfs_lttng_fsetxattr_exit, result);
        return result;
}


static bool vfs_lttng_aio_force(struct vfs_handle_struct *handle,
				     struct files_struct *fsp)

{
        bool result;
        tracepoint(vfs_lttng, vfs_lttng_aio_force_enter , fsp);
        result = SMB_VFS_NEXT_AIO_FORCE(handle, fsp);
        tracepoint(vfs_lttng, vfs_lttng_aio_force_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_durable_cookie(struct vfs_handle_struct *handle,
					      struct files_struct *fsp,
					      TALLOC_CTX *mem_ctx,
					      DATA_BLOB *cookie)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_durable_cookie_enter , fsp);
        result = SMB_VFS_NEXT_DURABLE_COOKIE(handle, fsp, mem_ctx, cookie);
        tracepoint(vfs_lttng, vfs_lttng_durable_cookie_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_durable_disconnect(struct vfs_handle_struct *handle,
						  struct files_struct *fsp,
						  const DATA_BLOB old_cookie,
						  TALLOC_CTX *mem_ctx,
						  DATA_BLOB *new_cookie)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_durable_disconnect_enter , fsp);
        result = SMB_VFS_NEXT_DURABLE_DISCONNECT(handle, fsp, old_cookie, mem_ctx, new_cookie);
        tracepoint(vfs_lttng, vfs_lttng_durable_disconnect_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_durable_reconnect(struct vfs_handle_struct *handle,
						 struct smb_request *smb1req,
						 struct smbXsrv_open *op,
						 const DATA_BLOB old_cookie,
						 TALLOC_CTX *mem_ctx,
						 struct files_struct **fsp,
						 DATA_BLOB *new_cookie)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_durable_reconnect_enter , fsp);
        result = SMB_VFS_NEXT_DURABLE_RECONNECT(handle, smb1req, op, old_cookie, mem_ctx, fsp, new_cookie);
        tracepoint(vfs_lttng, vfs_lttng_durable_reconnect_exit, result);
        return result;
}


static NTSTATUS vfs_lttng_readdir_attr(struct vfs_handle_struct *handle,
					    const struct smb_filename *fname,
					    TALLOC_CTX *mem_ctx,
					    struct readdir_attr_data **pattr_data)

{
        NTSTATUS result;
        tracepoint(vfs_lttng, vfs_lttng_readdir_attr_enter , fname);
        result = SMB_VFS_NEXT_READDIR_ATTR(handle, fname, mem_ctx, pattr_data);
        tracepoint(vfs_lttng, vfs_lttng_readdir_attr_exit, result);
        return result;
}

static struct vfs_fn_pointers vfs_lttng_fns = {
        .connect_fn = vfs_lttng_connect,
        .disconnect_fn = vfs_lttng_disconnect,
        .disk_free_fn = vfs_lttng_disk_free,
        .get_quota_fn = vfs_lttng_get_quota,
        .set_quota_fn = vfs_lttng_set_quota,
        .get_shadow_copy_data_fn = vfs_lttng_get_shadow_copy_data,
        .statvfs_fn = vfs_lttng_statvfs,
        .fs_capabilities_fn = vfs_lttng_fs_capabilities,
        .get_dfs_referrals_fn = vfs_lttng_get_dfs_referrals,
        .opendir_fn = vfs_lttng_opendir,
        .fdopendir_fn = vfs_lttng_fdopendir,
        .readdir_fn = vfs_lttng_readdir,
        .seekdir_fn = vfs_lttng_seekdir,
        .telldir_fn = vfs_lttng_telldir,
        .mkdir_fn = vfs_lttng_mkdir,
        .rmdir_fn = vfs_lttng_rmdir,
        .closedir_fn = vfs_lttng_closedir,
        .open_fn = vfs_lttng_open,
        .create_file_fn = vfs_lttng_create_file,
        .close_fn = vfs_lttng_close,
        .pread_fn = vfs_lttng_pread,
        .pwrite_fn = vfs_lttng_pwrite,
        .lseek_fn = vfs_lttng_lseek,
        .sendfile_fn = vfs_lttng_sendfile,
        .recvfile_fn = vfs_lttng_recvfile,
        .rename_fn = vfs_lttng_rename,
        .stat_fn = vfs_lttng_stat,
        .fstat_fn = vfs_lttng_fstat,
        .lstat_fn = vfs_lttng_lstat,
        .get_alloc_size_fn = vfs_lttng_get_alloc_size,
        .unlink_fn = vfs_lttng_unlink,
        .chmod_fn = vfs_lttng_chmod,
        .fchmod_fn = vfs_lttng_fchmod,
        .chown_fn = vfs_lttng_chown,
        .fchown_fn = vfs_lttng_fchown,
        .lchown_fn = vfs_lttng_lchown,
        .chdir_fn = vfs_lttng_chdir,
        .getwd_fn = vfs_lttng_getwd,
        .ntimes_fn = vfs_lttng_ntimes,
        .ftruncate_fn = vfs_lttng_ftruncate,
        .fallocate_fn = vfs_lttng_fallocate,
        .lock_fn = vfs_lttng_lock,
        .kernel_flock_fn = vfs_lttng_kernel_flock,
        .linux_setlease_fn = vfs_lttng_linux_setlease,
        .getlock_fn = vfs_lttng_getlock,
        .symlink_fn = vfs_lttng_symlink,
        .readlink_fn = vfs_lttng_readlink,
        .link_fn = vfs_lttng_link,
        .mknod_fn = vfs_lttng_mknod,
        .realpath_fn = vfs_lttng_realpath,
        .chflags_fn = vfs_lttng_chflags,
        .file_id_create_fn = vfs_lttng_file_id_create,
        .offload_read_send_fn = vfs_lttng_offload_read_send,
        .offload_read_recv_fn = vfs_lttng_offload_read_recv,
        .offload_write_send_fn = vfs_lttng_offload_write_send,
        .offload_write_recv_fn = vfs_lttng_offload_write_recv,
        .get_compression_fn = vfs_lttng_get_compression,
        .set_compression_fn = vfs_lttng_set_compression,
        .snap_check_path_fn = vfs_lttng_snap_check_path,
        .snap_create_fn = vfs_lttng_snap_create,
        .snap_delete_fn = vfs_lttng_snap_delete,
        .streaminfo_fn = vfs_lttng_streaminfo,
        .get_real_filename_fn = vfs_lttng_get_real_filename,
        .connectpath_fn = vfs_lttng_connectpath,
        .brl_lock_windows_fn = vfs_lttng_brl_lock_windows,
        .brl_unlock_windows_fn = vfs_lttng_brl_unlock_windows,
        .brl_cancel_windows_fn = vfs_lttng_brl_cancel_windows,
        .strict_lock_check_fn = vfs_lttng_strict_lock_check,
        .translate_name_fn = vfs_lttng_translate_name,
        .fsctl_fn = vfs_lttng_fsctl,
        .get_dos_attributes_fn = vfs_lttng_get_dos_attributes,
        .fget_dos_attributes_fn = vfs_lttng_fget_dos_attributes,
        .set_dos_attributes_fn = vfs_lttng_set_dos_attributes,
        .fset_dos_attributes_fn = vfs_lttng_fset_dos_attributes,
        .fget_nt_acl_fn = vfs_lttng_fget_nt_acl,
        .get_nt_acl_fn = vfs_lttng_get_nt_acl,
        .fset_nt_acl_fn = vfs_lttng_fset_nt_acl,
        .audit_file_fn = vfs_lttng_audit_file,
        .sys_acl_get_file_fn = vfs_lttng_sys_acl_get_file,
        .sys_acl_get_fd_fn = vfs_lttng_sys_acl_get_fd,
        .sys_acl_blob_get_file_fn = vfs_lttng_sys_acl_blob_get_file,
        .sys_acl_blob_get_fd_fn = vfs_lttng_sys_acl_blob_get_fd,
        .sys_acl_set_file_fn = vfs_lttng_sys_acl_set_file,
        .sys_acl_set_fd_fn = vfs_lttng_sys_acl_set_fd,
        .sys_acl_delete_def_file_fn = vfs_lttng_sys_acl_delete_def_file,
        .getxattr_fn = vfs_lttng_getxattr,
        .fgetxattr_fn = vfs_lttng_fgetxattr,
        .listxattr_fn = vfs_lttng_listxattr,
        .flistxattr_fn = vfs_lttng_flistxattr,
        .removexattr_fn = vfs_lttng_removexattr,
        .fremovexattr_fn = vfs_lttng_fremovexattr,
        .setxattr_fn = vfs_lttng_setxattr,
        .fsetxattr_fn = vfs_lttng_fsetxattr,
        .aio_force_fn = vfs_lttng_aio_force,
        .durable_cookie_fn = vfs_lttng_durable_cookie,
        .durable_disconnect_fn = vfs_lttng_durable_disconnect,
        .durable_reconnect_fn = vfs_lttng_durable_reconnect,
        .readdir_attr_fn = vfs_lttng_readdir_attr
};

NTSTATUS vfs_lttng_init(TALLOC_CTX *);
NTSTATUS vfs_lttng_init(TALLOC_CTX *ctx)
{
    return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "lttng",
                            &vfs_lttng_fns);
}
    
