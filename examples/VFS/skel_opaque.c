/* 
 * Skeleton VFS module.  Implements dummy versions of all VFS
 * functions.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Stefan (metze) Metzmacher, 2003
 * Copyright (C) Jeremy Allison 2009
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

#include "../source3/include/includes.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"

/* PLEASE,PLEASE READ THE VFS MODULES CHAPTER OF THE 
   SAMBA DEVELOPERS GUIDE!!!!!!
 */

/* If you take this file as template for your module
 * you must re-implement every function.
 */

static int skel_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
	errno = ENOSYS;
	return -1;
}

static void skel_disconnect(vfs_handle_struct *handle)
{
	;
}

static uint64_t skel_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	*bsize = 0;
	*dfree = 0;
	*dsize = 0;
	return 0;
}

static int skel_get_quota(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

static int skel_set_quota(vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype,
			  unid_t id, SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

static int skel_get_shadow_copy_data(vfs_handle_struct *handle,
				     files_struct *fsp,
				     struct shadow_copy_data *shadow_copy_data,
				     bool labels)
{
	errno = ENOSYS;
	return -1;
}

static int skel_statvfs(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				struct vfs_statvfs_struct *statbuf)
{
	errno = ENOSYS;
	return -1;
}

static uint32_t skel_fs_capabilities(struct vfs_handle_struct *handle,
				     enum timestamp_set_resolution *p_ts_res)
{
	return 0;
}

static NTSTATUS skel_get_dfs_referrals(struct vfs_handle_struct *handle,
				       struct dfs_GetDFSReferral *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_snap_check_path(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     const char *service_path,
				     char **base_volume)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS skel_snap_create(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 const char *base_volume,
				 time_t *tstamp,
				 bool rw,
				 char **base_path,
				 char **snap_path)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS skel_snap_delete(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 char *base_path,
				 char *snap_path)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static DIR *skel_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
			   const char *mask, uint32_t attr)
{
	return NULL;
}

static struct dirent *skel_readdir(vfs_handle_struct *handle,
				   DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
	return NULL;
}

static void skel_seekdir(vfs_handle_struct *handle, DIR *dirp, long offset)
{
	;
}

static long skel_telldir(vfs_handle_struct *handle, DIR *dirp)
{
	return (long)-1;
}

static void skel_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
	;
}

static int skel_mkdirat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int skel_closedir(vfs_handle_struct *handle, DIR *dir)
{
	errno = ENOSYS;
	return -1;
}

static int skel_openat(struct vfs_handle_struct *handle,
		       const struct files_struct *dirfsp,
		       const struct smb_filename *smb_fname,
		       struct files_struct *fsp,
		       int flags,
		       mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static NTSTATUS skel_create_file(struct vfs_handle_struct *handle,
				 struct smb_request *req,
				 struct files_struct **dirfsp,
				 struct smb_filename *smb_fname,
				 uint32_t access_mask,
				 uint32_t share_access,
				 uint32_t create_disposition,
				 uint32_t create_options,
				 uint32_t file_attributes,
				 uint32_t oplock_request,
				 const struct smb2_lease *lease,
				 uint64_t allocation_size,
				 uint32_t private_flags,
				 struct security_descriptor *sd,
				 struct ea_list *ea_list,
				 files_struct **result, int *pinfo,
				 const struct smb2_create_blobs *in_context_blobs,
				 struct smb2_create_blobs *out_context_blobs)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int skel_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_pread(vfs_handle_struct *handle, files_struct *fsp,
			  void *data, size_t n, off_t offset)
{
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *skel_pread_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp,
					  void *data, size_t n, off_t offset)
{
	return NULL;
}

static ssize_t skel_pread_recv(struct tevent_req *req,
			       struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

static ssize_t skel_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			   const void *data, size_t n, off_t offset)
{
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *skel_pwrite_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   const void *data,
					   size_t n, off_t offset)
{
	return NULL;
}

static ssize_t skel_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

static off_t skel_lseek(vfs_handle_struct *handle, files_struct *fsp,
			off_t offset, int whence)
{
	errno = ENOSYS;
	return (off_t) - 1;
}

static ssize_t skel_sendfile(vfs_handle_struct *handle, int tofd,
			     files_struct *fromfsp, const DATA_BLOB *hdr,
			     off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_recvfile(vfs_handle_struct *handle, int fromfd,
			     files_struct *tofsp, off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

static int skel_renameat(vfs_handle_struct *handle,
		       files_struct *srcfsp,
		       const struct smb_filename *smb_fname_src,
		       files_struct *dstfsp,
		       const struct smb_filename *smb_fname_dst)
{
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *skel_fsync_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp)
{
	return NULL;
}

static int skel_fsync_recv(struct tevent_req *req,
			   struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

static int skel_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static int skel_fstat(vfs_handle_struct *handle, files_struct *fsp,
		      SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return -1;
}

static int skel_lstat(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static uint64_t skel_get_alloc_size(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    const SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return -1;
}

static int skel_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	errno = ENOSYS;
	return -1;
}

static int skel_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int skel_fchmod(vfs_handle_struct *handle, files_struct *fsp,
		       mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int skel_fchown(vfs_handle_struct *handle, files_struct *fsp,
		       uid_t uid, gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

static int skel_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

static int skel_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static struct smb_filename *skel_getwd(vfs_handle_struct *handle,
				TALLOC_CTX *ctx)
{
	errno = ENOSYS;
	return NULL;
}

static int skel_ntimes(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       struct smb_file_time *ft)
{
	errno = ENOSYS;
	return -1;
}

static int skel_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
			  off_t offset)
{
	errno = ENOSYS;
	return -1;
}

static int skel_fallocate(vfs_handle_struct *handle, files_struct *fsp,
			  uint32_t mode, off_t offset, off_t len)
{
	errno = ENOSYS;
	return -1;
}

static bool skel_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
		      off_t offset, off_t count, int type)
{
	errno = ENOSYS;
	return false;
}

static int skel_kernel_flock(struct vfs_handle_struct *handle,
			     struct files_struct *fsp,
			     uint32_t share_mode, uint32_t access_mask)
{
	errno = ENOSYS;
	return -1;
}

static int skel_fcntl(struct vfs_handle_struct *handle,
		      struct files_struct *fsp, int cmd, va_list cmd_arg)
{
	errno = ENOSYS;
	return -1;
}

static int skel_linux_setlease(struct vfs_handle_struct *handle,
			       struct files_struct *fsp, int leasetype)
{
	errno = ENOSYS;
	return -1;
}

static bool skel_getlock(vfs_handle_struct *handle, files_struct *fsp,
			 off_t *poffset, off_t *pcount, int *ptype,
			 pid_t *ppid)
{
	errno = ENOSYS;
	return false;
}

static int skel_symlinkat(vfs_handle_struct *handle,
			const struct smb_filename *link_contents,
			struct files_struct *dirfsp,
			const struct smb_filename *new_smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static int skel_vfs_readlinkat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	errno = ENOSYS;
	return -1;
}

static int skel_linkat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags)
{
	errno = ENOSYS;
	return -1;
}

static int skel_mknodat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	errno = ENOSYS;
	return -1;
}

static struct smb_filename *skel_realpath(vfs_handle_struct *handle,
			TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return NULL;
}

static int skel_chflags(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uint flags)
{
	errno = ENOSYS;
	return -1;
}

static struct file_id skel_file_id_create(vfs_handle_struct *handle,
					  const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id;
	ZERO_STRUCT(id);
	errno = ENOSYS;
	return id;
}

static uint64_t skel_fs_file_id(vfs_handle_struct *handle,
				const SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return 0;
}

struct skel_offload_read_state {
	bool dummy;
};

static struct tevent_req *skel_offload_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct vfs_handle_struct *handle,
	struct files_struct *fsp,
	uint32_t fsctl,
	uint32_t ttl,
	off_t offset,
	size_t to_copy)
{
	struct tevent_req *req = NULL;
	struct skel_offload_read_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state, struct skel_offload_read_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

static NTSTATUS skel_offload_read_recv(struct tevent_req *req,
				       struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       DATA_BLOB *_token_blob)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	tevent_req_received(req);

	return NT_STATUS_OK;
}

struct skel_cc_state {
	uint64_t unused;
};
static struct tevent_req *skel_offload_write_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       uint32_t fsctl,
					       DATA_BLOB *token,
					       off_t transfer_offset,
					       struct files_struct *dest_fsp,
					       off_t dest_off,
					       off_t num)
{
	struct tevent_req *req;
	struct skel_cc_state *cc_state;

	req = tevent_req_create(mem_ctx, &cc_state, struct skel_cc_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

static NTSTATUS skel_offload_write_recv(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     off_t *copied)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}
	tevent_req_received(req);

	return NT_STATUS_OK;
}

static NTSTATUS skel_get_compression(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct files_struct *fsp,
				     struct smb_filename *smb_fname,
				     uint16_t *_compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS skel_set_compression(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct files_struct *fsp,
				     uint16_t compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS skel_streaminfo(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				unsigned int *num_streams,
				struct stream_struct **streams)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int skel_get_real_filename(struct vfs_handle_struct *handle,
				  const struct smb_filename *path,
				  const char *name,
				  TALLOC_CTX *mem_ctx, char **found_name)
{
	errno = ENOSYS;
	return -1;
}

static const char *skel_connectpath(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return NULL;
}

static NTSTATUS skel_brl_lock_windows(struct vfs_handle_struct *handle,
				      struct byte_range_lock *br_lck,
				      struct lock_struct *plock)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static bool skel_brl_unlock_windows(struct vfs_handle_struct *handle,
				    struct byte_range_lock *br_lck,
				    const struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

static bool skel_strict_lock_check(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

static NTSTATUS skel_translate_name(struct vfs_handle_struct *handle,
				    const char *mapped_name,
				    enum vfs_translate_direction direction,
				    TALLOC_CTX *mem_ctx, char **pmapped_name)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_fsctl(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   TALLOC_CTX *ctx,
			   uint32_t function,
			   uint16_t req_flags,	/* Needed for UNICODE ... */
			   const uint8_t *_in_data,
			   uint32_t in_len,
			   uint8_t **_out_data,
			   uint32_t max_out_len, uint32_t *out_len)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_readdir_attr(struct vfs_handle_struct *handle,
				  const struct smb_filename *fname,
				  TALLOC_CTX *mem_ctx,
				  struct readdir_attr_data **pattr_data)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_get_dos_attributes(struct vfs_handle_struct *handle,
				struct smb_filename *smb_fname,
				uint32_t *dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

struct skel_get_dos_attributes_state {
	struct vfs_aio_state aio_state;
	uint32_t dosmode;
};

static struct tevent_req *skel_get_dos_attributes_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			struct smb_filename *smb_fname)
{
	struct tevent_req *req = NULL;
	struct skel_get_dos_attributes_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct skel_get_dos_attributes_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

static NTSTATUS skel_get_dos_attributes_recv(struct tevent_req *req,
					     struct vfs_aio_state *aio_state,
					     uint32_t *dosmode)
{
	struct skel_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct skel_get_dos_attributes_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*aio_state = state->aio_state;
	*dosmode = state->dosmode;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

static NTSTATUS skel_fget_dos_attributes(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t *dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_set_dos_attributes(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_fset_dos_attributes(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info,
				 TALLOC_CTX *mem_ctx,
				 struct security_descriptor **ppdesc)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_get_nt_acl_at(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info_sent,
				 const struct security_descriptor *psd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static SMB_ACL_T skel_sys_acl_get_file(vfs_handle_struct *handle,
				       const struct smb_filename *smb_fname,
				       SMB_ACL_TYPE_T type,
				       TALLOC_CTX *mem_ctx)
{
	errno = ENOSYS;
	return (SMB_ACL_T) NULL;
}

static SMB_ACL_T skel_sys_acl_get_fd(vfs_handle_struct *handle,
				     files_struct *fsp, TALLOC_CTX *mem_ctx)
{
	errno = ENOSYS;
	return (SMB_ACL_T) NULL;
}

static int skel_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

static int skel_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				    files_struct *fsp, TALLOC_CTX *mem_ctx,
				    char **blob_description, DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

static int skel_sys_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

static int skel_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
			       SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

static int skel_sys_acl_delete_def_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_getxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)
{
	errno = ENOSYS;
	return -1;
}

struct skel_getxattrat_state {
	struct vfs_aio_state aio_state;
	ssize_t xattr_size;
	uint8_t *xattr_value;
};

static struct tevent_req *skel_getxattrat_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			const struct smb_filename *smb_fname,
			const char *xattr_name,
			size_t alloc_hint)
{
	struct tevent_req *req = NULL;
	struct skel_getxattrat_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct skel_getxattrat_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_error(req, ENOSYS);
	return tevent_req_post(req, ev);
}

static ssize_t skel_getxattrat_recv(struct tevent_req *req,
				    struct vfs_aio_state *aio_state,
				    TALLOC_CTX *mem_ctx,
				    uint8_t **xattr_value)
{
	struct skel_getxattrat_state *state = tevent_req_data(
		req, struct skel_getxattrat_state);
	ssize_t xattr_size;

	if (tevent_req_is_unix_error(req, &aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	*aio_state = state->aio_state;
	xattr_size = state->xattr_size;
	if (xattr_value != NULL) {
		*xattr_value = talloc_move(mem_ctx, &state->xattr_value);
	}

	tevent_req_received(req);
	return xattr_size;
}

static ssize_t skel_fgetxattr(vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name,
			      void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_listxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *list,
				size_t size)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_flistxattr(vfs_handle_struct *handle,
			       struct files_struct *fsp, char *list,
			       size_t size)
{
	errno = ENOSYS;
	return -1;
}

static int skel_removexattr(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name)
{
	errno = ENOSYS;
	return -1;
}

static int skel_fremovexattr(vfs_handle_struct *handle,
			     struct files_struct *fsp, const char *name)
{
	errno = ENOSYS;
	return -1;
}

static int skel_setxattr(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name,
			const void *value,
			size_t size,
			int flags)
{
	errno = ENOSYS;
	return -1;
}

static int skel_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	errno = ENOSYS;
	return -1;
}

static bool skel_aio_force(struct vfs_handle_struct *handle,
			   struct files_struct *fsp)
{
	errno = ENOSYS;
	return false;
}

static NTSTATUS skel_audit_file(struct vfs_handle_struct *handle,
				struct smb_filename *file,
				struct security_acl *sacl,
				uint32_t access_requested,
				uint32_t access_denied)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_durable_cookie(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *cookie)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_durable_disconnect(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					const DATA_BLOB old_cookie,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *new_cookie)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_durable_reconnect(struct vfs_handle_struct *handle,
				       struct smb_request *smb1req,
				       struct smbXsrv_open *op,
				       const DATA_BLOB old_cookie,
				       TALLOC_CTX *mem_ctx,
				       struct files_struct **fsp,
				       DATA_BLOB *new_cookie)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* VFS operations structure */

static struct vfs_fn_pointers skel_opaque_fns = {
	/* Disk operations */

	.connect_fn = skel_connect,
	.disconnect_fn = skel_disconnect,
	.disk_free_fn = skel_disk_free,
	.get_quota_fn = skel_get_quota,
	.set_quota_fn = skel_set_quota,
	.get_shadow_copy_data_fn = skel_get_shadow_copy_data,
	.statvfs_fn = skel_statvfs,
	.fs_capabilities_fn = skel_fs_capabilities,
	.get_dfs_referrals_fn = skel_get_dfs_referrals,
	.create_dfs_pathat_fn = skel_create_dfs_pathat,
	.read_dfs_pathat_fn = skel_read_dfs_pathat,
	.snap_check_path_fn = skel_snap_check_path,
	.snap_create_fn = skel_snap_create,
	.snap_delete_fn = skel_snap_delete,

	/* Directory operations */

	.fdopendir_fn = skel_fdopendir,
	.readdir_fn = skel_readdir,
	.seekdir_fn = skel_seekdir,
	.telldir_fn = skel_telldir,
	.rewind_dir_fn = skel_rewind_dir,
	.mkdirat_fn = skel_mkdirat,
	.closedir_fn = skel_closedir,

	/* File operations */

	.openat_fn = skel_openat,
	.create_file_fn = skel_create_file,
	.close_fn = skel_close_fn,
	.pread_fn = skel_pread,
	.pread_send_fn = skel_pread_send,
	.pread_recv_fn = skel_pread_recv,
	.pwrite_fn = skel_pwrite,
	.pwrite_send_fn = skel_pwrite_send,
	.pwrite_recv_fn = skel_pwrite_recv,
	.lseek_fn = skel_lseek,
	.sendfile_fn = skel_sendfile,
	.recvfile_fn = skel_recvfile,
	.renameat_fn = skel_renameat,
	.fsync_send_fn = skel_fsync_send,
	.fsync_recv_fn = skel_fsync_recv,
	.stat_fn = skel_stat,
	.fstat_fn = skel_fstat,
	.lstat_fn = skel_lstat,
	.get_alloc_size_fn = skel_get_alloc_size,
	.unlinkat_fn = skel_unlinkat,
	.chmod_fn = skel_chmod,
	.fchmod_fn = skel_fchmod,
	.fchown_fn = skel_fchown,
	.lchown_fn = skel_lchown,
	.chdir_fn = skel_chdir,
	.getwd_fn = skel_getwd,
	.ntimes_fn = skel_ntimes,
	.ftruncate_fn = skel_ftruncate,
	.fallocate_fn = skel_fallocate,
	.lock_fn = skel_lock,
	.kernel_flock_fn = skel_kernel_flock,
	.fcntl_fn = skel_fcntl,
	.linux_setlease_fn = skel_linux_setlease,
	.getlock_fn = skel_getlock,
	.symlinkat_fn = skel_symlinkat,
	.readlinkat_fn = skel_vfs_readlinkat,
	.linkat_fn = skel_linkat,
	.mknodat_fn = skel_mknodat,
	.realpath_fn = skel_realpath,
	.chflags_fn = skel_chflags,
	.file_id_create_fn = skel_file_id_create,
	.fs_file_id_fn = skel_fs_file_id,
	.offload_read_send_fn = skel_offload_read_send,
	.offload_read_recv_fn = skel_offload_read_recv,
	.offload_write_send_fn = skel_offload_write_send,
	.offload_write_recv_fn = skel_offload_write_recv,
	.get_compression_fn = skel_get_compression,
	.set_compression_fn = skel_set_compression,

	.streaminfo_fn = skel_streaminfo,
	.get_real_filename_fn = skel_get_real_filename,
	.connectpath_fn = skel_connectpath,
	.brl_lock_windows_fn = skel_brl_lock_windows,
	.brl_unlock_windows_fn = skel_brl_unlock_windows,
	.strict_lock_check_fn = skel_strict_lock_check,
	.translate_name_fn = skel_translate_name,
	.fsctl_fn = skel_fsctl,
	.readdir_attr_fn = skel_readdir_attr,
	.audit_file_fn = skel_audit_file,

	/* DOS attributes. */
	.get_dos_attributes_fn = skel_get_dos_attributes,
	.get_dos_attributes_send_fn = skel_get_dos_attributes_send,
	.get_dos_attributes_recv_fn = skel_get_dos_attributes_recv,
	.fget_dos_attributes_fn = skel_fget_dos_attributes,
	.set_dos_attributes_fn = skel_set_dos_attributes,
	.fset_dos_attributes_fn = skel_fset_dos_attributes,

	/* NT ACL operations. */

	.fget_nt_acl_fn = skel_fget_nt_acl,
	.get_nt_acl_at_fn = skel_get_nt_acl_at,
	.fset_nt_acl_fn = skel_fset_nt_acl,

	/* POSIX ACL operations. */

	.sys_acl_get_file_fn = skel_sys_acl_get_file,
	.sys_acl_get_fd_fn = skel_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = skel_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = skel_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = skel_sys_acl_set_file,
	.sys_acl_set_fd_fn = skel_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = skel_sys_acl_delete_def_file,

	/* EA operations. */
	.getxattr_fn = skel_getxattr,
	.getxattrat_send_fn = skel_getxattrat_send,
	.getxattrat_recv_fn = skel_getxattrat_recv,
	.fgetxattr_fn = skel_fgetxattr,
	.listxattr_fn = skel_listxattr,
	.flistxattr_fn = skel_flistxattr,
	.removexattr_fn = skel_removexattr,
	.fremovexattr_fn = skel_fremovexattr,
	.setxattr_fn = skel_setxattr,
	.fsetxattr_fn = skel_fsetxattr,

	/* aio operations */
	.aio_force_fn = skel_aio_force,

	/* durable handle operations */
	.durable_cookie_fn = skel_durable_cookie,
	.durable_disconnect_fn = skel_durable_disconnect,
	.durable_reconnect_fn = skel_durable_reconnect,
};

static_decl_vfs;
NTSTATUS vfs_skel_opaque_init(TALLOC_CTX *ctx)
{
	/*
	 * smb_vfs_assert_all_fns() makes sure every
	 * call is implemented.
	 *
	 * An opaque module requires this!
	 */
	smb_vfs_assert_all_fns(&skel_opaque_fns, "skel_opaque");
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "skel_opaque",
				&skel_opaque_fns);
}
