/*
 * VFS module with "not implemented " helper functions for other modules.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Stefan (metze) Metzmacher, 2003,2018
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

#include "includes.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"

int vfs_not_implemented_connect(
			vfs_handle_struct *handle,
			const char *service,
			const char *user)
{
	errno = ENOSYS;
	return -1;
}

void vfs_not_implemented_disconnect(vfs_handle_struct *handle)
{
	;
}

uint64_t vfs_not_implemented_disk_free(vfs_handle_struct *handle,
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

int vfs_not_implemented_get_quota(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_set_quota(vfs_handle_struct *handle,
				  enum SMB_QUOTA_TYPE qtype,
				  unid_t id, SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_get_shadow_copy_data(vfs_handle_struct *handle,
				files_struct *fsp,
				struct shadow_copy_data *shadow_copy_data,
				bool labels)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_statvfs(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				struct vfs_statvfs_struct *statbuf)
{
	errno = ENOSYS;
	return -1;
}

uint32_t vfs_not_implemented_fs_capabilities(struct vfs_handle_struct *handle,
				enum timestamp_set_resolution *p_ts_res)
{
	return 0;
}

NTSTATUS vfs_not_implemented_get_dfs_referrals(struct vfs_handle_struct *handle,
					       struct dfs_GetDFSReferral *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_snap_check_path(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				const char *service_path,
				char **base_volume)
{
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS vfs_not_implemented_snap_create(struct vfs_handle_struct *handle,
					 TALLOC_CTX *mem_ctx,
					 const char *base_volume,
					 time_t *tstamp,
					 bool rw,
					 char **base_path,
					 char **snap_path)
{
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS vfs_not_implemented_snap_delete(struct vfs_handle_struct *handle,
					 TALLOC_CTX *mem_ctx,
					 char *base_path,
					 char *snap_path)
{
	return NT_STATUS_NOT_SUPPORTED;
}

DIR *vfs_not_implemented_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
				   const char *mask, uint32_t attr)
{
	errno = ENOSYS;
	return NULL;
}

struct dirent *vfs_not_implemented_readdir(vfs_handle_struct *handle,
					   DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return NULL;
}

void vfs_not_implemented_seekdir(vfs_handle_struct *handle, DIR *dirp, long offset)
{
	;
}

long vfs_not_implemented_telldir(vfs_handle_struct *handle, DIR *dirp)
{
	errno = ENOSYS;
	return (long)-1;
}

void vfs_not_implemented_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
	;
}

int vfs_not_implemented_mkdirat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_closedir(vfs_handle_struct *handle, DIR *dir)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_openat(vfs_handle_struct *handle,
			       const struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname,
			       struct files_struct *fsp,
			       int flags,
			       mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

NTSTATUS vfs_not_implemented_create_file(struct vfs_handle_struct *handle,
				struct smb_request *req,
				struct files_struct **dirsp,
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

int vfs_not_implemented_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
	errno = ENOSYS;
	return -1;
}

ssize_t vfs_not_implemented_pread(vfs_handle_struct *handle, files_struct *fsp,
				  void *data, size_t n, off_t offset)
{
	errno = ENOSYS;
	return -1;
}

struct tevent_req *vfs_not_implemented_pread_send(struct vfs_handle_struct *handle,
						  TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct files_struct *fsp,
						  void *data, size_t n, off_t offset)
{
	return NULL;
}

ssize_t vfs_not_implemented_pread_recv(struct tevent_req *req,
				       struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

ssize_t vfs_not_implemented_pwrite(vfs_handle_struct *handle, files_struct *fsp,
				   const void *data, size_t n, off_t offset)
{
	errno = ENOSYS;
	return -1;
}

struct tevent_req *vfs_not_implemented_pwrite_send(struct vfs_handle_struct *handle,
						   TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct files_struct *fsp,
						   const void *data,
						   size_t n, off_t offset)
{
	return NULL;
}

ssize_t vfs_not_implemented_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

off_t vfs_not_implemented_lseek(vfs_handle_struct *handle, files_struct *fsp,
			off_t offset, int whence)
{
	errno = ENOSYS;
	return (off_t) - 1;
}

ssize_t vfs_not_implemented_sendfile(vfs_handle_struct *handle, int tofd,
				     files_struct *fromfsp, const DATA_BLOB *hdr,
				     off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

ssize_t vfs_not_implemented_recvfile(vfs_handle_struct *handle, int fromfd,
				     files_struct *tofsp, off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_renameat(vfs_handle_struct *handle,
			       files_struct *srcfsp,
			       const struct smb_filename *smb_fname_src,
			       files_struct *dstfsp,
			       const struct smb_filename *smb_fname_dst)
{
	errno = ENOSYS;
	return -1;
}

struct tevent_req *vfs_not_implemented_fsync_send(struct vfs_handle_struct *handle,
						  TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct files_struct *fsp)
{
	return NULL;
}

int vfs_not_implemented_fsync_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

int vfs_not_implemented_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_fstat(vfs_handle_struct *handle, files_struct *fsp,
			SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_lstat(vfs_handle_struct *handle,
			      struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

uint64_t vfs_not_implemented_get_alloc_size(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    const SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_chmod(vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname,
			      mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_fchmod(vfs_handle_struct *handle, files_struct *fsp,
			       mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_fchown(vfs_handle_struct *handle, files_struct *fsp,
			       uid_t uid, gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_lchown(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname,
			       uid_t uid,
			       gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_chdir(vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

struct smb_filename *vfs_not_implemented_getwd(vfs_handle_struct *handle,
					       TALLOC_CTX *ctx)
{
	errno = ENOSYS;
	return NULL;
}

int vfs_not_implemented_ntimes(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname,
			       struct smb_file_time *ft)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
				  off_t offset)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_fallocate(vfs_handle_struct *handle, files_struct *fsp,
				  uint32_t mode, off_t offset, off_t len)
{
	errno = ENOSYS;
	return -1;
}

bool vfs_not_implemented_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
			      off_t offset, off_t count, int type)
{
	errno = ENOSYS;
	return false;
}

int vfs_not_implemented_kernel_flock(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     uint32_t share_access, uint32_t access_mask)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_fcntl(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, int cmd,
			      va_list cmd_arg)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_linux_setlease(struct vfs_handle_struct *handle,
				       struct files_struct *fsp, int leasetype)
{
	errno = ENOSYS;
	return -1;
}

bool vfs_not_implemented_getlock(vfs_handle_struct *handle, files_struct *fsp,
				 off_t *poffset, off_t *pcount, int *ptype,
				 pid_t *ppid)
{
	errno = ENOSYS;
	return false;
}

int vfs_not_implemented_symlinkat(vfs_handle_struct *handle,
				const struct smb_filename *link_contents,
				struct files_struct *dirfsp,
				const struct smb_filename *new_smb_fname)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_vfs_readlinkat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_linkat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_mknodat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	errno = ENOSYS;
	return -1;
}

struct smb_filename *vfs_not_implemented_realpath(vfs_handle_struct *handle,
						  TALLOC_CTX *ctx,
						  const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return NULL;
}

int vfs_not_implemented_chflags(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint flags)
{
	errno = ENOSYS;
	return -1;
}

struct file_id vfs_not_implemented_file_id_create(vfs_handle_struct *handle,
						  const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id;
	ZERO_STRUCT(id);
	errno = ENOSYS;
	return id;
}

uint64_t vfs_not_implemented_fs_file_id(vfs_handle_struct *handle,
					const SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return 0;
}

struct vfs_not_implemented_offload_read_state {
	bool dummy;
};

struct tevent_req *vfs_not_implemented_offload_read_send(
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
	struct vfs_not_implemented_offload_read_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_not_implemented_offload_read_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

NTSTATUS vfs_not_implemented_offload_read_recv(struct tevent_req *req,
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

struct vfs_not_implemented_offload_write_state {
	uint64_t unused;
};

struct tevent_req *vfs_not_implemented_offload_write_send(
			struct vfs_handle_struct *handle,
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
	struct vfs_not_implemented_offload_write_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_not_implemented_offload_write_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

NTSTATUS vfs_not_implemented_offload_write_recv(struct vfs_handle_struct *handle,
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

NTSTATUS vfs_not_implemented_get_compression(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct files_struct *fsp,
					     struct smb_filename *smb_fname,
					     uint16_t *_compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS vfs_not_implemented_set_compression(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct files_struct *fsp,
					     uint16_t compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS vfs_not_implemented_streaminfo(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					const struct smb_filename *smb_fname,
					TALLOC_CTX *mem_ctx,
					unsigned int *num_streams,
					struct stream_struct **streams)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

int vfs_not_implemented_get_real_filename(struct vfs_handle_struct *handle,
					  const struct smb_filename *path,
					  const char *name,
					  TALLOC_CTX *mem_ctx,
					  char **found_name)
{
	errno = ENOSYS;
	return -1;
}

const char *vfs_not_implemented_connectpath(struct vfs_handle_struct *handle,
					    const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return NULL;
}

NTSTATUS vfs_not_implemented_brl_lock_windows(struct vfs_handle_struct *handle,
					      struct byte_range_lock *br_lck,
					      struct lock_struct *plock)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

bool vfs_not_implemented_brl_unlock_windows(struct vfs_handle_struct *handle,
					    struct byte_range_lock *br_lck,
					    const struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

bool vfs_not_implemented_strict_lock_check(struct vfs_handle_struct *handle,
					   struct files_struct *fsp,
					   struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

NTSTATUS vfs_not_implemented_translate_name(struct vfs_handle_struct *handle,
					    const char *mapped_name,
					    enum vfs_translate_direction direction,
					    TALLOC_CTX *mem_ctx, char **pmapped_name)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_fsctl(struct vfs_handle_struct *handle,
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

NTSTATUS vfs_not_implemented_readdir_attr(struct vfs_handle_struct *handle,
					  const struct smb_filename *fname,
					  TALLOC_CTX *mem_ctx,
					  struct readdir_attr_data **pattr_data)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_get_dos_attributes(struct vfs_handle_struct *handle,
						struct smb_filename *smb_fname,
						uint32_t *dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

struct vfs_not_implemented_get_dos_attributes_state {
	struct vfs_aio_state aio_state;
	uint32_t dosmode;
};

struct tevent_req *vfs_not_implemented_get_dos_attributes_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			struct smb_filename *smb_fname)
{
	struct tevent_req *req = NULL;
	struct vfs_not_implemented_get_dos_attributes_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
			struct vfs_not_implemented_get_dos_attributes_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
	return tevent_req_post(req, ev);
}

NTSTATUS vfs_not_implemented_get_dos_attributes_recv(
			struct tevent_req *req,
			struct vfs_aio_state *aio_state,
			uint32_t *dosmode)
{
	struct vfs_not_implemented_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct vfs_not_implemented_get_dos_attributes_state);
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

NTSTATUS vfs_not_implemented_fget_dos_attributes(struct vfs_handle_struct *handle,
						 struct files_struct *fsp,
						 uint32_t *dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_set_dos_attributes(struct vfs_handle_struct *handle,
						const struct smb_filename *smb_fname,
						uint32_t dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_fset_dos_attributes(struct vfs_handle_struct *handle,
						 struct files_struct *fsp,
						 uint32_t dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
					 uint32_t security_info,
					 TALLOC_CTX *mem_ctx,
					 struct security_descriptor **ppdesc)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_get_nt_acl_at(vfs_handle_struct *handle,
					struct files_struct *dirfsp,
					const struct smb_filename *smb_fname,
					uint32_t security_info,
					TALLOC_CTX *mem_ctx,
					struct security_descriptor **ppdesc)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
					 uint32_t security_info_sent,
					 const struct security_descriptor *psd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

SMB_ACL_T vfs_not_implemented_sys_acl_get_file(vfs_handle_struct *handle,
					       const struct smb_filename *smb_fname,
					       SMB_ACL_TYPE_T type,
					       TALLOC_CTX *mem_ctx)
{
	errno = ENOSYS;
	return (SMB_ACL_T) NULL;
}

SMB_ACL_T vfs_not_implemented_sys_acl_get_fd(vfs_handle_struct *handle,
					     files_struct *fsp, TALLOC_CTX *mem_ctx)
{
	errno = ENOSYS;
	return (SMB_ACL_T) NULL;
}

int vfs_not_implemented_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				files_struct *fsp, TALLOC_CTX *mem_ctx,
				char **blob_description, DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_sys_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
				       SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_sys_acl_delete_def_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

ssize_t vfs_not_implemented_getxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)
{
	errno = ENOSYS;
	return -1;
}

struct vfs_not_implemented_getxattrat_state {
	struct vfs_aio_state aio_state;
	ssize_t xattr_size;
	uint8_t *xattr_value;
};

struct tevent_req *vfs_not_implemented_getxattrat_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			const struct smb_filename *smb_fname,
			const char *xattr_name,
			size_t alloc_hint)
{
	struct tevent_req *req = NULL;
	struct vfs_not_implemented_getxattrat_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct vfs_not_implemented_getxattrat_state);
	if (req == NULL) {
		return NULL;
	}

	tevent_req_error(req, ENOSYS);
	return tevent_req_post(req, ev);
}

ssize_t vfs_not_implemented_getxattrat_recv(struct tevent_req *req,
				    struct vfs_aio_state *aio_state,
				    TALLOC_CTX *mem_ctx,
				    uint8_t **xattr_value)
{
	struct vfs_not_implemented_getxattrat_state *state = tevent_req_data(
		req, struct vfs_not_implemented_getxattrat_state);
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

ssize_t vfs_not_implemented_fgetxattr(vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name,
			      void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}

ssize_t vfs_not_implemented_listxattr(vfs_handle_struct *handle,
				      const struct smb_filename *smb_fname,
				      char *list,
				      size_t size)
{
	errno = ENOSYS;
	return -1;
}

ssize_t vfs_not_implemented_flistxattr(vfs_handle_struct *handle,
				       struct files_struct *fsp, char *list,
				       size_t size)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_removexattr(vfs_handle_struct *handle,
				    const struct smb_filename *smb_fname,
				    const char *name)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_fremovexattr(vfs_handle_struct *handle,
				     struct files_struct *fsp, const char *name)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_setxattr(vfs_handle_struct *handle,
				 const struct smb_filename *smb_fname,
				 const char *name,
				 const void *value,
				 size_t size,
				 int flags)
{
	errno = ENOSYS;
	return -1;
}

int vfs_not_implemented_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
				  const char *name, const void *value, size_t size,
				  int flags)
{
	errno = ENOSYS;
	return -1;
}

bool vfs_not_implemented_aio_force(struct vfs_handle_struct *handle,
				   struct files_struct *fsp)
{
	errno = ENOSYS;
	return false;
}

NTSTATUS vfs_not_implemented_audit_file(struct vfs_handle_struct *handle,
					struct smb_filename *file,
					struct security_acl *sacl,
					uint32_t access_requested,
					uint32_t access_denied)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_durable_cookie(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    TALLOC_CTX *mem_ctx,
					    DATA_BLOB *cookie)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_durable_disconnect(struct vfs_handle_struct *handle,
						struct files_struct *fsp,
						const DATA_BLOB old_cookie,
						TALLOC_CTX *mem_ctx,
						DATA_BLOB *new_cookie)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS vfs_not_implemented_durable_reconnect(struct vfs_handle_struct *handle,
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

static struct vfs_fn_pointers vfs_not_implemented_fns = {
	/* Disk operations */

	.connect_fn = vfs_not_implemented_connect,
	.disconnect_fn = vfs_not_implemented_disconnect,
	.disk_free_fn = vfs_not_implemented_disk_free,
	.get_quota_fn = vfs_not_implemented_get_quota,
	.set_quota_fn = vfs_not_implemented_set_quota,
	.get_shadow_copy_data_fn = vfs_not_implemented_get_shadow_copy_data,
	.statvfs_fn = vfs_not_implemented_statvfs,
	.fs_capabilities_fn = vfs_not_implemented_fs_capabilities,
	.get_dfs_referrals_fn = vfs_not_implemented_get_dfs_referrals,
	.create_dfs_pathat_fn = vfs_not_implemented_create_dfs_pathat,
	.read_dfs_pathat_fn = vfs_not_implemented_read_dfs_pathat,
	.snap_check_path_fn = vfs_not_implemented_snap_check_path,
	.snap_create_fn = vfs_not_implemented_snap_create,
	.snap_delete_fn = vfs_not_implemented_snap_delete,

	/* Directory operations */

	.fdopendir_fn = vfs_not_implemented_fdopendir,
	.readdir_fn = vfs_not_implemented_readdir,
	.seekdir_fn = vfs_not_implemented_seekdir,
	.telldir_fn = vfs_not_implemented_telldir,
	.rewind_dir_fn = vfs_not_implemented_rewind_dir,
	.mkdirat_fn = vfs_not_implemented_mkdirat,
	.closedir_fn = vfs_not_implemented_closedir,

	/* File operations */

	.openat_fn = vfs_not_implemented_openat,
	.create_file_fn = vfs_not_implemented_create_file,
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
	.get_alloc_size_fn = vfs_not_implemented_get_alloc_size,
	.unlinkat_fn = vfs_not_implemented_unlinkat,
	.chmod_fn = vfs_not_implemented_chmod,
	.fchmod_fn = vfs_not_implemented_fchmod,
	.fchown_fn = vfs_not_implemented_fchown,
	.lchown_fn = vfs_not_implemented_lchown,
	.chdir_fn = vfs_not_implemented_chdir,
	.getwd_fn = vfs_not_implemented_getwd,
	.ntimes_fn = vfs_not_implemented_ntimes,
	.ftruncate_fn = vfs_not_implemented_ftruncate,
	.fallocate_fn = vfs_not_implemented_fallocate,
	.lock_fn = vfs_not_implemented_lock,
	.kernel_flock_fn = vfs_not_implemented_kernel_flock,
	.fcntl_fn = vfs_not_implemented_fcntl,
	.linux_setlease_fn = vfs_not_implemented_linux_setlease,
	.getlock_fn = vfs_not_implemented_getlock,
	.symlinkat_fn = vfs_not_implemented_symlinkat,
	.readlinkat_fn = vfs_not_implemented_vfs_readlinkat,
	.linkat_fn = vfs_not_implemented_linkat,
	.mknodat_fn = vfs_not_implemented_mknodat,
	.realpath_fn = vfs_not_implemented_realpath,
	.chflags_fn = vfs_not_implemented_chflags,
	.file_id_create_fn = vfs_not_implemented_file_id_create,
	.fs_file_id_fn = vfs_not_implemented_fs_file_id,
	.offload_read_send_fn = vfs_not_implemented_offload_read_send,
	.offload_read_recv_fn = vfs_not_implemented_offload_read_recv,
	.offload_write_send_fn = vfs_not_implemented_offload_write_send,
	.offload_write_recv_fn = vfs_not_implemented_offload_write_recv,
	.get_compression_fn = vfs_not_implemented_get_compression,
	.set_compression_fn = vfs_not_implemented_set_compression,

	.streaminfo_fn = vfs_not_implemented_streaminfo,
	.get_real_filename_fn = vfs_not_implemented_get_real_filename,
	.connectpath_fn = vfs_not_implemented_connectpath,
	.brl_lock_windows_fn = vfs_not_implemented_brl_lock_windows,
	.brl_unlock_windows_fn = vfs_not_implemented_brl_unlock_windows,
	.strict_lock_check_fn = vfs_not_implemented_strict_lock_check,
	.translate_name_fn = vfs_not_implemented_translate_name,
	.fsctl_fn = vfs_not_implemented_fsctl,
	.readdir_attr_fn = vfs_not_implemented_readdir_attr,
	.audit_file_fn = vfs_not_implemented_audit_file,

	/* DOS attributes. */
	.get_dos_attributes_fn = vfs_not_implemented_get_dos_attributes,
	.get_dos_attributes_send_fn = vfs_not_implemented_get_dos_attributes_send,
	.get_dos_attributes_recv_fn = vfs_not_implemented_get_dos_attributes_recv,
	.fget_dos_attributes_fn = vfs_not_implemented_fget_dos_attributes,
	.set_dos_attributes_fn = vfs_not_implemented_set_dos_attributes,
	.fset_dos_attributes_fn = vfs_not_implemented_fset_dos_attributes,

	/* NT ACL operations. */

	.fget_nt_acl_fn = vfs_not_implemented_fget_nt_acl,
	.get_nt_acl_at_fn = vfs_not_implemented_get_nt_acl_at,
	.fset_nt_acl_fn = vfs_not_implemented_fset_nt_acl,

	/* POSIX ACL operations. */

	.sys_acl_get_file_fn = vfs_not_implemented_sys_acl_get_file,
	.sys_acl_get_fd_fn = vfs_not_implemented_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = vfs_not_implemented_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = vfs_not_implemented_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = vfs_not_implemented_sys_acl_set_file,
	.sys_acl_set_fd_fn = vfs_not_implemented_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = vfs_not_implemented_sys_acl_delete_def_file,

	/* EA operations. */
	.getxattr_fn = vfs_not_implemented_getxattr,
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = vfs_not_implemented_fgetxattr,
	.listxattr_fn = vfs_not_implemented_listxattr,
	.flistxattr_fn = vfs_not_implemented_flistxattr,
	.removexattr_fn = vfs_not_implemented_removexattr,
	.fremovexattr_fn = vfs_not_implemented_fremovexattr,
	.setxattr_fn = vfs_not_implemented_setxattr,
	.fsetxattr_fn = vfs_not_implemented_fsetxattr,

	/* aio operations */
	.aio_force_fn = vfs_not_implemented_aio_force,

	/* durable handle operations */
	.durable_cookie_fn = vfs_not_implemented_durable_cookie,
	.durable_disconnect_fn = vfs_not_implemented_durable_disconnect,
	.durable_reconnect_fn = vfs_not_implemented_durable_reconnect,
};

static_decl_vfs;
NTSTATUS vfs_not_implemented_init(TALLOC_CTX *ctx)
{
	/*
	 * smb_vfs_assert_all_fns() makes sure every
	 * call is implemented.
	 */
	smb_vfs_assert_all_fns(&vfs_not_implemented_fns, "vfs_not_implemented");
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "vfs_not_implemented",
				&vfs_not_implemented_fns);
}
