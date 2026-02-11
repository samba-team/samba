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

_PUBLIC_
int vfs_not_implemented_connect(
			vfs_handle_struct *handle,
			const char *service,
			const char *user)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
void vfs_not_implemented_disconnect(vfs_handle_struct *handle)
{
	;
}

_PUBLIC_
uint64_t vfs_not_implemented_disk_free(vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       uint64_t *bsize,
				       uint64_t *dfree,
				       uint64_t *dsize)
{
	*bsize = 0;
	*dfree = 0;
	*dsize = 0;
	return 0;
}

_PUBLIC_
int vfs_not_implemented_get_quota(vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  enum SMB_QUOTA_TYPE qtype,
				  unid_t id,
				  SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_set_quota(vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  enum SMB_QUOTA_TYPE qtype,
				  unid_t id,
				  SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_get_shadow_copy_data(vfs_handle_struct *handle,
				files_struct *fsp,
				struct shadow_copy_data *shadow_copy_data,
				bool labels)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_fstatvfs(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 struct vfs_statvfs_struct *statbuf)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
uint32_t vfs_not_implemented_fs_capabilities(struct vfs_handle_struct *handle,
				enum timestamp_set_resolution *p_ts_res)
{
	return 0;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_get_dfs_referrals(struct vfs_handle_struct *handle,
					       struct dfs_GetDFSReferral *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_snap_check_path(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				const char *service_path,
				char **base_volume)
{
	return NT_STATUS_NOT_SUPPORTED;
}

_PUBLIC_
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

_PUBLIC_
NTSTATUS vfs_not_implemented_snap_delete(struct vfs_handle_struct *handle,
					 TALLOC_CTX *mem_ctx,
					 char *base_path,
					 char *snap_path)
{
	return NT_STATUS_NOT_SUPPORTED;
}

_PUBLIC_
DIR *vfs_not_implemented_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
				   const char *mask, uint32_t attr)
{
	errno = ENOSYS;
	return NULL;
}

_PUBLIC_
struct dirent *vfs_not_implemented_readdir(vfs_handle_struct *handle,
					   struct files_struct *dirfsp,
					   DIR *dirp)
{
	errno = ENOSYS;
	return NULL;
}

_PUBLIC_
void vfs_not_implemented_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
	;
}

_PUBLIC_
int vfs_not_implemented_mkdirat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_closedir(vfs_handle_struct *handle, DIR *dir)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_openat(vfs_handle_struct *handle,
			       const struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname,
			       struct files_struct *fsp,
			       const struct vfs_open_how *how)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_create_file(struct vfs_handle_struct *handle,
				struct smb_request *req,
				struct files_struct *dirsp,
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

_PUBLIC_
int vfs_not_implemented_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
ssize_t vfs_not_implemented_pread(vfs_handle_struct *handle, files_struct *fsp,
				  void *data, size_t n, off_t offset)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
struct tevent_req *vfs_not_implemented_pread_send(struct vfs_handle_struct *handle,
						  TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct files_struct *fsp,
						  void *data, size_t n, off_t offset)
{
	return NULL;
}

_PUBLIC_
ssize_t vfs_not_implemented_pread_recv(struct tevent_req *req,
				       struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

_PUBLIC_
ssize_t vfs_not_implemented_pwrite(vfs_handle_struct *handle, files_struct *fsp,
				   const void *data, size_t n, off_t offset)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
struct tevent_req *vfs_not_implemented_pwrite_send(struct vfs_handle_struct *handle,
						   TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct files_struct *fsp,
						   const void *data,
						   size_t n, off_t offset)
{
	return NULL;
}

_PUBLIC_
ssize_t vfs_not_implemented_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

_PUBLIC_
off_t vfs_not_implemented_lseek(vfs_handle_struct *handle, files_struct *fsp,
			off_t offset, int whence)
{
	errno = ENOSYS;
	return (off_t) - 1;
}

_PUBLIC_
ssize_t vfs_not_implemented_sendfile(vfs_handle_struct *handle, int tofd,
				     files_struct *fromfsp, const DATA_BLOB *hdr,
				     off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
ssize_t vfs_not_implemented_recvfile(vfs_handle_struct *handle, int fromfd,
				     files_struct *tofsp, off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_renameat(vfs_handle_struct *handle,
				 files_struct *src_dirfsp,
				 const struct smb_filename *smb_fname_src,
				 files_struct *dst_dirfsp,
				 const struct smb_filename *smb_fname_dst,
				 const struct vfs_rename_how *how)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_rename_stream(struct vfs_handle_struct *handle,
				      struct files_struct *src_fsp,
				      const char *dst_name,
				      bool replace_if_exists)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
struct tevent_req *vfs_not_implemented_fsync_send(struct vfs_handle_struct *handle,
						  TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct files_struct *fsp)
{
	return NULL;
}

_PUBLIC_
int vfs_not_implemented_fsync_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	vfs_aio_state->error = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_fstat(vfs_handle_struct *handle, files_struct *fsp,
			SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_lstat(vfs_handle_struct *handle,
			      struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_fstatat(
	struct vfs_handle_struct *handle,
	const struct files_struct *dirfsp,
	const struct smb_filename *smb_fname,
	SMB_STRUCT_STAT *sbuf,
	int flags)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
uint64_t vfs_not_implemented_get_alloc_size(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    const SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_fchmod(vfs_handle_struct *handle, files_struct *fsp,
			       mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_fchown(vfs_handle_struct *handle, files_struct *fsp,
			       uid_t uid, gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_lchown(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname,
			       uid_t uid,
			       gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_chdir(vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
struct smb_filename *vfs_not_implemented_getwd(vfs_handle_struct *handle,
					       TALLOC_CTX *ctx)
{
	errno = ENOSYS;
	return NULL;
}

_PUBLIC_
int vfs_not_implemented_fntimes(vfs_handle_struct *handle,
				files_struct *fsp,
				struct smb_file_time *ft)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
				  off_t offset)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_fallocate(vfs_handle_struct *handle, files_struct *fsp,
				  uint32_t mode, off_t offset, off_t len)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
bool vfs_not_implemented_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
			      off_t offset, off_t count, int type)
{
	errno = ENOSYS;
	return false;
}

_PUBLIC_
int vfs_not_implemented_filesystem_sharemode(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     uint32_t share_access,
					     uint32_t access_mask)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_fcntl(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, int cmd,
			      va_list cmd_arg)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_linux_setlease(struct vfs_handle_struct *handle,
				       struct files_struct *fsp, int leasetype)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
bool vfs_not_implemented_getlock(vfs_handle_struct *handle, files_struct *fsp,
				 off_t *poffset, off_t *pcount, int *ptype,
				 pid_t *ppid)
{
	errno = ENOSYS;
	return false;
}

_PUBLIC_
int vfs_not_implemented_symlinkat(vfs_handle_struct *handle,
				const struct smb_filename *link_contents,
				struct files_struct *dirfsp,
				const struct smb_filename *new_smb_fname)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_vfs_readlinkat(vfs_handle_struct *handle,
			const struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_linkat(vfs_handle_struct *handle,
			       files_struct *src_dirfsp,
			       const struct smb_filename *old_smb_fname,
			       files_struct *dst_dirfsp,
			       const struct smb_filename *new_smb_fname,
			       int flags)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_mknodat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
struct smb_filename *vfs_not_implemented_realpath(vfs_handle_struct *handle,
						  TALLOC_CTX *ctx,
						  const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return NULL;
}

_PUBLIC_
int vfs_not_implemented_fchflags(vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint flags)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
struct file_id vfs_not_implemented_file_id_create(vfs_handle_struct *handle,
						  const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id;
	ZERO_STRUCT(id);
	errno = ENOSYS;
	return id;
}

_PUBLIC_
uint64_t vfs_not_implemented_fs_file_id(vfs_handle_struct *handle,
					const SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return 0;
}

struct vfs_not_implemented_offload_read_state {
	bool dummy;
};

_PUBLIC_
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

_PUBLIC_
NTSTATUS vfs_not_implemented_offload_read_recv(struct tevent_req *req,
				       struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       uint32_t *flags,
				       uint64_t *xferlen,
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

_PUBLIC_
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

_PUBLIC_
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

_PUBLIC_
NTSTATUS vfs_not_implemented_fget_compression(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct files_struct *fsp,
					     uint16_t *_compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_set_compression(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct files_struct *fsp,
					     uint16_t compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_fstreaminfo(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					TALLOC_CTX *mem_ctx,
					unsigned int *num_streams,
					struct stream_struct **streams)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_get_real_filename_at(
	struct vfs_handle_struct *handle,
	struct files_struct *dirfsp,
	const char *name,
	TALLOC_CTX *mem_ctx,
	char **found_name)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_brl_lock_windows(struct vfs_handle_struct *handle,
					      struct byte_range_lock *br_lck,
					      struct lock_struct *plock)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
bool vfs_not_implemented_brl_unlock_windows(struct vfs_handle_struct *handle,
					    struct byte_range_lock *br_lck,
					    const struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

_PUBLIC_
bool vfs_not_implemented_strict_lock_check(struct vfs_handle_struct *handle,
					   struct files_struct *fsp,
					   struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_translate_name(struct vfs_handle_struct *handle,
					    const char *mapped_name,
					    enum vfs_translate_direction direction,
					    TALLOC_CTX *mem_ctx, char **pmapped_name)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_parent_pathname(struct vfs_handle_struct *handle,
						    TALLOC_CTX *mem_ctx,
						    const struct smb_filename *smb_fname_in,
						    struct smb_filename **parent_dir_out,
						    struct smb_filename **atname_out)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
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

_PUBLIC_
NTSTATUS vfs_not_implemented_freaddir_attr(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					TALLOC_CTX *mem_ctx,
					struct readdir_attr_data **pattr_data)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

struct vfs_not_implemented_get_dos_attributes_state {
	struct vfs_aio_state aio_state;
	uint32_t dosmode;
};

_PUBLIC_
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

_PUBLIC_
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

_PUBLIC_
NTSTATUS vfs_not_implemented_fget_dos_attributes(struct vfs_handle_struct *handle,
						 struct files_struct *fsp,
						 uint32_t *dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_fset_dos_attributes(struct vfs_handle_struct *handle,
						 struct files_struct *fsp,
						 uint32_t dosmode)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
					 uint32_t security_info,
					 TALLOC_CTX *mem_ctx,
					 struct security_descriptor **ppdesc)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
					 uint32_t security_info_sent,
					 const struct security_descriptor *psd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
SMB_ACL_T vfs_not_implemented_sys_acl_get_fd(vfs_handle_struct *handle,
					     files_struct *fsp,
					     SMB_ACL_TYPE_T type,
					     TALLOC_CTX *mem_ctx)
{
	errno = ENOSYS;
	return (SMB_ACL_T) NULL;
}

_PUBLIC_
int vfs_not_implemented_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				files_struct *fsp, TALLOC_CTX *mem_ctx,
				char **blob_description, DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_sys_acl_set_fd(vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       SMB_ACL_TYPE_T type,
				       SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_sys_acl_delete_def_fd(vfs_handle_struct *handle,
					struct files_struct *fsp)
{
	errno = ENOSYS;
	return -1;
}

struct vfs_not_implemented_getxattrat_state {
	struct vfs_aio_state aio_state;
	ssize_t xattr_size;
	uint8_t *xattr_value;
};

_PUBLIC_
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

_PUBLIC_
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

_PUBLIC_
ssize_t vfs_not_implemented_fgetxattr(vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name,
			      void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
ssize_t vfs_not_implemented_flistxattr(vfs_handle_struct *handle,
				       struct files_struct *fsp, char *list,
				       size_t size)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_fremovexattr(vfs_handle_struct *handle,
				     struct files_struct *fsp, const char *name)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
int vfs_not_implemented_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
				  const char *name, const void *value, size_t size,
				  int flags)
{
	errno = ENOSYS;
	return -1;
}

_PUBLIC_
bool vfs_not_implemented_aio_force(struct vfs_handle_struct *handle,
				   struct files_struct *fsp)
{
	errno = ENOSYS;
	return false;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_durable_cookie(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    TALLOC_CTX *mem_ctx,
					    DATA_BLOB *cookie)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
NTSTATUS vfs_not_implemented_durable_disconnect(struct vfs_handle_struct *handle,
						struct files_struct *fsp,
						const DATA_BLOB old_cookie,
						TALLOC_CTX *mem_ctx,
						DATA_BLOB *new_cookie)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

_PUBLIC_
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
	.fstatvfs_fn = vfs_not_implemented_fstatvfs,
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
	.rename_stream_fn = vfs_not_implemented_rename_stream,
	.fsync_send_fn = vfs_not_implemented_fsync_send,
	.fsync_recv_fn = vfs_not_implemented_fsync_recv,
	.stat_fn = vfs_not_implemented_stat,
	.fstat_fn = vfs_not_implemented_fstat,
	.lstat_fn = vfs_not_implemented_lstat,
	.fstatat_fn = vfs_not_implemented_fstatat,
	.get_alloc_size_fn = vfs_not_implemented_get_alloc_size,
	.unlinkat_fn = vfs_not_implemented_unlinkat,
	.fchmod_fn = vfs_not_implemented_fchmod,
	.fchown_fn = vfs_not_implemented_fchown,
	.lchown_fn = vfs_not_implemented_lchown,
	.chdir_fn = vfs_not_implemented_chdir,
	.getwd_fn = vfs_not_implemented_getwd,
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
	.file_id_create_fn = vfs_not_implemented_file_id_create,
	.fs_file_id_fn = vfs_not_implemented_fs_file_id,
	.offload_read_send_fn = vfs_not_implemented_offload_read_send,
	.offload_read_recv_fn = vfs_not_implemented_offload_read_recv,
	.offload_write_send_fn = vfs_not_implemented_offload_write_send,
	.offload_write_recv_fn = vfs_not_implemented_offload_write_recv,
	.fget_compression_fn = vfs_not_implemented_fget_compression,
	.set_compression_fn = vfs_not_implemented_set_compression,

	.fstreaminfo_fn = vfs_not_implemented_fstreaminfo,
	.get_real_filename_at_fn = vfs_not_implemented_get_real_filename_at,
	.brl_lock_windows_fn = vfs_not_implemented_brl_lock_windows,
	.brl_unlock_windows_fn = vfs_not_implemented_brl_unlock_windows,
	.strict_lock_check_fn = vfs_not_implemented_strict_lock_check,
	.translate_name_fn = vfs_not_implemented_translate_name,
	.parent_pathname_fn = vfs_not_implemented_parent_pathname,
	.fsctl_fn = vfs_not_implemented_fsctl,
	.freaddir_attr_fn = vfs_not_implemented_freaddir_attr,

	/* DOS attributes. */
	.get_dos_attributes_send_fn = vfs_not_implemented_get_dos_attributes_send,
	.get_dos_attributes_recv_fn = vfs_not_implemented_get_dos_attributes_recv,
	.fget_dos_attributes_fn = vfs_not_implemented_fget_dos_attributes,
	.fset_dos_attributes_fn = vfs_not_implemented_fset_dos_attributes,

	/* NT ACL operations. */

	.fget_nt_acl_fn = vfs_not_implemented_fget_nt_acl,
	.fset_nt_acl_fn = vfs_not_implemented_fset_nt_acl,

	/* POSIX ACL operations. */

	.sys_acl_get_fd_fn = vfs_not_implemented_sys_acl_get_fd,
	.sys_acl_blob_get_fd_fn = vfs_not_implemented_sys_acl_blob_get_fd,
	.sys_acl_set_fd_fn = vfs_not_implemented_sys_acl_set_fd,
	.sys_acl_delete_def_fd_fn = vfs_not_implemented_sys_acl_delete_def_fd,

	/* EA operations. */
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = vfs_not_implemented_fgetxattr,
	.flistxattr_fn = vfs_not_implemented_flistxattr,
	.fremovexattr_fn = vfs_not_implemented_fremovexattr,
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
