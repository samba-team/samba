/* 
 * Skeleton VFS module.  Implements passthrough operation of all VFS
 * calls to disk functions.
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
 * please make sure that you remove all skel_XXX() functions you don't
 * want to implement!! The passthrough operations are not
 * necessary in a real module.
 *
 * --metze
 */

static int skel_connect(vfs_handle_struct *handle, const char *service,
			const char *user)
{
	return SMB_VFS_NEXT_CONNECT(handle, service, user);
}

static void skel_disconnect(vfs_handle_struct *handle)
{
	SMB_VFS_NEXT_DISCONNECT(handle);
}

static uint64_t skel_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
}

static int skel_get_quota(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *dq)
{
	return SMB_VFS_NEXT_GET_QUOTA(handle, smb_fname, qtype, id, dq);
}

static int skel_set_quota(vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype,
			  unid_t id, SMB_DISK_QUOTA *dq)
{
	return SMB_VFS_NEXT_SET_QUOTA(handle, qtype, id, dq);
}

static int skel_get_shadow_copy_data(vfs_handle_struct *handle,
				     files_struct *fsp,
				     struct shadow_copy_data *shadow_copy_data,
				     bool labels)
{
	return SMB_VFS_NEXT_GET_SHADOW_COPY_DATA(handle, fsp, shadow_copy_data,
						 labels);
}

static int skel_statvfs(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			struct vfs_statvfs_struct *statbuf)
{
	return SMB_VFS_NEXT_STATVFS(handle, smb_fname, statbuf);
}

static uint32_t skel_fs_capabilities(struct vfs_handle_struct *handle,
				     enum timestamp_set_resolution *p_ts_res)
{
	return SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res);
}

static NTSTATUS skel_get_dfs_referrals(struct vfs_handle_struct *handle,
				       struct dfs_GetDFSReferral *r)
{
	return SMB_VFS_NEXT_GET_DFS_REFERRALS(handle, r);
}

static NTSTATUS skel_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	return SMB_VFS_NEXT_CREATE_DFS_PATHAT(handle,
					dirfsp,
					smb_fname,
					reflist,
					referral_count);
}

static NTSTATUS skel_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
	return SMB_VFS_NEXT_READ_DFS_PATHAT(handle,
					mem_ctx,
					dirfsp,
					smb_fname,
					ppreflist,
					preferral_count);
}

static NTSTATUS skel_snap_check_path(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     const char *service_path,
				     char **base_volume)
{
	return SMB_VFS_NEXT_SNAP_CHECK_PATH(handle, mem_ctx, service_path,
					    base_volume);
}

static NTSTATUS skel_snap_create(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 const char *base_volume,
				 time_t *tstamp,
				 bool rw,
				 char **base_path,
				 char **snap_path)
{
	return SMB_VFS_NEXT_SNAP_CREATE(handle, mem_ctx, base_volume, tstamp,
					rw, base_path, snap_path);
}

static NTSTATUS skel_snap_delete(struct vfs_handle_struct *handle,
				 TALLOC_CTX *mem_ctx,
				 char *base_path,
				 char *snap_path)
{
	return SMB_VFS_NEXT_SNAP_DELETE(handle, mem_ctx, base_path, snap_path);
}

static DIR *skel_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
			   const char *mask, uint32_t attr)
{
	return SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);
}

static struct dirent *skel_readdir(vfs_handle_struct *handle,
				   DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_READDIR(handle, dirp, sbuf);
}

static void skel_seekdir(vfs_handle_struct *handle, DIR *dirp, long offset)
{
	SMB_VFS_NEXT_SEEKDIR(handle, dirp, offset);
}

static long skel_telldir(vfs_handle_struct *handle, DIR *dirp)
{
	return SMB_VFS_NEXT_TELLDIR(handle, dirp);
}

static void skel_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
	SMB_VFS_NEXT_REWINDDIR(handle, dirp);
}

static int skel_mkdirat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	return SMB_VFS_NEXT_MKDIRAT(handle,
			dirfsp,
			smb_fname,
			mode);
}

static int skel_closedir(vfs_handle_struct *handle, DIR *dir)
{
	return SMB_VFS_NEXT_CLOSEDIR(handle, dir);
}

static int skel_openat(struct vfs_handle_struct *handle,
		       const struct files_struct *dirfsp,
		       const struct smb_filename *smb_fname,
		       struct files_struct *fsp,
		       int flags,
		       mode_t mode)
{
	return SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, flags, mode);
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
				 files_struct ** result, int *pinfo,
				 const struct smb2_create_blobs *in_context_blobs,
				 struct smb2_create_blobs *out_context_blobs)
{
	return SMB_VFS_NEXT_CREATE_FILE(handle,
					req,
					dirfsp,
					smb_fname,
					access_mask,
					share_access,
					create_disposition,
					create_options,
					file_attributes,
					oplock_request,
					lease,
					allocation_size,
					private_flags,
					sd, ea_list, result, pinfo,
					in_context_blobs, out_context_blobs);
}

static int skel_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
	return SMB_VFS_NEXT_CLOSE(handle, fsp);
}

static ssize_t skel_pread(vfs_handle_struct *handle, files_struct *fsp,
			  void *data, size_t n, off_t offset)
{
	return SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
}

struct skel_pread_state {
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void skel_pread_done(struct tevent_req *subreq);

static struct tevent_req *skel_pread_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp,
					  void *data, size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct skel_pread_state *state;

	req = tevent_req_create(mem_ctx, &state, struct skel_pread_state);
	if (req == NULL) {
		return NULL;
	}
	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data,
					 n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, skel_pread_done, req);
	return req;
}

static void skel_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
	    tevent_req_callback_data(subreq, struct tevent_req);
	struct skel_pread_state *state =
	    tevent_req_data(req, struct skel_pread_state);

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t skel_pread_recv(struct tevent_req *req,
			       struct vfs_aio_state *vfs_aio_state)
{
	struct skel_pread_state *state =
	    tevent_req_data(req, struct skel_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static ssize_t skel_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			   const void *data, size_t n, off_t offset)
{
	return SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
}

struct skel_pwrite_state {
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void skel_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *skel_pwrite_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   const void *data,
					   size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct skel_pwrite_state *state;

	req = tevent_req_create(mem_ctx, &state, struct skel_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data,
					  n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, skel_pwrite_done, req);
	return req;
}

static void skel_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
	    tevent_req_callback_data(subreq, struct tevent_req);
	struct skel_pwrite_state *state =
	    tevent_req_data(req, struct skel_pwrite_state);

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t skel_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct skel_pwrite_state *state =
	    tevent_req_data(req, struct skel_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static off_t skel_lseek(vfs_handle_struct *handle, files_struct *fsp,
			off_t offset, int whence)
{
	return SMB_VFS_NEXT_LSEEK(handle, fsp, offset, whence);
}

static ssize_t skel_sendfile(vfs_handle_struct *handle, int tofd,
			     files_struct *fromfsp, const DATA_BLOB *hdr,
			     off_t offset, size_t n)
{
	return SMB_VFS_NEXT_SENDFILE(handle, tofd, fromfsp, hdr, offset, n);
}

static ssize_t skel_recvfile(vfs_handle_struct *handle, int fromfd,
			     files_struct *tofsp, off_t offset, size_t n)
{
	return SMB_VFS_NEXT_RECVFILE(handle, fromfd, tofsp, offset, n);
}

static int skel_renameat(vfs_handle_struct *handle,
		       files_struct *srcfsp,
		       const struct smb_filename *smb_fname_src,
		       files_struct *dstfsp,
		       const struct smb_filename *smb_fname_dst)
{
	return SMB_VFS_NEXT_RENAMEAT(handle,
			srcfsp,
			smb_fname_src,
			dstfsp,
			smb_fname_dst);
}

struct skel_fsync_state {
	int ret;
	struct vfs_aio_state vfs_aio_state;
};

static void skel_fsync_done(struct tevent_req *subreq);

static struct tevent_req *skel_fsync_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp)
{
	struct tevent_req *req, *subreq;
	struct skel_fsync_state *state;

	req = tevent_req_create(mem_ctx, &state, struct skel_fsync_state);
	if (req == NULL) {
		return NULL;
	}
	subreq = SMB_VFS_NEXT_FSYNC_SEND(state, ev, handle, fsp);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, skel_fsync_done, req);
	return req;
}

static void skel_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
	    tevent_req_callback_data(subreq, struct tevent_req);
	struct skel_fsync_state *state =
	    tevent_req_data(req, struct skel_fsync_state);

	state->ret = SMB_VFS_FSYNC_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static int skel_fsync_recv(struct tevent_req *req,
			   struct vfs_aio_state *vfs_aio_state)
{
	struct skel_fsync_state *state =
	    tevent_req_data(req, struct skel_fsync_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static int skel_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_STAT(handle, smb_fname);
}

static int skel_fstat(vfs_handle_struct *handle, files_struct *fsp,
		      SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
}

static int skel_lstat(vfs_handle_struct *handle,
		      struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
}

static uint64_t skel_get_alloc_size(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    const SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_GET_ALLOC_SIZE(handle, fsp, sbuf);
}

static int skel_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	return SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp,
			smb_fname,
			flags);
}

static int skel_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	return SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
}

static int skel_fchmod(vfs_handle_struct *handle, files_struct *fsp,
		       mode_t mode)
{
	return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
}

static int skel_fchown(vfs_handle_struct *handle, files_struct *fsp,
		       uid_t uid, gid_t gid)
{
	return SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);
}

static int skel_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	return SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);
}

static int skel_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_CHDIR(handle, smb_fname);
}

static struct smb_filename *skel_getwd(vfs_handle_struct *handle,
					TALLOC_CTX *ctx)
{
	return SMB_VFS_NEXT_GETWD(handle, ctx);
}

static int skel_ntimes(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       struct smb_file_time *ft)
{
	return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
}

static int skel_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
			  off_t offset)
{
	return SMB_VFS_NEXT_FTRUNCATE(handle, fsp, offset);
}

static int skel_fallocate(vfs_handle_struct *handle, files_struct *fsp,
			  uint32_t mode, off_t offset, off_t len)
{
	return SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
}

static bool skel_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
		      off_t offset, off_t count, int type)
{
	return SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type);
}

static int skel_kernel_flock(struct vfs_handle_struct *handle,
			     struct files_struct *fsp, uint32_t share_mode,
			     uint32_t access_mask)
{
	return SMB_VFS_NEXT_KERNEL_FLOCK(handle, fsp, share_mode, access_mask);
}

static int skel_fcntl(struct vfs_handle_struct *handle,
		      struct files_struct *fsp, int cmd, va_list cmd_arg)
{
	void *arg;
	va_list dup_cmd_arg;
	int result;

	va_copy(dup_cmd_arg, cmd_arg);
	arg = va_arg(dup_cmd_arg, void *);
	result = SMB_VFS_NEXT_FCNTL(handle, fsp, cmd, arg);
	va_end(dup_cmd_arg);

	return result;
}

static int skel_linux_setlease(struct vfs_handle_struct *handle,
			       struct files_struct *fsp, int leasetype)
{
	return SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype);
}

static bool skel_getlock(vfs_handle_struct *handle, files_struct *fsp,
			 off_t *poffset, off_t *pcount, int *ptype,
			 pid_t *ppid)
{
	return SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset, pcount, ptype, ppid);
}

static int skel_symlinkat(vfs_handle_struct *handle,
			const struct smb_filename *link_contents,
			struct files_struct *dirfsp,
			const struct smb_filename *new_smb_fname)
{
	return SMB_VFS_NEXT_SYMLINKAT(handle,
				link_contents,
				dirfsp,
				new_smb_fname);
}

static int skel_vfs_readlinkat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	return SMB_VFS_NEXT_READLINKAT(handle,
			dirfsp,
			smb_fname,
			buf,
			bufsiz);
}

static int skel_linkat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags)
{
	return SMB_VFS_NEXT_LINKAT(handle,
			srcfsp,
			old_smb_fname,
			dstfsp,
			new_smb_fname,
			flags);
}

static int skel_mknodat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	return SMB_VFS_NEXT_MKNODAT(handle,
			dirfsp,
			smb_fname,
			mode,
			dev);
}

static struct smb_filename *skel_realpath(vfs_handle_struct *handle,
			TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);
}

static int skel_chflags(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uint flags)
{
	return SMB_VFS_NEXT_CHFLAGS(handle, smb_fname, flags);
}

static struct file_id skel_file_id_create(vfs_handle_struct *handle,
					  const SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_FILE_ID_CREATE(handle, sbuf);
}

static uint64_t skel_fs_file_id(vfs_handle_struct *handle,
				const SMB_STRUCT_STAT *sbuf)
{
	return SMB_VFS_NEXT_FS_FILE_ID(handle, sbuf);
}

struct skel_offload_read_state {
	struct vfs_handle_struct *handle;
	DATA_BLOB token;
};

static void skel_offload_read_done(struct tevent_req *subreq);

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
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state, struct skel_offload_read_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct skel_offload_read_state) {
		.handle = handle,
	};

	subreq = SMB_VFS_NEXT_OFFLOAD_READ_SEND(mem_ctx, ev, handle, fsp,
						fsctl, ttl, offset, to_copy);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, skel_offload_read_done, req);
	return req;
}

static void skel_offload_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct skel_offload_read_state *state = tevent_req_data(
		req, struct skel_offload_read_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_OFFLOAD_READ_RECV(subreq,
						state->handle,
						state,
						&state->token);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
}

static NTSTATUS skel_offload_read_recv(struct tevent_req *req,
				       struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       DATA_BLOB *_token)
{
	struct skel_offload_read_state *state = tevent_req_data(
		req, struct skel_offload_read_state);
	DATA_BLOB token;
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	token = data_blob_talloc(mem_ctx,
				 state->token.data,
				 state->token.length);

	tevent_req_received(req);

	if (token.data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	*_token = token;
	return NT_STATUS_OK;
}

struct skel_offload_write_state {
	struct vfs_handle_struct *handle;
	off_t copied;
};
static void skel_offload_write_done(struct tevent_req *subreq);

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
	struct tevent_req *subreq;
	struct skel_offload_write_state *state;

	req = tevent_req_create(mem_ctx, &state, struct skel_offload_write_state);
	if (req == NULL) {
		return NULL;
	}

	state->handle = handle;
	subreq = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle, state, ev,
					      fsctl, token, transfer_offset,
					      dest_fsp, dest_off, num);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, skel_offload_write_done, req);
	return req;
}

static void skel_offload_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct skel_offload_write_state *state
			= tevent_req_data(req, struct skel_offload_write_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_OFFLOAD_WRITE_RECV(state->handle,
					      subreq,
					      &state->copied);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS skel_offload_write_recv(struct vfs_handle_struct *handle,
				     struct tevent_req *req,
				     off_t *copied)
{
	struct skel_offload_write_state *state
			= tevent_req_data(req, struct skel_offload_write_state);
	NTSTATUS status;

	*copied = state->copied;
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
	return SMB_VFS_NEXT_GET_COMPRESSION(handle, mem_ctx, fsp, smb_fname,
					    _compression_fmt);
}

static NTSTATUS skel_set_compression(struct vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct files_struct *fsp,
				     uint16_t compression_fmt)
{
	return SMB_VFS_NEXT_SET_COMPRESSION(handle, mem_ctx, fsp,
					    compression_fmt);
}

static NTSTATUS skel_streaminfo(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				unsigned int *num_streams,
				struct stream_struct **streams)
{
	return SMB_VFS_NEXT_STREAMINFO(handle,
				fsp,
				smb_fname,
				mem_ctx,
				num_streams,
				streams);
}

static int skel_get_real_filename(struct vfs_handle_struct *handle,
				  const struct smb_filename *path,
				  const char *name,
				  TALLOC_CTX *mem_ctx, char **found_name)
{
	return SMB_VFS_NEXT_GET_REAL_FILENAME(handle,
					      path, name, mem_ctx, found_name);
}

static const char *skel_connectpath(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_CONNECTPATH(handle, smb_fname);
}

static NTSTATUS skel_brl_lock_windows(struct vfs_handle_struct *handle,
				      struct byte_range_lock *br_lck,
				      struct lock_struct *plock)
{
	return SMB_VFS_NEXT_BRL_LOCK_WINDOWS(handle, br_lck, plock);
}

static bool skel_brl_unlock_windows(struct vfs_handle_struct *handle,
				    struct byte_range_lock *br_lck,
				    const struct lock_struct *plock)
{
	return SMB_VFS_NEXT_BRL_UNLOCK_WINDOWS(handle, br_lck, plock);
}

static bool skel_strict_lock_check(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   struct lock_struct *plock)
{
	return SMB_VFS_NEXT_STRICT_LOCK_CHECK(handle, fsp, plock);
}

static NTSTATUS skel_translate_name(struct vfs_handle_struct *handle,
				    const char *mapped_name,
				    enum vfs_translate_direction direction,
				    TALLOC_CTX *mem_ctx, char **pmapped_name)
{
	return SMB_VFS_NEXT_TRANSLATE_NAME(handle, mapped_name, direction,
					   mem_ctx, pmapped_name);
}

static NTSTATUS skel_fsctl(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   TALLOC_CTX *ctx,
			   uint32_t function,
			   uint16_t req_flags,	/* Needed for UNICODE ... */
			   const uint8_t *_in_data,
			   uint32_t in_len,
			   uint8_t ** _out_data,
			   uint32_t max_out_len, uint32_t *out_len)
{
	return SMB_VFS_NEXT_FSCTL(handle,
				  fsp,
				  ctx,
				  function,
				  req_flags,
				  _in_data,
				  in_len, _out_data, max_out_len, out_len);
}

static NTSTATUS skel_readdir_attr(struct vfs_handle_struct *handle,
				  const struct smb_filename *fname,
				  TALLOC_CTX *mem_ctx,
				  struct readdir_attr_data **pattr_data)
{
	return SMB_VFS_NEXT_READDIR_ATTR(handle, fname, mem_ctx, pattr_data);
}

static NTSTATUS skel_get_dos_attributes(struct vfs_handle_struct *handle,
				struct smb_filename *smb_fname,
				uint32_t *dosmode)
{
	return SMB_VFS_NEXT_GET_DOS_ATTRIBUTES(handle,
				smb_fname,
				dosmode);
}

struct skel_get_dos_attributes_state {
	struct vfs_aio_state aio_state;
	uint32_t dosmode;
};

static void skel_get_dos_attributes_done(struct tevent_req *subreq);

static struct tevent_req *skel_get_dos_attributes_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			struct smb_filename *smb_fname)
{
	struct tevent_req *req = NULL;
	struct skel_get_dos_attributes_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct skel_get_dos_attributes_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = SMB_VFS_NEXT_GET_DOS_ATTRIBUTES_SEND(mem_ctx,
						      ev,
						      handle,
						      dir_fsp,
						      smb_fname);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, skel_get_dos_attributes_done, req);

	return req;
}

static void skel_get_dos_attributes_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct skel_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct skel_get_dos_attributes_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_GET_DOS_ATTRIBUTES_RECV(subreq,
						      &state->aio_state,
						      &state->dosmode);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
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
	return SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle,
				fsp,
				dosmode);
}

static NTSTATUS skel_set_dos_attributes(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t dosmode)
{
	return SMB_VFS_NEXT_SET_DOS_ATTRIBUTES(handle,
				smb_fname,
				dosmode);
}

static NTSTATUS skel_fset_dos_attributes(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t dosmode)
{
	return SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle,
				fsp,
				dosmode);
}

static NTSTATUS skel_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info,
				 TALLOC_CTX *mem_ctx,
				 struct security_descriptor **ppdesc)
{
	return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info, mem_ctx,
					ppdesc);
}

static NTSTATUS skel_get_nt_acl_at(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	return SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
				dirfsp,
				smb_fname,
				security_info,
				mem_ctx,
				ppdesc);
}

static NTSTATUS skel_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32_t security_info_sent,
				 const struct security_descriptor *psd)
{
	return SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
}

static SMB_ACL_T skel_sys_acl_get_file(vfs_handle_struct *handle,
				       const struct smb_filename *smb_fname,
				       SMB_ACL_TYPE_T type,
				       TALLOC_CTX *mem_ctx)
{
	return SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, smb_fname, type, mem_ctx);
}

static SMB_ACL_T skel_sys_acl_get_fd(vfs_handle_struct *handle,
				     files_struct *fsp, TALLOC_CTX *mem_ctx)
{
	return SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, mem_ctx);
}

static int skel_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob)
{
	return SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle, smb_fname, mem_ctx,
						  blob_description, blob);
}

static int skel_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				    files_struct *fsp, TALLOC_CTX *mem_ctx,
				    char **blob_description, DATA_BLOB *blob)
{
	return SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx,
						blob_description, blob);
}

static int skel_sys_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl)
{
	return SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, smb_fname,
			acltype, theacl);
}

static int skel_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
			       SMB_ACL_T theacl)
{
	return SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl);
}

static int skel_sys_acl_delete_def_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname)
{
	return SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, smb_fname);
}

static ssize_t skel_getxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)
{
	return SMB_VFS_NEXT_GETXATTR(handle, smb_fname, name, value, size);
}

struct skel_getxattrat_state {
	struct vfs_aio_state aio_state;
	ssize_t xattr_size;
	uint8_t *xattr_value;
};

static void skel_getxattrat_done(struct tevent_req *subreq);

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
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct skel_getxattrat_state);
	if (req == NULL) {
		return NULL;
	}

	subreq = SMB_VFS_NEXT_GETXATTRAT_SEND(state,
					      ev,
					      handle,
					      dir_fsp,
					      smb_fname,
					      xattr_name,
					      alloc_hint);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, skel_getxattrat_done, req);

	return req;
}

static void skel_getxattrat_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct skel_getxattrat_state *state = tevent_req_data(
		req, struct skel_getxattrat_state);

	state->xattr_size = SMB_VFS_NEXT_GETXATTRAT_RECV(subreq,
							 &state->aio_state,
							 state,
							 &state->xattr_value);
	TALLOC_FREE(subreq);
	if (state->xattr_size == -1) {
		tevent_req_error(req, state->aio_state.error);
		return;
	}

	tevent_req_done(req);
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
	return SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, value, size);
}

static ssize_t skel_listxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *list,
				size_t size)
{
	return SMB_VFS_NEXT_LISTXATTR(handle, smb_fname, list, size);
}

static ssize_t skel_flistxattr(vfs_handle_struct *handle,
			       struct files_struct *fsp, char *list,
			       size_t size)
{
	return SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);
}

static int skel_removexattr(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name)
{
	return SMB_VFS_NEXT_REMOVEXATTR(handle, smb_fname, name);
}

static int skel_fremovexattr(vfs_handle_struct *handle,
			     struct files_struct *fsp, const char *name)
{
	return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
}

static int skel_setxattr(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name,
			const void *value,
			size_t size,
			int flags)
{
	return SMB_VFS_NEXT_SETXATTR(handle, smb_fname,
			name, value, size, flags);
}

static int skel_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	return SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value, size, flags);
}

static bool skel_aio_force(struct vfs_handle_struct *handle,
			   struct files_struct *fsp)
{
	return SMB_VFS_NEXT_AIO_FORCE(handle, fsp);
}

static NTSTATUS skel_audit_file(struct vfs_handle_struct *handle,
				struct smb_filename *file,
				struct security_acl *sacl,
				uint32_t access_requested,
				uint32_t access_denied)
{
	return SMB_VFS_NEXT_AUDIT_FILE(handle,
				       file,
				       sacl,
				       access_requested,
				       access_denied);
}

static NTSTATUS skel_durable_cookie(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    TALLOC_CTX *mem_ctx,
				    DATA_BLOB *cookie)
{
	return SMB_VFS_NEXT_DURABLE_COOKIE(handle,
					   fsp,
					   mem_ctx,
					   cookie);
}

static NTSTATUS skel_durable_disconnect(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					const DATA_BLOB old_cookie,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *new_cookie)
{
	return SMB_VFS_NEXT_DURABLE_DISCONNECT(handle,
					       fsp,
					       old_cookie,
					       mem_ctx,
					       new_cookie);
}

static NTSTATUS skel_durable_reconnect(struct vfs_handle_struct *handle,
				       struct smb_request *smb1req,
				       struct smbXsrv_open *op,
				       const DATA_BLOB old_cookie,
				       TALLOC_CTX *mem_ctx,
				       struct files_struct **fsp,
				       DATA_BLOB *new_cookie)
{
	return SMB_VFS_NEXT_DURABLE_RECONNECT(handle,
					      smb1req,
					      op,
					      old_cookie,
					      mem_ctx,
					      fsp,
					      new_cookie);
}

/* VFS operations structure */

static struct vfs_fn_pointers skel_transparent_fns = {
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
NTSTATUS vfs_skel_transparent_init(TALLOC_CTX *ctx)
{
	/*
	 * smb_vfs_assert_all_fns() is only needed in
	 * order to have a complete example.
	 *
	 * A transparent vfs module typically don't
	 * need to implement every calls.
	 */
	smb_vfs_assert_all_fns(&skel_transparent_fns, "skel_transparent");
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "skel_transparent",
				&skel_transparent_fns);
}
