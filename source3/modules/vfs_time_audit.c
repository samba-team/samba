/*
 * Time auditing VFS module for samba.  Log time taken for VFS call to syslog
 * facility.
 *
 * Copyright (C) Abhidnya Chirmule <achirmul@in.ibm.com> 2009
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
 * This module implements logging for time taken for all Samba VFS operations.
 *
 * vfs objects = time_audit
 */


#include "includes.h"
#include "smbd/smbd.h"
#include "ntioctl.h"
#include "lib/util/tevent_unix.h"
#include "lib/util/tevent_ntstatus.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static double audit_timeout;

static void smb_time_audit_log_msg(const char *syscallname, double elapsed,
				    const char *msg)
{
	DEBUG(0, ("WARNING: VFS call \"%s\" took unexpectedly long "
		  "(%.2f seconds) %s%s-- Validate that file and storage "
		  "subsystems are operating normally\n", syscallname,
		  elapsed, (msg != NULL) ? msg : "",
		  (msg != NULL) ? " " : ""));
}

static void smb_time_audit_log(const char *syscallname, double elapsed)
{
	smb_time_audit_log_msg(syscallname, elapsed, NULL);
}

static void smb_time_audit_log_fsp(const char *syscallname, double elapsed,
				   const struct files_struct *fsp)
{
	char *base_name = NULL;
	char *connectpath = NULL;
	char *msg = NULL;

	if (fsp == NULL) {
		smb_time_audit_log(syscallname, elapsed);
		return;
	}
	if (fsp->conn)
		connectpath = fsp->conn->connectpath;
	if (fsp->fsp_name)
		base_name = fsp->fsp_name->base_name;

	if (connectpath != NULL && base_name != NULL) {
		msg = talloc_asprintf(talloc_tos(), "filename = \"%s/%s\"",
				      connectpath, base_name);
	} else if (connectpath != NULL && base_name == NULL) {
		msg = talloc_asprintf(talloc_tos(), "connectpath = \"%s\", "
				      "base_name = <NULL>",
				      connectpath);
	} else if (connectpath == NULL && base_name != NULL) {
		msg = talloc_asprintf(talloc_tos(), "connectpath = <NULL>, "
				      "base_name = \"%s\"",
				      base_name);
	} else { /* connectpath == NULL && base_name == NULL */
		msg = talloc_asprintf(talloc_tos(), "connectpath = <NULL>, "
				      "base_name = <NULL>");
	}
	smb_time_audit_log_msg(syscallname, elapsed, msg);
	TALLOC_FREE(msg);
}

static void smb_time_audit_log_at(const char *syscallname,
				  double elapsed,
				  const struct files_struct *dir_fsp,
				  const struct smb_filename *smb_fname)
{
	char *msg = NULL;

	msg = talloc_asprintf(talloc_tos(),
			      "filename = \"%s/%s/%s\"",
			      dir_fsp->conn->connectpath,
			      dir_fsp->fsp_name->base_name,
			      smb_fname->base_name);

	smb_time_audit_log_msg(syscallname, elapsed, msg);
	TALLOC_FREE(msg);
}

static void smb_time_audit_log_fname(const char *syscallname, double elapsed,
				    const char *fname)
{
	char cwd[PATH_MAX];
	char *msg = NULL;

	if (getcwd(cwd, sizeof(cwd)) == NULL) {
		snprintf(cwd, sizeof(cwd), "<getcwd() error %d>", errno);
	}
	if (fname != NULL) {
		msg = talloc_asprintf(talloc_tos(),
				      "cwd = \"%s\", filename = \"%s\"",
				      cwd, fname);
	} else {
		msg = talloc_asprintf(talloc_tos(),
				      "cwd = \"%s\", filename = <NULL>",
				      cwd);
	}
	smb_time_audit_log_msg(syscallname, elapsed, msg);
	TALLOC_FREE(msg);
}

static void smb_time_audit_log_smb_fname(const char *syscallname, double elapsed,
				       const struct smb_filename *smb_fname)
{
	if (smb_fname != NULL) {
		smb_time_audit_log_fname(syscallname, elapsed,
					 smb_fname->base_name);
	} else {
		smb_time_audit_log_fname(syscallname, elapsed,
					 "smb_fname = <NULL>");
	}
}

static int smb_time_audit_connect(vfs_handle_struct *handle,
				  const char *svc, const char *user)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	if (!handle) {
		return -1;
	}

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_CONNECT(handle, svc, user);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;
	if (timediff > audit_timeout) {
		smb_time_audit_log_msg("connect", timediff, user);
	}
	return result;
}

static void smb_time_audit_disconnect(vfs_handle_struct *handle)
{
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	SMB_VFS_NEXT_DISCONNECT(handle);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("disconnect", timediff);
	}
}

static uint64_t smb_time_audit_disk_free(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					uint64_t *bsize,
					uint64_t *dfree,
					uint64_t *dsize)
{
	uint64_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	/* Don't have a reasonable notion of failure here */
	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("disk_free",
				timediff,
				smb_fname->base_name);
	}

	return result;
}

static int smb_time_audit_get_quota(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					enum SMB_QUOTA_TYPE qtype,
					unid_t id,
					SMB_DISK_QUOTA *qt)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GET_QUOTA(handle, smb_fname, qtype, id, qt);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("get_quota",
				timediff,
				smb_fname->base_name);
	}
	return result;
}

static int smb_time_audit_set_quota(struct vfs_handle_struct *handle,
				    enum SMB_QUOTA_TYPE qtype, unid_t id,
				    SMB_DISK_QUOTA *qt)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SET_QUOTA(handle, qtype, id, qt);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("set_quota", timediff);
	}

	return result;
}

static int smb_time_audit_get_shadow_copy_data(struct vfs_handle_struct *handle,
					       struct files_struct *fsp,
					       struct shadow_copy_data *shadow_copy_data,
					       bool labels)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GET_SHADOW_COPY_DATA(handle, fsp,
						   shadow_copy_data, labels);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("get_shadow_copy_data", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_statvfs(struct vfs_handle_struct *handle,
				  const struct smb_filename *smb_fname,
				  struct vfs_statvfs_struct *statbuf)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_STATVFS(handle, smb_fname, statbuf);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("statvfs", timediff,
			smb_fname->base_name);
	}

	return result;
}

static uint32_t smb_time_audit_fs_capabilities(struct vfs_handle_struct *handle,
					       enum timestamp_set_resolution *p_ts_res)
{
	uint32_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("fs_capabilities", timediff);
	}

	return result;
}

static NTSTATUS smb_time_audit_get_dfs_referrals(
			struct vfs_handle_struct *handle,
			struct dfs_GetDFSReferral *r)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GET_DFS_REFERRALS(handle, r);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("get_dfs_referrals", timediff);
	}

	return result;
}

static NTSTATUS smb_time_audit_create_dfs_pathat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			const struct referral *reflist,
			size_t referral_count)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_CREATE_DFS_PATHAT(handle,
			dirfsp,
			smb_fname,
			reflist,
			referral_count);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("get_dfs_referrals", timediff);
	}

	return result;
}

static NTSTATUS smb_time_audit_read_dfs_pathat(struct vfs_handle_struct *handle,
			TALLOC_CTX *mem_ctx,
			struct files_struct *dirfsp,
			struct smb_filename *smb_fname,
			struct referral **ppreflist,
			size_t *preferral_count)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_READ_DFS_PATHAT(handle,
			mem_ctx,
			dirfsp,
			smb_fname,
			ppreflist,
			preferral_count);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("read_dfs_pathat", timediff);
	}

	return result;
}

static NTSTATUS smb_time_audit_snap_check_path(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       const char *service_path,
					       char **base_volume)
{
	NTSTATUS status;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	status = SMB_VFS_NEXT_SNAP_CHECK_PATH(handle, mem_ctx, service_path,
					      base_volume);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2, &ts1) * 1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("snap_check_path", timediff);
	}

	return status;
}

static NTSTATUS smb_time_audit_snap_create(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   const char *base_volume,
					   time_t *tstamp,
					   bool rw,
					   char **base_path,
					   char **snap_path)
{
	NTSTATUS status;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	status = SMB_VFS_NEXT_SNAP_CREATE(handle, mem_ctx, base_volume, tstamp,
					  rw, base_path, snap_path);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2 ,&ts1) * 1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("snap_create", timediff);
	}

	return status;
}

static NTSTATUS smb_time_audit_snap_delete(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   char *base_path,
					   char *snap_path)
{
	NTSTATUS status;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	status = SMB_VFS_NEXT_SNAP_DELETE(handle, mem_ctx, base_path,
					  snap_path);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2, &ts1) * 1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("snap_delete", timediff);
	}

	return status;
}

static DIR *smb_time_audit_fdopendir(vfs_handle_struct *handle,
					      files_struct *fsp,
					      const char *mask, uint32_t attr)
{
	DIR *result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fdopendir", timediff, fsp);
	}

	return result;
}

static struct dirent *smb_time_audit_readdir(vfs_handle_struct *handle,
						 DIR *dirp,
						 SMB_STRUCT_STAT *sbuf)
{
	struct dirent *result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_READDIR(handle, dirp, sbuf);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("readdir", timediff);
	}

	return result;
}

static void smb_time_audit_seekdir(vfs_handle_struct *handle,
				   DIR *dirp, long offset)
{
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	SMB_VFS_NEXT_SEEKDIR(handle, dirp, offset);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("seekdir", timediff);
	}

}

static long smb_time_audit_telldir(vfs_handle_struct *handle,
				   DIR *dirp)
{
	long result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_TELLDIR(handle, dirp);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("telldir", timediff);
	}

	return result;
}

static void smb_time_audit_rewinddir(vfs_handle_struct *handle,
				     DIR *dirp)
{
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	SMB_VFS_NEXT_REWINDDIR(handle, dirp);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("rewinddir", timediff);
	}

}

static int smb_time_audit_mkdirat(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				mode_t mode)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_MKDIRAT(handle,
				dirfsp,
				smb_fname,
				mode);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_smb_fname("mkdirat",
			timediff,
			smb_fname);
	}

	return result;
}

static int smb_time_audit_closedir(vfs_handle_struct *handle,
				   DIR *dirp)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_CLOSEDIR(handle, dirp);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("closedir", timediff);
	}

	return result;
}

static int smb_time_audit_openat(vfs_handle_struct *handle,
				 const struct files_struct *dirfsp,
				 const struct smb_filename *smb_fname,
				 struct files_struct *fsp,
				 int flags,
				 mode_t mode)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_OPENAT(handle,
				     dirfsp,
				     smb_fname,
				     fsp,
				     flags,
				     mode);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("openat", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_audit_create_file(vfs_handle_struct *handle,
					   struct smb_request *req,
					   struct files_struct **dirfsp,
					   struct smb_filename *fname,
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
					   files_struct **result_fsp,
					   int *pinfo,
					   const struct smb2_create_blobs *in_context_blobs,
					   struct smb2_create_blobs *out_context_blobs)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_CREATE_FILE(
		handle,					/* handle */
		req,					/* req */
		dirfsp,					/* dirfsp */
		fname,					/* fname */
		access_mask,				/* access_mask */
		share_access,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		file_attributes,			/* file_attributes */
		oplock_request,				/* oplock_request */
		lease,					/* lease */
		allocation_size,			/* allocation_size */
		private_flags,
		sd,					/* sd */
		ea_list,				/* ea_list */
		result_fsp,				/* result */
		pinfo,
		in_context_blobs, out_context_blobs);   /* create context */
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		/*
		 * can't use result_fsp this time, may have
		 * invalid content causing smbd crash
		 */
		smb_time_audit_log_smb_fname("create_file", timediff,
					   fname);
	}

	return result;
}

static int smb_time_audit_close(vfs_handle_struct *handle, files_struct *fsp)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_CLOSE(handle, fsp);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("close", timediff, fsp);
	}

	return result;
}

static ssize_t smb_time_audit_pread(vfs_handle_struct *handle,
				    files_struct *fsp,
				    void *data, size_t n, off_t offset)
{
	ssize_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("pread", timediff, fsp);
	}

	return result;
}

struct smb_time_audit_pread_state {
	struct files_struct *fsp;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void smb_time_audit_pread_done(struct tevent_req *subreq);

static struct tevent_req *smb_time_audit_pread_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	void *data, size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct smb_time_audit_pread_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_time_audit_pread_state);
	if (req == NULL) {
		return NULL;
	}
	state->fsp = fsp;

	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data,
					 n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_time_audit_pread_done, req);
	return req;
}

static void smb_time_audit_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_time_audit_pread_state *state = tevent_req_data(
		req, struct smb_time_audit_pread_state);

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t smb_time_audit_pread_recv(struct tevent_req *req,
					 struct vfs_aio_state *vfs_aio_state)
{
	struct smb_time_audit_pread_state *state = tevent_req_data(
		req, struct smb_time_audit_pread_state);
	double timediff;

	timediff = state->vfs_aio_state.duration * 1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("async pread", timediff, state->fsp);
	}

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static ssize_t smb_time_audit_pwrite(vfs_handle_struct *handle,
				     files_struct *fsp,
				     const void *data, size_t n,
				     off_t offset)
{
	ssize_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("pwrite", timediff, fsp);
	}

	return result;
}

struct smb_time_audit_pwrite_state {
	struct files_struct *fsp;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void smb_time_audit_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *smb_time_audit_pwrite_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	const void *data, size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct smb_time_audit_pwrite_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_time_audit_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	state->fsp = fsp;

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data,
					 n, offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_time_audit_pwrite_done, req);
	return req;
}

static void smb_time_audit_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_time_audit_pwrite_state *state = tevent_req_data(
		req, struct smb_time_audit_pwrite_state);

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t smb_time_audit_pwrite_recv(struct tevent_req *req,
					  struct vfs_aio_state *vfs_aio_state)
{
	struct smb_time_audit_pwrite_state *state = tevent_req_data(
		req, struct smb_time_audit_pwrite_state);
	double timediff;

	timediff = state->vfs_aio_state.duration * 1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("async pwrite", timediff, state->fsp);
	}

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static off_t smb_time_audit_lseek(vfs_handle_struct *handle,
				      files_struct *fsp,
				      off_t offset, int whence)
{
	off_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_LSEEK(handle, fsp, offset, whence);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("lseek", timediff, fsp);
	}

	return result;
}

static ssize_t smb_time_audit_sendfile(vfs_handle_struct *handle, int tofd,
				       files_struct *fromfsp,
				       const DATA_BLOB *hdr, off_t offset,
				       size_t n)
{
	ssize_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SENDFILE(handle, tofd, fromfsp, hdr, offset, n);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("sendfile", timediff, fromfsp);
	}

	return result;
}

static ssize_t smb_time_audit_recvfile(vfs_handle_struct *handle, int fromfd,
				       files_struct *tofsp,
				       off_t offset,
				       size_t n)
{
	ssize_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_RECVFILE(handle, fromfd, tofsp, offset, n);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("recvfile", timediff, tofsp);
	}

	return result;
}

static int smb_time_audit_renameat(vfs_handle_struct *handle,
				files_struct *srcfsp,
				const struct smb_filename *oldname,
				files_struct *dstfsp,
				const struct smb_filename *newname)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_RENAMEAT(handle,
			srcfsp,
			oldname,
			dstfsp,
			newname);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_smb_fname("renameat", timediff, newname);
	}

	return result;
}

struct smb_time_audit_fsync_state {
	struct files_struct *fsp;
	int ret;
	struct vfs_aio_state vfs_aio_state;
};

static void smb_time_audit_fsync_done(struct tevent_req *subreq);

static struct tevent_req *smb_time_audit_fsync_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp)
{
	struct tevent_req *req, *subreq;
	struct smb_time_audit_fsync_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_time_audit_fsync_state);
	if (req == NULL) {
		return NULL;
	}
	state->fsp = fsp;

	subreq = SMB_VFS_NEXT_FSYNC_SEND(state, ev, handle, fsp);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_time_audit_fsync_done, req);
	return req;
}

static void smb_time_audit_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_time_audit_fsync_state *state = tevent_req_data(
		req, struct smb_time_audit_fsync_state);

	state->ret = SMB_VFS_FSYNC_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static int smb_time_audit_fsync_recv(struct tevent_req *req,
				     struct vfs_aio_state *vfs_aio_state)
{
	struct smb_time_audit_fsync_state *state = tevent_req_data(
		req, struct smb_time_audit_fsync_state);
	double timediff;

	timediff = state->vfs_aio_state.duration * 1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("async fsync", timediff, state->fsp);
	}

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static int smb_time_audit_stat(vfs_handle_struct *handle,
			       struct smb_filename *fname)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_STAT(handle, fname);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_smb_fname("stat", timediff, fname);
	}

	return result;
}

static int smb_time_audit_fstat(vfs_handle_struct *handle, files_struct *fsp,
				SMB_STRUCT_STAT *sbuf)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fstat", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_lstat(vfs_handle_struct *handle,
				struct smb_filename *path)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_LSTAT(handle, path);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_smb_fname("lstat", timediff, path);
	}

	return result;
}

static uint64_t smb_time_audit_get_alloc_size(vfs_handle_struct *handle,
					      files_struct *fsp,
					      const SMB_STRUCT_STAT *sbuf)
{
	uint64_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GET_ALLOC_SIZE(handle, fsp, sbuf);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("get_alloc_size", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *path,
			int flags)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp,
				path,
				flags);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_smb_fname("unlinkat", timediff, path);
	}

	return result;
}

static int smb_time_audit_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("chmod",
			timediff,
			smb_fname->base_name);
	}

	return result;
}

static int smb_time_audit_fchmod(vfs_handle_struct *handle, files_struct *fsp,
				 mode_t mode)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fchmod", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_fchown(vfs_handle_struct *handle, files_struct *fsp,
				 uid_t uid, gid_t gid)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fchown", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("lchown",
			timediff,
			smb_fname->base_name);
	}

	return result;
}

static int smb_time_audit_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_CHDIR(handle, smb_fname);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("chdir",
			timediff,
			smb_fname->base_name);
	}

	return result;
}

static struct smb_filename *smb_time_audit_getwd(vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx)
{
	struct smb_filename *result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GETWD(handle, mem_ctx);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("getwd", timediff);
	}

	return result;
}

static int smb_time_audit_ntimes(vfs_handle_struct *handle,
				 const struct smb_filename *path,
				 struct smb_file_time *ft)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_NTIMES(handle, path, ft);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_smb_fname("ntimes", timediff, path);
	}

	return result;
}

static int smb_time_audit_ftruncate(vfs_handle_struct *handle,
				    files_struct *fsp,
				    off_t len)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("ftruncate", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_fallocate(vfs_handle_struct *handle,
				    files_struct *fsp,
				    uint32_t mode,
				    off_t offset,
				    off_t len)
{
	int result;
	int saved_errno = 0;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);
	if (result == -1) {
		saved_errno = errno;
	}
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fallocate", timediff, fsp);
	}
	if (result == -1) {
		errno = saved_errno;
	}
	return result;
}

static bool smb_time_audit_lock(vfs_handle_struct *handle, files_struct *fsp,
				int op, off_t offset, off_t count,
				int type)
{
	bool result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("lock", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_kernel_flock(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       uint32_t share_access,
				       uint32_t access_mask)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_KERNEL_FLOCK(handle, fsp, share_access,
					   access_mask);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("kernel_flock", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_fcntl(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				int cmd, va_list cmd_arg)
{
	void *arg;
	va_list dup_cmd_arg;
	int result;
	struct timespec ts1,ts2;
	double timediff;

	va_copy(dup_cmd_arg, cmd_arg);
	arg = va_arg(dup_cmd_arg, void *);
	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FCNTL(handle, fsp, cmd, arg);
	clock_gettime_mono(&ts2);
	va_end(dup_cmd_arg);

	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;
	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("kernel_flock", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_linux_setlease(vfs_handle_struct *handle,
					 files_struct *fsp,
					 int leasetype)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("linux_setlease", timediff, fsp);
	}

	return result;
}

static bool smb_time_audit_getlock(vfs_handle_struct *handle,
				   files_struct *fsp,
				   off_t *poffset, off_t *pcount,
				   int *ptype, pid_t *ppid)
{
	bool result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset, pcount, ptype,
				      ppid);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("getlock", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_symlinkat(vfs_handle_struct *handle,
				const struct smb_filename *link_contents,
				struct files_struct *dirfsp,
				const struct smb_filename *new_smb_fname)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SYMLINKAT(handle,
				link_contents,
				dirfsp,
				new_smb_fname);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("symlinkat", timediff,
			new_smb_fname->base_name);
	}

	return result;
}

static int smb_time_audit_readlinkat(vfs_handle_struct *handle,
				files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				char *buf,
				size_t bufsiz)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_READLINKAT(handle,
				dirfsp,
				smb_fname,
				buf,
				bufsiz);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("readlinkat", timediff,
				smb_fname->base_name);
	}

	return result;
}

static int smb_time_audit_linkat(vfs_handle_struct *handle,
				files_struct *srcfsp,
				const struct smb_filename *old_smb_fname,
				files_struct *dstfsp,
				const struct smb_filename *new_smb_fname,
				int flags)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_LINKAT(handle,
			srcfsp,
			old_smb_fname,
			dstfsp,
			new_smb_fname,
			flags);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("linkat", timediff,
			new_smb_fname->base_name);
	}

	return result;
}

static int smb_time_audit_mknodat(vfs_handle_struct *handle,
				files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				mode_t mode,
				SMB_DEV_T dev)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_MKNODAT(handle,
				dirfsp,
				smb_fname,
				mode,
				dev);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_smb_fname("mknodat", timediff, smb_fname);
	}

	return result;
}

static struct smb_filename *smb_time_audit_realpath(vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)
{
	struct smb_filename *result_fname;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result_fname = SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("realpath", timediff,
				smb_fname->base_name);
	}

	return result_fname;
}

static int smb_time_audit_chflags(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				unsigned int flags)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_CHFLAGS(handle, smb_fname, flags);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_smb_fname("chflags", timediff, smb_fname);
	}

	return result;
}

static struct file_id smb_time_audit_file_id_create(struct vfs_handle_struct *handle,
						    const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id_zero;
	struct file_id result;
	struct timespec ts1,ts2;
	double timediff;

	ZERO_STRUCT(id_zero);

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FILE_ID_CREATE(handle, sbuf);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("file_id_create", timediff);
	}

	return result;
}

static uint64_t smb_time_audit_fs_file_id(struct vfs_handle_struct *handle,
					  const SMB_STRUCT_STAT *sbuf)
{
	uint64_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FS_FILE_ID(handle, sbuf);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("fs_file_id", timediff);
	}

	return result;
}

static NTSTATUS smb_time_audit_streaminfo(vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  const struct smb_filename *smb_fname,
					  TALLOC_CTX *mem_ctx,
					  unsigned int *pnum_streams,
					  struct stream_struct **pstreams)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_STREAMINFO(handle, fsp, smb_fname, mem_ctx,
					 pnum_streams, pstreams);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("streaminfo", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_get_real_filename(struct vfs_handle_struct *handle,
					    const struct smb_filename *path,
					    const char *name,
					    TALLOC_CTX *mem_ctx,
					    char **found_name)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name, mem_ctx,
						found_name);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("get_real_filename",
					 timediff, path->base_name);
	}

	return result;
}

static const char *smb_time_audit_connectpath(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname)
{
	const char *result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_CONNECTPATH(handle, smb_fname);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("connectpath", timediff,
			smb_fname->base_name);
	}

	return result;
}

static NTSTATUS smb_time_audit_brl_lock_windows(struct vfs_handle_struct *handle,
						struct byte_range_lock *br_lck,
						struct lock_struct *plock)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_BRL_LOCK_WINDOWS(handle, br_lck, plock);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("brl_lock_windows", timediff,
				       brl_fsp(br_lck));
	}

	return result;
}

static bool smb_time_audit_brl_unlock_windows(struct vfs_handle_struct *handle,
					      struct byte_range_lock *br_lck,
					      const struct lock_struct *plock)
{
	bool result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_BRL_UNLOCK_WINDOWS(handle, br_lck, plock);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("brl_unlock_windows", timediff,
				       brl_fsp(br_lck));
	}

	return result;
}

static bool smb_time_audit_strict_lock_check(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     struct lock_struct *plock)
{
	bool result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_STRICT_LOCK_CHECK(handle, fsp, plock);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("strict_lock_check", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_audit_translate_name(struct vfs_handle_struct *handle,
					      const char *name,
					      enum vfs_translate_direction direction,
					      TALLOC_CTX *mem_ctx,
					      char **mapped_name)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_TRANSLATE_NAME(handle, name, direction, mem_ctx,
					     mapped_name);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("translate_name", timediff, name);
	}

	return result;
}

static NTSTATUS smb_time_audit_fsctl(struct vfs_handle_struct *handle,
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
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FSCTL(handle,
				fsp,
				ctx,
				function,
				req_flags,
				_in_data,
				in_len,
				_out_data,
				max_out_len,
				out_len);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fsctl", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_get_dos_attributes(struct vfs_handle_struct *handle,
					struct smb_filename *smb_fname,
					uint32_t *dosmode)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GET_DOS_ATTRIBUTES(handle,
				smb_fname,
				dosmode);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("get_dos_attributes",
				timediff,
				smb_fname->base_name);
	}

	return result;
}

struct smb_time_audit_get_dos_attributes_state {
	struct vfs_aio_state aio_state;
	files_struct *dir_fsp;
	const struct smb_filename *smb_fname;
	uint32_t dosmode;
};

static void smb_time_audit_get_dos_attributes_done(struct tevent_req *subreq);

static struct tevent_req *smb_time_audit_get_dos_attributes_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			struct smb_filename *smb_fname)
{
	struct tevent_req *req = NULL;
	struct smb_time_audit_get_dos_attributes_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_time_audit_get_dos_attributes_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct smb_time_audit_get_dos_attributes_state) {
		.dir_fsp = dir_fsp,
		.smb_fname = smb_fname,
	};

	subreq = SMB_VFS_NEXT_GET_DOS_ATTRIBUTES_SEND(mem_ctx,
						      ev,
						      handle,
						      dir_fsp,
						      smb_fname);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				smb_time_audit_get_dos_attributes_done,
				req);

	return req;
}

static void smb_time_audit_get_dos_attributes_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb_time_audit_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct smb_time_audit_get_dos_attributes_state);
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

static NTSTATUS smb_time_audit_get_dos_attributes_recv(struct tevent_req *req,
						struct vfs_aio_state *aio_state,
						uint32_t *dosmode)
{
	struct smb_time_audit_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct smb_time_audit_get_dos_attributes_state);
	NTSTATUS status;
	double timediff;

	timediff = state->aio_state.duration * 1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_at("async get_dos_attributes",
				      timediff,
				      state->dir_fsp,
				      state->smb_fname);
	}

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	*aio_state = state->aio_state;
	*dosmode = state->dosmode;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

static NTSTATUS smb_time_fget_dos_attributes(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32_t *dosmode)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle,
				fsp,
				dosmode);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fget_dos_attributes", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_set_dos_attributes(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					uint32_t dosmode)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SET_DOS_ATTRIBUTES(handle,
				smb_fname,
				dosmode);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("set_dos_attributes",
				timediff,
				smb_fname->base_name);
	}

	return result;
}

static NTSTATUS smb_time_fset_dos_attributes(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32_t dosmode)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle,
				fsp,
				dosmode);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fset_dos_attributes", timediff, fsp);
	}

	return result;
}

struct time_audit_offload_read_state {
	struct vfs_handle_struct *handle;
	struct timespec ts_send;
	DATA_BLOB token_blob;
};

static void smb_time_audit_offload_read_done(struct tevent_req *subreq);

static struct tevent_req *smb_time_audit_offload_read_send(
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
	struct tevent_req *subreq = NULL;
	struct time_audit_offload_read_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct time_audit_offload_read_state);
	if (req == NULL) {
		return NULL;
	}
	state->handle = handle;
	clock_gettime_mono(&state->ts_send);

	subreq = SMB_VFS_NEXT_OFFLOAD_READ_SEND(mem_ctx, ev,
						handle, fsp,
						fsctl, ttl,
						offset, to_copy);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, smb_time_audit_offload_read_done, req);
	return req;
}

static void smb_time_audit_offload_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct time_audit_offload_read_state *state = tevent_req_data(
		req, struct time_audit_offload_read_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_OFFLOAD_READ_RECV(subreq,
						state->handle,
						state,
						&state->token_blob);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}
	tevent_req_done(req);
}

static NTSTATUS smb_time_audit_offload_read_recv(
	struct tevent_req *req,
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	DATA_BLOB *token_blob)
{
	struct time_audit_offload_read_state *state = tevent_req_data(
		req, struct time_audit_offload_read_state);
	struct timespec ts_recv;
	double timediff;
	NTSTATUS status;

	clock_gettime_mono(&ts_recv);
	timediff = nsec_time_diff(&ts_recv, &state->ts_send) * 1.0e-9;
	if (timediff > audit_timeout) {
		smb_time_audit_log("offload_read", timediff);
	}

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	token_blob->length = state->token_blob.length;
	token_blob->data = talloc_move(mem_ctx, &state->token_blob.data);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct time_audit_offload_write_state {
	struct timespec ts_send;
	struct vfs_handle_struct *handle;
	off_t copied;
};
static void smb_time_audit_offload_write_done(struct tevent_req *subreq);

static struct tevent_req *smb_time_audit_offload_write_send(struct vfs_handle_struct *handle,
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
	struct time_audit_offload_write_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct time_audit_offload_write_state);
	if (req == NULL) {
		return NULL;
	}

	state->handle = handle;
	clock_gettime_mono(&state->ts_send);
	subreq = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle, state, ev,
					      fsctl, token, transfer_offset,
					      dest_fsp, dest_off, num);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_set_callback(subreq, smb_time_audit_offload_write_done, req);
	return req;
}

static void smb_time_audit_offload_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct time_audit_offload_write_state *state = tevent_req_data(
		req, struct time_audit_offload_write_state);
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

static NTSTATUS smb_time_audit_offload_write_recv(struct vfs_handle_struct *handle,
					       struct tevent_req *req,
					       off_t *copied)
{
	struct time_audit_offload_write_state *state = tevent_req_data(
		req, struct time_audit_offload_write_state);
	struct timespec ts_recv;
	double timediff;
	NTSTATUS status;

	clock_gettime_mono(&ts_recv);
	timediff = nsec_time_diff(&ts_recv, &state->ts_send)*1.0e-9;
	if (timediff > audit_timeout) {
		smb_time_audit_log("offload_write", timediff);
	}

	*copied = state->copied;
	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static NTSTATUS smb_time_audit_get_compression(vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct files_struct *fsp,
					       struct smb_filename *smb_fname,
					       uint16_t *_compression_fmt)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GET_COMPRESSION(handle, mem_ctx, fsp, smb_fname,
					      _compression_fmt);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		if (fsp !=  NULL) {
			smb_time_audit_log_fsp("get_compression",
					       timediff, fsp);
		} else {
			smb_time_audit_log_smb_fname("get_compression",
						     timediff, smb_fname);
		}
	}

	return result;
}

static NTSTATUS smb_time_audit_set_compression(vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct files_struct *fsp,
					       uint16_t compression_fmt)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SET_COMPRESSION(handle, mem_ctx, fsp,
					      compression_fmt);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("set_compression", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_audit_readdir_attr(struct vfs_handle_struct *handle,
					    const struct smb_filename *fname,
					    TALLOC_CTX *mem_ctx,
					    struct readdir_attr_data **pattr_data)
{
	NTSTATUS status;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	status = SMB_VFS_NEXT_READDIR_ATTR(handle, fname, mem_ctx, pattr_data);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_smb_fname("readdir_attr", timediff, fname);
	}

	return status;
}

static NTSTATUS smb_time_audit_fget_nt_acl(vfs_handle_struct *handle,
					   files_struct *fsp,
					   uint32_t security_info,
					   TALLOC_CTX *mem_ctx,
					   struct security_descriptor **ppdesc)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
					  mem_ctx, ppdesc);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fget_nt_acl", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_audit_get_nt_acl_at(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
					dirfsp,
					smb_fname,
					security_info,
					mem_ctx,
					ppdesc);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("get_nt_acl",
			timediff,
			smb_fname->base_name);
	}

	return result;
}

static NTSTATUS smb_time_audit_fset_nt_acl(vfs_handle_struct *handle,
					   files_struct *fsp,
					   uint32_t security_info_sent,
					   const struct security_descriptor *psd)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent,
					  psd);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fset_nt_acl", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_audit_audit_file(struct vfs_handle_struct *handle,
				struct smb_filename *smb_fname,
				struct security_acl *sacl,
				uint32_t access_requested,
				uint32_t access_denied)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_AUDIT_FILE(handle,
					smb_fname,
					sacl,
					access_requested,
					access_denied);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("audit_file",
			timediff,
			smb_fname->base_name);
	}

	return result;
}

static SMB_ACL_T smb_time_audit_sys_acl_get_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					SMB_ACL_TYPE_T type,
					TALLOC_CTX *mem_ctx)
{
	SMB_ACL_T result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, smb_fname,
				type, mem_ctx);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("sys_acl_get_file", timediff,
			smb_fname->base_name);
	}

	return result;
}

static SMB_ACL_T smb_time_audit_sys_acl_get_fd(vfs_handle_struct *handle,
					       files_struct *fsp,
					       TALLOC_CTX *mem_ctx)
{
	SMB_ACL_T result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, mem_ctx);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("sys_acl_get_fd", timediff, fsp);
	}

	return result;
}


static int smb_time_audit_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle, smb_fname,
				mem_ctx, blob_description, blob);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("sys_acl_blob_get_file", timediff);
	}

	return result;
}

static int smb_time_audit_sys_acl_blob_get_fd(vfs_handle_struct *handle,
					      files_struct *fsp,
					      TALLOC_CTX *mem_ctx, 
					      char **blob_description,
					      DATA_BLOB *blob)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx, blob_description, blob);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("sys_acl_blob_get_fd", timediff);
	}

	return result;
}

static int smb_time_audit_sys_acl_set_file(vfs_handle_struct *handle,
					   const struct smb_filename *smb_fname,
					   SMB_ACL_TYPE_T acltype,
					   SMB_ACL_T theacl)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, smb_fname, acltype,
					       theacl);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("sys_acl_set_file", timediff,
			smb_fname->base_name);
	}

	return result;
}

static int smb_time_audit_sys_acl_set_fd(vfs_handle_struct *handle,
					 files_struct *fsp,
					 SMB_ACL_T theacl)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("sys_acl_set_fd", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_sys_acl_delete_def_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, smb_fname);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("sys_acl_delete_def_file", timediff,
			smb_fname->base_name);
	}

	return result;
}

static ssize_t smb_time_audit_getxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)
{
	ssize_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_GETXATTR(handle, smb_fname, name, value, size);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("getxattr", timediff,
			smb_fname->base_name);
	}

	return result;
}

struct smb_time_audit_getxattrat_state {
	struct vfs_aio_state aio_state;
	files_struct *dir_fsp;
	const struct smb_filename *smb_fname;
	const char *xattr_name;
	ssize_t xattr_size;
	uint8_t *xattr_value;
};

static void smb_time_audit_getxattrat_done(struct tevent_req *subreq);

static struct tevent_req *smb_time_audit_getxattrat_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			const struct smb_filename *smb_fname,
			const char *xattr_name,
			size_t alloc_hint)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct smb_time_audit_getxattrat_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_time_audit_getxattrat_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct smb_time_audit_getxattrat_state) {
		.dir_fsp = dir_fsp,
		.smb_fname = smb_fname,
		.xattr_name = xattr_name,
	};

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
	tevent_req_set_callback(subreq, smb_time_audit_getxattrat_done, req);

	return req;
}

static void smb_time_audit_getxattrat_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_time_audit_getxattrat_state *state = tevent_req_data(
		req, struct smb_time_audit_getxattrat_state);

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

static ssize_t smb_time_audit_getxattrat_recv(struct tevent_req *req,
					      struct vfs_aio_state *aio_state,
					      TALLOC_CTX *mem_ctx,
					      uint8_t **xattr_value)
{
	struct smb_time_audit_getxattrat_state *state = tevent_req_data(
		req, struct smb_time_audit_getxattrat_state);
	ssize_t xattr_size;
	double timediff;

	timediff = state->aio_state.duration * 1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_at("async getxattrat",
				      timediff,
				      state->dir_fsp,
				      state->smb_fname);
	}

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

static ssize_t smb_time_audit_fgetxattr(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					const char *name, void *value,
					size_t size)
{
	ssize_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, value, size);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fgetxattr", timediff, fsp);
	}

	return result;
}

static ssize_t smb_time_audit_listxattr(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					char *list,
					size_t size)
{
	ssize_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_LISTXATTR(handle, smb_fname, list, size);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("listxattr", timediff,
				smb_fname->base_name);
	}

	return result;
}

static ssize_t smb_time_audit_flistxattr(struct vfs_handle_struct *handle,
					 struct files_struct *fsp, char *list,
					 size_t size)
{
	ssize_t result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("flistxattr", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_removexattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_REMOVEXATTR(handle, smb_fname, name);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("removexattr", timediff,
			smb_fname->base_name);
	}

	return result;
}

static int smb_time_audit_fremovexattr(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       const char *name)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fremovexattr", timediff, fsp);
	}

	return result;
}

static int smb_time_audit_setxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				const void *value,
				size_t size,
				int flags)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_SETXATTR(handle, smb_fname, name, value, size,
				       flags);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fname("setxattr", timediff,
				smb_fname->base_name);
	}

	return result;
}

static int smb_time_audit_fsetxattr(struct vfs_handle_struct *handle,
				    struct files_struct *fsp, const char *name,
				    const void *value, size_t size, int flags)
{
	int result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value, size, flags);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("fsetxattr", timediff, fsp);
	}

	return result;
}

static bool smb_time_audit_aio_force(struct vfs_handle_struct *handle,
				     struct files_struct *fsp)
{
	bool result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_AIO_FORCE(handle, fsp);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("aio_force", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_audit_durable_cookie(struct vfs_handle_struct *handle,
					      struct files_struct *fsp,
					      TALLOC_CTX *mem_ctx,
					      DATA_BLOB *cookie)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_DURABLE_COOKIE(handle, fsp, mem_ctx, cookie);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("durable_cookie", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_audit_durable_disconnect(struct vfs_handle_struct *handle,
						  struct files_struct *fsp,
						  const DATA_BLOB old_cookie,
						  TALLOC_CTX *mem_ctx,
						  DATA_BLOB *new_cookie)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_DURABLE_DISCONNECT(handle, fsp, old_cookie,
						 mem_ctx, new_cookie);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log_fsp("durable_disconnect", timediff, fsp);
	}

	return result;
}

static NTSTATUS smb_time_audit_durable_reconnect(struct vfs_handle_struct *handle,
						 struct smb_request *smb1req,
						 struct smbXsrv_open *op,
						 const DATA_BLOB old_cookie,
						 TALLOC_CTX *mem_ctx,
						 struct files_struct **fsp,
						 DATA_BLOB *new_cookie)
{
	NTSTATUS result;
	struct timespec ts1,ts2;
	double timediff;

	clock_gettime_mono(&ts1);
	result = SMB_VFS_NEXT_DURABLE_RECONNECT(handle, smb1req, op, old_cookie,
						mem_ctx, fsp, new_cookie);
	clock_gettime_mono(&ts2);
	timediff = nsec_time_diff(&ts2,&ts1)*1.0e-9;

	if (timediff > audit_timeout) {
		smb_time_audit_log("durable_reconnect", timediff);
	}

	return result;
}

/* VFS operations */

static struct vfs_fn_pointers vfs_time_audit_fns = {
	.connect_fn = smb_time_audit_connect,
	.disconnect_fn = smb_time_audit_disconnect,
	.disk_free_fn = smb_time_audit_disk_free,
	.get_quota_fn = smb_time_audit_get_quota,
	.set_quota_fn = smb_time_audit_set_quota,
	.get_shadow_copy_data_fn = smb_time_audit_get_shadow_copy_data,
	.statvfs_fn = smb_time_audit_statvfs,
	.fs_capabilities_fn = smb_time_audit_fs_capabilities,
	.get_dfs_referrals_fn = smb_time_audit_get_dfs_referrals,
	.create_dfs_pathat_fn = smb_time_audit_create_dfs_pathat,
	.read_dfs_pathat_fn = smb_time_audit_read_dfs_pathat,
	.fdopendir_fn = smb_time_audit_fdopendir,
	.readdir_fn = smb_time_audit_readdir,
	.seekdir_fn = smb_time_audit_seekdir,
	.telldir_fn = smb_time_audit_telldir,
	.rewind_dir_fn = smb_time_audit_rewinddir,
	.mkdirat_fn = smb_time_audit_mkdirat,
	.closedir_fn = smb_time_audit_closedir,
	.openat_fn = smb_time_audit_openat,
	.create_file_fn = smb_time_audit_create_file,
	.close_fn = smb_time_audit_close,
	.pread_fn = smb_time_audit_pread,
	.pread_send_fn = smb_time_audit_pread_send,
	.pread_recv_fn = smb_time_audit_pread_recv,
	.pwrite_fn = smb_time_audit_pwrite,
	.pwrite_send_fn = smb_time_audit_pwrite_send,
	.pwrite_recv_fn = smb_time_audit_pwrite_recv,
	.lseek_fn = smb_time_audit_lseek,
	.sendfile_fn = smb_time_audit_sendfile,
	.recvfile_fn = smb_time_audit_recvfile,
	.renameat_fn = smb_time_audit_renameat,
	.fsync_send_fn = smb_time_audit_fsync_send,
	.fsync_recv_fn = smb_time_audit_fsync_recv,
	.stat_fn = smb_time_audit_stat,
	.fstat_fn = smb_time_audit_fstat,
	.lstat_fn = smb_time_audit_lstat,
	.get_alloc_size_fn = smb_time_audit_get_alloc_size,
	.unlinkat_fn = smb_time_audit_unlinkat,
	.chmod_fn = smb_time_audit_chmod,
	.fchmod_fn = smb_time_audit_fchmod,
	.fchown_fn = smb_time_audit_fchown,
	.lchown_fn = smb_time_audit_lchown,
	.chdir_fn = smb_time_audit_chdir,
	.getwd_fn = smb_time_audit_getwd,
	.ntimes_fn = smb_time_audit_ntimes,
	.ftruncate_fn = smb_time_audit_ftruncate,
	.fallocate_fn = smb_time_audit_fallocate,
	.lock_fn = smb_time_audit_lock,
	.kernel_flock_fn = smb_time_audit_kernel_flock,
	.fcntl_fn = smb_time_audit_fcntl,
	.linux_setlease_fn = smb_time_audit_linux_setlease,
	.getlock_fn = smb_time_audit_getlock,
	.symlinkat_fn = smb_time_audit_symlinkat,
	.readlinkat_fn = smb_time_audit_readlinkat,
	.linkat_fn = smb_time_audit_linkat,
	.mknodat_fn = smb_time_audit_mknodat,
	.realpath_fn = smb_time_audit_realpath,
	.chflags_fn = smb_time_audit_chflags,
	.file_id_create_fn = smb_time_audit_file_id_create,
	.fs_file_id_fn = smb_time_audit_fs_file_id,
	.offload_read_send_fn = smb_time_audit_offload_read_send,
	.offload_read_recv_fn = smb_time_audit_offload_read_recv,
	.offload_write_send_fn = smb_time_audit_offload_write_send,
	.offload_write_recv_fn = smb_time_audit_offload_write_recv,
	.get_compression_fn = smb_time_audit_get_compression,
	.set_compression_fn = smb_time_audit_set_compression,
	.snap_check_path_fn = smb_time_audit_snap_check_path,
	.snap_create_fn = smb_time_audit_snap_create,
	.snap_delete_fn = smb_time_audit_snap_delete,
	.streaminfo_fn = smb_time_audit_streaminfo,
	.get_real_filename_fn = smb_time_audit_get_real_filename,
	.connectpath_fn = smb_time_audit_connectpath,
	.brl_lock_windows_fn = smb_time_audit_brl_lock_windows,
	.brl_unlock_windows_fn = smb_time_audit_brl_unlock_windows,
	.strict_lock_check_fn = smb_time_audit_strict_lock_check,
	.translate_name_fn = smb_time_audit_translate_name,
	.fsctl_fn = smb_time_audit_fsctl,
	.get_dos_attributes_fn = smb_time_get_dos_attributes,
	.get_dos_attributes_send_fn = smb_time_audit_get_dos_attributes_send,
	.get_dos_attributes_recv_fn = smb_time_audit_get_dos_attributes_recv,
	.fget_dos_attributes_fn = smb_time_fget_dos_attributes,
	.set_dos_attributes_fn = smb_time_set_dos_attributes,
	.fset_dos_attributes_fn = smb_time_fset_dos_attributes,
	.fget_nt_acl_fn = smb_time_audit_fget_nt_acl,
	.get_nt_acl_at_fn = smb_time_audit_get_nt_acl_at,
	.fset_nt_acl_fn = smb_time_audit_fset_nt_acl,
	.audit_file_fn = smb_time_audit_audit_file,
	.sys_acl_get_file_fn = smb_time_audit_sys_acl_get_file,
	.sys_acl_get_fd_fn = smb_time_audit_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = smb_time_audit_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = smb_time_audit_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = smb_time_audit_sys_acl_set_file,
	.sys_acl_set_fd_fn = smb_time_audit_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = smb_time_audit_sys_acl_delete_def_file,
	.getxattr_fn = smb_time_audit_getxattr,
	.getxattrat_send_fn = smb_time_audit_getxattrat_send,
	.getxattrat_recv_fn = smb_time_audit_getxattrat_recv,
	.fgetxattr_fn = smb_time_audit_fgetxattr,
	.listxattr_fn = smb_time_audit_listxattr,
	.flistxattr_fn = smb_time_audit_flistxattr,
	.removexattr_fn = smb_time_audit_removexattr,
	.fremovexattr_fn = smb_time_audit_fremovexattr,
	.setxattr_fn = smb_time_audit_setxattr,
	.fsetxattr_fn = smb_time_audit_fsetxattr,
	.aio_force_fn = smb_time_audit_aio_force,
	.durable_cookie_fn = smb_time_audit_durable_cookie,
	.durable_disconnect_fn = smb_time_audit_durable_disconnect,
	.durable_reconnect_fn = smb_time_audit_durable_reconnect,
	.readdir_attr_fn = smb_time_audit_readdir_attr,
};


static_decl_vfs;
NTSTATUS vfs_time_audit_init(TALLOC_CTX *ctx)
{
	smb_vfs_assert_all_fns(&vfs_time_audit_fns, "time_audit");

	audit_timeout = (double)lp_parm_int(-1, "time_audit", "timeout",
					    10000) / 1000.0;
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "time_audit",
				&vfs_time_audit_fns);
}
