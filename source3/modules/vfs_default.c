/*
   Unix SMB/CIFS implementation.
   Wrap disk only vfs functions to sidestep dodgy compilers.
   Copyright (C) Tim Potter 1998
   Copyright (C) Jeremy Allison 2007

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
#include "system/time.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "ntioctl.h"
#include "smbprofile.h"
#include "../libcli/security/security.h"
#include "passdb/lookup_sid.h"
#include "source3/include/msdfs.h"
#include "librpc/gen_ndr/ndr_dfsblobs.h"
#include "lib/util/tevent_unix.h"
#include "lib/asys/asys.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/* Check for NULL pointer parameters in vfswrap_* functions */

/* We don't want to have NULL function pointers lying around.  Someone
   is sure to try and execute them.  These stubs are used to prevent
   this possibility. */

static int vfswrap_connect(vfs_handle_struct *handle,  const char *service, const char *user)
{
    return 0;    /* Return >= 0 for success */
}

static void vfswrap_disconnect(vfs_handle_struct *handle)
{
}

/* Disk operations */

static uint64_t vfswrap_disk_free(vfs_handle_struct *handle,  const char *path, bool small_query, uint64_t *bsize,
			       uint64_t *dfree, uint64_t *dsize)
{
	uint64_t result;

	result = sys_disk_free(handle->conn, path, small_query, bsize, dfree, dsize);
	return result;
}

static int vfswrap_get_quota(struct vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *qt)
{
#ifdef HAVE_SYS_QUOTAS
	int result;

	START_PROFILE(syscall_get_quota);
	result = sys_get_quota(handle->conn->connectpath, qtype, id, qt);
	END_PROFILE(syscall_get_quota);
	return result;
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int vfswrap_set_quota(struct vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *qt)
{
#ifdef HAVE_SYS_QUOTAS
	int result;

	START_PROFILE(syscall_set_quota);
	result = sys_set_quota(handle->conn->connectpath, qtype, id, qt);
	END_PROFILE(syscall_set_quota);
	return result;
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int vfswrap_get_shadow_copy_data(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					struct shadow_copy_data *shadow_copy_data,
					bool labels)
{
	errno = ENOSYS;
	return -1;  /* Not implemented. */
}

static int vfswrap_statvfs(struct vfs_handle_struct *handle,  const char *path, vfs_statvfs_struct *statbuf)
{
	return sys_statvfs(path, statbuf);
}

static uint32_t vfswrap_fs_capabilities(struct vfs_handle_struct *handle,
		enum timestamp_set_resolution *p_ts_res)
{
	connection_struct *conn = handle->conn;
	uint32_t caps = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;
	struct smb_filename *smb_fname_cpath = NULL;
	struct vfs_statvfs_struct statbuf;
	NTSTATUS status;
	int ret;

	ZERO_STRUCT(statbuf);
	ret = sys_statvfs(conn->connectpath, &statbuf);
	if (ret == 0) {
		caps = statbuf.FsCapabilities;
	}

	*p_ts_res = TIMESTAMP_SET_SECONDS;

	/* Work out what timestamp resolution we can
	 * use when setting a timestamp. */

	status = create_synthetic_smb_fname(talloc_tos(),
				conn->connectpath,
				NULL,
				NULL,
				&smb_fname_cpath);
	if (!NT_STATUS_IS_OK(status)) {
		return caps;
	}

	ret = SMB_VFS_STAT(conn, smb_fname_cpath);
	if (ret == -1) {
		TALLOC_FREE(smb_fname_cpath);
		return caps;
	}

	if (smb_fname_cpath->st.st_ex_mtime.tv_nsec ||
			smb_fname_cpath->st.st_ex_atime.tv_nsec ||
			smb_fname_cpath->st.st_ex_ctime.tv_nsec) {
		/* If any of the normal UNIX directory timestamps
		 * have a non-zero tv_nsec component assume
		 * we might be able to set sub-second timestamps.
		 * See what filetime set primitives we have.
		 */
#if defined(HAVE_UTIMENSAT)
		*p_ts_res = TIMESTAMP_SET_NT_OR_BETTER;
#elif defined(HAVE_UTIMES)
		/* utimes allows msec timestamps to be set. */
		*p_ts_res = TIMESTAMP_SET_MSEC;
#elif defined(HAVE_UTIME)
		/* utime only allows sec timestamps to be set. */
		*p_ts_res = TIMESTAMP_SET_SECONDS;
#endif

		DEBUG(10,("vfswrap_fs_capabilities: timestamp "
			"resolution of %s "
			"available on share %s, directory %s\n",
			*p_ts_res == TIMESTAMP_SET_MSEC ? "msec" : "sec",
			lp_servicename(talloc_tos(), conn->params->service),
			conn->connectpath ));
	}
	TALLOC_FREE(smb_fname_cpath);
	return caps;
}

static NTSTATUS vfswrap_get_dfs_referrals(struct vfs_handle_struct *handle,
					  struct dfs_GetDFSReferral *r)
{
	struct junction_map *junction = NULL;
	int consumedcnt = 0;
	bool self_referral = false;
	char *pathnamep = NULL;
	char *local_dfs_path = NULL;
	NTSTATUS status;
	int i;
	uint16_t max_referral_level = r->in.req.max_referral_level;

	if (DEBUGLVL(10)) {
		NDR_PRINT_IN_DEBUG(dfs_GetDFSReferral, r);
	}

	/* get the junction entry */
	if (r->in.req.servername == NULL) {
		return NT_STATUS_NOT_FOUND;
	}

	/*
	 * Trim pathname sent by client so it begins with only one backslash.
	 * Two backslashes confuse some dfs clients
	 */

	local_dfs_path = talloc_strdup(r, r->in.req.servername);
	if (local_dfs_path == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	pathnamep = local_dfs_path;
	while (IS_DIRECTORY_SEP(pathnamep[0]) &&
	       IS_DIRECTORY_SEP(pathnamep[1])) {
		pathnamep++;
	}

	junction = talloc_zero(r, struct junction_map);
	if (junction == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* The following call can change cwd. */
	status = get_referred_path(r, pathnamep,
				   !handle->conn->sconn->using_smb2,
				   junction, &consumedcnt, &self_referral);
	if (!NT_STATUS_IS_OK(status)) {
		vfs_ChDir(handle->conn, handle->conn->connectpath);
		return status;
	}
	vfs_ChDir(handle->conn, handle->conn->connectpath);

	if (!self_referral) {
		pathnamep[consumedcnt] = '\0';

		if (DEBUGLVL(3)) {
			dbgtext("setup_dfs_referral: Path %s to "
				"alternate path(s):",
				pathnamep);
			for (i=0; i < junction->referral_count; i++) {
				dbgtext(" %s",
				junction->referral_list[i].alternate_path);
			}
			dbgtext(".\n");
		}
	}

	if (r->in.req.max_referral_level <= 2) {
		max_referral_level = 2;
	}
	if (r->in.req.max_referral_level >= 3) {
		max_referral_level = 3;
	}

	r->out.resp = talloc_zero(r, struct dfs_referral_resp);
	if (r->out.resp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->out.resp->path_consumed = strlen_m(pathnamep) * 2;
	r->out.resp->nb_referrals = junction->referral_count;

	r->out.resp->header_flags = DFS_HEADER_FLAG_STORAGE_SVR;
	if (self_referral) {
		r->out.resp->header_flags |= DFS_HEADER_FLAG_REFERAL_SVR;
	}

	r->out.resp->referral_entries = talloc_zero_array(r,
				struct dfs_referral_type,
				r->out.resp->nb_referrals);
	if (r->out.resp->referral_entries == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	switch (max_referral_level) {
	case 2:
		for(i=0; i < junction->referral_count; i++) {
			struct referral *ref = &junction->referral_list[i];
			TALLOC_CTX *mem_ctx = r->out.resp->referral_entries;
			struct dfs_referral_type *t =
				&r->out.resp->referral_entries[i];
			struct dfs_referral_v2 *v2 = &t->referral.v2;

			t->version = 2;
			v2->size = VERSION2_REFERRAL_SIZE;
			if (self_referral) {
				v2->server_type = DFS_SERVER_ROOT;
			} else {
				v2->server_type = DFS_SERVER_NON_ROOT;
			}
			v2->entry_flags = 0;
			v2->proximity = ref->proximity;
			v2->ttl = ref->ttl;
			v2->DFS_path = talloc_strdup(mem_ctx, pathnamep);
			if (v2->DFS_path == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			v2->DFS_alt_path = talloc_strdup(mem_ctx, pathnamep);
			if (v2->DFS_alt_path == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			v2->netw_address = talloc_strdup(mem_ctx,
							 ref->alternate_path);
			if (v2->netw_address == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}

		break;
	case 3:
		for(i=0; i < junction->referral_count; i++) {
			struct referral *ref = &junction->referral_list[i];
			TALLOC_CTX *mem_ctx = r->out.resp->referral_entries;
			struct dfs_referral_type *t =
				&r->out.resp->referral_entries[i];
			struct dfs_referral_v3 *v3 = &t->referral.v3;
			struct dfs_normal_referral *r1 = &v3->referrals.r1;

			t->version = 3;
			v3->size = VERSION3_REFERRAL_SIZE;
			if (self_referral) {
				v3->server_type = DFS_SERVER_ROOT;
			} else {
				v3->server_type = DFS_SERVER_NON_ROOT;
			}
			v3->entry_flags = 0;
			v3->ttl = ref->ttl;
			r1->DFS_path = talloc_strdup(mem_ctx, pathnamep);
			if (r1->DFS_path == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			r1->DFS_alt_path = talloc_strdup(mem_ctx, pathnamep);
			if (r1->DFS_alt_path == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			r1->netw_address = talloc_strdup(mem_ctx,
							 ref->alternate_path);
			if (r1->netw_address == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
		}
		break;
	default:
		DEBUG(0,("setup_dfs_referral: Invalid dfs referral "
			"version: %d\n",
			max_referral_level));
		return NT_STATUS_INVALID_LEVEL;
	}

	if (DEBUGLVL(10)) {
		NDR_PRINT_OUT_DEBUG(dfs_GetDFSReferral, r);
	}

	return NT_STATUS_OK;
}

/* Directory operations */

static DIR *vfswrap_opendir(vfs_handle_struct *handle,  const char *fname, const char *mask, uint32 attr)
{
	DIR *result;

	START_PROFILE(syscall_opendir);
	result = opendir(fname);
	END_PROFILE(syscall_opendir);
	return result;
}

static DIR *vfswrap_fdopendir(vfs_handle_struct *handle,
			files_struct *fsp,
			const char *mask,
			uint32 attr)
{
	DIR *result;

	START_PROFILE(syscall_fdopendir);
	result = sys_fdopendir(fsp->fh->fd);
	END_PROFILE(syscall_fdopendir);
	return result;
}


static struct dirent *vfswrap_readdir(vfs_handle_struct *handle,
				          DIR *dirp,
					  SMB_STRUCT_STAT *sbuf)
{
	struct dirent *result;

	START_PROFILE(syscall_readdir);
	result = readdir(dirp);
	/* Default Posix readdir() does not give us stat info.
	 * Set to invalid to indicate we didn't return this info. */
	if (sbuf)
		SET_STAT_INVALID(*sbuf);
	END_PROFILE(syscall_readdir);
	return result;
}

static void vfswrap_seekdir(vfs_handle_struct *handle,  DIR *dirp, long offset)
{
	START_PROFILE(syscall_seekdir);
	seekdir(dirp, offset);
	END_PROFILE(syscall_seekdir);
}

static long vfswrap_telldir(vfs_handle_struct *handle,  DIR *dirp)
{
	long result;
	START_PROFILE(syscall_telldir);
	result = telldir(dirp);
	END_PROFILE(syscall_telldir);
	return result;
}

static void vfswrap_rewinddir(vfs_handle_struct *handle,  DIR *dirp)
{
	START_PROFILE(syscall_rewinddir);
	rewinddir(dirp);
	END_PROFILE(syscall_rewinddir);
}

static int vfswrap_mkdir(vfs_handle_struct *handle,  const char *path, mode_t mode)
{
	int result;
	bool has_dacl = False;
	char *parent = NULL;

	START_PROFILE(syscall_mkdir);

	if (lp_inherit_acls(SNUM(handle->conn))
	    && parent_dirname(talloc_tos(), path, &parent, NULL)
	    && (has_dacl = directory_has_default_acl(handle->conn, parent)))
		mode = (0777 & lp_dir_mask(SNUM(handle->conn)));

	TALLOC_FREE(parent);

	result = mkdir(path, mode);

	if (result == 0 && !has_dacl) {
		/*
		 * We need to do this as the default behavior of POSIX ACLs
		 * is to set the mask to be the requested group permission
		 * bits, not the group permission bits to be the requested
		 * group permission bits. This is not what we want, as it will
		 * mess up any inherited ACL bits that were set. JRA.
		 */
		int saved_errno = errno; /* We may get ENOSYS */
		if ((SMB_VFS_CHMOD_ACL(handle->conn, path, mode) == -1) && (errno == ENOSYS))
			errno = saved_errno;
	}

	END_PROFILE(syscall_mkdir);
	return result;
}

static int vfswrap_rmdir(vfs_handle_struct *handle,  const char *path)
{
	int result;

	START_PROFILE(syscall_rmdir);
	result = rmdir(path);
	END_PROFILE(syscall_rmdir);
	return result;
}

static int vfswrap_closedir(vfs_handle_struct *handle,  DIR *dirp)
{
	int result;

	START_PROFILE(syscall_closedir);
	result = closedir(dirp);
	END_PROFILE(syscall_closedir);
	return result;
}

static void vfswrap_init_search_op(vfs_handle_struct *handle,
				   DIR *dirp)
{
	/* Default behavior is a NOOP */
}

/* File operations */

static int vfswrap_open(vfs_handle_struct *handle,
			struct smb_filename *smb_fname,
			files_struct *fsp, int flags, mode_t mode)
{
	int result = -1;

	START_PROFILE(syscall_open);

	if (smb_fname->stream_name) {
		errno = ENOENT;
		goto out;
	}

	result = open(smb_fname->base_name, flags, mode);
 out:
	END_PROFILE(syscall_open);
	return result;
}

static NTSTATUS vfswrap_create_file(vfs_handle_struct *handle,
				    struct smb_request *req,
				    uint16_t root_dir_fid,
				    struct smb_filename *smb_fname,
				    uint32_t access_mask,
				    uint32_t share_access,
				    uint32_t create_disposition,
				    uint32_t create_options,
				    uint32_t file_attributes,
				    uint32_t oplock_request,
				    uint64_t allocation_size,
				    uint32_t private_flags,
				    struct security_descriptor *sd,
				    struct ea_list *ea_list,
				    files_struct **result,
				    int *pinfo)
{
	return create_file_default(handle->conn, req, root_dir_fid, smb_fname,
				   access_mask, share_access,
				   create_disposition, create_options,
				   file_attributes, oplock_request,
				   allocation_size, private_flags,
				   sd, ea_list, result,
				   pinfo);
}

static int vfswrap_close(vfs_handle_struct *handle, files_struct *fsp)
{
	int result;

	START_PROFILE(syscall_close);
	result = fd_close_posix(fsp);
	END_PROFILE(syscall_close);
	return result;
}

static ssize_t vfswrap_read(vfs_handle_struct *handle, files_struct *fsp, void *data, size_t n)
{
	ssize_t result;

	START_PROFILE_BYTES(syscall_read, n);
	result = sys_read(fsp->fh->fd, data, n);
	END_PROFILE(syscall_read);
	return result;
}

static ssize_t vfswrap_pread(vfs_handle_struct *handle, files_struct *fsp, void *data,
			size_t n, off_t offset)
{
	ssize_t result;

#if defined(HAVE_PREAD) || defined(HAVE_PREAD64)
	START_PROFILE_BYTES(syscall_pread, n);
	result = sys_pread(fsp->fh->fd, data, n, offset);
	END_PROFILE(syscall_pread);

	if (result == -1 && errno == ESPIPE) {
		/* Maintain the fiction that pipes can be seeked (sought?) on. */
		result = SMB_VFS_READ(fsp, data, n);
		fsp->fh->pos = 0;
	}

#else /* HAVE_PREAD */
	off_t   curr;
	int lerrno;

	curr = SMB_VFS_LSEEK(fsp, 0, SEEK_CUR);
	if (curr == -1 && errno == ESPIPE) {
		/* Maintain the fiction that pipes can be seeked (sought?) on. */
		result = SMB_VFS_READ(fsp, data, n);
		fsp->fh->pos = 0;
		return result;
	}

	if (SMB_VFS_LSEEK(fsp, offset, SEEK_SET) == -1) {
		return -1;
	}

	errno = 0;
	result = SMB_VFS_READ(fsp, data, n);
	lerrno = errno;

	SMB_VFS_LSEEK(fsp, curr, SEEK_SET);
	errno = lerrno;

#endif /* HAVE_PREAD */

	return result;
}

static ssize_t vfswrap_write(vfs_handle_struct *handle, files_struct *fsp, const void *data, size_t n)
{
	ssize_t result;

	START_PROFILE_BYTES(syscall_write, n);
	result = sys_write(fsp->fh->fd, data, n);
	END_PROFILE(syscall_write);
	return result;
}

static ssize_t vfswrap_pwrite(vfs_handle_struct *handle, files_struct *fsp, const void *data,
			size_t n, off_t offset)
{
	ssize_t result;

#if defined(HAVE_PWRITE) || defined(HAVE_PRWITE64)
	START_PROFILE_BYTES(syscall_pwrite, n);
	result = sys_pwrite(fsp->fh->fd, data, n, offset);
	END_PROFILE(syscall_pwrite);

	if (result == -1 && errno == ESPIPE) {
		/* Maintain the fiction that pipes can be sought on. */
		result = SMB_VFS_WRITE(fsp, data, n);
	}

#else /* HAVE_PWRITE */
	off_t   curr;
	int         lerrno;

	curr = SMB_VFS_LSEEK(fsp, 0, SEEK_CUR);
	if (curr == -1) {
		return -1;
	}

	if (SMB_VFS_LSEEK(fsp, offset, SEEK_SET) == -1) {
		return -1;
	}

	result = SMB_VFS_WRITE(fsp, data, n);
	lerrno = errno;

	SMB_VFS_LSEEK(fsp, curr, SEEK_SET);
	errno = lerrno;

#endif /* HAVE_PWRITE */

	return result;
}

static void vfswrap_asys_finished(struct tevent_context *ev,
				  struct tevent_fd *fde,
				  uint16_t flags, void *p);

static bool vfswrap_init_asys_ctx(struct smbXsrv_connection *conn)
{
	int ret;
	int fd;

	if (conn->asys_ctx != NULL) {
		return true;
	}
	ret = asys_context_init(&conn->asys_ctx, aio_pending_size);
	if (ret != 0) {
		DEBUG(1, ("asys_context_init failed: %s\n", strerror(ret)));
		return false;
	}

	fd = asys_signalfd(conn->asys_ctx);

	set_blocking(fd, false);

	conn->asys_fde = tevent_add_fd(conn->ev_ctx, conn, fd,
				       TEVENT_FD_READ,
				       vfswrap_asys_finished,
				       conn->asys_ctx);
	if (conn->asys_fde == NULL) {
		DEBUG(1, ("tevent_add_fd failed\n"));
		asys_context_destroy(conn->asys_ctx);
		conn->asys_ctx = NULL;
		return false;
	}
	return true;
}

struct vfswrap_asys_state {
	struct asys_context *asys_ctx;
	struct tevent_req *req;
	ssize_t ret;
	int err;
};

static int vfswrap_asys_state_destructor(struct vfswrap_asys_state *s)
{
	asys_cancel(s->asys_ctx, s->req);
	return 0;
}

static struct tevent_req *vfswrap_pread_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     void *data,
					     size_t n, off_t offset)
{
	struct tevent_req *req;
	struct vfswrap_asys_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct vfswrap_asys_state);
	if (req == NULL) {
		return NULL;
	}
	if (!vfswrap_init_asys_ctx(handle->conn->sconn->conn)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}
	state->asys_ctx = handle->conn->sconn->conn->asys_ctx;
	state->req = req;

	ret = asys_pread(state->asys_ctx, fsp->fh->fd, data, n, offset, req);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(state, vfswrap_asys_state_destructor);

	return req;
}

static struct tevent_req *vfswrap_pwrite_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      const void *data,
					      size_t n, off_t offset)
{
	struct tevent_req *req;
	struct vfswrap_asys_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct vfswrap_asys_state);
	if (req == NULL) {
		return NULL;
	}
	if (!vfswrap_init_asys_ctx(handle->conn->sconn->conn)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}
	state->asys_ctx = handle->conn->sconn->conn->asys_ctx;
	state->req = req;

	ret = asys_pwrite(state->asys_ctx, fsp->fh->fd, data, n, offset, req);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(state, vfswrap_asys_state_destructor);

	return req;
}

static struct tevent_req *vfswrap_fsync_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp)
{
	struct tevent_req *req;
	struct vfswrap_asys_state *state;
	int ret;

	req = tevent_req_create(mem_ctx, &state, struct vfswrap_asys_state);
	if (req == NULL) {
		return NULL;
	}
	if (!vfswrap_init_asys_ctx(handle->conn->sconn->conn)) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}
	state->asys_ctx = handle->conn->sconn->conn->asys_ctx;
	state->req = req;

	ret = asys_fsync(state->asys_ctx, fsp->fh->fd, req);
	if (ret != 0) {
		tevent_req_error(req, ret);
		return tevent_req_post(req, ev);
	}
	talloc_set_destructor(state, vfswrap_asys_state_destructor);

	return req;
}

static void vfswrap_asys_finished(struct tevent_context *ev,
					struct tevent_fd *fde,
					uint16_t flags, void *p)
{
	struct asys_context *asys_ctx = (struct asys_context *)p;
	struct tevent_req *req;
	struct vfswrap_asys_state *state;
	int res;
	ssize_t ret;
	int err;
	void *private_data;

	if ((flags & TEVENT_FD_READ) == 0) {
		return;
	}

	while (true) {
		res = asys_result(asys_ctx, &ret, &err, &private_data);
		if (res == EINTR || res == EAGAIN) {
			return;
		}
#ifdef EWOULDBLOCK
		if (res == EWOULDBLOCK) {
			return;
		}
#endif

		if (res == ECANCELED) {
			return;
		}

		if (res != 0) {
			DEBUG(1, ("asys_result returned %s\n", strerror(res)));
			return;
		}

		req = talloc_get_type_abort(private_data, struct tevent_req);
		state = tevent_req_data(req, struct vfswrap_asys_state);

		talloc_set_destructor(state, NULL);

		state->ret = ret;
		state->err = err;
		tevent_req_defer_callback(req, ev);
		tevent_req_done(req);
	}
}

static ssize_t vfswrap_asys_ssize_t_recv(struct tevent_req *req, int *err)
{
	struct vfswrap_asys_state *state = tevent_req_data(
		req, struct vfswrap_asys_state);

	if (tevent_req_is_unix_error(req, err)) {
		return -1;
	}
	*err = state->err;
	return state->ret;
}

static int vfswrap_asys_int_recv(struct tevent_req *req, int *err)
{
	struct vfswrap_asys_state *state = tevent_req_data(
		req, struct vfswrap_asys_state);

	if (tevent_req_is_unix_error(req, err)) {
		return -1;
	}
	*err = state->err;
	return state->ret;
}

static off_t vfswrap_lseek(vfs_handle_struct *handle, files_struct *fsp, off_t offset, int whence)
{
	off_t result = 0;

	START_PROFILE(syscall_lseek);

	/* Cope with 'stat' file opens. */
	if (fsp->fh->fd != -1)
		result = lseek(fsp->fh->fd, offset, whence);

	/*
	 * We want to maintain the fiction that we can seek
	 * on a fifo for file system purposes. This allows
	 * people to set up UNIX fifo's that feed data to Windows
	 * applications. JRA.
	 */

	if((result == -1) && (errno == ESPIPE)) {
		result = 0;
		errno = 0;
	}

	END_PROFILE(syscall_lseek);
	return result;
}

static ssize_t vfswrap_sendfile(vfs_handle_struct *handle, int tofd, files_struct *fromfsp, const DATA_BLOB *hdr,
			off_t offset, size_t n)
{
	ssize_t result;

	START_PROFILE_BYTES(syscall_sendfile, n);
	result = sys_sendfile(tofd, fromfsp->fh->fd, hdr, offset, n);
	END_PROFILE(syscall_sendfile);
	return result;
}

static ssize_t vfswrap_recvfile(vfs_handle_struct *handle,
			int fromfd,
			files_struct *tofsp,
			off_t offset,
			size_t n)
{
	ssize_t result;

	START_PROFILE_BYTES(syscall_recvfile, n);
	result = sys_recvfile(fromfd, tofsp->fh->fd, offset, n);
	END_PROFILE(syscall_recvfile);
	return result;
}

static int vfswrap_rename(vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname_src,
			  const struct smb_filename *smb_fname_dst)
{
	int result = -1;

	START_PROFILE(syscall_rename);

	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		errno = ENOENT;
		goto out;
	}

	result = rename(smb_fname_src->base_name, smb_fname_dst->base_name);

 out:
	END_PROFILE(syscall_rename);
	return result;
}

static int vfswrap_fsync(vfs_handle_struct *handle, files_struct *fsp)
{
#ifdef HAVE_FSYNC
	int result;

	START_PROFILE(syscall_fsync);
	result = fsync(fsp->fh->fd);
	END_PROFILE(syscall_fsync);
	return result;
#else
	return 0;
#endif
}

static int vfswrap_stat(vfs_handle_struct *handle,
			struct smb_filename *smb_fname)
{
	int result = -1;

	START_PROFILE(syscall_stat);

	if (smb_fname->stream_name) {
		errno = ENOENT;
		goto out;
	}

	result = sys_stat(smb_fname->base_name, &smb_fname->st,
			  lp_fake_dir_create_times(SNUM(handle->conn)));
 out:
	END_PROFILE(syscall_stat);
	return result;
}

static int vfswrap_fstat(vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int result;

	START_PROFILE(syscall_fstat);
	result = sys_fstat(fsp->fh->fd,
			   sbuf, lp_fake_dir_create_times(SNUM(handle->conn)));
	END_PROFILE(syscall_fstat);
	return result;
}

static int vfswrap_lstat(vfs_handle_struct *handle,
			 struct smb_filename *smb_fname)
{
	int result = -1;

	START_PROFILE(syscall_lstat);

	if (smb_fname->stream_name) {
		errno = ENOENT;
		goto out;
	}

	result = sys_lstat(smb_fname->base_name, &smb_fname->st,
			   lp_fake_dir_create_times(SNUM(handle->conn)));
 out:
	END_PROFILE(syscall_lstat);
	return result;
}

static NTSTATUS vfswrap_translate_name(struct vfs_handle_struct *handle,
				       const char *name,
				       enum vfs_translate_direction direction,
				       TALLOC_CTX *mem_ctx,
				       char **mapped_name)
{
	return NT_STATUS_NONE_MAPPED;
}

/*
 * Implement the default fsctl operation.
 */
static bool vfswrap_logged_ioctl_message = false;

static NTSTATUS vfswrap_fsctl(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      TALLOC_CTX *ctx,
			      uint32_t function,
			      uint16_t req_flags,  /* Needed for UNICODE ... */
			      const uint8_t *_in_data,
			      uint32_t in_len,
			      uint8_t **_out_data,
			      uint32_t max_out_len,
			      uint32_t *out_len)
{
	const char *in_data = (const char *)_in_data;
	char **out_data = (char **)_out_data;

	switch (function) {
	case FSCTL_SET_SPARSE:
	{
		bool set_sparse = true;
		NTSTATUS status;

		if (in_len >= 1 && in_data[0] == 0) {
			set_sparse = false;
		}

		status = file_set_sparse(handle->conn, fsp, set_sparse);
		
		DEBUG(NT_STATUS_IS_OK(status) ? 10 : 9,
		      ("FSCTL_SET_SPARSE: fname[%s] set[%u] - %s\n",
		       smb_fname_str_dbg(fsp->fsp_name), set_sparse, 
		       nt_errstr(status)));

		return status;
	}

	case FSCTL_CREATE_OR_GET_OBJECT_ID:
	{
		unsigned char objid[16];
		char *return_data = NULL;

		/* This should return the object-id on this file.
		 * I think I'll make this be the inode+dev. JRA.
		 */

		DEBUG(10,("FSCTL_CREATE_OR_GET_OBJECT_ID: called on %s\n",
			  fsp_fnum_dbg(fsp)));

		*out_len = (max_out_len >= 64) ? 64 : max_out_len;
		/* Hmmm, will this cause problems if less data asked for? */
		return_data = talloc_array(ctx, char, 64);
		if (return_data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		/* For backwards compatibility only store the dev/inode. */
		push_file_id_16(return_data, &fsp->file_id);
		memcpy(return_data+16,create_volume_objectid(fsp->conn,objid),16);
		push_file_id_16(return_data+32, &fsp->file_id);
		*out_data = return_data;
		return NT_STATUS_OK;
	}

	case FSCTL_GET_REPARSE_POINT:
	{
		/* Fail it with STATUS_NOT_A_REPARSE_POINT */
		DEBUG(10, ("FSCTL_GET_REPARSE_POINT: called on %s. "
			   "Status: NOT_IMPLEMENTED\n", fsp_fnum_dbg(fsp)));
		return NT_STATUS_NOT_A_REPARSE_POINT;
	}

	case FSCTL_SET_REPARSE_POINT:
	{
		/* Fail it with STATUS_NOT_A_REPARSE_POINT */
		DEBUG(10, ("FSCTL_SET_REPARSE_POINT: called on %s. "
			   "Status: NOT_IMPLEMENTED\n", fsp_fnum_dbg(fsp)));
		return NT_STATUS_NOT_A_REPARSE_POINT;
	}

	case FSCTL_GET_SHADOW_COPY_DATA:
	{
		/*
		 * This is called to retrieve the number of Shadow Copies (a.k.a. snapshots)
		 * and return their volume names.  If max_data_count is 16, then it is just
		 * asking for the number of volumes and length of the combined names.
		 *
		 * pdata is the data allocated by our caller, but that uses
		 * total_data_count (which is 0 in our case) rather than max_data_count.
		 * Allocate the correct amount and return the pointer to let
		 * it be deallocated when we return.
		 */
		struct shadow_copy_data *shadow_data = NULL;
		bool labels = False;
		uint32 labels_data_count = 0;
		uint32 i;
		char *cur_pdata = NULL;

		if (max_out_len < 16) {
			DEBUG(0,("FSCTL_GET_SHADOW_COPY_DATA: max_data_count(%u) < 16 is invalid!\n",
				max_out_len));
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (max_out_len > 16) {
			labels = True;
		}

		shadow_data = talloc_zero(ctx, struct shadow_copy_data);
		if (shadow_data == NULL) {
			DEBUG(0,("TALLOC_ZERO() failed!\n"));
			return NT_STATUS_NO_MEMORY;
		}

		/*
		 * Call the VFS routine to actually do the work.
		 */
		if (SMB_VFS_GET_SHADOW_COPY_DATA(fsp, shadow_data, labels)!=0) {
			TALLOC_FREE(shadow_data);
			if (errno == ENOSYS) {
				DEBUG(5,("FSCTL_GET_SHADOW_COPY_DATA: connectpath %s, not supported.\n", 
					fsp->conn->connectpath));
				return NT_STATUS_NOT_SUPPORTED;
			} else {
				DEBUG(0,("FSCTL_GET_SHADOW_COPY_DATA: connectpath %s, failed.\n", 
					fsp->conn->connectpath));
				return NT_STATUS_UNSUCCESSFUL;
			}
		}

		labels_data_count = (shadow_data->num_volumes * 2 * 
					sizeof(SHADOW_COPY_LABEL)) + 2;

		if (!labels) {
			*out_len = 16;
		} else {
			*out_len = 12 + labels_data_count + 4;
		}

		if (max_out_len < *out_len) {
			DEBUG(0,("FSCTL_GET_SHADOW_COPY_DATA: max_data_count(%u) too small (%u) bytes needed!\n",
				max_out_len, *out_len));
			TALLOC_FREE(shadow_data);
			return NT_STATUS_BUFFER_TOO_SMALL;
		}

		cur_pdata = talloc_array(ctx, char, *out_len);
		if (cur_pdata == NULL) {
			TALLOC_FREE(shadow_data);
			return NT_STATUS_NO_MEMORY;
		}

		*out_data = cur_pdata;

		/* num_volumes 4 bytes */
		SIVAL(cur_pdata, 0, shadow_data->num_volumes);

		if (labels) {
			/* num_labels 4 bytes */
			SIVAL(cur_pdata, 4, shadow_data->num_volumes);
		}

		/* needed_data_count 4 bytes */
		SIVAL(cur_pdata, 8, labels_data_count + 4);

		cur_pdata += 12;

		DEBUG(10,("FSCTL_GET_SHADOW_COPY_DATA: %u volumes for path[%s].\n",
			  shadow_data->num_volumes, fsp_str_dbg(fsp)));
		if (labels && shadow_data->labels) {
			for (i=0; i<shadow_data->num_volumes; i++) {
				srvstr_push(cur_pdata, req_flags,
					    cur_pdata, shadow_data->labels[i],
					    2 * sizeof(SHADOW_COPY_LABEL),
					    STR_UNICODE|STR_TERMINATE);
				cur_pdata += 2 * sizeof(SHADOW_COPY_LABEL);
				DEBUGADD(10,("Label[%u]: '%s'\n",i,shadow_data->labels[i]));
			}
		}

		TALLOC_FREE(shadow_data);

		return NT_STATUS_OK;
	}

	case FSCTL_FIND_FILES_BY_SID:
	{
		/* pretend this succeeded -
		 *
		 * we have to send back a list with all files owned by this SID
		 *
		 * but I have to check that --metze
		 */
		struct dom_sid sid;
		uid_t uid;
		size_t sid_len;

		DEBUG(10, ("FSCTL_FIND_FILES_BY_SID: called on %s\n",
			   fsp_fnum_dbg(fsp)));

		if (in_len < 8) {
			/* NT_STATUS_BUFFER_TOO_SMALL maybe? */
			return NT_STATUS_INVALID_PARAMETER;
		}

		sid_len = MIN(in_len - 4,SID_MAX_SIZE);

		/* unknown 4 bytes: this is not the length of the sid :-(  */
		/*unknown = IVAL(pdata,0);*/

		if (!sid_parse(in_data + 4, sid_len, &sid)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		DEBUGADD(10, ("for SID: %s\n", sid_string_dbg(&sid)));

		if (!sid_to_uid(&sid, &uid)) {
			DEBUG(0,("sid_to_uid: failed, sid[%s] sid_len[%lu]\n",
				 sid_string_dbg(&sid),
				 (unsigned long)sid_len));
			uid = (-1);
		}

		/* we can take a look at the find source :-)
		 *
		 * find ./ -uid $uid  -name '*'   is what we need here
		 *
		 *
		 * and send 4bytes len and then NULL terminated unicode strings
		 * for each file
		 *
		 * but I don't know how to deal with the paged results
		 * (maybe we can hang the result anywhere in the fsp struct)
		 *
		 * but I don't know how to deal with the paged results
		 * (maybe we can hang the result anywhere in the fsp struct)
		 *
		 * we don't send all files at once
		 * and at the next we should *not* start from the beginning,
		 * so we have to cache the result
		 *
		 * --metze
		 */

		/* this works for now... */
		return NT_STATUS_OK;
	}

	case FSCTL_QUERY_ALLOCATED_RANGES:
	{
		/* FIXME: This is just a dummy reply, telling that all of the
		 * file is allocated. MKS cp needs that.
		 * Adding the real allocated ranges via FIEMAP on Linux
		 * and SEEK_DATA/SEEK_HOLE on Solaris is needed to make
		 * this FSCTL correct for sparse files.
		 */
		NTSTATUS status;
		uint64_t offset, length;
		char *out_data_tmp = NULL;

		if (in_len != 16) {
			DEBUG(0,("FSCTL_QUERY_ALLOCATED_RANGES: data_count(%u) != 16 is invalid!\n",
				in_len));
			return NT_STATUS_INVALID_PARAMETER;
		}

		if (max_out_len < 16) {
			DEBUG(0,("FSCTL_QUERY_ALLOCATED_RANGES: max_out_len (%u) < 16 is invalid!\n",
				max_out_len));
			return NT_STATUS_INVALID_PARAMETER;
		}

		offset = BVAL(in_data,0);
		length = BVAL(in_data,8);

		if (offset + length < offset) {
			/* No 64-bit integer wrap. */
			return NT_STATUS_INVALID_PARAMETER;
		}

		/* Shouldn't this be SMB_VFS_STAT ... ? */
		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		*out_len = 16;
		out_data_tmp = talloc_array(ctx, char, *out_len);
		if (out_data_tmp == NULL) {
			DEBUG(10, ("unable to allocate memory for response\n"));
			return NT_STATUS_NO_MEMORY;
		}

		if (offset > fsp->fsp_name->st.st_ex_size ||
				fsp->fsp_name->st.st_ex_size == 0 ||
				length == 0) {
			memset(out_data_tmp, 0, *out_len);
		} else {
			uint64_t end = offset + length;
			end = MIN(end, fsp->fsp_name->st.st_ex_size);
			SBVAL(out_data_tmp, 0, 0);
			SBVAL(out_data_tmp, 8, end);
		}

		*out_data = out_data_tmp;

		return NT_STATUS_OK;
	}

	case FSCTL_IS_VOLUME_DIRTY:
	{
		DEBUG(10,("FSCTL_IS_VOLUME_DIRTY: called on %s "
			  "(but remotely not supported)\n", fsp_fnum_dbg(fsp)));
		/*
		 * http://msdn.microsoft.com/en-us/library/cc232128%28PROT.10%29.aspx
		 * says we have to respond with NT_STATUS_INVALID_PARAMETER
		 */
		return NT_STATUS_INVALID_PARAMETER;
	}

	default:
		/* 
		 * Only print once ... unfortunately there could be lots of
		 * different FSCTLs that are called.
		 */
		if (!vfswrap_logged_ioctl_message) {
			vfswrap_logged_ioctl_message = true;
			DEBUG(2, ("%s (0x%x): Currently not implemented.\n",
			__func__, function));
		}
	}

	return NT_STATUS_NOT_SUPPORTED;
}

/********************************************************************
 Given a stat buffer return the allocated size on disk, taking into
 account sparse files.
********************************************************************/
static uint64_t vfswrap_get_alloc_size(vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       const SMB_STRUCT_STAT *sbuf)
{
	uint64_t result;

	START_PROFILE(syscall_get_alloc_size);

	if(S_ISDIR(sbuf->st_ex_mode)) {
		result = 0;
		goto out;
	}

#if defined(HAVE_STAT_ST_BLOCKS) && defined(STAT_ST_BLOCKSIZE)
	/* The type of st_blocksize is blkcnt_t which *MUST* be
	   signed (according to POSIX) and can be less than 64-bits.
	   Ensure when we're converting to 64 bits wide we don't
	   sign extend. */
#if defined(SIZEOF_BLKCNT_T_8)
	result = (uint64_t)STAT_ST_BLOCKSIZE * (uint64_t)sbuf->st_ex_blocks;
#elif defined(SIZEOF_BLKCNT_T_4)
	{
		uint64_t bs = ((uint64_t)sbuf->st_ex_blocks) & 0xFFFFFFFFLL;
		result = (uint64_t)STAT_ST_BLOCKSIZE * bs;
	}
#else
#error SIZEOF_BLKCNT_T_NOT_A_SUPPORTED_VALUE
#endif
#else
	result = get_file_size_stat(sbuf);
#endif

	if (fsp && fsp->initial_allocation_size)
		result = MAX(result,fsp->initial_allocation_size);

	result = smb_roundup(handle->conn, result);

 out:
	END_PROFILE(syscall_get_alloc_size);
	return result;
}

static int vfswrap_unlink(vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname)
{
	int result = -1;

	START_PROFILE(syscall_unlink);

	if (smb_fname->stream_name) {
		errno = ENOENT;
		goto out;
	}
	result = unlink(smb_fname->base_name);

 out:
	END_PROFILE(syscall_unlink);
	return result;
}

static int vfswrap_chmod(vfs_handle_struct *handle,  const char *path, mode_t mode)
{
	int result;

	START_PROFILE(syscall_chmod);

	/*
	 * We need to do this due to the fact that the default POSIX ACL
	 * chmod modifies the ACL *mask* for the group owner, not the
	 * group owner bits directly. JRA.
	 */


	{
		int saved_errno = errno; /* We might get ENOSYS */
		if ((result = SMB_VFS_CHMOD_ACL(handle->conn, path, mode)) == 0) {
			END_PROFILE(syscall_chmod);
			return result;
		}
		/* Error - return the old errno. */
		errno = saved_errno;
	}

	result = chmod(path, mode);
	END_PROFILE(syscall_chmod);
	return result;
}

static int vfswrap_fchmod(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	int result;

	START_PROFILE(syscall_fchmod);

	/*
	 * We need to do this due to the fact that the default POSIX ACL
	 * chmod modifies the ACL *mask* for the group owner, not the
	 * group owner bits directly. JRA.
	 */

	{
		int saved_errno = errno; /* We might get ENOSYS */
		if ((result = SMB_VFS_FCHMOD_ACL(fsp, mode)) == 0) {
			END_PROFILE(syscall_fchmod);
			return result;
		}
		/* Error - return the old errno. */
		errno = saved_errno;
	}

#if defined(HAVE_FCHMOD)
	result = fchmod(fsp->fh->fd, mode);
#else
	result = -1;
	errno = ENOSYS;
#endif

	END_PROFILE(syscall_fchmod);
	return result;
}

static int vfswrap_chown(vfs_handle_struct *handle, const char *path, uid_t uid, gid_t gid)
{
	int result;

	START_PROFILE(syscall_chown);
	result = chown(path, uid, gid);
	END_PROFILE(syscall_chown);
	return result;
}

static int vfswrap_fchown(vfs_handle_struct *handle, files_struct *fsp, uid_t uid, gid_t gid)
{
#ifdef HAVE_FCHOWN
	int result;

	START_PROFILE(syscall_fchown);
	result = fchown(fsp->fh->fd, uid, gid);
	END_PROFILE(syscall_fchown);
	return result;
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int vfswrap_lchown(vfs_handle_struct *handle, const char *path, uid_t uid, gid_t gid)
{
	int result;

	START_PROFILE(syscall_lchown);
	result = lchown(path, uid, gid);
	END_PROFILE(syscall_lchown);
	return result;
}

static int vfswrap_chdir(vfs_handle_struct *handle,  const char *path)
{
	int result;

	START_PROFILE(syscall_chdir);
	result = chdir(path);
	END_PROFILE(syscall_chdir);
	return result;
}

static char *vfswrap_getwd(vfs_handle_struct *handle)
{
	char *result;

	START_PROFILE(syscall_getwd);
	result = sys_getwd();
	END_PROFILE(syscall_getwd);
	return result;
}

/*********************************************************************
 nsec timestamp resolution call. Convert down to whatever the underlying
 system will support.
**********************************************************************/

static int vfswrap_ntimes(vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname,
			  struct smb_file_time *ft)
{
	int result = -1;

	START_PROFILE(syscall_ntimes);

	if (smb_fname->stream_name) {
		errno = ENOENT;
		goto out;
	}

	if (ft != NULL) {
		if (null_timespec(ft->atime)) {
			ft->atime= smb_fname->st.st_ex_atime;
		}

		if (null_timespec(ft->mtime)) {
			ft->mtime = smb_fname->st.st_ex_mtime;
		}

		if (!null_timespec(ft->create_time)) {
			set_create_timespec_ea(handle->conn,
					       smb_fname,
					       ft->create_time);
		}

		if ((timespec_compare(&ft->atime,
				      &smb_fname->st.st_ex_atime) == 0) &&
		    (timespec_compare(&ft->mtime,
				      &smb_fname->st.st_ex_mtime) == 0)) {
			return 0;
		}
	}

#if defined(HAVE_UTIMENSAT)
	if (ft != NULL) {
		struct timespec ts[2];
		ts[0] = ft->atime;
		ts[1] = ft->mtime;
		result = utimensat(AT_FDCWD, smb_fname->base_name, ts, 0);
	} else {
		result = utimensat(AT_FDCWD, smb_fname->base_name, NULL, 0);
	}
	if (!((result == -1) && (errno == ENOSYS))) {
		goto out;
	}
#endif
#if defined(HAVE_UTIMES)
	if (ft != NULL) {
		struct timeval tv[2];
		tv[0] = convert_timespec_to_timeval(ft->atime);
		tv[1] = convert_timespec_to_timeval(ft->mtime);
		result = utimes(smb_fname->base_name, tv);
	} else {
		result = utimes(smb_fname->base_name, NULL);
	}
	if (!((result == -1) && (errno == ENOSYS))) {
		goto out;
	}
#endif
#if defined(HAVE_UTIME)
	if (ft != NULL) {
		struct utimbuf times;
		times.actime = convert_timespec_to_time_t(ft->atime);
		times.modtime = convert_timespec_to_time_t(ft->mtime);
		result = utime(smb_fname->base_name, &times);
	} else {
		result = utime(smb_fname->base_name, NULL);
	}
	if (!((result == -1) && (errno == ENOSYS))) {
		goto out;
	}
#endif
	errno = ENOSYS;
	result = -1;

 out:
	END_PROFILE(syscall_ntimes);
	return result;
}

/*********************************************************************
 A version of ftruncate that will write the space on disk if strict
 allocate is set.
**********************************************************************/

static int strict_allocate_ftruncate(vfs_handle_struct *handle, files_struct *fsp, off_t len)
{
	off_t space_to_write;
	uint64_t space_avail;
	uint64_t bsize,dfree,dsize;
	int ret;
	NTSTATUS status;
	SMB_STRUCT_STAT *pst;

	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		return -1;
	}
	pst = &fsp->fsp_name->st;

#ifdef S_ISFIFO
	if (S_ISFIFO(pst->st_ex_mode))
		return 0;
#endif

	if (pst->st_ex_size == len)
		return 0;

	/* Shrink - just ftruncate. */
	if (pst->st_ex_size > len)
		return ftruncate(fsp->fh->fd, len);

	space_to_write = len - pst->st_ex_size;

	/* for allocation try fallocate first. This can fail on some
	   platforms e.g. when the filesystem doesn't support it and no
	   emulation is being done by the libc (like on AIX with JFS1). In that
	   case we do our own emulation. fallocate implementations can
	   return ENOTSUP or EINVAL in cases like that. */
	ret = SMB_VFS_FALLOCATE(fsp, VFS_FALLOCATE_EXTEND_SIZE,
				pst->st_ex_size, space_to_write);
	if (ret == ENOSPC) {
		errno = ENOSPC;
		return -1;
	}
	if (ret == 0) {
		return 0;
	}
	DEBUG(10,("strict_allocate_ftruncate: SMB_VFS_FALLOCATE failed with "
		"error %d. Falling back to slow manual allocation\n", ret));

	/* available disk space is enough or not? */
	space_avail = get_dfree_info(fsp->conn,
				     fsp->fsp_name->base_name, false,
				     &bsize,&dfree,&dsize);
	/* space_avail is 1k blocks */
	if (space_avail == (uint64_t)-1 ||
			((uint64_t)space_to_write/1024 > space_avail) ) {
		errno = ENOSPC;
		return -1;
	}

	/* Write out the real space on disk. */
	ret = vfs_slow_fallocate(fsp, pst->st_ex_size, space_to_write);
	if (ret != 0) {
		errno = ret;
		ret = -1;
	}

	return 0;
}

static int vfswrap_ftruncate(vfs_handle_struct *handle, files_struct *fsp, off_t len)
{
	int result = -1;
	SMB_STRUCT_STAT *pst;
	NTSTATUS status;
	char c = 0;

	START_PROFILE(syscall_ftruncate);

	if (lp_strict_allocate(SNUM(fsp->conn)) && !fsp->is_sparse) {
		result = strict_allocate_ftruncate(handle, fsp, len);
		END_PROFILE(syscall_ftruncate);
		return result;
	}

	/* we used to just check HAVE_FTRUNCATE_EXTEND and only use
	   ftruncate if the system supports it. Then I discovered that
	   you can have some filesystems that support ftruncate
	   expansion and some that don't! On Linux fat can't do
	   ftruncate extend but ext2 can. */

	result = ftruncate(fsp->fh->fd, len);
	if (result == 0)
		goto done;

	/* According to W. R. Stevens advanced UNIX prog. Pure 4.3 BSD cannot
	   extend a file with ftruncate. Provide alternate implementation
	   for this */

	/* Do an fstat to see if the file is longer than the requested
	   size in which case the ftruncate above should have
	   succeeded or shorter, in which case seek to len - 1 and
	   write 1 byte of zero */
	status = vfs_stat_fsp(fsp);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	pst = &fsp->fsp_name->st;

#ifdef S_ISFIFO
	if (S_ISFIFO(pst->st_ex_mode)) {
		result = 0;
		goto done;
	}
#endif

	if (pst->st_ex_size == len) {
		result = 0;
		goto done;
	}

	if (pst->st_ex_size > len) {
		/* the ftruncate should have worked */
		goto done;
	}

	if (SMB_VFS_PWRITE(fsp, &c, 1, len-1)!=1) {
		goto done;
	}

	result = 0;

  done:

	END_PROFILE(syscall_ftruncate);
	return result;
}

static int vfswrap_fallocate(vfs_handle_struct *handle,
			files_struct *fsp,
			enum vfs_fallocate_mode mode,
			off_t offset,
			off_t len)
{
	int result;

	START_PROFILE(syscall_fallocate);
	if (mode == VFS_FALLOCATE_EXTEND_SIZE) {
		result = sys_posix_fallocate(fsp->fh->fd, offset, len);
	} else if (mode == VFS_FALLOCATE_KEEP_SIZE) {
		result = sys_fallocate(fsp->fh->fd, mode, offset, len);
	} else {
		errno = EINVAL;
		result = -1;
	}
	END_PROFILE(syscall_fallocate);
	return result;
}

static bool vfswrap_lock(vfs_handle_struct *handle, files_struct *fsp, int op, off_t offset, off_t count, int type)
{
	bool result;

	START_PROFILE(syscall_fcntl_lock);
	result =  fcntl_lock(fsp->fh->fd, op, offset, count, type);
	END_PROFILE(syscall_fcntl_lock);
	return result;
}

static int vfswrap_kernel_flock(vfs_handle_struct *handle, files_struct *fsp,
				uint32 share_mode, uint32 access_mask)
{
	START_PROFILE(syscall_kernel_flock);
	kernel_flock(fsp->fh->fd, share_mode, access_mask);
	END_PROFILE(syscall_kernel_flock);
	return 0;
}

static bool vfswrap_getlock(vfs_handle_struct *handle, files_struct *fsp, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid)
{
	bool result;

	START_PROFILE(syscall_fcntl_getlock);
	result =  fcntl_getlock(fsp->fh->fd, poffset, pcount, ptype, ppid);
	END_PROFILE(syscall_fcntl_getlock);
	return result;
}

static int vfswrap_linux_setlease(vfs_handle_struct *handle, files_struct *fsp,
				int leasetype)
{
	int result = -1;

	START_PROFILE(syscall_linux_setlease);

#ifdef HAVE_KERNEL_OPLOCKS_LINUX
	result = linux_setlease(fsp->fh->fd, leasetype);
#else
	errno = ENOSYS;
#endif
	END_PROFILE(syscall_linux_setlease);
	return result;
}

static int vfswrap_symlink(vfs_handle_struct *handle,  const char *oldpath, const char *newpath)
{
	int result;

	START_PROFILE(syscall_symlink);
	result = symlink(oldpath, newpath);
	END_PROFILE(syscall_symlink);
	return result;
}

static int vfswrap_readlink(vfs_handle_struct *handle,  const char *path, char *buf, size_t bufsiz)
{
	int result;

	START_PROFILE(syscall_readlink);
	result = readlink(path, buf, bufsiz);
	END_PROFILE(syscall_readlink);
	return result;
}

static int vfswrap_link(vfs_handle_struct *handle,  const char *oldpath, const char *newpath)
{
	int result;

	START_PROFILE(syscall_link);
	result = link(oldpath, newpath);
	END_PROFILE(syscall_link);
	return result;
}

static int vfswrap_mknod(vfs_handle_struct *handle,  const char *pathname, mode_t mode, SMB_DEV_T dev)
{
	int result;

	START_PROFILE(syscall_mknod);
	result = sys_mknod(pathname, mode, dev);
	END_PROFILE(syscall_mknod);
	return result;
}

static char *vfswrap_realpath(vfs_handle_struct *handle,  const char *path)
{
	char *result;

	START_PROFILE(syscall_realpath);
#ifdef REALPATH_TAKES_NULL
	result = realpath(path, NULL);
#else
	result = SMB_MALLOC_ARRAY(char, PATH_MAX+1);
	if (result) {
		char *resolved_path = realpath(path, result);
		if (!resolved_path) {
			SAFE_FREE(result);
		} else {
			/* SMB_ASSERT(result == resolved_path) ? */
			result = resolved_path;
		}
	}
#endif
	END_PROFILE(syscall_realpath);
	return result;
}

static NTSTATUS vfswrap_notify_watch(vfs_handle_struct *vfs_handle,
				     struct sys_notify_context *ctx,
				     const char *path,
				     uint32_t *filter,
				     uint32_t *subdir_filter,
				     void (*callback)(struct sys_notify_context *ctx, 
						      void *private_data,
						      struct notify_event *ev),
				     void *private_data, void *handle)
{
	/*
	 * So far inotify is the only supported default notify mechanism. If
	 * another platform like the the BSD's or a proprietary Unix comes
	 * along and wants another default, we can play the same trick we
	 * played with Posix ACLs.
	 *
	 * Until that is the case, hard-code inotify here.
	 */
#ifdef HAVE_INOTIFY
	if (lp_kernel_change_notify(vfs_handle->conn->params)) {
		return inotify_watch(ctx, path, filter, subdir_filter,
				     callback, private_data, handle);
	}
#endif
	/*
	 * Do nothing, leave everything to notify_internal.c
	 */
	return NT_STATUS_OK;
}

static int vfswrap_chflags(vfs_handle_struct *handle, const char *path,
			   unsigned int flags)
{
#ifdef HAVE_CHFLAGS
	return chflags(path, flags);
#else
	errno = ENOSYS;
	return -1;
#endif
}

static struct file_id vfswrap_file_id_create(struct vfs_handle_struct *handle,
					     const SMB_STRUCT_STAT *sbuf)
{
	struct file_id key;

	/* the ZERO_STRUCT ensures padding doesn't break using the key as a
	 * blob */
	ZERO_STRUCT(key);

	key.devid = sbuf->st_ex_dev;
	key.inode = sbuf->st_ex_ino;
	/* key.extid is unused by default. */

	return key;
}

static NTSTATUS vfswrap_streaminfo(vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   const char *fname,
				   TALLOC_CTX *mem_ctx,
				   unsigned int *pnum_streams,
				   struct stream_struct **pstreams)
{
	SMB_STRUCT_STAT sbuf;
	struct stream_struct *tmp_streams = NULL;
	int ret;

	if ((fsp != NULL) && (fsp->is_directory)) {
		/*
		 * No default streams on directories
		 */
		goto done;
	}

	if ((fsp != NULL) && (fsp->fh->fd != -1)) {
		ret = SMB_VFS_FSTAT(fsp, &sbuf);
	}
	else {
		struct smb_filename smb_fname;

		ZERO_STRUCT(smb_fname);
		smb_fname.base_name = discard_const_p(char, fname);

		if (lp_posix_pathnames()) {
			ret = SMB_VFS_LSTAT(handle->conn, &smb_fname);
		} else {
			ret = SMB_VFS_STAT(handle->conn, &smb_fname);
		}
		sbuf = smb_fname.st;
	}

	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	if (S_ISDIR(sbuf.st_ex_mode)) {
		goto done;
	}

	tmp_streams = talloc_realloc(mem_ctx, *pstreams, struct stream_struct,
					(*pnum_streams) + 1);
	if (tmp_streams == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tmp_streams[*pnum_streams].name = talloc_strdup(tmp_streams, "::$DATA");
	if (tmp_streams[*pnum_streams].name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tmp_streams[*pnum_streams].size = sbuf.st_ex_size;
	tmp_streams[*pnum_streams].alloc_size = SMB_VFS_GET_ALLOC_SIZE(handle->conn, fsp, &sbuf);

	*pnum_streams += 1;
	*pstreams = tmp_streams;
 done:
	return NT_STATUS_OK;
}

static int vfswrap_get_real_filename(struct vfs_handle_struct *handle,
				     const char *path,
				     const char *name,
				     TALLOC_CTX *mem_ctx,
				     char **found_name)
{
	/*
	 * Don't fall back to get_real_filename so callers can differentiate
	 * between a full directory scan and an actual case-insensitive stat.
	 */
	errno = EOPNOTSUPP;
	return -1;
}

static const char *vfswrap_connectpath(struct vfs_handle_struct *handle,
				       const char *fname)
{
	return handle->conn->connectpath;
}

static NTSTATUS vfswrap_brl_lock_windows(struct vfs_handle_struct *handle,
					 struct byte_range_lock *br_lck,
					 struct lock_struct *plock,
					 bool blocking_lock,
					 struct blocking_lock_record *blr)
{
	SMB_ASSERT(plock->lock_flav == WINDOWS_LOCK);

	/* Note: blr is not used in the default implementation. */
	return brl_lock_windows_default(br_lck, plock, blocking_lock);
}

static bool vfswrap_brl_unlock_windows(struct vfs_handle_struct *handle,
				       struct messaging_context *msg_ctx,
				       struct byte_range_lock *br_lck,
			               const struct lock_struct *plock)
{
	SMB_ASSERT(plock->lock_flav == WINDOWS_LOCK);

	return brl_unlock_windows_default(msg_ctx, br_lck, plock);
}

static bool vfswrap_brl_cancel_windows(struct vfs_handle_struct *handle,
				       struct byte_range_lock *br_lck,
				       struct lock_struct *plock,
				       struct blocking_lock_record *blr)
{
	SMB_ASSERT(plock->lock_flav == WINDOWS_LOCK);

	/* Note: blr is not used in the default implementation. */
	return brl_lock_cancel_default(br_lck, plock);
}

static bool vfswrap_strict_lock(struct vfs_handle_struct *handle,
				files_struct *fsp,
				struct lock_struct *plock)
{
	SMB_ASSERT(plock->lock_type == READ_LOCK ||
	    plock->lock_type == WRITE_LOCK);

	return strict_lock_default(fsp, plock);
}

static void vfswrap_strict_unlock(struct vfs_handle_struct *handle,
				files_struct *fsp,
				struct lock_struct *plock)
{
	SMB_ASSERT(plock->lock_type == READ_LOCK ||
	    plock->lock_type == WRITE_LOCK);

	strict_unlock_default(fsp, plock);
}

/* NT ACL operations. */

static NTSTATUS vfswrap_fget_nt_acl(vfs_handle_struct *handle,
				    files_struct *fsp,
				    uint32 security_info,
				    TALLOC_CTX *mem_ctx,
				    struct security_descriptor **ppdesc)
{
	NTSTATUS result;

	START_PROFILE(fget_nt_acl);
	result = posix_fget_nt_acl(fsp, security_info,
				   mem_ctx, ppdesc);
	END_PROFILE(fget_nt_acl);
	return result;
}

static NTSTATUS vfswrap_get_nt_acl(vfs_handle_struct *handle,
				   const char *name,
				   uint32 security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **ppdesc)
{
	NTSTATUS result;

	START_PROFILE(get_nt_acl);
	result = posix_get_nt_acl(handle->conn, name, security_info,
				  mem_ctx, ppdesc);
	END_PROFILE(get_nt_acl);
	return result;
}

static NTSTATUS vfswrap_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp, uint32 security_info_sent, const struct security_descriptor *psd)
{
	NTSTATUS result;

	START_PROFILE(fset_nt_acl);
	result = set_nt_acl(fsp, security_info_sent, psd);
	END_PROFILE(fset_nt_acl);
	return result;
}

static NTSTATUS vfswrap_audit_file(struct vfs_handle_struct *handle,
				   struct smb_filename *file,
				   struct security_acl *sacl,
				   uint32_t access_requested,
				   uint32_t access_denied)
{
	return NT_STATUS_OK; /* Nothing to do here ... */
}

static int vfswrap_chmod_acl(vfs_handle_struct *handle,  const char *name, mode_t mode)
{
#ifdef HAVE_NO_ACL
	errno = ENOSYS;
	return -1;
#else
	int result;

	START_PROFILE(chmod_acl);
	result = chmod_acl(handle->conn, name, mode);
	END_PROFILE(chmod_acl);
	return result;
#endif
}

static int vfswrap_fchmod_acl(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
#ifdef HAVE_NO_ACL
	errno = ENOSYS;
	return -1;
#else
	int result;

	START_PROFILE(fchmod_acl);
	result = fchmod_acl(fsp, mode);
	END_PROFILE(fchmod_acl);
	return result;
#endif
}

static SMB_ACL_T vfswrap_sys_acl_get_file(vfs_handle_struct *handle,
					  const char *path_p,
					  SMB_ACL_TYPE_T type,
					  TALLOC_CTX *mem_ctx)
{
	return sys_acl_get_file(handle, path_p, type, mem_ctx);
}

static SMB_ACL_T vfswrap_sys_acl_get_fd(vfs_handle_struct *handle,
					files_struct *fsp,
					TALLOC_CTX *mem_ctx)
{
	return sys_acl_get_fd(handle, fsp, mem_ctx);
}

static int vfswrap_sys_acl_blob_get_file(vfs_handle_struct *handle,
					 const char *path_p,
					 TALLOC_CTX *mem_ctx,
					 char **blob_description,
					 DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

static int vfswrap_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				       files_struct *fsp,
				       TALLOC_CTX *mem_ctx,
				       char **blob_description,
				       DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

static int vfswrap_sys_acl_set_file(vfs_handle_struct *handle,  const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return sys_acl_set_file(handle, name, acltype, theacl);
}

static int vfswrap_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp, SMB_ACL_T theacl)
{
	return sys_acl_set_fd(handle, fsp, theacl);
}

static int vfswrap_sys_acl_delete_def_file(vfs_handle_struct *handle,  const char *path)
{
	return sys_acl_delete_def_file(handle, path);
}

/****************************************************************
 Extended attribute operations.
*****************************************************************/

static ssize_t vfswrap_getxattr(struct vfs_handle_struct *handle,const char *path, const char *name, void *value, size_t size)
{
	return getxattr(path, name, value, size);
}

static ssize_t vfswrap_fgetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, void *value, size_t size)
{
	return fgetxattr(fsp->fh->fd, name, value, size);
}

static ssize_t vfswrap_listxattr(struct vfs_handle_struct *handle, const char *path, char *list, size_t size)
{
	return listxattr(path, list, size);
}

static ssize_t vfswrap_flistxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, char *list, size_t size)
{
	return flistxattr(fsp->fh->fd, list, size);
}

static int vfswrap_removexattr(struct vfs_handle_struct *handle, const char *path, const char *name)
{
	return removexattr(path, name);
}

static int vfswrap_fremovexattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name)
{
	return fremovexattr(fsp->fh->fd, name);
}

static int vfswrap_setxattr(struct vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags)
{
	return setxattr(path, name, value, size, flags);
}

static int vfswrap_fsetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, const void *value, size_t size, int flags)
{
	return fsetxattr(fsp->fh->fd, name, value, size, flags);
}

static bool vfswrap_aio_force(struct vfs_handle_struct *handle, struct files_struct *fsp)
{
	return false;
}

static bool vfswrap_is_offline(struct vfs_handle_struct *handle,
			       const struct smb_filename *fname,
			       SMB_STRUCT_STAT *sbuf)
{
	NTSTATUS status;
	char *path;
	bool offline = false;

        if (ISDOT(fname->base_name) || ISDOTDOT(fname->base_name)) {
		return false;
	}

	if (!lp_dmapi_support(SNUM(handle->conn)) || !dmapi_have_session()) {
#if defined(ENOTSUP)
		errno = ENOTSUP;
#endif
		return false;
	}

        status = get_full_smb_filename(talloc_tos(), fname, &path);
        if (!NT_STATUS_IS_OK(status)) {
                errno = map_errno_from_nt_status(status);
                return false;
        }

	offline = (dmapi_file_flags(path) & FILE_ATTRIBUTE_OFFLINE) != 0;

	TALLOC_FREE(path);

	return offline;
}

static int vfswrap_set_offline(struct vfs_handle_struct *handle,
			       const struct smb_filename *fname)
{
	/* We don't know how to set offline bit by default, needs to be overriden in the vfs modules */
#if defined(ENOTSUP)
	errno = ENOTSUP;
#endif
	return -1;
}

static NTSTATUS vfswrap_durable_cookie(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       TALLOC_CTX *mem_ctx,
				       DATA_BLOB *cookie)
{
	return vfs_default_durable_cookie(fsp, mem_ctx, cookie);
}

static NTSTATUS vfswrap_durable_disconnect(struct vfs_handle_struct *handle,
					   struct files_struct *fsp,
					   const DATA_BLOB old_cookie,
					   TALLOC_CTX *mem_ctx,
					   DATA_BLOB *new_cookie)
{
	return vfs_default_durable_disconnect(fsp, old_cookie, mem_ctx,
					      new_cookie);
}

static NTSTATUS vfswrap_durable_reconnect(struct vfs_handle_struct *handle,
					  struct smb_request *smb1req,
					  struct smbXsrv_open *op,
					  const DATA_BLOB old_cookie,
					  TALLOC_CTX *mem_ctx,
					  struct files_struct **fsp,
					  DATA_BLOB *new_cookie)
{
	return vfs_default_durable_reconnect(handle->conn, smb1req, op,
					     old_cookie, mem_ctx,
					     fsp, new_cookie);
}

static struct vfs_fn_pointers vfs_default_fns = {
	/* Disk operations */

	.connect_fn = vfswrap_connect,
	.disconnect_fn = vfswrap_disconnect,
	.disk_free_fn = vfswrap_disk_free,
	.get_quota_fn = vfswrap_get_quota,
	.set_quota_fn = vfswrap_set_quota,
	.get_shadow_copy_data_fn = vfswrap_get_shadow_copy_data,
	.statvfs_fn = vfswrap_statvfs,
	.fs_capabilities_fn = vfswrap_fs_capabilities,
	.get_dfs_referrals_fn = vfswrap_get_dfs_referrals,

	/* Directory operations */

	.opendir_fn = vfswrap_opendir,
	.fdopendir_fn = vfswrap_fdopendir,
	.readdir_fn = vfswrap_readdir,
	.seekdir_fn = vfswrap_seekdir,
	.telldir_fn = vfswrap_telldir,
	.rewind_dir_fn = vfswrap_rewinddir,
	.mkdir_fn = vfswrap_mkdir,
	.rmdir_fn = vfswrap_rmdir,
	.closedir_fn = vfswrap_closedir,
	.init_search_op_fn = vfswrap_init_search_op,

	/* File operations */

	.open_fn = vfswrap_open,
	.create_file_fn = vfswrap_create_file,
	.close_fn = vfswrap_close,
	.read_fn = vfswrap_read,
	.pread_fn = vfswrap_pread,
	.pread_send_fn = vfswrap_pread_send,
	.pread_recv_fn = vfswrap_asys_ssize_t_recv,
	.write_fn = vfswrap_write,
	.pwrite_fn = vfswrap_pwrite,
	.pwrite_send_fn = vfswrap_pwrite_send,
	.pwrite_recv_fn = vfswrap_asys_ssize_t_recv,
	.lseek_fn = vfswrap_lseek,
	.sendfile_fn = vfswrap_sendfile,
	.recvfile_fn = vfswrap_recvfile,
	.rename_fn = vfswrap_rename,
	.fsync_fn = vfswrap_fsync,
	.fsync_send_fn = vfswrap_fsync_send,
	.fsync_recv_fn = vfswrap_asys_int_recv,
	.stat_fn = vfswrap_stat,
	.fstat_fn = vfswrap_fstat,
	.lstat_fn = vfswrap_lstat,
	.get_alloc_size_fn = vfswrap_get_alloc_size,
	.unlink_fn = vfswrap_unlink,
	.chmod_fn = vfswrap_chmod,
	.fchmod_fn = vfswrap_fchmod,
	.chown_fn = vfswrap_chown,
	.fchown_fn = vfswrap_fchown,
	.lchown_fn = vfswrap_lchown,
	.chdir_fn = vfswrap_chdir,
	.getwd_fn = vfswrap_getwd,
	.ntimes_fn = vfswrap_ntimes,
	.ftruncate_fn = vfswrap_ftruncate,
	.fallocate_fn = vfswrap_fallocate,
	.lock_fn = vfswrap_lock,
	.kernel_flock_fn = vfswrap_kernel_flock,
	.linux_setlease_fn = vfswrap_linux_setlease,
	.getlock_fn = vfswrap_getlock,
	.symlink_fn = vfswrap_symlink,
	.readlink_fn = vfswrap_readlink,
	.link_fn = vfswrap_link,
	.mknod_fn = vfswrap_mknod,
	.realpath_fn = vfswrap_realpath,
	.notify_watch_fn = vfswrap_notify_watch,
	.chflags_fn = vfswrap_chflags,
	.file_id_create_fn = vfswrap_file_id_create,
	.streaminfo_fn = vfswrap_streaminfo,
	.get_real_filename_fn = vfswrap_get_real_filename,
	.connectpath_fn = vfswrap_connectpath,
	.brl_lock_windows_fn = vfswrap_brl_lock_windows,
	.brl_unlock_windows_fn = vfswrap_brl_unlock_windows,
	.brl_cancel_windows_fn = vfswrap_brl_cancel_windows,
	.strict_lock_fn = vfswrap_strict_lock,
	.strict_unlock_fn = vfswrap_strict_unlock,
	.translate_name_fn = vfswrap_translate_name,
	.fsctl_fn = vfswrap_fsctl,

	/* NT ACL operations. */

	.fget_nt_acl_fn = vfswrap_fget_nt_acl,
	.get_nt_acl_fn = vfswrap_get_nt_acl,
	.fset_nt_acl_fn = vfswrap_fset_nt_acl,
	.audit_file_fn = vfswrap_audit_file,

	/* POSIX ACL operations. */

	.chmod_acl_fn = vfswrap_chmod_acl,
	.fchmod_acl_fn = vfswrap_fchmod_acl,

	.sys_acl_get_file_fn = vfswrap_sys_acl_get_file,
	.sys_acl_get_fd_fn = vfswrap_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = vfswrap_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = vfswrap_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = vfswrap_sys_acl_set_file,
	.sys_acl_set_fd_fn = vfswrap_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = vfswrap_sys_acl_delete_def_file,

	/* EA operations. */
	.getxattr_fn = vfswrap_getxattr,
	.fgetxattr_fn = vfswrap_fgetxattr,
	.listxattr_fn = vfswrap_listxattr,
	.flistxattr_fn = vfswrap_flistxattr,
	.removexattr_fn = vfswrap_removexattr,
	.fremovexattr_fn = vfswrap_fremovexattr,
	.setxattr_fn = vfswrap_setxattr,
	.fsetxattr_fn = vfswrap_fsetxattr,

	/* aio operations */
	.aio_force_fn = vfswrap_aio_force,

	/* offline operations */
	.is_offline_fn = vfswrap_is_offline,
	.set_offline_fn = vfswrap_set_offline,

	/* durable handle operations */
	.durable_cookie_fn = vfswrap_durable_cookie,
	.durable_disconnect_fn = vfswrap_durable_disconnect,
	.durable_reconnect_fn = vfswrap_durable_reconnect,
};

NTSTATUS vfs_default_init(void);
NTSTATUS vfs_default_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				DEFAULT_VFS_MODULE_NAME, &vfs_default_fns);
}


