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
#include "lib/util/tevent_ntstatus.h"
#include "lib/util/sys_rw.h"
#include "lib/pthreadpool/pthreadpool_tevent.h"
#include "librpc/gen_ndr/ndr_ioctl.h"
#include "offload_token.h"
#include "util_reparse.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/* Check for NULL pointer parameters in vfswrap_* functions */

/* We don't want to have NULL function pointers lying around.  Someone
   is sure to try and execute them.  These stubs are used to prevent
   this possibility. */

static int vfswrap_connect(vfs_handle_struct *handle, const char *service, const char *user)
{
    return 0;    /* Return >= 0 for success */
}

static void vfswrap_disconnect(vfs_handle_struct *handle)
{
}

/* Disk operations */

static uint64_t vfswrap_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	if (sys_fsusage(smb_fname->base_name, dfree, dsize) != 0) {
		return (uint64_t)-1;
	}

	*bsize = 512;
	return *dfree / 2;
}

static int vfswrap_get_quota(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *qt)
{
#ifdef HAVE_SYS_QUOTAS
	int result;

	START_PROFILE(syscall_get_quota);
	result = sys_get_quota(smb_fname->base_name, qtype, id, qt);
	END_PROFILE(syscall_get_quota);
	return result;
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int vfswrap_set_quota(struct vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *qt)
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

static int vfswrap_statvfs(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				vfs_statvfs_struct *statbuf)
{
	return sys_statvfs(smb_fname->base_name, statbuf);
}

static uint32_t vfswrap_fs_capabilities(struct vfs_handle_struct *handle,
		enum timestamp_set_resolution *p_ts_res)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	connection_struct *conn = handle->conn;
	uint32_t caps = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;
	struct smb_filename *smb_fname_cpath = NULL;
	struct vfs_statvfs_struct statbuf;
	int ret;

	smb_fname_cpath = synthetic_smb_fname(talloc_tos(),
					      conn->connectpath,
					      NULL,
					      NULL,
					      0,
					      0);
	if (smb_fname_cpath == NULL) {
		return caps;
	}

	ZERO_STRUCT(statbuf);
	ret = SMB_VFS_STATVFS(conn, smb_fname_cpath, &statbuf);
	if (ret == 0) {
		caps = statbuf.FsCapabilities;
	}

	*p_ts_res = TIMESTAMP_SET_SECONDS;

	/* Work out what timestamp resolution we can
	 * use when setting a timestamp. */

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
			lp_servicename(talloc_tos(), lp_sub, conn->params->service),
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
	size_t i;
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
	status = get_referred_path(r,
				   handle->conn->session_info,
				   pathnamep,
				   handle->conn->sconn->remote_address,
				   handle->conn->sconn->local_address,
				   !handle->conn->sconn->using_smb2,
				   junction, &consumedcnt, &self_referral);
	if (!NT_STATUS_IS_OK(status)) {
		struct smb_filename connectpath_fname = {
			.base_name = handle->conn->connectpath
		};
		vfs_ChDir(handle->conn, &connectpath_fname);
		return status;
	}
	{
		struct smb_filename connectpath_fname = {
			.base_name = handle->conn->connectpath
		};
		vfs_ChDir(handle->conn, &connectpath_fname);
	}

	if (!self_referral) {
		pathnamep[consumedcnt] = '\0';

		if (DEBUGLVL(3)) {
			dbgtext("Path %s to alternate path(s):",
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
		DEBUG(0,("Invalid dfs referral version: %d\n",
			max_referral_level));
		return NT_STATUS_INVALID_LEVEL;
	}

	if (DEBUGLVL(10)) {
		NDR_PRINT_OUT_DEBUG(dfs_GetDFSReferral, r);
	}

	return NT_STATUS_OK;
}

static NTSTATUS vfswrap_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	TALLOC_CTX *frame = talloc_stackframe();
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	int ret;
	char *msdfs_link = NULL;

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	/* Form the msdfs_link contents */
	msdfs_link = msdfs_link_string(frame,
					reflist,
					referral_count);
	if (msdfs_link == NULL) {
		goto out;
	}

	ret = symlinkat(msdfs_link,
			dirfsp->fh->fd,
			smb_fname->base_name);
	if (ret == 0) {
		status = NT_STATUS_OK;
	} else {
		status = map_nt_error_from_unix(errno);
	}

  out:

	TALLOC_FREE(frame);
	return status;
}

/*
 * Read and return the contents of a DFS redirect given a
 * pathname. A caller can pass in NULL for ppreflist and
 * preferral_count but still determine if this was a
 * DFS redirect point by getting NT_STATUS_OK back
 * without incurring the overhead of reading and parsing
 * the referral contents.
 */

static NTSTATUS vfswrap_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	size_t bufsize;
	char *link_target = NULL;
	int referral_len;
	bool ok;
#if defined(HAVE_BROKEN_READLINK)
	char link_target_buf[PATH_MAX];
#else
	char link_target_buf[7];
#endif
	int ret;

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	if (is_named_stream(smb_fname)) {
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
		goto err;
	}

	if (ppreflist == NULL && preferral_count == NULL) {
		/*
		 * We're only checking if this is a DFS
		 * redirect. We don't need to return data.
		 */
		bufsize = sizeof(link_target_buf);
		link_target = link_target_buf;
	} else {
		bufsize = PATH_MAX;
		link_target = talloc_array(mem_ctx, char, bufsize);
		if (!link_target) {
			goto err;
		}
	}

	referral_len = readlinkat(dirfsp->fh->fd,
				smb_fname->base_name,
				link_target,
				bufsize - 1);
	if (referral_len == -1) {
		if (errno == EINVAL) {
			/*
			 * If the path isn't a link, readlinkat
			 * returns EINVAL. Allow the caller to
			 * detect this.
			 */
			DBG_INFO("%s is not a link.\n", smb_fname->base_name);
			status = NT_STATUS_OBJECT_TYPE_MISMATCH;
		} else {
			status = map_nt_error_from_unix(errno);
			DBG_ERR("Error reading "
				"msdfs link %s: %s\n",
				smb_fname->base_name,
				strerror(errno));
		}
                goto err;
        }
	link_target[referral_len] = '\0';

	DBG_INFO("%s -> %s\n",
			smb_fname->base_name,
			link_target);

	if (!strnequal(link_target, "msdfs:", 6)) {
		status = NT_STATUS_OBJECT_TYPE_MISMATCH;
		goto err;
	}

	ret = sys_lstat(smb_fname->base_name,
			&smb_fname->st,
			lp_fake_directory_create_times(SNUM(handle->conn)));
	if (ret < 0) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	if (ppreflist == NULL && preferral_count == NULL) {
		/* Early return for checking if this is a DFS link. */
		return NT_STATUS_OK;
	}

	ok = parse_msdfs_symlink(mem_ctx,
			lp_msdfs_shuffle_referrals(SNUM(handle->conn)),
			link_target,
			ppreflist,
			preferral_count);

	if (ok) {
		status = NT_STATUS_OK;
	} else {
		status = NT_STATUS_NO_MEMORY;
	}

  err:

	if (link_target != link_target_buf) {
		TALLOC_FREE(link_target);
	}
	return status;
}

static NTSTATUS vfswrap_snap_check_path(struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					const char *service_path,
					char **base_volume)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS vfswrap_snap_create(struct vfs_handle_struct *handle,
				    TALLOC_CTX *mem_ctx,
				    const char *base_volume,
				    time_t *tstamp,
				    bool rw,
				    char **base_path,
				    char **snap_path)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static NTSTATUS vfswrap_snap_delete(struct vfs_handle_struct *handle,
				    TALLOC_CTX *mem_ctx,
				    char *base_path,
				    char *snap_path)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/* Directory operations */

static DIR *vfswrap_fdopendir(vfs_handle_struct *handle,
			files_struct *fsp,
			const char *mask,
			uint32_t attr)
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
	END_PROFILE(syscall_readdir);
	if (sbuf) {
		/* Default Posix readdir() does not give us stat info.
		 * Set to invalid to indicate we didn't return this info. */
		SET_STAT_INVALID(*sbuf);
#if defined(HAVE_DIRFD) && defined(HAVE_FSTATAT)
		if (result != NULL) {
			/* See if we can efficiently return this. */
			struct stat st;
			int flags = AT_SYMLINK_NOFOLLOW;
			int ret = fstatat(dirfd(dirp),
					result->d_name,
					&st,
					flags);
			/*
			 * As this is an optimization,
			 * ignore it if we stat'ed a
			 * symlink. Make the caller
			 * do it again as we don't
			 * know if they wanted the link
			 * info, or its target info.
			 */
			if ((ret == 0) && (!S_ISLNK(st.st_mode))) {
				init_stat_ex_from_stat(sbuf,
					&st,
					lp_fake_directory_create_times(
						SNUM(handle->conn)));
			}
		}
#endif
	}
	return result;
}

static NTSTATUS vfswrap_readdir_attr(struct vfs_handle_struct *handle,
				     const struct smb_filename *fname,
				     TALLOC_CTX *mem_ctx,
				     struct readdir_attr_data **attr_data)
{
	return NT_STATUS_NOT_SUPPORTED;
}

static void vfswrap_seekdir(vfs_handle_struct *handle, DIR *dirp, long offset)
{
	START_PROFILE(syscall_seekdir);
	seekdir(dirp, offset);
	END_PROFILE(syscall_seekdir);
}

static long vfswrap_telldir(vfs_handle_struct *handle, DIR *dirp)
{
	long result;
	START_PROFILE(syscall_telldir);
	result = telldir(dirp);
	END_PROFILE(syscall_telldir);
	return result;
}

static void vfswrap_rewinddir(vfs_handle_struct *handle, DIR *dirp)
{
	START_PROFILE(syscall_rewinddir);
	rewinddir(dirp);
	END_PROFILE(syscall_rewinddir);
}

static int vfswrap_mkdirat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int result;
	struct smb_filename *parent = NULL;
	bool ok;

	START_PROFILE(syscall_mkdirat);

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	if (lp_inherit_acls(SNUM(handle->conn))) {
		ok = parent_smb_fname(talloc_tos(), smb_fname, &parent, NULL);
		if (ok && directory_has_default_acl(handle->conn,
				dirfsp,
				parent))
		{
			mode = (0777 & lp_directory_mask(SNUM(handle->conn)));
		}
	}

	TALLOC_FREE(parent);

	result = mkdirat(dirfsp->fh->fd, smb_fname->base_name, mode);

	END_PROFILE(syscall_mkdirat);
	return result;
}

static int vfswrap_closedir(vfs_handle_struct *handle, DIR *dirp)
{
	int result;

	START_PROFILE(syscall_closedir);
	result = closedir(dirp);
	END_PROFILE(syscall_closedir);
	return result;
}

/* File operations */

static int vfswrap_openat(vfs_handle_struct *handle,
			  const struct files_struct *dirfsp,
			  const struct smb_filename *smb_fname,
			  files_struct *fsp,
			  int flags,
			  mode_t mode)
{
	int result;

	START_PROFILE(syscall_openat);

	if (is_named_stream(smb_fname)) {
		errno = ENOENT;
		result = -1;
		goto out;
	}

	result = openat(dirfsp->fh->fd, smb_fname->base_name, flags, mode);

out:
	END_PROFILE(syscall_openat);
	return result;
}
static NTSTATUS vfswrap_create_file(vfs_handle_struct *handle,
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
				    files_struct **result,
				    int *pinfo,
				    const struct smb2_create_blobs *in_context_blobs,
				    struct smb2_create_blobs *out_context_blobs)
{
	return create_file_default(handle->conn, req, dirfsp, smb_fname,
				   access_mask, share_access,
				   create_disposition, create_options,
				   file_attributes, oplock_request, lease,
				   allocation_size, private_flags,
				   sd, ea_list, result,
				   pinfo, in_context_blobs, out_context_blobs);
}

static int vfswrap_close(vfs_handle_struct *handle, files_struct *fsp)
{
	int result;

	START_PROFILE(syscall_close);
	result = fd_close_posix(fsp);
	END_PROFILE(syscall_close);
	return result;
}

static ssize_t vfswrap_pread(vfs_handle_struct *handle, files_struct *fsp, void *data,
			size_t n, off_t offset)
{
	ssize_t result;

#if defined(HAVE_PREAD) || defined(HAVE_PREAD64)
	START_PROFILE_BYTES(syscall_pread, n);
	result = sys_pread_full(fsp->fh->fd, data, n, offset);
	END_PROFILE_BYTES(syscall_pread);

	if (result == -1 && errno == ESPIPE) {
		/* Maintain the fiction that pipes can be seeked (sought?) on. */
		result = sys_read(fsp->fh->fd, data, n);
		fsp->fh->pos = 0;
	}

#else /* HAVE_PREAD */
	errno = ENOSYS;
	result = -1;
#endif /* HAVE_PREAD */

	return result;
}

static ssize_t vfswrap_pwrite(vfs_handle_struct *handle, files_struct *fsp, const void *data,
			size_t n, off_t offset)
{
	ssize_t result;

#if defined(HAVE_PWRITE) || defined(HAVE_PRWITE64)
	START_PROFILE_BYTES(syscall_pwrite, n);
	result = sys_pwrite_full(fsp->fh->fd, data, n, offset);
	END_PROFILE_BYTES(syscall_pwrite);

	if (result == -1 && errno == ESPIPE) {
		/* Maintain the fiction that pipes can be sought on. */
		result = sys_write(fsp->fh->fd, data, n);
	}

#else /* HAVE_PWRITE */
	errno = ENOSYS;
	result = -1;
#endif /* HAVE_PWRITE */

	return result;
}

struct vfswrap_pread_state {
	ssize_t ret;
	int fd;
	void *buf;
	size_t count;
	off_t offset;

	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_pread_do(void *private_data);
static void vfs_pread_done(struct tevent_req *subreq);
static int vfs_pread_state_destructor(struct vfswrap_pread_state *state);

static struct tevent_req *vfswrap_pread_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     void *data,
					     size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct vfswrap_pread_state *state;

	req = tevent_req_create(mem_ctx, &state, struct vfswrap_pread_state);
	if (req == NULL) {
		return NULL;
	}

	state->ret = -1;
	state->fd = fsp->fh->fd;
	state->buf = data;
	state->count = n;
	state->offset = offset;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pread, profile_p,
				     state->profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	subreq = pthreadpool_tevent_job_send(
		state, ev, handle->conn->sconn->pool,
		vfs_pread_do, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_pread_done, req);

	talloc_set_destructor(state, vfs_pread_state_destructor);

	return req;
}

static void vfs_pread_do(void *private_data)
{
	struct vfswrap_pread_state *state = talloc_get_type_abort(
		private_data, struct vfswrap_pread_state);
	struct timespec start_time;
	struct timespec end_time;

	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);

	PROFILE_TIMESTAMP(&start_time);

	state->ret = sys_pread_full(state->fd,
				    state->buf,
				    state->count,
				    state->offset);

	if (state->ret == -1) {
		state->vfs_aio_state.error = errno;
	}

	PROFILE_TIMESTAMP(&end_time);

	state->vfs_aio_state.duration = nsec_time_diff(&end_time, &start_time);

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
}

static int vfs_pread_state_destructor(struct vfswrap_pread_state *state)
{
	return -1;
}

static void vfs_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfswrap_pread_state *state = tevent_req_data(
		req, struct vfswrap_pread_state);
	int ret;

	ret = pthreadpool_tevent_job_recv(subreq);
	TALLOC_FREE(subreq);
	SMBPROFILE_BYTES_ASYNC_END(state->profile_bytes);
	talloc_set_destructor(state, NULL);
	if (ret != 0) {
		if (ret != EAGAIN) {
			tevent_req_error(req, ret);
			return;
		}
		/*
		 * If we get EAGAIN from pthreadpool_tevent_job_recv() this
		 * means the lower level pthreadpool failed to create a new
		 * thread. Fallback to sync processing in that case to allow
		 * some progress for the client.
		 */
		vfs_pread_do(state);
	}

	tevent_req_done(req);
}

static ssize_t vfswrap_pread_recv(struct tevent_req *req,
				  struct vfs_aio_state *vfs_aio_state)
{
	struct vfswrap_pread_state *state = tevent_req_data(
		req, struct vfswrap_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

struct vfswrap_pwrite_state {
	ssize_t ret;
	int fd;
	const void *buf;
	size_t count;
	off_t offset;

	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_pwrite_do(void *private_data);
static void vfs_pwrite_done(struct tevent_req *subreq);
static int vfs_pwrite_state_destructor(struct vfswrap_pwrite_state *state);

static struct tevent_req *vfswrap_pwrite_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      const void *data,
					      size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct vfswrap_pwrite_state *state;

	req = tevent_req_create(mem_ctx, &state, struct vfswrap_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	state->ret = -1;
	state->fd = fsp->fh->fd;
	state->buf = data;
	state->count = n;
	state->offset = offset;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pwrite, profile_p,
				     state->profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	subreq = pthreadpool_tevent_job_send(
		state, ev, handle->conn->sconn->pool,
		vfs_pwrite_do, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_pwrite_done, req);

	talloc_set_destructor(state, vfs_pwrite_state_destructor);

	return req;
}

static void vfs_pwrite_do(void *private_data)
{
	struct vfswrap_pwrite_state *state = talloc_get_type_abort(
		private_data, struct vfswrap_pwrite_state);
	struct timespec start_time;
	struct timespec end_time;

	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);

	PROFILE_TIMESTAMP(&start_time);

	state->ret = sys_pwrite_full(state->fd,
				     state->buf,
				     state->count,
				     state->offset);

	if (state->ret == -1) {
		state->vfs_aio_state.error = errno;
	}

	PROFILE_TIMESTAMP(&end_time);

	state->vfs_aio_state.duration = nsec_time_diff(&end_time, &start_time);

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
}

static int vfs_pwrite_state_destructor(struct vfswrap_pwrite_state *state)
{
	return -1;
}

static void vfs_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfswrap_pwrite_state *state = tevent_req_data(
		req, struct vfswrap_pwrite_state);
	int ret;

	ret = pthreadpool_tevent_job_recv(subreq);
	TALLOC_FREE(subreq);
	SMBPROFILE_BYTES_ASYNC_END(state->profile_bytes);
	talloc_set_destructor(state, NULL);
	if (ret != 0) {
		if (ret != EAGAIN) {
			tevent_req_error(req, ret);
			return;
		}
		/*
		 * If we get EAGAIN from pthreadpool_tevent_job_recv() this
		 * means the lower level pthreadpool failed to create a new
		 * thread. Fallback to sync processing in that case to allow
		 * some progress for the client.
		 */
		vfs_pwrite_do(state);
	}

	tevent_req_done(req);
}

static ssize_t vfswrap_pwrite_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct vfswrap_pwrite_state *state = tevent_req_data(
		req, struct vfswrap_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

struct vfswrap_fsync_state {
	ssize_t ret;
	int fd;

	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_fsync_do(void *private_data);
static void vfs_fsync_done(struct tevent_req *subreq);
static int vfs_fsync_state_destructor(struct vfswrap_fsync_state *state);

static struct tevent_req *vfswrap_fsync_send(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp)
{
	struct tevent_req *req, *subreq;
	struct vfswrap_fsync_state *state;

	req = tevent_req_create(mem_ctx, &state, struct vfswrap_fsync_state);
	if (req == NULL) {
		return NULL;
	}

	state->ret = -1;
	state->fd = fsp->fh->fd;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_fsync, profile_p,
				     state->profile_bytes, 0);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	subreq = pthreadpool_tevent_job_send(
		state, ev, handle->conn->sconn->pool, vfs_fsync_do, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_fsync_done, req);

	talloc_set_destructor(state, vfs_fsync_state_destructor);

	return req;
}

static void vfs_fsync_do(void *private_data)
{
	struct vfswrap_fsync_state *state = talloc_get_type_abort(
		private_data, struct vfswrap_fsync_state);
	struct timespec start_time;
	struct timespec end_time;

	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);

	PROFILE_TIMESTAMP(&start_time);

	do {
		state->ret = fsync(state->fd);
	} while ((state->ret == -1) && (errno == EINTR));

	if (state->ret == -1) {
		state->vfs_aio_state.error = errno;
	}

	PROFILE_TIMESTAMP(&end_time);

	state->vfs_aio_state.duration = nsec_time_diff(&end_time, &start_time);

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
}

static int vfs_fsync_state_destructor(struct vfswrap_fsync_state *state)
{
	return -1;
}

static void vfs_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfswrap_fsync_state *state = tevent_req_data(
		req, struct vfswrap_fsync_state);
	int ret;

	ret = pthreadpool_tevent_job_recv(subreq);
	TALLOC_FREE(subreq);
	SMBPROFILE_BYTES_ASYNC_END(state->profile_bytes);
	talloc_set_destructor(state, NULL);
	if (ret != 0) {
		if (ret != EAGAIN) {
			tevent_req_error(req, ret);
			return;
		}
		/*
		 * If we get EAGAIN from pthreadpool_tevent_job_recv() this
		 * means the lower level pthreadpool failed to create a new
		 * thread. Fallback to sync processing in that case to allow
		 * some progress for the client.
		 */
		vfs_fsync_do(state);
	}

	tevent_req_done(req);
}

static int vfswrap_fsync_recv(struct tevent_req *req,
			      struct vfs_aio_state *vfs_aio_state)
{
	struct vfswrap_fsync_state *state = tevent_req_data(
		req, struct vfswrap_fsync_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static off_t vfswrap_lseek(vfs_handle_struct *handle, files_struct *fsp, off_t offset, int whence)
{
	off_t result = 0;

	START_PROFILE(syscall_lseek);

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
	END_PROFILE_BYTES(syscall_sendfile);
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
	END_PROFILE_BYTES(syscall_recvfile);
	return result;
}

static int vfswrap_renameat(vfs_handle_struct *handle,
			  files_struct *srcfsp,
			  const struct smb_filename *smb_fname_src,
			  files_struct *dstfsp,
			  const struct smb_filename *smb_fname_dst)
{
	int result = -1;

	START_PROFILE(syscall_renameat);

	if (is_named_stream(smb_fname_src) || is_named_stream(smb_fname_dst)) {
		errno = ENOENT;
		goto out;
	}

	result = renameat(srcfsp->fh->fd,
			smb_fname_src->base_name,
			dstfsp->fh->fd,
			smb_fname_dst->base_name);

 out:
	END_PROFILE(syscall_renameat);
	return result;
}

static int vfswrap_stat(vfs_handle_struct *handle,
			struct smb_filename *smb_fname)
{
	int result = -1;

	START_PROFILE(syscall_stat);

	if (is_named_stream(smb_fname)) {
		errno = ENOENT;
		goto out;
	}

	result = sys_stat(smb_fname->base_name, &smb_fname->st,
			  lp_fake_directory_create_times(SNUM(handle->conn)));
 out:
	END_PROFILE(syscall_stat);
	return result;
}

static int vfswrap_fstat(vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int result;

	START_PROFILE(syscall_fstat);
	result = sys_fstat(fsp->fh->fd,
			   sbuf, lp_fake_directory_create_times(SNUM(handle->conn)));
	END_PROFILE(syscall_fstat);
	return result;
}

static int vfswrap_lstat(vfs_handle_struct *handle,
			 struct smb_filename *smb_fname)
{
	int result = -1;

	START_PROFILE(syscall_lstat);

	if (is_named_stream(smb_fname)) {
		errno = ENOENT;
		goto out;
	}

	result = sys_lstat(smb_fname->base_name, &smb_fname->st,
			   lp_fake_directory_create_times(SNUM(handle->conn)));
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
			      uint16_t req_flags, /* Needed for UNICODE ... */
			      const uint8_t *_in_data,
			      uint32_t in_len,
			      uint8_t **_out_data,
			      uint32_t max_out_len,
			      uint32_t *out_len)
{
	const char *in_data = (const char *)_in_data;
	char **out_data = (char **)_out_data;
	NTSTATUS status;

	switch (function) {
	case FSCTL_SET_SPARSE:
	{
		bool set_sparse = true;

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

		*out_len = MIN(max_out_len, 64);

		/* Hmmm, will this cause problems if less data asked for? */
		return_data = talloc_array(ctx, char, 64);
		if (return_data == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		/* For backwards compatibility only store the dev/inode. */
		push_file_id_16(return_data, &fsp->file_id);
		memcpy(return_data+16,create_volume_objectid(fsp->conn,objid),16);
		push_file_id_16(return_data+32, &fsp->file_id);
		memset(return_data+48, 0, 16);
		*out_data = return_data;
		return NT_STATUS_OK;
	}

	case FSCTL_GET_REPARSE_POINT:
	{
		status = fsctl_get_reparse_point(
			fsp, ctx, out_data, max_out_len, out_len);
		return status;
	}

	case FSCTL_SET_REPARSE_POINT:
	{
		status = fsctl_set_reparse_point(fsp, ctx, _in_data, in_len);
		return status;
	}

	case FSCTL_DELETE_REPARSE_POINT:
	{
		status = fsctl_del_reparse_point(fsp, ctx, _in_data, in_len);
		return status;
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
		uint32_t labels_data_count = 0;
		uint32_t i;
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
			int log_lev = 0;
			if (errno == 0) {
				/* broken module didn't set errno on error */
				status = NT_STATUS_UNSUCCESSFUL;
			} else {
				status = map_nt_error_from_unix(errno);
				if (NT_STATUS_EQUAL(status,
						    NT_STATUS_NOT_SUPPORTED)) {
					log_lev = 5;
				}
			}
			DEBUG(log_lev, ("FSCTL_GET_SHADOW_COPY_DATA: "
					"connectpath %s, failed - %s.\n",
					fsp->conn->connectpath,
					nt_errstr(status)));
			TALLOC_FREE(shadow_data);
			return status;
		}

		labels_data_count = (shadow_data->num_volumes * 2 *
					sizeof(SHADOW_COPY_LABEL)) + 2;

		if (!labels) {
			*out_len = 16;
		} else {
			*out_len = 12 + labels_data_count;
		}

		if (max_out_len < *out_len) {
			DEBUG(0,("FSCTL_GET_SHADOW_COPY_DATA: max_data_count(%u) too small (%u) bytes needed!\n",
				max_out_len, *out_len));
			TALLOC_FREE(shadow_data);
			return NT_STATUS_BUFFER_TOO_SMALL;
		}

		cur_pdata = talloc_zero_array(ctx, char, *out_len);
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
		SIVAL(cur_pdata, 8, labels_data_count);

		cur_pdata += 12;

		DEBUG(10,("FSCTL_GET_SHADOW_COPY_DATA: %u volumes for path[%s].\n",
			  shadow_data->num_volumes, fsp_str_dbg(fsp)));
		if (labels && shadow_data->labels) {
			for (i=0; i<shadow_data->num_volumes; i++) {
				size_t len = 0;
				status = srvstr_push(cur_pdata, req_flags,
					    cur_pdata, shadow_data->labels[i],
					    2 * sizeof(SHADOW_COPY_LABEL),
					    STR_UNICODE|STR_TERMINATE, &len);
				if (!NT_STATUS_IS_OK(status)) {
					TALLOC_FREE(*out_data);
					TALLOC_FREE(shadow_data);
					return status;
				}
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
		ssize_t ret;
		struct dom_sid sid;
		struct dom_sid_buf buf;
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

		ret = sid_parse(_in_data + 4, sid_len, &sid);
		if (ret == -1) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		DEBUGADD(10, ("for SID: %s\n",
			      dom_sid_str_buf(&sid, &buf)));

		if (!sid_to_uid(&sid, &uid)) {
			DEBUG(0,("sid_to_uid: failed, sid[%s] sid_len[%lu]\n",
				 dom_sid_str_buf(&sid, &buf),
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

static bool vfswrap_is_offline(struct connection_struct *conn,
			       const struct smb_filename *fname);

static NTSTATUS vfswrap_get_dos_attributes(struct vfs_handle_struct *handle,
					   struct smb_filename *smb_fname,
					   uint32_t *dosmode)
{
	bool offline;

	offline = vfswrap_is_offline(handle->conn, smb_fname);
	if (offline) {
		*dosmode |= FILE_ATTRIBUTE_OFFLINE;
	}

	return get_ea_dos_attribute(handle->conn, smb_fname, dosmode);
}

struct vfswrap_get_dos_attributes_state {
	struct vfs_aio_state aio_state;
	connection_struct *conn;
	TALLOC_CTX *mem_ctx;
	struct tevent_context *ev;
	files_struct *dir_fsp;
	struct smb_filename *smb_fname;
	uint32_t dosmode;
	bool as_root;
};

static void vfswrap_get_dos_attributes_getxattr_done(struct tevent_req *subreq);

static struct tevent_req *vfswrap_get_dos_attributes_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			struct smb_filename *smb_fname)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct vfswrap_get_dos_attributes_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct vfswrap_get_dos_attributes_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct vfswrap_get_dos_attributes_state) {
		.conn = dir_fsp->conn,
		.mem_ctx = mem_ctx,
		.ev = ev,
		.dir_fsp = dir_fsp,
		.smb_fname = smb_fname,
	};

	subreq = SMB_VFS_GETXATTRAT_SEND(state,
					 ev,
					 dir_fsp,
					 smb_fname,
					 SAMBA_XATTR_DOS_ATTRIB,
					 sizeof(fstring));
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				vfswrap_get_dos_attributes_getxattr_done,
				req);

	return req;
}

static void vfswrap_get_dos_attributes_getxattr_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct vfswrap_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct vfswrap_get_dos_attributes_state);
	ssize_t xattr_size;
	DATA_BLOB blob = {0};
	char *path = NULL;
	char *tofree = NULL;
	char pathbuf[PATH_MAX+1];
	ssize_t pathlen;
	struct smb_filename smb_fname;
	bool offline;
	NTSTATUS status;

	xattr_size = SMB_VFS_GETXATTRAT_RECV(subreq,
					     &state->aio_state,
					     state,
					     &blob.data);
	TALLOC_FREE(subreq);
	if (xattr_size == -1) {
		status = map_nt_error_from_unix(state->aio_state.error);

		if (state->as_root) {
			tevent_req_nterror(req, status);
			return;
		}
		if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			tevent_req_nterror(req, status);
			return;
		}

		state->as_root = true;

		become_root();
		subreq = SMB_VFS_GETXATTRAT_SEND(state,
						 state->ev,
						 state->dir_fsp,
						 state->smb_fname,
						 SAMBA_XATTR_DOS_ATTRIB,
						 sizeof(fstring));
		unbecome_root();
		if (tevent_req_nomem(subreq, req)) {
			return;
		}
		tevent_req_set_callback(subreq,
					vfswrap_get_dos_attributes_getxattr_done,
					req);
		return;
	}

	blob.length = xattr_size;

	status = parse_dos_attribute_blob(state->smb_fname,
					  blob,
					  &state->dosmode);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	pathlen = full_path_tos(state->dir_fsp->fsp_name->base_name,
				state->smb_fname->base_name,
				pathbuf,
				sizeof(pathbuf),
				&path,
				&tofree);
	if (pathlen == -1) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}

	smb_fname = (struct smb_filename) {
		.base_name = path,
		.st = state->smb_fname->st,
		.flags = state->smb_fname->flags,
		.twrp = state->smb_fname->twrp,
	};

	offline = vfswrap_is_offline(state->conn, &smb_fname);
	if (offline) {
		state->dosmode |= FILE_ATTRIBUTE_OFFLINE;
	}
	TALLOC_FREE(tofree);

	tevent_req_done(req);
	return;
}

static NTSTATUS vfswrap_get_dos_attributes_recv(struct tevent_req *req,
						struct vfs_aio_state *aio_state,
						uint32_t *dosmode)
{
	struct vfswrap_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct vfswrap_get_dos_attributes_state);
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

static NTSTATUS vfswrap_fget_dos_attributes(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    uint32_t *dosmode)
{
	bool offline;

	offline = vfswrap_is_offline(handle->conn, fsp->fsp_name);
	if (offline) {
		*dosmode |= FILE_ATTRIBUTE_OFFLINE;
	}

	return get_ea_dos_attribute(handle->conn, fsp->fsp_name, dosmode);
}

static NTSTATUS vfswrap_set_dos_attributes(struct vfs_handle_struct *handle,
					   const struct smb_filename *smb_fname,
					   uint32_t dosmode)
{
	return set_ea_dos_attribute(handle->conn, smb_fname, dosmode);
}

static NTSTATUS vfswrap_fset_dos_attributes(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    uint32_t dosmode)
{
	return set_ea_dos_attribute(handle->conn, fsp->fsp_name, dosmode);
}

static struct vfs_offload_ctx *vfswrap_offload_ctx;

struct vfswrap_offload_read_state {
	DATA_BLOB token;
};

static struct tevent_req *vfswrap_offload_read_send(
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
	struct vfswrap_offload_read_state *state = NULL;
	NTSTATUS status;

	req = tevent_req_create(mem_ctx, &state,
				struct vfswrap_offload_read_state);
	if (req == NULL) {
		return NULL;
	}

	status = vfs_offload_token_ctx_init(fsp->conn->sconn->client,
					    &vfswrap_offload_ctx);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (fsctl != FSCTL_SRV_REQUEST_RESUME_KEY) {
		tevent_req_nterror(req, NT_STATUS_INVALID_DEVICE_REQUEST);
		return tevent_req_post(req, ev);
	}

	status = vfs_offload_token_create_blob(state, fsp, fsctl,
					       &state->token);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	status = vfs_offload_token_db_store_fsp(vfswrap_offload_ctx, fsp,
						&state->token);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS vfswrap_offload_read_recv(struct tevent_req *req,
					  struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  DATA_BLOB *token)
{
	struct vfswrap_offload_read_state *state = tevent_req_data(
		req, struct vfswrap_offload_read_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	token->length = state->token.length;
	token->data = talloc_move(mem_ctx, &state->token.data);

	tevent_req_received(req);
	return NT_STATUS_OK;
}

struct vfswrap_offload_write_state {
	uint8_t *buf;
	bool read_lck_locked;
	bool write_lck_locked;
	DATA_BLOB *token;
	struct tevent_context *src_ev;
	struct files_struct *src_fsp;
	off_t src_off;
	struct tevent_context *dst_ev;
	struct files_struct *dst_fsp;
	off_t dst_off;
	off_t to_copy;
	off_t remaining;
	size_t next_io_size;
};

static void vfswrap_offload_write_cleanup(struct tevent_req *req,
					  enum tevent_req_state req_state)
{
	struct vfswrap_offload_write_state *state = tevent_req_data(
		req, struct vfswrap_offload_write_state);
	bool ok;

	if (state->dst_fsp == NULL) {
		return;
	}

	ok = change_to_user_and_service_by_fsp(state->dst_fsp);
	SMB_ASSERT(ok);
	state->dst_fsp = NULL;
}

static NTSTATUS vfswrap_offload_write_loop(struct tevent_req *req);

static struct tevent_req *vfswrap_offload_write_send(
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	uint32_t fsctl,
	DATA_BLOB *token,
	off_t transfer_offset,
	struct files_struct *dest_fsp,
	off_t dest_off,
	off_t to_copy)
{
	struct tevent_req *req;
	struct vfswrap_offload_write_state *state = NULL;
	/* off_t is signed! */
	off_t max_offset = INT64_MAX - to_copy;
	size_t num = MIN(to_copy, COPYCHUNK_MAX_TOTAL_LEN);
	files_struct *src_fsp = NULL;
	NTSTATUS status;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct vfswrap_offload_write_state);
	if (req == NULL) {
		return NULL;
	}

	*state = (struct vfswrap_offload_write_state) {
		.token = token,
		.src_off = transfer_offset,
		.dst_ev = ev,
		.dst_fsp = dest_fsp,
		.dst_off = dest_off,
		.to_copy = to_copy,
		.remaining = to_copy,
	};

	tevent_req_set_cleanup_fn(req, vfswrap_offload_write_cleanup);

	switch (fsctl) {
	case FSCTL_SRV_COPYCHUNK:
	case FSCTL_SRV_COPYCHUNK_WRITE:
		break;

	case FSCTL_OFFLOAD_WRITE:
		tevent_req_nterror(req, NT_STATUS_NOT_IMPLEMENTED);
		return tevent_req_post(req, ev);

	case FSCTL_DUP_EXTENTS_TO_FILE:
		DBG_DEBUG("COW clones not supported by vfs_default\n");
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);

	default:
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return tevent_req_post(req, ev);
	}

	/*
	 * From here on we assume a copy-chunk fsctl
	 */

	if (to_copy == 0) {
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (state->src_off > max_offset) {
		/*
		 * Protect integer checks below.
		 */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}
	if (state->src_off < 0) {
		/*
		 * Protect integer checks below.
		 */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}
	if (state->dst_off > max_offset) {
		/*
		 * Protect integer checks below.
		 */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}
	if (state->dst_off < 0) {
		/*
		 * Protect integer checks below.
		 */
		tevent_req_nterror(req, NT_STATUS_INVALID_PARAMETER);
		return tevent_req_post(req, ev);
	}

	status = vfs_offload_token_db_fetch_fsp(vfswrap_offload_ctx,
						token, &src_fsp);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	DBG_DEBUG("server side copy chunk of length %" PRIu64 "\n", to_copy);

	status = vfs_offload_token_check_handles(fsctl, src_fsp, dest_fsp);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	ok = change_to_user_and_service_by_fsp(src_fsp);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_ACCESS_DENIED);
		return tevent_req_post(req, ev);
	}

	state->src_ev = src_fsp->conn->sconn->ev_ctx;
	state->src_fsp = src_fsp;

	status = vfs_stat_fsp(src_fsp);
	if (tevent_req_nterror(req, status)) {
		return tevent_req_post(req, ev);
	}

	if (src_fsp->fsp_name->st.st_ex_size < state->src_off + to_copy) {
		/*
		 * [MS-SMB2] 3.3.5.15.6 Handling a Server-Side Data Copy Request
		 *   If the SourceOffset or SourceOffset + Length extends beyond
		 *   the end of file, the server SHOULD<240> treat this as a
		 *   STATUS_END_OF_FILE error.
		 * ...
		 *   <240> Section 3.3.5.15.6: Windows servers will return
		 *   STATUS_INVALID_VIEW_SIZE instead of STATUS_END_OF_FILE.
		 */
		tevent_req_nterror(req, NT_STATUS_INVALID_VIEW_SIZE);
		return tevent_req_post(req, ev);
	}

	state->buf = talloc_array(state, uint8_t, num);
	if (tevent_req_nomem(state->buf, req)) {
		return tevent_req_post(req, ev);
	}

	status = vfswrap_offload_write_loop(req);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void vfswrap_offload_write_read_done(struct tevent_req *subreq);

static NTSTATUS vfswrap_offload_write_loop(struct tevent_req *req)
{
	struct vfswrap_offload_write_state *state = tevent_req_data(
		req, struct vfswrap_offload_write_state);
	struct tevent_req *subreq = NULL;
	struct lock_struct read_lck;
	bool ok;

	/*
	 * This is called under the context of state->src_fsp.
	 */

	state->next_io_size = MIN(state->remaining, talloc_array_length(state->buf));

	init_strict_lock_struct(state->src_fsp,
				state->src_fsp->op->global->open_persistent_id,
				state->src_off,
				state->next_io_size,
				READ_LOCK,
				&read_lck);

	ok = SMB_VFS_STRICT_LOCK_CHECK(state->src_fsp->conn,
				 state->src_fsp,
				 &read_lck);
	if (!ok) {
		return NT_STATUS_FILE_LOCK_CONFLICT;
	}

	subreq = SMB_VFS_PREAD_SEND(state,
				    state->src_ev,
				    state->src_fsp,
				    state->buf,
				    state->next_io_size,
				    state->src_off);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, vfswrap_offload_write_read_done, req);

	return NT_STATUS_OK;
}

static void vfswrap_offload_write_write_done(struct tevent_req *subreq);

static void vfswrap_offload_write_read_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfswrap_offload_write_state *state = tevent_req_data(
		req, struct vfswrap_offload_write_state);
	struct vfs_aio_state aio_state;
	struct lock_struct write_lck;
	ssize_t nread;
	bool ok;

	nread = SMB_VFS_PREAD_RECV(subreq, &aio_state);
	TALLOC_FREE(subreq);
	if (nread == -1) {
		DBG_ERR("read failed: %s\n", strerror(aio_state.error));
		tevent_req_nterror(req, map_nt_error_from_unix(aio_state.error));
		return;
	}
	if (nread != state->next_io_size) {
		DBG_ERR("Short read, only %zd of %zu\n",
			nread, state->next_io_size);
		tevent_req_nterror(req, NT_STATUS_IO_DEVICE_ERROR);
		return;
	}

	state->src_off += nread;

	ok = change_to_user_and_service_by_fsp(state->dst_fsp);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	init_strict_lock_struct(state->dst_fsp,
				state->dst_fsp->op->global->open_persistent_id,
				state->dst_off,
				state->next_io_size,
				WRITE_LOCK,
				&write_lck);

	ok = SMB_VFS_STRICT_LOCK_CHECK(state->dst_fsp->conn,
				 state->dst_fsp,
				 &write_lck);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_FILE_LOCK_CONFLICT);
		return;
	}

	subreq = SMB_VFS_PWRITE_SEND(state,
				     state->dst_ev,
				     state->dst_fsp,
				     state->buf,
				     state->next_io_size,
				     state->dst_off);
	if (subreq == NULL) {
		tevent_req_nterror(req, NT_STATUS_NO_MEMORY);
		return;
	}
	tevent_req_set_callback(subreq, vfswrap_offload_write_write_done, req);
}

static void vfswrap_offload_write_write_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfswrap_offload_write_state *state = tevent_req_data(
		req, struct vfswrap_offload_write_state);
	struct vfs_aio_state aio_state;
	ssize_t nwritten;
	NTSTATUS status;
	bool ok;

	nwritten = SMB_VFS_PWRITE_RECV(subreq, &aio_state);
	TALLOC_FREE(subreq);
	if (nwritten == -1) {
		DBG_ERR("write failed: %s\n", strerror(aio_state.error));
		tevent_req_nterror(req, map_nt_error_from_unix(aio_state.error));
		return;
	}
	if (nwritten != state->next_io_size) {
		DBG_ERR("Short write, only %zd of %zu\n", nwritten, state->next_io_size);
		tevent_req_nterror(req, NT_STATUS_IO_DEVICE_ERROR);
		return;
	}

	state->dst_off += nwritten;

	if (state->remaining < nwritten) {
		/* Paranoia check */
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}
	state->remaining -= nwritten;
	if (state->remaining == 0) {
		tevent_req_done(req);
		return;
	}

	ok = change_to_user_and_service_by_fsp(state->src_fsp);
	if (!ok) {
		tevent_req_nterror(req, NT_STATUS_INTERNAL_ERROR);
		return;
	}

	status = vfswrap_offload_write_loop(req);
	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	return;
}

static NTSTATUS vfswrap_offload_write_recv(struct vfs_handle_struct *handle,
					struct tevent_req *req,
					off_t *copied)
{
	struct vfswrap_offload_write_state *state = tevent_req_data(
		req, struct vfswrap_offload_write_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		DBG_DEBUG("copy chunk failed: %s\n", nt_errstr(status));
		*copied = 0;
		tevent_req_received(req);
		return status;
	}

	*copied = state->to_copy;
	DBG_DEBUG("copy chunk copied %lu\n", (unsigned long)*copied);
	tevent_req_received(req);

	return NT_STATUS_OK;
}

static NTSTATUS vfswrap_get_compression(struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					struct files_struct *fsp,
					struct smb_filename *smb_fname,
					uint16_t *_compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS vfswrap_set_compression(struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					struct files_struct *fsp,
					uint16_t compression_fmt)
{
	return NT_STATUS_INVALID_DEVICE_REQUEST;
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
	if (result == 0) {
		/*
		 * Some file systems do not allocate a block for very
		 * small files. But for non-empty file should report a
		 * positive size.
		 */

		uint64_t filesize = get_file_size_stat(sbuf);
		if (filesize > 0) {
			result = MIN((uint64_t)STAT_ST_BLOCKSIZE, filesize);
		}
	}
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

static int vfswrap_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	int result = -1;

	START_PROFILE(syscall_unlinkat);

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	if (is_named_stream(smb_fname)) {
		errno = ENOENT;
		goto out;
	}
	result = unlinkat(dirfsp->fh->fd,
			smb_fname->base_name,
			flags);

 out:
	END_PROFILE(syscall_unlinkat);
	return result;
}

static int vfswrap_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int result;

	START_PROFILE(syscall_chmod);
	result = chmod(smb_fname->base_name, mode);
	END_PROFILE(syscall_chmod);
	return result;
}

static int vfswrap_fchmod(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	int result;

	START_PROFILE(syscall_fchmod);
#if defined(HAVE_FCHMOD)
	result = fchmod(fsp->fh->fd, mode);
#else
	result = -1;
	errno = ENOSYS;
#endif

	END_PROFILE(syscall_fchmod);
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

static int vfswrap_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int result;

	START_PROFILE(syscall_lchown);
	result = lchown(smb_fname->base_name, uid, gid);
	END_PROFILE(syscall_lchown);
	return result;
}

static int vfswrap_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int result;

	START_PROFILE(syscall_chdir);
	result = chdir(smb_fname->base_name);
	END_PROFILE(syscall_chdir);
	return result;
}

static struct smb_filename *vfswrap_getwd(vfs_handle_struct *handle,
				TALLOC_CTX *ctx)
{
	char *result;
	struct smb_filename *smb_fname = NULL;

	START_PROFILE(syscall_getwd);
	result = sys_getwd();
	END_PROFILE(syscall_getwd);

	if (result == NULL) {
		return NULL;
	}
	smb_fname = synthetic_smb_fname(ctx,
				result,
				NULL,
				NULL,
				0,
				0);
	/*
	 * sys_getwd() *always* returns malloced memory.
	 * We must free here to avoid leaks:
	 * BUG:https://bugzilla.samba.org/show_bug.cgi?id=13372
	 */
	SAFE_FREE(result);
	return smb_fname;
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

	if (is_named_stream(smb_fname)) {
		errno = ENOENT;
		goto out;
	}

	if (ft != NULL) {
		if (is_omit_timespec(&ft->atime)) {
			ft->atime= smb_fname->st.st_ex_atime;
		}

		if (is_omit_timespec(&ft->mtime)) {
			ft->mtime = smb_fname->st.st_ex_mtime;
		}

		if (!is_omit_timespec(&ft->create_time)) {
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
	bool ok;

	ok = vfs_valid_pwrite_range(len, 0);
	if (!ok) {
		errno = EINVAL;
		return -1;
	}

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
	ret = SMB_VFS_FALLOCATE(fsp, 0, pst->st_ex_size, space_to_write);
	if (ret == -1 && errno == ENOSPC) {
		return -1;
	}
	if (ret == 0) {
		return 0;
	}
	DEBUG(10,("strict_allocate_ftruncate: SMB_VFS_FALLOCATE failed with "
		"error %d. Falling back to slow manual allocation\n", errno));

	/* available disk space is enough or not? */
	space_avail =
	    get_dfree_info(fsp->conn, fsp->fsp_name, &bsize, &dfree, &dsize);
	/* space_avail is 1k blocks */
	if (space_avail == (uint64_t)-1 ||
			((uint64_t)space_to_write/1024 > space_avail) ) {
		errno = ENOSPC;
		return -1;
	}

	/* Write out the real space on disk. */
	ret = vfs_slow_fallocate(fsp, pst->st_ex_size, space_to_write);
	if (ret != 0) {
		return -1;
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

	if (lp_strict_allocate(SNUM(fsp->conn)) && !fsp->fsp_flags.is_sparse) {
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

	/* We need to update the files_struct after successful ftruncate */
	if (result == 0) {
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
			uint32_t mode,
			off_t offset,
			off_t len)
{
	int result;

	START_PROFILE(syscall_fallocate);
	if (mode == 0) {
		result = sys_posix_fallocate(fsp->fh->fd, offset, len);
		/*
		 * posix_fallocate returns 0 on success, errno on error
		 * and doesn't set errno. Make it behave like fallocate()
		 * which returns -1, and sets errno on failure.
		 */
		if (result != 0) {
			errno = result;
			result = -1;
		}
	} else {
		/* sys_fallocate handles filtering of unsupported mode flags */
		result = sys_fallocate(fsp->fh->fd, mode, offset, len);
	}
	END_PROFILE(syscall_fallocate);
	return result;
}

static bool vfswrap_lock(vfs_handle_struct *handle, files_struct *fsp, int op, off_t offset, off_t count, int type)
{
	bool result;

	START_PROFILE(syscall_fcntl_lock);

	if (fsp->fsp_flags.use_ofd_locks) {
		op = map_process_lock_to_ofd_lock(op);
	}

	result =  fcntl_lock(fsp->fh->fd, op, offset, count, type);
	END_PROFILE(syscall_fcntl_lock);
	return result;
}

static int vfswrap_kernel_flock(vfs_handle_struct *handle, files_struct *fsp,
				uint32_t share_access, uint32_t access_mask)
{
	START_PROFILE(syscall_kernel_flock);
	kernel_flock(fsp->fh->fd, share_access, access_mask);
	END_PROFILE(syscall_kernel_flock);
	return 0;
}

static int vfswrap_fcntl(vfs_handle_struct *handle, files_struct *fsp, int cmd,
			 va_list cmd_arg)
{
	void *argp;
	va_list dup_cmd_arg;
	int result;
	int val;

	START_PROFILE(syscall_fcntl);

	va_copy(dup_cmd_arg, cmd_arg);

	switch(cmd) {
	case F_SETLK:
	case F_SETLKW:
	case F_GETLK:
#if defined(HAVE_OFD_LOCKS)
	case F_OFD_SETLK:
	case F_OFD_SETLKW:
	case F_OFD_GETLK:
#endif
#if defined(HAVE_F_OWNER_EX)
	case F_GETOWN_EX:
	case F_SETOWN_EX:
#endif
#if defined(HAVE_RW_HINTS)
	case F_GET_RW_HINT:
	case F_SET_RW_HINT:
	case F_GET_FILE_RW_HINT:
	case F_SET_FILE_RW_HINT:
#endif
		argp = va_arg(dup_cmd_arg, void *);
		result = sys_fcntl_ptr(fsp->fh->fd, cmd, argp);
		break;
	default:
		val = va_arg(dup_cmd_arg, int);
		result = sys_fcntl_int(fsp->fh->fd, cmd, val);
	}

	va_end(dup_cmd_arg);

	END_PROFILE(syscall_fcntl);
	return result;
}

static bool vfswrap_getlock(vfs_handle_struct *handle, files_struct *fsp, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid)
{
	bool result;
	int op = F_GETLK;

	START_PROFILE(syscall_fcntl_getlock);

	if (fsp->fsp_flags.use_ofd_locks) {
		op = map_process_lock_to_ofd_lock(op);
	}

	result = fcntl_getlock(fsp->fh->fd, op, poffset, pcount, ptype, ppid);
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

static int vfswrap_symlinkat(vfs_handle_struct *handle,
			const struct smb_filename *link_target,
			struct files_struct *dirfsp,
			const struct smb_filename *new_smb_fname)
{
	int result;

	START_PROFILE(syscall_symlinkat);

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	result = symlinkat(link_target->base_name,
			dirfsp->fh->fd,
			new_smb_fname->base_name);
	END_PROFILE(syscall_symlinkat);
	return result;
}

static int vfswrap_readlinkat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	int result;

	START_PROFILE(syscall_readlinkat);

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	result = readlinkat(dirfsp->fh->fd,
			smb_fname->base_name,
			buf,
			bufsiz);

	END_PROFILE(syscall_readlinkat);
	return result;
}

static int vfswrap_linkat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags)
{
	int result;

	START_PROFILE(syscall_linkat);

	SMB_ASSERT(srcfsp == srcfsp->conn->cwd_fsp);
	SMB_ASSERT(dstfsp == dstfsp->conn->cwd_fsp);

	result = linkat(srcfsp->fh->fd,
			old_smb_fname->base_name,
			dstfsp->fh->fd,
			new_smb_fname->base_name,
			flags);

	END_PROFILE(syscall_linkat);
	return result;
}

static int vfswrap_mknodat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	int result;

	START_PROFILE(syscall_mknodat);

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	result = sys_mknodat(dirfsp->fh->fd,
			smb_fname->base_name,
			mode,
			dev);

	END_PROFILE(syscall_mknodat);
	return result;
}

static struct smb_filename *vfswrap_realpath(vfs_handle_struct *handle,
			TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname)
{
	char *result;
	struct smb_filename *result_fname = NULL;

	START_PROFILE(syscall_realpath);
	result = sys_realpath(smb_fname->base_name);
	END_PROFILE(syscall_realpath);
	if (result) {
		result_fname = synthetic_smb_fname(ctx,
						   result,
						   NULL,
						   NULL,
						   0,
						   0);
		SAFE_FREE(result);
	}
	return result_fname;
}

static int vfswrap_chflags(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			unsigned int flags)
{
#ifdef HAVE_CHFLAGS
	return chflags(smb_fname->base_name, flags);
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

static uint64_t vfswrap_fs_file_id(struct vfs_handle_struct *handle,
				   const SMB_STRUCT_STAT *psbuf)
{
	uint64_t file_id;

	if (!(psbuf->st_ex_iflags & ST_EX_IFLAG_CALCULATED_FILE_ID)) {
		return psbuf->st_ex_file_id;
	}

	if (handle->conn->base_share_dev == psbuf->st_ex_dev) {
		return (uint64_t)psbuf->st_ex_ino;
	}

	/* FileIDLow */
	file_id = ((psbuf->st_ex_ino) & UINT32_MAX);

	/* FileIDHigh */
	file_id |= ((uint64_t)((psbuf->st_ex_dev) & UINT32_MAX)) << 32;

	return file_id;
}

static NTSTATUS vfswrap_streaminfo(vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   const struct smb_filename *smb_fname,
				   TALLOC_CTX *mem_ctx,
				   unsigned int *pnum_streams,
				   struct stream_struct **pstreams)
{
	SMB_STRUCT_STAT sbuf;
	struct stream_struct *tmp_streams = NULL;
	int ret;

	if ((fsp != NULL) && (fsp->fsp_flags.is_directory)) {
		/*
		 * No default streams on directories
		 */
		goto done;
	}

	if ((fsp != NULL) && (fsp->fh->fd != -1)) {
		ret = SMB_VFS_FSTAT(fsp, &sbuf);
	}
	else {
		struct smb_filename *smb_fname_cp = NULL;

		smb_fname_cp = cp_smb_filename_nostream(talloc_tos(), smb_fname);
		if (smb_fname_cp == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		if (smb_fname_cp->flags & SMB_FILENAME_POSIX_PATH) {
			ret = SMB_VFS_LSTAT(handle->conn, smb_fname_cp);
		} else {
			ret = SMB_VFS_STAT(handle->conn, smb_fname_cp);
		}
		sbuf = smb_fname_cp->st;
		TALLOC_FREE(smb_fname_cp);
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
				     const struct smb_filename *path,
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
				   const struct smb_filename *smb_fname)
{
	return handle->conn->connectpath;
}

static NTSTATUS vfswrap_brl_lock_windows(struct vfs_handle_struct *handle,
					 struct byte_range_lock *br_lck,
					 struct lock_struct *plock)
{
	SMB_ASSERT(plock->lock_flav == WINDOWS_LOCK);

	/* Note: blr is not used in the default implementation. */
	return brl_lock_windows_default(br_lck, plock);
}

static bool vfswrap_brl_unlock_windows(struct vfs_handle_struct *handle,
				       struct byte_range_lock *br_lck,
			               const struct lock_struct *plock)
{
	SMB_ASSERT(plock->lock_flav == WINDOWS_LOCK);

	return brl_unlock_windows_default(br_lck, plock);
}

static bool vfswrap_strict_lock_check(struct vfs_handle_struct *handle,
				      files_struct *fsp,
				      struct lock_struct *plock)
{
	SMB_ASSERT(plock->lock_type == READ_LOCK ||
	    plock->lock_type == WRITE_LOCK);

	return strict_lock_check_default(fsp, plock);
}

/* NT ACL operations. */

static NTSTATUS vfswrap_fget_nt_acl(vfs_handle_struct *handle,
				    files_struct *fsp,
				    uint32_t security_info,
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

static NTSTATUS vfswrap_get_nt_acl_at(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			uint32_t security_info,
			TALLOC_CTX *mem_ctx,
			struct security_descriptor **ppdesc)
{
	NTSTATUS result;

	START_PROFILE(get_nt_acl_at);

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	result = posix_get_nt_acl(handle->conn,
				smb_fname,
				security_info,
				mem_ctx,
				ppdesc);
	END_PROFILE(get_nt_acl_at);
	return result;
}

static NTSTATUS vfswrap_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp, uint32_t security_info_sent, const struct security_descriptor *psd)
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

static SMB_ACL_T vfswrap_sys_acl_get_file(vfs_handle_struct *handle,
					  const struct smb_filename *smb_fname,
					  SMB_ACL_TYPE_T type,
					  TALLOC_CTX *mem_ctx)
{
	return sys_acl_get_file(handle, smb_fname, type, mem_ctx);
}

static SMB_ACL_T vfswrap_sys_acl_get_fd(vfs_handle_struct *handle,
					files_struct *fsp,
					TALLOC_CTX *mem_ctx)
{
	return sys_acl_get_fd(handle, fsp, mem_ctx);
}

static int vfswrap_sys_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl)
{
	return sys_acl_set_file(handle, smb_fname, acltype, theacl);
}

static int vfswrap_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp, SMB_ACL_T theacl)
{
	return sys_acl_set_fd(handle, fsp, theacl);
}

static int vfswrap_sys_acl_delete_def_file(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	return sys_acl_delete_def_file(handle, smb_fname);
}

/****************************************************************
 Extended attribute operations.
*****************************************************************/

static ssize_t vfswrap_getxattr(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name,
			void *value,
			size_t size)
{
	return getxattr(smb_fname->base_name, name, value, size);
}

struct vfswrap_getxattrat_state {
	struct tevent_context *ev;
	files_struct *dir_fsp;
	const struct smb_filename *smb_fname;

	/*
	 * The following variables are talloced off "state" which is protected
	 * by a destructor and thus are guaranteed to be safe to be used in the
	 * job function in the worker thread.
	 */
	char *name;
	const char *xattr_name;
	uint8_t *xattr_value;
	struct security_unix_token *token;

	ssize_t xattr_size;
	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static int vfswrap_getxattrat_state_destructor(
		struct vfswrap_getxattrat_state *state)
{
	return -1;
}

static void vfswrap_getxattrat_do_sync(struct tevent_req *req);
static void vfswrap_getxattrat_do_async(void *private_data);
static void vfswrap_getxattrat_done(struct tevent_req *subreq);

static struct tevent_req *vfswrap_getxattrat_send(
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
	struct vfswrap_getxattrat_state *state = NULL;
	size_t max_threads = 0;
	bool have_per_thread_cwd = false;
	bool have_per_thread_creds = false;
	bool do_async = false;

	req = tevent_req_create(mem_ctx, &state,
				struct vfswrap_getxattrat_state);
	if (req == NULL) {
		return NULL;
	}
	*state = (struct vfswrap_getxattrat_state) {
		.ev = ev,
		.dir_fsp = dir_fsp,
		.smb_fname = smb_fname,
	};

	max_threads = pthreadpool_tevent_max_threads(dir_fsp->conn->sconn->pool);
	if (max_threads >= 1) {
		/*
		 * We need a non sync threadpool!
		 */
		have_per_thread_cwd = per_thread_cwd_supported();
	}
#ifdef HAVE_LINUX_THREAD_CREDENTIALS
	have_per_thread_creds = true;
#endif
	if (have_per_thread_cwd && have_per_thread_creds) {
		do_async = true;
	}

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_getxattrat, profile_p,
				     state->profile_bytes, 0);

	if (dir_fsp->fh->fd == -1) {
		DBG_ERR("Need a valid directory fd\n");
		tevent_req_error(req, EINVAL);
		return tevent_req_post(req, ev);
	}

	if (alloc_hint > 0) {
		state->xattr_value = talloc_zero_array(state,
						       uint8_t,
						       alloc_hint);
		if (tevent_req_nomem(state->xattr_value, req)) {
			return tevent_req_post(req, ev);
		}
	}

	if (!do_async) {
		vfswrap_getxattrat_do_sync(req);
		return tevent_req_post(req, ev);
	}

	/*
	 * Now allocate all parameters from a memory context that won't go away
	 * no matter what. These paremeters will get used in threads and we
	 * can't reliably cancel threads, so all buffers passed to the threads
	 * must not be freed before all referencing threads terminate.
	 */

	state->name = talloc_strdup(state, smb_fname->base_name);
	if (tevent_req_nomem(state->name, req)) {
		return tevent_req_post(req, ev);
	}

	state->xattr_name = talloc_strdup(state, xattr_name);
	if (tevent_req_nomem(state->xattr_name, req)) {
		return tevent_req_post(req, ev);
	}

	/*
	 * This is a hot codepath so at first glance one might think we should
	 * somehow optimize away the token allocation and do a
	 * talloc_reference() or similar black magic instead. But due to the
	 * talloc_stackframe pool per SMB2 request this should be a simple copy
	 * without a malloc in most cases.
	 */
	if (geteuid() == sec_initial_uid()) {
		state->token = root_unix_token(state);
	} else {
		state->token = copy_unix_token(
					state,
					dir_fsp->conn->session_info->unix_token);
	}
	if (tevent_req_nomem(state->token, req)) {
		return tevent_req_post(req, ev);
	}

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	subreq = pthreadpool_tevent_job_send(
			state,
			ev,
			dir_fsp->conn->sconn->pool,
			vfswrap_getxattrat_do_async,
			state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfswrap_getxattrat_done, req);

	talloc_set_destructor(state, vfswrap_getxattrat_state_destructor);

	return req;
}

static void vfswrap_getxattrat_do_sync(struct tevent_req *req)
{
	struct vfswrap_getxattrat_state *state = tevent_req_data(
		req, struct vfswrap_getxattrat_state);
	char *path = NULL;
	char *tofree = NULL;
	char pathbuf[PATH_MAX+1];
	ssize_t pathlen;
	int err;

	pathlen = full_path_tos(state->dir_fsp->fsp_name->base_name,
				state->smb_fname->base_name,
				pathbuf,
				sizeof(pathbuf),
				&path,
				&tofree);
	if (pathlen == -1) {
		tevent_req_error(req, ENOMEM);
		return;
	}

	state->xattr_size = getxattr(path,
				     state->xattr_name,
				     state->xattr_value,
				     talloc_array_length(state->xattr_value));
	err = errno;
	TALLOC_FREE(tofree);
	if (state->xattr_size == -1) {
		tevent_req_error(req, err);
		return;
	}

	tevent_req_done(req);
	return;
}

static void vfswrap_getxattrat_do_async(void *private_data)
{
	struct vfswrap_getxattrat_state *state = talloc_get_type_abort(
		private_data, struct vfswrap_getxattrat_state);
	struct timespec start_time;
	struct timespec end_time;
	int ret;

	PROFILE_TIMESTAMP(&start_time);
	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);

	/*
	 * Here we simulate a getxattrat()
	 * call using fchdir();getxattr()
	 */

	per_thread_cwd_activate();

	/* Become the correct credential on this thread. */
	ret = set_thread_credentials(state->token->uid,
				     state->token->gid,
				     (size_t)state->token->ngroups,
				     state->token->groups);
	if (ret != 0) {
		state->xattr_size = -1;
		state->vfs_aio_state.error = errno;
		goto end_profile;
	}

	ret = fchdir(state->dir_fsp->fh->fd);
	if (ret == -1) {
		state->xattr_size = -1;
		state->vfs_aio_state.error = errno;
		goto end_profile;
	}

	state->xattr_size = getxattr(state->name,
				     state->xattr_name,
				     state->xattr_value,
				     talloc_array_length(state->xattr_value));
	if (state->xattr_size == -1) {
		state->vfs_aio_state.error = errno;
	}

end_profile:
	PROFILE_TIMESTAMP(&end_time);
	state->vfs_aio_state.duration = nsec_time_diff(&end_time, &start_time);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
}

static void vfswrap_getxattrat_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfswrap_getxattrat_state *state = tevent_req_data(
		req, struct vfswrap_getxattrat_state);
	int ret;
	bool ok;

	/*
	 * Make sure we run as the user again
	 */
	ok = change_to_user_and_service_by_fsp(state->dir_fsp);
	SMB_ASSERT(ok);

	ret = pthreadpool_tevent_job_recv(subreq);
	TALLOC_FREE(subreq);
	SMBPROFILE_BYTES_ASYNC_END(state->profile_bytes);
	talloc_set_destructor(state, NULL);
	if (ret != 0) {
		if (ret != EAGAIN) {
			tevent_req_error(req, ret);
			return;
		}
		/*
		 * If we get EAGAIN from pthreadpool_tevent_job_recv() this
		 * means the lower level pthreadpool failed to create a new
		 * thread. Fallback to sync processing in that case to allow
		 * some progress for the client.
		 */
		vfswrap_getxattrat_do_sync(req);
		return;
	}

	if (state->xattr_size == -1) {
		tevent_req_error(req, state->vfs_aio_state.error);
		return;
	}

	if (state->xattr_value == NULL) {
		/*
		 * The caller only wanted the size.
		 */
		tevent_req_done(req);
		return;
	}

	/*
	 * shrink the buffer to the returned size.
	 * (can't fail). It means NULL if size is 0.
	 */
	state->xattr_value = talloc_realloc(state,
					    state->xattr_value,
					    uint8_t,
					    state->xattr_size);

	tevent_req_done(req);
}

static ssize_t vfswrap_getxattrat_recv(struct tevent_req *req,
				       struct vfs_aio_state *aio_state,
				       TALLOC_CTX *mem_ctx,
				       uint8_t **xattr_value)
{
	struct vfswrap_getxattrat_state *state = tevent_req_data(
		req, struct vfswrap_getxattrat_state);
	ssize_t xattr_size;

	if (tevent_req_is_unix_error(req, &aio_state->error)) {
		tevent_req_received(req);
		return -1;
	}

	*aio_state = state->vfs_aio_state;
	xattr_size = state->xattr_size;
	if (xattr_value != NULL) {
		*xattr_value = talloc_move(mem_ctx, &state->xattr_value);
	}

	tevent_req_received(req);
	return xattr_size;
}

static ssize_t vfswrap_fgetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, void *value, size_t size)
{
	return fgetxattr(fsp->fh->fd, name, value, size);
}

static ssize_t vfswrap_listxattr(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			char *list,
			size_t size)
{
	return listxattr(smb_fname->base_name, list, size);
}

static ssize_t vfswrap_flistxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, char *list, size_t size)
{
	return flistxattr(fsp->fh->fd, list, size);
}

static int vfswrap_removexattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name)
{
	return removexattr(smb_fname->base_name, name);
}

static int vfswrap_fremovexattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name)
{
	return fremovexattr(fsp->fh->fd, name);
}

static int vfswrap_setxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				const void *value,
				size_t size,
				int flags)
{
	return setxattr(smb_fname->base_name, name, value, size, flags);
}

static int vfswrap_fsetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, const void *value, size_t size, int flags)
{
	return fsetxattr(fsp->fh->fd, name, value, size, flags);
}

static bool vfswrap_aio_force(struct vfs_handle_struct *handle, struct files_struct *fsp)
{
	return false;
}

static bool vfswrap_is_offline(struct connection_struct *conn,
			       const struct smb_filename *fname)
{
	NTSTATUS status;
	char *path;
	bool offline = false;

        if (ISDOT(fname->base_name) || ISDOTDOT(fname->base_name)) {
		return false;
	}

	if (!lp_dmapi_support(SNUM(conn)) || !dmapi_have_session()) {
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
	.create_dfs_pathat_fn = vfswrap_create_dfs_pathat,
	.read_dfs_pathat_fn = vfswrap_read_dfs_pathat,
	.snap_check_path_fn = vfswrap_snap_check_path,
	.snap_create_fn = vfswrap_snap_create,
	.snap_delete_fn = vfswrap_snap_delete,

	/* Directory operations */

	.fdopendir_fn = vfswrap_fdopendir,
	.readdir_fn = vfswrap_readdir,
	.readdir_attr_fn = vfswrap_readdir_attr,
	.seekdir_fn = vfswrap_seekdir,
	.telldir_fn = vfswrap_telldir,
	.rewind_dir_fn = vfswrap_rewinddir,
	.mkdirat_fn = vfswrap_mkdirat,
	.closedir_fn = vfswrap_closedir,

	/* File operations */

	.openat_fn = vfswrap_openat,
	.create_file_fn = vfswrap_create_file,
	.close_fn = vfswrap_close,
	.pread_fn = vfswrap_pread,
	.pread_send_fn = vfswrap_pread_send,
	.pread_recv_fn = vfswrap_pread_recv,
	.pwrite_fn = vfswrap_pwrite,
	.pwrite_send_fn = vfswrap_pwrite_send,
	.pwrite_recv_fn = vfswrap_pwrite_recv,
	.lseek_fn = vfswrap_lseek,
	.sendfile_fn = vfswrap_sendfile,
	.recvfile_fn = vfswrap_recvfile,
	.renameat_fn = vfswrap_renameat,
	.fsync_send_fn = vfswrap_fsync_send,
	.fsync_recv_fn = vfswrap_fsync_recv,
	.stat_fn = vfswrap_stat,
	.fstat_fn = vfswrap_fstat,
	.lstat_fn = vfswrap_lstat,
	.get_alloc_size_fn = vfswrap_get_alloc_size,
	.unlinkat_fn = vfswrap_unlinkat,
	.chmod_fn = vfswrap_chmod,
	.fchmod_fn = vfswrap_fchmod,
	.fchown_fn = vfswrap_fchown,
	.lchown_fn = vfswrap_lchown,
	.chdir_fn = vfswrap_chdir,
	.getwd_fn = vfswrap_getwd,
	.ntimes_fn = vfswrap_ntimes,
	.ftruncate_fn = vfswrap_ftruncate,
	.fallocate_fn = vfswrap_fallocate,
	.lock_fn = vfswrap_lock,
	.kernel_flock_fn = vfswrap_kernel_flock,
	.fcntl_fn = vfswrap_fcntl,
	.linux_setlease_fn = vfswrap_linux_setlease,
	.getlock_fn = vfswrap_getlock,
	.symlinkat_fn = vfswrap_symlinkat,
	.readlinkat_fn = vfswrap_readlinkat,
	.linkat_fn = vfswrap_linkat,
	.mknodat_fn = vfswrap_mknodat,
	.realpath_fn = vfswrap_realpath,
	.chflags_fn = vfswrap_chflags,
	.file_id_create_fn = vfswrap_file_id_create,
	.fs_file_id_fn = vfswrap_fs_file_id,
	.streaminfo_fn = vfswrap_streaminfo,
	.get_real_filename_fn = vfswrap_get_real_filename,
	.connectpath_fn = vfswrap_connectpath,
	.brl_lock_windows_fn = vfswrap_brl_lock_windows,
	.brl_unlock_windows_fn = vfswrap_brl_unlock_windows,
	.strict_lock_check_fn = vfswrap_strict_lock_check,
	.translate_name_fn = vfswrap_translate_name,
	.fsctl_fn = vfswrap_fsctl,
	.set_dos_attributes_fn = vfswrap_set_dos_attributes,
	.fset_dos_attributes_fn = vfswrap_fset_dos_attributes,
	.get_dos_attributes_fn = vfswrap_get_dos_attributes,
	.get_dos_attributes_send_fn = vfswrap_get_dos_attributes_send,
	.get_dos_attributes_recv_fn = vfswrap_get_dos_attributes_recv,
	.fget_dos_attributes_fn = vfswrap_fget_dos_attributes,
	.offload_read_send_fn = vfswrap_offload_read_send,
	.offload_read_recv_fn = vfswrap_offload_read_recv,
	.offload_write_send_fn = vfswrap_offload_write_send,
	.offload_write_recv_fn = vfswrap_offload_write_recv,
	.get_compression_fn = vfswrap_get_compression,
	.set_compression_fn = vfswrap_set_compression,

	/* NT ACL operations. */

	.fget_nt_acl_fn = vfswrap_fget_nt_acl,
	.get_nt_acl_at_fn = vfswrap_get_nt_acl_at,
	.fset_nt_acl_fn = vfswrap_fset_nt_acl,
	.audit_file_fn = vfswrap_audit_file,

	/* POSIX ACL operations. */

	.sys_acl_get_file_fn = vfswrap_sys_acl_get_file,
	.sys_acl_get_fd_fn = vfswrap_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = posix_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = vfswrap_sys_acl_set_file,
	.sys_acl_set_fd_fn = vfswrap_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = vfswrap_sys_acl_delete_def_file,

	/* EA operations. */
	.getxattr_fn = vfswrap_getxattr,
	.getxattrat_send_fn = vfswrap_getxattrat_send,
	.getxattrat_recv_fn = vfswrap_getxattrat_recv,
	.fgetxattr_fn = vfswrap_fgetxattr,
	.listxattr_fn = vfswrap_listxattr,
	.flistxattr_fn = vfswrap_flistxattr,
	.removexattr_fn = vfswrap_removexattr,
	.fremovexattr_fn = vfswrap_fremovexattr,
	.setxattr_fn = vfswrap_setxattr,
	.fsetxattr_fn = vfswrap_fsetxattr,

	/* aio operations */
	.aio_force_fn = vfswrap_aio_force,

	/* durable handle operations */
	.durable_cookie_fn = vfswrap_durable_cookie,
	.durable_disconnect_fn = vfswrap_durable_disconnect,
	.durable_reconnect_fn = vfswrap_durable_reconnect,
};

static_decl_vfs;
NTSTATUS vfs_default_init(TALLOC_CTX *ctx)
{
	/*
	 * Here we need to implement every call!
	 *
	 * As this is the end of the vfs module chain.
	 */
	smb_vfs_assert_all_fns(&vfs_default_fns, DEFAULT_VFS_MODULE_NAME);
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				DEFAULT_VFS_MODULE_NAME, &vfs_default_fns);
}


