/*
   Unix SMB/CIFS implementation.
   Wrap disk only vfs functions to sidestep dodgy compilers.
   Copyright (C) Tim Potter 1998
   Copyright (C) Jeremy Allison 2007
   Copyright (C) Brian Chrisman 2011 <bchrisman@gmail.com>
   Copyright (C) Richard Sharpe 2011 <realrichardsharpe@gmail.com>

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
 * This VFS only works with the libceph.so user-space client. It is not needed
 * if you are using the kernel client or the FUSE client.
 *
 * Add the following smb.conf parameter to each share that will be hosted on
 * Ceph:
 *
 *   vfs objects = ceph [any others you need go here]
 */

#include "includes.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include <dirent.h>
#include <sys/statvfs.h>
#include "cephfs/libcephfs.h"
#include "smbprofile.h"
#include "modules/posixacl_xattr.h"
#include "lib/util/tevent_unix.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#ifndef LIBCEPHFS_VERSION
#define LIBCEPHFS_VERSION(maj, min, extra) ((maj << 16) + (min << 8) + extra)
#define LIBCEPHFS_VERSION_CODE LIBCEPHFS_VERSION(0, 0, 0)
#endif

/*
 * Use %llu whenever we have a 64bit unsigned int, and cast to (long long unsigned)
 */
#define llu(_var) ((long long unsigned)_var)

/*
 * Note, libceph's return code model is to return -errno! So we have to convert
 * to what Samba expects, with is set errno to -return and return -1
 */
#define WRAP_RETURN(_res) \
	errno = 0; \
	if (_res < 0) { \
		errno = -_res; \
		return -1; \
	} \
	return _res \

/*
 * We mount only one file system and then all shares are assumed to be in that.
 * FIXME: If we want to support more than one FS, then we have to deal with
 * this differently.
 *
 * So, cmount tells us if we have been this way before and whether
 * we need to mount ceph and cmount_cnt tells us how many times we have
 * connected
 */
static struct ceph_mount_info * cmount = NULL;
static uint32_t cmount_cnt = 0;

/* Check for NULL pointer parameters in cephwrap_* functions */

/* We don't want to have NULL function pointers lying around.  Someone
   is sure to try and execute them.  These stubs are used to prevent
   this possibility. */

static int cephwrap_connect(struct vfs_handle_struct *handle,  const char *service, const char *user)
{
	int ret;
	char buf[256];
	int snum = SNUM(handle->conn);
	const char *conf_file;
	const char *user_id;

	if (cmount) {
		handle->data = cmount; /* We have been here before */
		cmount_cnt++;
		return 0;
	}

	/* if config_file and/or user_id are NULL, ceph will use defaults */
	conf_file = lp_parm_const_string(snum, "ceph", "config_file", NULL);
	user_id = lp_parm_const_string(snum, "ceph", "user_id", NULL);

	DBG_DEBUG("[CEPH] calling: ceph_create\n");
	ret = ceph_create(&cmount, user_id);
	if (ret) {
		goto err_out;
	}

	DBG_DEBUG("[CEPH] calling: ceph_conf_read_file with %s\n",
		  (conf_file == NULL ? "default path" : conf_file));
	ret = ceph_conf_read_file(cmount, conf_file);
	if (ret) {
		goto err_cm_release;
	}

	DBG_DEBUG("[CEPH] calling: ceph_conf_get\n");
	ret = ceph_conf_get(cmount, "log file", buf, sizeof(buf));
	if (ret < 0) {
		goto err_cm_release;
	}

	/* libcephfs disables POSIX ACL support by default, enable it... */
	ret = ceph_conf_set(cmount, "client_acl_type", "posix_acl");
	if (ret < 0) {
		goto err_cm_release;
	}
	/* tell libcephfs to perform local permission checks */
	ret = ceph_conf_set(cmount, "fuse_default_permissions", "false");
	if (ret < 0) {
		goto err_cm_release;
	}

	DBG_DEBUG("[CEPH] calling: ceph_mount\n");
	ret = ceph_mount(cmount, NULL);
	if (ret < 0) {
		goto err_cm_release;
	}

	/*
	 * encode mount context/state into our vfs/connection holding structure
	 * cmount is a ceph_mount_t*
	 */
	handle->data = cmount;
	cmount_cnt++;

	/*
	 * Unless we have an async implementation of getxattrat turn this off.
	 */
	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");

	return 0;

err_cm_release:
	ceph_release(cmount);
	cmount = NULL;
err_out:
	/*
	 * Handle the error correctly. Ceph returns -errno.
	 */
	DBG_DEBUG("[CEPH] Error return: %s\n", strerror(-ret));
	WRAP_RETURN(ret);
}

static void cephwrap_disconnect(struct vfs_handle_struct *handle)
{
	int ret;

	if (!cmount) {
		DBG_ERR("[CEPH] Error, ceph not mounted\n");
		return;
	}

	/* Should we unmount/shutdown? Only if the last disconnect? */
	if (--cmount_cnt) {
		DBG_DEBUG("[CEPH] Not shuting down CEPH because still more connections\n");
		return;
	}

	ret = ceph_unmount(cmount);
	if (ret < 0) {
		DBG_ERR("[CEPH] failed to unmount: %s\n", strerror(-ret));
	}

	ret = ceph_release(cmount);
	if (ret < 0) {
		DBG_ERR("[CEPH] failed to release: %s\n", strerror(-ret));
	}

	cmount = NULL;  /* Make it safe */
}

/* Disk operations */

static uint64_t cephwrap_disk_free(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	struct statvfs statvfs_buf;
	int ret;

	if (!(ret = ceph_statfs(handle->data, smb_fname->base_name,
			&statvfs_buf))) {
		/*
		 * Provide all the correct values.
		 */
		*bsize = statvfs_buf.f_bsize;
		*dfree = statvfs_buf.f_bavail;
		*dsize = statvfs_buf.f_blocks;
		DBG_DEBUG("[CEPH] bsize: %llu, dfree: %llu, dsize: %llu\n",
			llu(*bsize), llu(*dfree), llu(*dsize));
		return *dfree;
	} else {
		DBG_DEBUG("[CEPH] ceph_statfs returned %d\n", ret);
		WRAP_RETURN(ret);
	}
}

static int cephwrap_get_quota(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *qt)
{
	/* libceph: Ceph does not implement this */
#if 0
/* was ifdef HAVE_SYS_QUOTAS */
	int ret;

	ret = ceph_get_quota(handle->conn->connectpath, qtype, id, qt);

	if (ret) {
		errno = -ret;
		ret = -1;
	}

	return ret;
#else
	errno = ENOSYS;
	return -1;
#endif
}

static int cephwrap_set_quota(struct vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *qt)
{
	/* libceph: Ceph does not implement this */
#if 0
/* was ifdef HAVE_SYS_QUOTAS */
	int ret;

	ret = ceph_set_quota(handle->conn->connectpath, qtype, id, qt);
	if (ret) {
		errno = -ret;
		ret = -1;
	}

	return ret;
#else
	WRAP_RETURN(-ENOSYS);
#endif
}

static int cephwrap_statvfs(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				vfs_statvfs_struct *statbuf)
{
	struct statvfs statvfs_buf;
	int ret;

	ret = ceph_statfs(handle->data, smb_fname->base_name, &statvfs_buf);
	if (ret < 0) {
		WRAP_RETURN(ret);
	}

	statbuf->OptimalTransferSize = statvfs_buf.f_frsize;
	statbuf->BlockSize = statvfs_buf.f_bsize;
	statbuf->TotalBlocks = statvfs_buf.f_blocks;
	statbuf->BlocksAvail = statvfs_buf.f_bfree;
	statbuf->UserBlocksAvail = statvfs_buf.f_bavail;
	statbuf->TotalFileNodes = statvfs_buf.f_files;
	statbuf->FreeFileNodes = statvfs_buf.f_ffree;
	statbuf->FsIdentifier = statvfs_buf.f_fsid;
	DBG_DEBUG("[CEPH] f_bsize: %ld, f_blocks: %ld, f_bfree: %ld, f_bavail: %ld\n",
		(long int)statvfs_buf.f_bsize, (long int)statvfs_buf.f_blocks,
		(long int)statvfs_buf.f_bfree, (long int)statvfs_buf.f_bavail);

	return ret;
}

static uint32_t cephwrap_fs_capabilities(struct vfs_handle_struct *handle,
					 enum timestamp_set_resolution *p_ts_res)
{
	uint32_t caps = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;

	*p_ts_res = TIMESTAMP_SET_NT_OR_BETTER;

	return caps;
}

/* Directory operations */

static DIR *cephwrap_fdopendir(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       const char *mask,
			       uint32_t attributes)
{
	int ret = 0;
	struct ceph_dir_result *result;
	DBG_DEBUG("[CEPH] fdopendir(%p, %p)\n", handle, fsp);

	ret = ceph_opendir(handle->data, fsp->fsp_name->base_name, &result);
	if (ret < 0) {
		result = NULL;
		errno = -ret; /* We return result which is NULL in this case */
	}

	DBG_DEBUG("[CEPH] fdopendir(...) = %d\n", ret);
	return (DIR *) result;
}

static struct dirent *cephwrap_readdir(struct vfs_handle_struct *handle,
				       DIR *dirp,
				       SMB_STRUCT_STAT *sbuf)
{
	struct dirent *result;

	DBG_DEBUG("[CEPH] readdir(%p, %p)\n", handle, dirp);
	result = ceph_readdir(handle->data, (struct ceph_dir_result *) dirp);
	DBG_DEBUG("[CEPH] readdir(...) = %p\n", result);

	/* Default Posix readdir() does not give us stat info.
	 * Set to invalid to indicate we didn't return this info. */
	if (sbuf)
		SET_STAT_INVALID(*sbuf);
	return result;
}

static void cephwrap_seekdir(struct vfs_handle_struct *handle, DIR *dirp, long offset)
{
	DBG_DEBUG("[CEPH] seekdir(%p, %p, %ld)\n", handle, dirp, offset);
	ceph_seekdir(handle->data, (struct ceph_dir_result *) dirp, offset);
}

static long cephwrap_telldir(struct vfs_handle_struct *handle, DIR *dirp)
{
	long ret;
	DBG_DEBUG("[CEPH] telldir(%p, %p)\n", handle, dirp);
	ret = ceph_telldir(handle->data, (struct ceph_dir_result *) dirp);
	DBG_DEBUG("[CEPH] telldir(...) = %ld\n", ret);
	WRAP_RETURN(ret);
}

static void cephwrap_rewinddir(struct vfs_handle_struct *handle, DIR *dirp)
{
	DBG_DEBUG("[CEPH] rewinddir(%p, %p)\n", handle, dirp);
	ceph_rewinddir(handle->data, (struct ceph_dir_result *) dirp);
}

static int cephwrap_mkdirat(struct vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int result;
	struct smb_filename *parent = NULL;
	bool ok;

	DBG_DEBUG("[CEPH] mkdir(%p, %s)\n",
		  handle, smb_fname_str_dbg(smb_fname));

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	if (lp_inherit_acls(SNUM(handle->conn))) {
		ok = parent_smb_fname(talloc_tos(), smb_fname, &parent, NULL);
		if (ok && directory_has_default_acl(handle->conn,
				dirfsp,
				parent))
		{
			mode = 0777;
		}
	}

	TALLOC_FREE(parent);

	result = ceph_mkdir(handle->data, smb_fname->base_name, mode);
	return WRAP_RETURN(result);
}

static int cephwrap_closedir(struct vfs_handle_struct *handle, DIR *dirp)
{
	int result;

	DBG_DEBUG("[CEPH] closedir(%p, %p)\n", handle, dirp);
	result = ceph_closedir(handle->data, (struct ceph_dir_result *) dirp);
	DBG_DEBUG("[CEPH] closedir(...) = %d\n", result);
	WRAP_RETURN(result);
}

/* File operations */

static int cephwrap_openat(struct vfs_handle_struct *handle,
			   const struct files_struct *dirfsp,
			   const struct smb_filename *smb_fname,
			   files_struct *fsp,
			   int flags,
			   mode_t mode)
{
	int result = -ENOENT;

	/*
	 * cephfs API doesn't have ceph_openat(), so for now assert this.
	 */
	SMB_ASSERT(dirfsp->fh->fd == AT_FDCWD);

	DBG_DEBUG("[CEPH] openat(%p, %s, %p, %d, %d)\n", handle,
		  smb_fname_str_dbg(smb_fname), fsp, flags, mode);

	if (smb_fname->stream_name) {
		goto out;
	}

	result = ceph_open(handle->data, smb_fname->base_name, flags, mode);
out:
	DBG_DEBUG("[CEPH] open(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cephwrap_close(struct vfs_handle_struct *handle, files_struct *fsp)
{
	int result;

	DBG_DEBUG("[CEPH] close(%p, %p)\n", handle, fsp);
	result = ceph_close(handle->data, fsp->fh->fd);
	DBG_DEBUG("[CEPH] close(...) = %d\n", result);

	WRAP_RETURN(result);
}

static ssize_t cephwrap_pread(struct vfs_handle_struct *handle, files_struct *fsp, void *data,
			size_t n, off_t offset)
{
	ssize_t result;

	DBG_DEBUG("[CEPH] pread(%p, %p, %p, %llu, %llu)\n", handle, fsp, data, llu(n), llu(offset));

	result = ceph_read(handle->data, fsp->fh->fd, data, n, offset);
	DBG_DEBUG("[CEPH] pread(...) = %llu\n", llu(result));
	WRAP_RETURN(result);
}

struct cephwrap_pread_state {
	ssize_t bytes_read;
	struct vfs_aio_state vfs_aio_state;
};

/*
 * Fake up an async ceph read by calling the synchronous API.
 */
static struct tevent_req *cephwrap_pread_send(struct vfs_handle_struct *handle,
					      TALLOC_CTX *mem_ctx,
					      struct tevent_context *ev,
					      struct files_struct *fsp,
					      void *data,
					      size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct cephwrap_pread_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] %s\n", __func__);
	req = tevent_req_create(mem_ctx, &state, struct cephwrap_pread_state);
	if (req == NULL) {
		return NULL;
	}

	ret = ceph_read(handle->data, fsp->fh->fd, data, n, offset);
	if (ret < 0) {
		/* ceph returns -errno on error. */
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	state->bytes_read = ret;
	tevent_req_done(req);
	/* Return and schedule the completion of the call. */
	return tevent_req_post(req, ev);
}

static ssize_t cephwrap_pread_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state)
{
	struct cephwrap_pread_state *state =
		tevent_req_data(req, struct cephwrap_pread_state);

	DBG_DEBUG("[CEPH] %s\n", __func__);
	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->bytes_read;
}

static ssize_t cephwrap_pwrite(struct vfs_handle_struct *handle, files_struct *fsp, const void *data,
			size_t n, off_t offset)
{
	ssize_t result;

	DBG_DEBUG("[CEPH] pwrite(%p, %p, %p, %llu, %llu)\n", handle, fsp, data, llu(n), llu(offset));
	result = ceph_write(handle->data, fsp->fh->fd, data, n, offset);
	DBG_DEBUG("[CEPH] pwrite(...) = %llu\n", llu(result));
	WRAP_RETURN(result);
}

struct cephwrap_pwrite_state {
	ssize_t bytes_written;
	struct vfs_aio_state vfs_aio_state;
};

/*
 * Fake up an async ceph write by calling the synchronous API.
 */
static struct tevent_req *cephwrap_pwrite_send(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct tevent_context *ev,
					       struct files_struct *fsp,
					       const void *data,
					       size_t n, off_t offset)
{
	struct tevent_req *req = NULL;
	struct cephwrap_pwrite_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] %s\n", __func__);
	req = tevent_req_create(mem_ctx, &state, struct cephwrap_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	ret = ceph_write(handle->data, fsp->fh->fd, data, n, offset);
	if (ret < 0) {
		/* ceph returns -errno on error. */
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	state->bytes_written = ret;
	tevent_req_done(req);
	/* Return and schedule the completion of the call. */
	return tevent_req_post(req, ev);
}

static ssize_t cephwrap_pwrite_recv(struct tevent_req *req,
				    struct vfs_aio_state *vfs_aio_state)
{
	struct cephwrap_pwrite_state *state =
		tevent_req_data(req, struct cephwrap_pwrite_state);

	DBG_DEBUG("[CEPH] %s\n", __func__);
	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = state->vfs_aio_state;
	return state->bytes_written;
}

static off_t cephwrap_lseek(struct vfs_handle_struct *handle, files_struct *fsp, off_t offset, int whence)
{
	off_t result = 0;

	DBG_DEBUG("[CEPH] cephwrap_lseek\n");
	result = ceph_lseek(handle->data, fsp->fh->fd, offset, whence);
	WRAP_RETURN(result);
}

static ssize_t cephwrap_sendfile(struct vfs_handle_struct *handle, int tofd, files_struct *fromfsp, const DATA_BLOB *hdr,
			off_t offset, size_t n)
{
	/*
	 * We cannot support sendfile because libceph is in user space.
	 */
	DBG_DEBUG("[CEPH] cephwrap_sendfile\n");
	errno = ENOTSUP;
	return -1;
}

static ssize_t cephwrap_recvfile(struct vfs_handle_struct *handle,
			int fromfd,
			files_struct *tofsp,
			off_t offset,
			size_t n)
{
	/*
	 * We cannot support recvfile because libceph is in user space.
	 */
	DBG_DEBUG("[CEPH] cephwrap_recvfile\n");
	errno=ENOTSUP;
	return -1;
}

static int cephwrap_renameat(struct vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst)
{
	int result = -1;
	DBG_DEBUG("[CEPH] cephwrap_renameat\n");
	if (smb_fname_src->stream_name || smb_fname_dst->stream_name) {
		errno = ENOENT;
		return result;
	}

	SMB_ASSERT(srcfsp == srcfsp->conn->cwd_fsp);
	SMB_ASSERT(dstfsp == dstfsp->conn->cwd_fsp);

	result = ceph_rename(handle->data, smb_fname_src->base_name, smb_fname_dst->base_name);
	WRAP_RETURN(result);
}

/*
 * Fake up an async ceph fsync by calling the synchronous API.
 */

static struct tevent_req *cephwrap_fsync_send(struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					struct tevent_context *ev,
					files_struct *fsp)
{
	struct tevent_req *req = NULL;
	struct vfs_aio_state *state = NULL;
	int ret = -1;

	DBG_DEBUG("[CEPH] cephwrap_fsync_send\n");

	req = tevent_req_create(mem_ctx, &state, struct vfs_aio_state);
	if (req == NULL) {
		return NULL;
	}

	/* Make sync call. */
	ret = ceph_fsync(handle->data, fsp->fh->fd, false);

	if (ret != 0) {
		/* ceph_fsync returns -errno on error. */
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	/* Mark it as done. */
	tevent_req_done(req);
	/* Return and schedule the completion of the call. */
	return tevent_req_post(req, ev);
}

static int cephwrap_fsync_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_aio_state *state =
		tevent_req_data(req, struct vfs_aio_state);

	DBG_DEBUG("[CEPH] cephwrap_fsync_recv\n");

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}
	*vfs_aio_state = *state;
	return 0;
}

#define SAMBA_STATX_ATTR_MASK	(CEPH_STATX_BASIC_STATS|CEPH_STATX_BTIME)

static void init_stat_ex_from_ceph_statx(struct stat_ex *dst, const struct ceph_statx *stx)
{
	DBG_DEBUG("[CEPH]\tstx = {dev = %llx, ino = %llu, mode = 0x%x, "
		  "nlink = %llu, uid = %d, gid = %d, rdev = %llx, size = %llu, "
		  "blksize = %llu, blocks = %llu, atime = %llu, mtime = %llu, "
		  "ctime = %llu, btime = %llu}\n",
		  llu(stx->stx_dev), llu(stx->stx_ino), stx->stx_mode,
		  llu(stx->stx_nlink), stx->stx_uid, stx->stx_gid,
		  llu(stx->stx_rdev), llu(stx->stx_size), llu(stx->stx_blksize),
		  llu(stx->stx_blocks), llu(stx->stx_atime.tv_sec),
		  llu(stx->stx_mtime.tv_sec), llu(stx->stx_ctime.tv_sec),
		  llu(stx->stx_btime.tv_sec));

	if ((stx->stx_mask & SAMBA_STATX_ATTR_MASK) != SAMBA_STATX_ATTR_MASK) {
		DBG_WARNING("%s: stx->stx_mask is incorrect (wanted %x, got %x)",
				__func__, SAMBA_STATX_ATTR_MASK, stx->stx_mask);
	}

	dst->st_ex_dev = stx->stx_dev;
	dst->st_ex_rdev = stx->stx_rdev;
	dst->st_ex_ino = stx->stx_ino;
	dst->st_ex_mode = stx->stx_mode;
	dst->st_ex_uid = stx->stx_uid;
	dst->st_ex_gid = stx->stx_gid;
	dst->st_ex_size = stx->stx_size;
	dst->st_ex_nlink = stx->stx_nlink;
	dst->st_ex_atime = stx->stx_atime;
	dst->st_ex_btime = stx->stx_btime;
	dst->st_ex_ctime = stx->stx_ctime;
	dst->st_ex_mtime = stx->stx_mtime;
	dst->st_ex_itime = dst->st_ex_btime;
	dst->st_ex_iflags = ST_EX_IFLAG_CALCULATED_ITIME;
	dst->st_ex_blksize = stx->stx_blksize;
	dst->st_ex_blocks = stx->stx_blocks;
	dst->st_ex_file_id = dst->st_ex_ino;
	dst->st_ex_iflags |= ST_EX_IFLAG_CALCULATED_FILE_ID;
}

static int cephwrap_stat(struct vfs_handle_struct *handle,
			struct smb_filename *smb_fname)
{
	int result = -1;
	struct ceph_statx stx;

	DBG_DEBUG("[CEPH] stat(%p, %s)\n", handle, smb_fname_str_dbg(smb_fname));

	if (smb_fname->stream_name) {
		errno = ENOENT;
		return result;
	}

	result = ceph_statx(handle->data, smb_fname->base_name, &stx,
				SAMBA_STATX_ATTR_MASK, 0);
	DBG_DEBUG("[CEPH] statx(...) = %d\n", result);
	if (result < 0) {
		WRAP_RETURN(result);
	}

	init_stat_ex_from_ceph_statx(&smb_fname->st, &stx);
	DBG_DEBUG("[CEPH] mode = 0x%x\n", smb_fname->st.st_ex_mode);
	return result;
}

static int cephwrap_fstat(struct vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int result = -1;
	struct ceph_statx stx;

	DBG_DEBUG("[CEPH] fstat(%p, %d)\n", handle, fsp->fh->fd);
	result = ceph_fstatx(handle->data, fsp->fh->fd, &stx,
				SAMBA_STATX_ATTR_MASK, 0);
	DBG_DEBUG("[CEPH] fstat(...) = %d\n", result);
	if (result < 0) {
		WRAP_RETURN(result);
	}

	init_stat_ex_from_ceph_statx(sbuf, &stx);
	DBG_DEBUG("[CEPH] mode = 0x%x\n", sbuf->st_ex_mode);
	return result;
}

static int cephwrap_lstat(struct vfs_handle_struct *handle,
			 struct smb_filename *smb_fname)
{
	int result = -1;
	struct ceph_statx stx;

	DBG_DEBUG("[CEPH] lstat(%p, %s)\n", handle, smb_fname_str_dbg(smb_fname));

	if (smb_fname->stream_name) {
		errno = ENOENT;
		return result;
	}

	result = ceph_statx(handle->data, smb_fname->base_name, &stx,
				SAMBA_STATX_ATTR_MASK, AT_SYMLINK_NOFOLLOW);
	DBG_DEBUG("[CEPH] lstat(...) = %d\n", result);
	if (result < 0) {
		WRAP_RETURN(result);
	}

	init_stat_ex_from_ceph_statx(&smb_fname->st, &stx);
	return result;
}

static int cephwrap_ntimes(struct vfs_handle_struct *handle,
			 const struct smb_filename *smb_fname,
			 struct smb_file_time *ft)
{
	struct ceph_statx stx = { 0 };
	int result;
	int mask = 0;

	if (!is_omit_timespec(&ft->atime)) {
		stx.stx_atime = ft->atime;
		mask |= CEPH_SETATTR_ATIME;
	}
	if (!is_omit_timespec(&ft->mtime)) {
		stx.stx_mtime = ft->mtime;
		mask |= CEPH_SETATTR_MTIME;
	}
	if (!is_omit_timespec(&ft->create_time)) {
		stx.stx_btime = ft->create_time;
		mask |= CEPH_SETATTR_BTIME;
	}

	if (!mask) {
		return 0;
	}

	result = ceph_setattrx(handle->data, smb_fname->base_name, &stx, mask, 0);
	DBG_DEBUG("[CEPH] ntimes(%p, %s, {%ld, %ld, %ld, %ld}) = %d\n", handle, smb_fname_str_dbg(smb_fname),
				ft->mtime.tv_sec, ft->atime.tv_sec, ft->ctime.tv_sec,
				ft->create_time.tv_sec, result);
	return result;
}

static int cephwrap_unlinkat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	int result = -1;

	DBG_DEBUG("[CEPH] unlink(%p, %s)\n",
		handle,
		smb_fname_str_dbg(smb_fname));
	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);
	if (smb_fname->stream_name) {
		errno = ENOENT;
		return result;
	}
	if (flags & AT_REMOVEDIR) {
		result = ceph_rmdir(handle->data, smb_fname->base_name);
	} else {
		result = ceph_unlink(handle->data, smb_fname->base_name);
	}
	DBG_DEBUG("[CEPH] unlink(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cephwrap_chmod(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int result;

	DBG_DEBUG("[CEPH] chmod(%p, %s, %d)\n", handle, smb_fname->base_name, mode);
	result = ceph_chmod(handle->data, smb_fname->base_name, mode);
	DBG_DEBUG("[CEPH] chmod(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cephwrap_fchmod(struct vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	int result;

	DBG_DEBUG("[CEPH] fchmod(%p, %p, %d)\n", handle, fsp, mode);
	result = ceph_fchmod(handle->data, fsp->fh->fd, mode);
	DBG_DEBUG("[CEPH] fchmod(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cephwrap_fchown(struct vfs_handle_struct *handle, files_struct *fsp, uid_t uid, gid_t gid)
{
	int result;

	DBG_DEBUG("[CEPH] fchown(%p, %p, %d, %d)\n", handle, fsp, uid, gid);
	result = ceph_fchown(handle->data, fsp->fh->fd, uid, gid);
	DBG_DEBUG("[CEPH] fchown(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cephwrap_lchown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int result;
	DBG_DEBUG("[CEPH] lchown(%p, %s, %d, %d)\n", handle, smb_fname->base_name, uid, gid);
	result = ceph_lchown(handle->data, smb_fname->base_name, uid, gid);
	DBG_DEBUG("[CEPH] lchown(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cephwrap_chdir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int result = -1;
	DBG_DEBUG("[CEPH] chdir(%p, %s)\n", handle, smb_fname->base_name);
	result = ceph_chdir(handle->data, smb_fname->base_name);
	DBG_DEBUG("[CEPH] chdir(...) = %d\n", result);
	WRAP_RETURN(result);
}

static struct smb_filename *cephwrap_getwd(struct vfs_handle_struct *handle,
			TALLOC_CTX *ctx)
{
	const char *cwd = ceph_getcwd(handle->data);
	DBG_DEBUG("[CEPH] getwd(%p) = %s\n", handle, cwd);
	return synthetic_smb_fname(ctx,
				cwd,
				NULL,
				NULL,
				0,
				0);
}

static int strict_allocate_ftruncate(struct vfs_handle_struct *handle, files_struct *fsp, off_t len)
{
	off_t space_to_write;
	int result;
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
	if (pst->st_ex_size > len) {
		result = ceph_ftruncate(handle->data, fsp->fh->fd, len);
		WRAP_RETURN(result);
	}

	space_to_write = len - pst->st_ex_size;
	result = ceph_fallocate(handle->data, fsp->fh->fd, 0, pst->st_ex_size,
				space_to_write);
	WRAP_RETURN(result);
}

static int cephwrap_ftruncate(struct vfs_handle_struct *handle, files_struct *fsp, off_t len)
{
	int result = -1;

	DBG_DEBUG("[CEPH] ftruncate(%p, %p, %llu\n", handle, fsp, llu(len));

	if (lp_strict_allocate(SNUM(fsp->conn))) {
		return strict_allocate_ftruncate(handle, fsp, len);
	}

	result = ceph_ftruncate(handle->data, fsp->fh->fd, len);
	WRAP_RETURN(result);
}

static int cephwrap_fallocate(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      uint32_t mode,
			      off_t offset,
			      off_t len)
{
	int result;

	DBG_DEBUG("[CEPH] fallocate(%p, %p, %u, %llu, %llu\n",
		  handle, fsp, mode, llu(offset), llu(len));
	/* unsupported mode flags are rejected by libcephfs */
	result = ceph_fallocate(handle->data, fsp->fh->fd, mode, offset, len);
	DBG_DEBUG("[CEPH] fallocate(...) = %d\n", result);
	WRAP_RETURN(result);
}

static bool cephwrap_lock(struct vfs_handle_struct *handle, files_struct *fsp, int op, off_t offset, off_t count, int type)
{
	DBG_DEBUG("[CEPH] lock\n");
	return true;
}

static int cephwrap_kernel_flock(struct vfs_handle_struct *handle,
				 files_struct *fsp,
				 uint32_t share_access,
				 uint32_t access_mask)
{
	DBG_ERR("[CEPH] flock unsupported! Consider setting "
		"\"kernel share modes = no\"\n");

	errno = ENOSYS;
	return -1;
}

static int cephwrap_fcntl(vfs_handle_struct *handle,
			  files_struct *fsp, int cmd, va_list cmd_arg)
{
	/*
	 * SMB_VFS_FCNTL() is currently only called by vfs_set_blocking() to
	 * clear O_NONBLOCK, etc for LOCK_MAND and FIFOs. Ignore it.
	 */
	if (cmd == F_GETFL) {
		return 0;
	} else if (cmd == F_SETFL) {
		va_list dup_cmd_arg;
		int opt;

		va_copy(dup_cmd_arg, cmd_arg);
		opt = va_arg(dup_cmd_arg, int);
		va_end(dup_cmd_arg);
		if (opt == 0) {
			return 0;
		}
		DBG_ERR("unexpected fcntl SETFL(%d)\n", opt);
		goto err_out;
	}
	DBG_ERR("unexpected fcntl: %d\n", cmd);
err_out:
	errno = EINVAL;
	return -1;
}

static bool cephwrap_getlock(struct vfs_handle_struct *handle, files_struct *fsp, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid)
{
	DBG_DEBUG("[CEPH] getlock returning false and errno=0\n");

	errno = 0;
	return false;
}

/*
 * We cannot let this fall through to the default, because the file might only
 * be accessible from libceph (which is a user-space client) but the fd might
 * be for some file the kernel knows about.
 */
static int cephwrap_linux_setlease(struct vfs_handle_struct *handle, files_struct *fsp,
				int leasetype)
{
	int result = -1;

	DBG_DEBUG("[CEPH] linux_setlease\n");
	errno = ENOSYS;
	return result;
}

static int cephwrap_symlinkat(struct vfs_handle_struct *handle,
		const struct smb_filename *link_target,
		struct files_struct *dirfsp,
		const struct smb_filename *new_smb_fname)
{
	int result = -1;
	DBG_DEBUG("[CEPH] symlink(%p, %s, %s)\n", handle,
			link_target->base_name,
			new_smb_fname->base_name);

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	result = ceph_symlink(handle->data,
			link_target->base_name,
			new_smb_fname->base_name);
	DBG_DEBUG("[CEPH] symlink(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cephwrap_readlinkat(struct vfs_handle_struct *handle,
		files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		char *buf,
		size_t bufsiz)
{
	int result = -1;
	DBG_DEBUG("[CEPH] readlink(%p, %s, %p, %llu)\n", handle,
			smb_fname->base_name, buf, llu(bufsiz));

	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);

	result = ceph_readlink(handle->data, smb_fname->base_name, buf, bufsiz);
	DBG_DEBUG("[CEPH] readlink(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cephwrap_linkat(struct vfs_handle_struct *handle,
		files_struct *srcfsp,
		const struct smb_filename *old_smb_fname,
		files_struct *dstfsp,
		const struct smb_filename *new_smb_fname,
		int flags)
{
	int result = -1;
	DBG_DEBUG("[CEPH] link(%p, %s, %s)\n", handle,
			old_smb_fname->base_name,
			new_smb_fname->base_name);

	SMB_ASSERT(srcfsp == srcfsp->conn->cwd_fsp);
	SMB_ASSERT(dstfsp == dstfsp->conn->cwd_fsp);

	result = ceph_link(handle->data,
				old_smb_fname->base_name,
				new_smb_fname->base_name);
	DBG_DEBUG("[CEPH] link(...) = %d\n", result);
	WRAP_RETURN(result);
}

static int cephwrap_mknodat(struct vfs_handle_struct *handle,
		files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode,
		SMB_DEV_T dev)
{
	int result = -1;
	DBG_DEBUG("[CEPH] mknodat(%p, %s)\n", handle, smb_fname->base_name);
	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);
	result = ceph_mknod(handle->data, smb_fname->base_name, mode, dev);
	DBG_DEBUG("[CEPH] mknodat(...) = %d\n", result);
	WRAP_RETURN(result);
}

/*
 * This is a simple version of real-path ... a better version is needed to
 * ask libceph about symbolic links.
 */
static struct smb_filename *cephwrap_realpath(struct vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)
{
	char *result = NULL;
	const char *path = smb_fname->base_name;
	size_t len = strlen(path);
	struct smb_filename *result_fname = NULL;
	int r = -1;

	if (len && (path[0] == '/')) {
		r = asprintf(&result, "%s", path);
	} else if ((len >= 2) && (path[0] == '.') && (path[1] == '/')) {
		if (len == 2) {
			r = asprintf(&result, "%s",
					handle->conn->cwd_fsp->fsp_name->base_name);
		} else {
			r = asprintf(&result, "%s/%s",
					handle->conn->cwd_fsp->fsp_name->base_name, &path[2]);
		}
	} else {
		r = asprintf(&result, "%s/%s",
				handle->conn->cwd_fsp->fsp_name->base_name, path);
	}

	if (r < 0) {
		return NULL;
	}

	DBG_DEBUG("[CEPH] realpath(%p, %s) = %s\n", handle, path, result);
	result_fname = synthetic_smb_fname(ctx,
				result,
				NULL,
				NULL,
				0,
				0);
	SAFE_FREE(result);
	return result_fname;
}

static int cephwrap_chflags(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}

static int cephwrap_get_real_filename(struct vfs_handle_struct *handle,
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

static const char *cephwrap_connectpath(struct vfs_handle_struct *handle,
				       const struct smb_filename *smb_fname)
{
	return handle->conn->connectpath;
}

/****************************************************************
 Extended attribute operations.
*****************************************************************/

static ssize_t cephwrap_getxattr(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			const char *name,
			void *value,
			size_t size)
{
	int ret;
	DBG_DEBUG("[CEPH] getxattr(%p, %s, %s, %p, %llu)\n", handle,
			smb_fname->base_name, name, value, llu(size));
	ret = ceph_getxattr(handle->data,
			smb_fname->base_name, name, value, size);
	DBG_DEBUG("[CEPH] getxattr(...) = %d\n", ret);
	if (ret < 0) {
		WRAP_RETURN(ret);
	}
	return (ssize_t)ret;
}

static ssize_t cephwrap_fgetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, void *value, size_t size)
{
	int ret;
	DBG_DEBUG("[CEPH] fgetxattr(%p, %p, %s, %p, %llu)\n", handle, fsp, name, value, llu(size));
	ret = ceph_fgetxattr(handle->data, fsp->fh->fd, name, value, size);
	DBG_DEBUG("[CEPH] fgetxattr(...) = %d\n", ret);
	if (ret < 0) {
		WRAP_RETURN(ret);
	}
	return (ssize_t)ret;
}

static ssize_t cephwrap_listxattr(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			char *list,
			size_t size)
{
	int ret;
	DBG_DEBUG("[CEPH] listxattr(%p, %s, %p, %llu)\n", handle,
			smb_fname->base_name, list, llu(size));
	ret = ceph_listxattr(handle->data, smb_fname->base_name, list, size);
	DBG_DEBUG("[CEPH] listxattr(...) = %d\n", ret);
	if (ret < 0) {
		WRAP_RETURN(ret);
	}
	return (ssize_t)ret;
}

static ssize_t cephwrap_flistxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, char *list, size_t size)
{
	int ret;
	DBG_DEBUG("[CEPH] flistxattr(%p, %p, %p, %llu)\n",
		  handle, fsp, list, llu(size));
	ret = ceph_flistxattr(handle->data, fsp->fh->fd, list, size);
	DBG_DEBUG("[CEPH] flistxattr(...) = %d\n", ret);
	if (ret < 0) {
		WRAP_RETURN(ret);
	}
	return (ssize_t)ret;
}

static int cephwrap_removexattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name)
{
	int ret;
	DBG_DEBUG("[CEPH] removexattr(%p, %s, %s)\n", handle,
			smb_fname->base_name, name);
	ret = ceph_removexattr(handle->data, smb_fname->base_name, name);
	DBG_DEBUG("[CEPH] removexattr(...) = %d\n", ret);
	WRAP_RETURN(ret);
}

static int cephwrap_fremovexattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name)
{
	int ret;
	DBG_DEBUG("[CEPH] fremovexattr(%p, %p, %s)\n", handle, fsp, name);
	ret = ceph_fremovexattr(handle->data, fsp->fh->fd, name);
	DBG_DEBUG("[CEPH] fremovexattr(...) = %d\n", ret);
	WRAP_RETURN(ret);
}

static int cephwrap_setxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				const void *value,
				size_t size,
				int flags)
{
	int ret;
	DBG_DEBUG("[CEPH] setxattr(%p, %s, %s, %p, %llu, %d)\n", handle,
			smb_fname->base_name, name, value, llu(size), flags);
	ret = ceph_setxattr(handle->data, smb_fname->base_name,
			name, value, size, flags);
	DBG_DEBUG("[CEPH] setxattr(...) = %d\n", ret);
	WRAP_RETURN(ret);
}

static int cephwrap_fsetxattr(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, const void *value, size_t size, int flags)
{
	int ret;
	DBG_DEBUG("[CEPH] fsetxattr(%p, %p, %s, %p, %llu, %d)\n", handle, fsp, name, value, llu(size), flags);
	ret = ceph_fsetxattr(handle->data, fsp->fh->fd,
			     name, value, size, flags);
	DBG_DEBUG("[CEPH] fsetxattr(...) = %d\n", ret);
	WRAP_RETURN(ret);
}

static bool cephwrap_aio_force(struct vfs_handle_struct *handle, struct files_struct *fsp)
{

	/*
	 * We do not support AIO yet.
	 */

	DBG_DEBUG("[CEPH] cephwrap_aio_force(%p, %p) = false (errno = ENOTSUP)\n", handle, fsp);
	errno = ENOTSUP;
	return false;
}

static NTSTATUS cephwrap_create_dfs_pathat(struct vfs_handle_struct *handle,
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

	ret = ceph_symlink(handle->data,
			msdfs_link,
			smb_fname->base_name);
	if (ret == 0) {
		status = NT_STATUS_OK;
	} else {
		status = map_nt_error_from_unix(-ret);
        }

  out:

	DBG_DEBUG("[CEPH] create_dfs_pathat(%s) = %s\n",
			smb_fname->base_name,
			nt_errstr(status));

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

static NTSTATUS cephwrap_read_dfs_pathat(struct vfs_handle_struct *handle,
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
	struct ceph_statx stx;
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

	ret = ceph_statx(handle->data,
			 smb_fname->base_name,
			 &stx,
			 SAMBA_STATX_ATTR_MASK,
			 AT_SYMLINK_NOFOLLOW);
	if (ret < 0) {
		status = map_nt_error_from_unix(-ret);
		goto err;
	}

        referral_len = ceph_readlink(handle->data,
                                smb_fname->base_name,
                                link_target,
                                bufsize - 1);
        if (referral_len < 0) {
		/* ceph errors are -errno. */
		if (-referral_len == EINVAL) {
			DBG_INFO("%s is not a link.\n",
				smb_fname->base_name);
			status = NT_STATUS_OBJECT_TYPE_MISMATCH;
		} else {
	                status = map_nt_error_from_unix(-referral_len);
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

        if (ppreflist == NULL && preferral_count == NULL) {
                /* Early return for checking if this is a DFS link. */
		init_stat_ex_from_ceph_statx(&smb_fname->st, &stx);
                return NT_STATUS_OK;
        }

        ok = parse_msdfs_symlink(mem_ctx,
                        lp_msdfs_shuffle_referrals(SNUM(handle->conn)),
                        link_target,
                        ppreflist,
                        preferral_count);

        if (ok) {
		init_stat_ex_from_ceph_statx(&smb_fname->st, &stx);
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

static struct vfs_fn_pointers ceph_fns = {
	/* Disk operations */

	.connect_fn = cephwrap_connect,
	.disconnect_fn = cephwrap_disconnect,
	.disk_free_fn = cephwrap_disk_free,
	.get_quota_fn = cephwrap_get_quota,
	.set_quota_fn = cephwrap_set_quota,
	.statvfs_fn = cephwrap_statvfs,
	.fs_capabilities_fn = cephwrap_fs_capabilities,

	/* Directory operations */

	.fdopendir_fn = cephwrap_fdopendir,
	.readdir_fn = cephwrap_readdir,
	.seekdir_fn = cephwrap_seekdir,
	.telldir_fn = cephwrap_telldir,
	.rewind_dir_fn = cephwrap_rewinddir,
	.mkdirat_fn = cephwrap_mkdirat,
	.closedir_fn = cephwrap_closedir,

	/* File operations */

	.create_dfs_pathat_fn = cephwrap_create_dfs_pathat,
	.read_dfs_pathat_fn = cephwrap_read_dfs_pathat,
	.openat_fn = cephwrap_openat,
	.close_fn = cephwrap_close,
	.pread_fn = cephwrap_pread,
	.pread_send_fn = cephwrap_pread_send,
	.pread_recv_fn = cephwrap_pread_recv,
	.pwrite_fn = cephwrap_pwrite,
	.pwrite_send_fn = cephwrap_pwrite_send,
	.pwrite_recv_fn = cephwrap_pwrite_recv,
	.lseek_fn = cephwrap_lseek,
	.sendfile_fn = cephwrap_sendfile,
	.recvfile_fn = cephwrap_recvfile,
	.renameat_fn = cephwrap_renameat,
	.fsync_send_fn = cephwrap_fsync_send,
	.fsync_recv_fn = cephwrap_fsync_recv,
	.stat_fn = cephwrap_stat,
	.fstat_fn = cephwrap_fstat,
	.lstat_fn = cephwrap_lstat,
	.unlinkat_fn = cephwrap_unlinkat,
	.chmod_fn = cephwrap_chmod,
	.fchmod_fn = cephwrap_fchmod,
	.fchown_fn = cephwrap_fchown,
	.lchown_fn = cephwrap_lchown,
	.chdir_fn = cephwrap_chdir,
	.getwd_fn = cephwrap_getwd,
	.ntimes_fn = cephwrap_ntimes,
	.ftruncate_fn = cephwrap_ftruncate,
	.fallocate_fn = cephwrap_fallocate,
	.lock_fn = cephwrap_lock,
	.kernel_flock_fn = cephwrap_kernel_flock,
	.fcntl_fn = cephwrap_fcntl,
	.linux_setlease_fn = cephwrap_linux_setlease,
	.getlock_fn = cephwrap_getlock,
	.symlinkat_fn = cephwrap_symlinkat,
	.readlinkat_fn = cephwrap_readlinkat,
	.linkat_fn = cephwrap_linkat,
	.mknodat_fn = cephwrap_mknodat,
	.realpath_fn = cephwrap_realpath,
	.chflags_fn = cephwrap_chflags,
	.get_real_filename_fn = cephwrap_get_real_filename,
	.connectpath_fn = cephwrap_connectpath,

	/* EA operations. */
	.getxattr_fn = cephwrap_getxattr,
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = cephwrap_fgetxattr,
	.listxattr_fn = cephwrap_listxattr,
	.flistxattr_fn = cephwrap_flistxattr,
	.removexattr_fn = cephwrap_removexattr,
	.fremovexattr_fn = cephwrap_fremovexattr,
	.setxattr_fn = cephwrap_setxattr,
	.fsetxattr_fn = cephwrap_fsetxattr,

	/* Posix ACL Operations */
	.sys_acl_get_file_fn = posixacl_xattr_acl_get_file,
	.sys_acl_get_fd_fn = posixacl_xattr_acl_get_fd,
	.sys_acl_blob_get_file_fn = posix_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = posixacl_xattr_acl_set_file,
	.sys_acl_set_fd_fn = posixacl_xattr_acl_set_fd,
	.sys_acl_delete_def_file_fn = posixacl_xattr_acl_delete_def_file,

	/* aio operations */
	.aio_force_fn = cephwrap_aio_force,
};

static_decl_vfs;
NTSTATUS vfs_ceph_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph", &ceph_fns);
}
