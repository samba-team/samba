/*
   Unix SMB/CIFS implementation.

   Wrap GlusterFS GFAPI calls in vfs functions.

   Copyright (c) 2013 Anand Avati <avati@redhat.com>

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

/**
 * @file   vfs_glusterfs.c
 * @author Anand Avati <avati@redhat.com>
 * @date   May 2013
 * @brief  Samba VFS module for glusterfs
 *
 * @todo
 *   - sendfile/recvfile support
 *
 * A Samba VFS module for GlusterFS, based on Gluster's libgfapi.
 * This is a "bottom" vfs module (not something to be stacked on top of
 * another module), and translates (most) calls to the closest actions
 * available in libgfapi.
 *
 */

#include "includes.h"
#include "smbd/smbd.h"
#include <stdio.h>
#include "api/glfs.h"
#include "lib/util/dlinklist.h"
#include "lib/util/tevent_unix.h"
#include "smbd/globals.h"
#include "lib/util/sys_rw.h"
#include "smbprofile.h"
#include "modules/posixacl_xattr.h"

#define DEFAULT_VOLFILE_SERVER "localhost"

static int read_fd = -1;
static int write_fd = -1;
static struct tevent_fd *aio_read_event = NULL;

/**
 * Helper to convert struct stat to struct stat_ex.
 */
static void smb_stat_ex_from_stat(struct stat_ex *dst, const struct stat *src)
{
	ZERO_STRUCTP(dst);

	dst->st_ex_dev = src->st_dev;
	dst->st_ex_ino = src->st_ino;
	dst->st_ex_mode = src->st_mode;
	dst->st_ex_nlink = src->st_nlink;
	dst->st_ex_uid = src->st_uid;
	dst->st_ex_gid = src->st_gid;
	dst->st_ex_rdev = src->st_rdev;
	dst->st_ex_size = src->st_size;
	dst->st_ex_atime.tv_sec = src->st_atime;
	dst->st_ex_mtime.tv_sec = src->st_mtime;
	dst->st_ex_ctime.tv_sec = src->st_ctime;
	dst->st_ex_btime.tv_sec = src->st_mtime;
	dst->st_ex_blksize = src->st_blksize;
	dst->st_ex_blocks = src->st_blocks;
#ifdef STAT_HAVE_NSEC
	dst->st_ex_atime.tv_nsec = src->st_atime_nsec;
	dst->st_ex_mtime.tv_nsec = src->st_mtime_nsec;
	dst->st_ex_ctime.tv_nsec = src->st_ctime_nsec;
	dst->st_ex_btime.tv_nsec = src->st_mtime_nsec;
#endif
}

/* pre-opened glfs_t */

static struct glfs_preopened {
	char *volume;
	char *connectpath;
	glfs_t *fs;
	int ref;
	struct glfs_preopened *next, *prev;
} *glfs_preopened;


static int glfs_set_preopened(const char *volume, const char *connectpath, glfs_t *fs)
{
	struct glfs_preopened *entry = NULL;

	entry = talloc_zero(NULL, struct glfs_preopened);
	if (!entry) {
		errno = ENOMEM;
		return -1;
	}

	entry->volume = talloc_strdup(entry, volume);
	if (!entry->volume) {
		talloc_free(entry);
		errno = ENOMEM;
		return -1;
	}

	entry->connectpath = talloc_strdup(entry, connectpath);
	if (entry->connectpath == NULL) {
		talloc_free(entry);
		errno = ENOMEM;
		return -1;
	}

	entry->fs = fs;
	entry->ref = 1;

	DLIST_ADD(glfs_preopened, entry);

	return 0;
}

static glfs_t *glfs_find_preopened(const char *volume, const char *connectpath)
{
	struct glfs_preopened *entry = NULL;

	for (entry = glfs_preopened; entry; entry = entry->next) {
		if (strcmp(entry->volume, volume) == 0 &&
		    strcmp(entry->connectpath, connectpath) == 0)
		{
			entry->ref++;
			return entry->fs;
		}
	}

	return NULL;
}

static void glfs_clear_preopened(glfs_t *fs)
{
	struct glfs_preopened *entry = NULL;

	for (entry = glfs_preopened; entry; entry = entry->next) {
		if (entry->fs == fs) {
			if (--entry->ref)
				return;

			DLIST_REMOVE(glfs_preopened, entry);

			glfs_fini(entry->fs);
			talloc_free(entry);
		}
	}
}

/* Disk Operations */

static int vfs_gluster_connect(struct vfs_handle_struct *handle,
			       const char *service,
			       const char *user)
{
	const char *volfile_server;
	const char *volume;
	char *logfile;
	int loglevel;
	glfs_t *fs = NULL;
	TALLOC_CTX *tmp_ctx;
	int ret = 0;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		ret = -1;
		goto done;
	}
	logfile = lp_parm_talloc_string(tmp_ctx, SNUM(handle->conn), "glusterfs",
				       "logfile", NULL);

	loglevel = lp_parm_int(SNUM(handle->conn), "glusterfs", "loglevel", -1);

	volfile_server = lp_parm_const_string(SNUM(handle->conn), "glusterfs",
					       "volfile_server", NULL);
	if (volfile_server == NULL) {
		volfile_server = DEFAULT_VOLFILE_SERVER;
	}

	volume = lp_parm_const_string(SNUM(handle->conn), "glusterfs", "volume",
				      NULL);
	if (volume == NULL) {
		volume = service;
	}

	fs = glfs_find_preopened(volume, handle->conn->connectpath);
	if (fs) {
		goto done;
	}

	fs = glfs_new(volume);
	if (fs == NULL) {
		ret = -1;
		goto done;
	}

	ret = glfs_set_volfile_server(fs, "tcp", volfile_server, 0);
	if (ret < 0) {
		DEBUG(0, ("Failed to set volfile_server %s\n", volfile_server));
		goto done;
	}

	ret = glfs_set_xlator_option(fs, "*-md-cache", "cache-posix-acl",
				     "true");
	if (ret < 0) {
		DEBUG(0, ("%s: Failed to set xlator options\n", volume));
		goto done;
	}


	ret = glfs_set_xlator_option(fs, "*-snapview-client",
				     "snapdir-entry-path",
				     handle->conn->connectpath);
	if (ret < 0) {
		DEBUG(0, ("%s: Failed to set xlator option:"
			  " snapdir-entry-path\n", volume));
		goto done;
	}

	ret = glfs_set_logging(fs, logfile, loglevel);
	if (ret < 0) {
		DEBUG(0, ("%s: Failed to set logfile %s loglevel %d\n",
			  volume, logfile, loglevel));
		goto done;
	}

	ret = glfs_init(fs);
	if (ret < 0) {
		DEBUG(0, ("%s: Failed to initialize volume (%s)\n",
			  volume, strerror(errno)));
		goto done;
	}

	ret = glfs_set_preopened(volume, handle->conn->connectpath, fs);
	if (ret < 0) {
		DEBUG(0, ("%s: Failed to register volume (%s)\n",
			  volume, strerror(errno)));
		goto done;
	}
done:
	talloc_free(tmp_ctx);
	if (ret < 0) {
		if (fs)
			glfs_fini(fs);
		return -1;
	} else {
		DEBUG(0, ("%s: Initialized volume from server %s\n",
                         volume, volfile_server));
		handle->data = fs;
		return 0;
	}
}

static void vfs_gluster_disconnect(struct vfs_handle_struct *handle)
{
	glfs_t *fs = NULL;

	fs = handle->data;

	glfs_clear_preopened(fs);
}

static uint64_t vfs_gluster_disk_free(struct vfs_handle_struct *handle,
				      const char *path, uint64_t *bsize_p,
				      uint64_t *dfree_p, uint64_t *dsize_p)
{
	struct statvfs statvfs = { 0, };
	int ret;

	ret = glfs_statvfs(handle->data, path, &statvfs);
	if (ret < 0) {
		return -1;
	}

	if (bsize_p != NULL) {
		*bsize_p = (uint64_t)statvfs.f_bsize; /* Block size */
	}
	if (dfree_p != NULL) {
		*dfree_p = (uint64_t)statvfs.f_bavail; /* Available Block units */
	}
	if (dsize_p != NULL) {
		*dsize_p = (uint64_t)statvfs.f_blocks; /* Total Block units */
	}

	return (uint64_t)statvfs.f_bavail;
}

static int vfs_gluster_get_quota(struct vfs_handle_struct *handle,
				 const char *path,
				 enum SMB_QUOTA_TYPE qtype, unid_t id,
				 SMB_DISK_QUOTA *qt)
{
	errno = ENOSYS;
	return -1;
}

static int
vfs_gluster_set_quota(struct vfs_handle_struct *handle,
		      enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *qt)
{
	errno = ENOSYS;
	return -1;
}

static int vfs_gluster_statvfs(struct vfs_handle_struct *handle,
			       const char *path,
			       struct vfs_statvfs_struct *vfs_statvfs)
{
	struct statvfs statvfs = { 0, };
	int ret;

	ret = glfs_statvfs(handle->data, path, &statvfs);
	if (ret < 0) {
		DEBUG(0, ("glfs_statvfs(%s) failed: %s\n",
			  path, strerror(errno)));
		return -1;
	}

	ZERO_STRUCTP(vfs_statvfs);

	vfs_statvfs->OptimalTransferSize = statvfs.f_frsize;
	vfs_statvfs->BlockSize = statvfs.f_bsize;
	vfs_statvfs->TotalBlocks = statvfs.f_blocks;
	vfs_statvfs->BlocksAvail = statvfs.f_bfree;
	vfs_statvfs->UserBlocksAvail = statvfs.f_bavail;
	vfs_statvfs->TotalFileNodes = statvfs.f_files;
	vfs_statvfs->FreeFileNodes = statvfs.f_ffree;
	vfs_statvfs->FsIdentifier = statvfs.f_fsid;
	vfs_statvfs->FsCapabilities =
	    FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;

	return ret;
}

static uint32_t vfs_gluster_fs_capabilities(struct vfs_handle_struct *handle,
					    enum timestamp_set_resolution *p_ts_res)
{
	uint32_t caps = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES;

#ifdef STAT_HAVE_NSEC
	*p_ts_res = TIMESTAMP_SET_NT_OR_BETTER;
#endif

	return caps;
}

static DIR *vfs_gluster_opendir(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *mask,
				uint32_t attributes)
{
	glfs_fd_t *fd;

	fd = glfs_opendir(handle->data, smb_fname->base_name);
	if (fd == NULL) {
		DEBUG(0, ("glfs_opendir(%s) failed: %s\n",
			  smb_fname->base_name, strerror(errno)));
	}

	return (DIR *) fd;
}

static DIR *vfs_gluster_fdopendir(struct vfs_handle_struct *handle,
				  files_struct *fsp, const char *mask,
				  uint32_t attributes)
{
	return (DIR *) *(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp);
}

static int vfs_gluster_closedir(struct vfs_handle_struct *handle, DIR *dirp)
{
	return glfs_closedir((void *)dirp);
}

static struct dirent *vfs_gluster_readdir(struct vfs_handle_struct *handle,
					  DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
	static char direntbuf[512];
	int ret;
	struct stat stat;
	struct dirent *dirent = 0;

	if (sbuf != NULL) {
		ret = glfs_readdirplus_r((void *)dirp, &stat, (void *)direntbuf,
					 &dirent);
	} else {
		ret = glfs_readdir_r((void *)dirp, (void *)direntbuf, &dirent);
	}

	if ((ret < 0) || (dirent == NULL)) {
		return NULL;
	}

	if (sbuf != NULL) {
		smb_stat_ex_from_stat(sbuf, &stat);
	}

	return dirent;
}

static long vfs_gluster_telldir(struct vfs_handle_struct *handle, DIR *dirp)
{
	return glfs_telldir((void *)dirp);
}

static void vfs_gluster_seekdir(struct vfs_handle_struct *handle, DIR *dirp,
				long offset)
{
	glfs_seekdir((void *)dirp, offset);
}

static void vfs_gluster_rewinddir(struct vfs_handle_struct *handle, DIR *dirp)
{
	glfs_seekdir((void *)dirp, 0);
}

static void vfs_gluster_init_search_op(struct vfs_handle_struct *handle,
				       DIR *dirp)
{
	return;
}

static int vfs_gluster_mkdir(struct vfs_handle_struct *handle,
			     const struct smb_filename *smb_fname,
			     mode_t mode)
{
	return glfs_mkdir(handle->data, smb_fname->base_name, mode);
}

static int vfs_gluster_rmdir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	return glfs_rmdir(handle->data, smb_fname->base_name);
}

static int vfs_gluster_open(struct vfs_handle_struct *handle,
			    struct smb_filename *smb_fname, files_struct *fsp,
			    int flags, mode_t mode)
{
	glfs_fd_t *glfd;
	glfs_fd_t **p_tmp;

	if (flags & O_DIRECTORY) {
		glfd = glfs_opendir(handle->data, smb_fname->base_name);
	} else if (flags & O_CREAT) {
		glfd = glfs_creat(handle->data, smb_fname->base_name, flags,
				  mode);
	} else {
		glfd = glfs_open(handle->data, smb_fname->base_name, flags);
	}

	if (glfd == NULL) {
		return -1;
	}
	p_tmp = (glfs_fd_t **)VFS_ADD_FSP_EXTENSION(handle, fsp,
							  glfs_fd_t *, NULL);
	*p_tmp = glfd;
	/* An arbitrary value for error reporting, so you know its us. */
	return 13371337;
}

static int vfs_gluster_close(struct vfs_handle_struct *handle,
			     files_struct *fsp)
{
	glfs_fd_t *glfd;
	glfd = *(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	VFS_REMOVE_FSP_EXTENSION(handle, fsp);
	return glfs_close(glfd);
}

static ssize_t vfs_gluster_read(struct vfs_handle_struct *handle,
				files_struct *fsp, void *data, size_t n)
{
	return glfs_read(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), data, n, 0);
}

static ssize_t vfs_gluster_pread(struct vfs_handle_struct *handle,
				 files_struct *fsp, void *data, size_t n,
				 off_t offset)
{
	return glfs_pread(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), data, n, offset, 0);
}

struct glusterfs_aio_state;

struct glusterfs_aio_wrapper {
	struct glusterfs_aio_state *state;
};

struct glusterfs_aio_state {
	ssize_t ret;
	struct tevent_req *req;
	bool cancelled;
	struct vfs_aio_state vfs_aio_state;
	struct timespec start;
};

static int aio_wrapper_destructor(struct glusterfs_aio_wrapper *wrap)
{
	if (wrap->state != NULL) {
		wrap->state->cancelled = true;
	}

	return 0;
}

/*
 * This function is the callback that will be called on glusterfs
 * threads once the async IO submitted is complete. To notify
 * Samba of the completion we use a pipe based queue.
 */
static void aio_glusterfs_done(glfs_fd_t *fd, ssize_t ret, void *data)
{
	struct glusterfs_aio_state *state = NULL;
	int sts = 0;
	struct timespec end;

	state = (struct glusterfs_aio_state *)data;

	PROFILE_TIMESTAMP(&end);

	if (ret < 0) {
		state->ret = -1;
		state->vfs_aio_state.error = errno;
	} else {
		state->ret = ret;
	}
	state->vfs_aio_state.duration = nsec_time_diff(&end, &state->start);

	/*
	 * Write the state pointer to glusterfs_aio_state to the
	 * pipe, so we can call tevent_req_done() from the main thread,
	 * because tevent_req_done() is not designed to be executed in
	 * the multithread environment, so tevent_req_done() must be
	 * executed from the smbd main thread.
	 *
	 * write(2) on pipes with sizes under _POSIX_PIPE_BUF
	 * in size is atomic, without this, the use op pipes in this
	 * code would not work.
	 *
	 * sys_write is a thin enough wrapper around write(2)
	 * that we can trust it here.
	 */

	sts = sys_write(write_fd, &state, sizeof(struct glusterfs_aio_state *));
	if (sts < 0) {
		DEBUG(0,("\nWrite to pipe failed (%s)", strerror(errno)));
	}

	return;
}

/*
 * Read each req off the pipe and process it.
 */
static void aio_tevent_fd_done(struct tevent_context *event_ctx,
				struct tevent_fd *fde,
				uint16_t flags, void *data)
{
	struct tevent_req *req = NULL;
	struct glusterfs_aio_state *state = NULL;
	int sts = 0;

	/*
	 * read(2) on pipes is atomic if the needed data is available
	 * in the pipe, per SUS and POSIX.  Because we always write
	 * to the pipe in sizeof(struct tevent_req *) chunks, we can
	 * always read in those chunks, atomically.
	 *
	 * sys_read is a thin enough wrapper around read(2) that we
	 * can trust it here.
	 */

	sts = sys_read(read_fd, &state, sizeof(struct glusterfs_aio_state *));

	if (sts < 0) {
		DEBUG(0,("\nRead from pipe failed (%s)", strerror(errno)));
	}

	/* if we've cancelled the op, there is no req, so just clean up. */
	if (state->cancelled == true) {
		TALLOC_FREE(state);
		return;
	}

	req = state->req;

	if (req) {
		tevent_req_done(req);
	}
	return;
}

static bool init_gluster_aio(struct vfs_handle_struct *handle)
{
	int fds[2];
	int ret = -1;

	if (read_fd != -1) {
		/*
		 * Already initialized.
		 */
		return true;
	}

	ret = pipe(fds);
	if (ret == -1) {
		goto fail;
	}

	read_fd = fds[0];
	write_fd = fds[1];

	aio_read_event = tevent_add_fd(handle->conn->sconn->ev_ctx,
					NULL,
					read_fd,
					TEVENT_FD_READ,
					aio_tevent_fd_done,
					NULL);
	if (aio_read_event == NULL) {
		goto fail;
	}

	return true;
fail:
	TALLOC_FREE(aio_read_event);
	if (read_fd != -1) {
		close(read_fd);
		close(write_fd);
		read_fd = -1;
		write_fd = -1;
	}
	return false;
}

static struct glusterfs_aio_state *aio_state_create(TALLOC_CTX *mem_ctx)
{
	struct tevent_req *req = NULL;
	struct glusterfs_aio_state *state = NULL;
	struct glusterfs_aio_wrapper *wrapper = NULL;

	req = tevent_req_create(mem_ctx, &wrapper, struct glusterfs_aio_wrapper);

	if (req == NULL) {
		return NULL;
	}

	state = talloc_zero(NULL, struct glusterfs_aio_state);

	if (state == NULL) {
		TALLOC_FREE(req);
		return NULL;
	}

	talloc_set_destructor(wrapper, aio_wrapper_destructor);
	state->cancelled = false;
	state->req = req;

	wrapper->state = state;

	return state;
}

static struct tevent_req *vfs_gluster_pread_send(struct vfs_handle_struct
						  *handle, TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  files_struct *fsp,
						  void *data, size_t n,
						  off_t offset)
{
	struct glusterfs_aio_state *state = NULL;
	struct tevent_req *req = NULL;
	int ret = 0;

	state = aio_state_create(mem_ctx);

	if (state == NULL) {
		return NULL;
	}

	req = state->req;

	if (!init_gluster_aio(handle)) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	PROFILE_TIMESTAMP(&state->start);
	ret = glfs_pread_async(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle,
				fsp), data, n, offset, 0, aio_glusterfs_done,
				state);
	if (ret < 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	return req;
}

static struct tevent_req *vfs_gluster_pwrite_send(struct vfs_handle_struct
						  *handle, TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  files_struct *fsp,
						  const void *data, size_t n,
						  off_t offset)
{
	struct glusterfs_aio_state *state = NULL;
	struct tevent_req *req = NULL;
	int ret = 0;

	state = aio_state_create(mem_ctx);

	if (state == NULL) {
		return NULL;
	}

	req = state->req;

	if (!init_gluster_aio(handle)) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	PROFILE_TIMESTAMP(&state->start);
	ret = glfs_pwrite_async(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle,
				fsp), data, n, offset, 0, aio_glusterfs_done,
				state);
	if (ret < 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}

	return req;
}

static ssize_t vfs_gluster_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state)
{
	struct glusterfs_aio_wrapper *wrapper = NULL;
	int ret = 0;

	wrapper = tevent_req_data(req, struct glusterfs_aio_wrapper);

	if (wrapper == NULL) {
		return -1;
	}

	if (wrapper->state == NULL) {
		return -1;
	}

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = wrapper->state->vfs_aio_state;
	ret = wrapper->state->ret;

	/* Clean up the state, it is in a NULL context. */

	TALLOC_FREE(wrapper->state);

	return ret;
}

static ssize_t vfs_gluster_write(struct vfs_handle_struct *handle,
				 files_struct *fsp, const void *data, size_t n)
{
	return glfs_write(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), data, n, 0);
}

static ssize_t vfs_gluster_pwrite(struct vfs_handle_struct *handle,
				  files_struct *fsp, const void *data,
				  size_t n, off_t offset)
{
	return glfs_pwrite(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), data, n, offset, 0);
}

static off_t vfs_gluster_lseek(struct vfs_handle_struct *handle,
			       files_struct *fsp, off_t offset, int whence)
{
	return glfs_lseek(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), offset, whence);
}

static ssize_t vfs_gluster_sendfile(struct vfs_handle_struct *handle, int tofd,
				    files_struct *fromfsp,
				    const DATA_BLOB *hdr,
				    off_t offset, size_t n)
{
	errno = ENOTSUP;
	return -1;
}

static ssize_t vfs_gluster_recvfile(struct vfs_handle_struct *handle,
				    int fromfd, files_struct *tofsp,
				    off_t offset, size_t n)
{
	errno = ENOTSUP;
	return -1;
}

static int vfs_gluster_rename(struct vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname_src,
			      const struct smb_filename *smb_fname_dst)
{
	return glfs_rename(handle->data, smb_fname_src->base_name,
			   smb_fname_dst->base_name);
}

static int vfs_gluster_fsync(struct vfs_handle_struct *handle,
			     files_struct *fsp)
{
	return glfs_fsync(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp));
}

static struct tevent_req *vfs_gluster_fsync_send(struct vfs_handle_struct
						 *handle, TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 files_struct *fsp)
{
	struct tevent_req *req = NULL;
	struct glusterfs_aio_state *state = NULL;
	int ret = 0;

	state = aio_state_create(mem_ctx);

	if (state == NULL) {
		return NULL;
	}

	req = state->req;

	if (!init_gluster_aio(handle)) {
		tevent_req_error(req, EIO);
		return tevent_req_post(req, ev);
	}

	PROFILE_TIMESTAMP(&state->start);
	ret = glfs_fsync_async(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle,
				fsp), aio_glusterfs_done, req);
	if (ret < 0) {
		tevent_req_error(req, -ret);
		return tevent_req_post(req, ev);
	}
	return req;
}

static int vfs_gluster_fsync_recv(struct tevent_req *req,
				  struct vfs_aio_state *vfs_aio_state)
{
	/*
	 * Use implicit conversion ssize_t->int
	 */
	return vfs_gluster_recv(req, vfs_aio_state);
}

static int vfs_gluster_stat(struct vfs_handle_struct *handle,
			    struct smb_filename *smb_fname)
{
	struct stat st;
	int ret;

	ret = glfs_stat(handle->data, smb_fname->base_name, &st);
	if (ret == 0) {
		smb_stat_ex_from_stat(&smb_fname->st, &st);
	}
	if (ret < 0 && errno != ENOENT) {
		DEBUG(0, ("glfs_stat(%s) failed: %s\n",
			  smb_fname->base_name, strerror(errno)));
	}
	return ret;
}

static int vfs_gluster_fstat(struct vfs_handle_struct *handle,
			     files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	struct stat st;
	int ret;

	ret = glfs_fstat(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), &st);
	if (ret == 0) {
		smb_stat_ex_from_stat(sbuf, &st);
	}
	if (ret < 0) {
		DEBUG(0, ("glfs_fstat(%d) failed: %s\n",
			  fsp->fh->fd, strerror(errno)));
	}
	return ret;
}

static int vfs_gluster_lstat(struct vfs_handle_struct *handle,
			     struct smb_filename *smb_fname)
{
	struct stat st;
	int ret;

	ret = glfs_lstat(handle->data, smb_fname->base_name, &st);
	if (ret == 0) {
		smb_stat_ex_from_stat(&smb_fname->st, &st);
	}
	if (ret < 0 && errno != ENOENT) {
		DEBUG(0, ("glfs_lstat(%s) failed: %s\n",
			  smb_fname->base_name, strerror(errno)));
	}
	return ret;
}

static uint64_t vfs_gluster_get_alloc_size(struct vfs_handle_struct *handle,
					   files_struct *fsp,
					   const SMB_STRUCT_STAT *sbuf)
{
	return sbuf->st_ex_blocks * 512;
}

static int vfs_gluster_unlink(struct vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname)
{
	return glfs_unlink(handle->data, smb_fname->base_name);
}

static int vfs_gluster_chmod(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				mode_t mode)
{
	return glfs_chmod(handle->data, smb_fname->base_name, mode);
}

static int vfs_gluster_fchmod(struct vfs_handle_struct *handle,
			      files_struct *fsp, mode_t mode)
{
	return glfs_fchmod(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), mode);
}

static int vfs_gluster_chown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	return glfs_chown(handle->data, smb_fname->base_name, uid, gid);
}

static int vfs_gluster_fchown(struct vfs_handle_struct *handle,
			      files_struct *fsp, uid_t uid, gid_t gid)
{
	return glfs_fchown(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), uid, gid);
}

static int vfs_gluster_lchown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	return glfs_lchown(handle->data, smb_fname->base_name, uid, gid);
}

static int vfs_gluster_chdir(struct vfs_handle_struct *handle, const char *path)
{
	return glfs_chdir(handle->data, path);
}

static char *vfs_gluster_getwd(struct vfs_handle_struct *handle)
{
	char *cwd;
	char *ret;

	cwd = SMB_CALLOC_ARRAY(char, PATH_MAX);
	if (cwd == NULL) {
		return NULL;
	}

	ret = glfs_getcwd(handle->data, cwd, PATH_MAX - 1);
	if (ret == 0) {
		free(cwd);
	}
	return ret;
}

static int vfs_gluster_ntimes(struct vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname,
			      struct smb_file_time *ft)
{
	struct timespec times[2];

	if (null_timespec(ft->atime)) {
		times[0].tv_sec = smb_fname->st.st_ex_atime.tv_sec;
		times[0].tv_nsec = smb_fname->st.st_ex_atime.tv_nsec;
	} else {
		times[0].tv_sec = ft->atime.tv_sec;
		times[0].tv_nsec = ft->atime.tv_nsec;
	}

	if (null_timespec(ft->mtime)) {
		times[1].tv_sec = smb_fname->st.st_ex_mtime.tv_sec;
		times[1].tv_nsec = smb_fname->st.st_ex_mtime.tv_nsec;
	} else {
		times[1].tv_sec = ft->mtime.tv_sec;
		times[1].tv_nsec = ft->mtime.tv_nsec;
	}

	if ((timespec_compare(&times[0],
			      &smb_fname->st.st_ex_atime) == 0) &&
	    (timespec_compare(&times[1],
			      &smb_fname->st.st_ex_mtime) == 0)) {
		return 0;
	}

	return glfs_utimens(handle->data, smb_fname->base_name, times);
}

static int vfs_gluster_ftruncate(struct vfs_handle_struct *handle,
				 files_struct *fsp, off_t offset)
{
	return glfs_ftruncate(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), offset);
}

static int vfs_gluster_fallocate(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 uint32_t mode,
				 off_t offset, off_t len)
{
	/* TODO: add support using glfs_fallocate() and glfs_zerofill() */
	errno = ENOTSUP;
	return -1;
}

static char *vfs_gluster_realpath(struct vfs_handle_struct *handle,
				  const char *path)
{
	char *result = NULL;
	char *resolved_path = SMB_MALLOC_ARRAY(char, PATH_MAX+1);

	if (resolved_path == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	result = glfs_realpath(handle->data, path, resolved_path);
	if (result == NULL) {
		SAFE_FREE(resolved_path);
	}

	return result;
}

static bool vfs_gluster_lock(struct vfs_handle_struct *handle,
			     files_struct *fsp, int op, off_t offset,
			     off_t count, int type)
{
	struct flock flock = { 0, };
	int ret;

	flock.l_type = type;
	flock.l_whence = SEEK_SET;
	flock.l_start = offset;
	flock.l_len = count;
	flock.l_pid = 0;

	ret = glfs_posix_lock(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), op, &flock);

	if (op == F_GETLK) {
		/* lock query, true if someone else has locked */
		if ((ret != -1) &&
		    (flock.l_type != F_UNLCK) &&
		    (flock.l_pid != 0) && (flock.l_pid != getpid()))
			return true;
		/* not me */
		return false;
	}

	if (ret == -1) {
		return false;
	}

	return true;
}

static int vfs_gluster_kernel_flock(struct vfs_handle_struct *handle,
				    files_struct *fsp, uint32_t share_mode,
				    uint32_t access_mask)
{
	errno = ENOSYS;
	return -1;
}

static int vfs_gluster_linux_setlease(struct vfs_handle_struct *handle,
				      files_struct *fsp, int leasetype)
{
	errno = ENOSYS;
	return -1;
}

static bool vfs_gluster_getlock(struct vfs_handle_struct *handle,
				files_struct *fsp, off_t *poffset,
				off_t *pcount, int *ptype, pid_t *ppid)
{
	struct flock flock = { 0, };
	int ret;

	flock.l_type = *ptype;
	flock.l_whence = SEEK_SET;
	flock.l_start = *poffset;
	flock.l_len = *pcount;
	flock.l_pid = 0;

	ret = glfs_posix_lock(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), F_GETLK, &flock);

	if (ret == -1) {
		return false;
	}

	*ptype = flock.l_type;
	*poffset = flock.l_start;
	*pcount = flock.l_len;
	*ppid = flock.l_pid;

	return true;
}

static int vfs_gluster_symlink(struct vfs_handle_struct *handle,
			       const char *oldpath, const char *newpath)
{
	return glfs_symlink(handle->data, oldpath, newpath);
}

static int vfs_gluster_readlink(struct vfs_handle_struct *handle,
				const char *path, char *buf, size_t bufsiz)
{
	return glfs_readlink(handle->data, path, buf, bufsiz);
}

static int vfs_gluster_link(struct vfs_handle_struct *handle,
			    const char *oldpath, const char *newpath)
{
	return glfs_link(handle->data, oldpath, newpath);
}

static int vfs_gluster_mknod(struct vfs_handle_struct *handle, const char *path,
			     mode_t mode, SMB_DEV_T dev)
{
	return glfs_mknod(handle->data, path, mode, dev);
}

static int vfs_gluster_chflags(struct vfs_handle_struct *handle,
			       const char *path, unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}

static int vfs_gluster_get_real_filename(struct vfs_handle_struct *handle,
					 const char *path, const char *name,
					 TALLOC_CTX *mem_ctx, char **found_name)
{
	int ret;
	char key_buf[NAME_MAX + 64];
	char val_buf[NAME_MAX + 1];

	if (strlen(name) >= NAME_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	snprintf(key_buf, NAME_MAX + 64,
		 "glusterfs.get_real_filename:%s", name);

	ret = glfs_getxattr(handle->data, path, key_buf, val_buf, NAME_MAX + 1);
	if (ret == -1) {
		if (errno == ENODATA) {
			errno = EOPNOTSUPP;
		}
		return -1;
	}

	*found_name = talloc_strdup(mem_ctx, val_buf);
	if (found_name[0] == NULL) {
		errno = ENOMEM;
		return -1;
	}
	return 0;
}

static const char *vfs_gluster_connectpath(struct vfs_handle_struct *handle,
					   const char *filename)
{
	return handle->conn->connectpath;
}

/* EA Operations */

static ssize_t vfs_gluster_getxattr(struct vfs_handle_struct *handle,
				    const char *path, const char *name,
				    void *value, size_t size)
{
	return glfs_getxattr(handle->data, path, name, value, size);
}

static ssize_t vfs_gluster_fgetxattr(struct vfs_handle_struct *handle,
				     files_struct *fsp, const char *name,
				     void *value, size_t size)
{
	return glfs_fgetxattr(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), name, value, size);
}

static ssize_t vfs_gluster_listxattr(struct vfs_handle_struct *handle,
				     const char *path, char *list, size_t size)
{
	return glfs_listxattr(handle->data, path, list, size);
}

static ssize_t vfs_gluster_flistxattr(struct vfs_handle_struct *handle,
				      files_struct *fsp, char *list,
				      size_t size)
{
	return glfs_flistxattr(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), list, size);
}

static int vfs_gluster_removexattr(struct vfs_handle_struct *handle,
				   const char *path, const char *name)
{
	return glfs_removexattr(handle->data, path, name);
}

static int vfs_gluster_fremovexattr(struct vfs_handle_struct *handle,
				    files_struct *fsp, const char *name)
{
	return glfs_fremovexattr(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), name);
}

static int vfs_gluster_setxattr(struct vfs_handle_struct *handle,
				const char *path, const char *name,
				const void *value, size_t size, int flags)
{
	return glfs_setxattr(handle->data, path, name, value, size, flags);
}

static int vfs_gluster_fsetxattr(struct vfs_handle_struct *handle,
				 files_struct *fsp, const char *name,
				 const void *value, size_t size, int flags)
{
	return glfs_fsetxattr(*(glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp), name, value, size,
			      flags);
}

/* AIO Operations */

static bool vfs_gluster_aio_force(struct vfs_handle_struct *handle,
				  files_struct *fsp)
{
	return false;
}

/* Offline Operations */

static bool vfs_gluster_is_offline(struct vfs_handle_struct *handle,
				   const struct smb_filename *fname,
				   SMB_STRUCT_STAT *sbuf)
{
	return false;
}

static int vfs_gluster_set_offline(struct vfs_handle_struct *handle,
				   const struct smb_filename *fname)
{
	errno = ENOTSUP;
	return -1;
}

static struct vfs_fn_pointers glusterfs_fns = {

	/* Disk Operations */

	.connect_fn = vfs_gluster_connect,
	.disconnect_fn = vfs_gluster_disconnect,
	.disk_free_fn = vfs_gluster_disk_free,
	.get_quota_fn = vfs_gluster_get_quota,
	.set_quota_fn = vfs_gluster_set_quota,
	.statvfs_fn = vfs_gluster_statvfs,
	.fs_capabilities_fn = vfs_gluster_fs_capabilities,

	.get_dfs_referrals_fn = NULL,

	/* Directory Operations */

	.opendir_fn = vfs_gluster_opendir,
	.fdopendir_fn = vfs_gluster_fdopendir,
	.readdir_fn = vfs_gluster_readdir,
	.seekdir_fn = vfs_gluster_seekdir,
	.telldir_fn = vfs_gluster_telldir,
	.rewind_dir_fn = vfs_gluster_rewinddir,
	.mkdir_fn = vfs_gluster_mkdir,
	.rmdir_fn = vfs_gluster_rmdir,
	.closedir_fn = vfs_gluster_closedir,
	.init_search_op_fn = vfs_gluster_init_search_op,

	/* File Operations */

	.open_fn = vfs_gluster_open,
	.create_file_fn = NULL,
	.close_fn = vfs_gluster_close,
	.read_fn = vfs_gluster_read,
	.pread_fn = vfs_gluster_pread,
	.pread_send_fn = vfs_gluster_pread_send,
	.pread_recv_fn = vfs_gluster_recv,
	.write_fn = vfs_gluster_write,
	.pwrite_fn = vfs_gluster_pwrite,
	.pwrite_send_fn = vfs_gluster_pwrite_send,
	.pwrite_recv_fn = vfs_gluster_recv,
	.lseek_fn = vfs_gluster_lseek,
	.sendfile_fn = vfs_gluster_sendfile,
	.recvfile_fn = vfs_gluster_recvfile,
	.rename_fn = vfs_gluster_rename,
	.fsync_fn = vfs_gluster_fsync,
	.fsync_send_fn = vfs_gluster_fsync_send,
	.fsync_recv_fn = vfs_gluster_fsync_recv,

	.stat_fn = vfs_gluster_stat,
	.fstat_fn = vfs_gluster_fstat,
	.lstat_fn = vfs_gluster_lstat,
	.get_alloc_size_fn = vfs_gluster_get_alloc_size,
	.unlink_fn = vfs_gluster_unlink,

	.chmod_fn = vfs_gluster_chmod,
	.fchmod_fn = vfs_gluster_fchmod,
	.chown_fn = vfs_gluster_chown,
	.fchown_fn = vfs_gluster_fchown,
	.lchown_fn = vfs_gluster_lchown,
	.chdir_fn = vfs_gluster_chdir,
	.getwd_fn = vfs_gluster_getwd,
	.ntimes_fn = vfs_gluster_ntimes,
	.ftruncate_fn = vfs_gluster_ftruncate,
	.fallocate_fn = vfs_gluster_fallocate,
	.lock_fn = vfs_gluster_lock,
	.kernel_flock_fn = vfs_gluster_kernel_flock,
	.linux_setlease_fn = vfs_gluster_linux_setlease,
	.getlock_fn = vfs_gluster_getlock,
	.symlink_fn = vfs_gluster_symlink,
	.readlink_fn = vfs_gluster_readlink,
	.link_fn = vfs_gluster_link,
	.mknod_fn = vfs_gluster_mknod,
	.realpath_fn = vfs_gluster_realpath,
	.chflags_fn = vfs_gluster_chflags,
	.file_id_create_fn = NULL,
	.copy_chunk_send_fn = NULL,
	.copy_chunk_recv_fn = NULL,
	.streaminfo_fn = NULL,
	.get_real_filename_fn = vfs_gluster_get_real_filename,
	.connectpath_fn = vfs_gluster_connectpath,

	.brl_lock_windows_fn = NULL,
	.brl_unlock_windows_fn = NULL,
	.brl_cancel_windows_fn = NULL,
	.strict_lock_fn = NULL,
	.strict_unlock_fn = NULL,
	.translate_name_fn = NULL,
	.fsctl_fn = NULL,

	/* NT ACL Operations */
	.fget_nt_acl_fn = NULL,
	.get_nt_acl_fn = NULL,
	.fset_nt_acl_fn = NULL,
	.audit_file_fn = NULL,

	/* Posix ACL Operations */
	.chmod_acl_fn = NULL,	/* passthrough to default */
	.fchmod_acl_fn = NULL,	/* passthrough to default */
	.sys_acl_get_file_fn = posixacl_xattr_acl_get_file,
	.sys_acl_get_fd_fn = posixacl_xattr_acl_get_fd,
	.sys_acl_blob_get_file_fn = posix_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = posixacl_xattr_acl_set_file,
	.sys_acl_set_fd_fn = posixacl_xattr_acl_set_fd,
	.sys_acl_delete_def_file_fn = posixacl_xattr_acl_delete_def_file,

	/* EA Operations */
	.getxattr_fn = vfs_gluster_getxattr,
	.fgetxattr_fn = vfs_gluster_fgetxattr,
	.listxattr_fn = vfs_gluster_listxattr,
	.flistxattr_fn = vfs_gluster_flistxattr,
	.removexattr_fn = vfs_gluster_removexattr,
	.fremovexattr_fn = vfs_gluster_fremovexattr,
	.setxattr_fn = vfs_gluster_setxattr,
	.fsetxattr_fn = vfs_gluster_fsetxattr,

	/* AIO Operations */
	.aio_force_fn = vfs_gluster_aio_force,

	/* Offline Operations */
	.is_offline_fn = vfs_gluster_is_offline,
	.set_offline_fn = vfs_gluster_set_offline,

	/* Durable handle Operations */
	.durable_cookie_fn = NULL,
	.durable_disconnect_fn = NULL,
	.durable_reconnect_fn = NULL,
};

NTSTATUS vfs_glusterfs_init(void);
NTSTATUS vfs_glusterfs_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"glusterfs", &glusterfs_fns);
}
