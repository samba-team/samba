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
#include <glusterfs/api/glfs.h>
#include "lib/util/dlinklist.h"
#include "lib/util/tevent_unix.h"
#include "smbd/globals.h"
#include "lib/util/sys_rw.h"
#include "smbprofile.h"
#include "modules/posixacl_xattr.h"
#include "lib/pthreadpool/pthreadpool_tevent.h"

#define DEFAULT_VOLFILE_SERVER "localhost"
#define GLUSTER_NAME_MAX 255

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
	dst->st_ex_file_id = dst->st_ex_ino;
	dst->st_ex_iflags |= ST_EX_IFLAG_CALCULATED_FILE_ID;
#ifdef STAT_HAVE_NSEC
	dst->st_ex_atime.tv_nsec = src->st_atime_nsec;
	dst->st_ex_mtime.tv_nsec = src->st_mtime_nsec;
	dst->st_ex_ctime.tv_nsec = src->st_ctime_nsec;
	dst->st_ex_btime.tv_nsec = src->st_mtime_nsec;
#endif
	dst->st_ex_itime = dst->st_ex_btime;
	dst->st_ex_iflags |= ST_EX_IFLAG_CALCULATED_ITIME;
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

static int vfs_gluster_set_volfile_servers(glfs_t *fs,
					   const char *volfile_servers)
{
	char *server = NULL;
	size_t server_count = 0;
	size_t server_success = 0;
	int   ret = -1;
	TALLOC_CTX *frame = talloc_stackframe();

	DBG_INFO("servers list %s\n", volfile_servers);

	while (next_token_talloc(frame, &volfile_servers, &server, " \t")) {
		char *transport = NULL;
		char *host = NULL;
		int   port = 0;

		server_count++;
		DBG_INFO("server %zu %s\n", server_count, server);

		/* Determine the transport type */
		if (strncmp(server, "unix+", 5) == 0) {
			port = 0;
			transport = talloc_strdup(frame, "unix");
			if (!transport) {
				errno = ENOMEM;
				goto out;
			}
			host = talloc_strdup(frame, server + 5);
			if (!host) {
				errno = ENOMEM;
				goto out;
			}
		} else {
			char *p = NULL;
			char *port_index = NULL;

			if (strncmp(server, "tcp+", 4) == 0) {
				server += 4;
			}

			/* IPv6 is enclosed in []
			 * ':' before ']' is part of IPv6
			 * ':' after  ']' indicates port
			 */
			p = server;
			if (server[0] == '[') {
				server++;
				p = index(server, ']');
				if (p == NULL) {
					/* Malformed IPv6 */
					continue;
				}
				p[0] = '\0';
				p++;
			}

			port_index = index(p, ':');

			if (port_index == NULL) {
				port = 0;
			} else {
				port = atoi(port_index + 1);
				port_index[0] = '\0';
			}
			transport = talloc_strdup(frame, "tcp");
			if (!transport) {
				errno = ENOMEM;
				goto out;
			}
			host = talloc_strdup(frame, server);
			if (!host) {
				errno = ENOMEM;
				goto out;
			}
		}

		DBG_INFO("Calling set volfile server with params "
			 "transport=%s, host=%s, port=%d\n", transport,
			  host, port);

		ret = glfs_set_volfile_server(fs, transport, host, port);
		if (ret < 0) {
			DBG_WARNING("Failed to set volfile_server "
				    "transport=%s, host=%s, port=%d (%s)\n",
				    transport, host, port, strerror(errno));
		} else {
			server_success++;
		}
	}

out:
	if (server_count == 0) {
		ret = -1;
	} else if (server_success < server_count) {
		DBG_WARNING("Failed to set %zu out of %zu servers parsed\n",
			    server_count - server_success, server_count);
		ret = 0;
	}

	TALLOC_FREE(frame);
	return ret;
}

/* Disk Operations */

static int check_for_write_behind_translator(TALLOC_CTX *mem_ctx,
					     glfs_t *fs,
					     const char *volume)
{
	char *buf = NULL;
	char **lines = NULL;
	int numlines = 0;
	int i;
	char *option;
	bool write_behind_present = false;
	size_t newlen;
	int ret;

	ret = glfs_get_volfile(fs, NULL, 0);
	if (ret == 0) {
		DBG_ERR("%s: Failed to get volfile for "
			"volume (%s): No volfile\n",
			volume,
			strerror(errno));
		return -1;
	}
	if (ret > 0) {
		DBG_ERR("%s: Invalid return %d for glfs_get_volfile for "
			"volume (%s): No volfile\n",
			volume,
			ret,
			strerror(errno));
		return -1;
	}

	newlen = 0 - ret;

	buf = talloc_zero_array(mem_ctx, char, newlen);
	if (buf == NULL) {
		return -1;
	}

	ret = glfs_get_volfile(fs, buf, newlen);
	if (ret != newlen) {
		TALLOC_FREE(buf);
		DBG_ERR("%s: Failed to get volfile for volume (%s)\n",
			volume, strerror(errno));
		return -1;
	}

	option = talloc_asprintf(mem_ctx, "volume %s-write-behind", volume);
	if (option == NULL) {
		TALLOC_FREE(buf);
		return -1;
	}

	/*
	 * file_lines_parse() plays horrible tricks with
	 * the passed-in talloc pointers and the hierarcy
	 * which makes freeing hard to get right.
	 *
	 * As we know mem_ctx is freed by the caller, after
	 * this point don't free on exit and let the caller
	 * handle it. This violates good Samba coding practice
	 * but we know we're not leaking here.
	 */

	lines = file_lines_parse(buf,
				newlen,
				&numlines,
				mem_ctx);
	if (lines == NULL || numlines <= 0) {
		return -1;
	}
	/* On success, buf is now a talloc child of lines !! */

	for (i=0; i < numlines; i++) {
		if (strequal(lines[i], option)) {
			write_behind_present = true;
			break;
		}
	}

	if (write_behind_present) {
		DBG_ERR("Write behind translator is enabled for "
			"volume (%s), refusing to connect! "
			"Please turn off the write behind translator by calling "
			"'gluster volume set %s performance.write-behind off' "
			"on the commandline. "
			"Check the vfs_glusterfs(8) manpage for "
			"further details.\n",
			volume, volume);
		return -1;
	}

	return 0;
}

static int vfs_gluster_connect(struct vfs_handle_struct *handle,
			       const char *service,
			       const char *user)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	const char *volfile_servers;
	const char *volume;
	char *logfile;
	int loglevel;
	glfs_t *fs = NULL;
	TALLOC_CTX *tmp_ctx;
	int ret = 0;
	bool write_behind_pass_through_set = false;

	tmp_ctx = talloc_new(NULL);
	if (tmp_ctx == NULL) {
		ret = -1;
		goto done;
	}
	logfile = lp_parm_substituted_string(tmp_ctx,
					     lp_sub,
					     SNUM(handle->conn),
					     "glusterfs",
					     "logfile",
					     NULL);

	loglevel = lp_parm_int(SNUM(handle->conn), "glusterfs", "loglevel", -1);

	volfile_servers = lp_parm_substituted_string(tmp_ctx,
						     lp_sub,
						     SNUM(handle->conn),
						     "glusterfs",
						     "volfile_server",
						     NULL);
	if (volfile_servers == NULL) {
		volfile_servers = DEFAULT_VOLFILE_SERVER;
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

	ret = vfs_gluster_set_volfile_servers(fs, volfile_servers);
	if (ret < 0) {
		DBG_ERR("Failed to set volfile_servers from list %s\n",
			volfile_servers);
		goto done;
	}

	ret = glfs_set_xlator_option(fs, "*-md-cache", "cache-posix-acl",
				     "true");
	if (ret < 0) {
		DEBUG(0, ("%s: Failed to set xlator options\n", volume));
		goto done;
	}

	ret = glfs_set_xlator_option(fs, "*-md-cache", "cache-selinux",
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

#ifdef HAVE_GFAPI_VER_7_9
	ret = glfs_set_xlator_option(fs, "*-write-behind", "pass-through",
				     "true");
	if (ret < 0) {
		DBG_ERR("%s: Failed to set xlator option: pass-through\n",
			volume);
		goto done;
	}
	write_behind_pass_through_set = true;
#endif

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

	if (!write_behind_pass_through_set) {
		ret = check_for_write_behind_translator(tmp_ctx, fs, volume);
		if (ret < 0) {
			goto done;
		}
	}

	ret = glfs_set_preopened(volume, handle->conn->connectpath, fs);
	if (ret < 0) {
		DEBUG(0, ("%s: Failed to register volume (%s)\n",
			  volume, strerror(errno)));
		goto done;
	}

	/*
	 * The shadow_copy2 module will fail to export subdirectories
	 * of a gluster volume unless we specify the mount point,
	 * because the detection fails if the file system is not
	 * locally mounted:
	 * https://bugzilla.samba.org/show_bug.cgi?id=13091
	 */
	lp_do_parameter(SNUM(handle->conn), "shadow:mountpoint", "/");

	/*
	 * Unless we have an async implementation of getxattrat turn this off.
	 */
	lp_do_parameter(SNUM(handle->conn), "smbd async dosmode", "false");

done:
	if (ret < 0) {
		if (fs)
			glfs_fini(fs);
	} else {
		DBG_ERR("%s: Initialized volume from servers %s\n",
			volume, volfile_servers);
		handle->data = fs;
	}
	talloc_free(tmp_ctx);
	return ret;
}

static void vfs_gluster_disconnect(struct vfs_handle_struct *handle)
{
	glfs_t *fs = NULL;

	fs = handle->data;

	glfs_clear_preopened(fs);
}

static uint64_t vfs_gluster_disk_free(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize_p,
				uint64_t *dfree_p,
				uint64_t *dsize_p)
{
	struct statvfs statvfs = { 0, };
	int ret;

	ret = glfs_statvfs(handle->data, smb_fname->base_name, &statvfs);
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
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
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
				const struct smb_filename *smb_fname,
				struct vfs_statvfs_struct *vfs_statvfs)
{
	struct statvfs statvfs = { 0, };
	int ret;

	ret = glfs_statvfs(handle->data, smb_fname->base_name, &statvfs);
	if (ret < 0) {
		DEBUG(0, ("glfs_statvfs(%s) failed: %s\n",
			  smb_fname->base_name, strerror(errno)));
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

#ifdef HAVE_GFAPI_VER_6
	caps |= FILE_SUPPORTS_SPARSE_FILES;
#endif

#ifdef STAT_HAVE_NSEC
	*p_ts_res = TIMESTAMP_SET_NT_OR_BETTER;
#endif

	return caps;
}

static glfs_fd_t *vfs_gluster_fetch_glfd(struct vfs_handle_struct *handle,
					 files_struct *fsp)
{
	glfs_fd_t **glfd = (glfs_fd_t **)VFS_FETCH_FSP_EXTENSION(handle, fsp);
	if (glfd == NULL) {
		DBG_INFO("Failed to fetch fsp extension\n");
		return NULL;
	}
	if (*glfd == NULL) {
		DBG_INFO("Empty glfs_fd_t pointer\n");
		return NULL;
	}

	return *glfd;
}

static DIR *vfs_gluster_fdopendir(struct vfs_handle_struct *handle,
				  files_struct *fsp, const char *mask,
				  uint32_t attributes)
{
	glfs_fd_t *glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		DBG_ERR("Failed to fetch gluster fd\n");
		return NULL;
	}

	return (DIR *)glfd;
}

static int vfs_gluster_closedir(struct vfs_handle_struct *handle, DIR *dirp)
{
	int ret;

	START_PROFILE(syscall_closedir);
	ret = glfs_closedir((void *)dirp);
	END_PROFILE(syscall_closedir);

	return ret;
}

static struct dirent *vfs_gluster_readdir(struct vfs_handle_struct *handle,
					  DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
	static char direntbuf[512];
	int ret;
	struct stat stat;
	struct dirent *dirent = 0;

	START_PROFILE(syscall_readdir);
	if (sbuf != NULL) {
		ret = glfs_readdirplus_r((void *)dirp, &stat, (void *)direntbuf,
					 &dirent);
	} else {
		ret = glfs_readdir_r((void *)dirp, (void *)direntbuf, &dirent);
	}

	if ((ret < 0) || (dirent == NULL)) {
		END_PROFILE(syscall_readdir);
		return NULL;
	}

	if (sbuf != NULL) {
		SET_STAT_INVALID(*sbuf);
		if (!S_ISLNK(stat.st_mode)) {
			smb_stat_ex_from_stat(sbuf, &stat);
		}
	}

	END_PROFILE(syscall_readdir);
	return dirent;
}

static long vfs_gluster_telldir(struct vfs_handle_struct *handle, DIR *dirp)
{
	long ret;

	START_PROFILE(syscall_telldir);
	ret = glfs_telldir((void *)dirp);
	END_PROFILE(syscall_telldir);

	return ret;
}

static void vfs_gluster_seekdir(struct vfs_handle_struct *handle, DIR *dirp,
				long offset)
{
	START_PROFILE(syscall_seekdir);
	glfs_seekdir((void *)dirp, offset);
	END_PROFILE(syscall_seekdir);
}

static void vfs_gluster_rewinddir(struct vfs_handle_struct *handle, DIR *dirp)
{
	START_PROFILE(syscall_rewinddir);
	glfs_seekdir((void *)dirp, 0);
	END_PROFILE(syscall_rewinddir);
}

static int vfs_gluster_mkdirat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int ret;

	START_PROFILE(syscall_mkdirat);
	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);
	ret = glfs_mkdir(handle->data, smb_fname->base_name, mode);
	END_PROFILE(syscall_mkdirat);

	return ret;
}

static int vfs_gluster_openat(struct vfs_handle_struct *handle,
			      const struct files_struct *dirfsp,
			      const struct smb_filename *smb_fname,
			      files_struct *fsp,
			      int flags,
			      mode_t mode)
{
	glfs_fd_t *glfd;
	glfs_fd_t **p_tmp;

	START_PROFILE(syscall_openat);

	/*
	 * Looks like glfs API doesn't have openat().
	 */
	SMB_ASSERT(dirfsp->fh->fd == AT_FDCWD);

	p_tmp = VFS_ADD_FSP_EXTENSION(handle, fsp, glfs_fd_t *, NULL);
	if (p_tmp == NULL) {
		END_PROFILE(syscall_openat);
		errno = ENOMEM;
		return -1;
	}

	if (flags & O_DIRECTORY) {
		glfd = glfs_opendir(handle->data, smb_fname->base_name);
	} else if (flags & O_CREAT) {
		glfd = glfs_creat(handle->data, smb_fname->base_name, flags,
				  mode);
	} else {
		glfd = glfs_open(handle->data, smb_fname->base_name, flags);
	}

	if (glfd == NULL) {
		END_PROFILE(syscall_openat);
		/* no extension destroy_fn, so no need to save errno */
		VFS_REMOVE_FSP_EXTENSION(handle, fsp);
		return -1;
	}

	*p_tmp = glfd;

	END_PROFILE(syscall_openat);
	/* An arbitrary value for error reporting, so you know its us. */
	return 13371337;
}

static int vfs_gluster_close(struct vfs_handle_struct *handle,
			     files_struct *fsp)
{
	int ret;
	glfs_fd_t *glfd = NULL;

	START_PROFILE(syscall_close);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE(syscall_close);
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	VFS_REMOVE_FSP_EXTENSION(handle, fsp);

	ret = glfs_close(glfd);
	END_PROFILE(syscall_close);

	return ret;
}

static ssize_t vfs_gluster_pread(struct vfs_handle_struct *handle,
				 files_struct *fsp, void *data, size_t n,
				 off_t offset)
{
	ssize_t ret;
	glfs_fd_t *glfd = NULL;

	START_PROFILE_BYTES(syscall_pread, n);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE_BYTES(syscall_pread);
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

#ifdef HAVE_GFAPI_VER_7_6
	ret = glfs_pread(glfd, data, n, offset, 0, NULL);
#else
	ret = glfs_pread(glfd, data, n, offset, 0);
#endif
	END_PROFILE_BYTES(syscall_pread);

	return ret;
}

struct vfs_gluster_pread_state {
	ssize_t ret;
	glfs_fd_t *fd;
	void *buf;
	size_t count;
	off_t offset;

	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_gluster_pread_do(void *private_data);
static void vfs_gluster_pread_done(struct tevent_req *subreq);
static int vfs_gluster_pread_state_destructor(struct vfs_gluster_pread_state *state);

static struct tevent_req *vfs_gluster_pread_send(struct vfs_handle_struct
						  *handle, TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  files_struct *fsp,
						  void *data, size_t n,
						  off_t offset)
{
	struct vfs_gluster_pread_state *state;
	struct tevent_req *req, *subreq;

	glfs_fd_t *glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		DBG_ERR("Failed to fetch gluster fd\n");
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state, struct vfs_gluster_pread_state);
	if (req == NULL) {
		return NULL;
	}

	state->ret = -1;
	state->fd = glfd;
	state->buf = data;
	state->count = n;
	state->offset = offset;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pread, profile_p,
				     state->profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	subreq = pthreadpool_tevent_job_send(
		state, ev, handle->conn->sconn->pool,
		vfs_gluster_pread_do, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_gluster_pread_done, req);

	talloc_set_destructor(state, vfs_gluster_pread_state_destructor);

	return req;
}

static void vfs_gluster_pread_do(void *private_data)
{
	struct vfs_gluster_pread_state *state = talloc_get_type_abort(
		private_data, struct vfs_gluster_pread_state);
	struct timespec start_time;
	struct timespec end_time;

	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);

	PROFILE_TIMESTAMP(&start_time);

	do {
#ifdef HAVE_GFAPI_VER_7_6
		state->ret = glfs_pread(state->fd, state->buf, state->count,
					state->offset, 0, NULL);
#else
		state->ret = glfs_pread(state->fd, state->buf, state->count,
					state->offset, 0);
#endif
	} while ((state->ret == -1) && (errno == EINTR));

	if (state->ret == -1) {
		state->vfs_aio_state.error = errno;
	}

	PROFILE_TIMESTAMP(&end_time);

	state->vfs_aio_state.duration = nsec_time_diff(&end_time, &start_time);

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
}

static int vfs_gluster_pread_state_destructor(struct vfs_gluster_pread_state *state)
{
	return -1;
}

static void vfs_gluster_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_gluster_pread_state *state = tevent_req_data(
		req, struct vfs_gluster_pread_state);
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
		vfs_gluster_pread_do(state);
	}

	tevent_req_done(req);
}

static ssize_t vfs_gluster_pread_recv(struct tevent_req *req,
				      struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_gluster_pread_state *state = tevent_req_data(
		req, struct vfs_gluster_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

struct vfs_gluster_pwrite_state {
	ssize_t ret;
	glfs_fd_t *fd;
	const void *buf;
	size_t count;
	off_t offset;

	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_gluster_pwrite_do(void *private_data);
static void vfs_gluster_pwrite_done(struct tevent_req *subreq);
static int vfs_gluster_pwrite_state_destructor(struct vfs_gluster_pwrite_state *state);

static struct tevent_req *vfs_gluster_pwrite_send(struct vfs_handle_struct
						  *handle, TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  files_struct *fsp,
						  const void *data, size_t n,
						  off_t offset)
{
	struct tevent_req *req, *subreq;
	struct vfs_gluster_pwrite_state *state;

	glfs_fd_t *glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		DBG_ERR("Failed to fetch gluster fd\n");
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state, struct vfs_gluster_pwrite_state);
	if (req == NULL) {
		return NULL;
	}

	state->ret = -1;
	state->fd = glfd;
	state->buf = data;
	state->count = n;
	state->offset = offset;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_pwrite, profile_p,
				     state->profile_bytes, n);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	subreq = pthreadpool_tevent_job_send(
		state, ev, handle->conn->sconn->pool,
		vfs_gluster_pwrite_do, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_gluster_pwrite_done, req);

	talloc_set_destructor(state, vfs_gluster_pwrite_state_destructor);

	return req;
}

static void vfs_gluster_pwrite_do(void *private_data)
{
	struct vfs_gluster_pwrite_state *state = talloc_get_type_abort(
		private_data, struct vfs_gluster_pwrite_state);
	struct timespec start_time;
	struct timespec end_time;

	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);

	PROFILE_TIMESTAMP(&start_time);

	do {
#ifdef HAVE_GFAPI_VER_7_6
		state->ret = glfs_pwrite(state->fd, state->buf, state->count,
					 state->offset, 0, NULL, NULL);
#else
		state->ret = glfs_pwrite(state->fd, state->buf, state->count,
					 state->offset, 0);
#endif
	} while ((state->ret == -1) && (errno == EINTR));

	if (state->ret == -1) {
		state->vfs_aio_state.error = errno;
	}

	PROFILE_TIMESTAMP(&end_time);

	state->vfs_aio_state.duration = nsec_time_diff(&end_time, &start_time);

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
}

static int vfs_gluster_pwrite_state_destructor(struct vfs_gluster_pwrite_state *state)
{
	return -1;
}

static void vfs_gluster_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_gluster_pwrite_state *state = tevent_req_data(
		req, struct vfs_gluster_pwrite_state);
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
		vfs_gluster_pwrite_do(state);
	}

	tevent_req_done(req);
}

static ssize_t vfs_gluster_pwrite_recv(struct tevent_req *req,
				       struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_gluster_pwrite_state *state = tevent_req_data(
		req, struct vfs_gluster_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;

	return state->ret;
}

static ssize_t vfs_gluster_pwrite(struct vfs_handle_struct *handle,
				  files_struct *fsp, const void *data,
				  size_t n, off_t offset)
{
	ssize_t ret;
	glfs_fd_t *glfd = NULL;

	START_PROFILE_BYTES(syscall_pwrite, n);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE_BYTES(syscall_pwrite);
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

#ifdef HAVE_GFAPI_VER_7_6
	ret = glfs_pwrite(glfd, data, n, offset, 0, NULL, NULL);
#else
	ret = glfs_pwrite(glfd, data, n, offset, 0);
#endif
	END_PROFILE_BYTES(syscall_pwrite);

	return ret;
}

static off_t vfs_gluster_lseek(struct vfs_handle_struct *handle,
			       files_struct *fsp, off_t offset, int whence)
{
	off_t ret = 0;
	glfs_fd_t *glfd = NULL;

	START_PROFILE(syscall_lseek);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE(syscall_lseek);
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	ret = glfs_lseek(glfd, offset, whence);
	END_PROFILE(syscall_lseek);

	return ret;
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

static int vfs_gluster_renameat(struct vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst)
{
	int ret;

	START_PROFILE(syscall_renameat);
	ret = glfs_rename(handle->data, smb_fname_src->base_name,
			  smb_fname_dst->base_name);
	END_PROFILE(syscall_renameat);

	return ret;
}

struct vfs_gluster_fsync_state {
	ssize_t ret;
	glfs_fd_t *fd;

	struct vfs_aio_state vfs_aio_state;
	SMBPROFILE_BYTES_ASYNC_STATE(profile_bytes);
};

static void vfs_gluster_fsync_do(void *private_data);
static void vfs_gluster_fsync_done(struct tevent_req *subreq);
static int vfs_gluster_fsync_state_destructor(struct vfs_gluster_fsync_state *state);

static struct tevent_req *vfs_gluster_fsync_send(struct vfs_handle_struct
						 *handle, TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 files_struct *fsp)
{
	struct tevent_req *req, *subreq;
	struct vfs_gluster_fsync_state *state;

	glfs_fd_t *glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		DBG_ERR("Failed to fetch gluster fd\n");
		return NULL;
	}

	req = tevent_req_create(mem_ctx, &state, struct vfs_gluster_fsync_state);
	if (req == NULL) {
		return NULL;
	}

	state->ret = -1;
	state->fd = glfd;

	SMBPROFILE_BYTES_ASYNC_START(syscall_asys_fsync, profile_p,
                                     state->profile_bytes, 0);
	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);

	subreq = pthreadpool_tevent_job_send(
		state, ev, handle->conn->sconn->pool, vfs_gluster_fsync_do, state);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, vfs_gluster_fsync_done, req);

	talloc_set_destructor(state, vfs_gluster_fsync_state_destructor);

	return req;
}

static void vfs_gluster_fsync_do(void *private_data)
{
	struct vfs_gluster_fsync_state *state = talloc_get_type_abort(
		private_data, struct vfs_gluster_fsync_state);
	struct timespec start_time;
	struct timespec end_time;

	SMBPROFILE_BYTES_ASYNC_SET_BUSY(state->profile_bytes);

	PROFILE_TIMESTAMP(&start_time);

	do {
#ifdef HAVE_GFAPI_VER_7_6
		state->ret = glfs_fsync(state->fd, NULL, NULL);
#else
		state->ret = glfs_fsync(state->fd);
#endif
	} while ((state->ret == -1) && (errno == EINTR));

	if (state->ret == -1) {
		state->vfs_aio_state.error = errno;
	}

	PROFILE_TIMESTAMP(&end_time);

	state->vfs_aio_state.duration = nsec_time_diff(&end_time, &start_time);

	SMBPROFILE_BYTES_ASYNC_SET_IDLE(state->profile_bytes);
}

static int vfs_gluster_fsync_state_destructor(struct vfs_gluster_fsync_state *state)
{
	return -1;
}

static void vfs_gluster_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct vfs_gluster_fsync_state *state = tevent_req_data(
		req, struct vfs_gluster_fsync_state);
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
		vfs_gluster_fsync_do(state);
	}

	tevent_req_done(req);
}

static int vfs_gluster_fsync_recv(struct tevent_req *req,
				  struct vfs_aio_state *vfs_aio_state)
{
	struct vfs_gluster_fsync_state *state = tevent_req_data(
		req, struct vfs_gluster_fsync_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static int vfs_gluster_stat(struct vfs_handle_struct *handle,
			    struct smb_filename *smb_fname)
{
	struct stat st;
	int ret;

	START_PROFILE(syscall_stat);
	ret = glfs_stat(handle->data, smb_fname->base_name, &st);
	if (ret == 0) {
		smb_stat_ex_from_stat(&smb_fname->st, &st);
	}
	if (ret < 0 && errno != ENOENT) {
		DEBUG(0, ("glfs_stat(%s) failed: %s\n",
			  smb_fname->base_name, strerror(errno)));
	}
	END_PROFILE(syscall_stat);

	return ret;
}

static int vfs_gluster_fstat(struct vfs_handle_struct *handle,
			     files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	struct stat st;
	int ret;
	glfs_fd_t *glfd = NULL;

	START_PROFILE(syscall_fstat);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE(syscall_fstat);
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	ret = glfs_fstat(glfd, &st);
	if (ret == 0) {
		smb_stat_ex_from_stat(sbuf, &st);
	}
	if (ret < 0) {
		DEBUG(0, ("glfs_fstat(%d) failed: %s\n",
			  fsp->fh->fd, strerror(errno)));
	}
	END_PROFILE(syscall_fstat);

	return ret;
}

static int vfs_gluster_lstat(struct vfs_handle_struct *handle,
			     struct smb_filename *smb_fname)
{
	struct stat st;
	int ret;

	START_PROFILE(syscall_lstat);
	ret = glfs_lstat(handle->data, smb_fname->base_name, &st);
	if (ret == 0) {
		smb_stat_ex_from_stat(&smb_fname->st, &st);
	}
	if (ret < 0 && errno != ENOENT) {
		DEBUG(0, ("glfs_lstat(%s) failed: %s\n",
			  smb_fname->base_name, strerror(errno)));
	}
	END_PROFILE(syscall_lstat);

	return ret;
}

static uint64_t vfs_gluster_get_alloc_size(struct vfs_handle_struct *handle,
					   files_struct *fsp,
					   const SMB_STRUCT_STAT *sbuf)
{
	uint64_t ret;

	START_PROFILE(syscall_get_alloc_size);
	ret = sbuf->st_ex_blocks * 512;
	END_PROFILE(syscall_get_alloc_size);

	return ret;
}

static int vfs_gluster_unlinkat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	int ret;

	START_PROFILE(syscall_unlinkat);
	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);
	if (flags & AT_REMOVEDIR) {
		ret = glfs_rmdir(handle->data, smb_fname->base_name);
	} else {
		ret = glfs_unlink(handle->data, smb_fname->base_name);
	}
	END_PROFILE(syscall_unlinkat);

	return ret;
}

static int vfs_gluster_chmod(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				mode_t mode)
{
	int ret;

	START_PROFILE(syscall_chmod);
	ret = glfs_chmod(handle->data, smb_fname->base_name, mode);
	END_PROFILE(syscall_chmod);

	return ret;
}

static int vfs_gluster_fchmod(struct vfs_handle_struct *handle,
			      files_struct *fsp, mode_t mode)
{
	int ret;
	glfs_fd_t *glfd = NULL;

	START_PROFILE(syscall_fchmod);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE(syscall_fchmod);
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	ret = glfs_fchmod(glfd, mode);
	END_PROFILE(syscall_fchmod);

	return ret;
}

static int vfs_gluster_fchown(struct vfs_handle_struct *handle,
			      files_struct *fsp, uid_t uid, gid_t gid)
{
	int ret;
	glfs_fd_t *glfd = NULL;

	START_PROFILE(syscall_fchown);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE(syscall_fchown);
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	ret = glfs_fchown(glfd, uid, gid);
	END_PROFILE(syscall_fchown);

	return ret;
}

static int vfs_gluster_lchown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int ret;

	START_PROFILE(syscall_lchown);
	ret = glfs_lchown(handle->data, smb_fname->base_name, uid, gid);
	END_PROFILE(syscall_lchown);

	return ret;
}

static int vfs_gluster_chdir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int ret;

	START_PROFILE(syscall_chdir);
	ret = glfs_chdir(handle->data, smb_fname->base_name);
	END_PROFILE(syscall_chdir);

	return ret;
}

static struct smb_filename *vfs_gluster_getwd(struct vfs_handle_struct *handle,
				TALLOC_CTX *ctx)
{
	char *cwd;
	char *ret;
	struct smb_filename *smb_fname = NULL;

	START_PROFILE(syscall_getwd);

	cwd = SMB_CALLOC_ARRAY(char, PATH_MAX);
	if (cwd == NULL) {
		END_PROFILE(syscall_getwd);
		return NULL;
	}

	ret = glfs_getcwd(handle->data, cwd, PATH_MAX - 1);
	END_PROFILE(syscall_getwd);

	if (ret == NULL) {
		SAFE_FREE(cwd);
		return NULL;
	}
	smb_fname = synthetic_smb_fname(ctx,
					ret,
					NULL,
					NULL,
					0,
					0);
	SAFE_FREE(cwd);
	return smb_fname;
}

static int vfs_gluster_ntimes(struct vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname,
			      struct smb_file_time *ft)
{
	int ret = -1;
	struct timespec times[2];

	START_PROFILE(syscall_ntimes);

	if (is_omit_timespec(&ft->atime)) {
		times[0].tv_sec = smb_fname->st.st_ex_atime.tv_sec;
		times[0].tv_nsec = smb_fname->st.st_ex_atime.tv_nsec;
	} else {
		times[0].tv_sec = ft->atime.tv_sec;
		times[0].tv_nsec = ft->atime.tv_nsec;
	}

	if (is_omit_timespec(&ft->mtime)) {
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
		END_PROFILE(syscall_ntimes);
		return 0;
	}

	ret = glfs_utimens(handle->data, smb_fname->base_name, times);
	END_PROFILE(syscall_ntimes);

	return ret;
}

static int vfs_gluster_ftruncate(struct vfs_handle_struct *handle,
				 files_struct *fsp, off_t offset)
{
	int ret;
	glfs_fd_t *glfd = NULL;

	START_PROFILE(syscall_ftruncate);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE(syscall_ftruncate);
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

#ifdef HAVE_GFAPI_VER_7_6
	ret = glfs_ftruncate(glfd, offset, NULL, NULL);
#else
	ret = glfs_ftruncate(glfd, offset);
#endif
	END_PROFILE(syscall_ftruncate);

	return ret;
}

static int vfs_gluster_fallocate(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 uint32_t mode,
				 off_t offset, off_t len)
{
	int ret;
#ifdef HAVE_GFAPI_VER_6
	glfs_fd_t *glfd = NULL;
	int keep_size, punch_hole;

	START_PROFILE(syscall_fallocate);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE(syscall_fallocate);
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	keep_size = mode & VFS_FALLOCATE_FL_KEEP_SIZE;
	punch_hole = mode & VFS_FALLOCATE_FL_PUNCH_HOLE;

	mode &= ~(VFS_FALLOCATE_FL_KEEP_SIZE|VFS_FALLOCATE_FL_PUNCH_HOLE);
	if (mode != 0) {
		END_PROFILE(syscall_fallocate);
		errno = ENOTSUP;
		return -1;
	}

	if (punch_hole) {
		ret = glfs_discard(glfd, offset, len);
		if (ret != 0) {
			DBG_DEBUG("glfs_discard failed: %s\n",
				  strerror(errno));
		}
	}

	ret = glfs_fallocate(glfd, keep_size, offset, len);
	END_PROFILE(syscall_fallocate);
#else
	errno = ENOTSUP;
	ret = -1;
#endif
	return ret;
}

static struct smb_filename *vfs_gluster_realpath(struct vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)
{
	char *result = NULL;
	struct smb_filename *result_fname = NULL;
	char *resolved_path = NULL;

	START_PROFILE(syscall_realpath);

	resolved_path = SMB_MALLOC_ARRAY(char, PATH_MAX+1);
	if (resolved_path == NULL) {
		END_PROFILE(syscall_realpath);
		errno = ENOMEM;
		return NULL;
	}

	result = glfs_realpath(handle->data,
			smb_fname->base_name,
			resolved_path);
	if (result != NULL) {
		result_fname = synthetic_smb_fname(ctx,
						   result,
						   NULL,
						   NULL,
						   0,
						   0);
	}

	SAFE_FREE(resolved_path);
	END_PROFILE(syscall_realpath);

	return result_fname;
}

static bool vfs_gluster_lock(struct vfs_handle_struct *handle,
			     files_struct *fsp, int op, off_t offset,
			     off_t count, int type)
{
	struct flock flock = { 0, };
	int ret;
	glfs_fd_t *glfd = NULL;
	bool ok = false;

	START_PROFILE(syscall_fcntl_lock);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		DBG_ERR("Failed to fetch gluster fd\n");
		ok = false;
		goto out;
	}

	flock.l_type = type;
	flock.l_whence = SEEK_SET;
	flock.l_start = offset;
	flock.l_len = count;
	flock.l_pid = 0;

	ret = glfs_posix_lock(glfd, op, &flock);

	if (op == F_GETLK) {
		/* lock query, true if someone else has locked */
		if ((ret != -1) &&
		    (flock.l_type != F_UNLCK) &&
		    (flock.l_pid != 0) && (flock.l_pid != getpid())) {
			ok = true;
			goto out;
		}
		/* not me */
		ok = false;
		goto out;
	}

	if (ret == -1) {
		ok = false;
		goto out;
	}

	ok = true;
out:
	END_PROFILE(syscall_fcntl_lock);

	return ok;
}

static int vfs_gluster_kernel_flock(struct vfs_handle_struct *handle,
				    files_struct *fsp, uint32_t share_access,
				    uint32_t access_mask)
{
	errno = ENOSYS;
	return -1;
}

static int vfs_gluster_fcntl(vfs_handle_struct *handle,
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
	glfs_fd_t *glfd = NULL;

	START_PROFILE(syscall_fcntl_getlock);

	glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		END_PROFILE(syscall_fcntl_getlock);
		DBG_ERR("Failed to fetch gluster fd\n");
		return false;
	}

	flock.l_type = *ptype;
	flock.l_whence = SEEK_SET;
	flock.l_start = *poffset;
	flock.l_len = *pcount;
	flock.l_pid = 0;

	ret = glfs_posix_lock(glfd, F_GETLK, &flock);

	if (ret == -1) {
		END_PROFILE(syscall_fcntl_getlock);
		return false;
	}

	*ptype = flock.l_type;
	*poffset = flock.l_start;
	*pcount = flock.l_len;
	*ppid = flock.l_pid;
	END_PROFILE(syscall_fcntl_getlock);

	return true;
}

static int vfs_gluster_symlinkat(struct vfs_handle_struct *handle,
				const struct smb_filename *link_target,
				struct files_struct *dirfsp,
				const struct smb_filename *new_smb_fname)
{
	int ret;

	START_PROFILE(syscall_symlinkat);
	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);
	ret = glfs_symlink(handle->data,
			link_target->base_name,
			new_smb_fname->base_name);
	END_PROFILE(syscall_symlinkat);

	return ret;
}

static int vfs_gluster_readlinkat(struct vfs_handle_struct *handle,
				files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				char *buf,
				size_t bufsiz)
{
	int ret;

	START_PROFILE(syscall_readlinkat);
	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);
	ret = glfs_readlink(handle->data, smb_fname->base_name, buf, bufsiz);
	END_PROFILE(syscall_readlinkat);

	return ret;
}

static int vfs_gluster_linkat(struct vfs_handle_struct *handle,
				files_struct *srcfsp,
				const struct smb_filename *old_smb_fname,
				files_struct *dstfsp,
				const struct smb_filename *new_smb_fname,
				int flags)
{
	int ret;

	START_PROFILE(syscall_linkat);

	SMB_ASSERT(srcfsp == srcfsp->conn->cwd_fsp);
	SMB_ASSERT(dstfsp == dstfsp->conn->cwd_fsp);

	ret = glfs_link(handle->data,
			old_smb_fname->base_name,
			new_smb_fname->base_name);
	END_PROFILE(syscall_linkat);

	return ret;
}

static int vfs_gluster_mknodat(struct vfs_handle_struct *handle,
				files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				mode_t mode,
				SMB_DEV_T dev)
{
	int ret;

	START_PROFILE(syscall_mknodat);
	SMB_ASSERT(dirfsp == dirfsp->conn->cwd_fsp);
	ret = glfs_mknod(handle->data, smb_fname->base_name, mode, dev);
	END_PROFILE(syscall_mknodat);

	return ret;
}

static int vfs_gluster_chflags(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}

static int vfs_gluster_get_real_filename(struct vfs_handle_struct *handle,
					 const struct smb_filename *path,
					 const char *name,
					 TALLOC_CTX *mem_ctx,
					 char **found_name)
{
	int ret;
	char key_buf[GLUSTER_NAME_MAX + 64];
	char val_buf[GLUSTER_NAME_MAX + 1];

	if (strlen(name) >= GLUSTER_NAME_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}

	snprintf(key_buf, GLUSTER_NAME_MAX + 64,
		 "glusterfs.get_real_filename:%s", name);

	ret = glfs_getxattr(handle->data, path->base_name, key_buf, val_buf,
			    GLUSTER_NAME_MAX + 1);
	if (ret == -1) {
		if (errno == ENOATTR) {
			errno = ENOENT;
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
				const struct smb_filename *smb_fname)
{
	return handle->conn->connectpath;
}

/* EA Operations */

static ssize_t vfs_gluster_getxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size)
{
	return glfs_getxattr(handle->data, smb_fname->base_name,
			     name, value, size);
}

static ssize_t vfs_gluster_fgetxattr(struct vfs_handle_struct *handle,
				     files_struct *fsp, const char *name,
				     void *value, size_t size)
{
	glfs_fd_t *glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	return glfs_fgetxattr(glfd, name, value, size);
}

static ssize_t vfs_gluster_listxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *list,
				size_t size)
{
	return glfs_listxattr(handle->data, smb_fname->base_name, list, size);
}

static ssize_t vfs_gluster_flistxattr(struct vfs_handle_struct *handle,
				      files_struct *fsp, char *list,
				      size_t size)
{
	glfs_fd_t *glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	return glfs_flistxattr(glfd, list, size);
}

static int vfs_gluster_removexattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name)
{
	return glfs_removexattr(handle->data, smb_fname->base_name, name);
}

static int vfs_gluster_fremovexattr(struct vfs_handle_struct *handle,
				    files_struct *fsp, const char *name)
{
	glfs_fd_t *glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	return glfs_fremovexattr(glfd, name);
}

static int vfs_gluster_setxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				const void *value, size_t size, int flags)
{
	return glfs_setxattr(handle->data, smb_fname->base_name, name, value, size, flags);
}

static int vfs_gluster_fsetxattr(struct vfs_handle_struct *handle,
				 files_struct *fsp, const char *name,
				 const void *value, size_t size, int flags)
{
	glfs_fd_t *glfd = vfs_gluster_fetch_glfd(handle, fsp);
	if (glfd == NULL) {
		DBG_ERR("Failed to fetch gluster fd\n");
		return -1;
	}

	return glfs_fsetxattr(glfd, name, value, size, flags);
}

/* AIO Operations */

static bool vfs_gluster_aio_force(struct vfs_handle_struct *handle,
				  files_struct *fsp)
{
	return false;
}

static NTSTATUS vfs_gluster_create_dfs_pathat(struct vfs_handle_struct *handle,
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

	ret = glfs_symlink(handle->data,
			msdfs_link,
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

static NTSTATUS vfs_gluster_read_dfs_pathat(struct vfs_handle_struct *handle,
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
	struct stat st;
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

	ret = glfs_lstat(handle->data, smb_fname->base_name, &st);
	if (ret < 0) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	referral_len = glfs_readlink(handle->data,
				smb_fname->base_name,
				link_target,
				bufsize - 1);
	if (referral_len < 0) {
		if (errno == EINVAL) {
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

	if (ppreflist == NULL && preferral_count == NULL) {
		/* Early return for checking if this is a DFS link. */
		smb_stat_ex_from_stat(&smb_fname->st, &st);
		return NT_STATUS_OK;
	}

	ok = parse_msdfs_symlink(mem_ctx,
			lp_msdfs_shuffle_referrals(SNUM(handle->conn)),
			link_target,
			ppreflist,
			preferral_count);

	if (ok) {
		smb_stat_ex_from_stat(&smb_fname->st, &st);
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

	.fdopendir_fn = vfs_gluster_fdopendir,
	.readdir_fn = vfs_gluster_readdir,
	.seekdir_fn = vfs_gluster_seekdir,
	.telldir_fn = vfs_gluster_telldir,
	.rewind_dir_fn = vfs_gluster_rewinddir,
	.mkdirat_fn = vfs_gluster_mkdirat,
	.closedir_fn = vfs_gluster_closedir,

	/* File Operations */

	.openat_fn = vfs_gluster_openat,
	.create_file_fn = NULL,
	.close_fn = vfs_gluster_close,
	.pread_fn = vfs_gluster_pread,
	.pread_send_fn = vfs_gluster_pread_send,
	.pread_recv_fn = vfs_gluster_pread_recv,
	.pwrite_fn = vfs_gluster_pwrite,
	.pwrite_send_fn = vfs_gluster_pwrite_send,
	.pwrite_recv_fn = vfs_gluster_pwrite_recv,
	.lseek_fn = vfs_gluster_lseek,
	.sendfile_fn = vfs_gluster_sendfile,
	.recvfile_fn = vfs_gluster_recvfile,
	.renameat_fn = vfs_gluster_renameat,
	.fsync_send_fn = vfs_gluster_fsync_send,
	.fsync_recv_fn = vfs_gluster_fsync_recv,

	.stat_fn = vfs_gluster_stat,
	.fstat_fn = vfs_gluster_fstat,
	.lstat_fn = vfs_gluster_lstat,
	.get_alloc_size_fn = vfs_gluster_get_alloc_size,
	.unlinkat_fn = vfs_gluster_unlinkat,

	.chmod_fn = vfs_gluster_chmod,
	.fchmod_fn = vfs_gluster_fchmod,
	.fchown_fn = vfs_gluster_fchown,
	.lchown_fn = vfs_gluster_lchown,
	.chdir_fn = vfs_gluster_chdir,
	.getwd_fn = vfs_gluster_getwd,
	.ntimes_fn = vfs_gluster_ntimes,
	.ftruncate_fn = vfs_gluster_ftruncate,
	.fallocate_fn = vfs_gluster_fallocate,
	.lock_fn = vfs_gluster_lock,
	.kernel_flock_fn = vfs_gluster_kernel_flock,
	.fcntl_fn = vfs_gluster_fcntl,
	.linux_setlease_fn = vfs_gluster_linux_setlease,
	.getlock_fn = vfs_gluster_getlock,
	.symlinkat_fn = vfs_gluster_symlinkat,
	.readlinkat_fn = vfs_gluster_readlinkat,
	.linkat_fn = vfs_gluster_linkat,
	.mknodat_fn = vfs_gluster_mknodat,
	.realpath_fn = vfs_gluster_realpath,
	.chflags_fn = vfs_gluster_chflags,
	.file_id_create_fn = NULL,
	.streaminfo_fn = NULL,
	.get_real_filename_fn = vfs_gluster_get_real_filename,
	.connectpath_fn = vfs_gluster_connectpath,
	.create_dfs_pathat_fn = vfs_gluster_create_dfs_pathat,
	.read_dfs_pathat_fn = vfs_gluster_read_dfs_pathat,

	.brl_lock_windows_fn = NULL,
	.brl_unlock_windows_fn = NULL,
	.strict_lock_check_fn = NULL,
	.translate_name_fn = NULL,
	.fsctl_fn = NULL,

	/* NT ACL Operations */
	.fget_nt_acl_fn = NULL,
	.get_nt_acl_at_fn = NULL,
	.fset_nt_acl_fn = NULL,
	.audit_file_fn = NULL,

	/* Posix ACL Operations */
	.sys_acl_get_file_fn = posixacl_xattr_acl_get_file,
	.sys_acl_get_fd_fn = posixacl_xattr_acl_get_fd,
	.sys_acl_blob_get_file_fn = posix_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = posix_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = posixacl_xattr_acl_set_file,
	.sys_acl_set_fd_fn = posixacl_xattr_acl_set_fd,
	.sys_acl_delete_def_file_fn = posixacl_xattr_acl_delete_def_file,

	/* EA Operations */
	.getxattr_fn = vfs_gluster_getxattr,
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.fgetxattr_fn = vfs_gluster_fgetxattr,
	.listxattr_fn = vfs_gluster_listxattr,
	.flistxattr_fn = vfs_gluster_flistxattr,
	.removexattr_fn = vfs_gluster_removexattr,
	.fremovexattr_fn = vfs_gluster_fremovexattr,
	.setxattr_fn = vfs_gluster_setxattr,
	.fsetxattr_fn = vfs_gluster_fsetxattr,

	/* AIO Operations */
	.aio_force_fn = vfs_gluster_aio_force,

	/* Durable handle Operations */
	.durable_cookie_fn = NULL,
	.durable_disconnect_fn = NULL,
	.durable_reconnect_fn = NULL,
};

static_decl_vfs;
NTSTATUS vfs_glusterfs_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"glusterfs", &glusterfs_fns);
}
