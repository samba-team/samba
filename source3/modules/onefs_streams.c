/*
 * Unix SMB/CIFS implementation.
 *
 * Support for OneFS Alternate Data Streams
 *
 * Copyright (C) Tim Prouty, 2008
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
#include "onefs.h"
#include "onefs_config.h"

#include <sys/isi_enc.h>

/*
 * OneFS stores streams without the explicit :$DATA at the end, so this strips
 * it off.  All onefs_stream functions must call through this instead of
 * split_ntfs_stream_name directly.
 */
NTSTATUS onefs_split_ntfs_stream_name(TALLOC_CTX *mem_ctx, const char *fname,
				      char **pbase, char **pstream)
{
	NTSTATUS status;
	char *stream;

	status = split_ntfs_stream_name(mem_ctx, fname, pbase, pstream);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Default $DATA stream.  */
	if (pstream == NULL || *pstream == NULL) {
		return NT_STATUS_OK;
	}

	/* Strip off the $DATA. */
	stream = strrchr_m(*pstream, ':');
	SMB_ASSERT(stream);
	stream[0] = '\0';

	return NT_STATUS_OK;
}

int onefs_is_stream(const char *path, char **pbase, char **pstream,
		    bool *is_stream)
{
	(*is_stream) = is_ntfs_stream_name(path);

	if (!(*is_stream)) {
		return 0;
	}

	if (!NT_STATUS_IS_OK(onefs_split_ntfs_stream_name(talloc_tos(), path,
							  pbase, pstream))) {
		DEBUG(10, ("onefs_split_ntfs_stream_name failed\n"));
		errno = ENOMEM;
		return -1;
	}

	return 0;
}

int onefs_close(vfs_handle_struct *handle, struct files_struct *fsp)
{
	int ret2, ret = 0;

	if (fsp->base_fsp) {
		ret = SMB_VFS_NEXT_CLOSE(handle, fsp->base_fsp);
	}
	ret2 = SMB_VFS_NEXT_CLOSE(handle, fsp);

	return ret ? ret : ret2;
}

/*
 * Get the ADS directory fd for a file.
 */
static int get_stream_dir_fd(connection_struct *conn, const char *base,
			     int *base_fdp)
{
	int base_fd;
	int dir_fd;
	int saved_errno;

	/* If a valid base_fdp was given, use it. */
	if (base_fdp && *base_fdp >= 0) {
		base_fd = *base_fdp;
	} else {
		base_fd = onefs_sys_create_file(conn,
						-1,
						base,
						0,
						0,
						0,
						0,
						0,
						0,
						INTERNAL_OPEN_ONLY,
						0,
						NULL,
						0,
						NULL);
		if (base_fd < 0) {
			return -1;
		}
	}

	/* Open the ADS directory. */
	dir_fd = onefs_sys_create_file(conn,
					base_fd,
					".",
					0,
					FILE_READ_DATA,
					0,
					0,
					0,
					0,
					INTERNAL_OPEN_ONLY,
					0,
					NULL,
					0,
					NULL);

	/* Close base_fd if it's not need or on error. */
	if (!base_fdp || dir_fd < 0) {
		saved_errno = errno;
		close(base_fd);
		errno = saved_errno;
	}

	/* Set the out base_fdp if successful and it was requested. */
	if (base_fdp && dir_fd >= 0) {
		*base_fdp = base_fd;
	}

	return dir_fd;
}

int onefs_rename(vfs_handle_struct *handle, const char *oldname,
		 const char *newname)
{
	TALLOC_CTX *frame = NULL;
	int ret = -1;
	int dir_fd = -1;
	int saved_errno;
	bool old_is_stream;
	bool new_is_stream;
	char *obase = NULL;
	char *osname = NULL;
	char *nbase = NULL;
	char *nsname = NULL;

	START_PROFILE(syscall_rename_at);

	frame = talloc_stackframe();

	ret = onefs_is_stream(oldname, &obase, &osname, &old_is_stream);
	if (ret) {
		END_PROFILE(syscall_rename_at);
		return ret;
	}

	ret = onefs_is_stream(newname, &nbase, &nsname, &new_is_stream);
	if (ret) {
		END_PROFILE(syscall_rename_at);
		return ret;
	}

	if (!old_is_stream && !new_is_stream) {
		ret = SMB_VFS_NEXT_RENAME(handle, oldname, newname);
		END_PROFILE(syscall_rename_at);
		return ret;
	}

	dir_fd = get_stream_dir_fd(handle->conn, obase, NULL);
	if (dir_fd < -1) {
		goto done;
	}

	DEBUG(8,("onefs_rename called for %s : %s  => %s : %s\n",
		obase, osname,  nbase, nsname));

	/* Handle rename of stream to default stream specially. */
	if (nsname == NULL) {
		ret = enc_renameat(dir_fd, osname, ENC_DEFAULT, AT_FDCWD,
				   nbase, ENC_DEFAULT);
	} else {
		ret = enc_renameat(dir_fd, osname, ENC_DEFAULT, dir_fd, nsname,
				   ENC_DEFAULT);
	}

 done:
	END_PROFILE(syscall_rename_at);

	saved_errno = errno;
	if (dir_fd >= 0) {
		close(dir_fd);
	}
	errno = saved_errno;
	TALLOC_FREE(frame);
	return ret;
}

/*
 * Merge a base file's sbuf into the a streams's sbuf.
 */
static void merge_stat(SMB_STRUCT_STAT *stream_sbuf,
		       const SMB_STRUCT_STAT *base_sbuf)
{
	int dos_flags = (UF_DOS_NOINDEX | UF_DOS_ARCHIVE |
	    UF_DOS_HIDDEN | UF_DOS_RO | UF_DOS_SYSTEM);
	stream_sbuf->st_mtime = base_sbuf->st_mtime;
	stream_sbuf->st_ctime = base_sbuf->st_ctime;
	stream_sbuf->st_atime = base_sbuf->st_atime;
	stream_sbuf->st_flags &= ~dos_flags;
	stream_sbuf->st_flags |= base_sbuf->st_flags & dos_flags;
}

/* fake timestamps */
static void onefs_adjust_stat_time(vfs_handle_struct *handle, const char *fname,
				   SMB_STRUCT_STAT *sbuf)
{
	struct onefs_vfs_share_config cfg;
	struct timeval tv_now = {0, 0};
	bool static_mtime = False;
	bool static_atime = False;

	if (!onefs_get_config(SNUM(handle->conn),
			      ONEFS_VFS_CONFIG_FAKETIMESTAMPS, &cfg)) {
		return;
	}

	if (IS_MTIME_STATIC_PATH(handle->conn, &cfg, fname)) {
		sbuf->st_mtime = sbuf->st_birthtime;
		static_mtime = True;
	}
	if (IS_ATIME_STATIC_PATH(handle->conn, &cfg, fname)) {
		sbuf->st_atime = sbuf->st_birthtime;
		static_atime = True;
	}

	if (IS_CTIME_NOW_PATH(handle->conn, &cfg, fname)) {
		if (cfg.ctime_slop < 0) {
			sbuf->st_birthtime = INT_MAX - 1;
		} else {
			GetTimeOfDay(&tv_now);
			sbuf->st_birthtime = tv_now.tv_sec + cfg.ctime_slop;
		}
	}

	if (!static_mtime && IS_MTIME_NOW_PATH(handle->conn,&cfg,fname)) {
		if (cfg.mtime_slop < 0) {
			sbuf->st_mtime = INT_MAX - 1;
		} else {
			if (tv_now.tv_sec == 0)
				GetTimeOfDay(&tv_now);
			sbuf->st_mtime = tv_now.tv_sec + cfg.mtime_slop;
		}
	}
	if (!static_atime && IS_ATIME_NOW_PATH(handle->conn,&cfg,fname)) {
		if (cfg.atime_slop < 0) {
			sbuf->st_atime = INT_MAX - 1;
		} else {
			if (tv_now.tv_sec == 0)
				GetTimeOfDay(&tv_now);
			sbuf->st_atime = tv_now.tv_sec + cfg.atime_slop;
		}
	}
}

static int stat_stream(vfs_handle_struct *handle, const char *base,
		       const char *stream, SMB_STRUCT_STAT *sbuf, int flags)
{
	SMB_STRUCT_STAT base_sbuf;
	int base_fd = -1, dir_fd, ret, saved_errno;

	dir_fd = get_stream_dir_fd(handle->conn, base, &base_fd);
	if (dir_fd < 0) {
		return -1;
	}

	/* Stat the stream. */
	ret = enc_fstatat(dir_fd, stream, ENC_DEFAULT, sbuf, flags);
	if (ret != -1) {
		/* Now stat the base file and merge the results. */
		ret = sys_fstat(base_fd, &base_sbuf);
		if (ret != -1) {
			merge_stat(sbuf, &base_sbuf);
		}
	}

	saved_errno = errno;
	close(dir_fd);
	close(base_fd);
	errno = saved_errno;
	return ret;
}

int onefs_stat(vfs_handle_struct *handle, const char *path,
	       SMB_STRUCT_STAT *sbuf)
{
	int ret;
	bool is_stream;
	char *base = NULL;
	char *stream = NULL;

	ret = onefs_is_stream(path, &base, &stream, &is_stream);
	if (ret)
		return ret;

	if (!is_stream) {
		ret = SMB_VFS_NEXT_STAT(handle, path, sbuf);
	} else if (!stream) {
		/* If it's the ::$DATA stream just stat the base file name. */
		ret = SMB_VFS_NEXT_STAT(handle, base, sbuf);
	} else {
		ret = stat_stream(handle, base, stream, sbuf, 0);
	}

	onefs_adjust_stat_time(handle, path, sbuf);
	return ret;
}

int onefs_fstat(vfs_handle_struct *handle, struct files_struct *fsp,
		SMB_STRUCT_STAT *sbuf)
{
	SMB_STRUCT_STAT base_sbuf;
	int ret;

	/* Stat the stream, by calling next_fstat on the stream's fd. */
	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	if (ret == -1) {
		return ret;
	}

	/* Stat the base file and merge the results. */
	if (fsp != NULL && fsp->base_fsp != NULL) {
		ret = sys_fstat(fsp->base_fsp->fh->fd, &base_sbuf);
		if (ret != -1) {
			merge_stat(sbuf, &base_sbuf);
		}
	}

	onefs_adjust_stat_time(handle, fsp->fsp_name, sbuf);
	return ret;
}

int onefs_lstat(vfs_handle_struct *handle, const char *path,
		SMB_STRUCT_STAT *sbuf)
{
	int ret;
	bool is_stream;
	char *base = NULL;
	char *stream = NULL;

	ret = onefs_is_stream(path, &base, &stream, &is_stream);
	if (ret)
		return ret;

	if (!is_stream) {
		ret = SMB_VFS_NEXT_LSTAT(handle, path, sbuf);
	} else if (!stream) {
		/* If it's the ::$DATA stream just stat the base file name. */
		ret = SMB_VFS_NEXT_LSTAT(handle, base, sbuf);
	} else {
		ret = stat_stream(handle, base, stream, sbuf,
				  AT_SYMLINK_NOFOLLOW);
	}

	onefs_adjust_stat_time(handle, path, sbuf);
	return ret;
}

int onefs_unlink(vfs_handle_struct *handle, const char *path)
{
	int ret;
	bool is_stream;
	char *base = NULL;
	char *stream = NULL;
	int dir_fd, saved_errno;

	ret = onefs_is_stream(path, &base, &stream, &is_stream);
	if (ret) {
		return ret;
	}

	if (!is_stream)	{
		return SMB_VFS_NEXT_UNLINK(handle, path);
	}

	/* If it's the ::$DATA stream just unlink the base file name. */
	if (!stream) {
		return SMB_VFS_NEXT_UNLINK(handle, base);
	}

	dir_fd = get_stream_dir_fd(handle->conn, base, NULL);
	if (dir_fd < 0) {
		return -1;
	}

	ret = enc_unlinkat(dir_fd, stream, ENC_DEFAULT, 0);

	saved_errno = errno;
	close(dir_fd);
	errno = saved_errno;
	return ret;
}

int onefs_vtimes_streams(vfs_handle_struct *handle, const char *fname,
			 int flags, struct timespec times[3])
{
	int ret;
	bool is_stream;
	char *base;
	char *stream;
	int dirfd;
	int saved_errno;

	START_PROFILE(syscall_ntimes);

	ret = onefs_is_stream(fname, &base, &stream, &is_stream);
	if (ret)
		return ret;

	if (!is_stream) {
		ret = vtimes(fname, times, flags);
		return ret;
	}

	dirfd = get_stream_dir_fd(handle->conn, base, NULL);
	if (dirfd < -1) {
		return -1;
	}

	ret = enc_vtimesat(dirfd, stream, ENC_DEFAULT, times, flags);

	END_PROFILE(syscall_ntimes);

	saved_errno = errno;
	close(dirfd);
	errno = saved_errno;
	return ret;
}

int onefs_chflags(vfs_handle_struct *handle, const char *path,
		  unsigned int flags)
{
	char *base = NULL;
	char *stream = NULL;

	if (!NT_STATUS_IS_OK(onefs_split_ntfs_stream_name(talloc_tos(), path,
							  &base, &stream))) {
		DEBUG(10, ("onefs_split_ntfs_stream_name failed\n"));
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Only set the attributes on the base file.  ifs_createfile handles
	 * file creation attribute semantics.
	 */
	return SMB_VFS_NEXT_CHFLAGS(handle, base, flags);
}

/*
 * Streaminfo enumeration functionality
 */
struct streaminfo_state {
	TALLOC_CTX *mem_ctx;
	vfs_handle_struct *handle;
	unsigned int num_streams;
	struct stream_struct *streams;
	NTSTATUS status;
};

static bool add_one_stream(TALLOC_CTX *mem_ctx, unsigned int *num_streams,
			   struct stream_struct **streams,
			   const char *name, SMB_OFF_T size,
			   SMB_OFF_T alloc_size)
{
	struct stream_struct *tmp;

	tmp = TALLOC_REALLOC_ARRAY(mem_ctx, *streams, struct stream_struct,
				   (*num_streams)+1);
	if (tmp == NULL) {
		return false;
	}

	tmp[*num_streams].name = talloc_asprintf(mem_ctx, ":%s:%s", name,
						 "$DATA");
	if (tmp[*num_streams].name == NULL) {
		return false;
	}

	tmp[*num_streams].size = size;
	tmp[*num_streams].alloc_size = alloc_size;

	*streams = tmp;
	*num_streams += 1;
	return true;
}

static NTSTATUS walk_onefs_streams(connection_struct *conn, files_struct *fsp,
				   const char *fname,
				   struct streaminfo_state *state,
				   SMB_STRUCT_STAT *base_sbuf)
{
	NTSTATUS status = NT_STATUS_OK;
	bool opened_base_fd = false;
	int base_fd = -1;
	int dir_fd = -1;
	int stream_fd = -1;
	int ret;
	SMB_STRUCT_DIR *dirp = NULL;
	SMB_STRUCT_DIRENT *dp = NULL;
	files_struct fake_fs;
	struct fd_handle fake_fh;
	SMB_STRUCT_STAT stream_sbuf;

	ZERO_STRUCT(fake_fh);
	ZERO_STRUCT(fake_fs);

	/* If the base file is already open, use its fd. */
	if ((fsp != NULL) && (fsp->fh->fd != -1)) {
		base_fd = fsp->fh->fd;
	} else {
		opened_base_fd = true;
	}

	dir_fd = get_stream_dir_fd(conn, fname, &base_fd);
	if (dir_fd < 0) {
		return map_nt_error_from_unix(errno);
	}

	/* Open the ADS directory. */
	if ((dirp = fdopendir(dir_fd)) == NULL) {
		DEBUG(0, ("Error on opendir %s. errno=%d (%s)\n",
			  fname, errno, strerror(errno)));
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	/* Initialize the dir state struct and add it to the list.
	 * This is a layer violation, and really should be handled by a
	 * VFS_FDOPENDIR() call which would properly setup the dir state.
	 * But since this is all within the onefs.so module, we cheat for
	 * now and call directly into the readdirplus code.
	 * NOTE: This state MUST be freed by a proper VFS_CLOSEDIR() call. */
	ret = onefs_rdp_add_dir_state(conn, dirp);
	if (ret) {
		DEBUG(0, ("Error adding dir_state to the list\n"));
		status = map_nt_error_from_unix(errno);
		goto out;
	}

	fake_fs.conn = conn;
	fake_fs.fh = &fake_fh;
	fake_fs.fsp_name = SMB_STRDUP(fname);

	/* Iterate over the streams in the ADS directory. */
	while ((dp = SMB_VFS_READDIR(conn, dirp, NULL)) != NULL) {
		/* Skip the "." and ".." entries */
		if ((strcmp(dp->d_name, ".") == 0) ||
		    (strcmp(dp->d_name, "..") == 0))
			continue;

		/* Open actual stream */
		if ((stream_fd = onefs_sys_create_file(conn,
							 base_fd,
							 dp->d_name,
							 0,
							 0,
							 0,
							 0,
							 0,
							 0,
							 INTERNAL_OPEN_ONLY,
							 0,
							 NULL,
							 0,
							 NULL)) == -1) {
			DEBUG(0, ("Error opening stream %s:%s. "
				  "errno=%d (%s)\n", fname, dp->d_name, errno,
				  strerror(errno)));
			continue;
		}

		/* Figure out the stat info. */
		fake_fh.fd = stream_fd;
		ret = SMB_VFS_FSTAT(&fake_fs, &stream_sbuf);
		close(stream_fd);

		if (ret) {
			DEBUG(0, ("Error fstating stream %s:%s. "
				  "errno=%d (%s)\n", fname, dp->d_name, errno,
				  strerror(errno)));
			continue;
		}

		merge_stat(&stream_sbuf, base_sbuf);

		if (!add_one_stream(state->mem_ctx,
				    &state->num_streams, &state->streams,
				    dp->d_name, stream_sbuf.st_size,
				    SMB_VFS_GET_ALLOC_SIZE(conn, NULL,
							   &stream_sbuf))) {
			state->status = NT_STATUS_NO_MEMORY;
			break;
		}
	}

out:
	/* Cleanup everything that was opened. */
	if (dirp != NULL) {
		SMB_VFS_CLOSEDIR(conn, dirp);
	}
	if (dir_fd >= 0) {
		close(dir_fd);
	}
	if (opened_base_fd) {
		SMB_ASSERT(base_fd >= 0);
		close(base_fd);
	}

	SAFE_FREE(fake_fs.fsp_name);
	return status;
}

NTSTATUS onefs_streaminfo(vfs_handle_struct *handle,
			  struct files_struct *fsp,
			  const char *fname,
			  TALLOC_CTX *mem_ctx,
			  unsigned int *num_streams,
			  struct stream_struct **streams)
{
	SMB_STRUCT_STAT sbuf;
	int ret;
	NTSTATUS status;
	struct streaminfo_state state;

	/* Get a valid stat. */
	if ((fsp != NULL) && (fsp->fh->fd != -1)) {
		if (is_ntfs_stream_name(fsp->fsp_name)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		ret = SMB_VFS_FSTAT(fsp, &sbuf);
	} else {
		if (is_ntfs_stream_name(fname)) {
			return NT_STATUS_INVALID_PARAMETER;
		}
		ret = SMB_VFS_STAT(handle->conn, fname, &sbuf);
	}

	if (ret == -1) {
		return map_nt_error_from_unix(errno);
	}

	state.streams = NULL;
	state.num_streams = 0;

	if (lp_parm_bool(SNUM(handle->conn), PARM_ONEFS_TYPE,
		PARM_IGNORE_STREAMS, PARM_IGNORE_STREAMS_DEFAULT)) {
		goto out;
	}

	/* Add the default stream. */
	if (S_ISREG(sbuf.st_mode)) {
		if (!add_one_stream(mem_ctx,
				    &state.num_streams, &state.streams,
				    "", sbuf.st_size,
				    SMB_VFS_GET_ALLOC_SIZE(handle->conn, fsp,
							   &sbuf))) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	state.mem_ctx = mem_ctx;
	state.handle = handle;
	state.status = NT_STATUS_OK;

	/* If there are more streams, add them too. */
	if (sbuf.st_flags & UF_HASADS) {

		status = walk_onefs_streams(handle->conn, fsp, fname,
		    &state, &sbuf);

		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(state.streams);
			return status;
		}

		if (!NT_STATUS_IS_OK(state.status)) {
			TALLOC_FREE(state.streams);
			return state.status;
		}
	}
 out:
	*num_streams = state.num_streams;
	*streams = state.streams;
	return NT_STATUS_OK;
}
