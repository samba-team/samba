/*
 * shadow_copy2: a shadow copy module (second implementation)
 *
 * Copyright (C) Andrew Tridgell   2007 (portions taken from shadow_copy2)
 * Copyright (C) Ed Plese          2009
 * Copyright (C) Volker Lendecke   2011
 * Copyright (C) Christian Ambach  2011
 * Copyright (C) Michael Adam      2013
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

/*
 * This is a second implemetation of a shadow copy module for exposing
 * file system snapshots to windows clients as shadow copies.
 *
 * See the manual page for documentation.
 */

#include "includes.h"
#include "system/filesys.h"
#include "include/ntioctl.h"
#include <ccan/hash/hash.h>
#include "util_tdb.h"

struct shadow_copy2_config {
	char *gmt_format;
	bool use_sscanf;
	bool use_localtime;
	char *snapdir;
	bool snapdirseverywhere;
	bool crossmountpoints;
	bool fixinodes;
	char *sort_order;
	bool snapdir_absolute;
	char *basedir;
	char *mount_point;
	char *rel_connectpath; /* share root, relative to the basedir */
	char *snapshot_basepath; /* the absolute version of snapdir */
};

static bool shadow_copy2_find_slashes(TALLOC_CTX *mem_ctx, const char *str,
				      size_t **poffsets,
				      unsigned *pnum_offsets)
{
	unsigned num_offsets;
	size_t *offsets;
	const char *p;

	num_offsets = 0;

	p = str;
	while ((p = strchr(p, '/')) != NULL) {
		num_offsets += 1;
		p += 1;
	}

	offsets = talloc_array(mem_ctx, size_t, num_offsets);
	if (offsets == NULL) {
		return false;
	}

	p = str;
	num_offsets = 0;
	while ((p = strchr(p, '/')) != NULL) {
		offsets[num_offsets] = p-str;
		num_offsets += 1;
		p += 1;
	}

	*poffsets = offsets;
	*pnum_offsets = num_offsets;
	return true;
}

/**
 * Given a timestamp, build the posix level GMT-tag string
 * based on the configurable format.
 */
static size_t shadow_copy2_posix_gmt_string(struct vfs_handle_struct *handle,
					    time_t snapshot,
					    char *snaptime_string,
					    size_t len)
{
	struct tm snap_tm;
	size_t snaptime_len;
	struct shadow_copy2_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return 0);

	if (config->use_sscanf) {
		snaptime_len = snprintf(snaptime_string,
					len,
					config->gmt_format,
					(unsigned long)snapshot);
		if (snaptime_len <= 0) {
			DEBUG(10, ("snprintf failed\n"));
			return snaptime_len;
		}
	} else {
		if (config->use_localtime) {
			if (localtime_r(&snapshot, &snap_tm) == 0) {
				DEBUG(10, ("gmtime_r failed\n"));
				return -1;
			}
		} else {
			if (gmtime_r(&snapshot, &snap_tm) == 0) {
				DEBUG(10, ("gmtime_r failed\n"));
				return -1;
			}
		}
		snaptime_len = strftime(snaptime_string,
					len,
					config->gmt_format,
					&snap_tm);
		if (snaptime_len == 0) {
			DEBUG(10, ("strftime failed\n"));
			return 0;
		}
	}

	return snaptime_len;
}

/**
 * Given a timestamp, build the string to insert into a path
 * as a path component for creating the local path to the
 * snapshot at the given timestamp of the input path.
 *
 * In the case of a parallel snapdir (specified with an
 * absolute path), this is the inital portion of the
 * local path of any snapshot file. The complete path is
 * obtained by appending the portion of the file's path
 * below the share root's mountpoint.
 */
static char *shadow_copy2_insert_string(TALLOC_CTX *mem_ctx,
					struct vfs_handle_struct *handle,
					time_t snapshot)
{
	fstring snaptime_string;
	size_t snaptime_len = 0;
	char *result = NULL;
	struct shadow_copy2_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return NULL);

	snaptime_len = shadow_copy2_posix_gmt_string(handle,
						     snapshot,
						     snaptime_string,
						     sizeof(snaptime_string));
	if (snaptime_len <= 0) {
		return NULL;
	}

	if (config->snapdir_absolute) {
		result = talloc_asprintf(mem_ctx, "%s/%s",
					 config->snapdir, snaptime_string);
	} else {
		result = talloc_asprintf(mem_ctx, "/%s/%s",
					 config->snapdir, snaptime_string);
	}
	if (result == NULL) {
		DEBUG(1, (__location__ " talloc_asprintf failed\n"));
	}

	return result;
}

/**
 * Build the posix snapshot path for the connection
 * at the given timestamp, i.e. the absolute posix path
 * that contains the snapshot for this file system.
 *
 * This only applies to classical case, i.e. not
 * to the "snapdirseverywhere" mode.
 */
static char *shadow_copy2_snapshot_path(TALLOC_CTX *mem_ctx,
					struct vfs_handle_struct *handle,
					time_t snapshot)
{
	fstring snaptime_string;
	size_t snaptime_len = 0;
	char *result = NULL;
	struct shadow_copy2_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return NULL);

	snaptime_len = shadow_copy2_posix_gmt_string(handle,
						     snapshot,
						     snaptime_string,
						     sizeof(snaptime_string));
	if (snaptime_len <= 0) {
		return NULL;
	}

	result = talloc_asprintf(mem_ctx, "%s/%s",
				 config->snapshot_basepath, snaptime_string);
	if (result == NULL) {
		DEBUG(1, (__location__ " talloc_asprintf failed\n"));
	}

	return result;
}

/**
 * Strip a snapshot component from a filename as
 * handed in via the smb layer.
 * Returns the parsed timestamp and the stripped filename.
 */
static bool shadow_copy2_strip_snapshot(TALLOC_CTX *mem_ctx,
					struct vfs_handle_struct *handle,
					const char *name,
					time_t *ptimestamp,
					char **pstripped)
{
	struct tm tm;
	time_t timestamp;
	const char *p;
	char *q;
	char *stripped;
	size_t rest_len, dst_len;
	struct shadow_copy2_config *config;
	const char *snapdir;
	ssize_t snapdirlen;
	ptrdiff_t len_before_gmt;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return false);

	DEBUG(10, (__location__ ": enter path '%s'\n", name));

	p = strstr_m(name, "@GMT-");
	if (p == NULL) {
		DEBUG(11, ("@GMT not found\n"));
		goto no_snapshot;
	}
	if ((p > name) && (p[-1] != '/')) {
		/* the GMT-token does not start a path-component */
		DEBUG(10, ("not at start, p=%p, name=%p, p[-1]=%d\n",
			   p, name, (int)p[-1]));
		goto no_snapshot;
	}

	/*
	 * Figure out whether we got an already converted string. One
	 * case where this happens is in a smb2 create call with the
	 * mxac create blob set. We do the get_acl call on
	 * fsp->fsp_name, which is already converted. We are converted
	 * if we got a file name of the form ".snapshots/@GMT-",
	 * i.e. ".snapshots/" precedes "p".
	 */

	snapdir = lp_parm_const_string(SNUM(handle->conn), "shadow", "snapdir",
				       ".snapshots");
	snapdirlen = strlen(snapdir);
	len_before_gmt = p - name;

	if ((len_before_gmt >= (snapdirlen + 1)) && (p[-1] == '/')) {
		const char *parent_snapdir = p - (snapdirlen+1);

		DEBUG(10, ("parent_snapdir = %s\n", parent_snapdir));

		if (strncmp(parent_snapdir, snapdir, snapdirlen) == 0) {
			DEBUG(10, ("name=%s is already converted\n", name));
			goto no_snapshot;
		}
	}
	q = strptime(p, GMT_FORMAT, &tm);
	if (q == NULL) {
		DEBUG(10, ("strptime failed\n"));
		goto no_snapshot;
	}
	tm.tm_isdst = -1;
	timestamp = timegm(&tm);
	if (timestamp == (time_t)-1) {
		DEBUG(10, ("timestamp==-1\n"));
		goto no_snapshot;
	}
	if (q[0] == '\0') {
		/*
		 * The name consists of only the GMT token or the GMT
		 * token is at the end of the path. XP seems to send
		 * @GMT- at the end under certain circumstances even
		 * with a path prefix.
		 */
		if (pstripped != NULL) {
			stripped = talloc_strndup(mem_ctx, name, p - name);
			if (stripped == NULL) {
				return false;
			}
			*pstripped = stripped;
		}
		*ptimestamp = timestamp;
		return true;
	}
	if (q[0] != '/') {
		/*
		 * It is not a complete path component, i.e. the path
		 * component continues after the gmt-token.
		 */
		DEBUG(10, ("q[0] = %d\n", (int)q[0]));
		goto no_snapshot;
	}
	q += 1;

	rest_len = strlen(q);
	dst_len = (p-name) + rest_len;

	if (config->snapdirseverywhere) {
		char *insert;
		bool have_insert;
		insert = shadow_copy2_insert_string(talloc_tos(), handle,
						    timestamp);
		if (insert == NULL) {
			errno = ENOMEM;
			return false;
		}

		DEBUG(10, (__location__ ": snapdirseverywhere mode.\n"
			   "path '%s'.\n"
			   "insert string '%s'\n", name, insert));

		have_insert = (strstr(name, insert+1) != NULL);
		DEBUG(10, ("have_insert=%d, name=%s, insert+1=%s\n",
			   (int)have_insert, name, insert+1));
		if (have_insert) {
			DEBUG(10, (__location__ ": insert string '%s' found in "
				   "path '%s' found in snapdirseverywhere mode "
				   "==> already converted\n", insert, name));
			TALLOC_FREE(insert);
			goto no_snapshot;
		}
		TALLOC_FREE(insert);
	} else {
		char *snapshot_path;
		char *s;

		snapshot_path = shadow_copy2_snapshot_path(talloc_tos(),
							   handle,
							   timestamp);
		if (snapshot_path == NULL) {
			errno = ENOMEM;
			return false;
		}

		DEBUG(10, (__location__ " path: '%s'.\n"
			   "snapshot path: '%s'\n", name, snapshot_path));

		s = strstr(name, snapshot_path);
		if (s == name) {
			/*
			 * this starts with "snapshot_basepath/GMT-Token"
			 * so it is already a converted absolute
			 * path. Don't process further.
			 */
			DEBUG(10, (__location__ ": path '%s' starts with "
				   "snapshot path '%s' (not in "
				   "snapdirseverywhere mode) ==> "
				   "already converted\n", name, snapshot_path));
			talloc_free(snapshot_path);
			goto no_snapshot;
		}
		talloc_free(snapshot_path);
	}

	if (pstripped != NULL) {
		stripped = talloc_array(mem_ctx, char, dst_len+1);
		if (stripped == NULL) {
			errno = ENOMEM;
			return false;
		}
		if (p > name) {
			memcpy(stripped, name, p-name);
		}
		if (rest_len > 0) {
			memcpy(stripped + (p-name), q, rest_len);
		}
		stripped[dst_len] = '\0';
		*pstripped = stripped;
	}
	*ptimestamp = timestamp;
	return true;
no_snapshot:
	*ptimestamp = 0;
	return true;
}

static char *shadow_copy2_find_mount_point(TALLOC_CTX *mem_ctx,
					   vfs_handle_struct *handle)
{
	char *path = talloc_strdup(mem_ctx, handle->conn->connectpath);
	dev_t dev;
	struct stat st;
	char *p;

	if (stat(path, &st) != 0) {
		talloc_free(path);
		return NULL;
	}

	dev = st.st_dev;

	while ((p = strrchr(path, '/')) && p > path) {
		*p = 0;
		if (stat(path, &st) != 0) {
			talloc_free(path);
			return NULL;
		}
		if (st.st_dev != dev) {
			*p = '/';
			break;
		}
	}

	return path;
}

/**
 * Convert from a name as handed in via the SMB layer
 * and a timestamp into the local path of the snapshot
 * of the provided file at the provided time.
 */
static char *shadow_copy2_convert(TALLOC_CTX *mem_ctx,
				  struct vfs_handle_struct *handle,
				  const char *name, time_t timestamp)
{
	struct smb_filename converted_fname;
	char *result = NULL;
	size_t *slashes = NULL;
	unsigned num_slashes;
	char *path = NULL;
	size_t pathlen;
	char *insert = NULL;
	char *converted = NULL;
	size_t insertlen;
	int i, saved_errno;
	size_t min_offset;
	struct shadow_copy2_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return NULL);

	DEBUG(10, ("converting '%s'\n", name));

	if (!config->snapdirseverywhere) {
		int ret;
		char *snapshot_path;

		snapshot_path = shadow_copy2_snapshot_path(talloc_tos(),
							   handle,
							   timestamp);
		if (snapshot_path == NULL) {
			goto fail;
		}

		if (config->rel_connectpath == NULL) {
			converted = talloc_asprintf(mem_ctx, "%s/%s",
						    snapshot_path, name);
		} else {
			converted = talloc_asprintf(mem_ctx, "%s/%s/%s",
						    snapshot_path,
						    config->rel_connectpath,
						    name);
		}
		if (converted == NULL) {
			goto fail;
		}

		ZERO_STRUCT(converted_fname);
		converted_fname.base_name = converted;

		ret = SMB_VFS_NEXT_LSTAT(handle, &converted_fname);
		DEBUG(10, ("Trying[not snapdirseverywhere] %s: %d (%s)\n",
			   converted,
			   ret, ret == 0 ? "ok" : strerror(errno)));
		if (ret == 0) {
			DEBUG(10, ("Found %s\n", converted));
			result = converted;
			converted = NULL;
			goto fail;
		} else {
			errno = ENOENT;
			goto fail;
		}
		/* never reached ... */
	}

	if (name[0] == 0) {
		path = talloc_strdup(mem_ctx, handle->conn->connectpath);
	} else {
		path = talloc_asprintf(
			mem_ctx, "%s/%s", handle->conn->connectpath, name);
	}
	if (path == NULL) {
		errno = ENOMEM;
		goto fail;
	}
	pathlen = talloc_get_size(path)-1;

	if (!shadow_copy2_find_slashes(talloc_tos(), path,
				       &slashes, &num_slashes)) {
		goto fail;
	}

	insert = shadow_copy2_insert_string(talloc_tos(), handle, timestamp);
	if (insert == NULL) {
		goto fail;
	}
	insertlen = talloc_get_size(insert)-1;

	/*
	 * Note: We deliberatly don't expensively initialize the
	 * array with talloc_zero here: Putting zero into
	 * converted[pathlen+insertlen] below is sufficient, because
	 * in the following for loop, the insert string is inserted
	 * at various slash places. So the memory up to position
	 * pathlen+insertlen will always be initialized when the
	 * converted string is used.
	 */
	converted = talloc_array(mem_ctx, char, pathlen + insertlen + 1);
	if (converted == NULL) {
		goto fail;
	}

	if (path[pathlen-1] != '/') {
		/*
		 * Append a fake slash to find the snapshot root
		 */
		size_t *tmp;
		tmp = talloc_realloc(talloc_tos(), slashes,
				     size_t, num_slashes+1);
		if (tmp == NULL) {
			goto fail;
		}
		slashes = tmp;
		slashes[num_slashes] = pathlen;
		num_slashes += 1;
	}

	min_offset = 0;

	if (!config->crossmountpoints) {
		min_offset = strlen(config->mount_point);
	}

	memcpy(converted, path, pathlen+1);
	converted[pathlen+insertlen] = '\0';

	ZERO_STRUCT(converted_fname);
	converted_fname.base_name = converted;

	for (i = num_slashes-1; i>=0; i--) {
		int ret;
		size_t offset;

		offset = slashes[i];

		if (offset < min_offset) {
			errno = ENOENT;
			goto fail;
		}

		memcpy(converted+offset, insert, insertlen);

		offset += insertlen;
		memcpy(converted+offset, path + slashes[i],
		       pathlen - slashes[i]);

		ret = SMB_VFS_NEXT_LSTAT(handle, &converted_fname);

		DEBUG(10, ("Trying[snapdirseverywhere] %s: %d (%s)\n",
			   converted,
			   ret, ret == 0 ? "ok" : strerror(errno)));
		if (ret == 0) {
			/* success */
			break;
		}
		if (errno == ENOTDIR) {
			/*
			 * This is a valid condition: We appended the
			 * .snaphots/@GMT.. to a file name. Just try
			 * with the upper levels.
			 */
			continue;
		}
		if (errno != ENOENT) {
			/* Other problem than "not found" */
			goto fail;
		}
	}

	if (i >= 0) {
		/*
		 * Found something
		 */
		DEBUG(10, ("Found %s\n", converted));
		result = converted;
		converted = NULL;
	} else {
		errno = ENOENT;
	}
fail:
	saved_errno = errno;
	TALLOC_FREE(converted);
	TALLOC_FREE(insert);
	TALLOC_FREE(slashes);
	TALLOC_FREE(path);
	errno = saved_errno;
	return result;
}

/*
  modify a sbuf return to ensure that inodes in the shadow directory
  are different from those in the main directory
 */
static void convert_sbuf(vfs_handle_struct *handle, const char *fname,
			 SMB_STRUCT_STAT *sbuf)
{
	struct shadow_copy2_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return);

	if (config->fixinodes) {
		/* some snapshot systems, like GPFS, return the name
		   device:inode for the snapshot files as the current
		   files. That breaks the 'restore' button in the shadow copy
		   GUI, as the client gets a sharing violation.

		   This is a crude way of allowing both files to be
		   open at once. It has a slight chance of inode
		   number collision, but I can't see a better approach
		   without significant VFS changes
		*/
		uint32_t shash;

		shash = hash(fname, strlen(fname), 0) & 0xFF000000;
		if (shash == 0) {
			shash = 1;
		}
		sbuf->st_ex_ino ^= shash;
	}
}

static DIR *shadow_copy2_opendir(vfs_handle_struct *handle,
					    const char *fname,
					    const char *mask,
					    uint32 attr)
{
	time_t timestamp;
	char *stripped;
	DIR *ret;
	int saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return NULL;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_OPENDIR(handle, fname, mask, attr);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return NULL;
	}
	ret = SMB_VFS_NEXT_OPENDIR(handle, conv, mask, attr);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_rename(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname_src,
			       const struct smb_filename *smb_fname_dst)
{
	time_t timestamp_src, timestamp_dst;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname_src->base_name,
					 &timestamp_src, NULL)) {
		return -1;
	}
	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname_dst->base_name,
					 &timestamp_dst, NULL)) {
		return -1;
	}
	if (timestamp_src != 0) {
		errno = EXDEV;
		return -1;
	}
	if (timestamp_dst != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_RENAME(handle, smb_fname_src, smb_fname_dst);
}

static int shadow_copy2_symlink(vfs_handle_struct *handle,
				const char *oldname, const char *newname)
{
	time_t timestamp_old, timestamp_new;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, oldname,
					 &timestamp_old, NULL)) {
		return -1;
	}
	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, newname,
					 &timestamp_new, NULL)) {
		return -1;
	}
	if ((timestamp_old != 0) || (timestamp_new != 0)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_SYMLINK(handle, oldname, newname);
}

static int shadow_copy2_link(vfs_handle_struct *handle,
			     const char *oldname, const char *newname)
{
	time_t timestamp_old, timestamp_new;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, oldname,
					 &timestamp_old, NULL)) {
		return -1;
	}
	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, newname,
					 &timestamp_new, NULL)) {
		return -1;
	}
	if ((timestamp_old != 0) || (timestamp_new != 0)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_LINK(handle, oldname, newname);
}

static int shadow_copy2_stat(vfs_handle_struct *handle,
			     struct smb_filename *smb_fname)
{
	time_t timestamp;
	char *stripped, *tmp;
	int ret, saved_errno;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname->base_name,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_STAT(handle, smb_fname);
	}

	tmp = smb_fname->base_name;
	smb_fname->base_name = shadow_copy2_convert(
		talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);

	if (smb_fname->base_name == NULL) {
		smb_fname->base_name = tmp;
		return -1;
	}

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	saved_errno = errno;

	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = tmp;

	if (ret == 0) {
		convert_sbuf(handle, smb_fname->base_name, &smb_fname->st);
	}
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_lstat(vfs_handle_struct *handle,
			      struct smb_filename *smb_fname)
{
	time_t timestamp;
	char *stripped, *tmp;
	int ret, saved_errno;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname->base_name,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}

	tmp = smb_fname->base_name;
	smb_fname->base_name = shadow_copy2_convert(
		talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);

	if (smb_fname->base_name == NULL) {
		smb_fname->base_name = tmp;
		return -1;
	}

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	saved_errno = errno;

	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = tmp;

	if (ret == 0) {
		convert_sbuf(handle, smb_fname->base_name, &smb_fname->st);
	}
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_fstat(vfs_handle_struct *handle, files_struct *fsp,
			      SMB_STRUCT_STAT *sbuf)
{
	time_t timestamp;
	int ret;

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	if (ret == -1) {
		return ret;
	}
	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 fsp->fsp_name->base_name,
					 &timestamp, NULL)) {
		return 0;
	}
	if (timestamp != 0) {
		convert_sbuf(handle, fsp->fsp_name->base_name, sbuf);
	}
	return 0;
}

static int shadow_copy2_open(vfs_handle_struct *handle,
			     struct smb_filename *smb_fname, files_struct *fsp,
			     int flags, mode_t mode)
{
	time_t timestamp;
	char *stripped, *tmp;
	int ret, saved_errno;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname->base_name,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	}

	tmp = smb_fname->base_name;
	smb_fname->base_name = shadow_copy2_convert(
		talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);

	if (smb_fname->base_name == NULL) {
		smb_fname->base_name = tmp;
		return -1;
	}

	ret = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	saved_errno = errno;

	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = tmp;

	errno = saved_errno;
	return ret;
}

static int shadow_copy2_unlink(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	struct smb_filename *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname->base_name,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_UNLINK(handle, smb_fname);
	}
	conv = cp_smb_filename(talloc_tos(), smb_fname);
	if (conv == NULL) {
		errno = ENOMEM;
		return -1;
	}
	conv->base_name = shadow_copy2_convert(
		conv, handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv->base_name == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_UNLINK(handle, conv);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_chmod(vfs_handle_struct *handle, const char *fname,
			      mode_t mode)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHMOD(handle, fname, mode);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHMOD(handle, conv, mode);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_chown(vfs_handle_struct *handle, const char *fname,
			      uid_t uid, gid_t gid)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHOWN(handle, fname, uid, gid);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHOWN(handle, conv, uid, gid);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_chdir(vfs_handle_struct *handle,
			      const char *fname)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHDIR(handle, fname);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHDIR(handle, conv);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_ntimes(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname,
			       struct smb_file_time *ft)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	struct smb_filename *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname->base_name,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
	}
	conv = cp_smb_filename(talloc_tos(), smb_fname);
	if (conv == NULL) {
		errno = ENOMEM;
		return -1;
	}
	conv->base_name = shadow_copy2_convert(
		conv, handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv->base_name == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_NTIMES(handle, conv, ft);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_readlink(vfs_handle_struct *handle,
				 const char *fname, char *buf, size_t bufsiz)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_READLINK(handle, fname, buf, bufsiz);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_READLINK(handle, conv, buf, bufsiz);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_mknod(vfs_handle_struct *handle,
			      const char *fname, mode_t mode, SMB_DEV_T dev)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_MKNOD(handle, fname, mode, dev);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_MKNOD(handle, conv, mode, dev);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static char *shadow_copy2_realpath(vfs_handle_struct *handle,
				   const char *fname)
{
	time_t timestamp;
	char *stripped = NULL;
	char *tmp = NULL;
	char *result = NULL;
	char *inserted = NULL;
	char *inserted_to, *inserted_end;
	int saved_errno;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		goto done;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_REALPATH(handle, fname);
	}

	tmp = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	if (tmp == NULL) {
		goto done;
	}

	result = SMB_VFS_NEXT_REALPATH(handle, tmp);
	if (result == NULL) {
		goto done;
	}

	/*
	 * Take away what we've inserted. This removes the @GMT-thingy
	 * completely, but will give a path under the share root.
	 */
	inserted = shadow_copy2_insert_string(talloc_tos(), handle, timestamp);
	if (inserted == NULL) {
		goto done;
	}
	inserted_to = strstr_m(result, inserted);
	if (inserted_to == NULL) {
		DEBUG(2, ("SMB_VFS_NEXT_REALPATH removed %s\n", inserted));
		goto done;
	}
	inserted_end = inserted_to + talloc_get_size(inserted) - 1;
	memmove(inserted_to, inserted_end, strlen(inserted_end)+1);

done:
	saved_errno = errno;
	TALLOC_FREE(inserted);
	TALLOC_FREE(tmp);
	TALLOC_FREE(stripped);
	errno = saved_errno;
	return result;
}

/**
 * Check whether a given directory contains a
 * snapshot directory as direct subdirectory.
 * If yes, return the path of the snapshot-subdir,
 * otherwise return NULL.
 */
static char *have_snapdir(struct vfs_handle_struct *handle,
			  const char *path)
{
	struct smb_filename smb_fname;
	int ret;
	struct shadow_copy2_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return NULL);

	ZERO_STRUCT(smb_fname);
	smb_fname.base_name = talloc_asprintf(talloc_tos(), "%s/%s",
					      path, config->snapdir);
	if (smb_fname.base_name == NULL) {
		return NULL;
	}

	ret = SMB_VFS_NEXT_STAT(handle, &smb_fname);
	if ((ret == 0) && (S_ISDIR(smb_fname.st.st_ex_mode))) {
		return smb_fname.base_name;
	}
	TALLOC_FREE(smb_fname.base_name);
	return NULL;
}

/**
 * Find the snapshot directory (if any) for the given
 * filename (which is relative to the share).
 */
static const char *shadow_copy2_find_snapdir(TALLOC_CTX *mem_ctx,
					     struct vfs_handle_struct *handle,
					     struct smb_filename *smb_fname)
{
	char *path, *p;
	const char *snapdir;
	struct shadow_copy2_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return NULL);

	/*
	 * If the non-snapdisrseverywhere mode, we should not search!
	 */
	if (!config->snapdirseverywhere) {
		return config->snapshot_basepath;
	}

	path = talloc_asprintf(mem_ctx, "%s/%s",
			       handle->conn->connectpath,
			       smb_fname->base_name);
	if (path == NULL) {
		return NULL;
	}

	snapdir = have_snapdir(handle, path);
	if (snapdir != NULL) {
		TALLOC_FREE(path);
		return snapdir;
	}

	while ((p = strrchr(path, '/')) && (p > path)) {

		p[0] = '\0';

		snapdir = have_snapdir(handle, path);
		if (snapdir != NULL) {
			TALLOC_FREE(path);
			return snapdir;
		}
	}
	TALLOC_FREE(path);
	return NULL;
}

static bool shadow_copy2_snapshot_to_gmt(vfs_handle_struct *handle,
					 const char *name,
					 char *gmt, size_t gmt_len)
{
	struct tm timestamp;
	time_t timestamp_t;
	unsigned long int timestamp_long;
	const char *fmt;
	struct shadow_copy2_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return NULL);

	fmt = config->gmt_format;

	ZERO_STRUCT(timestamp);
	if (config->use_sscanf) {
		if (sscanf(name, fmt, &timestamp_long) != 1) {
			DEBUG(10, ("shadow_copy2_snapshot_to_gmt: "
				   "no sscanf match %s: %s\n",
				   fmt, name));
			return false;
		}
		timestamp_t = timestamp_long;
		gmtime_r(&timestamp_t, &timestamp);
	} else {
		if (strptime(name, fmt, &timestamp) == NULL) {
			DEBUG(10, ("shadow_copy2_snapshot_to_gmt: "
				   "no match %s: %s\n",
				   fmt, name));
			return false;
		}
		DEBUG(10, ("shadow_copy2_snapshot_to_gmt: match %s: %s\n",
			   fmt, name));
		
		if (config->use_localtime) {
			timestamp.tm_isdst = -1;
			timestamp_t = mktime(&timestamp);
			gmtime_r(&timestamp_t, &timestamp);
		}
	}

	strftime(gmt, gmt_len, GMT_FORMAT, &timestamp);
	return true;
}

static int shadow_copy2_label_cmp_asc(const void *x, const void *y)
{
	return strncmp((const char *)x, (const char *)y, sizeof(SHADOW_COPY_LABEL));
}

static int shadow_copy2_label_cmp_desc(const void *x, const void *y)
{
	return -strncmp((const char *)x, (const char *)y, sizeof(SHADOW_COPY_LABEL));
}

/*
  sort the shadow copy data in ascending or descending order
 */
static void shadow_copy2_sort_data(vfs_handle_struct *handle,
				   struct shadow_copy_data *shadow_copy2_data)
{
	int (*cmpfunc)(const void *, const void *);
	const char *sort;
	struct shadow_copy2_config *config;

	SMB_VFS_HANDLE_GET_DATA(handle, config, struct shadow_copy2_config,
				return);

	sort = config->sort_order;
	if (sort == NULL) {
		return;
	}

	if (strcmp(sort, "asc") == 0) {
		cmpfunc = shadow_copy2_label_cmp_asc;
	} else if (strcmp(sort, "desc") == 0) {
		cmpfunc = shadow_copy2_label_cmp_desc;
	} else {
		return;
	}

	if (shadow_copy2_data && shadow_copy2_data->num_volumes > 0 &&
	    shadow_copy2_data->labels)
	{
		TYPESAFE_QSORT(shadow_copy2_data->labels,
			       shadow_copy2_data->num_volumes,
			       cmpfunc);
	}
}

static int shadow_copy2_get_shadow_copy_data(
	vfs_handle_struct *handle, files_struct *fsp,
	struct shadow_copy_data *shadow_copy2_data,
	bool labels)
{
	DIR *p;
	const char *snapdir;
	struct dirent *d;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();

	snapdir = shadow_copy2_find_snapdir(tmp_ctx, handle, fsp->fsp_name);
	if (snapdir == NULL) {
		DEBUG(0,("shadow:snapdir not found for %s in get_shadow_copy_data\n",
			 handle->conn->connectpath));
		errno = EINVAL;
		talloc_free(tmp_ctx);
		return -1;
	}

	p = SMB_VFS_NEXT_OPENDIR(handle, snapdir, NULL, 0);

	if (!p) {
		DEBUG(2,("shadow_copy2: SMB_VFS_NEXT_OPENDIR() failed for '%s'"
			 " - %s\n", snapdir, strerror(errno)));
		talloc_free(tmp_ctx);
		errno = ENOSYS;
		return -1;
	}

	shadow_copy2_data->num_volumes = 0;
	shadow_copy2_data->labels      = NULL;

	while ((d = SMB_VFS_NEXT_READDIR(handle, p, NULL))) {
		char snapshot[GMT_NAME_LEN+1];
		SHADOW_COPY_LABEL *tlabels;

		/*
		 * ignore names not of the right form in the snapshot
		 * directory
		 */
		if (!shadow_copy2_snapshot_to_gmt(
			    handle, d->d_name,
			    snapshot, sizeof(snapshot))) {

			DEBUG(6, ("shadow_copy2_get_shadow_copy_data: "
				  "ignoring %s\n", d->d_name));
			continue;
		}
		DEBUG(6,("shadow_copy2_get_shadow_copy_data: %s -> %s\n",
			 d->d_name, snapshot));

		if (!labels) {
			/* the caller doesn't want the labels */
			shadow_copy2_data->num_volumes++;
			continue;
		}

		tlabels = talloc_realloc(shadow_copy2_data,
					 shadow_copy2_data->labels,
					 SHADOW_COPY_LABEL,
					 shadow_copy2_data->num_volumes+1);
		if (tlabels == NULL) {
			DEBUG(0,("shadow_copy2: out of memory\n"));
			SMB_VFS_NEXT_CLOSEDIR(handle, p);
			talloc_free(tmp_ctx);
			return -1;
		}

		strlcpy(tlabels[shadow_copy2_data->num_volumes], snapshot,
			sizeof(*tlabels));

		shadow_copy2_data->num_volumes++;
		shadow_copy2_data->labels = tlabels;
	}

	SMB_VFS_NEXT_CLOSEDIR(handle,p);

	shadow_copy2_sort_data(handle, shadow_copy2_data);

	talloc_free(tmp_ctx);
	return 0;
}

static NTSTATUS shadow_copy2_fget_nt_acl(vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32 security_info,
					 TALLOC_CTX *mem_ctx,
					struct security_descriptor **ppdesc)
{
	time_t timestamp;
	char *stripped;
	NTSTATUS status;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 fsp->fsp_name->base_name,
					 &timestamp, &stripped)) {
		return map_nt_error_from_unix(errno);
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
						mem_ctx,
						ppdesc);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return map_nt_error_from_unix(errno);
	}
	status = SMB_VFS_NEXT_GET_NT_ACL(handle, conv, security_info,
					 mem_ctx, ppdesc);
	TALLOC_FREE(conv);
	return status;
}

static NTSTATUS shadow_copy2_get_nt_acl(vfs_handle_struct *handle,
					const char *fname,
					uint32 security_info,
					TALLOC_CTX *mem_ctx,
					struct security_descriptor **ppdesc)
{
	time_t timestamp;
	char *stripped;
	NTSTATUS status;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return map_nt_error_from_unix(errno);
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GET_NT_ACL(handle, fname, security_info,
					       mem_ctx, ppdesc);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return map_nt_error_from_unix(errno);
	}
	status = SMB_VFS_NEXT_GET_NT_ACL(handle, conv, security_info,
					 mem_ctx, ppdesc);
	TALLOC_FREE(conv);
	return status;
}

static int shadow_copy2_mkdir(vfs_handle_struct *handle,
			      const char *fname, mode_t mode)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_MKDIR(handle, fname, mode);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_MKDIR(handle, conv, mode);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_rmdir(vfs_handle_struct *handle, const char *fname)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_RMDIR(handle, fname);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_RMDIR(handle, conv);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_chflags(vfs_handle_struct *handle, const char *fname,
				unsigned int flags)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHFLAGS(handle, fname, flags);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHFLAGS(handle, conv, flags);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static ssize_t shadow_copy2_getxattr(vfs_handle_struct *handle,
				     const char *fname, const char *aname,
				     void *value, size_t size)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GETXATTR(handle, fname, aname, value,
					     size);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_GETXATTR(handle, conv, aname, value, size);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static ssize_t shadow_copy2_listxattr(struct vfs_handle_struct *handle,
				      const char *fname,
				      char *list, size_t size)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_LISTXATTR(handle, fname, list, size);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_LISTXATTR(handle, conv, list, size);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_removexattr(vfs_handle_struct *handle,
				    const char *fname, const char *aname)
{
	time_t timestamp;
	char *stripped;
	int ret, saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_REMOVEXATTR(handle, fname, aname);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_REMOVEXATTR(handle, conv, aname);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_setxattr(struct vfs_handle_struct *handle,
				 const char *fname,
				 const char *aname, const void *value,
				 size_t size, int flags)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_SETXATTR(handle, fname, aname, value, size,
					     flags);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_SETXATTR(handle, conv, aname, value, size, flags);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_chmod_acl(vfs_handle_struct *handle,
				  const char *fname, mode_t mode)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHMOD_ACL(handle, fname, mode);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHMOD_ACL(handle, conv, mode);
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static int shadow_copy2_get_real_filename(struct vfs_handle_struct *handle,
					  const char *path,
					  const char *name,
					  TALLOC_CTX *mem_ctx,
					  char **found_name)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	DEBUG(10, ("shadow_copy2_get_real_filename called for path=[%s], "
		   "name=[%s]\n", path, name));

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, path,
					 &timestamp, &stripped)) {
		DEBUG(10, ("shadow_copy2_strip_snapshot failed\n"));
		return -1;
	}
	if (timestamp == 0) {
		DEBUG(10, ("timestamp == 0\n"));
		return SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name,
						      mem_ctx, found_name);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		DEBUG(10, ("shadow_copy2_convert failed\n"));
		return -1;
	}
	DEBUG(10, ("Calling NEXT_GET_REAL_FILE_NAME for conv=[%s], "
		   "name=[%s]\n", conv, name));
	ret = SMB_VFS_NEXT_GET_REAL_FILENAME(handle, conv, name,
					     mem_ctx, found_name);
	DEBUG(10, ("NEXT_REAL_FILE_NAME returned %d\n", (int)ret));
	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;
	return ret;
}

static uint64_t shadow_copy2_disk_free(vfs_handle_struct *handle,
				       const char *path, bool small_query,
				       uint64_t *bsize, uint64_t *dfree,
				       uint64_t *dsize)
{
	time_t timestamp;
	char *stripped;
	ssize_t ret;
	int saved_errno;
	char *conv;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, path,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_DISK_FREE(handle, path, small_query,
					      bsize, dfree, dsize);
	}

	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}

	ret = SMB_VFS_NEXT_DISK_FREE(handle, conv, small_query, bsize, dfree,
				     dsize);

	saved_errno = errno;
	TALLOC_FREE(conv);
	errno = saved_errno;

	return ret;
}

static int shadow_copy2_connect(struct vfs_handle_struct *handle,
				const char *service, const char *user)
{
	struct shadow_copy2_config *config;
	int ret;
	const char *snapdir;
	const char *gmt_format;
	const char *sort_order;
	const char *basedir;
	const char *mount_point;

	DEBUG(10, (__location__ ": cnum[%u], connectpath[%s]\n",
		   (unsigned)handle->conn->cnum,
		   handle->conn->connectpath));

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	config = talloc_zero(handle->conn, struct shadow_copy2_config);
	if (config == NULL) {
		DEBUG(0, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	gmt_format = lp_parm_const_string(SNUM(handle->conn),
					  "shadow", "format",
					  GMT_FORMAT);
	config->gmt_format = talloc_strdup(config, gmt_format);
	if (config->gmt_format == NULL) {
		DEBUG(0, ("talloc_strdup() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	config->use_sscanf = lp_parm_bool(SNUM(handle->conn),
					  "shadow", "sscanf", false);

	config->use_localtime = lp_parm_bool(SNUM(handle->conn),
					     "shadow", "localtime",
					     false);

	snapdir = lp_parm_const_string(SNUM(handle->conn),
				       "shadow", "snapdir",
				       ".snapshots");
	config->snapdir = talloc_strdup(config, snapdir);
	if (config->snapdir == NULL) {
		DEBUG(0, ("talloc_strdup() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	config->snapdirseverywhere = lp_parm_bool(SNUM(handle->conn),
						  "shadow",
						  "snapdirseverywhere",
						  false);

	config->crossmountpoints = lp_parm_bool(SNUM(handle->conn),
						"shadow", "crossmountpoints",
						false);

	config->fixinodes = lp_parm_bool(SNUM(handle->conn),
					 "shadow", "fixinodes",
					 false);

	sort_order = lp_parm_const_string(SNUM(handle->conn),
					  "shadow", "sort", "desc");
	config->sort_order = talloc_strdup(config, sort_order);
	if (config->sort_order == NULL) {
		DEBUG(0, ("talloc_strdup() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	mount_point = lp_parm_const_string(SNUM(handle->conn),
					   "shadow", "mountpoint", NULL);
	if (mount_point != NULL) {
		if (mount_point[0] != '/') {
			DEBUG(1, (__location__ " Warning: 'mountpoint' is "
				  "relative ('%s'), but it has to be an "
				  "absolute path. Ignoring provided value.\n",
				  mount_point));
			mount_point = NULL;
		} else {
			char *p;
			p = strstr(handle->conn->connectpath, mount_point);
			if (p != handle->conn->connectpath) {
				DEBUG(1, ("Warning: mount_point (%s) is not a "
					  "subdirectory of the share root "
					  "(%s). Ignoring provided value.\n",
					  mount_point,
					  handle->conn->connectpath));
				mount_point = NULL;
			}
		}
	}

	if (mount_point != NULL) {
		config->mount_point = talloc_strdup(config, mount_point);
		if (config->mount_point == NULL) {
			DEBUG(0, (__location__ " talloc_strdup() failed\n"));
			return -1;
		}
	} else {
		config->mount_point = shadow_copy2_find_mount_point(config,
								    handle);
		if (config->mount_point == NULL) {
			DEBUG(0, (__location__ ": shadow_copy2_find_mount_point"
				  " failed: %s\n", strerror(errno)));
			return -1;
		}
	}

	basedir = lp_parm_const_string(SNUM(handle->conn),
				       "shadow", "basedir", NULL);

	if (basedir != NULL) {
		if (basedir[0] != '/') {
			DEBUG(1, (__location__ " Warning: 'basedir' is "
				  "relative ('%s'), but it has to be an "
				  "absolute path. Disabling basedir.\n",
				  basedir));
		} else {
			char *p;
			p = strstr(basedir, config->mount_point);
			if (p != basedir) {
				DEBUG(1, ("Warning: basedir (%s) is not a "
					  "subdirectory of the share root's "
					  "mount point (%s). "
					  "Disabling basedir\n",
					  basedir, config->mount_point));
			} else {
				config->basedir = talloc_strdup(config,
								basedir);
				if (config->basedir == NULL) {
					DEBUG(0, ("talloc_strdup() failed\n"));
					errno = ENOMEM;
					return -1;
				}
			}
		}
	}

	if (config->snapdirseverywhere && config->basedir != NULL) {
		DEBUG(1, (__location__ " Warning: 'basedir' is incompatible "
			  "with 'snapdirseverywhere'. Disabling basedir.\n"));
		TALLOC_FREE(config->basedir);
	}

	if (config->crossmountpoints && config->basedir != NULL) {
		DEBUG(1, (__location__ " Warning: 'basedir' is incompatible "
			  "with 'crossmountpoints'. Disabling basedir.\n"));
		TALLOC_FREE(config->basedir);
	}

	if (config->basedir == NULL) {
		config->basedir = config->mount_point;
	}

	if (strlen(config->basedir) != strlen(handle->conn->connectpath)) {
		config->rel_connectpath = talloc_strdup(config,
			handle->conn->connectpath + strlen(config->basedir));
		if (config->rel_connectpath == NULL) {
			DEBUG(0, ("talloc_strdup() failed\n"));
			errno = ENOMEM;
			return -1;
		}
	}

	if (config->snapdir[0] == '/') {
		config->snapdir_absolute = true;

		if (config->snapdirseverywhere == true) {
			DEBUG(1, (__location__ " Warning: An absolute snapdir "
				  "is incompatible with 'snapdirseverywhere', "
				  "setting 'snapdirseverywhere' to false.\n"));
			config->snapdirseverywhere = false;
		}

		if (config->crossmountpoints == true) {
			DEBUG(1, (__location__ " Warning: 'crossmountpoints' "
				  "is not supported with an absolute snapdir. "
				  "Disabling it.\n"));
			config->crossmountpoints = false;
		}

		config->snapshot_basepath = config->snapdir;
	} else {
		config->snapshot_basepath = talloc_asprintf(config, "%s/%s",
				config->mount_point, config->snapdir);
		if (config->snapshot_basepath == NULL) {
			DEBUG(0, ("talloc_asprintf() failed\n"));
			errno = ENOMEM;
			return -1;
		}
	}

	DEBUG(10, ("shadow_copy2_connect: configuration:\n"
		   "  share root: '%s'\n"
		   "  basedir: '%s'\n"
		   "  mountpoint: '%s'\n"
		   "  rel share root: '%s'\n"
		   "  snapdir: '%s'\n"
		   "  snapshot base path: '%s'\n"
		   "  format: '%s'\n"
		   "  use sscanf: %s\n"
		   "  snapdirs everywhere: %s\n"
		   "  cross mountpoints: %s\n"
		   "  fix inodes: %s\n"
		   "  sort order: %s\n"
		   "",
		   handle->conn->connectpath,
		   config->basedir,
		   config->mount_point,
		   config->rel_connectpath,
		   config->snapdir,
		   config->snapshot_basepath,
		   config->gmt_format,
		   config->use_sscanf ? "yes" : "no",
		   config->snapdirseverywhere ? "yes" : "no",
		   config->crossmountpoints ? "yes" : "no",
		   config->fixinodes ? "yes" : "no",
		   config->sort_order
		   ));


	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct shadow_copy2_config,
				return -1);

	return 0;
}

static struct vfs_fn_pointers vfs_shadow_copy2_fns = {
	.connect_fn = shadow_copy2_connect,
	.opendir_fn = shadow_copy2_opendir,
	.disk_free_fn = shadow_copy2_disk_free,
	.rename_fn = shadow_copy2_rename,
	.link_fn = shadow_copy2_link,
	.symlink_fn = shadow_copy2_symlink,
	.stat_fn = shadow_copy2_stat,
	.lstat_fn = shadow_copy2_lstat,
	.fstat_fn = shadow_copy2_fstat,
	.open_fn = shadow_copy2_open,
	.unlink_fn = shadow_copy2_unlink,
	.chmod_fn = shadow_copy2_chmod,
	.chown_fn = shadow_copy2_chown,
	.chdir_fn = shadow_copy2_chdir,
	.ntimes_fn = shadow_copy2_ntimes,
	.readlink_fn = shadow_copy2_readlink,
	.mknod_fn = shadow_copy2_mknod,
	.realpath_fn = shadow_copy2_realpath,
	.get_nt_acl_fn = shadow_copy2_get_nt_acl,
	.fget_nt_acl_fn = shadow_copy2_fget_nt_acl,
	.get_shadow_copy_data_fn = shadow_copy2_get_shadow_copy_data,
	.mkdir_fn = shadow_copy2_mkdir,
	.rmdir_fn = shadow_copy2_rmdir,
	.getxattr_fn = shadow_copy2_getxattr,
	.listxattr_fn = shadow_copy2_listxattr,
	.removexattr_fn = shadow_copy2_removexattr,
	.setxattr_fn = shadow_copy2_setxattr,
	.chmod_acl_fn = shadow_copy2_chmod_acl,
	.chflags_fn = shadow_copy2_chflags,
	.get_real_filename_fn = shadow_copy2_get_real_filename,
};

NTSTATUS vfs_shadow_copy2_init(void);
NTSTATUS vfs_shadow_copy2_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"shadow_copy2", &vfs_shadow_copy2_fns);
}
