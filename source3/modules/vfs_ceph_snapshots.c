/*
 * Module for accessing CephFS snapshots as Previous Versions. This module is
 * separate to vfs_ceph, so that it can also be used atop a CephFS kernel backed
 * share with vfs_default.
 *
 * Copyright (C) David Disseldorp 2019
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

#include <dirent.h>
#include <libgen.h>
#include "includes.h"
#include "include/ntioctl.h"
#include "include/smb.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "lib/util/tevent_ntstatus.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

/*
 * CephFS has a magic snapshots subdirectory in all parts of the directory tree.
 * This module automatically makes all snapshots in this subdir visible to SMB
 * clients (if permitted by corresponding access control).
 */
#define CEPH_SNAP_SUBDIR_DEFAULT ".snap"
/*
 * The ceph.snap.btime (virtual) extended attribute carries the snapshot
 * creation time in $secs.$nsecs format. It was added as part of
 * https://tracker.ceph.com/issues/38838. Running Samba atop old Ceph versions
 * which don't provide this xattr will not be able to enumerate or access
 * snapshots using this module. As an alternative, vfs_shadow_copy2 could be
 * used instead, alongside special shadow:format snapshot directory names.
 */
#define CEPH_SNAP_BTIME_XATTR "ceph.snap.btime"

static int ceph_snap_get_btime(struct vfs_handle_struct *handle,
			       struct smb_filename *smb_fname,
			       time_t *_snap_secs)
{
	int ret;
	char snap_btime[33];
	char *s = NULL;
	char *endptr = NULL;
	struct timespec snap_timespec;
	int err;

	ret = SMB_VFS_NEXT_GETXATTR(handle, smb_fname, CEPH_SNAP_BTIME_XATTR,
				    snap_btime, sizeof(snap_btime));
	if (ret < 0) {
		DBG_ERR("failed to get %s xattr: %s\n",
			CEPH_SNAP_BTIME_XATTR, strerror(errno));
		return -errno;
	}

	if (ret == 0 || ret >= sizeof(snap_btime) - 1) {
		return -EINVAL;
	}

	/* ensure zero termination */
	snap_btime[ret] = '\0';

	/* format is sec.nsec */
	s = strchr(snap_btime, '.');
	if (s == NULL) {
		DBG_ERR("invalid %s xattr value: %s\n",
			CEPH_SNAP_BTIME_XATTR, snap_btime);
		return -EINVAL;
	}

	/* First component is seconds, extract it */
	*s = '\0';
	snap_timespec.tv_sec = smb_strtoull(snap_btime,
					    &endptr,
					    10,
					    &err,
					    SMB_STR_FULL_STR_CONV);
	if (err != 0) {
		return -err;
	}

	/* second component is nsecs */
	s++;
	snap_timespec.tv_nsec = smb_strtoul(s,
					    &endptr,
					    10,
					    &err,
					    SMB_STR_FULL_STR_CONV);
	if (err != 0) {
		return -err;
	}

	/*
	 * >> 30 is a rough divide by ~10**9. No need to be exact, as @GMT
	 * tokens only offer 1-second resolution (while twrp is nsec).
	 */
	*_snap_secs = snap_timespec.tv_sec + (snap_timespec.tv_nsec >> 30);

	return 0;
}

/*
 * XXX Ceph snapshots can be created with sub-second granularity, which means
 * that multiple snapshots may be mapped to the same @GMT- label.
 *
 * @this_label is a pre-zeroed buffer to be filled with a @GMT label
 * @return 0 if label successfully filled or -errno on error.
 */
static int ceph_snap_fill_label(struct vfs_handle_struct *handle,
				TALLOC_CTX *tmp_ctx,
				const char *parent_snapsdir,
				const char *subdir,
				SHADOW_COPY_LABEL this_label)
{
	struct smb_filename *smb_fname;
	time_t snap_secs;
	struct tm gmt_snap_time;
	struct tm *tm_ret;
	size_t str_sz;
	char snap_path[PATH_MAX + 1];
	int ret;

	/*
	 * CephFS snapshot creation times are available via a special
	 * xattr - snapshot b/m/ctimes all match the snap source.
	 */
	ret = snprintf(snap_path, sizeof(snap_path), "%s/%s",
			parent_snapsdir, subdir);
	if (ret >= sizeof(snap_path)) {
		return -EINVAL;
	}

	smb_fname = synthetic_smb_fname(tmp_ctx,
					snap_path,
					NULL,
					NULL,
					0,
					0);
	if (smb_fname == NULL) {
		return -ENOMEM;
	}

	ret = ceph_snap_get_btime(handle, smb_fname, &snap_secs);
	if (ret < 0) {
		return ret;
	}

	tm_ret = gmtime_r(&snap_secs, &gmt_snap_time);
	if (tm_ret == NULL) {
		return -EINVAL;
	}
	str_sz = strftime(this_label, sizeof(SHADOW_COPY_LABEL),
			  "@GMT-%Y.%m.%d-%H.%M.%S", &gmt_snap_time);
	if (str_sz == 0) {
		DBG_ERR("failed to convert tm to @GMT token\n");
		return -EINVAL;
	}

	DBG_DEBUG("mapped snapshot at %s to enum snaps label %s\n",
		  snap_path, this_label);

	return 0;
}

static int ceph_snap_enum_snapdir(struct vfs_handle_struct *handle,
				  struct smb_filename *snaps_dname,
				  bool labels,
				  struct shadow_copy_data *sc_data)
{
	TALLOC_CTX *frame = talloc_stackframe();
	struct smb_Dir *dir_hnd = NULL;
	const char *dname = NULL;
	char *talloced = NULL;
	long offset = 0;
	NTSTATUS status;
	int ret;
	uint32_t slots;

	status = smbd_check_access_rights(handle->conn,
					handle->conn->cwd_fsp,
					snaps_dname,
					false,
					SEC_DIR_LIST);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("user does not have list permission "
			"on snapdir %s\n",
			snaps_dname->base_name));
		ret = -map_errno_from_nt_status(status);
		goto err_out;
	}

	DBG_DEBUG("enumerating shadow copy dir at %s\n",
		  snaps_dname->base_name);

	/*
	 * CephFS stat(dir).size *normally* returns the number of child entries
	 * for a given dir, but it unfortunately that's not the case for the one
	 * place we need it (dir=.snap), so we need to dynamically determine it
	 * via readdir.
	 */

	dir_hnd = OpenDir(frame, handle->conn, snaps_dname, NULL, 0);
	if (dir_hnd == NULL) {
		ret = -errno;
		goto err_out;
	}

	slots = 0;
	sc_data->num_volumes = 0;
	sc_data->labels = NULL;

        while ((dname = ReadDirName(dir_hnd, &offset, NULL, &talloced))
	       != NULL)
	{
		if (ISDOT(dname) || ISDOTDOT(dname)) {
			TALLOC_FREE(talloced);
			continue;
		}
		sc_data->num_volumes++;
		if (!labels) {
			TALLOC_FREE(talloced);
			continue;
		}
		if (sc_data->num_volumes > slots) {
			uint32_t new_slot_count = slots + 10;
			SMB_ASSERT(new_slot_count > slots);
			sc_data->labels = talloc_realloc(sc_data,
							 sc_data->labels,
							 SHADOW_COPY_LABEL,
							 new_slot_count);
			if (sc_data->labels == NULL) {
				TALLOC_FREE(talloced);
				ret = -ENOMEM;
				goto err_closedir;
			}
			memset(sc_data->labels[slots], 0,
			       sizeof(SHADOW_COPY_LABEL) * 10);

			DBG_DEBUG("%d->%d slots for enum_snaps response\n",
				  slots, new_slot_count);
			slots = new_slot_count;
		}
		DBG_DEBUG("filling shadow copy label for %s/%s\n",
			  snaps_dname->base_name, dname);
		ret = ceph_snap_fill_label(handle, snaps_dname,
				snaps_dname->base_name, dname,
				sc_data->labels[sc_data->num_volumes - 1]);
		if (ret < 0) {
			TALLOC_FREE(talloced);
			goto err_closedir;
		}
		TALLOC_FREE(talloced);
	}

	DBG_DEBUG("%s shadow copy enumeration found %d labels \n",
		  snaps_dname->base_name, sc_data->num_volumes);

	TALLOC_FREE(frame);
	return 0;

err_closedir:
	TALLOC_FREE(frame);
err_out:
	TALLOC_FREE(sc_data->labels);
	return ret;
}

/*
 * Prior reading: The Meaning of Path Names
 *   https://wiki.samba.org/index.php/Writing_a_Samba_VFS_Module
 *
 * translate paths so that we can use the parent dir for .snap access:
 *   myfile        -> parent=        trimmed=myfile
 *   /a            -> parent=/       trimmed=a
 *   dir/sub/file  -> parent=dir/sub trimmed=file
 *   /dir/sub      -> parent=/dir/   trimmed=sub
 */
static int ceph_snap_get_parent_path(const char *connectpath,
				     const char *path,
				     char *_parent_buf,
				     size_t buflen,
				     const char **_trimmed)
{
	const char *p;
	size_t len;
	int ret;

	if (!strcmp(path, "/")) {
		DBG_ERR("can't go past root for %s .snap dir\n", path);
		return -EINVAL;
	}

	p = strrchr_m(path, '/'); /* Find final '/', if any */
	if (p == NULL) {
		DBG_DEBUG("parent .snap dir for %s is cwd\n", path);
		ret = strlcpy(_parent_buf, "", buflen);
		if (ret >= buflen) {
			return -EINVAL;
		}
		if (_trimmed != NULL) {
			*_trimmed = path;
		}
		return 0;
	}

	SMB_ASSERT(p >= path);
	len = p - path;

	ret = snprintf(_parent_buf, buflen, "%.*s", (int)len, path);
	if (ret >= buflen) {
		return -EINVAL;
	}

	/* for absolute paths, check that we're not going outside the share */
	if ((len > 0) && (_parent_buf[0] == '/')) {
		bool connectpath_match = false;
		size_t clen = strlen(connectpath);
		DBG_DEBUG("checking absolute path %s lies within share at %s\n",
			  _parent_buf, connectpath);
		/* need to check for separator, to avoid /x/abcd vs /x/ab */
		connectpath_match = (strncmp(connectpath,
					_parent_buf,
					clen) == 0);
		if (!connectpath_match
		 || ((_parent_buf[clen] != '/') && (_parent_buf[clen] != '\0'))) {
			DBG_ERR("%s parent path is outside of share at %s\n",
				_parent_buf, connectpath);
			return -EINVAL;
		}
	}

	if (_trimmed != NULL) {
		/*
		 * point to path component which was trimmed from _parent_buf
		 * excluding path separator.
		 */
		*_trimmed = p + 1;
	}

	DBG_DEBUG("generated parent .snap path for %s as %s (trimmed \"%s\")\n",
		  path, _parent_buf, p + 1);

	return 0;
}

static int ceph_snap_get_shadow_copy_data(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					struct shadow_copy_data *sc_data,
					bool labels)
{
	int ret;
	TALLOC_CTX *tmp_ctx;
	const char *parent_dir = NULL;
	char tmp[PATH_MAX + 1];
	char snaps_path[PATH_MAX + 1];
	struct smb_filename *snaps_dname = NULL;
	const char *snapdir = lp_parm_const_string(SNUM(handle->conn),
						   "ceph", "snapdir",
						   CEPH_SNAP_SUBDIR_DEFAULT);

	DBG_DEBUG("getting shadow copy data for %s\n",
		  fsp->fsp_name->base_name);

	tmp_ctx = talloc_new(fsp);
	if (tmp_ctx == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	if (sc_data == NULL) {
		ret = -EINVAL;
		goto err_out;
	}

	if (fsp->fsp_flags.is_directory) {
		parent_dir = fsp->fsp_name->base_name;
	} else {
		ret = ceph_snap_get_parent_path(handle->conn->connectpath,
						fsp->fsp_name->base_name,
						tmp,
						sizeof(tmp),
						NULL);	/* trimmed */
		if (ret < 0) {
			goto err_out;
		}
		parent_dir = tmp;
	}

	if (strlen(parent_dir) == 0) {
		ret = strlcpy(snaps_path, snapdir, sizeof(snaps_path));
	} else {
		ret = snprintf(snaps_path, sizeof(snaps_path), "%s/%s",
			       parent_dir, snapdir);
	}
	if (ret >= sizeof(snaps_path)) {
		ret = -EINVAL;
		goto err_out;
	}

	snaps_dname = synthetic_smb_fname(tmp_ctx,
				snaps_path,
				NULL,
				NULL,
				0,
				fsp->fsp_name->flags);
	if (snaps_dname == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	ret = ceph_snap_enum_snapdir(handle, snaps_dname, labels, sc_data);
	if (ret < 0) {
		goto err_out;
	}

	talloc_free(tmp_ctx);
	return 0;

err_out:
	talloc_free(tmp_ctx);
	errno = -ret;
	return -1;
}

static int ceph_snap_gmt_strip_snapshot(struct vfs_handle_struct *handle,
					 const struct smb_filename *smb_fname,
					 time_t *_timestamp,
					 char *_stripped_buf,
					 size_t buflen)
{
	size_t len;

	if (smb_fname->twrp == 0) {
		goto no_snapshot;
	}

	if (_stripped_buf != NULL) {
		len = strlcpy(_stripped_buf, smb_fname->base_name, buflen);
		if (len >= buflen) {
			return -ENAMETOOLONG;
		}
	}

	*_timestamp = nt_time_to_unix(smb_fname->twrp);
	return 0;
no_snapshot:
	*_timestamp = 0;
	return 0;
}

static int ceph_snap_gmt_convert_dir(struct vfs_handle_struct *handle,
				     const char *name,
				     time_t timestamp,
				     char *_converted_buf,
				     size_t buflen)
{
	int ret;
	NTSTATUS status;
	struct smb_Dir *dir_hnd = NULL;
	const char *dname = NULL;
	char *talloced = NULL;
	long offset = 0;
	struct smb_filename *snaps_dname = NULL;
	const char *snapdir = lp_parm_const_string(SNUM(handle->conn),
						   "ceph", "snapdir",
						   CEPH_SNAP_SUBDIR_DEFAULT);
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);

	if (tmp_ctx == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	/*
	 * Temporally use the caller's return buffer for this.
	 */
	if (strlen(name) == 0) {
		ret = strlcpy(_converted_buf, snapdir, buflen);
	} else {
		ret = snprintf(_converted_buf, buflen, "%s/%s", name, snapdir);
	}
	if (ret >= buflen) {
		ret = -EINVAL;
		goto err_out;
	}

	snaps_dname = synthetic_smb_fname(tmp_ctx,
				_converted_buf,
				NULL,
				NULL,
				0,
				0);	/* XXX check? */
	if (snaps_dname == NULL) {
		ret = -ENOMEM;
		goto err_out;
	}

	/* stat first to trigger error fallback in ceph_snap_gmt_convert() */
	ret = SMB_VFS_NEXT_STAT(handle, snaps_dname);
	if (ret < 0) {
		ret = -errno;
		goto err_out;
	}

	status = smbd_check_access_rights(handle->conn,
					handle->conn->cwd_fsp,
					snaps_dname,
					false,
					SEC_DIR_LIST);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("user does not have list permission "
			"on snapdir %s\n",
			snaps_dname->base_name));
		ret = -map_errno_from_nt_status(status);
		goto err_out;
	}

	DBG_DEBUG("enumerating shadow copy dir at %s\n",
		  snaps_dname->base_name);

	dir_hnd = OpenDir(tmp_ctx, handle->conn, snaps_dname, NULL, 0);
	if (dir_hnd == NULL) {
		ret = -errno;
		goto err_out;
	}

        while ((dname = ReadDirName(dir_hnd, &offset, NULL, &talloced))
	       != NULL)
	{
		struct smb_filename *smb_fname;
		time_t snap_secs;

		if (ISDOT(dname) || ISDOTDOT(dname)) {
			TALLOC_FREE(talloced);
			continue;
		}

		ret = snprintf(_converted_buf, buflen, "%s/%s",
			       snaps_dname->base_name, dname);
		if (ret >= buflen) {
			ret = -EINVAL;
			goto err_out;
		}

		smb_fname = synthetic_smb_fname(tmp_ctx,
						_converted_buf,
						NULL,
						NULL,
						0,
						0);
		if (smb_fname == NULL) {
			ret = -ENOMEM;
			goto err_out;
		}

		ret = ceph_snap_get_btime(handle, smb_fname, &snap_secs);
		if (ret < 0) {
			goto err_out;
		}

		/*
		 * check gmt_snap_time matches @timestamp
		 */
		if (timestamp == snap_secs) {
			break;
		}
		DBG_DEBUG("[connectpath %s] %s@%lld no match for snap %s@%lld\n",
			  handle->conn->connectpath, name, (long long)timestamp,
			  dname, (long long)snap_secs);
		TALLOC_FREE(talloced);
	}

	if (dname == NULL) {
		DBG_INFO("[connectpath %s] failed to find %s @ time %lld\n",
			 handle->conn->connectpath, name, (long long)timestamp);
		ret = -ENOENT;
		goto err_out;
	}

	/* found, _converted_buf already contains path of interest */
	DBG_DEBUG("[connectpath %s] converted %s @ time %lld to %s\n",
		  handle->conn->connectpath, name, (long long)timestamp,
		  _converted_buf);

	TALLOC_FREE(talloced);
	talloc_free(tmp_ctx);
	return 0;

err_out:
	TALLOC_FREE(talloced);
	talloc_free(tmp_ctx);
	return ret;
}

static int ceph_snap_gmt_convert(struct vfs_handle_struct *handle,
				     const char *name,
				     time_t timestamp,
				     char *_converted_buf,
				     size_t buflen)
{
	int ret;
	char parent[PATH_MAX + 1];
	const char *trimmed = NULL;
	/*
	 * CephFS Snapshots for a given dir are nested under the ./.snap subdir
	 * *or* under ../.snap/dir (and subsequent parent dirs).
	 * Child dirs inherit snapshots created in parent dirs if the child
	 * exists at the time of snapshot creation.
	 *
	 * At this point we don't know whether @name refers to a file or dir, so
	 * first assume it's a dir (with a corresponding .snaps subdir)
	 */
	ret = ceph_snap_gmt_convert_dir(handle,
					name,
					timestamp,
					_converted_buf,
					buflen);
	if (ret >= 0) {
		/* all done: .snap subdir exists - @name is a dir */
		DBG_DEBUG("%s is a dir, accessing snaps via .snap\n", name);
		return ret;
	}

	/* @name/.snap access failed, attempt snapshot access via parent */
	DBG_DEBUG("%s/.snap access failed, attempting parent access\n",
		  name);

	ret = ceph_snap_get_parent_path(handle->conn->connectpath,
					name,
					parent,
					sizeof(parent),
					&trimmed);
	if (ret < 0) {
		return ret;
	}

	ret = ceph_snap_gmt_convert_dir(handle,
					parent,
					timestamp,
					_converted_buf,
					buflen);
	if (ret < 0) {
		return ret;
	}

	/*
	 * found snapshot via parent. Append the child path component
	 * that was trimmed... +1 for path separator + 1 for null termination.
	 */
	if (strlen(_converted_buf) + 1 + strlen(trimmed) + 1 > buflen) {
		return -EINVAL;
	}
	strlcat(_converted_buf, "/", buflen);
	strlcat(_converted_buf, trimmed, buflen);

	return 0;
}

static int ceph_snap_gmt_renameat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst)
{
	int ret;
	time_t timestamp_src, timestamp_dst;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					smb_fname_src,
					&timestamp_src, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	ret = ceph_snap_gmt_strip_snapshot(handle,
					smb_fname_dst,
					&timestamp_dst, NULL, 0);
	if (ret < 0) {
		errno = -ret;
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
	return SMB_VFS_NEXT_RENAMEAT(handle,
				srcfsp,
				smb_fname_src,
				dstfsp,
				smb_fname_dst);
}

/* block links from writeable shares to snapshots for now, like other modules */
static int ceph_snap_gmt_symlinkat(vfs_handle_struct *handle,
				const struct smb_filename *link_contents,
				struct files_struct *dirfsp,
				const struct smb_filename *new_smb_fname)
{
	int ret;
	time_t timestamp_old = 0;
	time_t timestamp_new = 0;

	ret = ceph_snap_gmt_strip_snapshot(handle,
				link_contents,
				&timestamp_old,
				NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	ret = ceph_snap_gmt_strip_snapshot(handle,
				new_smb_fname,
				&timestamp_new,
				NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if ((timestamp_old != 0) || (timestamp_new != 0)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_SYMLINKAT(handle,
				link_contents,
				dirfsp,
				new_smb_fname);
}

static int ceph_snap_gmt_linkat(vfs_handle_struct *handle,
				files_struct *srcfsp,
				const struct smb_filename *old_smb_fname,
				files_struct *dstfsp,
				const struct smb_filename *new_smb_fname,
				int flags)
{
	int ret;
	time_t timestamp_old = 0;
	time_t timestamp_new = 0;

	ret = ceph_snap_gmt_strip_snapshot(handle,
				old_smb_fname,
				&timestamp_old,
				NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	ret = ceph_snap_gmt_strip_snapshot(handle,
				new_smb_fname,
				&timestamp_new,
				NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if ((timestamp_old != 0) || (timestamp_new != 0)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_LINKAT(handle,
			srcfsp,
			old_smb_fname,
			dstfsp,
			new_smb_fname,
			flags);
}

static int ceph_snap_gmt_stat(vfs_handle_struct *handle,
			    struct smb_filename *smb_fname)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	char *tmp;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					smb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_STAT(handle, smb_fname);
	}

	ret = ceph_snap_gmt_convert(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	tmp = smb_fname->base_name;
	smb_fname->base_name = conv;

	ret = SMB_VFS_NEXT_STAT(handle, smb_fname);
	smb_fname->base_name = tmp;
	return ret;
}

static int ceph_snap_gmt_lstat(vfs_handle_struct *handle,
			     struct smb_filename *smb_fname)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	char *tmp;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					smb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}

	ret = ceph_snap_gmt_convert(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	tmp = smb_fname->base_name;
	smb_fname->base_name = conv;

	ret = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	smb_fname->base_name = tmp;
	return ret;
}

static int ceph_snap_gmt_openat(vfs_handle_struct *handle,
				const struct files_struct *dirfsp,
				const struct smb_filename *smb_fname_in,
				files_struct *fsp,
				int flags,
				mode_t mode)
{
	time_t timestamp = 0;
	struct smb_filename *smb_fname = NULL;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	int ret;
	int saved_errno = 0;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					   smb_fname_in,
					   &timestamp,
					   stripped,
					   sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname_in,
					   fsp,
					   flags,
					   mode);
	}

	ret = ceph_snap_gmt_convert(handle,
				    stripped,
				    timestamp,
				    conv,
				    sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	smb_fname = cp_smb_filename(talloc_tos(), smb_fname_in);
	if (smb_fname == NULL) {
		return -1;
	}
	smb_fname->base_name = conv;

	ret = SMB_VFS_NEXT_OPENAT(handle,
				  dirfsp,
				  smb_fname,
				  fsp,
				  flags,
				  mode);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int ceph_snap_gmt_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *csmb_fname,
			int flags)
{
	time_t timestamp = 0;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp,
			csmb_fname,
			flags);
}

static int ceph_snap_gmt_chmod(vfs_handle_struct *handle,
			const struct smb_filename *csmb_fname,
			mode_t mode)
{
	time_t timestamp = 0;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_CHMOD(handle, csmb_fname, mode);
}

static int ceph_snap_gmt_chdir(vfs_handle_struct *handle,
			const struct smb_filename *csmb_fname)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	int ret;
	struct smb_filename *new_fname;
	int saved_errno;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CHDIR(handle, csmb_fname);
	}

	ret = ceph_snap_gmt_convert_dir(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	new_fname = cp_smb_filename(talloc_tos(), csmb_fname);
	if (new_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}
	new_fname->base_name = conv;

	ret = SMB_VFS_NEXT_CHDIR(handle, new_fname);
	saved_errno = errno;
	TALLOC_FREE(new_fname);
	errno = saved_errno;
	return ret;
}

static int ceph_snap_gmt_ntimes(vfs_handle_struct *handle,
			      const struct smb_filename *csmb_fname,
			      struct smb_file_time *ft)
{
	time_t timestamp = 0;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_NTIMES(handle, csmb_fname, ft);
}

static int ceph_snap_gmt_readlinkat(vfs_handle_struct *handle,
				files_struct *dirfsp,
				const struct smb_filename *csmb_fname,
				char *buf,
				size_t bufsiz)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	int ret;
	struct smb_filename *new_fname;
	int saved_errno;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_READLINKAT(handle,
				dirfsp,
				csmb_fname,
				buf,
				bufsiz);
	}
	ret = ceph_snap_gmt_convert(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	new_fname = cp_smb_filename(talloc_tos(), csmb_fname);
	if (new_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}
	new_fname->base_name = conv;

	ret = SMB_VFS_NEXT_READLINKAT(handle,
				dirfsp,
				new_fname,
				buf,
				bufsiz);
	saved_errno = errno;
	TALLOC_FREE(new_fname);
	errno = saved_errno;
	return ret;
}

static int ceph_snap_gmt_mknodat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *csmb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	time_t timestamp = 0;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_MKNODAT(handle,
			dirfsp,
			csmb_fname,
			mode,
			dev);
}

static struct smb_filename *ceph_snap_gmt_realpath(vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *csmb_fname)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	struct smb_filename *result_fname;
	int ret;
	struct smb_filename *new_fname;
	int saved_errno;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return NULL;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_REALPATH(handle, ctx, csmb_fname);
	}
	ret = ceph_snap_gmt_convert(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return NULL;
	}
	new_fname = cp_smb_filename(talloc_tos(), csmb_fname);
	if (new_fname == NULL) {
		errno = ENOMEM;
		return NULL;
	}
	new_fname->base_name = conv;

	result_fname = SMB_VFS_NEXT_REALPATH(handle, ctx, new_fname);
	saved_errno = errno;
	TALLOC_FREE(new_fname);
	errno = saved_errno;
	return result_fname;
}

static NTSTATUS ceph_snap_gmt_get_nt_acl_at(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *csmb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	int ret;
	NTSTATUS status;
	struct smb_filename *new_fname;
	int saved_errno;

	SMB_ASSERT(dirfsp == handle->conn->cwd_fsp);

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		return map_nt_error_from_unix(-ret);
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
					dirfsp,
					csmb_fname,
					security_info,
					mem_ctx,
					ppdesc);
	}
	ret = ceph_snap_gmt_convert(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		return map_nt_error_from_unix(-ret);
	}
	new_fname = cp_smb_filename(talloc_tos(), csmb_fname);
	if (new_fname == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	new_fname->base_name = conv;

	status = SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
					dirfsp,
					new_fname,
					security_info,
					mem_ctx,
					ppdesc);
	saved_errno = errno;
	TALLOC_FREE(new_fname);
	errno = saved_errno;
	return status;
}

static int ceph_snap_gmt_mkdirat(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *csmb_fname,
				mode_t mode)
{
	time_t timestamp = 0;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_MKDIRAT(handle,
			dirfsp,
			csmb_fname,
			mode);
}

static int ceph_snap_gmt_chflags(vfs_handle_struct *handle,
				const struct smb_filename *csmb_fname,
				unsigned int flags)
{
	time_t timestamp = 0;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_CHFLAGS(handle, csmb_fname, flags);
}

static ssize_t ceph_snap_gmt_getxattr(vfs_handle_struct *handle,
				const struct smb_filename *csmb_fname,
				const char *aname,
				void *value,
				size_t size)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	int ret;
	struct smb_filename *new_fname;
	int saved_errno;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GETXATTR(handle, csmb_fname, aname, value,
					     size);
	}
	ret = ceph_snap_gmt_convert(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	new_fname = cp_smb_filename(talloc_tos(), csmb_fname);
	if (new_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}
	new_fname->base_name = conv;

	ret = SMB_VFS_NEXT_GETXATTR(handle, new_fname, aname, value, size);
	saved_errno = errno;
	TALLOC_FREE(new_fname);
	errno = saved_errno;
	return ret;
}

static ssize_t ceph_snap_gmt_listxattr(struct vfs_handle_struct *handle,
				     const struct smb_filename *csmb_fname,
				     char *list, size_t size)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	int ret;
	struct smb_filename *new_fname;
	int saved_errno;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_LISTXATTR(handle, csmb_fname, list, size);
	}
	ret = ceph_snap_gmt_convert(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	new_fname = cp_smb_filename(talloc_tos(), csmb_fname);
	if (new_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}
	new_fname->base_name = conv;

	ret = SMB_VFS_NEXT_LISTXATTR(handle, new_fname, list, size);
	saved_errno = errno;
	TALLOC_FREE(new_fname);
	errno = saved_errno;
	return ret;
}

static int ceph_snap_gmt_removexattr(vfs_handle_struct *handle,
				const struct smb_filename *csmb_fname,
				const char *aname)
{
	time_t timestamp = 0;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_REMOVEXATTR(handle, csmb_fname, aname);
}

static int ceph_snap_gmt_setxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *csmb_fname,
				const char *aname, const void *value,
				size_t size, int flags)
{
	time_t timestamp = 0;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, NULL, 0);
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_SETXATTR(handle, csmb_fname,
				aname, value, size, flags);
}

static int ceph_snap_gmt_get_real_filename(struct vfs_handle_struct *handle,
					 const struct smb_filename *path,
					 const char *name,
					 TALLOC_CTX *mem_ctx,
					 char **found_name)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	struct smb_filename conv_fname;
	int ret;

	ret = ceph_snap_gmt_strip_snapshot(handle, path,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name,
						      mem_ctx, found_name);
	}
	ret = ceph_snap_gmt_convert_dir(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}

	conv_fname = (struct smb_filename) {
		.base_name = conv,
	};

	ret = SMB_VFS_NEXT_GET_REAL_FILENAME(handle, &conv_fname, name,
					     mem_ctx, found_name);
	return ret;
}

static uint64_t ceph_snap_gmt_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *csmb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	int ret;
	struct smb_filename *new_fname;
	int saved_errno;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_DISK_FREE(handle, csmb_fname,
					      bsize, dfree, dsize);
	}
	ret = ceph_snap_gmt_convert(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	new_fname = cp_smb_filename(talloc_tos(), csmb_fname);
	if (new_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}
	new_fname->base_name = conv;

	ret = SMB_VFS_NEXT_DISK_FREE(handle, new_fname,
				bsize, dfree, dsize);
	saved_errno = errno;
	TALLOC_FREE(new_fname);
	errno = saved_errno;
	return ret;
}

static int ceph_snap_gmt_get_quota(vfs_handle_struct *handle,
			const struct smb_filename *csmb_fname,
			enum SMB_QUOTA_TYPE qtype,
			unid_t id,
			SMB_DISK_QUOTA *dq)
{
	time_t timestamp = 0;
	char stripped[PATH_MAX + 1];
	char conv[PATH_MAX + 1];
	int ret;
	struct smb_filename *new_fname;
	int saved_errno;

	ret = ceph_snap_gmt_strip_snapshot(handle,
					csmb_fname,
					&timestamp, stripped, sizeof(stripped));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GET_QUOTA(handle, csmb_fname, qtype, id, dq);
	}
	ret = ceph_snap_gmt_convert(handle, stripped,
					timestamp, conv, sizeof(conv));
	if (ret < 0) {
		errno = -ret;
		return -1;
	}
	new_fname = cp_smb_filename(talloc_tos(), csmb_fname);
	if (new_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}
	new_fname->base_name = conv;

	ret = SMB_VFS_NEXT_GET_QUOTA(handle, new_fname, qtype, id, dq);
	saved_errno = errno;
	TALLOC_FREE(new_fname);
	errno = saved_errno;
	return ret;
}

static struct vfs_fn_pointers ceph_snap_fns = {
	.get_shadow_copy_data_fn = ceph_snap_get_shadow_copy_data,
	.disk_free_fn = ceph_snap_gmt_disk_free,
	.get_quota_fn = ceph_snap_gmt_get_quota,
	.renameat_fn = ceph_snap_gmt_renameat,
	.linkat_fn = ceph_snap_gmt_linkat,
	.symlinkat_fn = ceph_snap_gmt_symlinkat,
	.stat_fn = ceph_snap_gmt_stat,
	.lstat_fn = ceph_snap_gmt_lstat,
	.openat_fn = ceph_snap_gmt_openat,
	.unlinkat_fn = ceph_snap_gmt_unlinkat,
	.chmod_fn = ceph_snap_gmt_chmod,
	.chdir_fn = ceph_snap_gmt_chdir,
	.ntimes_fn = ceph_snap_gmt_ntimes,
	.readlinkat_fn = ceph_snap_gmt_readlinkat,
	.mknodat_fn = ceph_snap_gmt_mknodat,
	.realpath_fn = ceph_snap_gmt_realpath,
	.get_nt_acl_at_fn = ceph_snap_gmt_get_nt_acl_at,
	.mkdirat_fn = ceph_snap_gmt_mkdirat,
	.getxattr_fn = ceph_snap_gmt_getxattr,
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.listxattr_fn = ceph_snap_gmt_listxattr,
	.removexattr_fn = ceph_snap_gmt_removexattr,
	.setxattr_fn = ceph_snap_gmt_setxattr,
	.chflags_fn = ceph_snap_gmt_chflags,
	.get_real_filename_fn = ceph_snap_gmt_get_real_filename,
};

static_decl_vfs;
NTSTATUS vfs_ceph_snapshots_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"ceph_snapshots", &ceph_snap_fns);
}
