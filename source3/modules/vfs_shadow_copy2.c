/*
 * shadow_copy2: a shadow copy module (second implementation)
 *
 * Copyright (C) Andrew Tridgell   2007 (portions taken from shadow_copy2)
 * Copyright (C) Ed Plese          2009
 * Copyright (C) Volker Lendecke   2011
 * Copyright (C) Christian Ambach  2011
 * Copyright (C) Michael Adam      2013
 * Copyright (C) Rajesh Joseph     2016
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
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "include/ntioctl.h"
#include "util_tdb.h"
#include "lib/util_path.h"
#include "libcli/security/security.h"
#include "lib/util/tevent_unix.h"

struct shadow_copy2_config {
	char *gmt_format;
	bool use_sscanf;
	bool use_localtime;
	char *snapdir;
	char *delimiter;
	bool snapdirseverywhere;
	bool crossmountpoints;
	bool fixinodes;
	char *sort_order;
	bool snapdir_absolute;
	char *mount_point;
	char *rel_connectpath; /* share root, relative to a snapshot root */
	char *snapshot_basepath; /* the absolute version of snapdir */
};

/* Data-structure to hold the list of snap entries */
struct shadow_copy2_snapentry {
	char *snapname;
	char *time_fmt;
	struct shadow_copy2_snapentry *next;
	struct shadow_copy2_snapentry *prev;
};

struct shadow_copy2_snaplist_info {
	struct shadow_copy2_snapentry *snaplist; /* snapshot list */
	regex_t *regex; /* Regex to filter snaps */
	time_t fetch_time; /* snaplist update time */
};


/*
 * shadow_copy2 private structure. This structure will be
 * used to keep module specific information
 */
struct shadow_copy2_private {
	struct shadow_copy2_config *config;
	struct shadow_copy2_snaplist_info *snaps;
	char *shadow_cwd; /* Absolute $cwd path. */
	/* Absolute connectpath - can vary depending on $cwd. */
	char *shadow_connectpath;
	/* talloc'ed realpath return. */
	struct smb_filename *shadow_realpath;
};

static int shadow_copy2_get_shadow_copy_data(
	vfs_handle_struct *handle, files_struct *fsp,
	struct shadow_copy_data *shadow_copy2_data,
	bool labels);

/**
 *This function will create a new snapshot list entry and
 * return to the caller. This entry will also be added to
 * the global snapshot list.
 *
 * @param[in]   priv	shadow_copy2 specific data structure
 * @return	Newly   created snapshot entry or NULL on failure
 */
static struct shadow_copy2_snapentry *shadow_copy2_create_snapentry(
					struct shadow_copy2_private *priv)
{
	struct shadow_copy2_snapentry *tmpentry = NULL;

	tmpentry = talloc_zero(priv->snaps, struct shadow_copy2_snapentry);
	if (tmpentry == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return NULL;
	}

	DLIST_ADD(priv->snaps->snaplist, tmpentry);

	return tmpentry;
}

/**
 *This function will delete the entire snaplist and reset
 * priv->snaps->snaplist to NULL.
 *
 * @param[in] priv shadow_copye specific data structure
 */
static void shadow_copy2_delete_snaplist(struct shadow_copy2_private *priv)
{
	struct shadow_copy2_snapentry *tmp = NULL;

	while ((tmp = priv->snaps->snaplist) != NULL) {
		DLIST_REMOVE(priv->snaps->snaplist, tmp);
		talloc_free(tmp);
	}
}

/**
 * Given a timestamp this function searches the global snapshot list
 * and returns the complete snapshot directory name saved in the entry.
 *
 * @param[in]   priv		shadow_copy2 specific structure
 * @param[in]   timestamp	timestamp corresponding to one of the snapshot
 * @param[out]  snap_str	buffer to copy the actual snapshot name
 * @param[in]   len		length of snap_str buffer
 *
 * @return 	Length of actual snapshot name, and -1 on failure
 */
static ssize_t shadow_copy2_saved_snapname(struct shadow_copy2_private *priv,
					  struct tm *timestamp,
					  char *snap_str, size_t len)
{
	ssize_t snaptime_len = -1;
	struct shadow_copy2_snapentry *entry = NULL;

	snaptime_len = strftime(snap_str, len, GMT_FORMAT, timestamp);
	if (snaptime_len == 0) {
		DBG_ERR("strftime failed\n");
		return -1;
	}

	snaptime_len = -1;

	for (entry = priv->snaps->snaplist; entry; entry = entry->next) {
		if (strcmp(entry->time_fmt, snap_str) == 0) {
			snaptime_len = snprintf(snap_str, len, "%s",
						entry->snapname);
			return snaptime_len;
		}
	}

	snap_str[0] = 0;
	return snaptime_len;
}


/**
 * This function will check if snaplist is updated or not. If snaplist
 * is empty then it will create a new list. Each time snaplist is updated
 * the time is recorded. If the snapshot time is greater than the snaplist
 * update time then chances are we are working on an older list. Then discard
 * the old list and fetch a new snaplist.
 *
 * @param[in]   handle		VFS handle struct
 * @param[in]   snap_time	time of snapshot
 *
 * @return 	true if the list is updated else false
 */
static bool shadow_copy2_update_snaplist(struct vfs_handle_struct *handle,
		time_t snap_time)
{
	int ret = -1;
	bool snaplist_updated = false;
	struct files_struct fsp = {0};
	struct smb_filename smb_fname = {0};
	double seconds = 0.0;
	struct shadow_copy2_private *priv = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return false);

	seconds = difftime(snap_time, priv->snaps->fetch_time);

	/*
	 * Fetch the snapshot list if either the snaplist is empty or the
	 * required snapshot time is greater than the last fetched snaplist
	 * time.
	 */
	if (seconds > 0 || (priv->snaps->snaplist == NULL)) {
		smb_fname.base_name = discard_const_p(char, ".");
		fsp.fsp_name = &smb_fname;

		ret = shadow_copy2_get_shadow_copy_data(handle, &fsp,
							NULL, false);
		if (ret == 0) {
			snaplist_updated = true;
		} else {
			DBG_ERR("Failed to get shadow copy data\n");
		}

	}

	return snaplist_updated;
}

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
static ssize_t shadow_copy2_posix_gmt_string(struct vfs_handle_struct *handle,
					    time_t snapshot,
					    char *snaptime_string,
					    size_t len)
{
	struct tm snap_tm;
	ssize_t snaptime_len;
	struct shadow_copy2_config *config;
	struct shadow_copy2_private *priv;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return 0);

	config = priv->config;

	if (config->use_sscanf) {
		snaptime_len = snprintf(snaptime_string,
					len,
					config->gmt_format,
					(unsigned long)snapshot);
		if (snaptime_len <= 0) {
			DEBUG(10, ("snprintf failed\n"));
			return -1;
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

		if (priv->snaps->regex != NULL) {
			snaptime_len = shadow_copy2_saved_snapname(priv,
						&snap_tm, snaptime_string, len);
			if (snaptime_len >= 0)
				return snaptime_len;

			/*
			 * If we fail to find the snapshot name, chances are
			 * that we have not updated our snaplist. Make sure the
			 * snaplist is updated.
			 */
			if (!shadow_copy2_update_snaplist(handle, snapshot)) {
				DBG_DEBUG("shadow_copy2_update_snaplist "
					  "failed\n");
				return -1;
			}

			return shadow_copy2_saved_snapname(priv,
						&snap_tm, snaptime_string, len);
		}

		snaptime_len = strftime(snaptime_string,
					len,
					config->gmt_format,
					&snap_tm);
		if (snaptime_len == 0) {
			DEBUG(10, ("strftime failed\n"));
			return -1;
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
 * absolute path), this is the initial portion of the
 * local path of any snapshot file. The complete path is
 * obtained by appending the portion of the file's path
 * below the share root's mountpoint.
 */
static char *shadow_copy2_insert_string(TALLOC_CTX *mem_ctx,
					struct vfs_handle_struct *handle,
					time_t snapshot)
{
	fstring snaptime_string;
	ssize_t snaptime_len = 0;
	char *result = NULL;
	struct shadow_copy2_config *config;
	struct shadow_copy2_private *priv;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return NULL);

	config = priv->config;

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
	ssize_t snaptime_len = 0;
	char *result = NULL;
	struct shadow_copy2_private *priv;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return NULL);

	snaptime_len = shadow_copy2_posix_gmt_string(handle,
						     snapshot,
						     snaptime_string,
						     sizeof(snaptime_string));
	if (snaptime_len <= 0) {
		return NULL;
	}

	result = talloc_asprintf(mem_ctx, "%s/%s",
				 priv->config->snapshot_basepath, snaptime_string);
	if (result == NULL) {
		DEBUG(1, (__location__ " talloc_asprintf failed\n"));
	}

	return result;
}

static char *make_path_absolute(TALLOC_CTX *mem_ctx,
				struct shadow_copy2_private *priv,
				const char *name)
{
	char *newpath = NULL;
	char *abs_path = NULL;

	if (name[0] != '/') {
		newpath = talloc_asprintf(mem_ctx,
					"%s/%s",
					priv->shadow_cwd,
					name);
		if (newpath == NULL) {
			return NULL;
		}
		name = newpath;
	}
	abs_path = canonicalize_absolute_path(mem_ctx, name);
	TALLOC_FREE(newpath);
	return abs_path;
}

/* Return a $cwd-relative path. */
static bool make_relative_path(const char *cwd, char *abs_path)
{
	size_t cwd_len = strlen(cwd);
	size_t abs_len = strlen(abs_path);

	if (abs_len < cwd_len) {
		return false;
	}
	if (memcmp(abs_path, cwd, cwd_len) != 0) {
		return false;
	}
	/* The cwd_len != 1 case is for $cwd == '/' */
	if (cwd_len != 1 &&
	    abs_path[cwd_len] != '/' &&
	    abs_path[cwd_len] != '\0')
	{
		return false;
	}
	if (abs_path[cwd_len] == '/') {
		cwd_len++;
	}
	memmove(abs_path, &abs_path[cwd_len], abs_len + 1 - cwd_len);
	return true;
}

static bool shadow_copy2_snapshot_to_gmt(vfs_handle_struct *handle,
					const char *name,
					char *gmt, size_t gmt_len);

/*
 * Check if an incoming filename is already a snapshot converted pathname.
 *
 * If so, it returns the pathname truncated at the snapshot point which
 * will be used as the connectpath.
 */

static int check_for_converted_path(TALLOC_CTX *mem_ctx,
				struct vfs_handle_struct *handle,
				struct shadow_copy2_private *priv,
				char *abs_path,
				bool *ppath_already_converted,
				char **pconnectpath)
{
	size_t snapdirlen = 0;
	char *p = strstr_m(abs_path, priv->config->snapdir);
	char *q = NULL;
	char *connect_path = NULL;
	char snapshot[GMT_NAME_LEN+1];

	*ppath_already_converted = false;

	if (p == NULL) {
		/* Must at least contain shadow:snapdir. */
		return 0;
	}

	if (priv->config->snapdir[0] == '/' &&
			p != abs_path) {
		/* Absolute shadow:snapdir must be at the start. */
		return 0;
	}

	snapdirlen = strlen(priv->config->snapdir);
	if (p[snapdirlen] != '/') {
		/* shadow:snapdir must end as a separate component. */
		return 0;
	}

	if (p > abs_path && p[-1] != '/') {
		/* shadow:snapdir must start as a separate component. */
		return 0;
	}

	p += snapdirlen;
	p++; /* Move past the / */

	/*
	 * Need to return up to the next path
	 * component after the time.
	 * This will be used as the connectpath.
	 */
	q = strchr(p, '/');
	if (q == NULL) {
		/*
		 * No next path component.
		 * Use entire string.
		 */
		connect_path = talloc_strdup(mem_ctx,
					abs_path);
	} else {
		connect_path = talloc_strndup(mem_ctx,
					abs_path,
					q - abs_path);
	}
	if (connect_path == NULL) {
		return ENOMEM;
	}

	/*
	 * Point p at the same offset in connect_path as
	 * it is in abs_path.
	 */

	p = &connect_path[p - abs_path];

	/*
	 * Now ensure there is a time string at p.
	 * The SMB-format @GMT-token string is returned
	 * in snapshot.
	 */

	if (!shadow_copy2_snapshot_to_gmt(handle,
				p,
				snapshot,
				sizeof(snapshot))) {
		TALLOC_FREE(connect_path);
		return 0;
	}

	if (pconnectpath != NULL) {
		*pconnectpath = connect_path;
	}

	*ppath_already_converted = true;

	DBG_DEBUG("path |%s| is already converted. "
		"connect path = |%s|\n",
		abs_path,
		connect_path);

	return 0;
}

/**
 * This function does two things.
 *
 * 1). Checks if an incoming filename is already a
 * snapshot converted pathname.
 *     If so, it returns the pathname truncated
 *     at the snapshot point which will be used
 *     as the connectpath, and then does an early return.
 *
 * 2). Checks if an incoming filename contains an
 * SMB-layer @GMT- style timestamp.
 *     If so, it strips the timestamp, and returns
 *     both the timestamp and the stripped path
 *     (making it cwd-relative).
 */

static bool _shadow_copy2_strip_snapshot_internal(TALLOC_CTX *mem_ctx,
					struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					time_t *ptimestamp,
					char **pstripped,
					char **psnappath,
					bool *_already_converted,
					const char *function)
{
	char *stripped = NULL;
	struct shadow_copy2_private *priv;
	char *abs_path = NULL;
	bool ret = true;
	bool already_converted = false;
	int err = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return false);

	DBG_DEBUG("[from %s()] Path '%s'\n",
		  function, smb_fname_str_dbg(smb_fname));

	if (_already_converted != NULL) {
		*_already_converted = false;
	}

	abs_path = make_path_absolute(mem_ctx, priv, smb_fname->base_name);
	if (abs_path == NULL) {
		ret = false;
		goto out;
	}

	DBG_DEBUG("abs path '%s'\n", abs_path);

	err = check_for_converted_path(mem_ctx,
					handle,
					priv,
					abs_path,
					&already_converted,
					psnappath);
	if (err != 0) {
		/* error in conversion. */
		ret = false;
		goto out;
	}

	if (already_converted) {
		if (_already_converted != NULL) {
			*_already_converted = true;
		}
		goto out;
	}

	if (smb_fname->twrp == 0) {
		goto out;
	}

	if (ptimestamp != NULL) {
		*ptimestamp = nt_time_to_unix(smb_fname->twrp);
	}

	if (pstripped != NULL) {
		stripped = talloc_strdup(mem_ctx, abs_path);
		if (stripped == NULL) {
			ret = false;
			goto out;
		}

		if (smb_fname->base_name[0] != '/') {
			ret = make_relative_path(priv->shadow_cwd, stripped);
			if (!ret) {
				DBG_DEBUG("Path '%s' "
					"doesn't start with cwd '%s'\n",
					stripped, priv->shadow_cwd);
				ret = false;
				errno = ENOENT;
				goto out;
			}
		}
		*pstripped = stripped;
	}

	ret = true;

  out:
	TALLOC_FREE(abs_path);
	return ret;
}

#define shadow_copy2_strip_snapshot_internal(mem_ctx, handle, orig_name, \
		ptimestamp, pstripped, psnappath, _already_converted) \
	_shadow_copy2_strip_snapshot_internal((mem_ctx), (handle), (orig_name), \
		(ptimestamp), (pstripped), (psnappath), (_already_converted), \
					      __FUNCTION__)

static bool _shadow_copy2_strip_snapshot(TALLOC_CTX *mem_ctx,
					 struct vfs_handle_struct *handle,
					 const struct smb_filename *orig_name,
					 time_t *ptimestamp,
					 char **pstripped,
					 const char *function)
{
	return _shadow_copy2_strip_snapshot_internal(mem_ctx,
					handle,
					orig_name,
					ptimestamp,
					pstripped,
					NULL,
					NULL,
					function);
}

#define shadow_copy2_strip_snapshot(mem_ctx, handle, orig_name, \
		ptimestamp, pstripped) \
	_shadow_copy2_strip_snapshot((mem_ctx), (handle), (orig_name), \
		(ptimestamp), (pstripped), __FUNCTION__)

static bool _shadow_copy2_strip_snapshot_converted(TALLOC_CTX *mem_ctx,
					struct vfs_handle_struct *handle,
					const struct smb_filename *orig_name,
					time_t *ptimestamp,
					char **pstripped,
					bool *is_converted,
					const char *function)
{
	return _shadow_copy2_strip_snapshot_internal(mem_ctx,
					handle,
					orig_name,
					ptimestamp,
					pstripped,
					NULL,
					is_converted,
					function);
}

#define shadow_copy2_strip_snapshot_converted(mem_ctx, handle, orig_name, \
		ptimestamp, pstripped, is_converted) \
	_shadow_copy2_strip_snapshot_converted((mem_ctx), (handle), (orig_name), \
		(ptimestamp), (pstripped), (is_converted), __FUNCTION__)

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
 * Also return the path in the snapshot corresponding
 * to the file's share root.
 */
static char *shadow_copy2_do_convert(TALLOC_CTX *mem_ctx,
				     struct vfs_handle_struct *handle,
				     const char *name, time_t timestamp,
				     size_t *snaproot_len)
{
	struct smb_filename converted_fname;
	char *result = NULL;
	size_t *slashes = NULL;
	unsigned num_slashes;
	char *path = NULL;
	size_t pathlen;
	char *insert = NULL;
	char *converted = NULL;
	size_t insertlen, connectlen = 0;
	int saved_errno = 0;
	int i;
	size_t min_offset;
	struct shadow_copy2_config *config;
	struct shadow_copy2_private *priv;
	size_t in_share_offset = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return NULL);

	config = priv->config;

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
			if (snaproot_len != NULL) {
				*snaproot_len = strlen(snapshot_path);
				if (config->rel_connectpath != NULL) {
					*snaproot_len +=
					    strlen(config->rel_connectpath) + 1;
				}
			}
			goto fail;
		} else {
			errno = ENOENT;
			goto fail;
		}
		/* never reached ... */
	}

	connectlen = strlen(handle->conn->connectpath);
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

		if (offset >= connectlen) {
			in_share_offset = offset;
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
			if (snaproot_len != NULL) {
				*snaproot_len = in_share_offset + insertlen;
			}
			break;
		}
		if (errno == ENOTDIR) {
			/*
			 * This is a valid condition: We appended the
			 * .snapshots/@GMT.. to a file name. Just try
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
	if (result == NULL) {
		saved_errno = errno;
	}
	TALLOC_FREE(converted);
	TALLOC_FREE(insert);
	TALLOC_FREE(slashes);
	TALLOC_FREE(path);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return result;
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
	return shadow_copy2_do_convert(mem_ctx, handle, name, timestamp, NULL);
}

/*
  modify a sbuf return to ensure that inodes in the shadow directory
  are different from those in the main directory
 */
static void convert_sbuf(vfs_handle_struct *handle, const char *fname,
			 SMB_STRUCT_STAT *sbuf)
{
	struct shadow_copy2_private *priv;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return);

	if (priv->config->fixinodes) {
		/* some snapshot systems, like GPFS, return the name
		   device:inode for the snapshot files as the current
		   files. That breaks the 'restore' button in the shadow copy
		   GUI, as the client gets a sharing violation.

		   This is a crude way of allowing both files to be
		   open at once. It has a slight chance of inode
		   number collision, but I can't see a better approach
		   without significant VFS changes
		*/
		TDB_DATA key = { .dptr = discard_const_p(uint8_t, fname),
				 .dsize = strlen(fname) };
		uint32_t shash;

		shash = tdb_jenkins_hash(&key) & 0xFF000000;
		if (shash == 0) {
			shash = 1;
		}
		sbuf->st_ex_ino ^= shash;
	}
}

static int shadow_copy2_renameat(vfs_handle_struct *handle,
				files_struct *srcfsp,
				const struct smb_filename *smb_fname_src,
				files_struct *dstfsp,
				const struct smb_filename *smb_fname_dst)
{
	time_t timestamp_src = 0;
	time_t timestamp_dst = 0;
	char *snappath_src = NULL;
	char *snappath_dst = NULL;

	if (!shadow_copy2_strip_snapshot_internal(talloc_tos(), handle,
					 smb_fname_src,
					 &timestamp_src, NULL, &snappath_src,
					 NULL)) {
		return -1;
	}
	if (!shadow_copy2_strip_snapshot_internal(talloc_tos(), handle,
					 smb_fname_dst,
					 &timestamp_dst, NULL, &snappath_dst,
					 NULL)) {
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
	/*
	 * Don't allow rename on already converted paths.
	 */
	if (snappath_src != NULL) {
		errno = EXDEV;
		return -1;
	}
	if (snappath_dst != NULL) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_RENAMEAT(handle,
			srcfsp,
			smb_fname_src,
			dstfsp,
			smb_fname_dst);
}

static int shadow_copy2_symlinkat(vfs_handle_struct *handle,
			const struct smb_filename *link_contents,
			struct files_struct *dirfsp,
			const struct smb_filename *new_smb_fname)
{
	time_t timestamp_old = 0;
	time_t timestamp_new = 0;
	char *snappath_old = NULL;
	char *snappath_new = NULL;

	if (!shadow_copy2_strip_snapshot_internal(talloc_tos(),
				handle,
				link_contents,
				&timestamp_old,
				NULL,
				&snappath_old,
				NULL)) {
		return -1;
	}
	if (!shadow_copy2_strip_snapshot_internal(talloc_tos(),
				handle,
				new_smb_fname,
				&timestamp_new,
				NULL,
				&snappath_new,
				NULL)) {
		return -1;
	}
	if ((timestamp_old != 0) || (timestamp_new != 0)) {
		errno = EROFS;
		return -1;
	}
	/*
	 * Don't allow symlinks on already converted paths.
	 */
	if ((snappath_old != NULL) || (snappath_new != NULL)) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_SYMLINKAT(handle,
				link_contents,
				dirfsp,
				new_smb_fname);
}

static int shadow_copy2_linkat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags)
{
	time_t timestamp_old = 0;
	time_t timestamp_new = 0;
	char *snappath_old = NULL;
	char *snappath_new = NULL;

	if (!shadow_copy2_strip_snapshot_internal(talloc_tos(),
				handle,
				old_smb_fname,
				&timestamp_old,
				NULL,
				&snappath_old,
				NULL)) {
		return -1;
	}
	if (!shadow_copy2_strip_snapshot_internal(talloc_tos(),
				handle,
				new_smb_fname,
				&timestamp_new,
				NULL,
				&snappath_new,
				NULL)) {
		return -1;
	}
	if ((timestamp_old != 0) || (timestamp_new != 0)) {
		errno = EROFS;
		return -1;
	}
	/*
	 * Don't allow links on already converted paths.
	 */
	if ((snappath_old != NULL) || (snappath_new != NULL)) {
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

static int shadow_copy2_stat(vfs_handle_struct *handle,
			     struct smb_filename *smb_fname)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	char *tmp;
	int saved_errno = 0;
	int ret;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname,
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
	if (ret == -1) {
		saved_errno = errno;
	}

	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = tmp;

	if (ret == 0) {
		convert_sbuf(handle, smb_fname->base_name, &smb_fname->st);
	}
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int shadow_copy2_lstat(vfs_handle_struct *handle,
			      struct smb_filename *smb_fname)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	char *tmp;
	int saved_errno = 0;
	int ret;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname,
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
	if (ret == -1) {
		saved_errno = errno;
	}

	TALLOC_FREE(smb_fname->base_name);
	smb_fname->base_name = tmp;

	if (ret == 0) {
		convert_sbuf(handle, smb_fname->base_name, &smb_fname->st);
	}
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int shadow_copy2_fstat(vfs_handle_struct *handle, files_struct *fsp,
			      SMB_STRUCT_STAT *sbuf)
{
	time_t timestamp = 0;
	struct smb_filename *orig_smb_fname = NULL;
	struct smb_filename vss_smb_fname;
	struct smb_filename *orig_base_smb_fname = NULL;
	struct smb_filename vss_base_smb_fname;
	char *stripped = NULL;
	int saved_errno = 0;
	bool ok;
	int ret;

	ok = shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 fsp->fsp_name,
					 &timestamp, &stripped);
	if (!ok) {
		return -1;
	}

	if (timestamp == 0) {
		TALLOC_FREE(stripped);
		return SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	}

	vss_smb_fname = *fsp->fsp_name;
	vss_smb_fname.base_name = shadow_copy2_convert(talloc_tos(),
						       handle,
						       stripped,
						       timestamp);
	TALLOC_FREE(stripped);
	if (vss_smb_fname.base_name == NULL) {
		return -1;
	}

	orig_smb_fname = fsp->fsp_name;
	fsp->fsp_name = &vss_smb_fname;

	if (fsp->base_fsp != NULL) {
		vss_base_smb_fname = *fsp->base_fsp->fsp_name;
		vss_base_smb_fname.base_name = vss_smb_fname.base_name;
		orig_base_smb_fname = fsp->base_fsp->fsp_name;
		fsp->base_fsp->fsp_name = &vss_base_smb_fname;
	}

	ret = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	fsp->fsp_name = orig_smb_fname;
	if (fsp->base_fsp != NULL) {
		fsp->base_fsp->fsp_name = orig_base_smb_fname;
	}
	if (ret == -1) {
		saved_errno = errno;
	}

	if (ret == 0) {
		convert_sbuf(handle, fsp->fsp_name->base_name, sbuf);
	}
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int shadow_copy2_openat(vfs_handle_struct *handle,
			       const struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname_in,
			       struct files_struct *fsp,
			       int flags,
			       mode_t mode)
{
	struct smb_filename *smb_fname = NULL;
	time_t timestamp = 0;
	char *stripped = NULL;
	bool is_converted = false;
	int saved_errno = 0;
	int ret;
	bool ok;

	ok = shadow_copy2_strip_snapshot_converted(talloc_tos(),
						   handle,
						   smb_fname_in,
						   &timestamp,
						   &stripped,
						   &is_converted);
	if (!ok) {
		return -1;
	}
	if (timestamp == 0) {
		if (is_converted) {
			/*
			 * Just pave over the user requested mode and use
			 * O_RDONLY. Later attempts by the client to write on
			 * the handle will fail in the pwrite() syscall with
			 * EINVAL which we carefully map to EROFS. In sum, this
			 * matches Windows behaviour.
			 */
			flags &= ~(O_WRONLY | O_RDWR | O_CREAT);
		}
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname_in,
					   fsp,
					   flags,
					   mode);
	}

	smb_fname = cp_smb_filename(talloc_tos(), smb_fname_in);
	if (smb_fname == NULL) {
		TALLOC_FREE(stripped);
		errno = ENOMEM;
		return -1;
	}

	smb_fname->base_name = shadow_copy2_convert(smb_fname,
					       handle,
					       stripped,
					       timestamp);
	TALLOC_FREE(stripped);
	if (smb_fname->base_name == NULL) {
		TALLOC_FREE(smb_fname);
		errno = ENOMEM;
		return -1;
	}

	/*
	 * Just pave over the user requested mode and use O_RDONLY. Later
	 * attempts by the client to write on the handle will fail in the
	 * pwrite() syscall with EINVAL which we carefully map to EROFS. In sum,
	 * this matches Windows behaviour.
	 */
	flags &= ~(O_WRONLY | O_RDWR | O_CREAT);

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

static int shadow_copy2_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	time_t timestamp = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname,
					 &timestamp, NULL)) {
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp,
			smb_fname,
			flags);
}

static int shadow_copy2_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	time_t timestamp = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
				handle,
				smb_fname,
				&timestamp,
				NULL)) {
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
}

static void store_cwd_data(vfs_handle_struct *handle,
				const char *connectpath)
{
	struct shadow_copy2_private *priv = NULL;
	struct smb_filename *cwd_fname = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return);

	TALLOC_FREE(priv->shadow_cwd);
	cwd_fname = SMB_VFS_NEXT_GETWD(handle, talloc_tos());
	if (cwd_fname == NULL) {
		smb_panic("getwd failed\n");
	}
	DBG_DEBUG("shadow cwd = %s\n", cwd_fname->base_name);
	priv->shadow_cwd = talloc_strdup(priv, cwd_fname->base_name);
	TALLOC_FREE(cwd_fname);
	if (priv->shadow_cwd == NULL) {
		smb_panic("talloc failed\n");
	}
	TALLOC_FREE(priv->shadow_connectpath);
	if (connectpath) {
		DBG_DEBUG("shadow connectpath = %s\n", connectpath);
		priv->shadow_connectpath = talloc_strdup(priv, connectpath);
		if (priv->shadow_connectpath == NULL) {
			smb_panic("talloc failed\n");
		}
	}
}

static int shadow_copy2_chdir(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	char *snappath = NULL;
	int ret = -1;
	int saved_errno = 0;
	char *conv = NULL;
	size_t rootpath_len = 0;
	struct smb_filename *conv_smb_fname = NULL;

	if (!shadow_copy2_strip_snapshot_internal(talloc_tos(),
					handle,
					smb_fname,
					&timestamp,
					&stripped,
					&snappath,
					NULL)) {
		return -1;
	}
	if (stripped != NULL) {
		conv = shadow_copy2_do_convert(talloc_tos(),
						handle,
						stripped,
						timestamp,
						&rootpath_len);
		TALLOC_FREE(stripped);
		if (conv == NULL) {
			return -1;
		}
		conv_smb_fname = synthetic_smb_fname(talloc_tos(),
					conv,
					NULL,
					NULL,
					0,
					smb_fname->flags);
	} else {
		conv_smb_fname = cp_smb_filename(talloc_tos(), smb_fname);
	}

	if (conv_smb_fname == NULL) {
		TALLOC_FREE(conv);
		errno = ENOMEM;
		return -1;
	}

	ret = SMB_VFS_NEXT_CHDIR(handle, conv_smb_fname);
	if (ret == -1) {
		saved_errno = errno;
	}

	if (ret == 0) {
		if (conv != NULL && rootpath_len != 0) {
			conv[rootpath_len] = '\0';
		} else if (snappath != 0) {
			TALLOC_FREE(conv);
			conv = snappath;
		}
		store_cwd_data(handle, conv);
	}

	TALLOC_FREE(stripped);
	TALLOC_FREE(conv);
	TALLOC_FREE(conv_smb_fname);

	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int shadow_copy2_ntimes(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname,
			       struct smb_file_time *ft)
{
	time_t timestamp = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname,
					 &timestamp, NULL)) {
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
}

static int shadow_copy2_readlinkat(vfs_handle_struct *handle,
				files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				char *buf,
				size_t bufsiz)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	int saved_errno = 0;
	int ret;
	struct smb_filename *conv = NULL;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname,
					 &timestamp, &stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_READLINKAT(handle,
				dirfsp,
				smb_fname,
				buf,
				bufsiz);
	}
	conv = cp_smb_filename(talloc_tos(), smb_fname);
	if (conv == NULL) {
		TALLOC_FREE(stripped);
		errno = ENOMEM;
		return -1;
	}
	conv->base_name = shadow_copy2_convert(
		conv, handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv->base_name == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_READLINKAT(handle,
				dirfsp,
				conv,
				buf,
				bufsiz);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(conv);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int shadow_copy2_mknodat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	time_t timestamp = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
					 smb_fname,
					 &timestamp, NULL)) {
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_MKNODAT(handle,
			dirfsp,
			smb_fname,
			mode,
			dev);
}

static struct smb_filename *shadow_copy2_realpath(vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	struct smb_filename *result_fname = NULL;
	struct smb_filename *conv_fname = NULL;
	int saved_errno = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle,
				smb_fname,
				&timestamp, &stripped)) {
		goto done;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);
	}

	conv_fname = cp_smb_filename(talloc_tos(), smb_fname);
	if (conv_fname == NULL) {
		goto done;
	}
	conv_fname->base_name = shadow_copy2_convert(
		conv_fname, handle, stripped, timestamp);
	if (conv_fname->base_name == NULL) {
		goto done;
	}

	result_fname = SMB_VFS_NEXT_REALPATH(handle, ctx, conv_fname);

done:
	if (result_fname == NULL) {
		saved_errno = errno;
	}
	TALLOC_FREE(conv_fname);
	TALLOC_FREE(stripped);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return result_fname;
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
	struct shadow_copy2_private *priv;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return NULL);

	ZERO_STRUCT(smb_fname);
	smb_fname.base_name = talloc_asprintf(talloc_tos(), "%s/%s",
					      path, priv->config->snapdir);
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

static bool check_access_snapdir(struct vfs_handle_struct *handle,
				const char *path)
{
	struct smb_filename smb_fname;
	int ret;
	NTSTATUS status;

	ZERO_STRUCT(smb_fname);
	smb_fname.base_name = talloc_asprintf(talloc_tos(),
						"%s",
						path);
	if (smb_fname.base_name == NULL) {
		return false;
	}

	ret = SMB_VFS_NEXT_STAT(handle, &smb_fname);
	if (ret != 0 || !S_ISDIR(smb_fname.st.st_ex_mode)) {
		TALLOC_FREE(smb_fname.base_name);
		return false;
	}

	status = smbd_check_access_rights(handle->conn,
					handle->conn->cwd_fsp,
					&smb_fname,
					false,
					SEC_DIR_LIST);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("user does not have list permission "
			"on snapdir %s\n",
			smb_fname.base_name));
		TALLOC_FREE(smb_fname.base_name);
		return false;
	}
	TALLOC_FREE(smb_fname.base_name);
	return true;
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
	struct shadow_copy2_private *priv;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return NULL);

	config = priv->config;

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
	struct shadow_copy2_private *priv;
	char *tmpstr = NULL;
	char *tmp = NULL;
	bool converted = false;
	int ret = -1;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return NULL);

	config = priv->config;

	fmt = config->gmt_format;

	/*
	 * If regex is provided, then we will have to parse the
	 * filename which will contain both the prefix and the time format.
	 * e.g. <prefix><delimiter><time_format>
	 */
	if (priv->snaps->regex != NULL) {
		tmpstr = talloc_strdup(talloc_tos(), name);
		/* point "name" to the time format */
		name = strstr(name, priv->config->delimiter);
		if (name == NULL) {
			goto done;
		}
		/* Extract the prefix */
		tmp = strstr(tmpstr, priv->config->delimiter);
		if (tmp == NULL) {
			goto done;
		}
		*tmp = '\0';

		/* Parse regex */
		ret = regexec(priv->snaps->regex, tmpstr, 0, NULL, 0);
		if (ret) {
			DBG_DEBUG("shadow_copy2_snapshot_to_gmt: "
				  "no regex match for %s\n", tmpstr);
			goto done;
		}
	}

	ZERO_STRUCT(timestamp);
	if (config->use_sscanf) {
		if (sscanf(name, fmt, &timestamp_long) != 1) {
			DEBUG(10, ("shadow_copy2_snapshot_to_gmt: "
				   "no sscanf match %s: %s\n",
				   fmt, name));
			goto done;
		}
		timestamp_t = timestamp_long;
		gmtime_r(&timestamp_t, &timestamp);
	} else {
		if (strptime(name, fmt, &timestamp) == NULL) {
			DEBUG(10, ("shadow_copy2_snapshot_to_gmt: "
				   "no match %s: %s\n",
				   fmt, name));
			goto done;
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
	converted = true;

done:
	TALLOC_FREE(tmpstr);
	return converted;
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
	struct shadow_copy2_private *priv;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return);

	sort = priv->config->sort_order;
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
	DIR *p = NULL;
	const char *snapdir;
	struct smb_filename *snapdir_smb_fname = NULL;
	struct files_struct *dirfsp = NULL;
	struct files_struct *fspcwd = NULL;
	struct dirent *d;
	TALLOC_CTX *tmp_ctx = talloc_stackframe();
	struct shadow_copy2_private *priv = NULL;
	struct shadow_copy2_snapentry *tmpentry = NULL;
	bool get_snaplist = false;
	bool access_granted = false;
	int open_flags = O_RDONLY;
	int ret = -1;
	NTSTATUS status;

	snapdir = shadow_copy2_find_snapdir(tmp_ctx, handle, fsp->fsp_name);
	if (snapdir == NULL) {
		DEBUG(0,("shadow:snapdir not found for %s in get_shadow_copy_data\n",
			 handle->conn->connectpath));
		errno = EINVAL;
		goto done;
	}

	access_granted = check_access_snapdir(handle, snapdir);
	if (!access_granted) {
		DEBUG(0,("access denied on listing snapdir %s\n", snapdir));
		errno = EACCES;
		goto done;
	}

	snapdir_smb_fname = synthetic_smb_fname(talloc_tos(),
					snapdir,
					NULL,
					NULL,
					0,
					fsp->fsp_name->flags);
	if (snapdir_smb_fname == NULL) {
		errno = ENOMEM;
		goto done;
	}

	status = create_internal_dirfsp(handle->conn,
					snapdir_smb_fname,
					&dirfsp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_WARNING("create_internal_dir_fsp() failed for '%s'"
			    " - %s\n", snapdir, nt_errstr(status));
		errno = ENOSYS;
		goto done;
	}

	status = vfs_at_fspcwd(talloc_tos(), handle->conn, &fspcwd);
	if (!NT_STATUS_IS_OK(status)) {
		errno = ENOMEM;
		goto done;
	}

#ifdef O_DIRECTORY
	open_flags |= O_DIRECTORY;
#endif

	dirfsp->fh->fd = SMB_VFS_NEXT_OPENAT(handle,
					     fspcwd,
					     snapdir_smb_fname,
					     dirfsp,
					     open_flags,
					     0);
	if (dirfsp->fh->fd == -1) {
		DBG_WARNING("SMB_VFS_NEXT_OPEN failed for '%s'"
			    " - %s\n", snapdir, strerror(errno));
		errno = ENOSYS;
		goto done;
	}

	p = SMB_VFS_NEXT_FDOPENDIR(handle, dirfsp, NULL, 0);
	if (!p) {
		DBG_NOTICE("shadow_copy2: SMB_VFS_NEXT_FDOPENDIR() failed for '%s'"
			   " - %s\n", snapdir, strerror(errno));
		errno = ENOSYS;
		goto done;
	}

	if (shadow_copy2_data != NULL) {
		shadow_copy2_data->num_volumes = 0;
		shadow_copy2_data->labels      = NULL;
	}

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				goto done);

	/*
	 * Normally this function is called twice once with labels = false and
	 * then with labels = true. When labels is false it will return the
	 * number of volumes so that the caller can allocate memory for that
	 * many labels. Therefore to eliminate snaplist both the times it is
	 * good to check if labels is set or not.
	 *
	 * shadow_copy2_data is NULL when we only want to update the list and
	 * don't want any labels.
	 */
	if ((priv->snaps->regex != NULL) && (labels || shadow_copy2_data == NULL)) {
		get_snaplist = true;
		/* Reset the global snaplist */
		shadow_copy2_delete_snaplist(priv);

		/* Set the current time as snaplist update time */
		time(&(priv->snaps->fetch_time));
	}

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

		if (get_snaplist) {
			/*
			 * Create a snap entry for each successful
			 * pattern match.
			 */
			tmpentry = shadow_copy2_create_snapentry(priv);
			if (tmpentry == NULL) {
				DBG_ERR("talloc_zero() failed\n");
				goto done;
			}
			tmpentry->snapname = talloc_strdup(tmpentry, d->d_name);
			tmpentry->time_fmt = talloc_strdup(tmpentry, snapshot);
		}

		if (shadow_copy2_data == NULL) {
			continue;
		}

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
			goto done;
		}

		strlcpy(tlabels[shadow_copy2_data->num_volumes], snapshot,
			sizeof(*tlabels));

		shadow_copy2_data->num_volumes++;
		shadow_copy2_data->labels = tlabels;
	}

	shadow_copy2_sort_data(handle, shadow_copy2_data);
	ret = 0;

done:
	TALLOC_FREE(fspcwd );
	if (p != NULL) {
		SMB_VFS_NEXT_CLOSEDIR(handle, p);
		p = NULL;
		if (dirfsp != NULL) {
			/*
			 * VFS_CLOSEDIR implicitly
			 * closed the associated fd.
			 */
			dirfsp->fh->fd = -1;
		}
	}
	if (dirfsp != NULL) {
		fd_close(dirfsp);
		file_free(NULL, dirfsp);
	}
	TALLOC_FREE(tmp_ctx);
	return ret;
}

static NTSTATUS shadow_copy2_get_nt_acl_at(vfs_handle_struct *handle,
					struct files_struct *dirfsp,
					const struct smb_filename *smb_fname,
					uint32_t security_info,
					TALLOC_CTX *mem_ctx,
					struct security_descriptor **ppdesc)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	NTSTATUS status;
	char *conv;
	struct smb_filename *conv_smb_fname = NULL;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
					handle,
					smb_fname,
					&timestamp,
					&stripped)) {
		return map_nt_error_from_unix(errno);
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
					dirfsp,
					smb_fname,
					security_info,
					mem_ctx,
					ppdesc);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return map_nt_error_from_unix(errno);
	}
	conv_smb_fname = synthetic_smb_fname(talloc_tos(),
					conv,
					NULL,
					NULL,
					0,
					smb_fname->flags);
	if (conv_smb_fname == NULL) {
		TALLOC_FREE(conv);
		return NT_STATUS_NO_MEMORY;
	}
	status = SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
					dirfsp,
					conv_smb_fname,
					security_info,
					mem_ctx,
					ppdesc);
	TALLOC_FREE(conv);
	TALLOC_FREE(conv_smb_fname);
	return status;
}

static int shadow_copy2_mkdirat(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				mode_t mode)
{
	time_t timestamp = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
					handle,
					smb_fname,
					&timestamp,
					NULL)) {
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_MKDIRAT(handle,
			dirfsp,
			smb_fname,
			mode);
}

static int shadow_copy2_chflags(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				unsigned int flags)
{
	time_t timestamp = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
					handle,
					smb_fname,
					&timestamp,
					NULL)) {
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_CHFLAGS(handle, smb_fname, flags);
}

static ssize_t shadow_copy2_getxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *aname,
				void *value,
				size_t size)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	ssize_t ret;
	int saved_errno = 0;
	char *conv;
	struct smb_filename *conv_smb_fname = NULL;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
				handle,
				smb_fname,
				&timestamp,
				&stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GETXATTR(handle, smb_fname, aname, value,
					     size);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}

	conv_smb_fname = synthetic_smb_fname(talloc_tos(),
					conv,
					NULL,
					NULL,
					0,
					smb_fname->flags);
	if (conv_smb_fname == NULL) {
		TALLOC_FREE(conv);
		return -1;
	}

	ret = SMB_VFS_NEXT_GETXATTR(handle, conv_smb_fname, aname, value, size);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(conv_smb_fname);
	TALLOC_FREE(conv);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static ssize_t shadow_copy2_listxattr(struct vfs_handle_struct *handle,
				      const struct smb_filename *smb_fname,
				      char *list, size_t size)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	ssize_t ret;
	int saved_errno = 0;
	char *conv;
	struct smb_filename *conv_smb_fname = NULL;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
				handle,
				smb_fname,
				&timestamp,
				&stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_LISTXATTR(handle, smb_fname, list, size);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	conv_smb_fname = synthetic_smb_fname(talloc_tos(),
					conv,
					NULL,
					NULL,
					0,
					smb_fname->flags);
	if (conv_smb_fname == NULL) {
		TALLOC_FREE(conv);
		return -1;
	}
	ret = SMB_VFS_NEXT_LISTXATTR(handle, conv_smb_fname, list, size);
	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(conv_smb_fname);
	TALLOC_FREE(conv);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int shadow_copy2_removexattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *aname)
{
	time_t timestamp = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
				handle,
				smb_fname,
				&timestamp,
				NULL)) {
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_REMOVEXATTR(handle, smb_fname, aname);
}

static int shadow_copy2_setxattr(struct vfs_handle_struct *handle,
				 const struct smb_filename *smb_fname,
				 const char *aname, const void *value,
				 size_t size, int flags)
{
	time_t timestamp = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
				handle,
				smb_fname,
				&timestamp,
				NULL)) {
		return -1;
	}
	if (timestamp != 0) {
		errno = EROFS;
		return -1;
	}
	return SMB_VFS_NEXT_SETXATTR(handle, smb_fname,
				aname, value, size, flags);
}

static NTSTATUS shadow_copy2_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	time_t timestamp = 0;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
					handle,
					smb_fname,
					&timestamp,
					NULL)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (timestamp != 0) {
		return NT_STATUS_MEDIA_WRITE_PROTECTED;
	}
	return SMB_VFS_NEXT_CREATE_DFS_PATHAT(handle,
			dirfsp,
			smb_fname,
			reflist,
			referral_count);
}

static NTSTATUS shadow_copy2_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	struct smb_filename *conv = NULL;
	NTSTATUS status;

	if (!shadow_copy2_strip_snapshot(mem_ctx,
					handle,
					smb_fname,
					&timestamp,
					&stripped)) {
		return NT_STATUS_NO_MEMORY;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_READ_DFS_PATHAT(handle,
					mem_ctx,
					dirfsp,
					smb_fname,
					ppreflist,
					preferral_count);
	}

	conv = cp_smb_filename(mem_ctx, smb_fname);
	if (conv == NULL) {
		TALLOC_FREE(stripped);
		return NT_STATUS_NO_MEMORY;
	}
	conv->base_name = shadow_copy2_convert(conv,
					handle,
					stripped,
					timestamp);
	TALLOC_FREE(stripped);
	if (conv->base_name == NULL) {
		TALLOC_FREE(conv);
		return NT_STATUS_NO_MEMORY;
	}

	status = SMB_VFS_NEXT_READ_DFS_PATHAT(handle,
				mem_ctx,
				dirfsp,
				conv,
				ppreflist,
				preferral_count);

	if (NT_STATUS_IS_OK(status)) {
		/* Return any stat(2) info. */
		smb_fname->st = conv->st;
	}

	TALLOC_FREE(conv);
	return status;
}

static int shadow_copy2_get_real_filename(struct vfs_handle_struct *handle,
					  const struct smb_filename *fname,
					  const char *name,
					  TALLOC_CTX *mem_ctx,
					  char **found_name)
{
	struct shadow_copy2_private *priv = NULL;
	struct shadow_copy2_config *config = NULL;
	time_t timestamp = 0;
	char *stripped = NULL;
	ssize_t ret;
	int saved_errno = 0;
	char *conv;
	struct smb_filename conv_fname;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return -1);
	config = priv->config;

	DBG_DEBUG("Path=[%s] name=[%s]\n", smb_fname_str_dbg(fname), name);

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, fname,
					 &timestamp, &stripped)) {
		DEBUG(10, ("shadow_copy2_strip_snapshot failed\n"));
		return -1;
	}
	if (timestamp == 0) {
		DEBUG(10, ("timestamp == 0\n"));
		return SMB_VFS_NEXT_GET_REAL_FILENAME(handle, fname, name,
						      mem_ctx, found_name);
	}

	/*
	 * Note that stripped may be an empty string "" if path was ".". As
	 * shadow_copy2_convert() combines "" with the shadow-copy tree connect
	 * root fullpath and get_real_filename_full_scan() has an explicit check
	 * for "" this works.
	 */
	DBG_DEBUG("stripped [%s]\n", stripped);

	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	if (conv == NULL) {
		if (!config->snapdirseverywhere) {
			DBG_DEBUG("shadow_copy2_convert [%s] failed\n", stripped);
			return -1;
		}

		/*
		 * We're called in the path traversal loop in unix_convert()
		 * walking down the directory hierarchy. shadow_copy2_convert()
		 * will fail if the snapshot directory is futher down in the
		 * hierachy. Set conv to the original stripped path and try to
		 * look it up in the filesystem with
		 * SMB_VFS_NEXT_GET_REAL_FILENAME() or
		 * get_real_filename_full_scan().
		 */
		DBG_DEBUG("Use stripped [%s] as conv\n", stripped);
		conv = talloc_strdup(talloc_tos(), stripped);
		if (conv == NULL) {
			TALLOC_FREE(stripped);
			return -1;
		}
	}

	conv_fname = (struct smb_filename) {
		.base_name = conv,
	};

	DEBUG(10, ("Calling NEXT_GET_REAL_FILE_NAME for conv=[%s], "
		   "name=[%s]\n", conv, name));
	ret = SMB_VFS_NEXT_GET_REAL_FILENAME(handle, &conv_fname, name,
					     mem_ctx, found_name);
	DEBUG(10, ("NEXT_REAL_FILE_NAME returned %d\n", (int)ret));
	if (ret == 0) {
		return 0;
	}
	if (errno != EOPNOTSUPP) {
		TALLOC_FREE(conv);
		errno = EOPNOTSUPP;
		return -1;
	}

	ret = get_real_filename_full_scan(handle->conn,
					  conv,
					  name,
					  false,
					  mem_ctx,
					  found_name);
	if (ret != 0) {
		saved_errno = errno;
		DBG_DEBUG("Scan [%s] for [%s] failed\n",
			  conv, name);
		errno = saved_errno;
		return -1;
	}

	DBG_DEBUG("Scan [%s] for [%s] returned [%s]\n",
		  conv, name, *found_name);

	TALLOC_FREE(conv);
	return 0;
}

static const char *shadow_copy2_connectpath(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname_in)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	char *tmp = NULL;
	const char *fname = smb_fname_in->base_name;
	struct smb_filename smb_fname = {0};
	struct smb_filename *result_fname = NULL;
	char *result = NULL;
	char *parent_dir = NULL;
	int saved_errno = 0;
	size_t rootpath_len = 0;
	struct shadow_copy2_private *priv = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, priv, struct shadow_copy2_private,
				return NULL);

	DBG_DEBUG("Calc connect path for [%s]\n", fname);

	if (priv->shadow_connectpath != NULL) {
		DBG_DEBUG("cached connect path is [%s]\n",
			priv->shadow_connectpath);
		return priv->shadow_connectpath;
	}

	if (!shadow_copy2_strip_snapshot(talloc_tos(), handle, smb_fname_in,
					 &timestamp, &stripped)) {
		goto done;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_CONNECTPATH(handle, smb_fname_in);
	}

	tmp = shadow_copy2_do_convert(talloc_tos(), handle, stripped, timestamp,
				      &rootpath_len);
	if (tmp == NULL) {
		if (errno != ENOENT) {
			goto done;
		}

		/*
		 * If the converted path does not exist, and converting
		 * the parent yields something that does exist, then
		 * this path refers to something that has not been
		 * created yet, relative to the parent path.
		 * The snapshot finding is relative to the parent.
		 * (usually snapshots are read/only but this is not
		 * necessarily true).
		 * This code also covers getting a wildcard in the
		 * last component, because this function is called
		 * prior to sanitizing the path, and in SMB1 we may
		 * get wildcards in path names.
		 */
		if (!parent_dirname(talloc_tos(), stripped, &parent_dir,
				    NULL)) {
			errno = ENOMEM;
			goto done;
		}

		tmp = shadow_copy2_do_convert(talloc_tos(), handle, parent_dir,
					      timestamp, &rootpath_len);
		if (tmp == NULL) {
			goto done;
		}
	}

	DBG_DEBUG("converted path is [%s] root path is [%.*s]\n", tmp,
		  (int)rootpath_len, tmp);

	tmp[rootpath_len] = '\0';
	smb_fname = (struct smb_filename) { .base_name = tmp };

	result_fname = SMB_VFS_NEXT_REALPATH(handle, priv, &smb_fname);
	if (result_fname == NULL) {
		goto done;
	}

	/*
	 * SMB_VFS_NEXT_REALPATH returns a talloc'ed string.
	 * Don't leak memory.
	 */
	TALLOC_FREE(priv->shadow_realpath);
	priv->shadow_realpath = result_fname;
	result = priv->shadow_realpath->base_name;

	DBG_DEBUG("connect path is [%s]\n", result);

done:
	if (result == NULL) {
		saved_errno = errno;
	}
	TALLOC_FREE(tmp);
	TALLOC_FREE(stripped);
	TALLOC_FREE(parent_dir);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return result;
}

static uint64_t shadow_copy2_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	int saved_errno = 0;
	char *conv = NULL;
	struct smb_filename *conv_smb_fname = NULL;
	uint64_t ret = (uint64_t)-1;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
				handle,
				smb_fname,
				&timestamp,
				&stripped)) {
		return (uint64_t)-1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_DISK_FREE(handle, smb_fname,
					      bsize, dfree, dsize);
	}
	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return (uint64_t)-1;
	}
	conv_smb_fname = synthetic_smb_fname(talloc_tos(),
					conv,
					NULL,
					NULL,
					0,
					smb_fname->flags);
	if (conv_smb_fname == NULL) {
		TALLOC_FREE(conv);
		return (uint64_t)-1;
	}
	ret = SMB_VFS_NEXT_DISK_FREE(handle, conv_smb_fname,
				bsize, dfree, dsize);
	if (ret == (uint64_t)-1) {
		saved_errno = errno;
	}
	TALLOC_FREE(conv);
	TALLOC_FREE(conv_smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int shadow_copy2_get_quota(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *dq)
{
	time_t timestamp = 0;
	char *stripped = NULL;
	int ret;
	int saved_errno = 0;
	char *conv;
	struct smb_filename *conv_smb_fname = NULL;

	if (!shadow_copy2_strip_snapshot(talloc_tos(),
				handle,
				smb_fname,
				&timestamp,
				&stripped)) {
		return -1;
	}
	if (timestamp == 0) {
		return SMB_VFS_NEXT_GET_QUOTA(handle, smb_fname, qtype, id, dq);
	}

	conv = shadow_copy2_convert(talloc_tos(), handle, stripped, timestamp);
	TALLOC_FREE(stripped);
	if (conv == NULL) {
		return -1;
	}
	conv_smb_fname = synthetic_smb_fname(talloc_tos(),
					conv,
					NULL,
					NULL,
					0,
					smb_fname->flags);
	if (conv_smb_fname == NULL) {
		TALLOC_FREE(conv);
		return -1;
	}
	ret = SMB_VFS_NEXT_GET_QUOTA(handle, conv_smb_fname, qtype, id, dq);

	if (ret == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(conv);
	TALLOC_FREE(conv_smb_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}

	return ret;
}

static ssize_t shadow_copy2_pwrite(vfs_handle_struct *handle,
				   files_struct *fsp,
				   const void *data,
				   size_t n,
				   off_t offset)
{
	ssize_t nwritten;

	nwritten = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);
	if (nwritten == -1) {
		if (errno == EBADF && fsp->fsp_flags.can_write) {
			errno = EROFS;
		}
	}

	return nwritten;
}

struct shadow_copy2_pwrite_state {
	vfs_handle_struct *handle;
	files_struct *fsp;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void shadow_copy2_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *shadow_copy2_pwrite_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	const void *data, size_t n, off_t offset)
{
	struct tevent_req *req = NULL, *subreq = NULL;
	struct shadow_copy2_pwrite_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct shadow_copy2_pwrite_state);
	if (req == NULL) {
		return NULL;
	}
	state->handle = handle;
	state->fsp = fsp;

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state,
					  ev,
					  handle,
					  fsp,
					  data,
					  n,
					  offset);
	if (tevent_req_nomem(subreq, req)) {
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, shadow_copy2_pwrite_done, req);

	return req;
}

static void shadow_copy2_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct shadow_copy2_pwrite_state *state = tevent_req_data(
		req, struct shadow_copy2_pwrite_state);

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	if (state->ret == -1) {
		tevent_req_error(req, state->vfs_aio_state.error);
		return;
	}

	tevent_req_done(req);
}

static ssize_t shadow_copy2_pwrite_recv(struct tevent_req *req,
					  struct vfs_aio_state *vfs_aio_state)
{
	struct shadow_copy2_pwrite_state *state = tevent_req_data(
		req, struct shadow_copy2_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		if ((vfs_aio_state->error == EBADF) &&
		    state->fsp->fsp_flags.can_write)
		{
			vfs_aio_state->error = EROFS;
			errno = EROFS;
		}
		return -1;
	}

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static int shadow_copy2_connect(struct vfs_handle_struct *handle,
				const char *service, const char *user)
{
	struct shadow_copy2_config *config;
	struct shadow_copy2_private *priv;
	int ret;
	const char *snapdir;
	const char *snapprefix = NULL;
	const char *delimiter;
	const char *gmt_format;
	const char *sort_order;
	const char *basedir = NULL;
	const char *snapsharepath = NULL;
	const char *mount_point;

	DEBUG(10, (__location__ ": cnum[%u], connectpath[%s]\n",
		   (unsigned)handle->conn->cnum,
		   handle->conn->connectpath));

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	priv = talloc_zero(handle->conn, struct shadow_copy2_private);
	if (priv == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	priv->snaps = talloc_zero(priv, struct shadow_copy2_snaplist_info);
	if (priv->snaps == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}

	config = talloc_zero(priv, struct shadow_copy2_config);
	if (config == NULL) {
		DEBUG(0, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	priv->config = config;

	gmt_format = lp_parm_const_string(SNUM(handle->conn),
					  "shadow", "format",
					  GMT_FORMAT);
	config->gmt_format = talloc_strdup(config, gmt_format);
	if (config->gmt_format == NULL) {
		DEBUG(0, ("talloc_strdup() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	/* config->gmt_format must not contain a path separator. */
	if (strchr(config->gmt_format, '/') != NULL) {
		DEBUG(0, ("shadow:format %s must not contain a /"
			"character. Unable to initialize module.\n",
			config->gmt_format));
		errno = EINVAL;
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

	snapprefix = lp_parm_const_string(SNUM(handle->conn),
				       "shadow", "snapprefix",
				       NULL);
	if (snapprefix != NULL) {
		priv->snaps->regex = talloc_zero(priv->snaps, regex_t);
		if (priv->snaps->regex == NULL) {
			DBG_ERR("talloc_zero() failed\n");
			errno = ENOMEM;
			return -1;
		}

		/* pre-compute regex rule for matching pattern later */
		ret = regcomp(priv->snaps->regex, snapprefix, 0);
		if (ret) {
			DBG_ERR("Failed to create regex object\n");
			return -1;
		}
	}

	delimiter = lp_parm_const_string(SNUM(handle->conn),
				       "shadow", "delimiter",
				       "_GMT");
	if (delimiter != NULL) {
		priv->config->delimiter = talloc_strdup(priv->config, delimiter);
		if (priv->config->delimiter == NULL) {
			DBG_ERR("talloc_strdup() failed\n");
			errno = ENOMEM;
			return -1;
		}
	}

	config->snapdirseverywhere = lp_parm_bool(SNUM(handle->conn),
						  "shadow",
						  "snapdirseverywhere",
						  false);

	config->crossmountpoints = lp_parm_bool(SNUM(handle->conn),
						"shadow", "crossmountpoints",
						false);

	if (config->crossmountpoints && !config->snapdirseverywhere) {
		DBG_WARNING("Warning: 'crossmountpoints' depends on "
			    "'snapdirseverywhere'. Disabling crossmountpoints.\n");
	}

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
				DBG_WARNING("Warning: the share root (%s) is "
					    "not a subdirectory of the "
					    "specified mountpoint (%s). "
					    "Ignoring provided value.\n",
					    handle->conn->connectpath,
					    mount_point);
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
			DBG_WARNING("shadow_copy2_find_mount_point "
				    "of the share root '%s' failed: %s\n",
				    handle->conn->connectpath, strerror(errno));
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
			basedir = NULL;
		} else {
			char *p;
			p = strstr(basedir, config->mount_point);
			if (p != basedir) {
				DEBUG(1, ("Warning: basedir (%s) is not a "
					  "subdirectory of the share root's "
					  "mount point (%s). "
					  "Disabling basedir\n",
					  basedir, config->mount_point));
				basedir = NULL;
			}
		}
	}

	if (config->snapdirseverywhere && basedir != NULL) {
		DEBUG(1, (__location__ " Warning: 'basedir' is incompatible "
			  "with 'snapdirseverywhere'. Disabling basedir.\n"));
		basedir = NULL;
	}

	snapsharepath = lp_parm_const_string(SNUM(handle->conn), "shadow",
					     "snapsharepath", NULL);
	if (snapsharepath != NULL) {
		if (snapsharepath[0] == '/') {
			DBG_WARNING("Warning: 'snapsharepath' is "
				    "absolute ('%s'), but it has to be a "
				    "relative path. Disabling snapsharepath.\n",
				    snapsharepath);
			snapsharepath = NULL;
		}
		if (config->snapdirseverywhere && snapsharepath != NULL) {
			DBG_WARNING("Warning: 'snapsharepath' is incompatible "
				    "with 'snapdirseverywhere'. Disabling "
				    "snapsharepath.\n");
			snapsharepath = NULL;
		}
	}

	if (basedir != NULL && snapsharepath != NULL) {
		DBG_WARNING("Warning: 'snapsharepath' is incompatible with "
			    "'basedir'. Disabling snapsharepath\n");
		snapsharepath = NULL;
	}

	if (snapsharepath != NULL) {
		config->rel_connectpath = talloc_strdup(config, snapsharepath);
		if (config->rel_connectpath == NULL) {
			DBG_ERR("talloc_strdup() failed\n");
			errno = ENOMEM;
			return -1;
		}
	}

	if (basedir == NULL) {
		basedir = config->mount_point;
	}

	if (config->rel_connectpath == NULL &&
	    strlen(basedir) < strlen(handle->conn->connectpath)) {
		config->rel_connectpath = talloc_strdup(config,
			handle->conn->connectpath + strlen(basedir));
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

	trim_string(config->mount_point, NULL, "/");
	trim_string(config->rel_connectpath, "/", "/");
	trim_string(config->snapdir, NULL, "/");
	trim_string(config->snapshot_basepath, NULL, "/");

	DEBUG(10, ("shadow_copy2_connect: configuration:\n"
		   "  share root: '%s'\n"
		   "  mountpoint: '%s'\n"
		   "  rel share root: '%s'\n"
		   "  snapdir: '%s'\n"
		   "  snapprefix: '%s'\n"
		   "  delimiter: '%s'\n"
		   "  snapshot base path: '%s'\n"
		   "  format: '%s'\n"
		   "  use sscanf: %s\n"
		   "  snapdirs everywhere: %s\n"
		   "  cross mountpoints: %s\n"
		   "  fix inodes: %s\n"
		   "  sort order: %s\n"
		   "",
		   handle->conn->connectpath,
		   config->mount_point,
		   config->rel_connectpath,
		   config->snapdir,
		   snapprefix,
		   config->delimiter,
		   config->snapshot_basepath,
		   config->gmt_format,
		   config->use_sscanf ? "yes" : "no",
		   config->snapdirseverywhere ? "yes" : "no",
		   config->crossmountpoints ? "yes" : "no",
		   config->fixinodes ? "yes" : "no",
		   config->sort_order
		   ));


	SMB_VFS_HANDLE_SET_DATA(handle, priv,
				NULL, struct shadow_copy2_private,
				return -1);

	return 0;
}

static struct vfs_fn_pointers vfs_shadow_copy2_fns = {
	.connect_fn = shadow_copy2_connect,
	.disk_free_fn = shadow_copy2_disk_free,
	.get_quota_fn = shadow_copy2_get_quota,
	.create_dfs_pathat_fn = shadow_copy2_create_dfs_pathat,
	.read_dfs_pathat_fn = shadow_copy2_read_dfs_pathat,
	.renameat_fn = shadow_copy2_renameat,
	.linkat_fn = shadow_copy2_linkat,
	.symlinkat_fn = shadow_copy2_symlinkat,
	.stat_fn = shadow_copy2_stat,
	.lstat_fn = shadow_copy2_lstat,
	.fstat_fn = shadow_copy2_fstat,
	.openat_fn = shadow_copy2_openat,
	.unlinkat_fn = shadow_copy2_unlinkat,
	.chmod_fn = shadow_copy2_chmod,
	.chdir_fn = shadow_copy2_chdir,
	.ntimes_fn = shadow_copy2_ntimes,
	.readlinkat_fn = shadow_copy2_readlinkat,
	.mknodat_fn = shadow_copy2_mknodat,
	.realpath_fn = shadow_copy2_realpath,
	.get_nt_acl_at_fn = shadow_copy2_get_nt_acl_at,
	.get_shadow_copy_data_fn = shadow_copy2_get_shadow_copy_data,
	.mkdirat_fn = shadow_copy2_mkdirat,
	.getxattr_fn = shadow_copy2_getxattr,
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.listxattr_fn = shadow_copy2_listxattr,
	.removexattr_fn = shadow_copy2_removexattr,
	.setxattr_fn = shadow_copy2_setxattr,
	.chflags_fn = shadow_copy2_chflags,
	.get_real_filename_fn = shadow_copy2_get_real_filename,
	.pwrite_fn = shadow_copy2_pwrite,
	.pwrite_send_fn = shadow_copy2_pwrite_send,
	.pwrite_recv_fn = shadow_copy2_pwrite_recv,
	.connectpath_fn = shadow_copy2_connectpath,
};

static_decl_vfs;
NTSTATUS vfs_shadow_copy2_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"shadow_copy2", &vfs_shadow_copy2_fns);
}
