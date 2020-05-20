/*
 * Samba VFS module supporting multiple AVID clients sharing media.
 *
 * Copyright (C) 2005  Philip de Nier <philipn@users.sourceforge.net>
 * Copyright (C) 2012  Andrew Klaassen <clawsoon@yahoo.com>
 * Copyright (C) 2013  Milos Lukacek
 * Copyright (C) 2013  Ralph Boehme <slow@samba.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/*
 * Unityed Media is a Samba VFS module that allows multiple AVID
 * clients to share media.
 *
 * Add this module to the vfs objects option in your Samba share
 * configuration.
 * eg.
 *
 *   [avid_win]
 *	path = /video
 *	vfs objects = unityed_media
 *	...
 *
 * It is recommended that you separate out Samba shares for Mac
 * and Windows clients, and add the following options to the shares
 * for Windows clients	(NOTE: replace @ with *):
 *
 *	veto files = /.DS_Store/._@/.Trash@/.Spotlight@/.hidden/.hotfiles@/.vol/
 *	delete veto files = yes
 *
 * This prevents hidden files from Mac clients interfering with Windows
 * clients. If you find any more problem hidden files then add them to
 * the list.
 *
 * Notes:
 * This module is designed to work with AVID editing applications that
 * look in the Avid MediaFiles or OMFI MediaFiles directory for media.
 * It is not designed to work as expected in all circumstances for
 * general use.
 */


#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "../smbd/globals.h"
#include "auth.h"
#include "../lib/tsocket/tsocket.h"
#include <libgen.h>

#define UM_PARAM_TYPE_NAME "unityed_media"

static const char *AVID_MXF_DIRNAME = "Avid MediaFiles/MXF";
static const size_t AVID_MXF_DIRNAME_LEN = 19;
static const char *OMFI_MEDIAFILES_DIRNAME = "OMFI MediaFiles";
static const size_t OMFI_MEDIAFILES_DIRNAME_LEN = 15;
static const char *APPLE_DOUBLE_PREFIX = "._";
static const size_t APPLE_DOUBLE_PREFIX_LEN = 2;
static int vfs_um_debug_level = DBGC_VFS;

enum um_clientid {UM_CLIENTID_NAME, UM_CLIENTID_IP, UM_CLIENTID_HOSTNAME};

struct um_config_data {
	enum um_clientid clientid;
};

static const struct enum_list um_clientid[] = {
	{UM_CLIENTID_NAME, "user"},
	{UM_CLIENTID_IP, "ip"},
	{UM_CLIENTID_HOSTNAME, "hostname"},
	{-1, NULL}
};

/* supplements the directory list stream */
typedef struct um_dirinfo_struct {
	DIR* dirstream;
	char *dirpath;
	char *clientPath;
	bool isInMediaFiles;
	char *clientSubDirname;
} um_dirinfo_struct;

/**
 * Returns true and first group of digits in path, false and 0 otherwise
 **/
static bool get_digit_group(const char *path, uintmax_t *digit)
{
	const char *p = path;
	codepoint_t cp;
	size_t size;
	int error = 0;

	DEBUG(10, ("get_digit_group entering with path '%s'\n",
		   path));

	/*
	 * Delibiretly initialize to 0 because callers use this result
	 * even though the string doesn't contain any number and we
	 * returned false
	 */
	*digit = 0;

	while (*p) {
		cp = next_codepoint(p, &size);
		if (cp == -1) {
			return false;
		}
		if ((size == 1) && (isdigit(cp))) {
			*digit = (uintmax_t)smb_strtoul(p,
							NULL,
							10,
							&error,
							SMB_STR_STANDARD);
			if (error != 0) {
				return false;
			}
			DEBUG(10, ("num_suffix = '%ju'\n",
				   *digit));
			return true;
		}
		p += size;
	}

	return false;
}

/* Add "_<remote_name>.<number>" suffix to path or filename.
 *
 * Success: return 0
 * Failure: set errno, path NULL, return -1
 */

static int alloc_append_client_suffix(vfs_handle_struct *handle,
				      char **path)
{
	int status = 0;
	uintmax_t number;
	const char *clientid;
	struct um_config_data *config;

	DEBUG(10, ("Entering with path '%s'\n", *path));

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct um_config_data,
				return -1);

	(void)get_digit_group(*path, &number);

	switch (config->clientid) {

	case UM_CLIENTID_IP:
		clientid = tsocket_address_inet_addr_string(
			handle->conn->sconn->remote_address, talloc_tos());
		if (clientid == NULL) {
			errno = ENOMEM;
			status = -1;
			goto err;
		}
		break;

	case UM_CLIENTID_HOSTNAME:
		clientid = get_remote_machine_name();
		break;

	case UM_CLIENTID_NAME:
	default:
		clientid = get_current_username();
		break;
	}

	*path = talloc_asprintf_append(*path, "_%s.%ju",
				       clientid, number);
	if (*path == NULL) {
		DEBUG(1, ("alloc_append_client_suffix "
				     "out of memory\n"));
		errno = ENOMEM;
		status = -1;
		goto err;
	}
	DEBUG(10, ("Leaving with *path '%s'\n", *path));
err:
	return status;
}

/* Returns true if the file or directory begins with the appledouble
 * prefix.
 */
static bool is_apple_double(const char* fname)
{
	bool ret = false;

	DEBUG(10, ("Entering with fname '%s'\n", fname));

	if (strnequal(APPLE_DOUBLE_PREFIX, fname, APPLE_DOUBLE_PREFIX_LEN)) {
		ret = true;
	}
	DEBUG(10, ("Leaving with ret '%s'\n",
			      ret == true ? "true" : "false"));
	return ret;
}

static bool starts_with_media_dir(const char* media_dirname,
				  size_t media_dirname_len,
				  const char *path)
{
	bool ret = false;
	const char *path_start = path;

	DEBUG(10, ("Entering with media_dirname '%s' "
			      "path '%s'\n", media_dirname, path));

	/* Sometimes Samba gives us "./OMFI MediaFiles". */
	if (strnequal(path, "./", 2)) {
		path_start += 2;
	}

	if (strnequal(media_dirname, path_start, media_dirname_len)
	    &&
	    ((path_start[media_dirname_len] == '\0') ||
	     (path_start[media_dirname_len] == '/'))) {
		ret = true;
	}

	DEBUG(10, ("Leaving with ret '%s'\n",
			      ret == true ? "true" : "false"));
	return ret;
}

/*
 * Returns true if the file or directory referenced by the path is ONE
 * LEVEL below the AVID_MXF_DIRNAME or OMFI_MEDIAFILES_DIRNAME
 * directory
 */
static bool is_in_media_dir(const char *path)
{
	int transition_count = 0;
	const char *path_start = path;
	const char *p;
	const char *media_dirname;
	size_t media_dirname_len;

	DEBUG(10, ("Entering with path'%s' ", path));

	/* Sometimes Samba gives us "./OMFI MediaFiles". */
	if (strnequal(path, "./", 2)) {
		path_start += 2;
	}

	if (strnequal(path_start, AVID_MXF_DIRNAME, AVID_MXF_DIRNAME_LEN)) {
		media_dirname = AVID_MXF_DIRNAME;
		media_dirname_len = AVID_MXF_DIRNAME_LEN;
	} else if (strnequal(path_start,
			     OMFI_MEDIAFILES_DIRNAME,
			     OMFI_MEDIAFILES_DIRNAME_LEN)) {
		media_dirname = OMFI_MEDIAFILES_DIRNAME;
		media_dirname_len = OMFI_MEDIAFILES_DIRNAME_LEN;
	} else {
		return false;
	}

	if (path_start[media_dirname_len] == '\0') {
		goto out;
	}

	p = path_start + media_dirname_len + 1;

	while (true) {
		if (*p == '\0' || *p == '/') {
			if (strnequal(p - 3, "/..", 3)) {
				transition_count--;
			} else if ((p[-1] != '/') || !strnequal(p - 2, "/.", 2)) {
				transition_count++;
			}
		}
		if (*p == '\0') {
			break;
		}
		p++;
	}

out:
	DEBUG(10, ("Going out with transition_count '%i'\n",
			      transition_count));
	if (((transition_count == 1) && (media_dirname == AVID_MXF_DIRNAME))
	    ||
	    ((transition_count == 0) && (media_dirname == OMFI_MEDIAFILES_DIRNAME))) {
		return true;
	}
	else return false;
}

/*
 * Returns true if the file or directory referenced by the path is
 * below the AVID_MEDIAFILES_DIRNAME or OMFI_MEDIAFILES_DIRNAME
 * directory The AVID_MEDIAFILES_DIRNAME and OMFI_MEDIAFILES_DIRNAME
 * are assumed to be in the root directory, which is generally a safe
 * assumption in the fixed-path world of Avid.
 */
static bool is_in_media_files(const char *path)
{
	bool ret = false;

	DEBUG(10, ("Entering with path '%s'\n", path));

	if (starts_with_media_dir(AVID_MXF_DIRNAME,
				  AVID_MXF_DIRNAME_LEN, path) ||
	    starts_with_media_dir(OMFI_MEDIAFILES_DIRNAME,
				  OMFI_MEDIAFILES_DIRNAME_LEN, path)) {
		ret = true;
	}
	DEBUG(10, ("Leaving with ret '%s'\n",
			      ret == true ? "true" : "false"));
	return ret;
}


/* Add client suffix to "pure-number" path.
 *
 * Caller must free newPath.
 *
 * Success: return 0
 * Failure: set errno, newPath NULL, return -1
 */
static int alloc_get_client_path(vfs_handle_struct *handle,
				 TALLOC_CTX *ctx,
				 const char *path_in,
				 char **path_out)
{
	int status = 0;
	char *p;
	char *digits;
	size_t digits_len;
	uintmax_t number;

	*path_out = talloc_strdup(ctx, path_in);
        if (*path_out == NULL) {
		DEBUG(1, ("alloc_get_client_path ENOMEM\n"));
		return -1;
	}

	(void)get_digit_group(*path_out, &number);

	digits = talloc_asprintf(NULL, "%ju", number);
        if (digits == NULL) {
		DEBUG(1, ("alloc_get_client_path ENOMEM\n"));
		return -1;
	}
	digits_len = strlen(digits);

	p = strstr_m(path_in, digits);
	if ((p)
	    &&
	    ((p[digits_len] == '\0') || (p[digits_len] == '/'))
	    &&
	    (((p - path_in > 0) && (p[-1] == '/'))
	     ||
	     (((p - path_in) > APPLE_DOUBLE_PREFIX_LEN)
	      &&
	      is_apple_double(p - APPLE_DOUBLE_PREFIX_LEN)
	      &&
	      (p[-(APPLE_DOUBLE_PREFIX_LEN + 1)] == '/'))))
	{
		(*path_out)[p - path_in + digits_len] = '\0';

		status = alloc_append_client_suffix(handle, path_out);
		if (status != 0) {
			goto out;
		}

                *path_out = talloc_strdup_append(*path_out, p + digits_len);
		if (*path_out == NULL) {
			DEBUG(1, ("alloc_get_client_path ENOMEM\n"));
			status = -1;
			goto out;
		}
	}
out:
	/* path_out must be freed in caller. */
	DEBUG(10, ("Result:'%s'\n", *path_out));
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int alloc_get_client_smb_fname(struct vfs_handle_struct *handle,
				      TALLOC_CTX *ctx,
				      const struct smb_filename *smb_fname,
				      struct smb_filename **client_fname)
{
	int status ;

	DEBUG(10, ("Entering with smb_fname->base_name '%s'\n",
		   smb_fname->base_name));

	*client_fname = cp_smb_filename(ctx, smb_fname);
	if (*client_fname == NULL) {
		DEBUG(1, ("cp_smb_filename returned NULL\n"));
		return -1;
	}
	status = alloc_get_client_path(handle, ctx,
				       smb_fname->base_name,
				       &(*client_fname)->base_name);
	if (status != 0) {
		return -1;
	}

	DEBUG(10, ("Leaving with (*client_fname)->base_name "
		   "'%s'\n", (*client_fname)->base_name));

	return 0;
}


/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int alloc_set_client_dirinfo_path(struct vfs_handle_struct *handle,
					 TALLOC_CTX *ctx,
					 char **path,
					 const char *suffix_number)
{
	int status;

	DEBUG(10, ("Entering with suffix_number '%s'\n",
		   suffix_number));

	*path = talloc_strdup(ctx, suffix_number);
	if (*path == NULL) {
		DEBUG(1, ("alloc_set_client_dirinfo_path ENOMEM\n"));
		return -1;
	}
	status = alloc_append_client_suffix(handle, path);
	if (status != 0) {
		return -1;
	}

	DEBUG(10, ("Leaving with *path '%s'\n", *path));

	return 0;
}

static int alloc_set_client_dirinfo(vfs_handle_struct *handle,
				    const char *fname,
				    struct um_dirinfo_struct **di_result)
{
	int status = 0;
	char *digits;
	uintmax_t number;
	struct um_dirinfo_struct *dip;

	DEBUG(10, ("Entering with fname '%s'\n", fname));

	*di_result = talloc(NULL, struct um_dirinfo_struct);
	if (*di_result == NULL) {
		goto err;
	}
	dip = *di_result;

	dip->dirpath = talloc_strdup(dip, fname);
	if (dip->dirpath == NULL) {
		goto err;
	}

	if (!is_in_media_files(fname)) {
		dip->isInMediaFiles = false;
		dip->clientPath = NULL;
		dip->clientSubDirname = NULL;
		goto out;
	}

	dip->isInMediaFiles = true;

	(void)get_digit_group(fname, &number);
	digits = talloc_asprintf(talloc_tos(), "%ju", number);
	if (digits == NULL) {
		goto err;
	}

	status = alloc_set_client_dirinfo_path(handle, dip,
					       &dip->clientSubDirname,
					       digits);
	if (status != 0) {
		goto err;
	}

	status = alloc_get_client_path(handle, dip, fname,
				       &dip->clientPath);
	if (status != 0 || dip->clientPath == NULL) {
		goto err;
	}

out:
	DEBUG(10, ("Leaving with (*dirInfo)->dirpath '%s', "
			      "(*dirInfo)->clientPath '%s'\n",
			      dip->dirpath, dip->clientPath));
	return status;

err:
	DEBUG(1, ("Failing with fname '%s'\n", fname));
	TALLOC_FREE(*di_result);
	status = -1;
	errno = ENOMEM;
	return status;
}

/**********************************************************************
 * VFS functions
 **********************************************************************/

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int um_statvfs(struct vfs_handle_struct *handle,
		      const struct smb_filename *smb_fname,
		      struct vfs_statvfs_struct *statbuf)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering with path '%s'\n", smb_fname->base_name));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_STATVFS(handle, smb_fname, statbuf);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_STATVFS(handle, client_fname, statbuf);
err:
	TALLOC_FREE(client_fname);
	DEBUG(10, ("Leaving with path '%s'\n", smb_fname->base_name));
	return status;
}

static DIR *um_fdopendir(vfs_handle_struct *handle,
			 files_struct *fsp,
			 const char *mask,
			 uint32_t attr)
{
	struct um_dirinfo_struct *dirInfo = NULL;
	DIR *dirstream;

	DEBUG(10, ("Entering with fsp->fsp_name->base_name '%s'\n",
		   fsp->fsp_name->base_name));

	dirstream = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);
	if (!dirstream) {
		goto err;
	}

	if (alloc_set_client_dirinfo(handle,
				     fsp->fsp_name->base_name,
				     &dirInfo)) {
		goto err;
	}

	dirInfo->dirstream = dirstream;

	if (!dirInfo->isInMediaFiles) {
		/*
		 * FIXME: this is the original code, something must be
		 * missing here, but what? -slow
		 */
		goto out;
	}

out:
	DEBUG(10, ("Leaving with dirInfo->dirpath '%s', "
		   "dirInfo->clientPath '%s', "
		   "fsp->fsp_name->st.st_ex_mtime %s",
		   dirInfo->dirpath,
		   dirInfo->clientPath,
		   ctime(&(fsp->fsp_name->st.st_ex_mtime.tv_sec))));
	return (DIR *) dirInfo;

err:
	DEBUG(1, ("Failing with fsp->fsp_name->base_name '%s'\n",
		  fsp->fsp_name->base_name));
	TALLOC_FREE(dirInfo);
	return NULL;
}

/*
 * skip own suffixed directory
 * replace own suffixed directory with non suffixed.
 *
 * Success: return dirent
 * End of data: return NULL
 * Failure: set errno, return NULL
 */
static struct dirent *um_readdir(vfs_handle_struct *handle,
				 DIR *dirp,
				 SMB_STRUCT_STAT *sbuf)
{
	um_dirinfo_struct* dirInfo = (um_dirinfo_struct*)dirp;
	struct dirent *d = NULL;
	int skip;

	DEBUG(10, ("dirInfo->dirpath '%s', "
		   "dirInfo->clientPath '%s', "
		   "dirInfo->isInMediaFiles '%s', "
		   "dirInfo->clientSubDirname '%s'\n",
		   dirInfo->dirpath,
		   dirInfo->clientPath,
		   dirInfo->isInMediaFiles ? "true" : "false",
		   dirInfo->clientSubDirname));

	if (!dirInfo->isInMediaFiles) {
		return SMB_VFS_NEXT_READDIR(handle, dirInfo->dirstream, sbuf);
	}

	do {
		const char* dname;
		bool isAppleDouble;
		char *digits;
		size_t digits_len;
		uintmax_t number;

		skip = false;
		d = SMB_VFS_NEXT_READDIR(handle, dirInfo->dirstream, sbuf);

		if (d == NULL) {
			break;
		}

		/* ignore apple double prefix for logic below */
		if (is_apple_double(d->d_name)) {
			dname = &d->d_name[APPLE_DOUBLE_PREFIX_LEN];
			isAppleDouble = true;
		} else {
			dname = d->d_name;
			isAppleDouble = false;
		}

		DEBUG(10, ("dname = '%s'\n", dname));

		(void)get_digit_group(dname, &number);
		digits = talloc_asprintf(talloc_tos(), "%ju", number);
		if (digits == NULL) {
			DEBUG(1, ("out of memory"));
			goto err;
		}
		digits_len = strlen(digits);

		if (alloc_set_client_dirinfo_path(handle,
						  dirInfo,
						  &((dirInfo)->clientSubDirname),
						  digits)) {
			goto err;
		}

		/*
		 * If set to "true", vfs shows digits-only
		 * non-suffixed subdirectories.  Normally, such
		 * subdirectories can exists only in non-media
		 * directories, so we set it to "false".  Otherwise,
		 * if we have such subdirectories (probably created
		 * over not "unityed" connection), it can be little
		 * bit confusing.
		 */
		if (strequal(dname, digits)) {
			skip = false;
		} else if (strequal(dname, dirInfo->clientSubDirname)) {
			/*
			 * Remove suffix of this client's suffixed
			 * subdirectories
			 */
			if (isAppleDouble) {
				d->d_name[digits_len + APPLE_DOUBLE_PREFIX_LEN] = '\0';
			} else {
				d->d_name[digits_len] = '\0';
			}
		} else if (strnequal(digits, dname, digits_len)) {
			/*
			 * Set to false to see another clients subdirectories
			 */
			skip = false;
		}
	} while (skip);

	DEBUG(10, ("Leaving um_readdir\n"));
	return d;
err:
	TALLOC_FREE(dirInfo);
	return NULL;
}

static void um_seekdir(vfs_handle_struct *handle,
		       DIR *dirp,
		       long offset)
{
	DEBUG(10, ("Entering and leaving um_seekdir\n"));
	SMB_VFS_NEXT_SEEKDIR(handle,
			     ((um_dirinfo_struct*)dirp)->dirstream, offset);
}

static long um_telldir(vfs_handle_struct *handle,
		       DIR *dirp)
{
	DEBUG(10, ("Entering and leaving um_telldir\n"));
	return SMB_VFS_NEXT_TELLDIR(handle,
				    ((um_dirinfo_struct*)dirp)->dirstream);
}

static void um_rewinddir(vfs_handle_struct *handle,
			 DIR *dirp)
{
	DEBUG(10, ("Entering and leaving um_rewinddir\n"));
	SMB_VFS_NEXT_REWINDDIR(handle,
			       ((um_dirinfo_struct*)dirp)->dirstream);
}

static int um_mkdirat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int status;
	const char *path = smb_fname->base_name;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering with path '%s'\n", path));

	if (!is_in_media_files(path) || !is_in_media_dir(path)) {
		return SMB_VFS_NEXT_MKDIRAT(handle,
				dirfsp,
				smb_fname,
				mode);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_MKDIRAT(handle,
				dirfsp,
				client_fname,
				mode);
err:
	TALLOC_FREE(client_fname);
	DEBUG(10, ("Leaving with path '%s'\n", path));
	return status;
}

static int um_closedir(vfs_handle_struct *handle,
		       DIR *dirp)
{
	DIR *realdirp = ((um_dirinfo_struct*)dirp)->dirstream;

	TALLOC_FREE(dirp);

	return SMB_VFS_NEXT_CLOSEDIR(handle, realdirp);
}

static int um_openat(struct vfs_handle_struct *handle,
		     const struct files_struct *dirfsp,
		     const struct smb_filename *smb_fname,
		     struct files_struct *fsp,
		     int flags,
		     mode_t mode)
{
	struct smb_filename *client_fname = NULL;
	int ret;

	DBG_DEBUG("Entering with smb_fname->base_name '%s'\n",
		  smb_fname->base_name);

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_OPENAT(handle,
					   dirfsp,
					   smb_fname,
					   fsp,
					   flags,
					   mode);
	}

	if (alloc_get_client_smb_fname(handle, talloc_tos(),
				       smb_fname,
				       &client_fname)) {
		ret = -1;
		goto err;
	}

	/*
	 * FIXME:
	 * What about fsp->fsp_name?  We also have to get correct stat
	 * info into fsp and smb_fname for DB files, don't we?
	 */

	DEBUG(10, ("Leaving with smb_fname->base_name '%s' "
		   "smb_fname->st.st_ex_mtime %s"
		   "fsp->fsp_name->st.st_ex_mtime %s",
		   smb_fname->base_name,
		   ctime(&(smb_fname->st.st_ex_mtime.tv_sec)),
		   ctime(&(fsp->fsp_name->st.st_ex_mtime.tv_sec))));

	ret = SMB_VFS_NEXT_OPENAT(handle,
				  dirfsp,
				  client_fname,
				  fsp,
				  flags,
				  mode);
err:
	TALLOC_FREE(client_fname);
	DEBUG(10, ("Leaving with smb_fname->base_name '%s'\n",
			      smb_fname->base_name));
	return ret;
}

static NTSTATUS um_create_file(vfs_handle_struct *handle,
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
			       files_struct **result_fsp,
			       int *pinfo,
			       const struct smb2_create_blobs *in_context_blobs,
			       struct smb2_create_blobs *out_context_blobs)
{
	NTSTATUS status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering with smb_fname->base_name '%s'\n",
		   smb_fname->base_name));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_CREATE_FILE(
			handle,
			req,
			dirfsp,
			smb_fname,
			access_mask,
			share_access,
			create_disposition,
			create_options,
			file_attributes,
			oplock_request,
			lease,
			allocation_size,
			private_flags,
			sd,
			ea_list,
			result_fsp,
			pinfo,
			in_context_blobs,
			out_context_blobs);
	}

	if (alloc_get_client_smb_fname(handle, talloc_tos(),
				       smb_fname,
				       &client_fname)) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	/*
	 * FIXME:
	 * This only creates files, so we don't have to worry about
	 * our fake directory stat'ing here.  But we still need to
	 * route stat calls for DB files properly, right?
	 */
	status = SMB_VFS_NEXT_CREATE_FILE(
		handle,
		req,
		dirfsp,
		client_fname,
		access_mask,
		share_access,
		create_disposition,
		create_options,
		file_attributes,
		oplock_request,
		lease,
		allocation_size,
		private_flags,
		sd,
		ea_list,
		result_fsp,
		pinfo,
		in_context_blobs,
		out_context_blobs);
err:
	TALLOC_FREE(client_fname);
	DEBUG(10, ("Leaving with smb_fname->base_name '%s'"
		   "smb_fname->st.st_ex_mtime %s"
		   " fsp->fsp_name->st.st_ex_mtime %s",
		   smb_fname->base_name,
		   ctime(&(smb_fname->st.st_ex_mtime.tv_sec)),
		   (*result_fsp) && VALID_STAT((*result_fsp)->fsp_name->st) ?
		   ctime(&((*result_fsp)->fsp_name->st.st_ex_mtime.tv_sec)) :
		   "No fsp time\n"));
	return status;
}

static int um_renameat(vfs_handle_struct *handle,
		files_struct *srcfsp,
		const struct smb_filename *smb_fname_src,
		files_struct *dstfsp,
		const struct smb_filename *smb_fname_dst)
{
	int status;
	struct smb_filename *src_client_fname = NULL;
	struct smb_filename *dst_client_fname = NULL;

	DEBUG(10, ("Entering with "
		   "smb_fname_src->base_name '%s', "
		   "smb_fname_dst->base_name '%s'\n",
		   smb_fname_src->base_name,
		   smb_fname_dst->base_name));

	if (!is_in_media_files(smb_fname_src->base_name)
	    &&
	    !is_in_media_files(smb_fname_dst->base_name)) {
		return SMB_VFS_NEXT_RENAMEAT(handle,
					srcfsp,
					smb_fname_src,
					dstfsp,
					smb_fname_dst);
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname_src,
					    &src_client_fname);
	if (status != 0) {
		goto err;
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname_dst,
					    &dst_client_fname);

	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_RENAMEAT(handle,
				srcfsp,
				src_client_fname,
				dstfsp,
				dst_client_fname);

err:
	TALLOC_FREE(dst_client_fname);
	TALLOC_FREE(src_client_fname);
	DEBUG(10, ("Leaving with smb_fname_src->base_name '%s',"
		   " smb_fname_dst->base_name '%s'\n",
		   smb_fname_src->base_name,
		   smb_fname_dst->base_name));
	return status;
}


/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int um_stat(vfs_handle_struct *handle,
		   struct smb_filename *smb_fname)
{
	int status = 0;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering with smb_fname->base_name '%s'\n",
		   smb_fname->base_name));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_STAT(handle, smb_fname);
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname,
					    &client_fname);
	if (status != 0) {
		goto err;
	}
	DEBUG(10, ("Stat'ing client_fname->base_name '%s'\n",
		   client_fname->base_name));

	status = SMB_VFS_NEXT_STAT(handle, client_fname);
	if (status != 0) {
		goto err;
	}

	/*
	 * Unlike functions with const smb_filename, we have to modify
	 * smb_fname itself to pass our info back up.
	 */
	DEBUG(10, ("Setting smb_fname '%s' stat from client_fname '%s'\n",
		   smb_fname->base_name, client_fname->base_name));
	smb_fname->st = client_fname->st;

err:
	TALLOC_FREE(client_fname);
	DEBUG(10, ("Leaving with smb_fname->st.st_ex_mtime %s",
		   ctime(&(smb_fname->st.st_ex_mtime.tv_sec))));
	return status;
}

static int um_lstat(vfs_handle_struct *handle,
		    struct smb_filename *smb_fname)
{
	int status = 0;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering with smb_fname->base_name '%s'\n",
		   smb_fname->base_name));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_LSTAT(handle, smb_fname);
	}

	client_fname = NULL;

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname,
					    &client_fname);
	if (status != 0) {
		goto err;
	}
	status = SMB_VFS_NEXT_LSTAT(handle, client_fname);
	if (status != 0) {
		goto err;
	}

	smb_fname->st = client_fname->st;

err:
	TALLOC_FREE(client_fname);
	DEBUG(10, ("Leaving with smb_fname->st.st_ex_mtime %s",
		   ctime(&(smb_fname->st.st_ex_mtime.tv_sec))));
	return status;
}

static int um_fstat(vfs_handle_struct *handle,
		    files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int status = 0;

	DEBUG(10, ("Entering with fsp->fsp_name->base_name "
		   "'%s'\n", fsp_str_dbg(fsp)));

	status = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);
	if (status != 0) {
		goto out;
	}

	if ((fsp->fsp_name == NULL) ||
	    !is_in_media_files(fsp->fsp_name->base_name)) {
		goto out;
	}

	status = um_stat(handle, fsp->fsp_name);
	if (status != 0) {
		goto out;
	}

	*sbuf = fsp->fsp_name->st;

out:
	DEBUG(10, ("Leaving with fsp->fsp_name->st.st_ex_mtime %s\n",
		   fsp->fsp_name != NULL ?
		   ctime(&(fsp->fsp_name->st.st_ex_mtime.tv_sec)) : "0"));
	return status;
}

static int um_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	int ret;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_unlinkat\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp,
				smb_fname,
				flags);
	}

	ret = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname,
					    &client_fname);
	if (ret != 0) {
		goto err;
	}

	ret = SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp,
				client_fname,
				flags);

err:
	TALLOC_FREE(client_fname);
	return ret;
}

static int um_chmod(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_chmod\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_CHMOD(handle, client_fname, mode);

err:
	TALLOC_FREE(client_fname);
	return status;
}

static int um_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_lchown\n"));
	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_LCHOWN(handle, client_fname, uid, gid);

err:
	TALLOC_FREE(client_fname);
	return status;
}

static int um_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_chdir\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_CHDIR(handle, smb_fname);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_CHDIR(handle, client_fname);

err:
	TALLOC_FREE(client_fname);
	return status;
}

static int um_ntimes(vfs_handle_struct *handle,
		     const struct smb_filename *smb_fname,
		     struct smb_file_time *ft)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_ntimes\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname, &client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_NTIMES(handle, client_fname, ft);

err:
	TALLOC_FREE(client_fname);
	return status;
}

static int um_symlinkat(vfs_handle_struct *handle,
			const struct smb_filename *link_contents,
			struct files_struct *dirfsp,
			const struct smb_filename *new_smb_fname)
{
	int status;
	struct smb_filename *new_link_target = NULL;
	struct smb_filename *new_client_fname = NULL;

	DEBUG(10, ("Entering um_symlinkat\n"));

	if (!is_in_media_files(link_contents->base_name) &&
			!is_in_media_files(new_smb_fname->base_name)) {
		return SMB_VFS_NEXT_SYMLINKAT(handle,
				link_contents,
				dirfsp,
				new_smb_fname);
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
				link_contents, &new_link_target);
	if (status != 0) {
		goto err;
	}
	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    new_smb_fname, &new_client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_SYMLINKAT(handle,
					new_link_target,
					dirfsp,
					new_client_fname);

err:
	TALLOC_FREE(new_link_target);
	TALLOC_FREE(new_client_fname);
	return status;
}

static int um_readlinkat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_readlinkat\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_READLINKAT(handle,
				dirfsp,
				smb_fname,
				buf,
				bufsiz);
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname, &client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_READLINKAT(handle,
				dirfsp,
				client_fname,
				buf,
				bufsiz);

err:
	TALLOC_FREE(client_fname);
	return status;
}

static int um_linkat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags)
{
	int status;
	struct smb_filename *old_client_fname = NULL;
	struct smb_filename *new_client_fname = NULL;

	DEBUG(10, ("Entering um_linkat\n"));
	if (!is_in_media_files(old_smb_fname->base_name) &&
				!is_in_media_files(new_smb_fname->base_name)) {
		return SMB_VFS_NEXT_LINKAT(handle,
				srcfsp,
				old_smb_fname,
				dstfsp,
				new_smb_fname,
				flags);
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    old_smb_fname, &old_client_fname);
	if (status != 0) {
		goto err;
	}
	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    new_smb_fname, &new_client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_LINKAT(handle,
				srcfsp,
				old_client_fname,
				dstfsp,
				new_client_fname,
				flags);

err:
	TALLOC_FREE(old_client_fname);
	TALLOC_FREE(new_client_fname);
	return status;
}

static int um_mknodat(vfs_handle_struct *handle,
		files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode,
		SMB_DEV_T dev)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_mknodat\n"));
	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_MKNODAT(handle,
				dirfsp,
				smb_fname,
				mode,
				dev);
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname, &client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_MKNODAT(handle,
			dirfsp,
			client_fname,
			mode,
			dev);

err:
	TALLOC_FREE(client_fname);
	return status;
}

static struct smb_filename *um_realpath(vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)
{
	struct smb_filename *client_fname = NULL;
	struct smb_filename *result_fname = NULL;
	int status;

	DEBUG(10, ("Entering um_realpath\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname, &client_fname);
	if (status != 0) {
		goto err;
	}

	result_fname = SMB_VFS_NEXT_REALPATH(handle, ctx, client_fname);

err:
	TALLOC_FREE(client_fname);
	return result_fname;
}

static int um_chflags(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			unsigned int flags)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_mknod\n"));
	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_CHFLAGS(handle, smb_fname, flags);
	}

	status = alloc_get_client_smb_fname(handle, talloc_tos(),
					    smb_fname, &client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_CHFLAGS(handle, client_fname, flags);

err:
	TALLOC_FREE(client_fname);
	return status;
}

static NTSTATUS um_streaminfo(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      const struct smb_filename *smb_fname,
			      TALLOC_CTX *ctx,
			      unsigned int *num_streams,
			      struct stream_struct **streams)
{
	NTSTATUS status;
	int ret;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_streaminfo\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_STREAMINFO(handle, fsp, smb_fname,
					       ctx, num_streams, streams);
	}

	ret = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (ret != 0) {
		status = NT_STATUS_NO_MEMORY;
		goto err;
	}

	/*
	 * This only works on files, so we don't have to worry about
	 * our fake directory stat'ing here.  But what does this
	 * function do, exactly?  Does it need extra modifications for
	 * the Avid stuff?
	 */
	status = SMB_VFS_NEXT_STREAMINFO(handle, fsp, client_fname,
					 ctx, num_streams, streams);
err:
	TALLOC_FREE(client_fname);
	return status;
}

/*
 * Ignoring get_real_filename function because the default doesn't do
 * anything.
 */

static NTSTATUS um_get_nt_acl_at(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			uint32_t security_info,
			TALLOC_CTX *mem_ctx,
			struct security_descriptor **ppdesc)
{
	NTSTATUS status;
	char *client_path = NULL;
	struct smb_filename *client_smb_fname = NULL;
	bool ok;
	int ret;

	DBG_DEBUG("Entering um_get_nt_acl_at\n");

	ok = is_in_media_files(smb_fname->base_name);
	if (!ok) {
		return SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
				dirfsp,
				smb_fname,
				security_info,
				mem_ctx,
				ppdesc);
	}

	ret = alloc_get_client_path(handle,
				talloc_tos(),
				smb_fname->base_name,
				&client_path);
	if (ret != 0) {
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	client_smb_fname = synthetic_smb_fname(talloc_tos(),
					client_path,
					NULL,
					NULL,
					smb_fname->twrp,
					smb_fname->flags);
	if (client_smb_fname == NULL) {
		TALLOC_FREE(client_path);
		return NT_STATUS_NO_MEMORY;
	}

	status = SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
				dirfsp,
				client_smb_fname,
				security_info,
				mem_ctx,
				ppdesc);
err:
	TALLOC_FREE(client_smb_fname);
	TALLOC_FREE(client_path);
	return status;
}

static SMB_ACL_T um_sys_acl_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T type,
				TALLOC_CTX *mem_ctx)
{
	SMB_ACL_T ret;
	int saved_errno = 0;
	struct smb_filename *client_fname = NULL;
	int status;

	DEBUG(10, ("Entering um_sys_acl_get_file\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, smb_fname,
						     type, mem_ctx);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		ret = (SMB_ACL_T)NULL;
		goto err;
	}

	ret = SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, client_fname,
				type, mem_ctx);

err:
	if (ret == (SMB_ACL_T)NULL) {
		saved_errno = errno;
	}
	TALLOC_FREE(client_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return ret;
}

static int um_sys_acl_set_file(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname,
			       SMB_ACL_TYPE_T acltype,
			       SMB_ACL_T theacl)
{
	int status;
	int saved_errno = 0;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_sys_acl_set_file\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, smb_fname,
						     acltype, theacl);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, client_fname,
					       acltype, theacl);

err:
	if (status == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(client_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return status;
}

static int um_sys_acl_delete_def_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
	int status;
	int saved_errno = 0;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_sys_acl_delete_def_file\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle,
				smb_fname);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, client_fname);

err:
	if (status == -1) {
		saved_errno = errno;
	}
	TALLOC_FREE(client_fname);
	if (saved_errno != 0) {
		errno = saved_errno;
	}
	return status;
}

static ssize_t um_getxattr(struct vfs_handle_struct *handle,
			   const struct smb_filename *smb_fname,
			   const char *name,
			   void *value,
			   size_t size)
{
	ssize_t ret;
	struct smb_filename *client_fname = NULL;
	int status;

	DEBUG(10, ("Entering um_getxattr\n"));
	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_GETXATTR(handle, smb_fname,
				name, value, size);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		ret = -1;
		goto err;
	}

	ret = SMB_VFS_NEXT_GETXATTR(handle, client_fname, name, value, size);
err:
	TALLOC_FREE(client_fname);
	return ret;
}

static ssize_t um_listxattr(struct vfs_handle_struct *handle,
			    const struct smb_filename *smb_fname,
			    char *list,
			    size_t size)
{
	ssize_t ret;
	struct smb_filename *client_fname = NULL;
	int status;

	DEBUG(10, ("Entering um_listxattr\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_LISTXATTR(handle, smb_fname, list, size);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		ret = -1;
		goto err;
	}

	ret = SMB_VFS_NEXT_LISTXATTR(handle, client_fname, list, size);

err:
	TALLOC_FREE(client_fname);
	return ret;
}

static int um_removexattr(struct vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname,
			  const char *name)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_removexattr\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_REMOVEXATTR(handle, smb_fname, name);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_REMOVEXATTR(handle, client_fname, name);

err:
	TALLOC_FREE(client_fname);
	return status;
}

static int um_setxattr(struct vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       const char *name,
		       const void *value,
		       size_t size,
		       int flags)
{
	int status;
	struct smb_filename *client_fname = NULL;

	DEBUG(10, ("Entering um_setxattr\n"));

	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_SETXATTR(handle, smb_fname, name, value,
					     size, flags);
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&client_fname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_SETXATTR(handle, client_fname, name, value,
				       size, flags);

err:
	TALLOC_FREE(client_fname);
	return status;
}

static int um_connect(vfs_handle_struct *handle,
			 const char *service,
			 const char *user)
{
	int rc;
	struct um_config_data *config;
	int enumval;

	rc = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (rc != 0) {
		return rc;
	}

	config = talloc_zero(handle->conn, struct um_config_data);
	if (!config) {
		DEBUG(1, ("talloc_zero() failed\n"));
		errno = ENOMEM;
		return -1;
	}

	enumval = lp_parm_enum(SNUM(handle->conn), UM_PARAM_TYPE_NAME,
			       "clientid", um_clientid, UM_CLIENTID_NAME);
	if (enumval == -1) {
		DEBUG(1, ("value for %s: type unknown\n",
			  UM_PARAM_TYPE_NAME));
		return -1;
	}
	config->clientid = (enum um_clientid)enumval;

	SMB_VFS_HANDLE_SET_DATA(handle, config,
				NULL, struct um_config_data,
				return -1);

	return 0;
}

/* VFS operations structure */

static struct vfs_fn_pointers vfs_um_fns = {
	.connect_fn = um_connect,

	/* Disk operations */

	.statvfs_fn = um_statvfs,

	/* Directory operations */

	.fdopendir_fn = um_fdopendir,
	.readdir_fn = um_readdir,
	.seekdir_fn = um_seekdir,
	.telldir_fn = um_telldir,
	.rewind_dir_fn = um_rewinddir,
	.mkdirat_fn = um_mkdirat,
	.closedir_fn = um_closedir,

	/* File operations */

	.openat_fn = um_openat,
	.create_file_fn = um_create_file,
	.renameat_fn = um_renameat,
	.stat_fn = um_stat,
	.lstat_fn = um_lstat,
	.fstat_fn = um_fstat,
	.unlinkat_fn = um_unlinkat,
	.chmod_fn = um_chmod,
	.lchown_fn = um_lchown,
	.chdir_fn = um_chdir,
	.ntimes_fn = um_ntimes,
	.symlinkat_fn = um_symlinkat,
	.readlinkat_fn = um_readlinkat,
	.linkat_fn = um_linkat,
	.mknodat_fn = um_mknodat,
	.realpath_fn = um_realpath,
	.chflags_fn = um_chflags,
	.streaminfo_fn = um_streaminfo,

	/* NT ACL operations. */

	.get_nt_acl_at_fn = um_get_nt_acl_at,

	/* POSIX ACL operations. */

	.sys_acl_get_file_fn = um_sys_acl_get_file,
	.sys_acl_set_file_fn = um_sys_acl_set_file,
	.sys_acl_delete_def_file_fn = um_sys_acl_delete_def_file,

	/* EA operations. */
	.getxattr_fn = um_getxattr,
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,
	.listxattr_fn = um_listxattr,
	.removexattr_fn = um_removexattr,
	.setxattr_fn = um_setxattr,
};

static_decl_vfs;
NTSTATUS vfs_unityed_media_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
					"unityed_media", &vfs_um_fns);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}

	vfs_um_debug_level = debug_add_class("unityed_media");

	if (vfs_um_debug_level == -1) {
		vfs_um_debug_level = DBGC_VFS;
		DEBUG(1, ("unityed_media_init: Couldn't register custom "
			  "debugging class.\n"));
	}

	return ret;
}
