/*
 * $Id: media_harmony.c,v 1.1 2007/11/06 10:07:22 stuart_hc Exp $
 *
 * Samba VFS module supporting multiple AVID clients sharing media.
 *
 * Copyright (C) 2005  Philip de Nier <philipn@users.sourceforge.net>
 * Copyright (C) 2012  Andrew Klaassen <clawsoon@yahoo.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */


/*
 * Media Harmony is a Samba VFS module that allows multiple AVID
 * clients to share media. Each client sees their own copy of the
 * AVID msmMMOB.mdb and msmFMID.pmr files and Creating directories.
 *
 * Add this module to the vfs objects option in your Samba share
 * configuration.
 * eg.
 *
 *   [avid_win]
 *	path = /video
 *	vfs objects = media_harmony
 *	...
 *
 * It is recommended that you separate out Samba shares for Mac
 * and Windows clients, and add the following options to the shares
 * for Windows clients  (NOTE: replace @ with *):
 *
 *	veto files = /.DS_Store/._@/.Trash@/.Spotlight@/.hidden/.hotfiles@/.vol/
 *	delete veto files = yes
 *
 * This prevents hidden files from Mac clients interfering with Windows
 * clients. If you find any more problem hidden files then add them to
 * the list.
 *
 *
 * Andrew Klaassen, 2012-03-14
 * To prevent Avid clients from interrupting each other (via Avid's habit
 * of launching a database refresh whenever it notices an mtime update
 * on media directories, i.e. whenever one editor adds new material to a
 * shared share), I've added code that causes stat information for anything
 * directly under "Avid MediaFile/MXF" to be taken from
 * dirname_clientaddr_clientuser if it exists.  These files ~aren't~
 * hidden, unlike the client-suffixed database files.
 *
 * For example, stat information for
 *	Avid MediaFiles/MXF/1
 * will come from
 *	Avid MediaFiles/MXF/1_192.168.1.10_dave
 * for dave working on 192.168.1.10, but will come from
 *	Avid MediaFile/MXF/1_192.168.1.11_susan
 * for susan working on 192.168.1.11.  If those alternate
 * directories don't exist, the user will get the actual directory's stat
 * info.  When an editor wants to force a database refresh, they update
 * the mtime on "their" file.  This will cause Avid
 * on that client to see an updated mtime for "Avid MediaFiles/MXF/1",
 * which will trigger an Avid database refresh just for that editor.
 *
 *
 * Notes:
 * - This module is designed to work with AVID editing applications that
 * look in the Avid MediaFiles or OMFI MediaFiles directory for media.
 * It is not designed to work as expected in all circumstances for
 * general use. For example: it is possibly to open client specific
 * files such as msmMMOB.mdb_192.168.1.10_userx even though is doesn't
 * show up in a directory listing.
 *
 */


#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "../smbd/globals.h"
#include "auth.h"
#include "../lib/tsocket/tsocket.h"

#define MH_INFO_DEBUG 10
#define MH_ERR_DEBUG 0

static const char* MDB_FILENAME = "msmMMOB.mdb";
static const size_t MDB_FILENAME_LEN = 11;
static const char* PMR_FILENAME = "msmFMID.pmr";
static const size_t PMR_FILENAME_LEN = 11;
static const char* CREATING_DIRNAME = "Creating";
static const size_t CREATING_DIRNAME_LEN = 8;
static const char* AVID_MEDIAFILES_DIRNAME = "Avid MediaFiles";
static const size_t AVID_MEDIAFILES_DIRNAME_LEN = 15;
static const char* OMFI_MEDIAFILES_DIRNAME = "OMFI MediaFiles";
static const size_t OMFI_MEDIAFILES_DIRNAME_LEN = 15;
static const char* APPLE_DOUBLE_PREFIX = "._";
static const size_t APPLE_DOUBLE_PREFIX_LEN = 2;
static const char* AVID_MXF_DIRNAME = "Avid MediaFiles/MXF";
static const size_t AVID_MXF_DIRNAME_LEN = 19;

static int vfs_mh_debug_level = DBGC_VFS;

/* supplements the directory list stream */
typedef struct mh_dirinfo_struct
{
	DIR* dirstream;
	char *dirpath;
	char *clientPath;
	bool isInMediaFiles;
	char *clientMDBFilename;
	char *clientPMRFilename;
	char *clientCreatingDirname;
} mh_dirinfo_struct;


/* Add "_<ip address>_<user name>" suffix to path or filename.
 *
 * Success: return 0
 * Failure: set errno, path NULL, return -1
 */
static int alloc_append_client_suffix(vfs_handle_struct *handle,
		char **path)
{
	int status = 0;
	char *raddr = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering with *path '%s'\n", *path));

	raddr = tsocket_address_inet_addr_string(
			handle->conn->sconn->remote_address, talloc_tos());
	if (raddr == NULL)
	{
		errno = ENOMEM;
		status = -1;
		goto err;
	}

	/* talloc_asprintf_append uses talloc_realloc, which
	 * frees original 'path' memory so we don't have to.
	 */
	*path = talloc_asprintf_append(*path, "_%s_%s",
		raddr,
		handle->conn->session_info->unix_info->sanitized_username);
	if (*path == NULL)
	{
		DEBUG(MH_ERR_DEBUG, ("alloc_append_client_suffix "
					"out of memory\n"));
		errno = ENOMEM;
		status = -1;
		goto err;
	}
	DEBUG(MH_INFO_DEBUG, ("Leaving with *path '%s'\n", *path));
err:
	TALLOC_FREE(raddr);
	return status;
}


/* Returns True if the file or directory begins with the appledouble
 * prefix.
 */
static bool is_apple_double(const char* fname)
{
	bool ret = False;

	DEBUG(MH_INFO_DEBUG, ("Entering with fname '%s'\n", fname));

	if (strncmp(APPLE_DOUBLE_PREFIX, fname, APPLE_DOUBLE_PREFIX_LEN)
			== 0)
	{
		ret = True;
	}
	DEBUG(MH_INFO_DEBUG, ("Leaving with ret '%s'\n",
				ret == True ? "True" : "False"));
	return ret;
}

static bool starts_with_media_dir(const char* media_dirname,
		size_t media_dirname_len, const char* path)
{
	bool ret = False;
	const char *path_start;

	DEBUG(MH_INFO_DEBUG, ("Entering with media_dirname '%s' "
			      "path '%s'\n", media_dirname, path));

	/* Sometimes Samba gives us "./OMFI MediaFiles". */
	if (strncmp(path, "./", 2) == 0)
	{
		path_start = &path[2];
	}
	else {
		path_start = path;
	}

	if (strncmp(media_dirname, path_start, media_dirname_len) == 0
			&&
		(
			path_start[media_dirname_len] == '\0'
			||
			path_start[media_dirname_len] == '/'
		)
	)
	{
		ret = True;
	}

	DEBUG(MH_INFO_DEBUG, ("Leaving with ret '%s'\n",
				ret == True ? "True" : "False"));
	return ret;
}

/*
 * Returns True if the file or directory referenced by the path is below
 * the AVID_MEDIAFILES_DIRNAME or OMFI_MEDIAFILES_DIRNAME directory
 * The AVID_MEDIAFILES_DIRNAME and OMFI_MEDIAFILES_DIRNAME are assumed to
 * be in the root directory, which is generally a safe assumption
 * in the fixed-path world of Avid.
 */
static bool is_in_media_files(const char* path)
{
	bool ret = False;

	DEBUG(MH_INFO_DEBUG, ("Entering with path '%s'\n", path));

	if (
		starts_with_media_dir(AVID_MEDIAFILES_DIRNAME,
				AVID_MEDIAFILES_DIRNAME_LEN, path)
		||
		starts_with_media_dir(OMFI_MEDIAFILES_DIRNAME,
				OMFI_MEDIAFILES_DIRNAME_LEN, path)
	)
	{
		ret = True;
	}
	DEBUG(MH_INFO_DEBUG, ("Leaving with ret '%s'\n",
				ret == True ? "True" : "False"));
	return ret;
}

/*
 * Returns depth of path under media directory.  Deals with the
 * occasional ..../. and ..../.. paths that get passed to stat.
 *
 * Assumes is_in_media_files has already been called and has returned
 * true for the path; if it hasn't, this function will likely crash
 * and burn.
 *
 * Not foolproof; something like "Avid MediaFiles/MXF/../foo/1"
 * would fool it.  Haven't seen paths like that getting to the
 * stat function yet, so ignoring that possibility for now.
 */
static int depth_from_media_dir(const char* media_dirname,
		size_t media_dirname_len, const char* path)
{
	int transition_count = 0;
	const char *path_start;
	const char *pathPtr;

	DEBUG(MH_INFO_DEBUG, ("Entering with media_dirname '%s' "
			      "path '%s'\n", media_dirname, path));

	/* Sometimes Samba gives us "./OMFI MediaFiles". */
	if (strncmp(path, "./", 2) == 0)
	{
		path_start = &path[2];
	}
	else {
		path_start = path;
	}

	if (path_start[media_dirname_len] == '\0')
	{
		goto out;
	}

	pathPtr = &path_start[media_dirname_len + 1];

	while(1)
	{
		if (*pathPtr == '\0' || *pathPtr == '/')
		{
			if (
				*(pathPtr - 1) == '.'
					&&
				*(pathPtr - 2) == '.'
					&&
				*(pathPtr - 3) == '/'
			)
			{
				transition_count--;
			}
			else if (
				!
				(
					*(pathPtr - 1) == '/'
					||
					(
						*(pathPtr - 1) == '.'
							&&
						*(pathPtr - 2) == '/'
					)
				)
			)
			{
				transition_count++;
			}
		}
		if (*pathPtr == '\0')
		{
			break;
		}
		pathPtr++;
	}

	DEBUG(MH_INFO_DEBUG, ("Leaving with transition_count '%i'\n",
				transition_count));
out:
	return transition_count;
}

/* Identifies MDB and PMR files at end of path. */
static bool is_avid_database(
		char *path,
		size_t path_len,
		const char *avid_db_filename,
		const size_t avid_db_filename_len)
{
	bool ret = False;

	DEBUG(MH_INFO_DEBUG, ("Entering with path '%s', "
			      "avid_db_filename '%s', "
			      "path_len '%i', "
			      "avid_db_filename_len '%i'\n",
			      path, avid_db_filename,
			      (int)path_len, (int)avid_db_filename_len));

	if (
		path_len > avid_db_filename_len
			&&
		strcmp(&path[path_len - avid_db_filename_len],
				avid_db_filename) == 0
			&&
		(
			path[path_len - avid_db_filename_len - 1] == '/'
			||
			(path_len > avid_db_filename_len
				+ APPLE_DOUBLE_PREFIX_LEN
				&&
			path[path_len - avid_db_filename_len
				- APPLE_DOUBLE_PREFIX_LEN - 1] == '/'
				&&
			is_apple_double(&path[path_len
				- avid_db_filename_len
				- APPLE_DOUBLE_PREFIX_LEN]))
		)
	)
	{
		ret = True;
	}
	DEBUG(MH_INFO_DEBUG, ("Leaving with ret '%s'\n",
				ret == True ? "True" : "False"));
	return ret;
}


/* Add client suffix to paths to MDB_FILENAME, PMR_FILENAME and
 * CREATING_SUBDIRNAME.
 *
 * Caller must free newPath.
 *
 * Success: return 0
 * Failure: set errno, newPath NULL, return -1
 */
static int alloc_get_client_path(vfs_handle_struct *handle,
		TALLOC_CTX *ctx,
		const char *path,
		char **newPath)
{
	/* replace /CREATING_DIRNAME/ or /._CREATING_DIRNAME/
	 * directory in path - potentially in middle of path
	 * - with suffixed name.
	 */
	int status = 0;
	char* pathPtr;
	size_t intermPathLen;

	DEBUG(MH_INFO_DEBUG, ("Entering with path '%s'\n", path));

	*newPath = talloc_strdup(ctx, path);
	if (*newPath == NULL)
	{
		DEBUG(MH_ERR_DEBUG, ("alloc_get_client_path ENOMEM #1\n"));
		errno = ENOMEM;
		status = -1;
		goto out;
	}
	DEBUG(MH_INFO_DEBUG, ("newPath #1 %s\n", *newPath));
	if (
		(pathPtr = strstr(path, CREATING_DIRNAME)) != NULL
			&&
		(
			*(pathPtr + CREATING_DIRNAME_LEN) == '\0'
			||
			*(pathPtr + CREATING_DIRNAME_LEN) == '/'
		)
			&&
		(
			(pathPtr - path > 0
				&&
			 *(pathPtr - 1) == '/')
			||
			(pathPtr - path > APPLE_DOUBLE_PREFIX_LEN
				&&
			*(pathPtr - APPLE_DOUBLE_PREFIX_LEN - 1) == '/'
				&&
			 is_apple_double(pathPtr - APPLE_DOUBLE_PREFIX_LEN))
		)
	)
	{
		/* Insert client suffix into path. */
		(*newPath)[pathPtr - path + CREATING_DIRNAME_LEN] = '\0';
		DEBUG(MH_INFO_DEBUG, ("newPath #2 %s\n", *newPath));

		if ((status = alloc_append_client_suffix(handle, newPath)))
		{
			goto out;
		}

		DEBUG(MH_INFO_DEBUG, ("newPath #3 %s\n", *newPath));
		*newPath = talloc_strdup_append(*newPath,
				pathPtr + CREATING_DIRNAME_LEN);
		if (*newPath == NULL)
		{
			DEBUG(MH_ERR_DEBUG, ("alloc_get_client_path "
						"ENOMEM #2\n"));
			errno = ENOMEM;
			status = -1;
			goto out;
		}
		DEBUG(MH_INFO_DEBUG, ("newPath #4 %s\n", *newPath));
	}

	/* replace /MDB_FILENAME or /PMR_FILENAME or /._MDB_FILENAME
	 * or /._PMR_FILENAME at newPath end with suffixed name.
	 */
	intermPathLen = strlen(*newPath);
	if (
		is_avid_database(*newPath, intermPathLen,
			MDB_FILENAME, MDB_FILENAME_LEN)
		||
		is_avid_database(*newPath, intermPathLen,
			PMR_FILENAME, PMR_FILENAME_LEN)
	)
	{
		DEBUG(MH_INFO_DEBUG, ("newPath #5 %s\n", *newPath));
		if ((status = alloc_append_client_suffix(handle, newPath)))
		{
			goto out;
		}
		DEBUG(MH_INFO_DEBUG, ("newPath #6 %s\n", *newPath));
	}
out:
	/* newPath must be freed in caller. */
	DEBUG(MH_INFO_DEBUG, ("Leaving with *newPath '%s'\n", *newPath));
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int alloc_get_client_smb_fname(struct vfs_handle_struct *handle,
		TALLOC_CTX *ctx,
		const struct smb_filename *smb_fname,
		struct smb_filename **clientFname)
{
	int status = 0;

	DEBUG(MH_INFO_DEBUG, ("Entering with smb_fname->base_name '%s'\n",
			      smb_fname->base_name));

	*clientFname = cp_smb_filename(ctx, smb_fname);
	if ((*clientFname) == NULL) {
		DEBUG(MH_ERR_DEBUG, ("alloc_get_client_smb_fname "
					"NTERR\n"));
		errno = ENOMEM;
		status = -1;
		goto err;
	}
	if ((status = alloc_get_client_path(handle, ctx,
				smb_fname->base_name,
				&(*clientFname)->base_name)))
	{
		goto err;
	}
	DEBUG(MH_INFO_DEBUG, ("Leaving with (*clientFname)->base_name "
				"'%s'\n", (*clientFname)->base_name));
err:
	return status;
}


/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int alloc_set_client_dirinfo_path(struct vfs_handle_struct *handle,
		TALLOC_CTX *ctx,
		char **path,
		const char *avid_db_filename)
{
	int status = 0;

	DEBUG(MH_INFO_DEBUG, ("Entering with avid_db_filename '%s'\n",
			      avid_db_filename));

	if ((*path = talloc_strdup(ctx, avid_db_filename)) == NULL)
	{
		DEBUG(MH_ERR_DEBUG, ("alloc_set_client_dirinfo_path "
					"ENOMEM\n"));
		errno = ENOMEM;
		status = -1;
		goto err;
	}
	if ((status = alloc_append_client_suffix(handle, path)))
	{
		goto err;
	}
	DEBUG(MH_INFO_DEBUG, ("Leaving with *path '%s'\n", *path));
err:
	return status;
}

/*
 * Replace mtime on clientFname with mtime from client-suffixed
 * equivalent, if it exists.
 *
 * Success: return 0
 * Failure: set errno, return -1
 */
static int set_fake_mtime(vfs_handle_struct *handle,
		TALLOC_CTX *ctx,
		struct smb_filename **clientFname,
		int (*statFn)(const char *, SMB_STRUCT_STAT *, bool))
{
	int status = 0;
	char *statPath;
	SMB_STRUCT_STAT fakeStat;
	int copy_len;

	DEBUG(MH_INFO_DEBUG, ("Entering with (*clientFname)->base_name "
			      "'%s', (*clientFname)->st.st_ex_mtime %s",
			      (*clientFname)->base_name,
			      ctime(&((*clientFname)->st.st_ex_mtime.tv_sec))));

	if (
		depth_from_media_dir(AVID_MXF_DIRNAME,
				AVID_MXF_DIRNAME_LEN,
				(*clientFname)->base_name)
			!= 1
			&&
		depth_from_media_dir(OMFI_MEDIAFILES_DIRNAME,
				OMFI_MEDIAFILES_DIRNAME_LEN,
				(*clientFname)->base_name)
			!= 0
	)
	{
		goto out;
	}

	copy_len = strlen((*clientFname)->base_name);

	/* Hack to deal with occasional "Avid MediaFiles/MXF/1/." paths.
	 * We know we're under a media dir, so paths are at least 2 chars
	 * long.
	 */
	if ((*clientFname)->base_name[copy_len - 1] == '.' &&
			(*clientFname)->base_name[copy_len - 2] == '/')
	{
		copy_len -= 2;
	}

	if (((statPath = talloc_strndup(ctx,
			(*clientFname)->base_name, copy_len)) == NULL))
	{
		errno = ENOMEM;
		status = -1;
		goto err;
	}
	if ((status = alloc_append_client_suffix(handle, &statPath)))
	{
		goto err;
	}

	DEBUG(MH_INFO_DEBUG, ("Fake stat'ing '%s'\n", statPath));
	if (statFn(statPath, &fakeStat,
			lp_fake_directory_create_times(SNUM(handle->conn))))
	{
		/* This can fail for legitimate reasons - i.e. the
		 * fakeStat directory doesn't exist, which is okay
		 * - so we don't set status.  But if it does fail,
		 * we need to skip over the mtime assignment.
		 */
		goto err;
	}

	DEBUG(MH_INFO_DEBUG, ("Setting fake mtime from '%s'\n", statPath));
	(*clientFname)->st.st_ex_mtime = fakeStat.st_ex_mtime;
err:
	TALLOC_FREE(statPath);
out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with (*clientFname)->base_name "
			"'%s', (*clientFname)->st.st_ex_mtime %s",
			(*clientFname)->base_name,
			ctime(&((*clientFname)->st.st_ex_mtime.tv_sec))));
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_statvfs(struct vfs_handle_struct *handle,
		const struct smb_filename *smb_fname,
		struct vfs_statvfs_struct *statbuf)
{
	int status;
	struct smb_filename *clientFname = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering with path '%s'\n",
			smb_fname->base_name));

	if (!is_in_media_files(smb_fname->base_name))
	{
		status = SMB_VFS_NEXT_STATVFS(handle, smb_fname, statbuf);
		goto out;
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&clientFname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_STATVFS(handle, clientFname, statbuf);
err:
	TALLOC_FREE(clientFname);
out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with path '%s'\n",
			smb_fname->base_name));
	return status;
}

static int alloc_set_client_dirinfo(vfs_handle_struct *handle,
		const char *fname,
		struct mh_dirinfo_struct **dirInfo)
{
	int status = 0;
	char *clientPath;
	TALLOC_CTX *ctx;

	DEBUG(MH_INFO_DEBUG, ("Entering with fname '%s'\n", fname));

	*dirInfo = talloc(NULL, struct mh_dirinfo_struct);
	if (*dirInfo == NULL)
	{
		goto err;
	}

	(*dirInfo)->dirpath = talloc_strdup(*dirInfo, fname);
	if ((*dirInfo)->dirpath == NULL)
	{
		goto err;
	}

	if (!is_in_media_files(fname))
	{
		(*dirInfo)->clientPath = NULL;
		(*dirInfo)->clientMDBFilename = NULL;
		(*dirInfo)->clientPMRFilename = NULL;
		(*dirInfo)->clientCreatingDirname = NULL;
		(*dirInfo)->isInMediaFiles = False;
		goto out;
	}

	(*dirInfo)->isInMediaFiles = True;

	if (alloc_set_client_dirinfo_path(handle,
				*dirInfo,
				&((*dirInfo)->clientMDBFilename),
				MDB_FILENAME))
	{
		goto err;
	}

	if (alloc_set_client_dirinfo_path(handle,
				*dirInfo,
				&((*dirInfo)->clientPMRFilename),
				PMR_FILENAME))
	{
		goto err;
	}

	if (alloc_set_client_dirinfo_path(handle,
				*dirInfo,
				&((*dirInfo)->clientCreatingDirname),
				CREATING_DIRNAME))
	{
		goto err;
	}

	clientPath = NULL;
	ctx = talloc_tos();

	if (alloc_get_client_path(handle, ctx,
				fname,
				&clientPath))
	{
		goto err;
	}

	(*dirInfo)->clientPath = talloc_strdup(*dirInfo, clientPath);
	if ((*dirInfo)->clientPath == NULL)
	{
		goto err;
	}

	TALLOC_FREE(clientPath);

out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with (*dirInfo)->dirpath '%s', "
				"(*dirInfo)->clientPath '%s'\n",
				(*dirInfo)->dirpath,
				(*dirInfo)->clientPath));
	return status;

err:
	DEBUG(MH_ERR_DEBUG, ("Failing with fname '%s'\n", fname));
	TALLOC_FREE(*dirInfo);
	status = -1;
	errno = ENOMEM;
	return status;
}

static DIR *mh_fdopendir(vfs_handle_struct *handle,
		files_struct *fsp,
		const char *mask,
		uint32_t attr)
{
	struct mh_dirinfo_struct *dirInfo = NULL;
	DIR *dirstream;

	DEBUG(MH_INFO_DEBUG, ("Entering with fsp->fsp_name->base_name '%s'\n",
			      fsp->fsp_name->base_name));

	dirstream = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);
	if (!dirstream)
	{
		goto err;
	}

	if (alloc_set_client_dirinfo(handle, fsp->fsp_name->base_name,
					&dirInfo))
	{
		goto err;
	}

	dirInfo->dirstream = dirstream;

	if (! dirInfo->isInMediaFiles) {
		goto out;
	}

	if (set_fake_mtime(handle, fsp, &(fsp->fsp_name), sys_stat))
	{
		goto err;
	}

out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with dirInfo->dirpath '%s', "
			"dirInfo->clientPath '%s', "
			"fsp->fsp_name->st.st_ex_mtime %s",
			dirInfo->dirpath,
			dirInfo->clientPath,
			ctime(&(fsp->fsp_name->st.st_ex_mtime.tv_sec))));
	/* Success is freed in closedir. */
	return (DIR *) dirInfo;
err:
	/* Failure is freed here. */
	DEBUG(MH_ERR_DEBUG, ("Failing with fsp->fsp_name->base_name '%s'\n",
			fsp->fsp_name->base_name));
	TALLOC_FREE(dirInfo);
	return NULL;
}

/*
 * skip MDB_FILENAME and PMR_FILENAME filenames and CREATING_DIRNAME
 * directory, skip other client's suffixed MDB_FILENAME and PMR_FILENAME
 * filenames and CREATING_DIRNAME directory, replace this client's
 * suffixed MDB_FILENAME and PMR_FILENAME filenames and CREATING_DIRNAME
 * directory with non suffixed.
 *
 * Success: return dirent
 * End of data: return NULL
 * Failure: set errno, return NULL
 */
static struct dirent *
mh_readdir(vfs_handle_struct *handle, struct files_struct *dirfsp, DIR *dirp)
{
	mh_dirinfo_struct* dirInfo = (mh_dirinfo_struct*)dirp;
	struct dirent *d = NULL;
	int skip;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_readdir\n"));

	DEBUG(MH_INFO_DEBUG, ("dirInfo->dirpath '%s', "
			      "dirInfo->clientPath '%s', "
			      "dirInfo->isInMediaFiles '%s', "
			      "dirInfo->clientMDBFilename '%s', "
			      "dirInfo->clientPMRFilename '%s', "
			      "dirInfo->clientCreatingDirname '%s'\n",
			      dirInfo->dirpath,
			      dirInfo->clientPath,
			      dirInfo->isInMediaFiles ? "True" : "False",
			      dirInfo->clientMDBFilename,
			      dirInfo->clientPMRFilename,
			      dirInfo->clientCreatingDirname));

	if (! dirInfo->isInMediaFiles)
	{
		d = SMB_VFS_NEXT_READDIR(handle, dirfsp, dirInfo->dirstream);
		goto out;
	}

	do
	{
		const char* dname;
		bool isAppleDouble;

		skip = False;
		d = SMB_VFS_NEXT_READDIR(handle, dirfsp, dirInfo->dirstream);

		if (d == NULL)
		{
			break;
		}

		/* ignore apple double prefix for logic below */
		if (is_apple_double(d->d_name))
		{
			dname = &d->d_name[APPLE_DOUBLE_PREFIX_LEN];
			isAppleDouble = True;
		}
		else
		{
			dname = d->d_name;
			isAppleDouble = False;
		}

		/* skip Avid-special files with no client suffix */
		if (
			strcmp(dname, MDB_FILENAME) == 0
			||
			strcmp(dname, PMR_FILENAME) == 0
			||
			strcmp(dname, CREATING_DIRNAME) == 0
		)
		{
			skip = True;
		}
		/* chop client suffix off this client's suffixed files */
		else if (strcmp(dname, dirInfo->clientMDBFilename) == 0)
		{
			if (isAppleDouble)
			{
				d->d_name[MDB_FILENAME_LEN
					+ APPLE_DOUBLE_PREFIX_LEN] = '\0';
			}
			else
			{
				d->d_name[MDB_FILENAME_LEN] = '\0';
			}
		}
		else if (strcmp(dname, dirInfo->clientPMRFilename) == 0)
		{
			if (isAppleDouble)
			{
				d->d_name[PMR_FILENAME_LEN
					+ APPLE_DOUBLE_PREFIX_LEN] = '\0';
			}
			else
			{
				d->d_name[PMR_FILENAME_LEN] = '\0';
			}
		}
		else if (strcmp(dname, dirInfo->clientCreatingDirname)
				== 0)
		{
			if (isAppleDouble)
			{
				d->d_name[CREATING_DIRNAME_LEN
					+ APPLE_DOUBLE_PREFIX_LEN] = '\0';
			}
			else
			{
				d->d_name[CREATING_DIRNAME_LEN] = '\0';
			}
		}
		/*
		 * Anything that starts as an Avid-special file
		 * that's made it this far should be skipped.  This
		 * is different from the original behaviour, which
		 * only skipped other client's suffixed files.
		 */
		else if (
			strncmp(MDB_FILENAME, dname,
				MDB_FILENAME_LEN) == 0
			||
			strncmp(PMR_FILENAME, dname,
				PMR_FILENAME_LEN) == 0
			||
			strncmp(CREATING_DIRNAME, dname,
				CREATING_DIRNAME_LEN) == 0
		)
		{
			skip = True;
		}
	}
	while (skip);

out:
	DEBUG(MH_INFO_DEBUG, ("Leaving mh_readdir\n"));
	return d;
}

/*
 * Success: no success result defined.
 * Failure: no failure result defined.
 */
static void mh_rewinddir(vfs_handle_struct *handle,
		DIR *dirp)
{
	DEBUG(MH_INFO_DEBUG, ("Entering and leaving mh_rewinddir\n"));
	SMB_VFS_NEXT_REWINDDIR(handle,
			((mh_dirinfo_struct*)dirp)->dirstream);
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_mkdirat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode)
{
	int status;
	struct smb_filename *clientFname = NULL;
	const char *path = smb_fname->base_name;
	struct smb_filename *full_fname = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering with path '%s'\n", path));

	if (!is_in_media_files(path)) {
		status = SMB_VFS_NEXT_MKDIRAT(handle,
				dirfsp,
				smb_fname,
				mode);
		goto out;
	}

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				full_fname,
				&clientFname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_MKDIRAT(handle,
			handle->conn->cwd_fsp,
			clientFname,
			mode);
err:
	TALLOC_FREE(full_fname);
	TALLOC_FREE(clientFname);
out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with path '%s'\n", path));
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_closedir(vfs_handle_struct *handle,
		DIR *dirp)
{
	DIR *realdirp = ((mh_dirinfo_struct*)dirp)->dirstream;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_closedir\n"));
	// Will this talloc_free destroy realdirp?
	TALLOC_FREE(dirp);

	DEBUG(MH_INFO_DEBUG, ("Leaving mh_closedir\n"));
	return SMB_VFS_NEXT_CLOSEDIR(handle, realdirp);
}

/*
 * Success: return non-negative file descriptor
 * Failure: set errno, return -1
 */
static int mh_openat(struct vfs_handle_struct *handle,
		     const struct files_struct *dirfsp,
		     const struct smb_filename *smb_fname,
		     files_struct *fsp,
		     const struct vfs_open_how *how)
{
	int ret;
	struct smb_filename *clientFname;
	TALLOC_CTX *ctx;

	DEBUG(MH_INFO_DEBUG, ("Entering with smb_fname->base_name '%s'\n",
			      smb_fname->base_name));

	if (!is_in_media_files(smb_fname->base_name)) {
		ret = SMB_VFS_NEXT_OPENAT(handle,
					  dirfsp,
					  smb_fname,
					  fsp,
					  how);
		goto out;
	}

	clientFname = NULL;
	ctx = talloc_tos();

	if (alloc_get_client_smb_fname(handle, ctx, smb_fname, &clientFname)) {
		ret = -1;
		goto err;
	}

	/*
	 * What about fsp->fsp_name? We also have to get correct stat info into
	 * fsp and smb_fname for DB files, don't we?
	 */

	DEBUG(MH_INFO_DEBUG, ("Leaving with smb_fname->base_name '%s' "
			      "smb_fname->st.st_ex_mtime %s"
			      " fsp->fsp_name->st.st_ex_mtime %s",
			      smb_fname->base_name,
			      ctime(&(smb_fname->st.st_ex_mtime.tv_sec)),
			      ctime(&(fsp->fsp_name->st.st_ex_mtime.tv_sec))));

	ret = SMB_VFS_NEXT_OPENAT(handle, dirfsp, clientFname, fsp, how);
err:
	TALLOC_FREE(clientFname);
out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with smb_fname->base_name '%s'\n",
				smb_fname->base_name));
	return ret;
}

/*
 * Success: return non-negative file descriptor
 * Failure: set errno, return -1
 */
static NTSTATUS mh_create_file(vfs_handle_struct *handle,
		struct smb_request *req,
		struct files_struct *dirfsp,
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
	struct smb_filename *clientFname;
	TALLOC_CTX *ctx;


	DEBUG(MH_INFO_DEBUG, ("Entering with smb_fname->base_name '%s'\n",
				smb_fname->base_name));
	if (!is_in_media_files(smb_fname->base_name))
	{
		status = SMB_VFS_NEXT_CREATE_FILE(
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
		goto out;
	}

	clientFname = NULL;
	ctx = talloc_tos();

	if (alloc_get_client_smb_fname(handle, ctx,
				smb_fname,
				&clientFname))
	{
		status = map_nt_error_from_unix(errno);
		goto err;
	}

	/* This only creates files, so we don't have to worry about
	 * our fake directory stat'ing here.
	 */
	// But we still need to route stat calls for DB files
	// properly, right?
	status = SMB_VFS_NEXT_CREATE_FILE(
		handle,
		req,
		dirfsp,
		clientFname,
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
	TALLOC_FREE(clientFname);
out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with smb_fname->base_name '%s'"
		"smb_fname->st.st_ex_mtime %s"
		"		fsp->fsp_name->st.st_ex_mtime %s",
		smb_fname->base_name,
		ctime(&(smb_fname->st.st_ex_mtime.tv_sec)),
		(*result_fsp) && VALID_STAT((*result_fsp)->fsp_name->st) ?
		ctime(&((*result_fsp)->fsp_name->st.st_ex_mtime.tv_sec)) :
		"No fsp time\n"));
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_renameat(vfs_handle_struct *handle,
		files_struct *srcfsp,
		const struct smb_filename *smb_fname_src,
		files_struct *dstfsp,
		const struct smb_filename *smb_fname_dst,
		const struct vfs_rename_how *how)
{
	int status = -1;
	struct smb_filename *full_fname_src = NULL;
	struct smb_filename *full_fname_dst = NULL;
	struct smb_filename *srcClientFname = NULL;
	struct smb_filename *dstClientFname = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering with "
			      "smb_fname_src->base_name '%s', "
			      "smb_fname_dst->base_name '%s'\n",
			      smb_fname_src->base_name,
			      smb_fname_dst->base_name));

	if (!is_in_media_files(smb_fname_src->base_name)
				&&
			!is_in_media_files(smb_fname_dst->base_name))
	{
		status = SMB_VFS_NEXT_RENAMEAT(handle,
				srcfsp,
				smb_fname_src,
				dstfsp,
				smb_fname_dst,
				how);
		goto out;
	}

	full_fname_src = full_path_from_dirfsp_atname(talloc_tos(),
						      srcfsp,
						      smb_fname_src);
	if (full_fname_src == NULL) {
		errno = ENOMEM;
		goto out;
        }
	full_fname_dst = full_path_from_dirfsp_atname(talloc_tos(),
						      dstfsp,
						      smb_fname_dst);
	if (full_fname_dst == NULL) {
		errno = ENOMEM;
		goto out;
        }

	if ((status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				full_fname_src,
				&srcClientFname)))
	{
		goto err;
	}

	if ((status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				full_fname_dst,
				&dstClientFname)))
	{
		goto err;
	}

	status = SMB_VFS_NEXT_RENAMEAT(handle,
				srcfsp->conn->cwd_fsp,
				srcClientFname,
				dstfsp->conn->cwd_fsp,
				dstClientFname,
				how);
err:
	TALLOC_FREE(full_fname_src);
	TALLOC_FREE(full_fname_dst);
	TALLOC_FREE(dstClientFname);
	TALLOC_FREE(srcClientFname);
out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with smb_fname_src->base_name '%s',"
				" smb_fname_dst->base_name '%s'\n",
				smb_fname_src->base_name,
				smb_fname_dst->base_name));
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_stat(vfs_handle_struct *handle,
		struct smb_filename *smb_fname)
{
	int status = 0;
	struct smb_filename *clientFname;
	TALLOC_CTX *ctx;


	DEBUG(MH_INFO_DEBUG, ("Entering with smb_fname->base_name '%s'\n",
			      smb_fname->base_name));

	if (!is_in_media_files(smb_fname->base_name))
	{
		status = SMB_VFS_NEXT_STAT(handle, smb_fname);
		goto out;
	}

	clientFname = NULL;
	ctx = talloc_tos();

	if ((status = alloc_get_client_smb_fname(handle, ctx,
				smb_fname,
				&clientFname)))
	{
		goto err;
	}
	DEBUG(MH_INFO_DEBUG, ("Stat'ing clientFname->base_name '%s'\n",
				clientFname->base_name));
	if ((status = SMB_VFS_NEXT_STAT(handle, clientFname)))
	{
		goto err;
	}
	if ((status = set_fake_mtime(handle, ctx, &clientFname, sys_stat)))
	{
		goto err;
	}

	/* Unlike functions with const smb_filename, we have to
	 * modify smb_fname itself to pass our info back up.
	 */
	DEBUG(MH_INFO_DEBUG, ("Setting smb_fname '%s' stat "
				"from clientFname '%s'\n",
				smb_fname->base_name,
				clientFname->base_name));
	smb_fname->st = clientFname->st;
err:
	TALLOC_FREE(clientFname);
out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with smb_fname->st.st_ex_mtime %s",
			ctime(&(smb_fname->st.st_ex_mtime.tv_sec))));
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_lstat(vfs_handle_struct *handle,
		struct smb_filename *smb_fname)
{
	int status = 0;
	struct smb_filename *clientFname;
	TALLOC_CTX *ctx;

	DEBUG(MH_INFO_DEBUG, ("Entering with smb_fname->base_name '%s'\n",
			      smb_fname->base_name));

	if (!is_in_media_files(smb_fname->base_name))
	{
		status = SMB_VFS_NEXT_LSTAT(handle, smb_fname);
		goto out;
	}

	clientFname = NULL;
	ctx = talloc_tos();

	if ((status = alloc_get_client_smb_fname(handle, ctx,
				smb_fname,
				&clientFname)))
	{
		goto err;
	}
	if ((status = SMB_VFS_NEXT_LSTAT(handle, clientFname)))
	{
		goto err;
	}

	if ((status = set_fake_mtime(handle, ctx, &clientFname, sys_lstat)))
	{
		goto err;
	}
	/* Unlike functions with const smb_filename, we have to
	 * modify smb_fname itself to pass our info back up.
	 */
	smb_fname->st = clientFname->st;
err:
	TALLOC_FREE(clientFname);
out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with smb_fname->st.st_ex_mtime %s",
			ctime(&(smb_fname->st.st_ex_mtime.tv_sec))));
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_fstat(vfs_handle_struct *handle,
		files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	int status = 0;

	DEBUG(MH_INFO_DEBUG, ("Entering with fsp->fsp_name->base_name "
				"'%s'\n", fsp_str_dbg(fsp)));

	if ((status = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf)))
	{
		goto out;
	}

	if (fsp->fsp_name == NULL
			|| !is_in_media_files(fsp->fsp_name->base_name))
	{
		goto out;
	}

	if ((status = mh_stat(handle, fsp->fsp_name)))
	{
		goto out;
	}

	*sbuf = fsp->fsp_name->st;
out:
	DEBUG(MH_INFO_DEBUG, ("Leaving with fsp->fsp_name->st.st_ex_mtime "
			"%s",
			fsp->fsp_name != NULL ?
				ctime(&(fsp->fsp_name->st.st_ex_mtime.tv_sec)) :
				"0"));
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_unlinkat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		int flags)
{
	int status;
	struct smb_filename *full_fname = NULL;
	struct smb_filename *clientFname;
	TALLOC_CTX *ctx;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_unlinkat\n"));
	if (!is_in_media_files(smb_fname->base_name)) {
		status = SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp,
				smb_fname,
				flags);
		goto out;
	}

	clientFname = NULL;
	ctx = talloc_tos();

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	if ((status = alloc_get_client_smb_fname(handle, ctx,
				full_fname,
				&clientFname))) {
		goto err;
	}

	status = SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp->conn->cwd_fsp,
				clientFname,
				flags);
err:
	TALLOC_FREE(full_fname);
	TALLOC_FREE(clientFname);
out:
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_lchown(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname,
		uid_t uid,
		gid_t gid)
{
	int status;
	struct smb_filename *clientFname = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_lchown\n"));
	if (!is_in_media_files(smb_fname->base_name))
	{
		status = SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);
		goto out;
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&clientFname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_LCHOWN(handle, clientFname, uid, gid);
err:
	TALLOC_FREE(clientFname);
out:
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_chdir(vfs_handle_struct *handle,
		const struct smb_filename *smb_fname)
{
	int status;
	struct smb_filename *clientFname = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_chdir\n"));
	if (!is_in_media_files(smb_fname->base_name)) {
		status = SMB_VFS_NEXT_CHDIR(handle, smb_fname);
		goto out;
	}

	status = alloc_get_client_smb_fname(handle,
				talloc_tos(),
				smb_fname,
				&clientFname);
	if (status != 0) {
		goto err;
	}

	status = SMB_VFS_NEXT_CHDIR(handle, clientFname);
err:
	TALLOC_FREE(clientFname);
out:
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */

static int mh_symlinkat(vfs_handle_struct *handle,
		const struct smb_filename *link_contents,
		struct files_struct *dirfsp,
		const struct smb_filename *new_smb_fname)
{
	int status = -1;
	struct smb_filename *full_fname = NULL;
	struct smb_filename *new_link_target = NULL;
	struct smb_filename *newclientFname = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_symlinkat\n"));

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						new_smb_fname);
	if (full_fname == NULL) {
		status = -1;
		goto err;
	}

	if (!is_in_media_files(link_contents->base_name) &&
			!is_in_media_files(full_fname->base_name)) {
		status = SMB_VFS_NEXT_SYMLINKAT(handle,
				link_contents,
				dirfsp,
				new_smb_fname);
		goto out;
	}

	if ((status = alloc_get_client_smb_fname(handle, talloc_tos(),
				link_contents,
				&new_link_target))) {
		goto err;
	}
	if ((status = alloc_get_client_smb_fname(handle, talloc_tos(),
				full_fname,
				&newclientFname))) {
		goto err;
	}

	status = SMB_VFS_NEXT_SYMLINKAT(handle,
				new_link_target,
				handle->conn->cwd_fsp,
				newclientFname);
err:
	TALLOC_FREE(new_link_target);
	TALLOC_FREE(newclientFname);
out:
	TALLOC_FREE(full_fname);
	return status;
}

/*
 * Success: return byte count
 * Failure: set errno, return -1
 */
static int mh_readlinkat(vfs_handle_struct *handle,
		const struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		char *buf,
		size_t bufsiz)
{
	int status;
	struct smb_filename *full_fname = NULL;
	struct smb_filename *clientFname = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_readlinkat\n"));
	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						smb_fname);
	if (full_fname == NULL) {
		status = -1;
		goto err;
	}

	if (!is_in_media_files(full_fname->base_name)) {
		status = SMB_VFS_NEXT_READLINKAT(handle,
				dirfsp,
				smb_fname,
				buf,
				bufsiz);
		goto out;
	}

	if ((status = alloc_get_client_smb_fname(handle, talloc_tos(),
				full_fname,
				&clientFname))) {
		goto err;
	}

	status = SMB_VFS_NEXT_READLINKAT(handle,
				handle->conn->cwd_fsp,
				clientFname,
				buf,
				bufsiz);

err:
	TALLOC_FREE(clientFname);
out:
	TALLOC_FREE(full_fname);
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_linkat(vfs_handle_struct *handle,
		files_struct *srcfsp,
		const struct smb_filename *old_smb_fname,
		files_struct *dstfsp,
		const struct smb_filename *new_smb_fname,
		int flags)
{
	int status;
	struct smb_filename *old_full_fname = NULL;
	struct smb_filename *oldclientFname = NULL;
	struct smb_filename *new_full_fname = NULL;
	struct smb_filename *newclientFname = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_linkat\n"));

	old_full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						srcfsp,
						old_smb_fname);
	if (old_full_fname == NULL) {
		status = -1;
		goto err;
	}

	new_full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dstfsp,
						new_smb_fname);
	if (new_full_fname == NULL) {
		status = -1;
		goto err;
	}

	if (!is_in_media_files(old_full_fname->base_name) &&
			!is_in_media_files(new_full_fname->base_name)) {
		TALLOC_FREE(old_full_fname);
		TALLOC_FREE(new_full_fname);

		status = SMB_VFS_NEXT_LINKAT(handle,
				srcfsp,
				old_smb_fname,
				dstfsp,
				new_smb_fname,
				flags);
		goto out;
	}

	if ((status = alloc_get_client_smb_fname(handle, talloc_tos(),
				old_full_fname,
				&oldclientFname))) {
		goto err;
	}
	if ((status = alloc_get_client_smb_fname(handle, talloc_tos(),
				new_full_fname,
				&newclientFname))) {
		goto err;
	}

	status = SMB_VFS_NEXT_LINKAT(handle,
				handle->conn->cwd_fsp,
				oldclientFname,
				handle->conn->cwd_fsp,
				newclientFname,
				flags);

err:
	TALLOC_FREE(old_full_fname);
	TALLOC_FREE(new_full_fname);
	TALLOC_FREE(newclientFname);
	TALLOC_FREE(oldclientFname);
out:
	return status;
}

/*
 * Success: return 0
 * Failure: set errno, return -1
 */
static int mh_mknodat(vfs_handle_struct *handle,
		files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode,
		SMB_DEV_T dev)
{
	int status;
	struct smb_filename *full_fname = NULL;
	struct smb_filename *clientFname = NULL;
	TALLOC_CTX *ctx;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_mknodat\n"));

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						dirfsp,
						smb_fname);
	if (full_fname == NULL) {
		status = -1;
		goto err;
	}

	if (!is_in_media_files(full_fname->base_name)) {
		status = SMB_VFS_NEXT_MKNODAT(handle,
				dirfsp,
				smb_fname,
				mode,
				dev);
		goto out;
	}

	ctx = talloc_tos();

	if ((status = alloc_get_client_smb_fname(handle, ctx,
				full_fname,
				&clientFname))) {
		goto err;
	}

	status = SMB_VFS_NEXT_MKNODAT(handle,
			handle->conn->cwd_fsp,
			clientFname,
			mode,
			dev);

err:
	TALLOC_FREE(clientFname);
out:
	TALLOC_FREE(full_fname);
	return status;
}

/*
 * Success: return path pointer
 * Failure: set errno, return NULL pointer
 */
static struct smb_filename *mh_realpath(vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)
{
	struct smb_filename *result_fname = NULL;
	struct smb_filename *clientFname = NULL;

	DEBUG(MH_INFO_DEBUG, ("Entering mh_realpath\n"));
	if (!is_in_media_files(smb_fname->base_name)) {
		return SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);
	}

	if (alloc_get_client_smb_fname(handle, ctx,
				smb_fname,
				&clientFname) != 0) {
		goto err;
	}

	result_fname = SMB_VFS_NEXT_REALPATH(handle, ctx, clientFname);
err:
	TALLOC_FREE(clientFname);
	return result_fname;
}

/* Ignoring get_real_filename function because the default
 * doesn't do anything.
 */

/*
 * Success: return 0
 * Failure: set errno, return -1
 * In this case, "name" is an attr name.
 */

/* VFS operations structure */

static struct vfs_fn_pointers vfs_mh_fns = {
	/* Disk operations */

	.statvfs_fn = mh_statvfs,

	/* Directory operations */

	.fdopendir_fn = mh_fdopendir,
	.readdir_fn = mh_readdir,
	.rewind_dir_fn = mh_rewinddir,
	.mkdirat_fn = mh_mkdirat,
	.closedir_fn = mh_closedir,

	/* File operations */

	.openat_fn = mh_openat,
	.create_file_fn = mh_create_file,
	.renameat_fn = mh_renameat,
	.stat_fn = mh_stat,
	.lstat_fn = mh_lstat,
	.fstat_fn = mh_fstat,
	.unlinkat_fn = mh_unlinkat,
	.lchown_fn = mh_lchown,
	.chdir_fn = mh_chdir,
	.symlinkat_fn = mh_symlinkat,
	.readlinkat_fn = mh_readlinkat,
	.linkat_fn = mh_linkat,
	.mknodat_fn = mh_mknodat,
	.realpath_fn = mh_realpath,

	/* EA operations. */
	.getxattrat_send_fn = vfs_not_implemented_getxattrat_send,
	.getxattrat_recv_fn = vfs_not_implemented_getxattrat_recv,

	/* aio operations */
};

static_decl_vfs;
NTSTATUS vfs_media_harmony_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"media_harmony", &vfs_mh_fns);
	if (!NT_STATUS_IS_OK(ret))
	{
		goto out;
	}

	vfs_mh_debug_level = debug_add_class("media_harmony");

	if (vfs_mh_debug_level == -1) {
		vfs_mh_debug_level = DBGC_VFS;
		DEBUG(1, ("media_harmony_init: Couldn't register custom "
				"debugging class.\n"));
	} else {
		DEBUG(3, ("media_harmony_init: Debug class number of "
				"'media_harmony': %d\n",
				vfs_mh_debug_level));
	}

out:
	return ret;
}
