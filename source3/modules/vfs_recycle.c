/*
 * Recycle bin VFS module for Samba.
 *
 * Copyright (C) 2001, Brandon Stone, Amherst College, <bbstone@amherst.edu>.
 * Copyright (C) 2002, Jeremy Allison - modified to make a VFS module.
 * Copyright (C) 2002, Alexander Bokovoy - cascaded VFS adoption,
 * Copyright (C) 2002, Juergen Hasch - added some options.
 * Copyright (C) 2002, Simo Sorce
 * Copyright (C) 2002, Stefan (metze) Metzmacher
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
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "auth.h"
#include "source3/lib/substitute.h"

#define ALLOC_CHECK(ptr, label) do { if ((ptr) == NULL) { DEBUG(0, ("recycle.bin: out of memory!\n")); errno = ENOMEM; goto label; } } while(0)

static int vfs_recycle_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_recycle_debug_level

struct recycle_config_data {
	const char *repository;
	bool keeptree;
	bool versions;
	bool touch;
	bool touch_mtime;
	const char **exclude;
	const char **exclude_dir;
	const char **noversions;
	mode_t directory_mode;
	mode_t subdir_mode;
	off_t minsize;
	off_t maxsize;
};

static int vfs_recycle_connect(struct vfs_handle_struct *handle,
			       const char *service,
			       const char *user)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	struct recycle_config_data *config = NULL;
	int ret;
	int t;
	const char *buff = NULL;
	const char **tmplist = NULL;
	char *repository = NULL;

	ret = SMB_VFS_NEXT_CONNECT(handle, service, user);
	if (ret < 0) {
		return ret;
	}

	if (IS_IPC(handle->conn) || IS_PRINT(handle->conn)) {
		return 0;
	}

	config = talloc_zero(handle->conn, struct recycle_config_data);
	if (config == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return -1;
	}
	buff = lp_parm_const_string(SNUM(handle->conn),
				    "recycle",
				    "repository",
				    ".recycle");
	repository = talloc_sub_full(
		config,
		lp_servicename(talloc_tos(), lp_sub, SNUM(handle->conn)),
		handle->conn->session_info->unix_info->unix_name,
		handle->conn->connectpath,
		handle->conn->session_info->unix_token->gid,
		handle->conn->session_info->unix_info->sanitized_username,
		handle->conn->session_info->info->domain_name,
		buff);
	if (repository == NULL) {
		DBG_ERR("talloc_sub_full() failed\n");
		TALLOC_FREE(config);
		errno = ENOMEM;
		return -1;
	}
	/* shouldn't we allow absolute path names here? --metze */
	/* Yes :-). JRA. */
	trim_char(repository, '\0', '/');
	config->repository = repository;

	config->keeptree = lp_parm_bool(SNUM(handle->conn),
					"recycle",
					"keeptree",
					False);
	config->versions = lp_parm_bool(SNUM(handle->conn),
					"recycle",
					"versions",
					False);
	config->touch = lp_parm_bool(SNUM(handle->conn),
				     "recycle",
				     "touch",
				     False);
	config->touch_mtime = lp_parm_bool(SNUM(handle->conn),
					   "recycle",
					   "touch_mtime",
					   False);
	tmplist = lp_parm_string_list(SNUM(handle->conn),
				      "recycle",
				      "exclude",
				      NULL);
	if (tmplist != NULL) {
		char **tmpcpy = str_list_copy(config, tmplist);
		if (tmpcpy == NULL) {
			DBG_ERR("str_list_copy() failed\n");
			TALLOC_FREE(config);
			errno = ENOMEM;
			return -1;
		}
		config->exclude = discard_const_p(const char *, tmpcpy);
	}
	tmplist = lp_parm_string_list(SNUM(handle->conn),
				      "recycle",
				      "exclude_dir",
				      NULL);
	if (tmplist != NULL) {
		char **tmpcpy = str_list_copy(config, tmplist);
		if (tmpcpy == NULL) {
			DBG_ERR("str_list_copy() failed\n");
			TALLOC_FREE(config);
			errno = ENOMEM;
			return -1;
		}
		config->exclude_dir = discard_const_p(const char *, tmpcpy);
	}
	tmplist = lp_parm_string_list(SNUM(handle->conn),
				      "recycle",
				      "noversions",
				      NULL);
	if (tmplist != NULL) {
		char **tmpcpy = str_list_copy(config, tmplist);
		if (tmpcpy == NULL) {
			DBG_ERR("str_list_copy() failed\n");
			TALLOC_FREE(config);
			errno = ENOMEM;
			return -1;
		}
		config->noversions = discard_const_p(const char *, tmpcpy);
	}
	config->minsize = conv_str_size(lp_parm_const_string(
		SNUM(handle->conn), "recycle", "minsize", NULL));
	config->maxsize = conv_str_size(lp_parm_const_string(
		SNUM(handle->conn), "recycle", "maxsize", NULL));

	buff = lp_parm_const_string(SNUM(handle->conn),
				    "recycle",
				    "directory_mode",
				    NULL);
	if (buff != NULL ) {
		sscanf(buff, "%o", &t);
	} else {
		t = S_IRUSR | S_IWUSR | S_IXUSR;
	}
	config->directory_mode = (mode_t)t;

	buff = lp_parm_const_string(SNUM(handle->conn),
				    "recycle",
				    "subdir_mode",
				    NULL);
	if (buff != NULL ) {
		sscanf(buff, "%o", &t);
	} else {
		t = config->directory_mode;
	}
	config->subdir_mode = (mode_t)t;

	SMB_VFS_HANDLE_SET_DATA(
		handle, config, NULL, struct recycle_config_data, return -1);
	return 0;
}

static bool recycle_directory_exist(vfs_handle_struct *handle, const char *dname)
{
	struct smb_filename smb_fname = {
			.base_name = discard_const_p(char, dname)
	};

	if (SMB_VFS_STAT(handle->conn, &smb_fname) == 0) {
		if (S_ISDIR(smb_fname.st.st_ex_mode)) {
			return True;
		}
	}

	return False;
}

static bool recycle_file_exist(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname)
{
	struct smb_filename *smb_fname_tmp = NULL;
	bool ret = false;

	smb_fname_tmp = cp_smb_filename(talloc_tos(), smb_fname);
	if (smb_fname_tmp == NULL) {
		return false;
	}

	if (SMB_VFS_STAT(handle->conn, smb_fname_tmp) == 0) {
		if (S_ISREG(smb_fname_tmp->st.st_ex_mode)) {
			ret = true;
		}
	}

	TALLOC_FREE(smb_fname_tmp);
	return ret;
}

/**
 * Return file size
 * @param conn connection
 * @param fname file name
 * @return size in bytes
 **/
static off_t recycle_get_file_size(vfs_handle_struct *handle,
				       const struct smb_filename *smb_fname)
{
	struct smb_filename *smb_fname_tmp = NULL;
	off_t size;

	smb_fname_tmp = cp_smb_filename(talloc_tos(), smb_fname);
	if (smb_fname_tmp == NULL) {
		size = (off_t)0;
		goto out;
	}

	if (SMB_VFS_STAT(handle->conn, smb_fname_tmp) != 0) {
		DBG_DEBUG("stat for %s returned %s\n",
			 smb_fname_str_dbg(smb_fname_tmp), strerror(errno));
		size = (off_t)0;
		goto out;
	}

	size = smb_fname_tmp->st.st_ex_size;
 out:
	TALLOC_FREE(smb_fname_tmp);
	return size;
}

/**
 * Create directory tree
 * @param conn connection
 * @param dname Directory tree to be created
 * @param directory mode
 * @param subdirectory mode
 * @return Returns True for success
 **/
static bool recycle_create_dir(vfs_handle_struct *handle,
			       const char *dname,
			       mode_t dir_mode,
			       mode_t subdir_mode)
{
	size_t len;
	mode_t mode = dir_mode;
	char *new_dir = NULL;
	char *tmp_str = NULL;
	char *token;
	char *tok_str;
	bool ret = False;
	char *saveptr;

	tmp_str = SMB_STRDUP(dname);
	ALLOC_CHECK(tmp_str, done);
	tok_str = tmp_str;

	len = strlen(dname)+1;
	new_dir = (char *)SMB_MALLOC(len + 1);
	ALLOC_CHECK(new_dir, done);
	*new_dir = '\0';
	if (dname[0] == '/') {
		/* Absolute path. */
		if (strlcat(new_dir,"/",len+1) >= len+1) {
			goto done;
		}
	}

	/* Create directory tree if necessary */
	for(token = strtok_r(tok_str, "/", &saveptr); token;
	    token = strtok_r(NULL, "/", &saveptr)) {
		if (strlcat(new_dir, token, len+1) >= len+1) {
			goto done;
		}
		if (recycle_directory_exist(handle, new_dir))
			DEBUG(10, ("recycle: dir %s already exists\n", new_dir));
		else {
			struct smb_filename *smb_fname = NULL;
			int retval;

			DEBUG(5, ("recycle: creating new dir %s\n", new_dir));

			smb_fname = cp_smb_basename(talloc_tos(), new_dir);
			if (smb_fname == NULL) {
				goto done;
			}

			retval = SMB_VFS_NEXT_MKDIRAT(handle,
					handle->conn->cwd_fsp,
					smb_fname,
					mode);
			if (retval != 0) {
				DBG_WARNING("recycle: mkdirat failed "
					"for %s with error: %s\n",
					new_dir,
					strerror(errno));
				TALLOC_FREE(smb_fname);
				ret = False;
				goto done;
			}
			TALLOC_FREE(smb_fname);
		}
		if (strlcat(new_dir, "/", len+1) >= len+1) {
			goto done;
		}
		mode = subdir_mode;
	}

	ret = True;
done:
	SAFE_FREE(tmp_str);
	SAFE_FREE(new_dir);
	return ret;
}

/**
 * Check if any of the components of "exclude_list" are contained in path.
 * Return True if found
 **/

static bool matchdirparam(const char **dir_exclude_list, char *path)
{
	char *startp = NULL, *endp = NULL;

	if (dir_exclude_list == NULL || dir_exclude_list[0] == NULL ||
		*dir_exclude_list[0] == '\0' || path == NULL || *path == '\0') {
		return False;
	}

	/*
	 * Walk the components of path, looking for matches with the
	 * exclude list on each component.
	 */

	for (startp = path; startp; startp = endp) {
		int i;

		while (*startp == '/') {
			startp++;
		}
		endp = strchr(startp, '/');
		if (endp) {
			*endp = '\0';
		}

		for(i=0; dir_exclude_list[i] ; i++) {
			if(unix_wild_match(dir_exclude_list[i], startp)) {
				/* Repair path. */
				if (endp) {
					*endp = '/';
				}
				return True;
			}
		}

		/* Repair path. */
		if (endp) {
			*endp = '/';
		}
	}

	return False;
}

/**
 * Check if needle is contained in haystack, * and ? patterns are resolved
 * @param haystack list of parameters separated by delimimiter character
 * @param needle string to be matched exectly to haystack including pattern matching
 * @return True if found
 **/
static bool matchparam(const char **haystack_list, const char *needle)
{
	int i;

	if (haystack_list == NULL || haystack_list[0] == NULL ||
		*haystack_list[0] == '\0' || needle == NULL || *needle == '\0') {
		return False;
	}

	for(i=0; haystack_list[i] ; i++) {
		if(unix_wild_match(haystack_list[i], needle)) {
			return True;
		}
	}

	return False;
}

/**
 * Touch access or modify date
 **/
static void recycle_do_touch(vfs_handle_struct *handle,
			     const struct smb_filename *smb_fname,
			     bool touch_mtime)
{
	struct smb_filename *smb_fname_tmp = NULL;
	struct smb_file_time ft;
	int ret, err;
	NTSTATUS status;

	init_smb_file_time(&ft);

	status = synthetic_pathref(talloc_tos(),
				   handle->conn->cwd_fsp,
				   smb_fname->base_name,
				   smb_fname->stream_name,
				   NULL,
				   smb_fname->twrp,
				   smb_fname->flags,
				   &smb_fname_tmp);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("synthetic_pathref for '%s' failed: %s\n",
			  smb_fname_str_dbg(smb_fname), nt_errstr(status));
		return;
	}

	/* atime */
	ft.atime = timespec_current();
	/* mtime */
	ft.mtime = touch_mtime ? ft.atime : smb_fname_tmp->st.st_ex_mtime;

	become_root();
	ret = SMB_VFS_NEXT_FNTIMES(handle, smb_fname_tmp->fsp, &ft);
	err = errno;
	unbecome_root();
	if (ret == -1 ) {
		DEBUG(0, ("recycle: touching %s failed, reason = %s\n",
			  smb_fname_str_dbg(smb_fname_tmp), strerror(err)));
	}

	TALLOC_FREE(smb_fname_tmp);
}

/**
 * Check if file should be recycled
 **/
static int recycle_unlink_internal(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				int flags)
{
	TALLOC_CTX *frame = NULL;
	struct smb_filename *full_fname = NULL;
	char *path_name = NULL;
	const char *temp_name = NULL;
	const char *final_name = NULL;
	struct smb_filename *smb_fname_final = NULL;
	const char *base = NULL;
	int i = 1;
	off_t file_size; /* space_avail;	*/
	bool exist;
	int rc = -1;
	struct recycle_config_data *config = NULL;
	struct vfs_rename_how rhow = { .flags = 0, };

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct recycle_config_data,
				return -1);

	frame = talloc_stackframe();

	if (config->repository[0] == '\0') {
		DEBUG(3, ("recycle: repository path not set, purging %s...\n",
			  smb_fname_str_dbg(smb_fname)));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	full_fname = full_path_from_dirfsp_atname(frame,
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		rc = -1;
		errno = ENOMEM;
		goto done;
	}

	/* we don't recycle the recycle bin... */
	if (strncmp(full_fname->base_name, config->repository,
		    strlen(config->repository)) == 0) {
		DEBUG(3, ("recycle: File is within recycling bin, unlinking ...\n"));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	file_size = recycle_get_file_size(handle, full_fname);
	/* it is wrong to purge filenames only because they are empty imho
	 *   --- simo
	 *
	if(fsize == 0) {
		DEBUG(3, ("recycle: File %s is empty, purging...\n", file_name));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					file_name,
					flags);
		goto done;
	}
	 */

	/* FIXME: this is wrong, we should check the whole size of the recycle bin is
	 * not greater then maxsize, not the size of the single file, also it is better
	 * to remove older files
	 */
	if (config->maxsize > 0 && file_size > config->maxsize) {
		DBG_NOTICE("File %s exceeds maximum recycle size, "
			   "purging... \n",
			   smb_fname_str_dbg(full_fname));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}
	if (config->minsize > 0 && file_size < config->minsize) {
		DBG_NOTICE("File %s lowers minimum recycle size, "
			   "purging... \n",
			   smb_fname_str_dbg(full_fname));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	/* FIXME: this is wrong: moving files with rename does not change the disk space
	 * allocation
	 *
	space_avail = SMB_VFS_NEXT_DISK_FREE(handle, ".", True, &bsize, &dfree, &dsize) * 1024L;
	DEBUG(5, ("space_avail = %Lu, file_size = %Lu\n", space_avail, file_size));
	if(space_avail < file_size) {
		DEBUG(3, ("recycle: Not enough diskspace, purging file %s\n", file_name));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					file_name,
					flags);
		goto done;
	}
	 */

	/* extract filename and path */
	if (!parent_dirname(frame, full_fname->base_name, &path_name, &base)) {
		rc = -1;
		errno = ENOMEM;
		goto done;
	}

	/* original filename with path */
	DEBUG(10, ("recycle: fname = %s\n", smb_fname_str_dbg(full_fname)));
	/* original path */
	DEBUG(10, ("recycle: fpath = %s\n", path_name));
	/* filename without path */
	DEBUG(10, ("recycle: base = %s\n", base));

	if (matchparam(config->exclude, base)) {
		DEBUG(3, ("recycle: file %s is excluded \n", base));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	if (matchdirparam(config->exclude_dir, path_name)) {
		DEBUG(3, ("recycle: directory %s is excluded \n", path_name));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	if (config->keeptree && !ISDOT(path_name)) {
		temp_name = talloc_asprintf(frame, "%s/%s",
					    config->repository,
					    path_name);
		if (temp_name == NULL) {
			rc = -1;
			goto done;
		}
	} else {
		temp_name = config->repository;
	}

	exist = recycle_directory_exist(handle, temp_name);
	if (exist) {
		DEBUG(10, ("recycle: Directory already exists\n"));
	} else {
		DEBUG(10, ("recycle: Creating directory %s\n", temp_name));
		if (recycle_create_dir(handle,
				       temp_name,
				       config->directory_mode,
				       config->subdir_mode) == False)
		{
			DEBUG(3, ("recycle: Could not create directory, "
				  "purging %s...\n",
				  smb_fname_str_dbg(full_fname)));
			rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
			goto done;
		}
	}

	final_name = talloc_asprintf(frame, "%s/%s",
				     temp_name, base);
	if (final_name == NULL) {
		rc = -1;
		goto done;
	}

	/* Create smb_fname with final base name and orig stream name. */
	smb_fname_final = synthetic_smb_fname(frame,
					final_name,
					full_fname->stream_name,
					NULL,
					full_fname->twrp,
					full_fname->flags);
	if (smb_fname_final == NULL) {
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
		goto done;
	}

	/* new filename with path */
	DEBUG(10, ("recycle: recycled file name: %s\n",
		   smb_fname_str_dbg(smb_fname_final)));

	/* check if we should delete file from recycle bin */
	if (recycle_file_exist(handle, smb_fname_final)) {
		if (config->versions == False ||
		    matchparam(config->noversions, base) == True) {
			DEBUG(3, ("recycle: Removing old file %s from recycle "
				  "bin\n", smb_fname_str_dbg(smb_fname_final)));
			if (SMB_VFS_NEXT_UNLINKAT(handle,
						dirfsp->conn->cwd_fsp,
						smb_fname_final,
						flags) != 0) {
				DEBUG(1, ("recycle: Error deleting old file: %s\n", strerror(errno)));
			}
		}
	}

	/* rename file we move to recycle bin */
	i = 1;
	while (recycle_file_exist(handle, smb_fname_final)) {
		char *copy = NULL;

		TALLOC_FREE(smb_fname_final->base_name);
		copy = talloc_asprintf(smb_fname_final, "%s/Copy #%d of %s",
				       temp_name, i++, base);
		if (copy == NULL) {
			rc = -1;
			goto done;
		}
		smb_fname_final->base_name = copy;
	}

	DEBUG(10, ("recycle: Moving %s to %s\n", smb_fname_str_dbg(full_fname),
		smb_fname_str_dbg(smb_fname_final)));
	rc = SMB_VFS_NEXT_RENAMEAT(handle,
			dirfsp,
			smb_fname,
			handle->conn->cwd_fsp,
			smb_fname_final,
			&rhow);
	if (rc != 0) {
		DEBUG(3, ("recycle: Move error %d (%s), purging file %s "
			  "(%s)\n", errno, strerror(errno),
			  smb_fname_str_dbg(full_fname),
			  smb_fname_str_dbg(smb_fname_final)));
		rc = SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp,
				smb_fname,
				flags);
		goto done;
	}

	/* touch access date of moved file */
	if (config->touch || config->touch_mtime)
		recycle_do_touch(handle, smb_fname_final, config->touch_mtime);

done:
	TALLOC_FREE(frame);
	return rc;
}

static int recycle_unlinkat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		int flags)
{
	int ret;

	if (flags & AT_REMOVEDIR) {
		ret = SMB_VFS_NEXT_UNLINKAT(handle,
					dirfsp,
					smb_fname,
					flags);
	} else {
		ret = recycle_unlink_internal(handle,
					dirfsp,
					smb_fname,
					flags);
	}
	return ret;
}

static struct vfs_fn_pointers vfs_recycle_fns = {
	.connect_fn = vfs_recycle_connect,
	.unlinkat_fn = recycle_unlinkat,
};

static_decl_vfs;
NTSTATUS vfs_recycle_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "recycle",
					&vfs_recycle_fns);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_recycle_debug_level = debug_add_class("recycle");
	if (vfs_recycle_debug_level == -1) {
		vfs_recycle_debug_level = DBGC_VFS;
		DEBUG(0, ("vfs_recycle: Couldn't register custom debugging class!\n"));
	} else {
		DEBUG(10, ("vfs_recycle: Debug class number of 'recycle': %d\n", vfs_recycle_debug_level));
	}

	return ret;
}
