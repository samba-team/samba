/*
 * Widelinks VFS module. Causes smbd not to see symlinks.
 *
 * Copyright (C) Jeremy Allison, 2020
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

/*
 What does this module do ? It implements the explicitly insecure
 "widelinks = yes" functionality that used to be in the core smbd
 code.

 Now this is implemented here, the insecure share-escape code that
 explicitly allows escape from an exported share path can be removed
 from smbd, leaving it a cleaner and more maintainable code base.

 The smbd code can now always return ACCESS_DENIED if a path
 leads outside a share.

 How does it do that ? There are 2 features.

 1). When the upper layer code does a chdir() call to a pathname,
 this module stores the requested pathname inside config->cwd.

 When the upper layer code does a getwd() or realpath(), we return
 the absolute path of the value stored in config->cwd, *not* the
 position on the underlying filesystem.

 This hides symlinks as if the chdir pathname contains a symlink,
 normally doing a realpath call on it would return the real
 position on the filesystem. For widelinks = yes, this isn't what
 you want. You want the position you think is underneath the share
 definition - the symlink path you used to go outside the share,
 not the contents of the symlink itself.

 That way, the upper layer smbd code can strictly enforce paths
 being underneath a share definition without the knowledge that
 "widelinks = yes" has moved us outside the share definition.

 1a). Note that when setting up a share, smbd may make calls such
 as realpath and stat/lstat in order to set up the share definition.
 These calls are made *before* smbd calls chdir() to move the working
 directory below the exported share definition. In order to allow
 this, all the vfs_widelinks functions are coded to just pass through
 the vfs call to the next module in the chain if (a). The widelinks
 module was loaded in error by an administrator and widelinks is
 set to "no". This is the:

	if (!config->active) {
		Module not active.
		SMB_VFS_NEXT_XXXXX(...)
	}

 idiom in the vfs functions.

 1b). If the module was correctly active, but smbd has yet
 to call chdir(), then config->cwd == NULL. In that case
 the correct action (to match the previous widelinks behavior
 in the code inside smbd) is to pass through the vfs call to
 the next module in the chain. That way, any symlinks in the
 pathname are still exposed to smbd, which will restrict them to
 be under the exported share definition. This allows the module
 to "fail safe" for any vfs call made when setting up the share
 structure definition, rather than fail unsafe by hiding symlinks
 before chdir is called. This is the:

	if (config->cwd == NULL) {
		XXXXX syscall before chdir - see note 1b above.
		return SMB_VFS_NEXT_XXXXX()
	}

 idiom in the vfs functions.

 2). The module hides the existance of symlinks by inside
 lstat(), open(), and readdir() so long as it's not a POSIX
 pathname request (those requests *must* be aware of symlinks
 and the POSIX client has to follow them, it's expected that
 a server will always fail to follow symlinks).

 It does this by:

 2a). lstat -> stat
 2b). open removes any O_NOFOLLOW from flags.
 2c). The optimization in readdir that returns a stat
 struct is removed as this could return a symlink mode
 bit, causing smbd to always call stat/lstat itself on
 a pathname (which we'll then use to hide symlinks).

*/

#include "includes.h"
#include "smbd/smbd.h"
#include "lib/util_path.h"

struct widelinks_config {
	bool active;
	char *cwd;
};

static int widelinks_connect(struct vfs_handle_struct *handle,
			const char *service,
			const char *user)
{
	struct widelinks_config *config;
	int ret;

	ret = SMB_VFS_NEXT_CONNECT(handle,
				service,
				user);
	if (ret != 0) {
		return ret;
	}

	config = talloc_zero(handle->conn,
				struct widelinks_config);
	if (!config) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}
	config->active = lp_widelinks(SNUM(handle->conn));
	if (!config->active) {
		DBG_ERR("vfs_widelinks module loaded with "
			"widelinks = no\n");
	}

        SMB_VFS_HANDLE_SET_DATA(handle,
				config,
				NULL, /* free_fn */
				struct widelinks_config,
				return -1);
	return 0;
}

static int widelinks_chdir(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
	int ret = -1;
	struct widelinks_config *config = NULL;
	char *new_cwd = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct widelinks_config,
				return -1);

	if (!config->active) {
		/* Module not active. */
		return SMB_VFS_NEXT_CHDIR(handle, smb_fname);
	}

	/*
	 * We know we never get a path containing
	 * DOT or DOTDOT.
	 */

	if (smb_fname->base_name[0] == '/') {
		/* Absolute path - replace. */
		new_cwd = talloc_strdup(config,
				smb_fname->base_name);
	} else {
		if (config->cwd == NULL) {
			/*
			 * Relative chdir before absolute one -
			 * see note 1b above.
			 */
			struct smb_filename *current_dir_fname =
					SMB_VFS_NEXT_GETWD(handle,
							config);
			if (current_dir_fname == NULL) {
				return -1;
			}
			/* Paranoia.. */
			if (current_dir_fname->base_name[0] != '/') {
				DBG_ERR("SMB_VFS_NEXT_GETWD returned "
					"non-absolute path |%s|\n",
					current_dir_fname->base_name);
				TALLOC_FREE(current_dir_fname);
				return -1;
			}
			config->cwd = talloc_strdup(config,
					current_dir_fname->base_name);
			TALLOC_FREE(current_dir_fname);
			if (config->cwd == NULL) {
				return -1;
			}
		}
		new_cwd = talloc_asprintf(config,
				"%s/%s",
				config->cwd,
				smb_fname->base_name);
	}
	if (new_cwd == NULL) {
		return -1;
	}
	ret = SMB_VFS_NEXT_CHDIR(handle, smb_fname);
	if (ret == -1) {
		TALLOC_FREE(new_cwd);
		return ret;
	}
	/* Replace the cache we use for realpath/getwd. */
	TALLOC_FREE(config->cwd);
	config->cwd = new_cwd;
	DBG_DEBUG("config->cwd now |%s|\n", config->cwd);
	return 0;
}

static struct smb_filename *widelinks_getwd(vfs_handle_struct *handle,
                                TALLOC_CTX *ctx)
{
	struct widelinks_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct widelinks_config,
				return NULL);

	if (!config->active) {
		/* Module not active. */
		return SMB_VFS_NEXT_GETWD(handle, ctx);
	}
	if (config->cwd == NULL) {
		/* getwd before chdir. See note 1b above. */
		return SMB_VFS_NEXT_GETWD(handle, ctx);
	}
	return synthetic_smb_fname(ctx,
				config->cwd,
				NULL,
				NULL,
				0,
				0);
}

static struct smb_filename *widelinks_realpath(vfs_handle_struct *handle,
			TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname_in)
{
	struct widelinks_config *config = NULL;
	char *pathname = NULL;
	char *resolved_pathname = NULL;
	struct smb_filename *smb_fname;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct widelinks_config,
				return NULL);

	if (!config->active) {
		/* Module not active. */
		return SMB_VFS_NEXT_REALPATH(handle,
				ctx,
				smb_fname_in);
	}

	if (config->cwd == NULL) {
		/* realpath before chdir. See note 1b above. */
		return SMB_VFS_NEXT_REALPATH(handle,
				ctx,
				smb_fname_in);
	}

	if (smb_fname_in->base_name[0] == '/') {
		/* Absolute path - process as-is. */
		pathname = talloc_strdup(config,
					smb_fname_in->base_name);
	} else {
		/* Relative path - most commonly "." */
		pathname = talloc_asprintf(config,
				"%s/%s",
				config->cwd,
				smb_fname_in->base_name);
	}

	SMB_ASSERT(pathname[0] == '/');

	resolved_pathname = canonicalize_absolute_path(config, pathname);
	if (resolved_pathname == NULL) {
		TALLOC_FREE(pathname);
		return NULL;
	}

	DBG_DEBUG("realpath |%s| -> |%s| -> |%s|\n",
			smb_fname_in->base_name,
			pathname,
			resolved_pathname);

	smb_fname = synthetic_smb_fname(ctx,
				resolved_pathname,
				NULL,
				NULL,
				0,
				0);
	TALLOC_FREE(pathname);
	TALLOC_FREE(resolved_pathname);
	return smb_fname;
}

static int widelinks_lstat(vfs_handle_struct *handle,
			struct smb_filename *smb_fname)
{
	struct widelinks_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct widelinks_config,
				return -1);

	if (!config->active) {
		/* Module not active. */
		return SMB_VFS_NEXT_LSTAT(handle,
				smb_fname);
	}

	if (config->cwd == NULL) {
		/* lstat before chdir. See note 1b above. */
		return SMB_VFS_NEXT_LSTAT(handle,
				smb_fname);
	}

	if (smb_fname->flags & SMB_FILENAME_POSIX_PATH) {
		/* POSIX sees symlinks. */
		return SMB_VFS_NEXT_LSTAT(handle,
				smb_fname);
	}

	/* Replace with STAT. */
	return SMB_VFS_NEXT_STAT(handle, smb_fname);
}

static int widelinks_openat(vfs_handle_struct *handle,
			    const struct files_struct *dirfsp,
			    const struct smb_filename *smb_fname,
			    files_struct *fsp,
			    int flags,
			    mode_t mode)
{
	struct widelinks_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct widelinks_config,
				return -1);

	if (config->active &&
	    (config->cwd != NULL) &&
	    !(smb_fname->flags & SMB_FILENAME_POSIX_PATH))
	{
		/*
		 * Module active, openat after chdir (see note 1b above) and not
		 * a POSIX open (POSIX sees symlinks), so remove O_NOFOLLOW.
		 */
		flags = (flags & ~O_NOFOLLOW);
	}

	return SMB_VFS_NEXT_OPENAT(handle,
				   dirfsp,
				   smb_fname,
				   fsp,
				   flags,
				   mode);
}

static struct dirent *widelinks_readdir(vfs_handle_struct *handle,
			DIR *dirp,
			SMB_STRUCT_STAT *sbuf)
{
	struct widelinks_config *config = NULL;
	struct dirent *result;

	SMB_VFS_HANDLE_GET_DATA(handle,
				config,
				struct widelinks_config,
				return NULL);

	result = SMB_VFS_NEXT_READDIR(handle,
				dirp,
				sbuf);

	if (!config->active) {
		/* Module not active. */
		return result;
	}

	/*
	 * Prevent optimization of returning
	 * the stat info. Force caller to go
	 * through our LSTAT that hides symlinks.
	 */

	if (sbuf) {
		SET_STAT_INVALID(*sbuf);
	}
	return result;
}

static struct vfs_fn_pointers vfs_widelinks_fns = {
	.connect_fn = widelinks_connect,

	.openat_fn = widelinks_openat,
	.lstat_fn = widelinks_lstat,
	/*
	 * NB. We don't need an lchown function as this
	 * is only called (a) on directory create and
	 * (b) on POSIX extensions names.
	 */
	.chdir_fn = widelinks_chdir,
	.getwd_fn = widelinks_getwd,
	.realpath_fn = widelinks_realpath,
	.readdir_fn = widelinks_readdir
};

static_decl_vfs;
NTSTATUS vfs_widelinks_init(TALLOC_CTX *ctx)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
				"widelinks",
				&vfs_widelinks_fns);
}
