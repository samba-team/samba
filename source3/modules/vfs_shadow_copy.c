/*
 * implementation of an Shadow Copy module
 *
 * Copyright (C) Stefan Metzmacher	2003-2004
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
#include "ntioctl.h"
#include "source3/smbd/dir.h"

/*
    Please read the VFS module Samba-HowTo-Collection.
    there's a chapter about this module

    For this share
    Z:\

    the ShadowCopies are in this directories

    Z:\@GMT-2003.08.05-12.00.00\
    Z:\@GMT-2003.08.05-12.01.00\
    Z:\@GMT-2003.08.05-12.02.00\

    e.g.

    Z:\testfile.txt
    Z:\@GMT-2003.08.05-12.02.00\testfile.txt

    or:

    Z:\testdir\testfile.txt
    Z:\@GMT-2003.08.05-12.02.00\testdir\testfile.txt


    Note: Files must differ to be displayed via Windows Explorer!
	  Directories are always displayed...
*/

static int vfs_shadow_copy_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_shadow_copy_debug_level

#define SHADOW_COPY_PREFIX "@GMT-"
#define SHADOW_COPY_SAMPLE "@GMT-2004.02.18-15.44.00"

typedef struct {
	int pos;
	int num;
	struct dirent *dirs;
} shadow_copy_Dir;

static bool shadow_copy_match_name(const char *name)
{
	if (strncmp(SHADOW_COPY_PREFIX,name, sizeof(SHADOW_COPY_PREFIX)-1)==0 &&
		(strlen(SHADOW_COPY_SAMPLE) == strlen(name))) {
		return True;
	}

	return False;
}

static DIR *shadow_copy_fdopendir(vfs_handle_struct *handle, files_struct *fsp, const char *mask, uint32_t attr)
{
	shadow_copy_Dir *dirp;
	DIR *p = SMB_VFS_NEXT_FDOPENDIR(handle,fsp,mask,attr);

	if (!p) {
		DEBUG(10,("shadow_copy_opendir: SMB_VFS_NEXT_FDOPENDIR() failed for [%s]\n",
			smb_fname_str_dbg(fsp->fsp_name)));
		return NULL;
	}

	dirp = SMB_CALLOC_ARRAY(shadow_copy_Dir, 1);
	if (!dirp) {
		DEBUG(0,("shadow_copy_fdopendir: Out of memory\n"));
		SMB_VFS_NEXT_CLOSEDIR(handle,p);
		/* We have now closed the fd in fsp. */
		fsp_set_fd(fsp, -1);
		return NULL;
	}

	while (True) {
		struct dirent *d;

		d = SMB_VFS_NEXT_READDIR(handle, fsp, p);
		if (d == NULL) {
			break;
		}

		if (shadow_copy_match_name(d->d_name)) {
			DEBUG(8,("shadow_copy_fdopendir: hide [%s]\n",d->d_name));
			continue;
		}

		DEBUG(10,("shadow_copy_fdopendir: not hide [%s]\n",d->d_name));

		dirp->dirs = SMB_REALLOC_ARRAY(dirp->dirs,struct dirent, dirp->num+1);
		if (!dirp->dirs) {
			DEBUG(0,("shadow_copy_fdopendir: Out of memory\n"));
			break;
		}

		dirp->dirs[dirp->num++] = *d;
	}

	SMB_VFS_NEXT_CLOSEDIR(handle,p);
	/* We have now closed the fd in fsp. */
	fsp_set_fd(fsp, -1);
	return((DIR *)dirp);
}

static struct dirent *shadow_copy_readdir(vfs_handle_struct *handle,
					  struct files_struct *dirfsp,
					  DIR *_dirp)
{
	shadow_copy_Dir *dirp = (shadow_copy_Dir *)_dirp;

	if (dirp->pos < dirp->num) {
		return &(dirp->dirs[dirp->pos++]);
	}

	return NULL;
}

static void shadow_copy_rewinddir(struct vfs_handle_struct *handle, DIR *_dirp)
{
	shadow_copy_Dir *dirp = (shadow_copy_Dir *)_dirp;
	dirp->pos = 0 ;
}

static int shadow_copy_closedir(vfs_handle_struct *handle, DIR *_dirp)
{
	shadow_copy_Dir *dirp = (shadow_copy_Dir *)_dirp;

	SAFE_FREE(dirp->dirs);
	SAFE_FREE(dirp);

	return 0;
}

static int shadow_copy_get_shadow_copy_data(vfs_handle_struct *handle,
					    files_struct *fsp,
					    struct shadow_copy_data *shadow_copy_data,
					    bool labels)
{
	struct smb_Dir *dir_hnd = NULL;
	const char *dname = NULL;
	char *talloced = NULL;
	NTSTATUS status;
	struct smb_filename *smb_fname = synthetic_smb_fname(talloc_tos(),
						fsp->conn->connectpath,
						NULL,
						NULL,
						0,
						0);
	if (smb_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}

	status = OpenDir(talloc_tos(),
			 handle->conn,
			 smb_fname,
			 NULL,
			 0,
			 &dir_hnd);
	TALLOC_FREE(smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("OpenDir() failed for [%s]\n", fsp->conn->connectpath);
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	shadow_copy_data->num_volumes = 0;
	shadow_copy_data->labels = NULL;

	while (True) {
		SHADOW_COPY_LABEL *tmp_labels = NULL;
		int ret;

		dname = ReadDirName(dir_hnd, &talloced);
		if (dname == NULL) {
			break;
		}

		/* */
		if (!shadow_copy_match_name(dname)) {
			DBG_DEBUG("ignore [%s]\n", dname);
			TALLOC_FREE(talloced);
			continue;
		}

		DBG_DEBUG("not ignore [%s]\n", dname);

		if (!labels) {
			shadow_copy_data->num_volumes++;
			TALLOC_FREE(talloced);
			continue;
		}

		tmp_labels = talloc_realloc(shadow_copy_data, shadow_copy_data->labels,
				            SHADOW_COPY_LABEL, shadow_copy_data->num_volumes + 1);

		if (tmp_labels == NULL) {
			DEBUG(0,("shadow_copy_get_shadow_copy_data: Out of memory\n"));
			shadow_copy_data->num_volumes = 0;
			TALLOC_FREE(shadow_copy_data->labels);
			TALLOC_FREE(talloced);
			TALLOC_FREE(dir_hnd);
			return -1;
		}

		shadow_copy_data->labels = tmp_labels;

		ret = strlcpy(shadow_copy_data->labels[shadow_copy_data->num_volumes], dname,
			      sizeof(shadow_copy_data->labels[shadow_copy_data->num_volumes]));
		if (ret != sizeof(shadow_copy_data->labels[shadow_copy_data->num_volumes]) - 1) {
			DBG_ERR("malformed label %s\n", dname);
			shadow_copy_data->num_volumes = 0;
			TALLOC_FREE(shadow_copy_data->labels);
			TALLOC_FREE(talloced);
			TALLOC_FREE(dir_hnd);
			return -1;
		}
		shadow_copy_data->num_volumes++;

		TALLOC_FREE(talloced);
	}

	TALLOC_FREE(dir_hnd);
	return 0;
}

static struct vfs_fn_pointers vfs_shadow_copy_fns = {
	.fdopendir_fn = shadow_copy_fdopendir,
	.readdir_fn = shadow_copy_readdir,
	.rewind_dir_fn = shadow_copy_rewinddir,
	.closedir_fn = shadow_copy_closedir,
	.get_shadow_copy_data_fn = shadow_copy_get_shadow_copy_data,
};

static_decl_vfs;
NTSTATUS vfs_shadow_copy_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
					"shadow_copy", &vfs_shadow_copy_fns);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_shadow_copy_debug_level = debug_add_class("shadow_copy");
	if (vfs_shadow_copy_debug_level == -1) {
		vfs_shadow_copy_debug_level = DBGC_VFS;
		DEBUG(0, ("%s: Couldn't register custom debugging class!\n",
			"vfs_shadow_copy_init"));
	} else {
		DEBUG(10, ("%s: Debug class number of '%s': %d\n",
			"vfs_shadow_copy_init","shadow_copy",vfs_shadow_copy_debug_level));
	}

	return ret;
}
