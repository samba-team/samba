/* 
 * implementation of an Shadow Copy module
 *
 * Copyright (C) Stefan Metzmacher	2003-2004
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

#include "includes.h"

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

static BOOL shadow_copy_match_name(const char *name)
{
	if (strncmp(SHADOW_COPY_PREFIX,name, sizeof(SHADOW_COPY_PREFIX)-1)==0 &&
		(strlen(SHADOW_COPY_SAMPLE) == strlen(name))) {
		return True;
	}

	return False;
}

static DIR *shadow_copy_opendir(vfs_handle_struct *handle, connection_struct *conn, const char *fname)
{
	shadow_copy_Dir *dirp;
	DIR *p = SMB_VFS_NEXT_OPENDIR(handle,conn,fname);

	if (!p) {
		DEBUG(0,("shadow_copy_opendir: SMB_VFS_NEXT_OPENDIR() failed for [%s]\n",fname));
		return NULL;
	}

	dirp = (shadow_copy_Dir *)malloc(sizeof(shadow_copy_Dir));
	if (!dirp) {
		DEBUG(0,("shadow_copy_opendir: Out of memory\n"));
		SMB_VFS_NEXT_CLOSEDIR(handle,conn,p);
		return NULL;
	}

	ZERO_STRUCTP(dirp);

	while (True) {
		struct dirent *d;
		struct dirent *r;


		d = SMB_VFS_NEXT_READDIR(handle, conn, p);
		if (d == NULL) {
			break;
		}

		if (shadow_copy_match_name(d->d_name)) {
			DEBUG(8,("shadow_copy_opendir: hide [%s]\n",d->d_name));
			continue;
		}

		DEBUG(10,("shadow_copy_opendir: not hide [%s]\n",d->d_name));

		r = (struct dirent *)Realloc(dirp->dirs,(dirp->num+1)*sizeof(struct dirent));
		if (!r) {
			DEBUG(0,("shadow_copy_opendir: Out of memory\n"));
			break;
		}

		dirp->dirs = r;
		dirp->dirs[dirp->num++] = *d;
	}

	SMB_VFS_NEXT_CLOSEDIR(handle,conn,p);
	return((DIR *)dirp);
}

struct dirent *shadow_copy_readdir(vfs_handle_struct *handle, connection_struct *conn, DIR *_dirp)
{
	shadow_copy_Dir *dirp = (shadow_copy_Dir *)_dirp;

	if (dirp->pos < dirp->num) {
		return &(dirp->dirs[dirp->pos++]);
	}

	return NULL;
}

int shadow_copy_closedir(vfs_handle_struct *handle, connection_struct *conn, DIR *_dirp)
{
	shadow_copy_Dir *dirp = (shadow_copy_Dir *)_dirp;

	SAFE_FREE(dirp);
 
	return 0;	
}

static int shadow_copy_get_shadow_copy_data(vfs_handle_struct *handle, files_struct *fsp, SHADOW_COPY_DATA *shadow_copy_data, BOOL labels)
{
	DIR *p = SMB_VFS_NEXT_OPENDIR(handle,fsp->conn,fsp->conn->connectpath);

	shadow_copy_data->num_volumes = 0;
	shadow_copy_data->labels = NULL;

	if (!p) {
		DEBUG(0,("shadow_copy_get_shadow_copy_data: SMB_VFS_NEXT_OPENDIR() failed for [%s]\n",fsp->conn->connectpath));
		return -1;
	}

	while (True) {
		SHADOW_COPY_LABEL *tlabels;
		struct dirent *d;

		d = SMB_VFS_NEXT_READDIR(handle, fsp->conn, p);
		if (d == NULL) {
			break;
		}

		/* */
		if (!shadow_copy_match_name(d->d_name)) {
			DEBUG(10,("shadow_copy_get_shadow_copy_data: ignore [%s]\n",d->d_name));
			continue;
		}

		DEBUG(7,("shadow_copy_get_shadow_copy_data: not ignore [%s]\n",d->d_name));

		if (!labels) {
			shadow_copy_data->num_volumes++;
			continue;
		}

		tlabels = (SHADOW_COPY_LABEL *)talloc_realloc(shadow_copy_data->mem_ctx,
									shadow_copy_data->labels,
									(shadow_copy_data->num_volumes+1)*sizeof(SHADOW_COPY_LABEL));
		if (tlabels == NULL) {
			DEBUG(0,("shadow_copy_get_shadow_copy_data: Out of memory\n"));
			SMB_VFS_NEXT_CLOSEDIR(handle,fsp->conn,p);
			return -1;
		}

		snprintf(tlabels[shadow_copy_data->num_volumes++], sizeof(*tlabels), "%s",d->d_name);

		shadow_copy_data->labels = tlabels;
	}

	SMB_VFS_NEXT_CLOSEDIR(handle,fsp->conn,p);
	return 0;
}

/* VFS operations structure */

static vfs_op_tuple shadow_copy_ops[] = {
	{SMB_VFS_OP(shadow_copy_opendir),		SMB_VFS_OP_OPENDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(shadow_copy_readdir),		SMB_VFS_OP_READDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(shadow_copy_closedir),		SMB_VFS_OP_CLOSEDIR,		SMB_VFS_LAYER_TRANSPARENT},

	{SMB_VFS_OP(shadow_copy_get_shadow_copy_data),	SMB_VFS_OP_GET_SHADOW_COPY_DATA,SMB_VFS_LAYER_OPAQUE},

	{SMB_VFS_OP(NULL),				SMB_VFS_OP_NOOP,		SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_shadow_copy_init(void)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "shadow_copy", shadow_copy_ops);

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
