/* 
 * ensure meta data operations are performed synchronously
 *
 * Copyright (C) Andrew Tridgell     2007
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

  Some filesystems (even some journaled filesystems) require that a
  fsync() be performed on many meta data operations to ensure that the
  operation is guaranteed to remain in the filesystem after a power
  failure. This is particularly important for some cluster filesystems
  which are participating in a node failover system with clustered
  Samba

  On those filesystems this module provides a way to perform those
  operations safely.  
 */

/*
  most of the performance loss with this module is in fsync on close(). 
  You can disable that with syncops:onclose = no
 */
static bool sync_onclose;

/*
  given a filename, find the parent directory
 */
static char *parent_dir(TALLOC_CTX *mem_ctx, const char *name)
{
	const char *p = strrchr(name, '/');
	if (p == NULL) {
		return talloc_strdup(mem_ctx, ".");
	}
	return talloc_strndup(mem_ctx, name, (p+1) - name);
}

/*
  fsync a directory by name
 */
static void syncops_sync_directory(const char *dname)
{
#ifdef O_DIRECTORY
	int fd = open(dname, O_DIRECTORY|O_RDONLY);
	if (fd != -1) {
		fsync(fd);
		close(fd);
	}
#else
	DIR *d = opendir(dname);
	if (d != NULL) {
		fsync(dirfd(d));
		closedir(d);
	}
#endif
}

/*
  sync two meta data changes for 2 names
 */
static void syncops_two_names(const char *name1, const char *name2)
{
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	char *parent1, *parent2;
	parent1 = parent_dir(tmp_ctx, name1);
	parent2 = parent_dir(tmp_ctx, name2);
	if (!parent1 || !parent2) {
		talloc_free(tmp_ctx);
		return;
	}
	syncops_sync_directory(parent1);
	if (strcmp(parent1, parent2) != 0) {
		syncops_sync_directory(parent2);		
	}
	talloc_free(tmp_ctx);
}

/*
  sync two meta data changes for 1 names
 */
static void syncops_name(const char *name)
{
	char *parent;
	parent = parent_dir(NULL, name);
	if (parent) {
		syncops_sync_directory(parent);
		talloc_free(parent);
	}
}


/*
  rename needs special handling, as we may need to fsync two directories
 */
static int syncops_rename(vfs_handle_struct *handle,
			  const char *oldname, const char *newname)
{
	int ret = SMB_VFS_NEXT_RENAME(handle, oldname, newname);
	if (ret == 0) {
		syncops_two_names(oldname, newname);
	}
	return ret;
}

/* handle the rest with a macro */
#define SYNCOPS_NEXT(op, fname, args) do {   \
	int ret = SMB_VFS_NEXT_ ## op args; \
	if (ret == 0 && fname) syncops_name(fname); \
	return ret; \
} while (0)

static int syncops_symlink(vfs_handle_struct *handle,
			   const char *oldname, const char *newname)
{
	SYNCOPS_NEXT(SYMLINK, newname, (handle, oldname, newname));
}

static int syncops_link(vfs_handle_struct *handle,
			 const char *oldname, const char *newname)
{
	SYNCOPS_NEXT(LINK, newname, (handle, oldname, newname));
}

static int syncops_open(vfs_handle_struct *handle,
			const char *fname, files_struct *fsp, int flags, mode_t mode)
{
	SYNCOPS_NEXT(OPEN, (flags&O_CREAT?fname:NULL), (handle, fname, fsp, flags, mode));
}

static int syncops_unlink(vfs_handle_struct *handle, const char *fname)
{
        SYNCOPS_NEXT(UNLINK, fname, (handle, fname));
}

static int syncops_mknod(vfs_handle_struct *handle,
			 const char *fname, mode_t mode, SMB_DEV_T dev)
{
        SYNCOPS_NEXT(MKNOD, fname, (handle, fname, mode, dev));
}

static int syncops_mkdir(vfs_handle_struct *handle,  const char *fname, mode_t mode)
{
        SYNCOPS_NEXT(MKDIR, fname, (handle, fname, mode));
}

static int syncops_rmdir(vfs_handle_struct *handle,  const char *fname)
{
        SYNCOPS_NEXT(RMDIR, fname, (handle, fname));
}

/* close needs to be handled specially */
static int syncops_close(vfs_handle_struct *handle, files_struct *fsp)
{
	if (fsp->can_write && sync_onclose) {
		/* ideally we'd only do this if we have written some
		 data, but there is no flag for that in fsp yet. */
		fsync(fsp->fh->fd);
	}
	return SMB_VFS_NEXT_CLOSE(handle, fsp);
}


/* VFS operations structure */

static vfs_op_tuple syncops_ops[] = {
	/* directory operations */
        {SMB_VFS_OP(syncops_mkdir),       SMB_VFS_OP_MKDIR,       SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(syncops_rmdir),       SMB_VFS_OP_RMDIR,       SMB_VFS_LAYER_TRANSPARENT},

        /* File operations */
        {SMB_VFS_OP(syncops_open),       SMB_VFS_OP_OPEN,     SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(syncops_rename),     SMB_VFS_OP_RENAME,   SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(syncops_unlink),     SMB_VFS_OP_UNLINK,   SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(syncops_symlink),    SMB_VFS_OP_SYMLINK,  SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(syncops_link),       SMB_VFS_OP_LINK,     SMB_VFS_LAYER_TRANSPARENT},
        {SMB_VFS_OP(syncops_mknod),      SMB_VFS_OP_MKNOD,    SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(syncops_close), 	 SMB_VFS_OP_CLOSE,    SMB_VFS_LAYER_TRANSPARENT},

	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_syncops_init(void)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "syncops", syncops_ops);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	sync_onclose = lp_parm_bool(-1, "syncops", "onclose", true);
	
	return ret;
}
