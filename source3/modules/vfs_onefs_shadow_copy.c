/*
 * OneFS shadow copy implementation that utilizes the file system's native
 * snapshot support. This is based on the original shadow copy module from
 * 2004.
 *
 * Copyright (C) Stefan Metzmacher	2003-2004
 * Copyright (C) Tim Prouty		2009
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
#include "onefs_shadow_copy.h"

static int vfs_onefs_shadow_copy_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_onefs_shadow_copy_debug_level

#define SHADOW_COPY_PREFIX "@GMT-"
#define SHADOW_COPY_SAMPLE "@GMT-2004.02.18-15.44.00"

bool
shadow_copy_match_name(const char *name, char **snap_component)
{
	uint32  i = 0;
	char delim[] = SHADOW_COPY_PREFIX;
	char* start;

	start = strstr( name, delim );

	/*
	 * The name could have SHADOW_COPY_PREFIX in it so we need to keep
	 * trying until we get something that is the full length of the
	 * SHADOW_COPY_SAMPLE.
	 */
	while (start != NULL) {

		DEBUG(10,("Processing %s\n", name));

		/* size / correctness check */
		*snap_component = start;
		for ( i = sizeof(SHADOW_COPY_PREFIX);
		      i < sizeof(SHADOW_COPY_SAMPLE); i++) {
			if (start[i] == '/') {
				if (i == sizeof(SHADOW_COPY_SAMPLE) - 1)
					return true;
				else
					break;
			} else if (start[i] == '\0')
				return (i == sizeof(SHADOW_COPY_SAMPLE) - 1);
		}

		start = strstr( start, delim );
	}

	return false;
}

static int
onefs_shadow_copy_get_shadow_copy_data(vfs_handle_struct *handle,
				       files_struct *fsp,
				       SHADOW_COPY_DATA *shadow_copy_data,
				       bool labels)
{
	void *p = osc_version_opendir();
	char *snap_component = NULL;
	shadow_copy_data->num_volumes = 0;
	shadow_copy_data->labels = NULL;

	if (!p) {
		DEBUG(0, ("shadow_copy_get_shadow_copy_data: osc_opendir() "
			  "failed for [%s]\n",fsp->conn->connectpath));
		return -1;
	}

	while (true) {
		SHADOW_COPY_LABEL *tlabels;
		char *d;

		d = osc_version_readdir(p);
		if (d == NULL)
			break;

		if (!shadow_copy_match_name(d, &snap_component)) {
			DEBUG(10,("shadow_copy_get_shadow_copy_data: ignore "
				  "[%s]\n",d));
			continue;
		}

		DEBUG(7,("shadow_copy_get_shadow_copy_data: not ignore "
			 "[%s]\n",d));

		if (!labels) {
			shadow_copy_data->num_volumes++;
			continue;
		}

		tlabels = (SHADOW_COPY_LABEL *)TALLOC_REALLOC(
			shadow_copy_data->mem_ctx,
			shadow_copy_data->labels,
			(shadow_copy_data->num_volumes+1) *
			sizeof(SHADOW_COPY_LABEL));

		if (tlabels == NULL) {
			DEBUG(0,("shadow_copy_get_shadow_copy_data: Out of "
				 "memory\n"));
			osc_version_closedir(p);
			return -1;
		}

		snprintf(tlabels[shadow_copy_data->num_volumes++],
			 sizeof(*tlabels), "%s",d);

		shadow_copy_data->labels = tlabels;
	}

	osc_version_closedir(p);

	return 0;
}

#define SHADOW_NEXT(op, args, rtype) do {			      \
	char *cpath = NULL;					      \
	char *snap_component = NULL;				      \
	rtype ret;						      \
	if (shadow_copy_match_name(path, &snap_component))	      \
		cpath = osc_canonicalize_path(path, snap_component); \
	ret = SMB_VFS_NEXT_ ## op args;				      \
	SAFE_FREE(cpath);					      \
	return ret;						      \
	} while (0)						      \



static uint64_t
onefs_shadow_copy_disk_free(vfs_handle_struct *handle, const char *path,
			    bool small_query, uint64_t *bsize, uint64_t *dfree,
			    uint64_t *dsize)
{

	SHADOW_NEXT(DISK_FREE,
		    (handle, cpath ?: path, small_query, bsize, dfree, dsize),
		    uint64_t);

}

static int
onefs_shadow_copy_statvfs(struct vfs_handle_struct *handle, const char *path,
			  struct vfs_statvfs_struct *statbuf)
{
	SHADOW_NEXT(STATVFS,
		    (handle, cpath ?: path, statbuf),
		    int);
}

static SMB_STRUCT_DIR *
onefs_shadow_copy_opendir(vfs_handle_struct *handle, const char *path,
			  const char *mask, uint32_t attr)
{
	SHADOW_NEXT(OPENDIR,
		    (handle, cpath ?: path, mask, attr),
		    SMB_STRUCT_DIR *);
}

static int
onefs_shadow_copy_mkdir(vfs_handle_struct *handle, const char *path,
			mode_t mode)
{
	SHADOW_NEXT(MKDIR,
		    (handle, cpath ?: path, mode),
		    int);
}

static int
onefs_shadow_copy_rmdir(vfs_handle_struct *handle, const char *path)
{
	SHADOW_NEXT(RMDIR,
		    (handle, cpath ?: path),
		    int);
}

static int
onefs_shadow_copy_open(vfs_handle_struct *handle, const char *path,
		       files_struct *fsp, int flags, mode_t mode)
{
	SHADOW_NEXT(OPEN,
		    (handle, cpath ?: path, fsp, flags, mode),
		    int);
}

static NTSTATUS
onefs_shadow_copy_create_file(vfs_handle_struct *handle,
			      struct smb_request *req,
			      uint16_t root_dir_fid,
			      const char *path,
			      uint32_t create_file_flags,
			      uint32_t access_mask,
			      uint32_t share_access,
			      uint32_t create_disposition,
			      uint32_t create_options,
			      uint32_t file_attributes,
			      uint32_t oplock_request,
			      uint64_t allocation_size,
			      struct security_descriptor *sd,
			      struct ea_list *ea_list,
			      files_struct **result,
			      int *pinfo,
			      SMB_STRUCT_STAT *psbuf)
{
	SHADOW_NEXT(CREATE_FILE,
		    (handle, req, root_dir_fid, cpath ?: path,
			create_file_flags, access_mask, share_access,
			create_disposition, create_options, file_attributes,
			oplock_request, allocation_size, sd, ea_list, result,
			pinfo, psbuf),
		    NTSTATUS);
}

/**
 * XXX: macro-ize
 */
static int
onefs_shadow_copy_rename(vfs_handle_struct *handle, const char *old_name,
			 const char *new_name)
{
	char *old_cpath = NULL;
	char *old_snap_component = NULL;
	char *new_cpath = NULL;
	char *new_snap_component = NULL;
	int ret;

	if (shadow_copy_match_name(old_name, &old_snap_component))
		old_cpath = osc_canonicalize_path(old_name, old_snap_component);

	if (shadow_copy_match_name(new_name, &new_snap_component))
		new_cpath = osc_canonicalize_path(new_name, new_snap_component);

        ret = SMB_VFS_NEXT_RENAME(handle, old_cpath ?: old_name,
	    new_cpath ?: new_name);

	SAFE_FREE(old_cpath);
	SAFE_FREE(new_cpath);

	return ret;
}

static int
onefs_shadow_copy_stat(vfs_handle_struct *handle, const char *path,
		       SMB_STRUCT_STAT *sbuf)
{
	SHADOW_NEXT(STAT,
		    (handle, cpath ?: path, sbuf),
		    int);
}

static int
onefs_shadow_copy_lstat(vfs_handle_struct *handle, const char *path,
			SMB_STRUCT_STAT *sbuf)
{
	SHADOW_NEXT(LSTAT,
		    (handle, cpath ?: path, sbuf),
		    int);
}

static int
onefs_shadow_copy_unlink(vfs_handle_struct *handle, const char *path)
{
	SHADOW_NEXT(UNLINK,
		    (handle, cpath ?: path),
		    int);
}

static int
onefs_shadow_copy_chmod(vfs_handle_struct *handle, const char *path,
			mode_t mode)
{
	SHADOW_NEXT(CHMOD,
		    (handle, cpath ?: path, mode),
		    int);
}

static int
onefs_shadow_copy_chown(vfs_handle_struct *handle, const char *path,
			uid_t uid, gid_t gid)
{
	SHADOW_NEXT(CHOWN,
		    (handle, cpath ?: path, uid, gid),
		    int);
}

static int
onefs_shadow_copy_lchown(vfs_handle_struct *handle, const char *path,
			 uid_t uid, gid_t gid)
{
	SHADOW_NEXT(LCHOWN,
		    (handle, cpath ?: path, uid, gid),
		    int);
}

static int
onefs_shadow_copy_chdir(vfs_handle_struct *handle, const char *path)
{
	SHADOW_NEXT(CHDIR,
		    (handle, cpath ?: path),
		    int);
}

static int
onefs_shadow_copy_ntimes(vfs_handle_struct *handle, const char *path,
			struct smb_file_time *ft)
{
	SHADOW_NEXT(NTIMES,
		    (handle, cpath ?: path, ft),
		    int);

}

/**
 * XXX: macro-ize
 */
static bool
onefs_shadow_copy_symlink(vfs_handle_struct *handle,
    const char *oldpath, const char *newpath)
{
	char *old_cpath = NULL;
	char *old_snap_component = NULL;
	char *new_cpath = NULL;
	char *new_snap_component = NULL;
	bool ret;

	if (shadow_copy_match_name(oldpath, &old_snap_component))
		old_cpath = osc_canonicalize_path(oldpath, old_snap_component);

	if (shadow_copy_match_name(newpath, &new_snap_component))
		new_cpath = osc_canonicalize_path(newpath, new_snap_component);

        ret = SMB_VFS_NEXT_SYMLINK(handle, old_cpath ?: oldpath,
	    new_cpath ?: newpath);

	SAFE_FREE(old_cpath);
	SAFE_FREE(new_cpath);

	return ret;
}

static bool
onefs_shadow_copy_readlink(vfs_handle_struct *handle, const char *path,
			   char *buf, size_t bufsiz)
{
	SHADOW_NEXT(READLINK,
		    (handle, cpath ?: path, buf, bufsiz),
		    bool);
}

/**
 * XXX: macro-ize
 */
static int
onefs_shadow_copy_link(vfs_handle_struct *handle, const char *oldpath,
		       const char *newpath)
{
	char *old_cpath = NULL;
	char *old_snap_component = NULL;
	char *new_cpath = NULL;
	char *new_snap_component = NULL;
	int ret;

	if (shadow_copy_match_name(oldpath, &old_snap_component))
		old_cpath = osc_canonicalize_path(oldpath, old_snap_component);

	if (shadow_copy_match_name(newpath, &new_snap_component))
		new_cpath = osc_canonicalize_path(newpath, new_snap_component);

        ret = SMB_VFS_NEXT_LINK(handle, old_cpath ?: oldpath,
	    new_cpath ?: newpath);

	SAFE_FREE(old_cpath);
	SAFE_FREE(new_cpath);

	return ret;
}

static int
onefs_shadow_copy_mknod(vfs_handle_struct *handle, const char *path,
			mode_t mode, SMB_DEV_T dev)
{
	SHADOW_NEXT(MKNOD,
		    (handle, cpath ?: path, mode, dev),
		    int);
}

static char *
onefs_shadow_copy_realpath(vfs_handle_struct *handle, const char *path,
			   char *resolved_path)
{
	SHADOW_NEXT(REALPATH,
		    (handle, cpath ?: path, resolved_path),
		    char *);
}

static int onefs_shadow_copy_chflags(struct vfs_handle_struct *handle,
				     const char *path, unsigned int flags)
{
	SHADOW_NEXT(CHFLAGS,
		    (handle, cpath ?: path, flags),
		    int);
}

static NTSTATUS
onefs_shadow_copy_streaminfo(struct vfs_handle_struct *handle,
			     struct files_struct *fsp,
			     const char *path,
			     TALLOC_CTX *mem_ctx,
			     unsigned int *num_streams,
			     struct stream_struct **streams)
{
	SHADOW_NEXT(STREAMINFO,
		    (handle, fsp, cpath ?: path, mem_ctx, num_streams,
			streams),
		    NTSTATUS);
}

static int
onefs_shadow_copy_get_real_filename(struct vfs_handle_struct *handle,
				    const char *full_path,
				    const char *path,
				    TALLOC_CTX *mem_ctx,
				    char **found_name)
{
	SHADOW_NEXT(GET_REAL_FILENAME,
		    (handle, full_path, cpath ?: path, mem_ctx, found_name),
		    int);
}

static NTSTATUS
onefs_shadow_copy_get_nt_acl(struct vfs_handle_struct *handle,
			    const char *path, uint32 security_info,
			    struct security_descriptor **ppdesc)
{
	SHADOW_NEXT(GET_NT_ACL,
		    (handle, cpath ?: path, security_info, ppdesc),
		    NTSTATUS);
}

static int
onefs_shadow_copy_chmod_acl(vfs_handle_struct *handle, const char *path,
			    mode_t mode)
{
	SHADOW_NEXT(CHMOD_ACL,
		    (handle, cpath ?: path, mode),
		    int);
}

static SMB_ACL_T
onefs_shadow_copy_sys_acl_get_file(vfs_handle_struct *handle,
				   const char *path, SMB_ACL_TYPE_T type)
{
	SHADOW_NEXT(SYS_ACL_GET_FILE,
		    (handle, cpath ?: path, type),
		    SMB_ACL_T);
}

static int
onefs_shadow_copy_sys_acl_set_file(vfs_handle_struct *handle, const char *path,
				   SMB_ACL_TYPE_T type, SMB_ACL_T theacl)
{
	SHADOW_NEXT(SYS_ACL_SET_FILE,
		    (handle, cpath ?: path, type, theacl),
		    int);
}

static int
onefs_shadow_copy_sys_acl_delete_def_file(vfs_handle_struct *handle,
					  const char *path)
{
	SHADOW_NEXT(SYS_ACL_DELETE_DEF_FILE,
		    (handle, cpath ?: path),
		    int);
}

static ssize_t
onefs_shadow_copy_getxattr(vfs_handle_struct *handle, const char *path,
			   const char *name, void *value, size_t size)
{
	SHADOW_NEXT(GETXATTR,
		    (handle, cpath ?: path, name, value, size),
		    ssize_t);
}

static ssize_t
onefs_shadow_copy_lgetxattr(vfs_handle_struct *handle, const char *path,
			    const char *name, void *value, size_t size)
{
	SHADOW_NEXT(LGETXATTR,
		    (handle, cpath ?: path, name, value, size),
		    ssize_t);
}

static ssize_t
onefs_shadow_copy_listxattr(vfs_handle_struct *handle, const char *path,
			    char *list, size_t size)
{
	SHADOW_NEXT(LISTXATTR,
		    (handle, cpath ?: path, list, size),
		    ssize_t);
}

static ssize_t
onefs_shadow_copy_llistxattr(vfs_handle_struct *handle, const char *path,
			     char *list, size_t size)
{
	SHADOW_NEXT(LLISTXATTR,
		    (handle, cpath ?: path, list, size),
		    ssize_t);
}

static int
onefs_shadow_copy_removexattr(vfs_handle_struct *handle, const char *path,
			      const char *name)
{
	SHADOW_NEXT(REMOVEXATTR,
		    (handle, cpath ?: path, name),
		    int);
}

static int
onefs_shadow_copy_lremovexattr(vfs_handle_struct *handle, const char *path,
			       const char *name)
{
	SHADOW_NEXT(LREMOVEXATTR,
		    (handle, cpath ?: path, name),
		    int);
}

static int
onefs_shadow_copy_setxattr(vfs_handle_struct *handle, const char *path,
			   const char *name, const void *value, size_t size,
			   int flags)
{
	SHADOW_NEXT(SETXATTR,
		    (handle, cpath ?: path, name, value, size, flags),
		    int);
}

static int
onefs_shadow_copy_lsetxattr(vfs_handle_struct *handle, const char *path,
			    const char *name, const void *value, size_t size,
			    int flags)
{
	SHADOW_NEXT(LSETXATTR,
		    (handle, cpath ?: path, name, value, size, flags),
		    int);
}

static bool
onefs_shadow_copy_is_offline(struct vfs_handle_struct *handle,
			     const char *path, SMB_STRUCT_STAT *sbuf)
{
	SHADOW_NEXT(IS_OFFLINE,
		    (handle, cpath ?: path, sbuf),
		    bool);
}

static int
onefs_shadow_copy_set_offline(struct vfs_handle_struct *handle,
			      const char *path)
{
	SHADOW_NEXT(SET_OFFLINE,
		    (handle, cpath ?: path),
		    int);
}

/* VFS operations structure */

static vfs_op_tuple onefs_shadow_copy_ops[] = {

	/* Disk operations */

	{SMB_VFS_OP(onefs_shadow_copy_disk_free), SMB_VFS_OP_DISK_FREE,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_get_shadow_copy_data),
	 SMB_VFS_OP_GET_SHADOW_COPY_DATA, SMB_VFS_LAYER_OPAQUE},
	{SMB_VFS_OP(onefs_shadow_copy_statvfs), SMB_VFS_OP_STATVFS,
	 SMB_VFS_LAYER_TRANSPARENT},

	/* Directory operations */

	{SMB_VFS_OP(onefs_shadow_copy_opendir), SMB_VFS_OP_OPENDIR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_mkdir), SMB_VFS_OP_MKDIR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_rmdir), SMB_VFS_OP_RMDIR,
	 SMB_VFS_LAYER_TRANSPARENT},

	/* File operations */

	{SMB_VFS_OP(onefs_shadow_copy_open), SMB_VFS_OP_OPEN,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_create_file), SMB_VFS_OP_CREATE_FILE,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_rename), SMB_VFS_OP_RENAME,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_stat), SMB_VFS_OP_STAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_stat), SMB_VFS_OP_STAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_lstat), SMB_VFS_OP_LSTAT,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_unlink), SMB_VFS_OP_UNLINK,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_chmod), SMB_VFS_OP_CHMOD,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_chown), SMB_VFS_OP_CHOWN,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_lchown), SMB_VFS_OP_LCHOWN,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_chdir), SMB_VFS_OP_CHDIR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_ntimes), SMB_VFS_OP_NTIMES,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_symlink), SMB_VFS_OP_SYMLINK,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_readlink), SMB_VFS_OP_READLINK,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_link), SMB_VFS_OP_LINK,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_mknod), SMB_VFS_OP_MKNOD,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_realpath), SMB_VFS_OP_REALPATH,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_chflags), SMB_VFS_OP_CHFLAGS,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_streaminfo), SMB_VFS_OP_STREAMINFO,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_get_real_filename),
	 SMB_VFS_OP_GET_REAL_FILENAME, SMB_VFS_LAYER_TRANSPARENT},

	/* NT File ACL operations */

	{SMB_VFS_OP(onefs_shadow_copy_get_nt_acl), SMB_VFS_OP_GET_NT_ACL,
	 SMB_VFS_LAYER_TRANSPARENT},

	/* POSIX ACL operations */

	{SMB_VFS_OP(onefs_shadow_copy_chmod_acl), SMB_VFS_OP_CHMOD_ACL,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_sys_acl_get_file),
	 SMB_VFS_OP_SYS_ACL_GET_FILE, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_sys_acl_set_file),
	 SMB_VFS_OP_SYS_ACL_SET_FILE, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_sys_acl_delete_def_file),
	 SMB_VFS_OP_SYS_ACL_DELETE_DEF_FILE, SMB_VFS_LAYER_TRANSPARENT},

        /* EA operations. */

	{SMB_VFS_OP(onefs_shadow_copy_getxattr), SMB_VFS_OP_GETXATTR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_lgetxattr), SMB_VFS_OP_LGETXATTR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_listxattr), SMB_VFS_OP_LISTXATTR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_llistxattr), SMB_VFS_OP_LLISTXATTR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_removexattr), SMB_VFS_OP_REMOVEXATTR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_lremovexattr), SMB_VFS_OP_LREMOVEXATTR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_setxattr), SMB_VFS_OP_SETXATTR,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_lsetxattr), SMB_VFS_OP_LSETXATTR,
	 SMB_VFS_LAYER_TRANSPARENT},

	/* offline operations */
	{SMB_VFS_OP(onefs_shadow_copy_is_offline), SMB_VFS_OP_IS_OFFLINE,
	 SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(onefs_shadow_copy_set_offline), SMB_VFS_OP_SET_OFFLINE,
	 SMB_VFS_LAYER_TRANSPARENT},

	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_shadow_copy_init(void)
{
	NTSTATUS ret;

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
			       "onefs_shadow_copy",
			       onefs_shadow_copy_ops);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_onefs_shadow_copy_debug_level = debug_add_class("onefs_shadow_copy");

	if (vfs_onefs_shadow_copy_debug_level == -1) {
		vfs_onefs_shadow_copy_debug_level = DBGC_VFS;
		DEBUG(0, ("Couldn't register custom debugging class!\n"));
	} else {
		DEBUG(10, ("Debug class number of 'onefs_shadow_copy': %d\n",
			   vfs_onefs_shadow_copy_debug_level));
	}

	return ret;
}
