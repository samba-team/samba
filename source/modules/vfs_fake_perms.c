/* 
 * Fake Perms VFS module.  Implements passthrough operation of all VFS
 * calls to disk functions, except for file permissions, which are now
 * mode 0700 for the current uid/gid.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Andrew Bartlett, 2002
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

#include "config.h"

#include <stdio.h>
#include <sys/stat.h>
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <errno.h>
#include <string.h>

#include <includes.h>
#include <vfs.h>

static struct vfs_ops default_vfs_ops;   /* For passthrough operation */
static struct smb_vfs_handle_struct *fake_perms_handle; /* use fake_perms_handle->data for storing per-instance private data */

static int fake_perms_stat(struct connection_struct *conn, const char *fname, SMB_STRUCT_STAT *sbuf)
{
	int ret = default_vfs_ops.stat(conn, fname, sbuf);
	if (ret == 0) {
		extern struct current_user current_user;
		
		if (S_ISDIR(sbuf->st_mode)) {
			sbuf->st_mode = S_IFDIR | S_IRWXU;
		} else {
			sbuf->st_mode = S_IRWXU;
		}
		sbuf->st_uid = current_user.uid;
		sbuf->st_gid = current_user.gid;
	}
	return ret;
}

static int fake_perms_fstat(struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf)
{
	int ret = default_vfs_ops.fstat(fsp, fd, sbuf);
	if (ret == 0) {
		extern struct current_user current_user;
		
		if (S_ISDIR(sbuf->st_mode)) {
			sbuf->st_mode = S_IFDIR | S_IRWXU;
		} else {
			sbuf->st_mode = S_IRWXU;
		}
		sbuf->st_uid = current_user.uid;
		sbuf->st_gid = current_user.gid;
	}
	return ret;
}

#if 0
static size_t fake_perms_fget_nt_acl(struct files_struct *fsp, int fd, struct security_descriptor_info **ppdesc)
{
	return default_vfs_ops.fget_nt_acl(fsp, fd, ppdesc);
}

static size_t fake_perms_get_nt_acl(struct files_struct *fsp, const char *name, struct security_descriptor_info **ppdesc)
{
	return default_vfs_ops.get_nt_acl(fsp, name, ppdesc);
}

static BOOL fake_perms_fset_nt_acl(struct files_struct *fsp, int fd, uint32 security_info_sent, struct security_descriptor_info *psd)
{
	return default_vfs_ops.fset_nt_acl(fsp, fd, security_info_sent, psd);
}

static BOOL fake_perms_set_nt_acl(struct files_struct *fsp, const char *name, uint32 security_info_sent, struct security_descriptor_info *psd)
{
	return default_vfs_ops.set_nt_acl(fsp, name, security_info_sent, psd);
}

static BOOL fake_perms_chmod_acl(struct connection_struct *conn, const char *name, mode_t mode)
{
	return default_vfs_ops.chmod_acl(conn, name, mode);
}

static BOOL fake_perms_fchmod_acl(struct files_struct *fsp, int fd, mode_t mode)
{
	return default_vfs_ops.fchmod_acl(fsp, fd, mode);
}

static int fake_perms_sys_acl_get_entry(struct connection_struct *conn, SMB_ACL_T theacl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	return default_vfs_ops.sys_acl_get_entry(conn, theacl, entry_id, entry_p);
}

static int fake_perms_sys_acl_get_tag_type(struct connection_struct *conn, SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
{
	return default_vfs_ops.sys_acl_get_tag_type(conn, entry_d, tag_type_p);
}

static int fake_perms_sys_acl_get_permset(struct connection_struct *conn, SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
	return default_vfs_ops.sys_acl_get_permset(conn, entry_d, permset_p);
}

static void *fake_perms_sys_acl_get_qualifier(struct connection_struct *conn, SMB_ACL_ENTRY_T entry_d)
{
	return default_vfs_ops.sys_acl_get_qualifier(conn, entry_d);
}

static SMB_ACL_T fake_perms_sys_acl_get_file(struct connection_struct *conn, const char *path_p, SMB_ACL_TYPE_T type)
{
	return default_vfs_ops.sys_acl_get_file(conn, path_p, type);
}

static SMB_ACL_T fake_perms_sys_acl_get_fd(struct files_struct *fsp, int fd)
{
	return default_vfs_ops.sys_acl_get_fd(fsp, fd);
}

static int fake_perms_sys_acl_clear_perms(struct connection_struct *conn, SMB_ACL_PERMSET_T permset)
{
	return default_vfs_ops.sys_acl_clear_perms(conn, permset);
}

static int fake_perms_sys_acl_add_perm(struct connection_struct *conn, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return default_vfs_ops.sys_acl_add_perm(conn, permset, perm);
}

static char *fake_perms_sys_acl_to_text(struct connection_struct *conn, SMB_ACL_T theacl, ssize_t *plen)
{
	return default_vfs_ops.sys_acl_to_text(conn, theacl, plen);
}

static SMB_ACL_T fake_perms_sys_acl_init(struct connection_struct *conn, int count)
{
	return default_vfs_ops.sys_acl_init(conn, count);
}

static int fake_perms_sys_acl_create_entry(struct connection_struct *conn, SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry)
{
	return default_vfs_ops.sys_acl_create_entry(conn, pacl, pentry);
}

static int fake_perms_sys_acl_set_tag_type(struct connection_struct *conn, SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype)
{
	return default_vfs_ops.sys_acl_set_tag_type(conn, entry, tagtype);
}

static int fake_perms_sys_acl_set_qualifier(struct connection_struct *conn, SMB_ACL_ENTRY_T entry, void *qual)
{
	return default_vfs_ops.sys_acl_set_qualifier(conn, entry, qual);
}

static int fake_perms_sys_acl_set_permset(struct connection_struct *conn, SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset)
{
	return default_vfs_ops.sys_acl_set_permset(conn, entry, permset);
}

static int fake_perms_sys_acl_valid(struct connection_struct *conn, SMB_ACL_T theacl )
{
	return default_vfs_ops.sys_acl_valid(conn, theacl );
}

static int fake_perms_sys_acl_set_file(struct connection_struct *conn, const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return default_vfs_ops.sys_acl_set_file(conn, name, acltype, theacl);
}

static int fake_perms_sys_acl_set_fd(struct files_struct *fsp, int fd, SMB_ACL_T theacl)
{
	return default_vfs_ops.sys_acl_set_fd(fsp, fd, theacl);
}

static int fake_perms_sys_acl_delete_def_file(struct connection_struct *conn, const char *path)
{
	return default_vfs_ops.sys_acl_delete_def_file(conn, path);
}

static int fake_perms_sys_acl_get_perm(struct connection_struct *conn, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return default_vfs_ops.sys_acl_get_perm(conn, permset, perm);
}

static int fake_perms_sys_acl_free_text(struct connection_struct *conn, char *text)
{
	return default_vfs_ops.sys_acl_free_text(conn, text);
}

static int fake_perms_sys_acl_free_acl(struct connection_struct *conn, SMB_ACL_T posix_acl)
{
	return default_vfs_ops.sys_acl_free_acl(conn, posix_acl);
}

static int fake_perms_sys_acl_free_qualifier(struct connection_struct *conn, void *qualifier, SMB_ACL_TAG_T tagtype)
{
	return default_vfs_ops.sys_acl_free_qualifier(conn, qualifier, tagtype);
}
#endif

/* VFS operations structure */

static vfs_op_tuple fake_perms_ops[] = {

	/* NT File ACL operations */
#if 0
	{fake_perms_fget_nt_acl,		SMB_VFS_OP_FGET_NT_ACL,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_get_nt_acl,		SMB_VFS_OP_GET_NT_ACL,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_fset_nt_acl,		SMB_VFS_OP_FSET_NT_ACL,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_set_nt_acl,		SMB_VFS_OP_SET_NT_ACL,		SMB_VFS_LAYER_TRANSPARENT},

	/* POSIX ACL operations */

	{fake_perms_chmod_acl,		SMB_VFS_OP_CHMOD_ACL,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_fchmod_acl,		SMB_VFS_OP_FCHMOD_ACL,		SMB_VFS_LAYER_TRANSPARENT},

	{fake_perms_sys_acl_get_entry,	SMB_VFS_OP_SYS_ACL_GET_ENTRY,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_get_tag_type,	SMB_VFS_OP_SYS_ACL_GET_TAG_TYPE,	SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_get_permset,	SMB_VFS_OP_SYS_ACL_GET_PERMSET,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_get_qualifier,	SMB_VFS_OP_SYS_ACL_GET_QUALIFIER,	SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_get_file,		SMB_VFS_OP_SYS_ACL_GET_FILE,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_get_fd,		SMB_VFS_OP_SYS_ACL_GET_FD,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_clear_perms,	SMB_VFS_OP_SYS_ACL_CLEAR_PERMS,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_add_perm,		SMB_VFS_OP_SYS_ACL_ADD_PERM,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_to_text,		SMB_VFS_OP_SYS_ACL_TO_TEXT,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_init,		SMB_VFS_OP_SYS_ACL_INIT,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_create_entry,	SMB_VFS_OP_SYS_ACL_CREATE_ENTRY,	SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_set_tag_type,	SMB_VFS_OP_SYS_ACL_SET_TAG_TYPE,	SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_set_qualifier,	SMB_VFS_OP_SYS_ACL_SET_QUALIFIER,	SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_set_permset,	SMB_VFS_OP_SYS_ACL_SET_PERMSET,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_valid,		SMB_VFS_OP_SYS_ACL_VALID,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_set_file,		SMB_VFS_OP_SYS_ACL_SET_FILE,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_set_fd,		SMB_VFS_OP_SYS_ACL_SET_FD,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_delete_def_file,	SMB_VFS_OP_SYS_ACL_DELETE_DEF_FILE,	SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_get_perm,		SMB_VFS_OP_SYS_ACL_GET_PERM,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_free_text,	SMB_VFS_OP_SYS_ACL_FREE_TEXT,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_free_acl,		SMB_VFS_OP_SYS_ACL_FREE_ACL,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_sys_acl_free_qualifier,	SMB_VFS_OP_SYS_ACL_FREE_QUALIFIER,	SMB_VFS_LAYER_TRANSPARENT},
#endif
	
	{fake_perms_stat,	SMB_VFS_OP_STAT,	SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_fstat,	SMB_VFS_OP_FSTAT,	SMB_VFS_LAYER_TRANSPARENT},
	{NULL,	SMB_VFS_OP_NOOP,	SMB_VFS_LAYER_NOOP}
};

/* VFS initialisation - return initialized vfs_op_tuple array back to Samba */

static vfs_op_tuple *fake_perms_init(const struct vfs_ops *def_vfs_ops,
			struct smb_vfs_handle_struct *vfs_handle)
{
	DEBUG(3, ("Initialising default vfs hooks\n"));

	memcpy(&default_vfs_ops, def_vfs_ops, sizeof(struct vfs_ops));
	
	/* Remember vfs_handle for further allocation and referencing of private
	   information in vfs_handle->data
	*/
	fake_perms_handle = vfs_handle;
	return fake_perms_ops;
}

int vfs_fake_perms_init(void)
{
	return smb_register_vfs("fake_perms", fake_perms_init, SMB_VFS_INTERFACE_VERSION);
}
