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

static int fake_perms_connect(struct tcon_context *conn, const char *service, const char *user)    
{
	return default_vfs_ops.connect(conn, service, user);
}

static void fake_perms_disconnect(struct tcon_context *conn)
{
	default_vfs_ops.disconnect(conn);
}

static SMB_BIG_UINT fake_perms_disk_free(struct tcon_context *conn, const char *path,
	BOOL small_query, SMB_BIG_UINT *bsize,
	SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{
	return default_vfs_ops.disk_free(conn, path, small_query, bsize, 
					 dfree, dsize);
}

static DIR *fake_perms_opendir(struct tcon_context *conn, const char *fname)
{
	return default_vfs_ops.opendir(conn, fname);
}

static struct dirent *fake_perms_readdir(struct tcon_context *conn, DIR *dirp)
{
	return default_vfs_ops.readdir(conn, dirp);
}

static int fake_perms_mkdir(struct tcon_context *conn, const char *path, mode_t mode)
{
	return default_vfs_ops.mkdir(conn, path, mode);
}

static int fake_perms_rmdir(struct tcon_context *conn, const char *path)
{
	return default_vfs_ops.rmdir(conn, path);
}

static int fake_perms_closedir(struct tcon_context *conn, DIR *dir)
{
	return default_vfs_ops.closedir(conn, dir);
}

static int fake_perms_open(struct tcon_context *conn, const char *fname, int flags, mode_t mode)
{
	return default_vfs_ops.open(conn, fname, flags, mode);
}

static int fake_perms_close(struct files_struct *fsp, int fd)
{
	return default_vfs_ops.close(fsp, fd);
}

static ssize_t fake_perms_read(struct files_struct *fsp, int fd, void *data, size_t n)
{
	return default_vfs_ops.read(fsp, fd, data, n);
}

static ssize_t fake_perms_write(struct files_struct *fsp, int fd, const void *data, size_t n)
{
	return default_vfs_ops.write(fsp, fd, data, n);
}

static SMB_OFF_T fake_perms_lseek(struct files_struct *fsp, int filedes, SMB_OFF_T offset, int whence)
{
	return default_vfs_ops.lseek(fsp, filedes, offset, whence);
}

static int fake_perms_rename(struct tcon_context *conn, const char *old, const char *new)
{
	return default_vfs_ops.rename(conn, old, new);
}

static int fake_perms_fsync(struct files_struct *fsp, int fd)
{
	return default_vfs_ops.fsync(fsp, fd);
}

static int fake_perms_stat(struct tcon_context *conn, const char *fname, SMB_STRUCT_STAT *sbuf)
{
	int ret = default_vfs_ops.stat(conn, fname, sbuf);
	extern struct current_user current_user;
	
	if (S_ISDIR(sbuf->st_mode)) {
		sbuf->st_mode = S_IFDIR | S_IRWXU;
	} else {
		sbuf->st_mode = S_IRWXU;
	}
	sbuf->st_uid = current_user.uid;
	sbuf->st_gid = current_user.gid;
	return ret;
}

static int fake_perms_fstat(struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf)
{
	return default_vfs_ops.fstat(fsp, fd, sbuf);
}

static int fake_perms_lstat(struct tcon_context *conn, const char *path, SMB_STRUCT_STAT *sbuf)
{
	return default_vfs_ops.lstat(conn, path, sbuf);
}

static int fake_perms_unlink(struct tcon_context *conn, const char *path)
{
	return default_vfs_ops.unlink(conn, path);
}

static int fake_perms_chmod(struct tcon_context *conn, const char *path, mode_t mode)
{
	return default_vfs_ops.chmod(conn, path, mode);
}

static int fake_perms_fchmod(struct files_struct *fsp, int fd, mode_t mode)
{
	return default_vfs_ops.fchmod(fsp, fd, mode);
}

static int fake_perms_chown(struct tcon_context *conn, const char *path, uid_t uid, gid_t gid)
{
	return default_vfs_ops.chown(conn, path, uid, gid);
}

static int fake_perms_fchown(struct files_struct *fsp, int fd, uid_t uid, gid_t gid)
{
	return default_vfs_ops.fchown(fsp, fd, uid, gid);
}

static int fake_perms_chdir(struct tcon_context *conn, const char *path)
{
	return default_vfs_ops.chdir(conn, path);
}

static char *fake_perms_getwd(struct tcon_context *conn, char *buf)
{
	return default_vfs_ops.getwd(conn, buf);
}

static int fake_perms_utime(struct tcon_context *conn, const char *path, struct utimbuf *times)
{
	return default_vfs_ops.utime(conn, path, times);
}

static int fake_perms_ftruncate(struct files_struct *fsp, int fd, SMB_OFF_T offset)
{
	return default_vfs_ops.ftruncate(fsp, fd, offset);
}

static BOOL fake_perms_lock(struct files_struct *fsp, int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type)
{
	return default_vfs_ops.lock(fsp, fd, op, offset, count, type);
}

static BOOL fake_perms_symlink(struct tcon_context *conn, const char *oldpath, const char *newpath)
{
	return default_vfs_ops.symlink(conn, oldpath, newpath);
}

static BOOL fake_perms_readlink(struct tcon_context *conn, const char *path, char *buf, size_t bufsiz)
{
	return default_vfs_ops.readlink(conn, path, buf, bufsiz);
}

static int fake_perms_link(struct tcon_context *conn, const char *oldpath, const char *newpath)
{
	return default_vfs_ops.link(conn, oldpath, newpath);
}

static int fake_perms_mknod(struct tcon_context *conn, const char *path, mode_t mode, SMB_DEV_T dev)
{
	return default_vfs_ops.mknod(conn, path, mode, dev);
}

static char *fake_perms_realpath(struct tcon_context *conn, const char *path, char *resolved_path)
{
	return default_vfs_ops.realpath(conn, path, resolved_path);
}

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

static BOOL fake_perms_chmod_acl(struct tcon_context *conn, const char *name, mode_t mode)
{
	return default_vfs_ops.chmod_acl(conn, name, mode);
}

static BOOL fake_perms_fchmod_acl(struct files_struct *fsp, int fd, mode_t mode)
{
	return default_vfs_ops.fchmod_acl(fsp, fd, mode);
}

static int fake_perms_sys_acl_get_entry(struct tcon_context *conn, SMB_ACL_T theacl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	return default_vfs_ops.sys_acl_get_entry(conn, theacl, entry_id, entry_p);
}

static int fake_perms_sys_acl_get_tag_type(struct tcon_context *conn, SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
{
	return default_vfs_ops.sys_acl_get_tag_type(conn, entry_d, tag_type_p);
}

static int fake_perms_sys_acl_get_permset(struct tcon_context *conn, SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
	return default_vfs_ops.sys_acl_get_permset(conn, entry_d, permset_p);
}

static void *fake_perms_sys_acl_get_qualifier(struct tcon_context *conn, SMB_ACL_ENTRY_T entry_d)
{
	return default_vfs_ops.sys_acl_get_qualifier(conn, entry_d);
}

static SMB_ACL_T fake_perms_sys_acl_get_file(struct tcon_context *conn, const char *path_p, SMB_ACL_TYPE_T type)
{
	return default_vfs_ops.sys_acl_get_file(conn, path_p, type);
}

static SMB_ACL_T fake_perms_sys_acl_get_fd(struct files_struct *fsp, int fd)
{
	return default_vfs_ops.sys_acl_get_fd(fsp, fd);
}

static int fake_perms_sys_acl_clear_perms(struct tcon_context *conn, SMB_ACL_PERMSET_T permset)
{
	return default_vfs_ops.sys_acl_clear_perms(conn, permset);
}

static int fake_perms_sys_acl_add_perm(struct tcon_context *conn, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return default_vfs_ops.sys_acl_add_perm(conn, permset, perm);
}

static char *fake_perms_sys_acl_to_text(struct tcon_context *conn, SMB_ACL_T theacl, ssize_t *plen)
{
	return default_vfs_ops.sys_acl_to_text(conn, theacl, plen);
}

static SMB_ACL_T fake_perms_sys_acl_init(struct tcon_context *conn, int count)
{
	return default_vfs_ops.sys_acl_init(conn, count);
}

static int fake_perms_sys_acl_create_entry(struct tcon_context *conn, SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry)
{
	return default_vfs_ops.sys_acl_create_entry(conn, pacl, pentry);
}

static int fake_perms_sys_acl_set_tag_type(struct tcon_context *conn, SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype)
{
	return default_vfs_ops.sys_acl_set_tag_type(conn, entry, tagtype);
}

static int fake_perms_sys_acl_set_qualifier(struct tcon_context *conn, SMB_ACL_ENTRY_T entry, void *qual)
{
	return default_vfs_ops.sys_acl_set_qualifier(conn, entry, qual);
}

static int fake_perms_sys_acl_set_permset(struct tcon_context *conn, SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset)
{
	return default_vfs_ops.sys_acl_set_permset(conn, entry, permset);
}

static int fake_perms_sys_acl_valid(struct tcon_context *conn, SMB_ACL_T theacl )
{
	return default_vfs_ops.sys_acl_valid(conn, theacl );
}

static int fake_perms_sys_acl_set_file(struct tcon_context *conn, const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return default_vfs_ops.sys_acl_set_file(conn, name, acltype, theacl);
}

static int fake_perms_sys_acl_set_fd(struct files_struct *fsp, int fd, SMB_ACL_T theacl)
{
	return default_vfs_ops.sys_acl_set_fd(fsp, fd, theacl);
}

static int fake_perms_sys_acl_delete_def_file(struct tcon_context *conn, const char *path)
{
	return default_vfs_ops.sys_acl_delete_def_file(conn, path);
}

static int fake_perms_sys_acl_get_perm(struct tcon_context *conn, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return default_vfs_ops.sys_acl_get_perm(conn, permset, perm);
}

static int fake_perms_sys_acl_free_text(struct tcon_context *conn, char *text)
{
	return default_vfs_ops.sys_acl_free_text(conn, text);
}

static int fake_perms_sys_acl_free_acl(struct tcon_context *conn, SMB_ACL_T posix_acl)
{
	return default_vfs_ops.sys_acl_free_acl(conn, posix_acl);
}

static int fake_perms_sys_acl_free_qualifier(struct tcon_context *conn, void *qualifier, SMB_ACL_TAG_T tagtype)
{
	return default_vfs_ops.sys_acl_free_qualifier(conn, qualifier, tagtype);
}


/* VFS operations structure */

static vfs_op_tuple fake_perms_ops[] = {

	/* Disk operations */

	{fake_perms_connect,			SMB_VFS_OP_CONNECT, 		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_disconnect,		SMB_VFS_OP_DISCONNECT,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_disk_free,		SMB_VFS_OP_DISK_FREE,		SMB_VFS_LAYER_TRANSPARENT},
	
	/* Directory operations */

	{fake_perms_opendir,			SMB_VFS_OP_OPENDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_readdir,			SMB_VFS_OP_READDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_mkdir,			SMB_VFS_OP_MKDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_rmdir,			SMB_VFS_OP_RMDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_closedir,			SMB_VFS_OP_CLOSEDIR,		SMB_VFS_LAYER_TRANSPARENT},

	/* File operations */

	{fake_perms_open,			SMB_VFS_OP_OPEN,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_close,			SMB_VFS_OP_CLOSE,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_read,			SMB_VFS_OP_READ,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_write,			SMB_VFS_OP_WRITE,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_lseek,			SMB_VFS_OP_LSEEK,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_rename,			SMB_VFS_OP_RENAME,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_fsync,			SMB_VFS_OP_FSYNC,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_stat,			SMB_VFS_OP_STAT,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_fstat,			SMB_VFS_OP_FSTAT,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_lstat,			SMB_VFS_OP_LSTAT,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_unlink,			SMB_VFS_OP_UNLINK,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_chmod,			SMB_VFS_OP_CHMOD,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_fchmod,			SMB_VFS_OP_FCHMOD,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_chown,			SMB_VFS_OP_CHOWN,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_fchown,			SMB_VFS_OP_FCHOWN,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_chdir,			SMB_VFS_OP_CHDIR,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_getwd,			SMB_VFS_OP_GETWD,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_utime,			SMB_VFS_OP_UTIME,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_ftruncate,		SMB_VFS_OP_FTRUNCATE,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_lock,			SMB_VFS_OP_LOCK,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_symlink,			SMB_VFS_OP_SYMLINK,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_readlink,			SMB_VFS_OP_READLINK,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_link,			SMB_VFS_OP_LINK,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_mknod,			SMB_VFS_OP_MKNOD,		SMB_VFS_LAYER_TRANSPARENT},
	{fake_perms_realpath,			SMB_VFS_OP_REALPATH,		SMB_VFS_LAYER_TRANSPARENT},

	/* NT File ACL operations */

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
	
	{NULL,	SMB_VFS_OP_NOOP,	SMB_VFS_LAYER_NOOP}
};

/* VFS initialisation - return initialized vfs_op_tuple array back to Samba */

vfs_op_tuple *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops,
			struct smb_vfs_handle_struct *vfs_handle)
{
	DEBUG(3, ("Initialising default vfs hooks\n"));

	*vfs_version = SMB_VFS_INTERFACE_VERSION;
	memcpy(&default_vfs_ops, def_vfs_ops, sizeof(struct vfs_ops));
	
	/* Remember vfs_handle for further allocation and referencing of private
	   information in vfs_handle->data
	*/
	fake_perms_handle = vfs_handle;
	return fake_perms_ops;
}

/* VFS finalization function */
void vfs_done(struct tcon_context *conn)
{
	DEBUG(3, ("Finalizing default vfs hooks\n"));
}
