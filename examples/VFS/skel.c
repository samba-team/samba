/* 
 * Skeleton VFS module.  Implements passthrough operation of all VFS
 * calls to disk functions.
 *
 * Copyright (C) Tim Potter, 1999-2000
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

extern struct vfs_ops default_vfs_ops;   /* For passthrough operation */
extern struct vfs_ops skel_ops;

static int skel_connect(struct connection_struct *conn, char *service, char *user)    
{
	return default_vfs_ops.connect(conn, service, user);
}

static void skel_disconnect(struct connection_struct *conn)
{
	default_vfs_ops.disconnect(conn);
}

static SMB_BIG_UINT skel_disk_free(struct connection_struct *conn, char *path,
	BOOL small_query, SMB_BIG_UINT *bsize,
	SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{
	return default_vfs_ops.disk_free(conn, path, small_query, bsize, 
					 dfree, dsize);
}

static DIR *skel_opendir(struct connection_struct *conn, char *fname)
{
	return default_vfs_ops.opendir(conn, fname);
}

static struct dirent *skel_readdir(struct connection_struct *conn, DIR *dirp)
{
	return default_vfs_ops.readdir(conn, dirp);
}

static int skel_mkdir(struct connection_struct *conn, char *path, mode_t mode)
{
	return default_vfs_ops.mkdir(conn, path, mode);
}

static int skel_rmdir(struct connection_struct *conn, char *path)
{
	return default_vfs_ops.rmdir(conn, path);
}

static int skel_closedir(struct connection_struct *conn, DIR *dir)
{
	return default_vfs_ops.closedir(conn, dir);
}

static int skel_open(struct connection_struct *conn, char *fname, int flags, mode_t mode)
{
	return default_vfs_ops.open(conn, fname, flags, mode);
}

static int skel_close(struct files_struct *fsp, int fd)
{
	return default_vfs_ops.close(fsp, fd);
}

static ssize_t skel_read(struct files_struct *fsp, int fd, void *data, size_t n)
{
	return default_vfs_ops.read(fsp, fd, data, n);
}

static ssize_t skel_write(struct files_struct *fsp, int fd, const void *data, size_t n)
{
	return default_vfs_ops.write(fsp, fd, data, n);
}

static SMB_OFF_T skel_lseek(struct files_struct *fsp, int filedes, SMB_OFF_T offset, int whence)
{
	return default_vfs_ops.lseek(fsp, filedes, offset, whence);
}

static int skel_rename(struct connection_struct *conn, char *old, char *new)
{
	return default_vfs_ops.rename(conn, old, new);
}

static int skel_fsync(struct files_struct *fsp, int fd)
{
	return default_vfs_ops.fsync(fsp, fd);
}

static int skel_stat(struct connection_struct *conn, char *fname, SMB_STRUCT_STAT *sbuf)
{
	return default_vfs_ops.stat(conn, fname, sbuf);
}

static int skel_fstat(struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf)
{
	return default_vfs_ops.fstat(fsp, fd, sbuf);
}

static int skel_lstat(struct connection_struct *conn, char *path, SMB_STRUCT_STAT *sbuf)
{
	return default_vfs_ops.lstat(conn, path, sbuf);
}

static int skel_unlink(struct connection_struct *conn, char *path)
{
	return default_vfs_ops.unlink(conn, path);
}

static int skel_chmod(struct connection_struct *conn, char *path, mode_t mode)
{
	return default_vfs_ops.chmod(conn, path, mode);
}

static int skel_fchmod(struct files_struct *fsp, int fd, mode_t mode)
{
	return default_vfs_ops.fchmod(fsp, fd, mode);
}

static int skel_chown(struct connection_struct *conn, char *path, uid_t uid, gid_t gid)
{
	return default_vfs_ops.chown(conn, path, uid, gid);
}

static int skel_fchown(struct files_struct *fsp, int fd, uid_t uid, gid_t gid)
{
	return default_vfs_ops.fchown(fsp, fd, uid, gid);
}

static int skel_chdir(struct connection_struct *conn, char *path)
{
	return default_vfs_ops.chdir(conn, path);
}

static char *skel_getwd(struct connection_struct *conn, char *buf)
{
	return default_vfs_ops.getwd(conn, buf);
}

static int skel_utime(struct connection_struct *conn, char *path, struct utimbuf *times)
{
	return default_vfs_ops.utime(conn, path, times);
}

static int skel_ftruncate(struct files_struct *fsp, int fd, SMB_OFF_T offset)
{
	return default_vfs_ops.ftruncate(fsp, fd, offset);
}

static BOOL skel_lock(struct files_struct *fsp, int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type)
{
	return default_vfs_ops.lock(fsp, fd, op, offset, count, type);
}

static BOOL skel_symlink(struct connection_struct *conn, const char *oldpath, const char *newpath)
{
	return default_vfs_ops.symlink(conn, oldpath, newpath);
}

static BOOL skel_readlink(struct connection_struct *conn, const char *path, char *buf, size_t bufsiz)
{
	return default_vfs_ops.readlink(conn, path, buf, bufsiz);
}

static int skel_link(struct connection_struct *conn, const char *oldpath, const char *newpath)
{
	return default_vfs_ops.link(conn, oldpath, newpath);
}

static int skel_mknod(struct connection_struct *conn, const char *path, mode_t mode, SMB_DEV_T dev)
{
	return default_vfs_ops.mknod(conn, path, mode, dev);
}

static char *skel_realpath(struct connection_struct *conn, const char *path, char *resolved_path)
{
	return default_vfs_ops.realpath(conn, path, resolved_path);
}

static size_t skel_fget_nt_acl(struct files_struct *fsp, int fd, struct security_descriptor_info **ppdesc)
{
	return default_vfs_ops.fget_nt_acl(fsp, fd, ppdesc);
}

static size_t skel_get_nt_acl(struct files_struct *fsp, char *name, struct security_descriptor_info **ppdesc)
{
	return default_vfs_ops.get_nt_acl(fsp, name, ppdesc);
}

static BOOL skel_fset_nt_acl(struct files_struct *fsp, int fd, uint32 security_info_sent, struct security_descriptor_info *psd)
{
	return default_vfs_ops.fset_nt_acl(fsp, fd, security_info_sent, psd);
}

static BOOL skel_set_nt_acl(struct files_struct *fsp, char *name, uint32 security_info_sent, struct security_descriptor_info *psd)
{
	return default_vfs_ops.set_nt_acl(fsp, name, security_info_sent, psd);
}

static BOOL skel_chmod_acl(struct connection_struct *conn, char *name, mode_t mode)
{
	return default_vfs_ops.chmod_acl(conn, name, mode);
}

static BOOL skel_fchmod_acl(struct files_struct *fsp, int fd, mode_t mode)
{
	return default_vfs_ops.fchmod_acl(fsp, fd, mode);
}

static int skel_sys_acl_get_entry(struct connection_struct *conn, SMB_ACL_T theacl, int entry_id, SMB_ACL_ENTRY_T *entry_p)
{
	return default_vfs_ops.sys_acl_get_entry(conn, theacl, entry_id, entry_p);
}

static int skel_sys_acl_get_tag_type(struct connection_struct *conn, SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p)
{
	return default_vfs_ops.sys_acl_get_tag_type(conn, entry_d, tag_type_p);
}

static int skel_sys_acl_get_permset(struct connection_struct *conn, SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p)
{
	return default_vfs_ops.sys_acl_get_permset(conn, entry_d, permset_p);
}

static void *skel_sys_acl_get_qualifier(struct connection_struct *conn, SMB_ACL_ENTRY_T entry_d)
{
	return default_vfs_ops.sys_acl_get_qualifier(conn, entry_d);
}

static SMB_ACL_T skel_sys_acl_get_file(struct connection_struct *conn, const char *path_p, SMB_ACL_TYPE_T type)
{
	return default_vfs_ops.sys_acl_get_file(conn, path_p, type);
}

static SMB_ACL_T skel_sys_acl_get_fd(struct files_struct *fsp, int fd)
{
	return default_vfs_ops.sys_acl_get_fd(fsp, fd);
}

static int skel_sys_acl_clear_perms(struct connection_struct *conn, SMB_ACL_PERMSET_T permset)
{
	return default_vfs_ops.sys_acl_clear_perms(conn, permset);
}

static int skel_sys_acl_add_perm(struct connection_struct *conn, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return default_vfs_ops.sys_acl_add_perm(conn, permset, perm);
}

static char *skel_sys_acl_to_text(struct connection_struct *conn, SMB_ACL_T theacl, ssize_t *plen)
{
	return default_vfs_ops.sys_acl_to_text(conn, theacl, plen);
}

static SMB_ACL_T skel_sys_acl_init(struct connection_struct *conn, int count)
{
	return default_vfs_ops.sys_acl_init(conn, count);
}

static int skel_sys_acl_create_entry(struct connection_struct *conn, SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry)
{
	return default_vfs_ops.sys_acl_create_entry(conn, pacl, pentry);
}

static int skel_sys_acl_set_tag_type(struct connection_struct *conn, SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype)
{
	return default_vfs_ops.sys_acl_set_tag_type(conn, entry, tagtype);
}

static int skel_sys_acl_set_qualifier(struct connection_struct *conn, SMB_ACL_ENTRY_T entry, void *qual)
{
	return default_vfs_ops.sys_acl_set_qualifier(conn, entry, qual);
}

static int skel_sys_acl_set_permset(struct connection_struct *conn, SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset)
{
	return default_vfs_ops.sys_acl_set_permset(conn, entry, permset);
}

static int skel_sys_acl_valid(struct connection_struct *conn, SMB_ACL_T theacl )
{
	return default_vfs_ops.sys_acl_valid(conn, theacl );
}

static int skel_sys_acl_set_file(struct connection_struct *conn, const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	return default_vfs_ops.sys_acl_set_file(conn, name, acltype, theacl);
}

static int skel_sys_acl_set_fd(struct files_struct *fsp, int fd, SMB_ACL_T theacl)
{
	return default_vfs_ops.sys_acl_set_fd(fsp, fd, theacl);
}

static int skel_sys_acl_delete_def_file(struct connection_struct *conn, const char *path)
{
	return default_vfs_ops.sys_acl_delete_def_file(conn, path);
}

static int skel_sys_acl_get_perm(struct connection_struct *conn, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm)
{
	return default_vfs_ops.sys_acl_get_perm(conn, permset, perm);
}

static int skel_sys_acl_free_text(struct connection_struct *conn, char *text)
{
	return default_vfs_ops.sys_acl_free_text(conn, text);
}

static int skel_sys_acl_free_acl(struct connection_struct *conn, SMB_ACL_T posix_acl)
{
	return default_vfs_ops.sys_acl_free_acl(conn, posix_acl);
}

static int skel_sys_acl_free_qualifier(struct connection_struct *conn, void *qualifier, SMB_ACL_TAG_T tagtype)
{
	return default_vfs_ops.sys_acl_free_qualifier(conn, qualifier, tagtype);
}

/* VFS initialisation - return vfs_ops function pointer structure */

struct vfs_ops *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops)
{
	struct vfs_ops tmp_ops;

	DEBUG(3, ("Initialising default vfs hooks\n"));

	*vfs_version = SMB_VFS_INTERFACE_VERSION;
	memcpy(&tmp_ops, def_vfs_ops, sizeof(struct vfs_ops));

	tmp_ops.connect = skel_connect;
	tmp_ops.disconnect = skel_disconnect;
	tmp_ops.disk_free = skel_disk_free;

	/* Directory operations */

	tmp_ops.opendir = skel_opendir;
	tmp_ops.readdir = skel_readdir;
	tmp_ops.mkdir = skel_mkdir;
	tmp_ops.rmdir = skel_rmdir;
	tmp_ops.closedir = skel_closedir;

	/* File operations */

	tmp_ops.open = skel_open;
	tmp_ops.close = skel_close;
	tmp_ops.read = skel_read;
	tmp_ops.write = skel_write;
	tmp_ops.lseek = skel_lseek;
	tmp_ops.rename = skel_rename;
	tmp_ops.fsync = skel_fsync;
	tmp_ops.stat = skel_stat;
	tmp_ops.fstat = skel_fstat;
	tmp_ops.lstat = skel_lstat;
	tmp_ops.unlink = skel_unlink;
	tmp_ops.chmod = skel_chmod;
	tmp_ops.fchmod = skel_fchmod;
	tmp_ops.chown = skel_chown;
	tmp_ops.fchown = skel_fchown;
	tmp_ops.chdir = skel_chdir;
	tmp_ops.getwd = skel_getwd;
	tmp_ops.utime = skel_utime;
	tmp_ops.ftruncate = skel_ftruncate;
	tmp_ops.lock = skel_lock;
	tmp_ops.symlink = skel_symlink;
	tmp_ops.readlink = skel_readlink;
	tmp_ops.link = skel_link;
	tmp_ops.mknod = skel_mknod;
	tmp_ops.realpath = skel_realpath;

	tmp_ops.fget_nt_acl = skel_fget_nt_acl;
	tmp_ops.get_nt_acl = skel_get_nt_acl;
	tmp_ops.fset_nt_acl = skel_fset_nt_acl;
	tmp_ops.set_nt_acl = skel_set_nt_acl;

	/* POSIX ACL operations. */

	tmp_ops.chmod_acl = skel_chmod_acl;
	tmp_ops.fchmod_acl = skel_fchmod_acl;
	tmp_ops.sys_acl_get_entry = skel_sys_acl_get_entry;
	tmp_ops.sys_acl_get_tag_type = skel_sys_acl_get_tag_type;
	tmp_ops.sys_acl_get_permset = skel_sys_acl_get_permset;
	tmp_ops.sys_acl_get_qualifier = skel_sys_acl_get_qualifier;
	tmp_ops.sys_acl_get_file = skel_sys_acl_get_file;
	tmp_ops.sys_acl_get_fd = skel_sys_acl_get_fd;
	tmp_ops.sys_acl_clear_perms = skel_sys_acl_clear_perms;
	tmp_ops.sys_acl_add_perm = skel_sys_acl_add_perm;
	tmp_ops.sys_acl_to_text = skel_sys_acl_to_text;
	tmp_ops.sys_acl_init = skel_sys_acl_init;
	tmp_ops.sys_acl_create_entry = skel_sys_acl_create_entry;
	tmp_ops.sys_acl_set_tag_type = skel_sys_acl_set_tag_type;
	tmp_ops.sys_acl_set_qualifier = skel_sys_acl_set_qualifier;
	tmp_ops.sys_acl_set_permset = skel_sys_acl_set_permset;
	tmp_ops.sys_acl_valid = skel_sys_acl_valid;
	tmp_ops.sys_acl_set_file = skel_sys_acl_set_file;
	tmp_ops.sys_acl_set_fd = skel_sys_acl_set_fd;
	tmp_ops.sys_acl_delete_def_file = skel_sys_acl_delete_def_file;
	tmp_ops.sys_acl_get_perm = skel_sys_acl_get_perm;
	tmp_ops.sys_acl_free_text = skel_sys_acl_free_text;
	tmp_ops.sys_acl_free_acl = skel_sys_acl_free_acl;
	tmp_ops.sys_acl_free_qualifier = skel_sys_acl_free_qualifier;

	memcpy(&skel_ops, &tmp_ops, sizeof(struct vfs_ops));

	return &skel_ops;
}

/* VFS operations structure */

struct vfs_ops skel_ops = {

	/* Disk operations */

	skel_connect,
	skel_disconnect,
	skel_disk_free,
	
	/* Directory operations */

	skel_opendir,
	skel_readdir,
	skel_mkdir,
	skel_rmdir,
	skel_closedir,

	/* File operations */

	skel_open,
	skel_close,
	skel_read,
	skel_write,
	skel_lseek,
	skel_rename,
	skel_fsync,
	skel_stat,
	skel_fstat,
	skel_lstat,
	skel_unlink,
	skel_chmod,
	skel_fchmod,
	skel_chown,
	skel_fchown,
	skel_chdir,
	skel_getwd,
	skel_utime,
	skel_ftruncate,
	skel_lock,
	skel_symlink,
	skel_readlink,
	skel_link,
	skel_mknod,
	skel_realpath,

	/* NT File ACL operations */

	skel_fget_nt_acl,
	skel_get_nt_acl,
	skel_fset_nt_acl,
	skel_set_nt_acl,

	/* POSIX ACL operations */

	skel_chmod_acl,
	skel_fchmod_acl,

	skel_sys_acl_get_entry,
	skel_sys_acl_get_tag_type,
	skel_sys_acl_get_permset,
	skel_sys_acl_get_qualifier,
	skel_sys_acl_get_file,
	skel_sys_acl_get_fd,
	skel_sys_acl_clear_perms,
	skel_sys_acl_add_perm,
	skel_sys_acl_to_text,
	skel_sys_acl_init,
	skel_sys_acl_create_entry,
	skel_sys_acl_set_tag_type,
	skel_sys_acl_set_qualifier,
	skel_sys_acl_set_permset,
	skel_sys_acl_valid,
	skel_sys_acl_set_file,
	skel_sys_acl_set_fd,
	skel_sys_acl_delete_def_file,
	skel_sys_acl_get_perm,
	skel_sys_acl_free_text,
	skel_sys_acl_free_acl,
	skel_sys_acl_free_qualifier
};
