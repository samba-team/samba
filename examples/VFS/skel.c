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
struct vfs_ops skel_ops;



/* VFS initialisation - return vfs_ops function pointer structure */

BOOL vfs_init(connection_struct *conn)
{
    DEBUG(3, ("Initialising default vfs hooks\n"));
 
    memcpy(&conn->vfs_ops, &skel_ops, sizeof(struct vfs_ops));
    return True;
}

int skel_connect(struct connection_struct *conn, char *service, char *user)    
{
	return default_vfs_ops.connect(conn, service, user);
}

void skel_disconnect(struct connection_struct *conn)
{
	default_vfs_ops.disconnect(conn);
}

SMB_BIG_UINT skel_disk_free(struct connection_struct *conn, char *path,
	BOOL small_query, SMB_BIG_UINT *bsize,
	SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{
	return default_vfs_ops.disk_free(conn, path, small_query, bsize, 
					 dfree, dsize);
}

DIR *skel_opendir(struct connection_struct *conn, char *fname)
{
	return default_vfs_ops.opendir(conn, fname);
}

struct dirent *skel_readdir(struct connection_struct *conn, DIR *dirp)
{
	return default_vfs_ops.readdir(conn, dirp);
}

int skel_mkdir(struct connection_struct *conn, char *path, mode_t mode)
{
	return default_vfs_ops.mkdir(conn, path, mode);
}

int skel_rmdir(struct connection_struct *conn, char *path)
{
	return default_vfs_ops.rmdir(conn, path);
}

int skel_closedir(struct connection_struct *conn, DIR *dir)
{
	return default_vfs_ops.closedir(conn, dir);
}

int skel_open(struct connection_struct *conn, char *fname, int flags, mode_t mode)
{
	return default_vfs_ops.open(conn, fname, flags, mode);
}

int skel_close(struct files_struct *fsp, int fd)
{
	return default_vfs_ops.close(fsp, fd);
}

ssize_t skel_read(struct files_struct *fsp, int fd, char *data, size_t n)
{
	return default_vfs_ops.read(fsp, fd, data, n);
}

ssize_t skel_write(struct files_struct *fsp, int fd, char *data, size_t n)
{
	return default_vfs_ops.write(fsp, fd, data, n);
}

SMB_OFF_T skel_lseek(struct files_struct *fsp, int filedes, SMB_OFF_T offset, int whence)
{
	return default_vfs_ops.lseek(fsp, filedes, offset, whence);
}

int skel_rename(struct connection_struct *conn, char *old, char *new)
{
	return default_vfs_ops.rename(conn, old, new);
}

int skel_fsync(struct files_struct *fsp, int fd)
{
	return default_vfs_ops.fsync(fsp, fd);
}

int skel_stat(struct connection_struct *conn, char *fname, SMB_STRUCT_STAT *sbuf)
{
	return default_vfs_ops.stat(conn, fname, sbuf);
}

int skel_fstat(struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf)
{
	return default_vfs_ops.fstat(fsp, fd, sbuf);
}

int skel_lstat(struct connection_struct *conn, char *path, SMB_STRUCT_STAT *sbuf)
{
	return default_vfs_ops.lstat(conn, path, sbuf);
}

int skel_unlink(struct connection_struct *conn, char *path)
{
	return default_vfs_ops.unlink(conn, path);
}

int skel_chmod(struct connection_struct *conn, char *path, mode_t mode)
{
	return default_vfs_ops.chmod(conn, path, mode);
}

int skel_fchmod(struct files_struct *fsp, int fd, mode_t mode)
{
	return default_vfs_ops.fchmod(fsp, fd, mode);
}

int skel_chown(struct connection_struct *conn, char *path, uid_t uid, gid_t gid)
{
	return default_vfs_ops.chown(conn, path, uid, gid);
}

int skel_fchown(struct files_struct *fsp, int fd, uid_t uid, gid_t gid)
{
	return default_vfs_ops.fchown(fsp, fd, uid, gid);
}

int skel_chdir(struct connection_struct *conn, char *path)
{
	return default_vfs_ops.chdir(conn, path);
}

char *skel_getwd(struct connection_struct *conn, char *buf)
{
	return default_vfs_ops.getwd(conn, buf);
}

int skel_utime(struct connection_struct *conn, char *path, struct utimbuf *times)
{
	return default_vfs_ops.utime(conn, path, times);
}

int skel_ftruncate(struct files_struct *fsp, int fd, SMB_OFF_T offset)
{
	return default_vfs_ops.ftruncate(fsp, fd, offset);
}

BOOL skel_lock(struct files_struct *fsp, int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type)
{
	return default_vfs_ops.lock(fsp, fd, op, offset, count, type);
}

BOOL skel_symlink(struct connection_struct *conn, const char *oldpath, const char *newpath)
{
	return default_vfs_ops.symlink(conn, oldpath, newpath);
}

BOOL skel_readlink(struct connection_struct *conn, const char *path, char *buf, size_t bufsiz)
{
	return default_vfs_ops.readlink(conn, path, buf, bufsiz);
}

size_t skel_fget_nt_acl(struct files_struct *fsp, int fd, struct security_descriptor_info **ppdesc)
{
	return default_vfs_ops.fget_nt_acl(fsp, fd, ppdesc);
}

size_t skel_get_nt_acl(struct files_struct *fsp, char *name, struct security_descriptor_info **ppdesc)
{
	return default_vfs_ops.get_nt_acl(fsp, name, ppdesc);
}

BOOL skel_fset_nt_acl(struct files_struct *fsp, int fd, uint32 security_info_sent, struct security_descriptor_info *psd)
{
	return default_vfs_ops.fset_nt_acl(fsp, fd, security_info_sent, psd);
}

BOOL skel_set_nt_acl(struct files_struct *fsp, char *name, uint32 security_info_sent, struct security_descriptor_info *psd)
{
	return default_vfs_ops.set_nt_acl(fsp, name, security_info_sent, psd);
}

BOOL skel_chmod_acl(struct connection_struct *conn, char *name, mode_t mode)
{
	return default_vfs_ops.chmod_acl(conn, name, mode);
}

BOOL skel_fchmod_acl(struct files_struct *fsp, int fd, mode_t mode)
{
	return default_vfs_ops.fchmod_acl(fsp, fd, mode);
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

	/* NT File ACL operations */

        skel_fget_nt_acl,
        skel_get_nt_acl,
        skel_fset_nt_acl,
        skel_set_nt_acl,

	skel_chmod_acl,
	skel_fchmod_acl
};
