/* 
 * Skeleton VFS module.
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
 *
 * $Id: skel.c,v 1.3 2000/04/05 22:42:26 tpot Exp $
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

#include <vfs.h>

/* Function prototypes */

int skel_connect(struct vfs_connection_struct *conn, char *svc, char *user);
void skel_disconnect(void);
SMB_BIG_UINT skel_disk_free(char *path, BOOL smallquery, SMB_BIG_UINT *bsize, 
			    SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);

DIR *skel_opendir(char *fname);
struct dirent *skel_readdir(DIR *dirp);
int skel_mkdir(char *path, mode_t mode);
int skel_rmdir(char *path);
int skel_closedir(DIR *dir);

int skel_open(char *fname, int flags, mode_t mode);
int skel_close(int fd);
ssize_t skel_read(int fd, char *data, size_t n);
ssize_t skel_write(int fd, char *data, size_t n);
SMB_OFF_T skel_lseek(int filedes, SMB_OFF_T offset, int whence);
int skel_rename(char *old, char *new);
int skel_fsync(int fd);
int skel_stat(char *fname, SMB_STRUCT_STAT *sbuf);
int skel_fstat(int fd, SMB_STRUCT_STAT *sbuf);
int skel_lstat(char *path, SMB_STRUCT_STAT *sbuf);
int skel_unlink(char *path);
int skel_chmod(char *path, mode_t mode);
int skel_utime(char *path, struct utimbuf *times);

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
    skel_utime
};

/* VFS initialisation - return vfs_ops function pointer structure */

struct vfs_ops *vfs_init(void)
{
    return(&skel_ops);
}

/* Implementation of VFS functions.  Insert your useful stuff here */

extern struct vfs_ops default_vfs_ops;   /* For passthrough operation */

int skel_connect(struct vfs_connection_struct *conn, char *svc, char *user)
{
    return default_vfs_ops.connect(conn, svc, user);
}

void skel_disconnect(void)
{
    default_vfs_ops.disconnect();
}

SMB_BIG_UINT skel_disk_free(char *path, BOOL small_query, SMB_BIG_UINT *bsize, 
			    SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{
    return default_vfs_ops.disk_free(path, small_query, bsize, dfree, dsize);
}

DIR *skel_opendir(char *fname)
{
    return default_vfs_ops.opendir(fname);
}

struct dirent *skel_readdir(DIR *dirp)
{
    return default_vfs_ops.readdir(dirp);
}

int skel_mkdir(char *path, mode_t mode)
{
    return default_vfs_ops.mkdir(path, mode);
}

int skel_rmdir(char *path)
{
    return default_vfs_ops.rmdir(path);
}

int skel_closedir(DIR *dir)
{
    return default_vfs_ops.closedir(dir);
}

int skel_open(char *fname, int flags, mode_t mode)
{
    return default_vfs_ops.open(fname, flags, mode);
}

int skel_close(int fd)
{
    return default_vfs_ops.close(fd);
}

ssize_t skel_read(int fd, char *data, size_t n)
{
    return default_vfs_ops.read(fd, data, n);
}

ssize_t skel_write(int fd, char *data, size_t n)
{
    return default_vfs_ops.write(fd, data, n);
}

SMB_OFF_T skel_lseek(int filedes, SMB_OFF_T offset, int whence)
{
    return default_vfs_ops.lseek(filedes, offset, whence);
}

int skel_rename(char *old, char *new)
{
    return default_vfs_ops.rename(old, new);
}

int skel_fsync(int fd)
{
    default_vfs_ops.fsync(fd);
}

int skel_stat(char *fname, SMB_STRUCT_STAT *sbuf)
{
    return default_vfs_ops.stat(fname, sbuf);
}

int skel_fstat(int fd, SMB_STRUCT_STAT *sbuf)
{
    return default_vfs_ops.fstat(fd, sbuf);
}

int skel_lstat(char *path, SMB_STRUCT_STAT *sbuf)
{
    return default_vfs_ops.lstat(path, sbuf);
}

int skel_unlink(char *path)
{
    return default_vfs_ops.unlink(path);
}

int skel_chmod(char *path, mode_t mode)
{
    return default_vfs_ops.chmod(path, mode);
}

int skel_utime(char *path, struct utimbuf *times)
{
    return default_vfs_ops.utime(path, times);
}
