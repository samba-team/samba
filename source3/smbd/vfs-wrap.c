/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   Wrap disk only vfs functions to sidestep dodgy compilers.
   Copyright (C) Tim Potter 1998
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

/* Disk operations */

SMB_BIG_UINT vfswrap_disk_free(char *path, SMB_BIG_UINT *bsize, 
			       SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{
    SMB_BIG_UINT result;

    result = sys_disk_free(path, bsize, dfree, dsize);
    return result;
}
    
/* Directory operations */

DIR *vfswrap_opendir(char *fname)
{
    DIR *result;

    result = opendir(fname);
    return result;
}

struct dirent *vfswrap_readdir(DIR *dirp)
{
    struct dirent *result;

    result = readdir(dirp);
    return result;
}

int vfswrap_mkdir(char *path, mode_t mode)
{
    int result;

    result = mkdir(path, mode);
    return result;
}

int vfswrap_rmdir(char *path)
{
    int result;

    result = rmdir(path);
    return result;
}

int vfswrap_closedir(DIR *dirp)
{
    int result;
    
    result = closedir(path);
    return result;
}

/* File operations */
    
int vfswrap_open(char *fname, int flags, mode_t mode)
{
    int result;

    result = sys_open(fname, flags, mode);
    return result;
}

int vfswrap_close(int fd)
{
    int result;

    result = close(fd);
    return result;
}

ssize_t vfswrap_read(int fd, char *data, size_t n)
{
    ssize_t result;

    result = read(fd, data, n);
    return result;
}

ssize_t vfswrap_write(int fd, char *data, size_t n)
{
    ssize_t result;

    result = write(fd, data, n);
    return result;
}

SMB_OFF_T vfswrap_lseek(int filedes, SMB_OFF_T offset, int whence)
{
    SMB_OFF_T result;

    result = sys_lseek(filedes, offset, whence);
    return result;
}

int vfswrap_rename(char *old, char *new)
{
    int result;

    result = rename(old, new);
    return result;
}

void vfswrap_sync_file(struct connection_struct *conn, files_struct *fsp)
{
    sys_sync_file(conn, fsp);
}

int vfswrap_stat(char *fname, SMB_STRUCT_STAT *sbuf)
{
    int result;

    result = sys_stat(fname, sbuf);
    return result;
}

int vfswrap_fstat(int fd, SMB_STRUCT_STAT *sbuf)
{
    int result;

    result = sys_fstat(fd, sbuf);
    return result;
}

int vfswrap_lstat(char *path, 
		  SMB_STRUCT_STAT *sbuf)
{
    int result;

    result = sys_lstat(path, sbuf);
    return result;
}

BOOL vfswrap_fcntl_lock(int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, 
			int type)
{
    BOOL result;

    result = fcntl_lock(fd, op, offset, count, type);
    return result;
}

int vfswrap_unlink(char *path)
{
    int result;

    result = unlink(path);
    return result;
}

int vfswrap_chmod(char *path, mode_t mode)
{
    int result;

    result = chmod(path, mode);
    return result;
}

int vfswrap_utime(char *path, struct utimbuf *times)
{
    int result;

    result = utime(path, times);
    return result;
}
