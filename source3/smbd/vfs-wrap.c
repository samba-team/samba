/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
s   Wrap disk only vfs functions to sidestep dodgy compilers.
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

/* Check for NULL pointer parameters in vfswrap_* functions */

#define VFS_CHECK_NULL

/* We don't want to have NULL function pointers lying around.  Someone
   is sure to try and execute them.  These stubs are used to prevent
   this possibility. */

int vfswrap_dummy_connect(struct vfs_connection_struct *conn, char *service,
			  char *user)
{
    return 0;    /* Return >= 0 for success */
}

void vfswrap_dummy_disconnect(void)
{
}

/* Disk operations */

SMB_BIG_UINT vfswrap_disk_free(char *path, BOOL small_query, SMB_BIG_UINT *bsize, 
			       SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize)
{
    SMB_BIG_UINT result;

#ifdef VFS_CHECK_NULL
    if ((path == NULL) || (bsize == NULL) || (dfree == NULL) ||
	(dsize == NULL)) {
	
	smb_panic("NULL pointer passed to vfswrap_disk_free() function\n");
    }
#endif

    result = sys_disk_free(path, small_query, bsize, dfree, dsize);
    return result;
}
    
/* Directory operations */

DIR *vfswrap_opendir(char *fname)
{
    DIR *result;

#ifdef VFS_CHECK_NULL
    if (fname == NULL) {
	smb_panic("NULL pointer passed to vfswrap_opendir()\n");
    }
#endif

    result = opendir(fname);
    return result;
}

struct dirent *vfswrap_readdir(DIR *dirp)
{
    struct dirent *result;

#ifdef VFS_CHECK_NULL
    if (dirp == NULL) {
	smb_panic("NULL pointer passed to vfswrap_readdir()\n");
    }
#endif

    result = readdir(dirp);
    return result;
}

int vfswrap_mkdir(char *path, mode_t mode)
{
    int result;

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_mkdir()\n");
    }
#endif

    result = mkdir(path, mode);
    return result;
}

int vfswrap_rmdir(char *path)
{
    int result;

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_rmdir()\n");
    }
#endif

    result = rmdir(path);
    return result;
}

int vfswrap_closedir(DIR *dirp)
{
    int result;

#ifdef VFS_CHECK_NULL
    if (dirp == NULL) {
	smb_panic("NULL pointer passed to vfswrap_closedir()\n");
    }
#endif

    result = closedir(dirp);
    return result;
}

/* File operations */
    
int vfswrap_open(char *fname, int flags, mode_t mode)
{
    int result;

#ifdef VFS_CHECK_NULL
    if (fname == NULL) {
	smb_panic("NULL pointer passed to vfswrap_open()\n");
    }
#endif

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

#ifdef VFS_CHECK_NULL
    if (data == NULL) {
	smb_panic("NULL pointer passed to vfswrap_read()\n");
    }
#endif

    result = read(fd, data, n);
    return result;
}

ssize_t vfswrap_write(int fd, char *data, size_t n)
{
    ssize_t result;

#ifdef VFS_CHECK_NULL
    if (data == NULL) {
	smb_panic("NULL pointer passed to vfswrap_write()\n");
    }
#endif

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

#ifdef VFS_CHECK_NULL
    if ((old == NULL) || (new == NULL)) {
	smb_panic("NULL pointer passed to vfswrap_rename()\n");
    }
#endif

    result = rename(old, new);
    return result;
}

int vfswrap_fsync(int fd)
{
#ifdef HAVE_FSYNC
    return fsync(fd);
#else
	return 0;
#endif
}

int vfswrap_stat(char *fname, SMB_STRUCT_STAT *sbuf)
{
    int result;

#ifdef VFS_CHECK_NULL
    if ((fname == NULL) || (sbuf == NULL)) {
	smb_panic("NULL pointer passed to vfswrap_stat()\n");
    }
#endif

    result = sys_stat(fname, sbuf);
    return result;
}

int vfswrap_fstat(int fd, SMB_STRUCT_STAT *sbuf)
{
    int result;

#ifdef VFS_CHECK_NULL
    if (sbuf == NULL) {
	smb_panic("NULL pointer passed to vfswrap_fstat()\n");
    }
#endif

    result = sys_fstat(fd, sbuf);
    return result;
}

int vfswrap_lstat(char *path, 
		  SMB_STRUCT_STAT *sbuf)
{
    int result;

#ifdef VFS_CHECK_NULL
    if ((path == NULL) || (sbuf == NULL)) {
	smb_panic("NULL pointer passed to vfswrap_lstat()\n");
    }
#endif

    result = sys_lstat(path, sbuf);
    return result;
}

int vfswrap_unlink(char *path)
{
    int result;

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_unlink()\n");
    }
#endif

    result = unlink(path);
    return result;
}

int vfswrap_chmod(char *path, mode_t mode)
{
    int result;

#ifdef VFS_CHECK_NULL
    if (path == NULL) {
	smb_panic("NULL pointer passed to vfswrap_chmod()\n");
    }
#endif

    result = chmod(path, mode);
    return result;
}

int vfswrap_utime(char *path, struct utimbuf *times)
{
    int result;

#ifdef VFS_CHECK_NULL
    if ((path == NULL) || (times == NULL)) {
	smb_panic("NULL pointer passed to vfswrap_utime()\n");
    }
#endif

    result = utime(path, times);
    return result;
}

int vfswrap_ftruncate(int fd, SMB_OFF_T offset)
{
    int result;

    result = sys_ftruncate(fd, offset);
    return result;
}
