/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB wrapper functions - definitions
   Copyright (C) Andrew Tridgell 1998
   
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

#include "config.h"

#ifdef HAVE_SYSCALL_H
#include <syscall.h>
#elif HAVE_SYS_SYSCALL_H
#include <sys/syscall.h>
#endif

#include <stdio.h>
#include <dirent.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#ifdef LINUX
#include "kernel_stat.h"
#endif
#include "realcalls.h"

int smbw_dirp(DIR *dirp);
int smbw_fd(int fd);
int smbw_dir_open(const char *fname);
int smbw_dir_close(int fd);
int smbw_stat(const char *fname, struct stat *st);
off_t smbw_dir_lseek(int fd, off_t offset, int whence);
int smbw_path(const char *path);
int smbw_open(const char *fname, int flags, mode_t mode);
int smbw_chdir(const char *name);
int smbw_close(int fd);
int smbw_fchdir(unsigned int fd);
int smbw_fcntl(int fd, int cmd, long arg);
int smbw_getdents(unsigned int fd, struct dirent *dirp, int count);
off_t smbw_lseek(int fd, off_t offset, int whence);
ssize_t smbw_read(int fd, void *buf, size_t count);
ssize_t smbw_write(int fd, void *buf, size_t count);
int smbw_access(const char *name, int mode);
int smbw_chmod(const char *fname, mode_t newmode);
int smbw_chown(const char *fname, uid_t owner, gid_t group);
int smbw_closedir(DIR *d);
int smbw_fstat(int fd, struct stat *st);
char *smbw_getcwd(char *buf, size_t size);
int smbw_stat(const char *fname, struct stat *st);
int smbw_mkdir(const char *fname, mode_t mode);
void smbw_seekdir(DIR *d, off_t offset);
off_t smbw_telldir(DIR *d);
int smbw_unlink(const char *fname);
int smbw_utime(const char *fname,void *buf);
DIR *smbw_opendir(const char *fname);
struct dirent *smbw_readdir(DIR *d);
int smbw_readlink(const char *path, char *buf, size_t bufsize);
int smbw_rename(const char *oldname, const char *newname);
int smbw_rmdir(const char *fname);

