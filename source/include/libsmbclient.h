/* 
   Unix SMB/Netbios implementation.
   Version 2.0
   SMB client library API definitions
   Copyright (C) Andrew Tridgell 1998
   Copyright (C) Richard Sharpe 2000
   Copyright (C) John Terpsra 2000
   
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

#ifndef _SMBCLIENT_H
#define _SMBCLIENT_H

/* Make sure we have the following includes for now ... */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#define SMBC_FILE_MODE (S_IFREG | 0444)
#define SMBC_DIR_MODE  (S_IFDIR | 0555)

typedef void (*smbc_get_auth_data_fn)(char *server, char *share,
				      char **workgroup, char **username,
				      char **password);

/*
 * Init the smbc package
 */
int smbc_init(smbc_get_auth_data_fn fn, const char *workgroup, int debug);

/*
 * Open a file on an SMB server, this has the same form as normal open
 * but the fname is a URL of the form smb://server/share/path
 */

int smbc_open(const char *fname, int flags, mode_t mode);

/*
 * Create a file on an SMB server, similar to smbc_open
 */

int smbc_creat(const char *fname, mode_t mode);

/*
 * Read from a file, what about pread?
 */

ssize_t smbc_read(int fd, void *buf, size_t count);

/* 
 * Write to a file, what about pwrite?
 */

ssize_t smbc_write(int fd, void *buf, size_t count);

/*
 * Close a file by fd
 */

int smbc_close(int fd);

/*
 * Unlink a file on server, share, dir, file ...
 */

int smbc_unlink(const char *fname);

/*
 * rename oname to nname ... probably need to be on the same
 * server initially. Later can copy between servers ...
 */

int smbc_rename(const char *oname, const char *nname);

/*
 * Seek to a specific location in a file on an SMB server 
 */

off_t smbc_lseek(int fd, off_t offset, int whence);

/*
 * Stat a file to get info via file name
 */

int smbc_stat(const char *fname, struct stat *st);

/*
 * Stat a file to get info via an fd
 */

int smbc_fstat(int fd, struct stat *st);

/* 
 * Chown a file 
 */

int smbc_chown(const *fname, uid_t owner, gid_t group);

/*
 * Chmod a file
 */

int smbc_chmod(const char *fname, mode_t newmode);

/*
 * Open a directory on a URL (server and share and dir)
 */

int smbc_opendir(const char *fname);

/*
 * Close a directory
 */

int smbc_closedir(int fd);

/* 
 * Get a directory entry
 */

int smbc_getdents(unsigned int fd, struct dirent *dirp, int count);

/* 
 * Create a directory on a server, share, dir in fname URL
 */

int smbc_mkdir(const char *fname, mode_t mode);

/* 
 * lseek on directories, rewind by smbc_lseekdir(fd, 0, SEEK_SET)
 */

int smbc_lseekdir(int fd, off_t offset, int whence);

/* 
 * Must also provide print functions ... soon
 */

#endif
