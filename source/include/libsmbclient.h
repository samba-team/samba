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

#define SMBC_MAX_NAME 1023

struct smbc_dirent {

  uint smbc_type;  /* Type of entity, see below */
  uint dirlen;     /* Convenience               */
  uint namelen;
  uint commentlen;
  char *comment;   /* Points to the comment futher down */
  char name[1];

};

/*
 * Entity types
 */
#define SMBC_WORKGROUP     1
#define SMBC_SERVER        2
#define SMBC_FILE_SHARE    3
#define SMBC_PRINTER_SHARE 4
#define SMBC_COMMS_SHARE   5
#define SMBC_IPC_SHARE     6
#define SMBC_DIR           7
#define SMBC_FILE          8
#define SMBC_LINK          9

#define SMBC_FILE_MODE (S_IFREG | 0444)
#define SMBC_DIR_MODE  (S_IFDIR | 0555)

typedef void (*smbc_get_auth_data_fn)(char *server, char *share,
				      char *workgroup, int wgmaxlen, 
				      char *username, int unmaxlen,
				      char *password, int pwmaxlen);

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

int smbc_chown(const char *fname, uid_t owner, gid_t group);

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

int smbc_getdents(unsigned int fd, struct smbc_dirent *dirp, int count);

/*
 * Read a dirent in the old way
 */

struct smbc_dirent *smbc_readdir(unsigned int fd);

/* 
 * Create a directory on a server, share, dir in fname URL
 */

int smbc_mkdir(const char *fname, mode_t mode);

/*
 * Remove a directory on a server
 */

int smbc_rmdir(const char *fname);

/*
 * Get the current directory offset
 */

off_t smbc_telldir(int fd);

/* 
 * lseek on directories, rewind by smbc_lseekdir(fd, 0, SEEK_SET)
 */

int smbc_lseekdir(int fd, off_t offset, int whence);

/* 
 * Print a file given the name in fname. It would be a URL ...
 */

int smbc_print_file(const char *fname, const char *printq);

/* 
 * Open a print file that can be written to by other calls. This simply
 * does an smbc_open call after checking if there is a file name on the
 * URI. If not, a temporary name is added ...
 */

int smbc_open_print_job(const char *fname);

/*
 * List the print jobs on a print share, for the moment, pass a callback 
 */

int smbc_list_print_jobs(const char *fname, void (*fn)(struct print_job_info *));

/* 
 * Delete a print job 
 */

int smbc_unlink_print_job(const char *fname, int id);

#endif
