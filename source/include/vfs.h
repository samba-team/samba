/* 
   Unix SMB/Netbios implementation.
   Version 1.9.
   VFS structures and parameters
   Copyright (C) Tim Potter 1999
   
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

#ifndef _VFS_H
#define _VFS_H

/* Avoid conflict with an AIX include file */

#ifdef vfs_ops
#undef vfs_ops
#endif

/*
 * As we're now (thanks Andrew ! :-) using file_structs and connection
 * structs in the vfs - then anyone writing a vfs must include includes.h...
 */

/*
 * This next constant specifies the version number of the VFS interface
 * this smbd will load. Increment this if *ANY* changes are made to the
 * vfs_ops below. JRA.
 */

/* Changed to version 2 for CIFS UNIX extensions (mknod and link added). JRA. */
#define SMB_VFS_INTERFACE_VERSION 2

/* VFS operations structure */

struct connection_struct;
struct files_struct;
struct security_descriptor_info;

struct vfs_ops {

	/* Disk operations */
    
	int (*connect)(struct connection_struct *conn, char *service, char *user);
	void (*disconnect)(struct connection_struct *conn);
	SMB_BIG_UINT (*disk_free)(struct connection_struct *conn, char *path, BOOL small_query, SMB_BIG_UINT *bsize, 
		SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
    
	/* Directory operations */

	DIR *(*opendir)(struct connection_struct *conn, char *fname);
	struct dirent *(*readdir)(struct connection_struct *conn, DIR *dirp);
	int (*mkdir)(struct connection_struct *conn, char *path, mode_t mode);
	int (*rmdir)(struct connection_struct *conn, char *path);
	int (*closedir)(struct connection_struct *conn, DIR *dir);
    
	/* File operations */
    
	int (*open)(struct connection_struct *conn, char *fname, int flags, mode_t mode);
	int (*close)(struct files_struct *fsp, int fd);
	ssize_t (*read)(struct files_struct *fsp, int fd, void *data, size_t n);
	ssize_t (*write)(struct files_struct *fsp, int fd, const void *data, size_t n);
	SMB_OFF_T (*lseek)(struct files_struct *fsp, int filedes, SMB_OFF_T offset, int whence);
	int (*rename)(struct connection_struct *conn, char *old, char *new);
	int (*fsync)(struct files_struct *fsp, int fd);
	int (*stat)(struct connection_struct *conn, char *fname, SMB_STRUCT_STAT *sbuf);
	int (*fstat)(struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf);
	int (*lstat)(struct connection_struct *conn, char *path, SMB_STRUCT_STAT *sbuf);
	int (*unlink)(struct connection_struct *conn, char *path);
	int (*chmod)(struct connection_struct *conn, char *path, mode_t mode);
	int (*fchmod)(struct files_struct *fsp, int fd, mode_t mode);
	int (*chown)(struct connection_struct *conn, char *path, uid_t uid, gid_t gid);
	int (*fchown)(struct files_struct *fsp, int fd, uid_t uid, gid_t gid);
	int (*chdir)(struct connection_struct *conn, char *path);
	char *(*getwd)(struct connection_struct *conn, char *buf);
	int (*utime)(struct connection_struct *conn, char *path, struct utimbuf *times);
	int (*ftruncate)(struct files_struct *fsp, int fd, SMB_OFF_T offset);
	BOOL (*lock)(struct files_struct *fsp, int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type);
	int (*symlink)(struct connection_struct *conn, const char *oldpath, const char *newpath);
	int (*readlink)(struct connection_struct *conn, const char *path, char *buf, size_t bufsiz);
	int (*link)(struct connection_struct *conn, const char *oldpath, const char *newpath);
	int (*mknod)(struct connection_struct *conn, const char *path, mode_t mode, SMB_DEV_T dev);

	/* NT ACL operations. */

	size_t (*fget_nt_acl)(struct files_struct *fsp, int fd, struct security_descriptor_info **ppdesc);
	size_t (*get_nt_acl)(struct files_struct *fsp, char *name, struct security_descriptor_info **ppdesc);
	BOOL (*fset_nt_acl)(struct files_struct *fsp, int fd, uint32 security_info_sent, struct security_descriptor_info *psd);
	BOOL (*set_nt_acl)(struct files_struct *fsp, char *name, uint32 security_info_sent, struct security_descriptor_info *psd);

	/* POSIX ACL operations. */

	int (*chmod_acl)(struct connection_struct *conn, char *name, mode_t mode);
	int (*fchmod_acl)(struct files_struct *fsp, int fd, mode_t mode);
	
};

struct vfs_options {
    struct vfs_options *prev, *next;
    char *name;
    char *value;
};

#endif /* _VFS_H */
