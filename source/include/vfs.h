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
/* Changed to version 3 for POSIX acl extensions. JRA. */
/* Changed to version 4 for sendfile extension. JRA. */
#define SMB_VFS_INTERFACE_VERSION 4

/* VFS operations structure */

struct connection_struct;
struct files_struct;
struct security_descriptor_info;

struct vfs_ops {

	/* Disk operations */
    
	int (*connect)(struct connection_struct *conn, const char *service, const char *user);
	void (*disconnect)(struct connection_struct *conn);
	SMB_BIG_UINT (*disk_free)(struct connection_struct *conn, const char *path, BOOL small_query, SMB_BIG_UINT *bsize, 
		SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
    
	/* Directory operations */

	DIR *(*opendir)(struct connection_struct *conn, const char *fname);
	struct dirent *(*readdir)(struct connection_struct *conn, DIR *dirp);
	int (*mkdir)(struct connection_struct *conn, const char *path, mode_t mode);
	int (*rmdir)(struct connection_struct *conn, const char *path);
	int (*closedir)(struct connection_struct *conn, DIR *dir);
    
	/* File operations */
    
	int (*open)(struct connection_struct *conn, const char *fname, int flags, mode_t mode);
	int (*close)(struct files_struct *fsp, int fd);
	ssize_t (*read)(struct files_struct *fsp, int fd, void *data, size_t n);
	ssize_t (*write)(struct files_struct *fsp, int fd, const void *data, size_t n);
	SMB_OFF_T (*lseek)(struct files_struct *fsp, int filedes, SMB_OFF_T offset, int whence);
	ssize_t (*sendfile)(int tofd, files_struct *fsp, int fromfd, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);
	int (*rename)(struct connection_struct *conn, const char *old, const char *new);
	int (*fsync)(struct files_struct *fsp, int fd);
	int (*stat)(struct connection_struct *conn, const char *fname, SMB_STRUCT_STAT *sbuf);
	int (*fstat)(struct files_struct *fsp, int fd, SMB_STRUCT_STAT *sbuf);
	int (*lstat)(struct connection_struct *conn, const char *path, SMB_STRUCT_STAT *sbuf);
	int (*unlink)(struct connection_struct *conn, const char *path);
	int (*chmod)(struct connection_struct *conn, const char *path, mode_t mode);
	int (*fchmod)(struct files_struct *fsp, int fd, mode_t mode);
	int (*chown)(struct connection_struct *conn, const char *path, uid_t uid, gid_t gid);
	int (*fchown)(struct files_struct *fsp, int fd, uid_t uid, gid_t gid);
	int (*chdir)(struct connection_struct *conn, const char *path);
	char *(*getwd)(struct connection_struct *conn, char *buf);
	int (*utime)(struct connection_struct *conn, const char *path, struct utimbuf *times);
	int (*ftruncate)(struct files_struct *fsp, int fd, SMB_OFF_T offset);
	BOOL (*lock)(struct files_struct *fsp, int fd, int op, SMB_OFF_T offset, SMB_OFF_T count, int type);
	int (*symlink)(struct connection_struct *conn, const char *oldpath, const char *newpath);
	int (*readlink)(struct connection_struct *conn, const char *path, char *buf, size_t bufsiz);
	int (*link)(struct connection_struct *conn, const char *oldpath, const char *newpath);
	int (*mknod)(struct connection_struct *conn, const char *path, mode_t mode, SMB_DEV_T dev);
	char *(*realpath)(struct connection_struct *conn, const char *path, char *resolved_path);

	/* NT ACL operations. */

	size_t (*fget_nt_acl)(struct files_struct *fsp, int fd, struct security_descriptor_info **ppdesc);
	size_t (*get_nt_acl)(struct files_struct *fsp, const char *name, struct security_descriptor_info **ppdesc);
	BOOL (*fset_nt_acl)(struct files_struct *fsp, int fd, uint32 security_info_sent, struct security_descriptor_info *psd);
	BOOL (*set_nt_acl)(struct files_struct *fsp, const char *name, uint32 security_info_sent, struct security_descriptor_info *psd);

	/* POSIX ACL operations. */

	int (*chmod_acl)(struct connection_struct *conn, const char *name, mode_t mode);
	int (*fchmod_acl)(struct files_struct *fsp, int fd, mode_t mode);

	int (*sys_acl_get_entry)(struct connection_struct *conn, SMB_ACL_T theacl, int entry_id, SMB_ACL_ENTRY_T *entry_p);
	int (*sys_acl_get_tag_type)(struct connection_struct *conn, SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p);
	int (*sys_acl_get_permset)(struct connection_struct *conn, SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p);
	void * (*sys_acl_get_qualifier)(struct connection_struct *conn, SMB_ACL_ENTRY_T entry_d);
	SMB_ACL_T (*sys_acl_get_file)(struct connection_struct *conn, const char *path_p, SMB_ACL_TYPE_T type);
	SMB_ACL_T (*sys_acl_get_fd)(struct files_struct *fsp, int fd);
	int (*sys_acl_clear_perms)(struct connection_struct *conn, SMB_ACL_PERMSET_T permset);
	int (*sys_acl_add_perm)(struct connection_struct *conn, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm);
	char * (*sys_acl_to_text)(struct connection_struct *conn, SMB_ACL_T theacl, ssize_t *plen);
	SMB_ACL_T (*sys_acl_init)(struct connection_struct *conn, int count);
	int (*sys_acl_create_entry)(struct connection_struct *conn, SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry);
	int (*sys_acl_set_tag_type)(struct connection_struct *conn, SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype);
	int (*sys_acl_set_qualifier)(struct connection_struct *conn, SMB_ACL_ENTRY_T entry, void *qual);
	int (*sys_acl_set_permset)(struct connection_struct *conn, SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset);
	int (*sys_acl_valid)(struct connection_struct *conn, SMB_ACL_T theacl );
	int (*sys_acl_set_file)(struct connection_struct *conn, const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl);
	int (*sys_acl_set_fd)(struct files_struct *fsp, int fd, SMB_ACL_T theacl);
	int (*sys_acl_delete_def_file)(struct connection_struct *conn, const char *path);
	int (*sys_acl_get_perm)(struct connection_struct *conn, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm);
	int (*sys_acl_free_text)(struct connection_struct *conn, char *text);
	int (*sys_acl_free_acl)(struct connection_struct *conn, SMB_ACL_T posix_acl);
	int (*sys_acl_free_qualifier)(struct connection_struct *conn, void *qualifier, SMB_ACL_TAG_T tagtype);
};

struct vfs_options {
    struct vfs_options *prev, *next;
    char *name;
    char *value;
};

#endif /* _VFS_H */
