/* 
   Unix SMB/CIFS implementation.
   VFS structures and parameters
   Copyright (C) Jeremy Allison                         1999-2005
   Copyright (C) Tim Potter				1999
   Copyright (C) Alexander Bokovoy			2002-2005
   Copyright (C) Stefan (metze) Metzmacher		2003
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   This work was sponsored by Optifacio Software Services, Inc.
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
 *
 * If you change anything here, please also update modules/vfs_full_audit.c.
 * VL.
 */

/* Changed to version 2 for CIFS UNIX extensions (mknod and link added). JRA. */
/* Changed to version 3 for POSIX acl extensions. JRA. */
/* Changed to version 4 for cascaded VFS interface. Alexander Bokovoy. */
/* Changed to version 5 for sendfile addition. JRA. */
/* Changed to version 6 for the new module system, fixed cascading and quota functions. --metze */
/* Changed to version 7 to include the get_nt_acl info parameter. JRA. */
/* Changed to version 8 includes EA calls. JRA. */
/* Changed to version 9 to include the get_shadow_data call. --metze */
/* Changed to version 10 to include pread/pwrite calls. */
/* Changed to version 11 to include seekdir/telldir/rewinddir calls. JRA */
/* Changed to version 12 to add mask and attributes to opendir(). JRA 
   Also include aio calls. JRA. */
/* Changed to version 13 as the internal structure of files_struct has changed. JRA */
/* Changed to version 14 as we had to change DIR to SMB_STRUCT_DIR. JRA */
/* Changed to version 15 as we added the statvfs call. JRA */
/* Changed to version 16 as we added the getlock call. JRA */
/* Changed to version 17 as we removed redundant connection_struct parameters. --jpeach */
/* Changed to version 18 to add fsp parameter to the open call -- jpeach 
   Also include kernel_flock call - jmcd */
/* Changed to version 19, kernel change notify has been merged 
   Also included linux setlease call - jmcd */
/* Changed to version 20, use ntimes call instead of utime (greater
 * timestamp resolition. JRA. */
/* Changed to version21 to add chflags operation -- jpeach */
/* Changed to version22 to add lchown operation -- jra */
/* Leave at 22 - not yet released. But change set_nt_acl to return an NTSTATUS. jra. */
/* Leave at 22 - not yet released. Add file_id_create operation. --metze */
/* Leave at 22 - not yet released. Change all BOOL parameters (int) to bool. jra. */
/* Leave at 22 - not yet released. Added recvfile. */
/* Leave at 22 - not yet released. Change get_nt_acl to return NTSTATUS - vl */
/* Leave at 22 - not yet released. Change get_nt_acl to *not* take a
 * files_struct. - obnox.*/
/* Leave at 22 - not yet released. Remove parameter fd from fget_nt_acl. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from gset_nt_acl. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from pread. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from pwrite. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from lseek. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from fsync. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from fstat. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from fchmod. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from fchown. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from ftruncate. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from lock. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from kernel_flock. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from linux_setlease. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from getlock. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from sys_acl_get_fd. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from fchmod_acl. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from sys_acl_set_fd. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from fgetxattr. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from flistxattr. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from fremovexattr. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from fsetxattr. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from aio_cancel. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from read. - obnox */
/* Leave at 22 - not yet released. Remove parameter fd from write. - obnox */
/* Leave at 22 - not yet released. Remove parameter fromfd from sendfile. - obnox */
/* Leave at 22 - not yet released. Remove parameter fromfd from recvfile. - obnox */
/* Leave at 22 - not yet released. Additional change: add operations for offline files -- ab */
/* Leave at 22 - not yet released. Add the streaminfo call. -- jpeach, vl */
/* Leave at 22 - not yet released. Remove parameter fd from close_fn. - obnox */

#define SMB_VFS_INTERFACE_VERSION 22


/* to bug old modules which are trying to compile with the old functions */
#define vfs_init __ERROR_please_port_this_module_to_SMB_VFS_INTERFACE_VERSION_8_donot_use_vfs_init_anymore(void) { __ERROR_please_port_this_module_to_SMB_VFS_INTERFACE_VERSION_8_donot_use_vfs_init_anymore };
#define lp_parm_string __ERROR_please_port_lp_parm_string_to_lp_parm_const_string_or_lp_parm_talloc_string { \
  __ERROR_please_port_lp_parm_string_to_lp_parm_const_string_or_lp_parm_talloc_string };
#define lp_vfs_options __ERROR_please_donot_use_lp_vfs_options_anymore_use_lp_parm_xxxx_functions_instead { \
  __ERROR_please_donot_use_lp_vfs_options_anymore_use_lp_parm_xxxx_functions_instead };

/*
    All intercepted VFS operations must be declared as static functions inside module source
    in order to keep smbd namespace unpolluted. See source of audit, extd_audit, fake_perms and recycle
    example VFS modules for more details.
*/

/* VFS operations structure */

struct vfs_handle_struct;
struct connection_struct;
struct files_struct;
struct security_descriptor;
struct vfs_statvfs_struct;

/*
    Available VFS operations. These values must be in sync with vfs_ops struct
    (struct vfs_fn_pointers and struct vfs_handle_pointers inside of struct vfs_ops). 
    In particular, if new operations are added to vfs_ops, appropriate constants
    should be added to vfs_op_type so that order of them kept same as in vfs_ops.
*/

typedef enum _vfs_op_type {
	SMB_VFS_OP_NOOP = -1,
	
	/* Disk operations */

	SMB_VFS_OP_CONNECT = 0,
	SMB_VFS_OP_DISCONNECT,
	SMB_VFS_OP_DISK_FREE,
	SMB_VFS_OP_GET_QUOTA,
	SMB_VFS_OP_SET_QUOTA,
	SMB_VFS_OP_GET_SHADOW_COPY_DATA,
	SMB_VFS_OP_STATVFS,
	SMB_VFS_OP_FS_CAPABILITIES,

	/* Directory operations */

	SMB_VFS_OP_OPENDIR,
	SMB_VFS_OP_READDIR,
	SMB_VFS_OP_SEEKDIR,
	SMB_VFS_OP_TELLDIR,
	SMB_VFS_OP_REWINDDIR,
	SMB_VFS_OP_MKDIR,
	SMB_VFS_OP_RMDIR,
	SMB_VFS_OP_CLOSEDIR,

	/* File operations */

	SMB_VFS_OP_OPEN,
	SMB_VFS_OP_CLOSE,
	SMB_VFS_OP_READ,
	SMB_VFS_OP_PREAD,
	SMB_VFS_OP_WRITE,
	SMB_VFS_OP_PWRITE,
	SMB_VFS_OP_LSEEK,
	SMB_VFS_OP_SENDFILE,
	SMB_VFS_OP_RECVFILE,
	SMB_VFS_OP_RENAME,
	SMB_VFS_OP_FSYNC,
	SMB_VFS_OP_STAT,
	SMB_VFS_OP_FSTAT,
	SMB_VFS_OP_LSTAT,
	SMB_VFS_OP_UNLINK,
	SMB_VFS_OP_CHMOD,
	SMB_VFS_OP_FCHMOD,
	SMB_VFS_OP_CHOWN,
	SMB_VFS_OP_FCHOWN,
	SMB_VFS_OP_LCHOWN,
	SMB_VFS_OP_CHDIR,
	SMB_VFS_OP_GETWD,
	SMB_VFS_OP_NTIMES,
	SMB_VFS_OP_FTRUNCATE,
	SMB_VFS_OP_LOCK,
	SMB_VFS_OP_KERNEL_FLOCK,
	SMB_VFS_OP_LINUX_SETLEASE,
	SMB_VFS_OP_GETLOCK,
	SMB_VFS_OP_SYMLINK,
	SMB_VFS_OP_READLINK,
	SMB_VFS_OP_LINK,
	SMB_VFS_OP_MKNOD,
	SMB_VFS_OP_REALPATH,
	SMB_VFS_OP_NOTIFY_WATCH,
	SMB_VFS_OP_CHFLAGS,
	SMB_VFS_OP_FILE_ID_CREATE,
	SMB_VFS_OP_STREAMINFO,

	/* NT ACL operations. */

	SMB_VFS_OP_FGET_NT_ACL,
	SMB_VFS_OP_GET_NT_ACL,
	SMB_VFS_OP_FSET_NT_ACL,
	SMB_VFS_OP_SET_NT_ACL,

	/* POSIX ACL operations. */

	SMB_VFS_OP_CHMOD_ACL,
	SMB_VFS_OP_FCHMOD_ACL,

	SMB_VFS_OP_SYS_ACL_GET_ENTRY,
	SMB_VFS_OP_SYS_ACL_GET_TAG_TYPE,
	SMB_VFS_OP_SYS_ACL_GET_PERMSET,
	SMB_VFS_OP_SYS_ACL_GET_QUALIFIER,
	SMB_VFS_OP_SYS_ACL_GET_FILE,
	SMB_VFS_OP_SYS_ACL_GET_FD,
	SMB_VFS_OP_SYS_ACL_CLEAR_PERMS,
	SMB_VFS_OP_SYS_ACL_ADD_PERM,
	SMB_VFS_OP_SYS_ACL_TO_TEXT,
	SMB_VFS_OP_SYS_ACL_INIT,
	SMB_VFS_OP_SYS_ACL_CREATE_ENTRY,
	SMB_VFS_OP_SYS_ACL_SET_TAG_TYPE,
	SMB_VFS_OP_SYS_ACL_SET_QUALIFIER,
	SMB_VFS_OP_SYS_ACL_SET_PERMSET,
	SMB_VFS_OP_SYS_ACL_VALID,
	SMB_VFS_OP_SYS_ACL_SET_FILE,
	SMB_VFS_OP_SYS_ACL_SET_FD,
	SMB_VFS_OP_SYS_ACL_DELETE_DEF_FILE,
	SMB_VFS_OP_SYS_ACL_GET_PERM,
	SMB_VFS_OP_SYS_ACL_FREE_TEXT,
	SMB_VFS_OP_SYS_ACL_FREE_ACL,
	SMB_VFS_OP_SYS_ACL_FREE_QUALIFIER,
	
	/* EA operations. */
	SMB_VFS_OP_GETXATTR,
	SMB_VFS_OP_LGETXATTR,
	SMB_VFS_OP_FGETXATTR,
	SMB_VFS_OP_LISTXATTR,
	SMB_VFS_OP_LLISTXATTR,
	SMB_VFS_OP_FLISTXATTR,
	SMB_VFS_OP_REMOVEXATTR,
	SMB_VFS_OP_LREMOVEXATTR,
	SMB_VFS_OP_FREMOVEXATTR,
	SMB_VFS_OP_SETXATTR,
	SMB_VFS_OP_LSETXATTR,
	SMB_VFS_OP_FSETXATTR,

	/* aio operations */
	SMB_VFS_OP_AIO_READ,
	SMB_VFS_OP_AIO_WRITE,
	SMB_VFS_OP_AIO_RETURN,
	SMB_VFS_OP_AIO_CANCEL,
	SMB_VFS_OP_AIO_ERROR,
	SMB_VFS_OP_AIO_FSYNC,
	SMB_VFS_OP_AIO_SUSPEND,
        SMB_VFS_OP_AIO_FORCE,

	/* offline operations */
	SMB_VFS_OP_IS_OFFLINE,
	SMB_VFS_OP_SET_OFFLINE,

	/* This should always be last enum value */

	SMB_VFS_OP_LAST
} vfs_op_type;

/*
    Please keep vfs_op_type, struct vfs_fn_pointers and struct vfs_handles_pointers in sync.
*/
struct vfs_ops {
	struct vfs_fn_pointers {
		/* Disk operations */

		int (*connect_fn)(struct vfs_handle_struct *handle, const char *service, const char *user);
		void (*disconnect)(struct vfs_handle_struct *handle);
		SMB_BIG_UINT (*disk_free)(struct vfs_handle_struct *handle, const char *path, bool small_query, SMB_BIG_UINT *bsize,
			SMB_BIG_UINT *dfree, SMB_BIG_UINT *dsize);
		int (*get_quota)(struct vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *qt);
		int (*set_quota)(struct vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *qt);
		int (*get_shadow_copy_data)(struct vfs_handle_struct *handle, struct files_struct *fsp, SHADOW_COPY_DATA *shadow_copy_data, bool labels);
		int (*statvfs)(struct vfs_handle_struct *handle, const char *path, struct vfs_statvfs_struct *statbuf);
		uint32_t (*fs_capabilities)(struct vfs_handle_struct *handle);

		/* Directory operations */

		SMB_STRUCT_DIR *(*opendir)(struct vfs_handle_struct *handle, const char *fname, const char *mask, uint32 attributes);
		SMB_STRUCT_DIRENT *(*readdir)(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp);
		void (*seekdir)(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp, long offset);
		long (*telldir)(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp);
		void (*rewind_dir)(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dirp);
		int (*mkdir)(struct vfs_handle_struct *handle, const char *path, mode_t mode);
		int (*rmdir)(struct vfs_handle_struct *handle, const char *path);
		int (*closedir)(struct vfs_handle_struct *handle, SMB_STRUCT_DIR *dir);

		/* File operations */

		int (*open)(struct vfs_handle_struct *handle, const char *fname, files_struct *fsp, int flags, mode_t mode);
		int (*close_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp);
		ssize_t (*vfs_read)(struct vfs_handle_struct *handle, struct files_struct *fsp, void *data, size_t n);
		ssize_t (*pread)(struct vfs_handle_struct *handle, struct files_struct *fsp, void *data, size_t n, SMB_OFF_T offset);
		ssize_t (*write)(struct vfs_handle_struct *handle, struct files_struct *fsp, const void *data, size_t n);
		ssize_t (*pwrite)(struct vfs_handle_struct *handle, struct files_struct *fsp, const void *data, size_t n, SMB_OFF_T offset);
		SMB_OFF_T (*lseek)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_OFF_T offset, int whence);
		ssize_t (*sendfile)(struct vfs_handle_struct *handle, int tofd, files_struct *fromfsp, const DATA_BLOB *header, SMB_OFF_T offset, size_t count);
		ssize_t (*recvfile)(struct vfs_handle_struct *handle, int fromfd, files_struct *tofsp, SMB_OFF_T offset, size_t count);
		int (*rename)(struct vfs_handle_struct *handle, const char *oldname, const char *newname);
		int (*fsync)(struct vfs_handle_struct *handle, struct files_struct *fsp);
		int (*stat)(struct vfs_handle_struct *handle, const char *fname, SMB_STRUCT_STAT *sbuf);
		int (*fstat)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_STAT *sbuf);
		int (*lstat)(struct vfs_handle_struct *handle, const char *path, SMB_STRUCT_STAT *sbuf);
		int (*unlink)(struct vfs_handle_struct *handle, const char *path);
		int (*chmod)(struct vfs_handle_struct *handle, const char *path, mode_t mode);
		int (*fchmod)(struct vfs_handle_struct *handle, struct files_struct *fsp, mode_t mode);
		int (*chown)(struct vfs_handle_struct *handle, const char *path, uid_t uid, gid_t gid);
		int (*fchown)(struct vfs_handle_struct *handle, struct files_struct *fsp, uid_t uid, gid_t gid);
		int (*lchown)(struct vfs_handle_struct *handle, const char *path, uid_t uid, gid_t gid);
		int (*chdir)(struct vfs_handle_struct *handle, const char *path);
		char *(*getwd)(struct vfs_handle_struct *handle, char *buf);
		int (*ntimes)(struct vfs_handle_struct *handle, const char *path, const struct timespec ts[2]);
		int (*ftruncate)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_OFF_T offset);
		bool (*lock)(struct vfs_handle_struct *handle, struct files_struct *fsp, int op, SMB_OFF_T offset, SMB_OFF_T count, int type);
		int (*kernel_flock)(struct vfs_handle_struct *handle, struct files_struct *fsp, uint32 share_mode);
		int (*linux_setlease)(struct vfs_handle_struct *handle, struct files_struct *fsp, int leasetype);
		bool (*getlock)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_OFF_T *poffset, SMB_OFF_T *pcount, int *ptype, pid_t *ppid);
		int (*symlink)(struct vfs_handle_struct *handle, const char *oldpath, const char *newpath);
		int (*vfs_readlink)(struct vfs_handle_struct *handle, const char *path, char *buf, size_t bufsiz);
		int (*link)(struct vfs_handle_struct *handle, const char *oldpath, const char *newpath);
		int (*mknod)(struct vfs_handle_struct *handle, const char *path, mode_t mode, SMB_DEV_T dev);
		char *(*realpath)(struct vfs_handle_struct *handle, const char *path, char *resolved_path);
		NTSTATUS (*notify_watch)(struct vfs_handle_struct *handle,
					 struct sys_notify_context *ctx,
					 struct notify_entry *e,
					 void (*callback)(struct sys_notify_context *ctx, 
							  void *private_data,
							  struct notify_event *ev),
					 void *private_data, void *handle_p);
		int (*chflags)(struct vfs_handle_struct *handle, const char *path, unsigned int flags);
		struct file_id (*file_id_create)(struct vfs_handle_struct *handle, SMB_DEV_T dev, SMB_INO_T inode);

		NTSTATUS (*streaminfo)(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       const char *fname,
				       TALLOC_CTX *mem_ctx,
				       unsigned int *num_streams,
				       struct stream_struct **streams);

		/* NT ACL operations. */

		NTSTATUS (*fget_nt_acl)(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32 security_info,
					struct security_descriptor **ppdesc);
		NTSTATUS (*get_nt_acl)(struct vfs_handle_struct *handle,
				       const char *name,
				       uint32 security_info,
				       struct security_descriptor **ppdesc);
		NTSTATUS (*fset_nt_acl)(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					uint32 security_info_sent,
					struct security_descriptor *psd);
		NTSTATUS (*set_nt_acl)(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       const char *name,
				       uint32 security_info_sent,
				       struct security_descriptor *psd);

		/* POSIX ACL operations. */

		int (*chmod_acl)(struct vfs_handle_struct *handle, const char *name, mode_t mode);
		int (*fchmod_acl)(struct vfs_handle_struct *handle, struct files_struct *fsp, mode_t mode);

		int (*sys_acl_get_entry)(struct vfs_handle_struct *handle, SMB_ACL_T theacl, int entry_id, SMB_ACL_ENTRY_T *entry_p);
		int (*sys_acl_get_tag_type)(struct vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry_d, SMB_ACL_TAG_T *tag_type_p);
		int (*sys_acl_get_permset)(struct vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry_d, SMB_ACL_PERMSET_T *permset_p);
		void * (*sys_acl_get_qualifier)(struct vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry_d);
		SMB_ACL_T (*sys_acl_get_file)(struct vfs_handle_struct *handle, const char *path_p, SMB_ACL_TYPE_T type);
		SMB_ACL_T (*sys_acl_get_fd)(struct vfs_handle_struct *handle, struct files_struct *fsp);
		int (*sys_acl_clear_perms)(struct vfs_handle_struct *handle, SMB_ACL_PERMSET_T permset);
		int (*sys_acl_add_perm)(struct vfs_handle_struct *handle, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm);
		char * (*sys_acl_to_text)(struct vfs_handle_struct *handle, SMB_ACL_T theacl, ssize_t *plen);
		SMB_ACL_T (*sys_acl_init)(struct vfs_handle_struct *handle, int count);
		int (*sys_acl_create_entry)(struct vfs_handle_struct *handle, SMB_ACL_T *pacl, SMB_ACL_ENTRY_T *pentry);
		int (*sys_acl_set_tag_type)(struct vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry, SMB_ACL_TAG_T tagtype);
		int (*sys_acl_set_qualifier)(struct vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry, void *qual);
		int (*sys_acl_set_permset)(struct vfs_handle_struct *handle, SMB_ACL_ENTRY_T entry, SMB_ACL_PERMSET_T permset);
		int (*sys_acl_valid)(struct vfs_handle_struct *handle, SMB_ACL_T theacl );
		int (*sys_acl_set_file)(struct vfs_handle_struct *handle, const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl);
		int (*sys_acl_set_fd)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_ACL_T theacl);
		int (*sys_acl_delete_def_file)(struct vfs_handle_struct *handle, const char *path);
		int (*sys_acl_get_perm)(struct vfs_handle_struct *handle, SMB_ACL_PERMSET_T permset, SMB_ACL_PERM_T perm);
		int (*sys_acl_free_text)(struct vfs_handle_struct *handle, char *text);
		int (*sys_acl_free_acl)(struct vfs_handle_struct *handle, SMB_ACL_T posix_acl);
		int (*sys_acl_free_qualifier)(struct vfs_handle_struct *handle, void *qualifier, SMB_ACL_TAG_T tagtype);

		/* EA operations. */
		ssize_t (*getxattr)(struct vfs_handle_struct *handle,const char *path, const char *name, void *value, size_t size);
		ssize_t (*lgetxattr)(struct vfs_handle_struct *handle,const char *path, const char *name, void *value, size_t size);
		ssize_t (*fgetxattr)(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, void *value, size_t size);
		ssize_t (*listxattr)(struct vfs_handle_struct *handle, const char *path, char *list, size_t size);
		ssize_t (*llistxattr)(struct vfs_handle_struct *handle, const char *path, char *list, size_t size);
		ssize_t (*flistxattr)(struct vfs_handle_struct *handle, struct files_struct *fsp, char *list, size_t size);
		int (*removexattr)(struct vfs_handle_struct *handle, const char *path, const char *name);
		int (*lremovexattr)(struct vfs_handle_struct *handle, const char *path, const char *name);
		int (*fremovexattr)(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name);
		int (*setxattr)(struct vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags);
		int (*lsetxattr)(struct vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags);
		int (*fsetxattr)(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, const void *value, size_t size, int flags);

		/* aio operations */
		int (*aio_read)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb);
		int (*aio_write)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb);
		ssize_t (*aio_return_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb);
		int (*aio_cancel)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb);
		int (*aio_error_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_AIOCB *aiocb);
		int (*aio_fsync)(struct vfs_handle_struct *handle, struct files_struct *fsp, int op, SMB_STRUCT_AIOCB *aiocb);
		int (*aio_suspend)(struct vfs_handle_struct *handle, struct files_struct *fsp, const SMB_STRUCT_AIOCB * const aiocb[], int n, const struct timespec *timeout);
		bool (*aio_force)(struct vfs_handle_struct *handle, struct files_struct *fsp);

		/* offline operations */
		bool (*is_offline)(struct vfs_handle_struct *handle, const char *path, SMB_STRUCT_STAT *sbuf);
		int (*set_offline)(struct vfs_handle_struct *handle, const char *path);
	} ops;

	struct vfs_handles_pointers {
		/* Disk operations */

		struct vfs_handle_struct *connect_hnd;
		struct vfs_handle_struct *disconnect;
		struct vfs_handle_struct *disk_free;
		struct vfs_handle_struct *get_quota;
		struct vfs_handle_struct *set_quota;
		struct vfs_handle_struct *get_shadow_copy_data;
		struct vfs_handle_struct *statvfs;
		struct vfs_handle_struct *fs_capabilities;

		/* Directory operations */

		struct vfs_handle_struct *opendir;
		struct vfs_handle_struct *readdir;
		struct vfs_handle_struct *seekdir;
		struct vfs_handle_struct *telldir;
		struct vfs_handle_struct *rewind_dir;
		struct vfs_handle_struct *mkdir;
		struct vfs_handle_struct *rmdir;
		struct vfs_handle_struct *closedir;

		/* File operations */

		struct vfs_handle_struct *open;
		struct vfs_handle_struct *close_hnd;
		struct vfs_handle_struct *vfs_read;
		struct vfs_handle_struct *pread;
		struct vfs_handle_struct *write;
		struct vfs_handle_struct *pwrite;
		struct vfs_handle_struct *lseek;
		struct vfs_handle_struct *sendfile;
		struct vfs_handle_struct *recvfile;
		struct vfs_handle_struct *rename;
		struct vfs_handle_struct *fsync;
		struct vfs_handle_struct *stat;
		struct vfs_handle_struct *fstat;
		struct vfs_handle_struct *lstat;
		struct vfs_handle_struct *unlink;
		struct vfs_handle_struct *chmod;
		struct vfs_handle_struct *fchmod;
		struct vfs_handle_struct *chown;
		struct vfs_handle_struct *fchown;
		struct vfs_handle_struct *lchown;
		struct vfs_handle_struct *chdir;
		struct vfs_handle_struct *getwd;
		struct vfs_handle_struct *ntimes;
		struct vfs_handle_struct *ftruncate;
		struct vfs_handle_struct *lock;
		struct vfs_handle_struct *kernel_flock;
		struct vfs_handle_struct *linux_setlease;
		struct vfs_handle_struct *getlock;
		struct vfs_handle_struct *symlink;
		struct vfs_handle_struct *vfs_readlink;
		struct vfs_handle_struct *link;
		struct vfs_handle_struct *mknod;
		struct vfs_handle_struct *realpath;
		struct vfs_handle_struct *notify_watch;
		struct vfs_handle_struct *chflags;
		struct vfs_handle_struct *file_id_create;
		struct vfs_handle_struct *streaminfo;

		/* NT ACL operations. */

		struct vfs_handle_struct *fget_nt_acl;
		struct vfs_handle_struct *get_nt_acl;
		struct vfs_handle_struct *fset_nt_acl;
		struct vfs_handle_struct *set_nt_acl;

		/* POSIX ACL operations. */

		struct vfs_handle_struct *chmod_acl;
		struct vfs_handle_struct *fchmod_acl;

		struct vfs_handle_struct *sys_acl_get_entry;
		struct vfs_handle_struct *sys_acl_get_tag_type;
		struct vfs_handle_struct *sys_acl_get_permset;
		struct vfs_handle_struct *sys_acl_get_qualifier;
		struct vfs_handle_struct *sys_acl_get_file;
		struct vfs_handle_struct *sys_acl_get_fd;
		struct vfs_handle_struct *sys_acl_clear_perms;
		struct vfs_handle_struct *sys_acl_add_perm;
		struct vfs_handle_struct *sys_acl_to_text;
		struct vfs_handle_struct *sys_acl_init;
		struct vfs_handle_struct *sys_acl_create_entry;
		struct vfs_handle_struct *sys_acl_set_tag_type;
		struct vfs_handle_struct *sys_acl_set_qualifier;
		struct vfs_handle_struct *sys_acl_set_permset;
		struct vfs_handle_struct *sys_acl_valid;
		struct vfs_handle_struct *sys_acl_set_file;
		struct vfs_handle_struct *sys_acl_set_fd;
		struct vfs_handle_struct *sys_acl_delete_def_file;
		struct vfs_handle_struct *sys_acl_get_perm;
		struct vfs_handle_struct *sys_acl_free_text;
		struct vfs_handle_struct *sys_acl_free_acl;
		struct vfs_handle_struct *sys_acl_free_qualifier;

		/* EA operations. */
		struct vfs_handle_struct *getxattr;
		struct vfs_handle_struct *lgetxattr;
		struct vfs_handle_struct *fgetxattr;
		struct vfs_handle_struct *listxattr;
		struct vfs_handle_struct *llistxattr;
		struct vfs_handle_struct *flistxattr;
		struct vfs_handle_struct *removexattr;
		struct vfs_handle_struct *lremovexattr;
		struct vfs_handle_struct *fremovexattr;
		struct vfs_handle_struct *setxattr;
		struct vfs_handle_struct *lsetxattr;
		struct vfs_handle_struct *fsetxattr;

		/* aio operations */
		struct vfs_handle_struct *aio_read;
		struct vfs_handle_struct *aio_write;
		struct vfs_handle_struct *aio_return;
		struct vfs_handle_struct *aio_cancel;
		struct vfs_handle_struct *aio_error;
		struct vfs_handle_struct *aio_fsync;
		struct vfs_handle_struct *aio_suspend;
		struct vfs_handle_struct *aio_force;

		/* offline operations */
		struct vfs_handle_struct *is_offline;
		struct vfs_handle_struct *set_offline;
	} handles;
};

/*
    Possible VFS operation layers (per-operation)

    These values are used by VFS subsystem when building vfs_ops for connection
    from multiple VFS modules. Internally, Samba differentiates only opaque and
    transparent layers at this process. Other types are used for providing better
    diagnosing facilities.

    Most modules will provide transparent layers. Opaque layer is for modules
    which implement actual file system calls (like DB-based VFS). For example,
    default POSIX VFS which is built in into Samba is an opaque VFS module.

    Other layer types (audit, splitter, scanner) were designed to provide different 
    degree of transparency and for diagnosing VFS module behaviour.

    Each module can implement several layers at the same time provided that only
    one layer is used per each operation.

*/

typedef enum _vfs_op_layer {
	SMB_VFS_LAYER_NOOP = -1,	/* - For using in VFS module to indicate end of array */
					/*   of operations description */
	SMB_VFS_LAYER_OPAQUE = 0,	/* - Final level, does not call anything beyond itself */
	SMB_VFS_LAYER_TRANSPARENT,	/* - Normal operation, calls underlying layer after */
					/*   possibly changing passed data */
	SMB_VFS_LAYER_LOGGER,		/* - Logs data, calls underlying layer, logging may not */
					/*   use Samba VFS */
	SMB_VFS_LAYER_SPLITTER,		/* - Splits operation, calls underlying layer _and_ own facility, */
					/*   then combines result */
	SMB_VFS_LAYER_SCANNER		/* - Checks data and possibly initiates additional */
					/*   file activity like logging to files _inside_ samba VFS */
} vfs_op_layer;

/*
    VFS operation description. Each VFS module registers an array of vfs_op_tuple to VFS subsystem,
    which describes all operations this module is willing to intercept.
    VFS subsystem initializes then the conn->vfs_ops and conn->vfs_opaque_ops structs
    using this information.
*/

typedef struct vfs_op_tuple {
	void* op;
	vfs_op_type type;
	vfs_op_layer layer;
} vfs_op_tuple;


typedef struct vfs_handle_struct {
	struct vfs_handle_struct  *next, *prev;
	const char *param;
	struct vfs_ops vfs_next;
	struct connection_struct *conn;
	void *data;
	void (*free_data)(void **data);
} vfs_handle_struct;


typedef struct vfs_statvfs_struct {
	/* For undefined recommended transfer size return -1 in that field */
	uint32 OptimalTransferSize;  /* bsize on some os, iosize on other os */
	uint32 BlockSize;

	/*
	 The next three fields are in terms of the block size.
	 (above). If block size is unknown, 4096 would be a
	 reasonable block size for a server to report.
	 Note that returning the blocks/blocksavail removes need
	 to make a second call (to QFSInfo level 0x103 to get this info.
	 UserBlockAvail is typically less than or equal to BlocksAvail,
	 if no distinction is made return the same value in each.
	*/

	SMB_BIG_UINT TotalBlocks;
	SMB_BIG_UINT BlocksAvail;       /* bfree */
	SMB_BIG_UINT UserBlocksAvail;   /* bavail */

	/* For undefined Node fields or FSID return -1 */
	SMB_BIG_UINT TotalFileNodes;
	SMB_BIG_UINT FreeFileNodes;
	SMB_BIG_UINT FsIdentifier;   /* fsid */
	/* NB Namelen comes from FILE_SYSTEM_ATTRIBUTE_INFO call */
	/* NB flags can come from FILE_SYSTEM_DEVICE_INFO call   */

	int FsCapabilities;
} vfs_statvfs_struct;

/* Add a new FSP extension of the given type. Returns a pointer to the
 * extenstion data.
 */
#define VFS_ADD_FSP_EXTENSION(handle, fsp, type) \
    vfs_add_fsp_extension_notype(handle, (fsp), sizeof(type))

/* Return a pointer to the existing FSP extension data. */
#define VFS_FETCH_FSP_EXTENSION(handle, fsp) \
    vfs_fetch_fsp_extension(handle, (fsp))

/* Return the talloc context associated with an FSP extension. */
#define VFS_MEMCTX_FSP_EXTENSION(handle, fsp) \
    vfs_memctx_fsp_extension(handle, (fsp))

/* Remove and destroy an FSP extension. */
#define VFS_REMOVE_FSP_EXTENSION(handle, fsp) \
    vfs_remove_fsp_extension((handle), (fsp))

#define SMB_VFS_HANDLE_GET_DATA(handle, datap, type, ret) { \
	if (!(handle)||((datap=(type *)(handle)->data)==NULL)) { \
		DEBUG(0,("%s() failed to get vfs_handle->data!\n",FUNCTION_MACRO)); \
		ret; \
	} \
}

#define SMB_VFS_HANDLE_SET_DATA(handle, datap, free_fn, type, ret) { \
	if (!(handle)) { \
		DEBUG(0,("%s() failed to set handle->data!\n",FUNCTION_MACRO)); \
		ret; \
	} else { \
		if ((handle)->free_data) { \
			(handle)->free_data(&(handle)->data); \
		} \
		(handle)->data = (void *)datap; \
		(handle)->free_data = free_fn; \
	} \
}

#define SMB_VFS_HANDLE_FREE_DATA(handle) { \
	if ((handle) && (handle)->free_data) { \
		(handle)->free_data(&(handle)->data); \
	} \
}

/* Check whether module-specific data handle was already allocated or not */
#define SMB_VFS_HANDLE_TEST_DATA(handle)  ( !(handle) || !(handle)->data ? False : True )

#define SMB_VFS_OP(x) ((void *) x)

#define DEFAULT_VFS_MODULE_NAME "/[Default VFS]/"

#include "vfs_macros.h"

#endif /* _VFS_H */
