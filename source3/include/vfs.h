/* 
   Unix SMB/CIFS implementation.
   VFS structures and parameters
   Copyright (C) Tim Potter				1999
   Copyright (C) Alexander Bokovoy			2002
   
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
 */

/* Changed to version 2 for CIFS UNIX extensions (mknod and link added). JRA. */
/* Changed to version 3 for POSIX acl extensions. JRA. */
/* Changed to version 4 for cascaded VFS interface. Alexander Bokovoy. */
/* Changed to version 5 for sendfile addition. JRA. */
#define SMB_VFS_INTERFACE_VERSION 5


/* Version of supported cascaded interface backward copmatibility.
   (version 5 corresponds to SMB_VFS_INTERFACE_VERSION 5)
   It is used in vfs_init_custom() to detect VFS modules which conform to cascaded 
   VFS interface but implement elder version than current version of Samba uses.
   This allows to use old modules with new VFS interface as far as combined VFS operation
   set is coherent (will be in most cases). 
*/
#define SMB_VFS_INTERFACE_CASCADED 5

/*
    Each VFS module must provide following global functions:
    vfs_init	-- initialization function
    vfs_done	-- finalization function
    
    vfs_init must return proper initialized vfs_op_tuple[] array
    which describes all operations this module claims to intercept. This function
    is called whenever module is loaded into smbd process using sys_dlopen().
    
    vfs_init must store somewhere vfs_handle reference if module wants to store per-instance
    private information for further usage. vfs_handle->data should be used to
    store such information. Do not try to change other fields in this structure
    or results likely to be unpredictable.
    
    vfs_done must perform finalization of the module. In particular,
    this function must free vfs_ops structure returned to module from smb_vfs_get_opaque_ops()
    function if it is used (see below). This function is called whenever module 
    is unloaded from smbd process using sys_dlclose().
    
    Prototypes:
    vfs_op_tuple *vfs_init(int *vfs_version, const struct vfs_ops *def_vfs_ops,
			    struct smb_vfs_handle_struct *vfs_handle);
    void	  vfs_done(connection_struct *conn);
    
    All intercepted VFS operations must be declared as static functions inside module source
    in order to keep smbd namespace unpolluted. See source of skel, audit, and recycle bin
    example VFS modules for more details.
    
*/

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

/*
    Available VFS operations. These values must be in sync with vfs_ops struct.
    In particular, if new operations are added to vfs_ops, appropriate constants
    should be added to vfs_op_type so that order of them kept same as in vfs_ops.
*/

typedef enum _vfs_op_type {

	SMB_VFS_OP_NOOP = -1,
	
	/* Disk operations */

	SMB_VFS_OP_CONNECT = 0,
	SMB_VFS_OP_DISCONNECT,
	SMB_VFS_OP_DISK_FREE,

	/* Directory operations */

	SMB_VFS_OP_OPENDIR,
	SMB_VFS_OP_READDIR,
	SMB_VFS_OP_MKDIR,
	SMB_VFS_OP_RMDIR,
	SMB_VFS_OP_CLOSEDIR,

	/* File operations */

	SMB_VFS_OP_OPEN,
	SMB_VFS_OP_CLOSE,
	SMB_VFS_OP_READ,
	SMB_VFS_OP_WRITE,
	SMB_VFS_OP_LSEEK,
	SMB_VFS_OP_SENDFILE,
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
	SMB_VFS_OP_CHDIR,
	SMB_VFS_OP_GETWD,
	SMB_VFS_OP_UTIME,
	SMB_VFS_OP_FTRUNCATE,
	SMB_VFS_OP_LOCK,
	SMB_VFS_OP_SYMLINK,
	SMB_VFS_OP_READLINK,
	SMB_VFS_OP_LINK,
	SMB_VFS_OP_MKNOD,
	SMB_VFS_OP_REALPATH,

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
	
	/* This should always be last enum value */
	
	SMB_VFS_OP_LAST
} vfs_op_type;

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
	SMB_VFS_LAYER_LOGGER,		/* - Logs data, calls underlying layer, logging does not */
					/*   use Samba VFS */
	SMB_VFS_LAYER_SPLITTER,		/* - Splits operation, calls underlying layer _and_ own facility, */
					/*   then combines result */
	SMB_VFS_LAYER_SCANNER		/* - Checks data and possibly initiates additional */
					/*   file activity like logging to files _inside_ samba VFS */
} vfs_op_layer;

/*
    VFS operation description. Each VFS module initialization function returns to VFS subsystem 
    an array of vfs_op_tuple which describes all operations this module is willing to intercept. 
    VFS subsystem initializes then vfs_ops using this information and passes it 
    to next VFS module as underlying vfs_ops and to connection after all VFS modules are initialized.
*/

typedef struct _vfs_op_tuple {
	void* op;
	vfs_op_type type;
	vfs_op_layer layer;
} vfs_op_tuple;

/*
    Return vfs_ops filled with current opaque VFS operations. This function is designed to
    be called from VFS module initialization function for those modules which needs 'direct' VFS
    access (loggers or initiators of file operations other than connection asks for).
    
    Returned vfs_ops must be cleaned up in VFS module's finalizer function (vfs_done_<module_name>)
    using safe_free().
    
    Prototype:
    struct vfs_ops *smb_vfs_get_opaque_ops();
    
    This prototype will be available via include/proto.h
*/

#endif /* _VFS_H */
