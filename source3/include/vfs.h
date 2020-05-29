/* 
   Unix SMB/CIFS implementation.
   VFS structures and parameters
   Copyright (C) Jeremy Allison                         1999-2005
   Copyright (C) Tim Potter				1999
   Copyright (C) Alexander Bokovoy			2002-2005
   Copyright (C) Stefan (metze) Metzmacher		2003
   Copyright (C) Volker Lendecke			2009

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

/*
 * Changed to version 2 for CIFS UNIX extensions (mknod and link added). JRA.
 * Changed to version 3 for POSIX acl extensions. JRA.
 * Changed to version 4 for cascaded VFS interface. Alexander Bokovoy.
 * Changed to version 5 for sendfile addition. JRA.
 * Changed to version 6 for the new module system, fixed cascading and quota functions. --metze
 * Changed to version 7 to include the get_nt_acl info parameter. JRA.
 * Changed to version 8 includes EA calls. JRA.
 * Changed to version 9 to include the get_shadow_data call. --metze
 * Changed to version 10 to include pread pwrite calls.
 * Changed to version 11 to include seekdir telldir rewinddir calls. JRA
 * Changed to version 12 to add mask and attributes to opendir(). JRA
 * Also include aio calls. JRA.
 * Changed to version 13 as the internal structure of files_struct has changed. JRA
 * Changed to version 14 as we had to change DIR to SMB_STRUCT_DIR. JRA
 * Changed to version 15 as we added the statvfs call. JRA
 * Changed to version 16 as we added the getlock call. JRA
 * Changed to version 17 as we removed redundant connection_struct parameters. --jpeach
 * Changed to version 18 to add fsp parameter to the open call -- jpeach
 * Also include kernel_flock call - jmcd
 * Changed to version 19, kernel change notify has been merged
 * Also included linux setlease call - jmcd
 * Changed to version 20, use ntimes call instead of utime (greater
 * timestamp resolition. JRA.
 * Changed to version21 to add chflags operation -- jpeach
 * Changed to version22 to add lchown operation -- jra
 * Leave at 22 - not yet released. But change set_nt_acl to return an NTSTATUS. jra.
 * Leave at 22 - not yet released. Add file_id_create operation. --metze
 * Leave at 22 - not yet released. Change all BOOL parameters (int) to bool. jra.
 * Leave at 22 - not yet released. Added recvfile.
 * Leave at 22 - not yet released. Change get_nt_acl to return NTSTATUS - vl
 * Leave at 22 - not yet released. Change get_nt_acl to *not* take a
 * files_struct. - obnox.
 * Leave at 22 - not yet released. Remove parameter fd from fget_nt_acl. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from gset_nt_acl. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from pread. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from pwrite. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from lseek. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from fsync. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from fstat. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from fchmod. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from fchown. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from ftruncate. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from lock. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from kernel_flock. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from linux_setlease. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from getlock. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from sys_acl_get_fd. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from fchmod_acl. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from sys_acl_set_fd. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from fgetxattr. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from flistxattr. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from fremovexattr. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from fsetxattr. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from aio_cancel. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from read. - obnox
 * Leave at 22 - not yet released. Remove parameter fd from write. - obnox
 * Leave at 22 - not yet released. Remove parameter fromfd from sendfile. - obnox
 * Leave at 22 - not yet released. Remove parameter fromfd from recvfile. - obnox
 * Leave at 22 - not yet released. Additional change: add operations for offline files -- ab
 * Leave at 22 - not yet released. Add the streaminfo call. -- jpeach, vl
 * Leave at 22 - not yet released. Remove parameter fd from close_fn. - obnox
 * Changed to version 23 - remove set_nt_acl call. This can only be done via an
 *                         open handle. JRA.
 * Changed to version 24 - make security descriptor const in fset_nt_acl. JRA.
 * Changed to version 25 - Jelmer's change from SMB_BIG_UINT to uint64_t.
 * Leave at 25 - not yet released. Add create_file call. -- tprouty.
 * Leave at 25 - not yet released. Add create time to ntimes. -- tstecher.
 * Leave at 25 - not yet released. Add get_alloc_size call. -- tprouty.
 * Leave at 25 - not yet released. Add SMB_STRUCT_STAT to readdir. - sdann
 * Leave at 25 - not yet released. Add init_search_op call. - sdann
 * Leave at 25 - not yet released. Add locking calls. -- zkirsch.
 * Leave at 25 - not yet released. Add strict locking calls. -- drichards.
 * Changed to version 26 - Plumb struct smb_filename to SMB_VFS_CREATE_FILE,
 *                         SMB_VFS_OPEN, SMB_VFS_STAT, SMB_VFS_LSTAT,
 *                         SMB_VFS_RENAME, SMB_VFS_UNLINK, SMB_VFS_NTIMES.
 * Changed to version 27 - not yet released. Added enum timestamp_set_resolution
 *                         return to fs_capabilities call. JRA.
 * Leave at 27 - not yet released. Add translate_name VFS call to convert
 *               UNIX names to Windows supported names -- asrinivasan.
 * Changed to version 28 - Add private_flags uint32_t to CREATE call.
 * Leave at 28 - not yet released. Change realpath to assume NULL and return a
 *               malloc'ed path. JRA.
 * Leave at 28 - not yet released. Move posix_fallocate into the VFS
 *              where it belongs. JRA.
 * Leave at 28 - not yet released. Rename posix_fallocate to fallocate
 *              to split out the two possible uses. JRA.
 * Leave at 28 - not yet released. Add fdopendir. JRA.
 * Leave at 28 - not yet released. Rename open function to open_fn. - gd
 * Leave at 28 - not yet released. Make getwd function always return malloced memory. JRA.
 * Bump to version 29 - Samba 3.6.0 will ship with interface version 28.
 * Leave at 29 - not yet releases. Add fsctl. Richard Sharpe
 * Leave at 29 - not yet released. add SMB_VFS_GET_DFS_REFERRAL() - metze
 * Leave at 29 - not yet released. Remove l{list,get,set,remove}xattr - abartlet
 * Leave at 29 - not yet released. move to plain off_t - abartlet
 * Leave at 29 - not yet released. Remove sys_acl functions other than set and get - abartlet
 * Leave at 29 - not yet released. Added backup_intent bool to files_struct - JRA
 * Leave at 29 - not yet released. Add durable handle functions - metze obnox
 * Leave at 29 - not yet released. Added sys_acl_blob_get_file and sys_acl_blob_get_fd
 * Bump to version 30 - Samba 4.0.0 will ship with interface version 30
 * Leave at 30 - not yet released. Added conn->cwd to save vfs_GetWd() calls.
 * Leave at 30 - not yet released. Changed sys_acl_blob_get_file interface to remove type
 * Bump to version 31 - Samba 4.1.0 will ship with interface version 31
 * Leave at 31 - not yet released. Make struct vuid_cache_entry in
 *               connection_struct a pointer.
 * Leave at 31 - not yet released. Add share_access to vuid_cache_entry.
 * Leave at 31 - not yet released. add SMB_VFS_COPY_CHUNK()
 * Leave at 31 - not yet released. Remove the unused
 *               fsp->pending_break_messages array
 * Leave at 31 - not yet released. add SMB_VFS_[GET SET]_COMPRESSION()
 *
 * Bump to version 32 - Samba 4.2 will ship with that.
 * Version 32 - Add "lease" to CREATE_FILE operation
 * Version 32 - Add "lease" to struct files_struct
 * Version 32 - Add SMB_VFS_READDIR_ATTR()
 * Version 32 - Add in and out create context blobs to create_file
 * Version 32 - Remove unnecessary SMB_VFS_DISK_FREE() small_query parameter
 * Bump to version 33 - Samba 4.3 will ship with that.
 * Version 33 - change fallocate mode flags param from enum->uint32_t
 * Version 33 - Add snapshot create delete calls
 * Version 33 - Add OS X SMB2 AAPL copyfile extension flag to fsp
 * Version 33 - Remove notify_watch_fn
 * Bump to version 34 - Samba 4.4 will ship with that
 * Version 34 - Remove bool posix_open, add uint64_t posix_flags
 * Version 34 - Added bool posix_pathnames to struct smb_request
 * Bump to version 35 - Samba 4.5 will ship with that
 * Version 35 - Change get_nt_acl_fn from const char *, to
 *              const struct smb_filename *
 * Version 35 - Change mkdir from const char *, to
 *              const struct smb_filename *
 * Version 35 - Change rmdir from const char *, to
 *              const struct smb_filename *
 * Version 35 - Change opendir from const char *, to
 *              const struct smb_filename *
 * Version 35 - Wrap aio async funtions args in a struct vfs_aio_state
 * Version 35 - Change chmod from const char *, to
 *              const struct smb_filename *
 * Version 35 - Change chmod_acl from const char *, to
 *              const struct smb_filename *
 * Version 35 - Change chown from const char *, to
 *              const struct smb_filename *
 * Version 35 - Change lchown from const char *, to
 *              const struct smb_filename *
 * Version 35 - Change streaminfo from const char *, to
 *              const struct smb_filename *
 * Version 35 - Add uint32_t flags to struct smb_filename
 * Version 35 - Add get set fget fset dos attribute functions.
 * Version 35 - Add bool use_ofd_locks to struct files_struct
 * Bump to version 36 - Samba 4.6 will ship with that
 * Version 36 - Remove is_offline and set_offline
 * Version 37 - Module init functions now take a TALLOC_CTX * parameter.
 * Version 37 - Add vfs_copy_chunk_flags for DUP_EXTENTS_TO_FILE
 * Version 37 - Change sys_acl_delete_def_file from const char *
 *              to const struct smb_filename *
 * Version 37 - Change sys_acl_get_file from const char *
 *              to const struct smb_filename *
 * Version 37 - Change sys_acl_blob_get_file from const char *
 *              to const struct smb_filename *
 * Version 37 - Change sys_acl_set_file from const char *
 *              to const struct smb_filename *
 * Version 37 - Change listxattr from const char *
 *              to const struct smb_filename *
 * Version 37 - Change removexattr from const char *
 *              to const struct smb_filename *
 * Version 37 - Change setxattr from const char *
 *              to const struct smb_filename *
 * Version 37 - Change getxattr from const char *
 *              to const struct smb_filename *
 * Version 37 - Change mknod from const char * to const struct smb_filename *
 * Version 37 - Change chflags from const char *
 *              to const struct smb_filename *
 * Version 37 - Change disk_free from const char *
 *              to const struct smb_filename *
 * Version 37 - Change get_quota from const char *
 *              to const struct smb_filename *
 * Version 37 - Change link from const char *
 *              to const struct smb_filename *
 * Version 37 - Change statvfs from const char *
 *              to const struct smb_filename *
 * Version 37 - Change readlink from const char *
 *              to const struct smb_filename *
 * Version 37 - Change symlink from const char *
 *              to const struct smb_filename *
 * Version 37 - Change chdir from const char *
 *              to const struct smb_filename *
 * Version 37 - Change getwd from char *
 *              to const struct smb_filename *
 * Version 37 - Change conn->cwd from char *
 *              to struct smb_filename *
 * Version 37 - Change realpath from char *
 *              to struct smb_filename *
 * Version 37 - Change connectpath from char *
 *              to struct smb_filename *
 * Version 37 - Add SMB_VFS_OFFLOAD_READ_SEND RECV
 * Version 37 - Rename SMB_VFS_COPY_CHUNK_SEND RECV to
 *              SMB_VFS_OFFLOAD_READ_SEND RECV
 * Version 37 - Remove SMB_VFS_STRICT_UNLOCK
 * Version 37 - Rename SMB_VFS_STRICT_LOCK to
 *              SMB_VFS_STRICT_LOCK_CHECK
 * Version 38 - Remove SMB_VFS_INIT_SEARCH_OP
 * Bump to version 39, Samba 4.9 will ship with that
 * Version 39 - Remove SMB_VFS_FSYNC
 *              Only implement async versions.
 * Version 39 - Remove SMB_VFS_READ
 *              All users are now pread or async versions.
 * Version 39 - Remove SMB_VFS_WRITE
 *              All users are now pwrite or async versions.
 * Version 39 - Remove SMB_VFS_CHMOD_ACL - no longer used.
 * Version 39 - Remove SMB_VFS_FCHMOD_ACL - no longer used.
 * Version 39 - Remove struct dfree_cached_info pointer from
 *              connection struct
 * Bump to version 40, Samba 4.10 will ship with that
 * Version 40 - Add SMB_VFS_GETXATTRAT_SEND RECV
 * Version 40 - Add SMB_VFS_GET_DOS_ATTRIBUTES_SEND RECV
 * Bump to version 41, Samba 4.11 will ship with that
 * Version 41 - Remove SMB_VFS_BRL_CANCEL_WINDOWS
 * Version 41 - Remove unused st_ex_mask from struct stat_ex
 * Version 41 - convert struct stat_ex.st_ex_calculated_birthtime to flags
 * Version 41 - add st_ex_itime to struct stat_ex
 * Version 41 - add st_ex_file_id to struct stat_ex
 * Version 41 - add SMB_VFS_FS_FILE_ID
 * Version 41 - Remove "blocking_lock" parameter from
 *              SMB_VFS_BRL_LOCK_WINDOWS
 * Version 41 - Remove "msg_ctx" parameter from SMB_VFS_BRL_UNLOCK_WINDOWS
 * Bump to version 42, Samba 4.12 will ship with that
 * Version 42 - Remove share_access member from struct files_struct
 * Version 42 - Make "lease" a const* in create_file_fn
 * Version 42 - Move SMB_VFS_RENAME -> SMB_VFS_RENAMEAT
 * Version 42 - Move SMB_VFS_LINK -> SMB_VFS_LINKAT.
 * Version 42 - Move SMB_VFS_MKNOD -> SMB_VFS_MKDNODAT.
 * Version 42 - Move SMB_VFS_READLINK -> SMB_VFS_READLINKAT.
 * Version 42 - Move SMB_VFS_SYMLINK -> SMB_VFS_SYMLINKAT.
 * Version 42 - Move SMB_VFS_MKDIR -> SMB_VFS_MKDIRAT.
 * Version 42 - Move change_to_user() -> change_to_user_and_service()
 * Version 42 - Move change_to_user_by_fsp() -> change_to_user_and_service_by_fsp()
 * Version 42 - Move [un]become_user*() -> [un]become_user_without_service*()
 * Version 42 - Move SMB_VFS_UNLINK -> SMB_VFS_UNLINKAT.
 * Version 42 - Add SMB_VFS_FCNTL
 * Version 42 - Remove SMB_VFS_RMDIR.
 *              Use SMB_VFS_UNLINKAT(.., AT_REMOVEDIR) instead.
 * Version 42 - Remove SMB_VFS_CHOWN
 * Version 42 - Remove struct write_cache *wcp from files_struct
 * Version 42 - SMB_VFS_NTIMES() receives null times based on UTIMES_OMIT
 * Version 42 - Add SMB_VFS_CREATE_DFS_PATHAT()
 * Version 42 - Add SMB_VFS_READ_DFS_PATHAT()
 * Change to Version 43 - will ship with 4.13.
 * Version 43 - Remove deferred_close from struct files_struct
 * Version 43 - Remove SMB_VFS_OPENDIR()
 * Version 43 - Remove original_lcomp from struct smb_filename
 * Version 43 - files_struct flags:
 *              bool kernel_share_modes_taken
 *              bool update_write_time_triggered
 *              bool update_write_time_on_close
 *              bool write_time_forced
 *              bool can_lock
 *              bool can_read
 *              bool can_write
 *              bool modified
 *              bool is_directory
 *              bool aio_write_behind
 *              bool initial_delete_on_close
 *              bool delete_on_close
 *              bool is_sparse
 *              bool backup_intent
 *              bool use_ofd_locks
 *              bool closing
 *              bool lock_failure_seen
 *              changed to bitfields.
 * Version 43 - convert SMB_VFS_GET_REAL_FILENAME() arg path
 *              to be a struct smb_filename
 * Version 43 - convert link_contents arg of SMB_VFS_SYMLINKAT()
 *              to struct smb_filename
 * Version 43 - Move SMB_VFS_GET_NT_ACL() -> SMB_VFS_GET_NT_ACL_AT().
 * Version 43 - Remove root_dir_fid from SMB_VFS_CREATE_FILE().
 * Version 43 - Add dirfsp to struct files_struct
 * Version 43 - Add dirfsp args to SMB_VFS_CREATE_FILE()
 * Version 43 - Add SMB_VFS_OPENAT()
 * Version 43 - Remove SMB_VFS_OPEN()
 * Version 43 - SMB_VFS_READ_DFS_PATHAT() should take a non-const name.
		There's no easy way to return stat info for a DFS link
		otherwise.
 */

#define SMB_VFS_INTERFACE_VERSION 43

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
struct smb_request;
struct ea_list;
struct smb_file_time;
struct smb_filename;
struct dfs_GetDFSReferral;

typedef union unid_t {
	uid_t uid;
	gid_t gid;
} unid_t;

struct fd_handle {
	size_t ref_count;
	int fd;
	uint64_t position_information;
	off_t pos;
	uint32_t private_options;	/* NT Create options, but we only look at
				 * NTCREATEX_OPTIONS_PRIVATE_DENY_DOS and
				 * NTCREATEX_OPTIONS_PRIVATE_DENY_FCB and
				 * NTCREATEX_OPTIONS_PRIVATE_DELETE_ON_CLOSE
				 * for print files *only*, where
				 * DELETE_ON_CLOSE is not stored in the share
				 * mode database.
				 */
	uint64_t gen_id;
};

struct fsp_lease {
	size_t ref_count;
	struct smbd_server_connection *sconn;
	struct tevent_timer *timeout;
	struct smb2_lease lease;
};

typedef struct files_struct {
	struct files_struct *next, *prev;
	uint64_t fnum;
	struct smbXsrv_open *op;
	struct connection_struct *conn;
	struct fd_handle *fh;
	struct files_struct *dirfsp;
	unsigned int num_smb_operations;
	struct file_id file_id;
	uint64_t initial_allocation_size; /* Faked up initial allocation on disk. */
	uint16_t file_pid;
	uint64_t vuid; /* SMB2 compat */
	struct timeval open_time;
	uint32_t access_mask;		/* NTCreateX access bits (FILE_READ_DATA etc.) */
	struct {
		bool kernel_share_modes_taken : 1;
		bool update_write_time_triggered : 1;
		bool update_write_time_on_close : 1;
		bool write_time_forced : 1;
		bool can_lock : 1;
		bool can_read : 1;
		bool can_write : 1;
		bool modified : 1;
		bool is_directory : 1;
		bool is_dirfsp : 1;
		bool aio_write_behind : 1;
		bool initial_delete_on_close : 1;
		bool delete_on_close : 1;
		bool is_sparse : 1;
		bool backup_intent : 1;
		bool use_ofd_locks : 1;
		bool closing : 1;
		bool lock_failure_seen : 1;
	} fsp_flags;

	struct tevent_timer *update_write_time_event;
	struct timespec close_write_time;

	int oplock_type;

	/*
	 * Cache of our lease_type, stored as "current_state" in
	 * leases.tdb
	 */
	int leases_db_seqnum;
	uint32_t lease_type;

	struct fsp_lease *lease;
	int sent_oplock_break;
	struct tevent_timer *oplock_timeout;
	struct lock_struct last_lock_failure;
	int current_lock_count; /* Count the number of outstanding locks and pending locks. */

	uint64_t posix_flags;
	struct smb_filename *fsp_name;
	uint32_t name_hash;		/* Jenkins hash of full pathname. */
	uint64_t mid;			/* Mid of the operation that created us. */

	struct vfs_fsp_data *vfs_extension;
	struct fake_file_handle *fake_file_handle;

	struct notify_change_buf *notify;

	struct files_struct *base_fsp; /* placeholder for delete on close */

	/*
	 * Cache of share_mode_data->flags
	 */
	int share_mode_flags_seqnum;
	uint16_t share_mode_flags;

	/*
	 * Read-only cached brlock record, thrown away when the
	 * brlock.tdb seqnum changes. This avoids fetching data from
	 * the brlock.tdb on every read/write call.
	 */
	int brlock_seqnum;
	struct byte_range_lock *brlock_rec;

	struct dptr_struct *dptr;

	/* if not NULL, means this is a print file */
	struct print_file_data *print_file;

	/*
	 * Optimize the aio_requests array for high performance: Never
	 * shrink it, maintain num_aio_requests separately
	 */
	unsigned num_aio_requests;
	struct tevent_req **aio_requests;

	/*
	 * Requests waiting for smb1 byte range locks. They are
	 * generated by smbd_smb1_do_locks_send and are required here,
	 * because lock cancel operations index through reply_lockingX
	 * not based on mid but on the lock type and range.
	 */
	struct tevent_req **blocked_smb1_lock_reqs;

	/*
	 * SMB1 remembers lock failures and delays repeated blocking
	 * lock attempts on the same offset.
	 */
	uint64_t lock_failure_offset;
} files_struct;

#define FSP_POSIX_FLAGS_OPEN		0x01
#define FSP_POSIX_FLAGS_RENAME		0x02
#define FSP_POSIX_FLAGS_PATHNAMES	0x04

#define FSP_POSIX_FLAGS_ALL			\
	(FSP_POSIX_FLAGS_OPEN |			\
	 FSP_POSIX_FLAGS_PATHNAMES |		\
	 FSP_POSIX_FLAGS_RENAME)

struct vuid_cache_entry {
	struct auth_session_info *session_info;
	uint64_t vuid; /* SMB2 compat */
	bool read_only;
	uint32_t share_access;
};

struct vuid_cache {
	unsigned int next_entry;
	struct vuid_cache_entry array[VUID_CACHE_SIZE];
};

typedef struct {
	char *name;
	bool is_wild;
} name_compare_entry;

struct share_params {
	int service;
};

typedef struct connection_struct {
	struct connection_struct *next, *prev;
	struct smbd_server_connection *sconn; /* can be NULL */
	struct smbXsrv_tcon *tcon; /* can be NULL */
	uint32_t cnum; /* an index passed over the wire */
	struct share_params *params;
	bool force_user;
	struct vuid_cache *vuid_cache;
	bool printer;
	bool ipc;
	bool read_only; /* Attributes for the current user of the share. */
	uint32_t share_access;
	/* Does this filesystem honor
	   sub second timestamps on files
	   and directories when setting time ? */
	enum timestamp_set_resolution ts_res;
	char *connectpath;
	struct files_struct *cwd_fsp; /* Working directory. */
	bool tcon_done;

	struct vfs_handle_struct *vfs_handles;		/* for the new plugins */

	/*
	 * This represents the user information on this connection. Depending
	 * on the vuid using this tid, this might change per SMB request.
	 */
	struct auth_session_info *session_info;

	/*
	 * If the "force group" parameter is set, this is the primary gid that
	 * may be used in the users token, depending on the vuid using this tid.
	 */
	gid_t force_group_gid;

	uint64_t vuid; /* vuid of user who *opened* this connection, or UID_FIELD_INVALID */

	time_t lastused;
	time_t lastused_count;
	int num_files_open;
	unsigned int num_smb_operations; /* Count of smb operations on this tree. */
	int encrypt_level;
	bool encrypted_tid;

	/* Semantics requested by the client or forced by the server config. */
	bool case_sensitive;
	bool case_preserve;
	bool short_case_preserve;

	/* Semantics provided by the underlying filesystem. */
	int fs_capabilities;
	/* Device number of the directory of the share mount.
	   Used to ensure unique FileIndex returns. */
	SMB_DEV_T base_share_dev;

	name_compare_entry *hide_list; /* Per-share list of files to return as hidden. */
	name_compare_entry *veto_list; /* Per-share list of files to veto (never show). */
	name_compare_entry *veto_oplock_list; /* Per-share list of files to refuse oplocks on. */       
	name_compare_entry *aio_write_behind_list; /* Per-share list of files to use aio write behind on. */       
	struct trans_state *pending_trans;

	struct rpc_pipe_client *spoolss_pipe;

} connection_struct;

struct smbd_smb2_request;
struct referral;

struct smb_request {
	uint8_t cmd;
	uint16_t flags2;
	uint16_t smbpid;
	uint64_t mid; /* For compatibility with SMB2. */
	uint32_t seqnum;
	uint64_t vuid; /* For compatibility with SMB2. */
	uint32_t tid;
	uint8_t  wct;
	const uint16_t *vwv;
	uint16_t buflen;
	const uint8_t *buf;
	const uint8_t *inbuf;

	/*
	 * Async handling in the main smb processing loop is directed by
	 * outbuf: reply_xxx routines indicate sync behaviour by putting their
	 * reply into "outbuf". If they leave it as NULL, they take care of it
	 * themselves, possibly later.
	 *
	 * If async handling is wanted, the reply_xxx routine must make sure
	 * that it talloc_move()s the smb_req somewhere else.
	 */
	uint8_t *outbuf;

	size_t unread_bytes;
	bool encrypted;
	connection_struct *conn;
	struct smbd_server_connection *sconn;
	struct smbXsrv_connection *xconn;

	/*
	 * Pointer to session, can be NULL,
	 * eg during negprot and session setup.
	 */
	struct smbXsrv_session *session;

	struct smb_perfcount_data pcd;

	/*
	 * Chained request handling
	 */
	struct files_struct *chain_fsp;

	/*
	 * state information for async smb handling
	 */
	void *async_priv;

	/*
	 * Back pointer to smb2 request.
	 */
	struct smbd_smb2_request *smb2req;

	/*
	 * Request list for chained requests, we're part of it.
	 */
	struct smb_request **chain;

	struct timeval request_time;

	bool posix_pathnames;
};

/*
 * Info about an alternate data stream
 */

struct stream_struct {
	off_t size;
	off_t alloc_size;
	char *name;
};

/* time info */
struct smb_file_time {
	struct timespec mtime;
	struct timespec atime;
	struct timespec ctime;
	struct timespec create_time;
};

/*
 * smb_filename
 */
struct smb_filename {
	char *base_name;
	char *stream_name;
	uint32_t flags;
	SMB_STRUCT_STAT st;
	NTTIME twrp;
};

/*
 * smb_filename flags. Define in terms of the FSP_POSIX_FLAGS_XX
 * to keep the numeric values consistent.
 */

#define SMB_FILENAME_POSIX_PATH		FSP_POSIX_FLAGS_PATHNAMES

#define VFS_FIND(__fn__) while (handle->fns->__fn__##_fn==NULL) { \
				handle = handle->next; \
			 }

enum vfs_translate_direction {
	vfs_translate_to_unix = 0,
	vfs_translate_to_windows
};

enum vfs_fallocate_flags {
	VFS_FALLOCATE_FL_KEEP_SIZE		= 0x0001,
	VFS_FALLOCATE_FL_PUNCH_HOLE		= 0x0002,
};

struct vfs_aio_state {
	int error;
	uint64_t duration;
};

/*
    Available VFS operations. These values must be in sync with vfs_ops struct
    (struct vfs_fn_pointers and struct vfs_handle_pointers inside of struct vfs_ops).
    In particular, if new operations are added to vfs_ops, appropriate constants
    should be added to vfs_op_type so that order of them kept same as in vfs_ops.
*/
struct shadow_copy_data;

struct vfs_fn_pointers {
	/* Disk operations */

	int (*connect_fn)(struct vfs_handle_struct *handle, const char *service, const char *user);
	void (*disconnect_fn)(struct vfs_handle_struct *handle);
	uint64_t (*disk_free_fn)(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize);
	int (*get_quota_fn)(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *qt);
	int (*set_quota_fn)(struct vfs_handle_struct *handle, enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *qt);
	int (*get_shadow_copy_data_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, struct shadow_copy_data *shadow_copy_data, bool labels);
	int (*statvfs_fn)(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				struct vfs_statvfs_struct *statbuf);
	uint32_t (*fs_capabilities_fn)(struct vfs_handle_struct *handle, enum timestamp_set_resolution *p_ts_res);

	/*
	 * Note: that "struct dfs_GetDFSReferral *r"
	 * needs to be a valid TALLOC_CTX
	 */
	NTSTATUS (*get_dfs_referrals_fn)(struct vfs_handle_struct *handle,
					 struct dfs_GetDFSReferral *r);
	NTSTATUS (*create_dfs_pathat_fn)(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count);
	NTSTATUS (*read_dfs_pathat_fn)(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count);

	/* Directory operations */

	DIR *(*fdopendir_fn)(struct vfs_handle_struct *handle, files_struct *fsp, const char *mask, uint32_t attributes);
	struct dirent *(*readdir_fn)(struct vfs_handle_struct *handle,
					 DIR *dirp,
					 SMB_STRUCT_STAT *sbuf);
	void (*seekdir_fn)(struct vfs_handle_struct *handle, DIR *dirp, long offset);
	long (*telldir_fn)(struct vfs_handle_struct *handle, DIR *dirp);
	void (*rewind_dir_fn)(struct vfs_handle_struct *handle, DIR *dirp);
	int (*mkdirat_fn)(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode);
	int (*closedir_fn)(struct vfs_handle_struct *handle, DIR *dir);

	/* File operations */

	int (*openat_fn)(struct vfs_handle_struct *handle,
			 const struct files_struct *dirfsp,
			 const struct smb_filename *smb_fname,
			 struct files_struct *fsp,
			 int flags,
			 mode_t mode);
	NTSTATUS (*create_file_fn)(struct vfs_handle_struct *handle,
				   struct smb_request *req,
				   struct files_struct **dirfsp,
				   struct smb_filename *smb_fname,
				   uint32_t access_mask,
				   uint32_t share_access,
				   uint32_t create_disposition,
				   uint32_t create_options,
				   uint32_t file_attributes,
				   uint32_t oplock_request,
				   const struct smb2_lease *lease,
				   uint64_t allocation_size,
				   uint32_t private_flags,
				   struct security_descriptor *sd,
				   struct ea_list *ea_list,
				   files_struct **result,
				   int *pinfo,
				   const struct smb2_create_blobs *in_context_blobs,
				   struct smb2_create_blobs *out_context_blobs);
	int (*close_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp);
	ssize_t (*pread_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, void *data, size_t n, off_t offset);
	struct tevent_req *(*pread_send_fn)(struct vfs_handle_struct *handle,
					    TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct files_struct *fsp,
					    void *data,
					    size_t n, off_t offset);
	ssize_t (*pread_recv_fn)(struct tevent_req *req, struct vfs_aio_state *state);
	ssize_t (*pwrite_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, const void *data, size_t n, off_t offset);
	struct tevent_req *(*pwrite_send_fn)(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct tevent_context *ev,
					     struct files_struct *fsp,
					     const void *data,
					     size_t n, off_t offset);
	ssize_t (*pwrite_recv_fn)(struct tevent_req *req, struct vfs_aio_state *state);
	off_t (*lseek_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, off_t offset, int whence);
	ssize_t (*sendfile_fn)(struct vfs_handle_struct *handle, int tofd, files_struct *fromfsp, const DATA_BLOB *header, off_t offset, size_t count);
	ssize_t (*recvfile_fn)(struct vfs_handle_struct *handle, int fromfd, files_struct *tofsp, off_t offset, size_t count);
	int (*renameat_fn)(struct vfs_handle_struct *handle,
			 struct files_struct *srcdir_fsp,
			 const struct smb_filename *smb_fname_src,
			 struct files_struct *dstdir_fsp,
			 const struct smb_filename *smb_fname_dst);
	struct tevent_req *(*fsync_send_fn)(struct vfs_handle_struct *handle,
					    TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct files_struct *fsp);
	int (*fsync_recv_fn)(struct tevent_req *req, struct vfs_aio_state *state);
	int (*stat_fn)(struct vfs_handle_struct *handle, struct smb_filename *smb_fname);
	int (*fstat_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_STRUCT_STAT *sbuf);
	int (*lstat_fn)(struct vfs_handle_struct *handle, struct smb_filename *smb_filename);
	uint64_t (*get_alloc_size_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, const SMB_STRUCT_STAT *sbuf);
	int (*unlinkat_fn)(struct vfs_handle_struct *handle,
			struct files_struct *srcdir_fsp,
			const struct smb_filename *smb_fname,
			int flags);
	int (*chmod_fn)(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode);
	int (*fchmod_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, mode_t mode);
	int (*fchown_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, uid_t uid, gid_t gid);
	int (*lchown_fn)(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid);
	int (*chdir_fn)(struct vfs_handle_struct *handle,
			 const struct smb_filename *smb_fname);
	struct smb_filename *(*getwd_fn)(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx);
	int (*ntimes_fn)(struct vfs_handle_struct *handle,
			 const struct smb_filename *smb_fname,
			 struct smb_file_time *ft);
	int (*ftruncate_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, off_t offset);
	int (*fallocate_fn)(struct vfs_handle_struct *handle,
			    struct files_struct *fsp,
			    uint32_t mode,
			    off_t offset,
			    off_t len);
	bool (*lock_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, int op, off_t offset, off_t count, int type);
	int (*kernel_flock_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp,
			       uint32_t share_access, uint32_t access_mask);
	int (*fcntl_fn)(struct vfs_handle_struct *handle,
			struct files_struct *fsp, int cmd, va_list cmd_arg);
	int (*linux_setlease_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, int leasetype);
	bool (*getlock_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid);
	int (*symlinkat_fn)(struct vfs_handle_struct *handle,
				const struct smb_filename *link_contents,
				struct files_struct *dirfsp,
				const struct smb_filename *new_smb_fname);
	int (*readlinkat_fn)(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				char *buf,
				size_t bufsiz);
	int (*linkat_fn)(struct vfs_handle_struct *handle,
				struct files_struct *srcfsp,
				const struct smb_filename *old_smb_fname,
				struct files_struct *dstfsp,
				const struct smb_filename *new_smb_fname,
				int flags);
	int (*mknodat_fn)(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				mode_t mode,
				SMB_DEV_T dev);
	struct smb_filename *(*realpath_fn)(struct vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname);
	int (*chflags_fn)(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				unsigned int flags);
	struct file_id (*file_id_create_fn)(struct vfs_handle_struct *handle,
					    const SMB_STRUCT_STAT *sbuf);
	uint64_t (*fs_file_id_fn)(struct vfs_handle_struct *handle,
				  const SMB_STRUCT_STAT *sbuf);
	struct tevent_req *(*offload_read_send_fn)(TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct vfs_handle_struct *handle,
						   struct files_struct *fsp,
						   uint32_t fsctl,
						   uint32_t ttl,
						   off_t offset,
						   size_t to_copy);
	NTSTATUS (*offload_read_recv_fn)(struct tevent_req *req,
					 struct vfs_handle_struct *handle,
					 TALLOC_CTX *mem_ctx,
					 DATA_BLOB *token_blob);
	struct tevent_req *(*offload_write_send_fn)(struct vfs_handle_struct *handle,
						    TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    uint32_t fsctl,
						    DATA_BLOB *token,
						    off_t transfer_offset,
						    struct files_struct *dest_fsp,
						    off_t dest_off,
						    off_t to_copy);
	NTSTATUS (*offload_write_recv_fn)(struct vfs_handle_struct *handle,
					  struct tevent_req *req,
					  off_t *copied);
	NTSTATUS (*get_compression_fn)(struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       struct files_struct *fsp,
				       struct smb_filename *smb_fname,
				       uint16_t *_compression_fmt);
	NTSTATUS (*set_compression_fn)(struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       struct files_struct *fsp,
				       uint16_t compression_fmt);
	NTSTATUS (*snap_check_path_fn)(struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       const char *service_path,
				       char **base_volume);
	NTSTATUS (*snap_create_fn)(struct vfs_handle_struct *handle,
				   TALLOC_CTX *mem_ctx,
				   const char *base_volume,
				   time_t *tstamp,
				   bool rw,
				   char **base_path,
				   char **snap_path);
	NTSTATUS (*snap_delete_fn)(struct vfs_handle_struct *handle,
				   TALLOC_CTX *mem_ctx,
				   char *base_path,
				   char *snap_path);

	NTSTATUS (*streaminfo_fn)(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  const struct smb_filename *smb_fname,
				  TALLOC_CTX *mem_ctx,
				  unsigned int *num_streams,
				  struct stream_struct **streams);

	int (*get_real_filename_fn)(struct vfs_handle_struct *handle,
				    const struct smb_filename *path,
				    const char *name,
				    TALLOC_CTX *mem_ctx,
				    char **found_name);

	const char *(*connectpath_fn)(struct vfs_handle_struct *handle,
				      const struct smb_filename *smb_fname);

	NTSTATUS (*brl_lock_windows_fn)(struct vfs_handle_struct *handle,
					struct byte_range_lock *br_lck,
					struct lock_struct *plock);

	bool (*brl_unlock_windows_fn)(struct vfs_handle_struct *handle,
				      struct byte_range_lock *br_lck,
				      const struct lock_struct *plock);

	bool (*strict_lock_check_fn)(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     struct lock_struct *plock);

	NTSTATUS (*translate_name_fn)(struct vfs_handle_struct *handle,
				      const char *name,
				      enum vfs_translate_direction direction,
				      TALLOC_CTX *mem_ctx,
				      char **mapped_name);

	NTSTATUS (*fsctl_fn)(struct vfs_handle_struct *handle,
			     struct files_struct *fsp,
			     TALLOC_CTX *ctx,
			     uint32_t function,
			     uint16_t req_flags,
			     const uint8_t *_in_data,
			     uint32_t in_len,
			     uint8_t **_out_data,
			     uint32_t max_out_len,
			     uint32_t *out_len); 

	NTSTATUS (*get_dos_attributes_fn)(struct vfs_handle_struct *handle,
					  struct smb_filename *smb_fname,
					  uint32_t *dosmode);

	NTSTATUS (*fget_dos_attributes_fn)(struct vfs_handle_struct *handle,
					   struct files_struct *fsp,
					   uint32_t *dosmode);

	NTSTATUS (*set_dos_attributes_fn)(struct vfs_handle_struct *handle,
					  const struct smb_filename *smb_fname,
					  uint32_t dosmode);

	NTSTATUS (*fset_dos_attributes_fn)(struct vfs_handle_struct *hande,
					   struct files_struct *fsp,
					   uint32_t dosmode);

	struct tevent_req *(*get_dos_attributes_send_fn)(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct vfs_handle_struct *handle,
				files_struct *dir_fsp,
				struct smb_filename *smb_fname);

	NTSTATUS (*get_dos_attributes_recv_fn)(
				struct tevent_req *req,
				struct vfs_aio_state *aio_state,
				uint32_t *dosmode);

	/* NT ACL operations. */

	NTSTATUS (*fget_nt_acl_fn)(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   uint32_t security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **ppdesc);
	NTSTATUS (*get_nt_acl_at_fn)(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc);
	NTSTATUS (*fset_nt_acl_fn)(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   uint32_t security_info_sent,
				   const struct security_descriptor *psd);

	NTSTATUS (*audit_file_fn)(struct vfs_handle_struct *handle,
				  struct smb_filename *file,
				  struct security_acl *sacl,
				  uint32_t access_requested,
				  uint32_t access_denied);

	/* POSIX ACL operations. */

	SMB_ACL_T (*sys_acl_get_file_fn)(struct vfs_handle_struct *handle,
					 const struct smb_filename *smb_fname,
					 SMB_ACL_TYPE_T type,
					 TALLOC_CTX *mem_ctx);
	SMB_ACL_T (*sys_acl_get_fd_fn)(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       TALLOC_CTX *mem_ctx);
	int (*sys_acl_blob_get_file_fn)(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					TALLOC_CTX *mem_ctx,
					char **blob_description,
					DATA_BLOB *blob);
	int (*sys_acl_blob_get_fd_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp,
				      TALLOC_CTX *mem_ctx, char **blob_description,
				      DATA_BLOB *blob);
	int (*sys_acl_set_file_fn)(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					SMB_ACL_TYPE_T acltype,
					SMB_ACL_T theacl);
	int (*sys_acl_set_fd_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, SMB_ACL_T theacl);
	int (*sys_acl_delete_def_file_fn)(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname);

	/* EA operations. */
	ssize_t (*getxattr_fn)(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					const char *name,
					void *value,
					size_t size);
	struct tevent_req *(*getxattrat_send_fn)(
				TALLOC_CTX *mem_ctx,
				struct tevent_context *ev,
				struct vfs_handle_struct *handle,
				files_struct *dir_fsp,
				const struct smb_filename *smb_fname,
				const char *xattr_name,
				size_t alloc_hint);
	ssize_t (*getxattrat_recv_fn)(struct tevent_req *req,
				      struct vfs_aio_state *aio_state,
				      TALLOC_CTX *mem_ctx,
				      uint8_t **xattr_value);
	ssize_t (*fgetxattr_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, void *value, size_t size);
	ssize_t (*listxattr_fn)(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					char *list,
					size_t size);
	ssize_t (*flistxattr_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, char *list, size_t size);
	int (*removexattr_fn)(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					const char *name);
	int (*fremovexattr_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name);
	int (*setxattr_fn)(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					const char *name,
					const void *value,
					size_t size,
					int flags);
	int (*fsetxattr_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp, const char *name, const void *value, size_t size, int flags);

	/* aio operations */
	bool (*aio_force_fn)(struct vfs_handle_struct *handle, struct files_struct *fsp);

	/* durable handle operations */
	NTSTATUS (*durable_cookie_fn)(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      TALLOC_CTX *mem_ctx,
				      DATA_BLOB *cookie);
	NTSTATUS (*durable_disconnect_fn)(struct vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  const DATA_BLOB old_cookie,
					  TALLOC_CTX *mem_ctx,
					  DATA_BLOB *new_cookie);
	NTSTATUS (*durable_reconnect_fn)(struct vfs_handle_struct *handle,
					 struct smb_request *smb1req,
					 struct smbXsrv_open *op,
					 const DATA_BLOB old_cookie,
					 TALLOC_CTX *mem_ctx,
					 struct files_struct **fsp,
					 DATA_BLOB *new_cookie);

	NTSTATUS (*readdir_attr_fn)(struct vfs_handle_struct *handle,
				    const struct smb_filename *fname,
				    TALLOC_CTX *mem_ctx,
				    struct readdir_attr_data **attr_data);
};

/*
    VFS operation description. Each VFS module registers an array of vfs_op_tuple to VFS subsystem,
    which describes all operations this module is willing to intercept.
    VFS subsystem initializes then the conn->vfs_ops and conn->vfs_opaque_ops structs
    using this information.
*/

typedef struct vfs_handle_struct {
	struct vfs_handle_struct  *next, *prev;
	const char *param;
	struct connection_struct *conn;
	const struct vfs_fn_pointers *fns;
	void *data;
	void (*free_data)(void **data);
} vfs_handle_struct;


typedef struct vfs_statvfs_struct {
	/* For undefined recommended transfer size return -1 in that field */
	uint32_t OptimalTransferSize;  /* bsize on some os, iosize on other os */
	uint32_t BlockSize;

	/*
	 The next three fields are in terms of the block size.
	 (above). If block size is unknown, 4096 would be a
	 reasonable block size for a server to report.
	 Note that returning the blocks/blocksavail removes need
	 to make a second call (to QFSInfo level 0x103 to get this info.
	 UserBlockAvail is typically less than or equal to BlocksAvail,
	 if no distinction is made return the same value in each.
	*/

	uint64_t TotalBlocks;
	uint64_t BlocksAvail;       /* bfree */
	uint64_t UserBlocksAvail;   /* bavail */

	/* For undefined Node fields or FSID return -1 */
	uint64_t TotalFileNodes;
	uint64_t FreeFileNodes;
	uint64_t FsIdentifier;   /* fsid */
	/* NB Namelen comes from FILE_SYSTEM_ATTRIBUTE_INFO call */
	/* NB flags can come from FILE_SYSTEM_DEVICE_INFO call   */

	int FsCapabilities;
} vfs_statvfs_struct;

/* Add a new FSP extension of the given type. Returns a pointer to the
 * extenstion data.
 */
#define VFS_ADD_FSP_EXTENSION(handle, fsp, type, destroy_fn)		\
    (type *)vfs_add_fsp_extension_notype(handle, (fsp), sizeof(type), (destroy_fn))

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
		DEBUG(0,("%s() failed to get vfs_handle->data!\n",__FUNCTION__)); \
		ret; \
	} \
}

#define SMB_VFS_HANDLE_SET_DATA(handle, datap, free_fn, type, ret) { \
	if (!(handle)) { \
		DEBUG(0,("%s() failed to set handle->data!\n",__FUNCTION__)); \
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

int smb_vfs_call_connect(struct vfs_handle_struct *handle,
			 const char *service, const char *user);
void smb_vfs_call_disconnect(struct vfs_handle_struct *handle);
uint64_t smb_vfs_call_disk_free(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_filename,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize);
int smb_vfs_call_get_quota(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_filename,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *qt);
int smb_vfs_call_set_quota(struct vfs_handle_struct *handle,
			   enum SMB_QUOTA_TYPE qtype, unid_t id,
			   SMB_DISK_QUOTA *qt);
int smb_vfs_call_get_shadow_copy_data(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      struct shadow_copy_data *shadow_copy_data,
				      bool labels);
int smb_vfs_call_statvfs(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			struct vfs_statvfs_struct *statbuf);
uint32_t smb_vfs_call_fs_capabilities(struct vfs_handle_struct *handle,
				      enum timestamp_set_resolution *p_ts_res);
/*
 * Note: that "struct dfs_GetDFSReferral *r" needs to be a valid TALLOC_CTX
 */
NTSTATUS smb_vfs_call_get_dfs_referrals(struct vfs_handle_struct *handle,
					struct dfs_GetDFSReferral *r);
NTSTATUS smb_vfs_call_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count);
NTSTATUS smb_vfs_call_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count);
DIR *smb_vfs_call_fdopendir(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					const char *mask,
					uint32_t attributes);
struct dirent *smb_vfs_call_readdir(struct vfs_handle_struct *handle,
					DIR *dirp,
					SMB_STRUCT_STAT *sbuf);
void smb_vfs_call_seekdir(struct vfs_handle_struct *handle,
			  DIR *dirp, long offset);
long smb_vfs_call_telldir(struct vfs_handle_struct *handle,
			  DIR *dirp);
void smb_vfs_call_rewind_dir(struct vfs_handle_struct *handle,
			     DIR *dirp);
int smb_vfs_call_mkdirat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode);
int smb_vfs_call_closedir(struct vfs_handle_struct *handle,
			  DIR *dir);
int smb_vfs_call_openat(struct vfs_handle_struct *handle,
			const struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			struct files_struct *fsp,
			int flags,
			mode_t mode);
NTSTATUS smb_vfs_call_create_file(struct vfs_handle_struct *handle,
				  struct smb_request *req,
				  struct files_struct **dirfsp,
				  struct smb_filename *smb_fname,
				  uint32_t access_mask,
				  uint32_t share_access,
				  uint32_t create_disposition,
				  uint32_t create_options,
				  uint32_t file_attributes,
				  uint32_t oplock_request,
				  const struct smb2_lease *lease,
				  uint64_t allocation_size,
				  uint32_t private_flags,
				  struct security_descriptor *sd,
				  struct ea_list *ea_list,
				  files_struct **result,
				  int *pinfo,
				  const struct smb2_create_blobs *in_context_blobs,
				  struct smb2_create_blobs *out_context_blobs);
int smb_vfs_call_close(struct vfs_handle_struct *handle,
		       struct files_struct *fsp);
ssize_t smb_vfs_call_pread(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, void *data, size_t n,
			   off_t offset);
struct tevent_req *smb_vfs_call_pread_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   void *data,
					   size_t n, off_t offset);
ssize_t SMB_VFS_PREAD_RECV(struct tevent_req *req, struct vfs_aio_state *state);

ssize_t smb_vfs_call_pwrite(struct vfs_handle_struct *handle,
			    struct files_struct *fsp, const void *data,
			    size_t n, off_t offset);
struct tevent_req *smb_vfs_call_pwrite_send(struct vfs_handle_struct *handle,
					    TALLOC_CTX *mem_ctx,
					    struct tevent_context *ev,
					    struct files_struct *fsp,
					    const void *data,
					    size_t n, off_t offset);
ssize_t SMB_VFS_PWRITE_RECV(struct tevent_req *req, struct vfs_aio_state *state);

off_t smb_vfs_call_lseek(struct vfs_handle_struct *handle,
			     struct files_struct *fsp, off_t offset,
			     int whence);
ssize_t smb_vfs_call_sendfile(struct vfs_handle_struct *handle, int tofd,
			      files_struct *fromfsp, const DATA_BLOB *header,
			      off_t offset, size_t count);
ssize_t smb_vfs_call_recvfile(struct vfs_handle_struct *handle, int fromfd,
			      files_struct *tofsp, off_t offset,
			      size_t count);
int smb_vfs_call_renameat(struct vfs_handle_struct *handle,
			struct files_struct *srcfsp,
			const struct smb_filename *smb_fname_src,
			struct files_struct *dstfsp,
			const struct smb_filename *smb_fname_dst);

struct tevent_req *smb_vfs_call_fsync_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp);
int SMB_VFS_FSYNC_RECV(struct tevent_req *req, struct vfs_aio_state *state);

int smb_vfs_fsync_sync(files_struct *fsp);
int smb_vfs_call_stat(struct vfs_handle_struct *handle,
		      struct smb_filename *smb_fname);
int smb_vfs_call_fstat(struct vfs_handle_struct *handle,
		       struct files_struct *fsp, SMB_STRUCT_STAT *sbuf);
int smb_vfs_call_lstat(struct vfs_handle_struct *handle,
		       struct smb_filename *smb_filename);
uint64_t smb_vfs_call_get_alloc_size(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     const SMB_STRUCT_STAT *sbuf);
int smb_vfs_call_unlinkat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags);
int smb_vfs_call_chmod(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			mode_t mode);
int smb_vfs_call_fchmod(struct vfs_handle_struct *handle,
			struct files_struct *fsp, mode_t mode);
int smb_vfs_call_fchown(struct vfs_handle_struct *handle,
			struct files_struct *fsp, uid_t uid, gid_t gid);
int smb_vfs_call_lchown(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid);
int smb_vfs_call_chdir(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname);
struct smb_filename *smb_vfs_call_getwd(struct vfs_handle_struct *handle,
				TALLOC_CTX *ctx);
int smb_vfs_call_ntimes(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			struct smb_file_time *ft);
int smb_vfs_call_ftruncate(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, off_t offset);
int smb_vfs_call_fallocate(struct vfs_handle_struct *handle,
			   struct files_struct *fsp,
			   uint32_t mode,
			   off_t offset,
			   off_t len);
bool smb_vfs_call_lock(struct vfs_handle_struct *handle,
		       struct files_struct *fsp, int op, off_t offset,
		       off_t count, int type);
int smb_vfs_call_kernel_flock(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, uint32_t share_access,
			      uint32_t access_mask);
int smb_vfs_call_fcntl(struct vfs_handle_struct *handle,
		       struct files_struct *fsp, int cmd, ...);
int smb_vfs_call_linux_setlease(struct vfs_handle_struct *handle,
				struct files_struct *fsp, int leasetype);
bool smb_vfs_call_getlock(struct vfs_handle_struct *handle,
			  struct files_struct *fsp, off_t *poffset,
			  off_t *pcount, int *ptype, pid_t *ppid);
int smb_vfs_call_symlinkat(struct vfs_handle_struct *handle,
			const struct smb_filename *link_contents,
			struct files_struct *dirfsp,
			const struct smb_filename *new_smb_fname);
int smb_vfs_call_readlinkat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz);
int smb_vfs_call_linkat(struct vfs_handle_struct *handle,
			struct files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			struct files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags);
int smb_vfs_call_mknodat(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev);
struct smb_filename *smb_vfs_call_realpath(struct vfs_handle_struct *handle,
			TALLOC_CTX *ctx,
			const struct smb_filename *smb_fname);
int smb_vfs_call_chflags(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			unsigned int flags);
struct file_id smb_vfs_call_file_id_create(struct vfs_handle_struct *handle,
					   const SMB_STRUCT_STAT *sbuf);
uint64_t smb_vfs_call_fs_file_id(struct vfs_handle_struct *handle,
				 const SMB_STRUCT_STAT *sbuf);
NTSTATUS smb_vfs_call_streaminfo(struct vfs_handle_struct *handle,
				 struct files_struct *fsp,
				 const struct smb_filename *smb_fname,
				 TALLOC_CTX *mem_ctx,
				 unsigned int *num_streams,
				 struct stream_struct **streams);
int smb_vfs_call_get_real_filename(struct vfs_handle_struct *handle,
				   const struct smb_filename *path,
				   const char *name,
				   TALLOC_CTX *mem_ctx,
				   char **found_name);
const char *smb_vfs_call_connectpath(struct vfs_handle_struct *handle,
				     const struct smb_filename *smb_fname);
NTSTATUS smb_vfs_call_brl_lock_windows(struct vfs_handle_struct *handle,
				       struct byte_range_lock *br_lck,
				       struct lock_struct *plock);
bool smb_vfs_call_brl_unlock_windows(struct vfs_handle_struct *handle,
				     struct byte_range_lock *br_lck,
				     const struct lock_struct *plock);
bool smb_vfs_call_strict_lock_check(struct vfs_handle_struct *handle,
				    struct files_struct *fsp,
				    struct lock_struct *plock);
NTSTATUS smb_vfs_call_translate_name(struct vfs_handle_struct *handle,
				     const char *name,
				     enum vfs_translate_direction direction,
				     TALLOC_CTX *mem_ctx,
				     char **mapped_name);
NTSTATUS smb_vfs_call_fsctl(struct vfs_handle_struct *handle,
			    struct files_struct *fsp,
			    TALLOC_CTX *ctx,
			    uint32_t function,
			    uint16_t req_flags,
			    const uint8_t *_in_data,
			    uint32_t in_len,
			    uint8_t **_out_data,
			    uint32_t max_out_len,
			    uint32_t *out_len);
NTSTATUS smb_vfs_call_get_dos_attributes(struct vfs_handle_struct *handle,
					 struct smb_filename *smb_fname,
					 uint32_t *dosmode);
NTSTATUS smb_vfs_call_fget_dos_attributes(struct vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  uint32_t *dosmode);
NTSTATUS smb_vfs_call_set_dos_attributes(struct vfs_handle_struct *handle,
					 const struct smb_filename *smb_fname,
					 uint32_t dosmode);
NTSTATUS smb_vfs_call_fset_dos_attributes(struct vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  uint32_t dosmode);
struct tevent_req *smb_vfs_call_get_dos_attributes_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			struct smb_filename *smb_fname);
NTSTATUS smb_vfs_call_get_dos_attributes_recv(
			struct tevent_req *req,
			struct vfs_aio_state *aio_state,
			uint32_t *dosmode);
struct tevent_req *smb_vfs_call_offload_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct vfs_handle_struct *handle,
	struct files_struct *fsp,
	uint32_t fsctl,
	uint32_t ttl,
	off_t offset,
	size_t to_copy);
NTSTATUS smb_vfs_call_offload_read_recv(struct tevent_req *req,
					struct vfs_handle_struct *handle,
					TALLOC_CTX *mem_ctx,
					DATA_BLOB *token_blob);
struct tevent_req *smb_vfs_call_offload_write_send(struct vfs_handle_struct *handle,
						   TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   uint32_t fsctl,
						   DATA_BLOB *token,
						   off_t transfer_offset,
						   struct files_struct *dest_fsp,
						   off_t dest_off,
						   off_t num);
NTSTATUS smb_vfs_call_offload_write_recv(struct vfs_handle_struct *handle,
					 struct tevent_req *req,
					 off_t *copied);
NTSTATUS smb_vfs_call_get_compression(struct vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      struct files_struct *fsp,
				      struct smb_filename *smb_fname,
				      uint16_t *_compression_fmt);
NTSTATUS smb_vfs_call_set_compression(struct vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      struct files_struct *fsp,
				      uint16_t compression_fmt);
NTSTATUS smb_vfs_call_snap_check_path(vfs_handle_struct *handle,
				      TALLOC_CTX *mem_ctx,
				      const char *service_path,
				      char **base_volume);
NTSTATUS smb_vfs_call_snap_create(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  const char *base_volume,
				  time_t *tstamp,
				  bool rw,
				  char **base_path,
				  char **snap_path);
NTSTATUS smb_vfs_call_snap_delete(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  char *base_path,
				  char *snap_path);
NTSTATUS smb_vfs_call_fget_nt_acl(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  uint32_t security_info,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor **ppdesc);
NTSTATUS smb_vfs_call_get_nt_acl_at(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc);
NTSTATUS smb_vfs_call_fset_nt_acl(struct vfs_handle_struct *handle,
				  struct files_struct *fsp,
				  uint32_t security_info_sent,
				  const struct security_descriptor *psd);
NTSTATUS smb_vfs_call_audit_file(struct vfs_handle_struct *handle,
				 struct smb_filename *file,
				 struct security_acl *sacl,
				 uint32_t access_requested,
				 uint32_t access_denied);
int smb_vfs_call_chmod_acl(struct vfs_handle_struct *handle,
				const struct smb_filename *file,
				mode_t mode);
SMB_ACL_T smb_vfs_call_sys_acl_get_file(struct vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					SMB_ACL_TYPE_T type,
					TALLOC_CTX *mem_ctx);
SMB_ACL_T smb_vfs_call_sys_acl_get_fd(struct vfs_handle_struct *handle,
				      struct files_struct *fsp,
				      TALLOC_CTX *mem_ctx);
int smb_vfs_call_sys_acl_blob_get_file(struct vfs_handle_struct *handle,
				       const struct smb_filename *smb_fname,
				       TALLOC_CTX *mem_ctx,
				       char **blob_description,
				       DATA_BLOB *blob);
int smb_vfs_call_sys_acl_blob_get_fd(struct vfs_handle_struct *handle,
				     struct files_struct *fsp, 	
				     TALLOC_CTX *mem_ctx,
				     char **blob_description,
				     DATA_BLOB *blob);
int smb_vfs_call_sys_acl_set_file(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl);
int smb_vfs_call_sys_acl_set_fd(struct vfs_handle_struct *handle,
				struct files_struct *fsp, SMB_ACL_T theacl);
int smb_vfs_call_sys_acl_delete_def_file(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname);
ssize_t smb_vfs_call_getxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size);
struct tevent_req *smb_vfs_call_getxattrat_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			const struct smb_filename *smb_fname,
			const char *xattr_name,
			size_t alloc_hint);
ssize_t smb_vfs_call_getxattrat_recv(struct tevent_req *req,
				     struct vfs_aio_state *aio_state,
				     TALLOC_CTX *mem_ctx,
				     uint8_t **xattr_value);
ssize_t smb_vfs_call_fgetxattr(struct vfs_handle_struct *handle,
			       struct files_struct *fsp, const char *name,
			       void *value, size_t size);
ssize_t smb_vfs_call_listxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *list,
				size_t size);
ssize_t smb_vfs_call_flistxattr(struct vfs_handle_struct *handle,
				struct files_struct *fsp, char *list,
				size_t size);
int smb_vfs_call_removexattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name);
int smb_vfs_call_fremovexattr(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name);
int smb_vfs_call_setxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				const void *value,
				size_t size,
				int flags);
int smb_vfs_call_lsetxattr(struct vfs_handle_struct *handle, const char *path,
			   const char *name, const void *value, size_t size,
			   int flags);
int smb_vfs_call_fsetxattr(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, const char *name,
			   const void *value, size_t size, int flags);
bool smb_vfs_call_aio_force(struct vfs_handle_struct *handle,
			    struct files_struct *fsp);
NTSTATUS smb_vfs_call_durable_cookie(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     TALLOC_CTX *mem_ctx,
				     DATA_BLOB *cookie);
NTSTATUS smb_vfs_call_durable_disconnect(struct vfs_handle_struct *handle,
					 struct files_struct *fsp,
					 const DATA_BLOB old_cookie,
					 TALLOC_CTX *mem_ctx,
					 DATA_BLOB *new_cookie);
NTSTATUS smb_vfs_call_durable_reconnect(struct vfs_handle_struct *handle,
					struct smb_request *smb1req,
					struct smbXsrv_open *op,
					const DATA_BLOB old_cookie,
					TALLOC_CTX *mem_ctx,
					struct files_struct **fsp,
					DATA_BLOB *new_cookie);
NTSTATUS smb_vfs_call_readdir_attr(struct vfs_handle_struct *handle,
				   const struct smb_filename *fname,
				   TALLOC_CTX *mem_ctx,
				   struct readdir_attr_data **attr_data);

NTSTATUS smb_register_vfs(int version, const char *name,
			  const struct vfs_fn_pointers *fns);
void *vfs_add_fsp_extension_notype(vfs_handle_struct *handle,
				   files_struct *fsp, size_t ext_size,
				   void (*destroy_fn)(void *p_data));
void vfs_remove_fsp_extension(vfs_handle_struct *handle, files_struct *fsp);
void vfs_remove_all_fsp_extensions(struct files_struct *fsp);
void *vfs_memctx_fsp_extension(vfs_handle_struct *handle, files_struct *fsp);
void *vfs_fetch_fsp_extension(vfs_handle_struct *handle, files_struct *fsp);

void smb_vfs_assert_all_fns(const struct vfs_fn_pointers* fns,
			    const char *module);

/*
 * Helper functions from source3/modules/vfs_not_implemented.c
 */
int vfs_not_implemented_connect(
			vfs_handle_struct *handle,
			const char *service,
			const char *user);
void vfs_not_implemented_disconnect(vfs_handle_struct *handle);
uint64_t vfs_not_implemented_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize);
int vfs_not_implemented_get_quota(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *dq);
int vfs_not_implemented_set_quota(vfs_handle_struct *handle,
				  enum SMB_QUOTA_TYPE qtype,
				  unid_t id, SMB_DISK_QUOTA *dq);
int vfs_not_implemented_get_shadow_copy_data(vfs_handle_struct *handle,
				files_struct *fsp,
				struct shadow_copy_data *shadow_copy_data,
				bool labels);
int vfs_not_implemented_statvfs(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				struct vfs_statvfs_struct *statbuf);
uint32_t vfs_not_implemented_fs_capabilities(struct vfs_handle_struct *handle,
				enum timestamp_set_resolution *p_ts_res);
NTSTATUS vfs_not_implemented_get_dfs_referrals(struct vfs_handle_struct *handle,
					       struct dfs_GetDFSReferral *r);
NTSTATUS vfs_not_implemented_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count);
NTSTATUS vfs_not_implemented_read_dfs_pathat(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct files_struct *dirfsp,
				struct smb_filename *smb_fname,
				struct referral **ppreflist,
				size_t *preferral_count);
NTSTATUS vfs_not_implemented_snap_check_path(struct vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				const char *service_path,
				char **base_volume);
NTSTATUS vfs_not_implemented_snap_create(struct vfs_handle_struct *handle,
					 TALLOC_CTX *mem_ctx,
					 const char *base_volume,
					 time_t *tstamp,
					 bool rw,
					 char **base_path,
					 char **snap_path);
NTSTATUS vfs_not_implemented_snap_delete(struct vfs_handle_struct *handle,
					 TALLOC_CTX *mem_ctx,
					 char *base_path,
					 char *snap_path);
DIR *vfs_not_implemented_fdopendir(vfs_handle_struct *handle, files_struct *fsp,
				   const char *mask, uint32_t attr);
struct dirent *vfs_not_implemented_readdir(vfs_handle_struct *handle,
					   DIR *dirp, SMB_STRUCT_STAT *sbuf);
void vfs_not_implemented_seekdir(vfs_handle_struct *handle, DIR *dirp, long offset);
long vfs_not_implemented_telldir(vfs_handle_struct *handle, DIR *dirp);
void vfs_not_implemented_rewind_dir(vfs_handle_struct *handle, DIR *dirp);
int vfs_not_implemented_mkdirat(vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname,
		mode_t mode);
int vfs_not_implemented_closedir(vfs_handle_struct *handle, DIR *dir);
int vfs_not_implemented_open(vfs_handle_struct *handle,
			     struct smb_filename *smb_fname,
			     files_struct *fsp, int flags, mode_t mode);
int vfs_not_implemented_openat(vfs_handle_struct *handle,
			       const struct files_struct *dirfsp,
			       const struct smb_filename *smb_fname,
			       struct files_struct *fsp,
			       int flags,
			       mode_t mode);
NTSTATUS vfs_not_implemented_create_file(struct vfs_handle_struct *handle,
				struct smb_request *req,
				struct files_struct **dirfsp,
				struct smb_filename *smb_fname,
				uint32_t access_mask,
				uint32_t share_access,
				uint32_t create_disposition,
				uint32_t create_options,
				uint32_t file_attributes,
				uint32_t oplock_request,
				const struct smb2_lease *lease,
				uint64_t allocation_size,
				uint32_t private_flags,
				struct security_descriptor *sd,
				struct ea_list *ea_list,
				files_struct **result, int *pinfo,
				const struct smb2_create_blobs *in_context_blobs,
				struct smb2_create_blobs *out_context_blobs);
int vfs_not_implemented_close_fn(vfs_handle_struct *handle, files_struct *fsp);
ssize_t vfs_not_implemented_pread(vfs_handle_struct *handle, files_struct *fsp,
				  void *data, size_t n, off_t offset);
struct tevent_req *vfs_not_implemented_pread_send(struct vfs_handle_struct *handle,
						  TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct files_struct *fsp,
						  void *data, size_t n, off_t offset);
ssize_t vfs_not_implemented_pread_recv(struct tevent_req *req,
				       struct vfs_aio_state *vfs_aio_state);
ssize_t vfs_not_implemented_pwrite(vfs_handle_struct *handle, files_struct *fsp,
				   const void *data, size_t n, off_t offset);
struct tevent_req *vfs_not_implemented_pwrite_send(struct vfs_handle_struct *handle,
						   TALLOC_CTX *mem_ctx,
						   struct tevent_context *ev,
						   struct files_struct *fsp,
						   const void *data,
						   size_t n, off_t offset);
ssize_t vfs_not_implemented_pwrite_recv(struct tevent_req *req,
				struct vfs_aio_state *vfs_aio_state);
off_t vfs_not_implemented_lseek(vfs_handle_struct *handle, files_struct *fsp,
			off_t offset, int whence);
ssize_t vfs_not_implemented_sendfile(vfs_handle_struct *handle, int tofd,
				     files_struct *fromfsp, const DATA_BLOB *hdr,
				     off_t offset, size_t n);
ssize_t vfs_not_implemented_recvfile(vfs_handle_struct *handle, int fromfd,
				     files_struct *tofsp, off_t offset, size_t n);
int vfs_not_implemented_renameat(vfs_handle_struct *handle,
			       files_struct *srcfsp,
			       const struct smb_filename *smb_fname_src,
			       files_struct *dstfsp,
			       const struct smb_filename *smb_fname_dst);
struct tevent_req *vfs_not_implemented_fsync_send(struct vfs_handle_struct *handle,
						  TALLOC_CTX *mem_ctx,
						  struct tevent_context *ev,
						  struct files_struct *fsp);
int vfs_not_implemented_fsync_recv(struct tevent_req *req,
				   struct vfs_aio_state *vfs_aio_state);
int vfs_not_implemented_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname);
int vfs_not_implemented_fstat(vfs_handle_struct *handle, files_struct *fsp,
			SMB_STRUCT_STAT *sbuf);
int vfs_not_implemented_lstat(vfs_handle_struct *handle,
			      struct smb_filename *smb_fname);
uint64_t vfs_not_implemented_get_alloc_size(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    const SMB_STRUCT_STAT *sbuf);
int vfs_not_implemented_unlinkat(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				int flags);
int vfs_not_implemented_chmod(vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname,
			      mode_t mode);
int vfs_not_implemented_fchmod(vfs_handle_struct *handle, files_struct *fsp,
			       mode_t mode);
int vfs_not_implemented_fchown(vfs_handle_struct *handle, files_struct *fsp,
			       uid_t uid, gid_t gid);
int vfs_not_implemented_lchown(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname,
			       uid_t uid,
			       gid_t gid);
int vfs_not_implemented_chdir(vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname);
struct smb_filename *vfs_not_implemented_getwd(vfs_handle_struct *handle,
					       TALLOC_CTX *ctx);
int vfs_not_implemented_ntimes(vfs_handle_struct *handle,
			       const struct smb_filename *smb_fname,
			       struct smb_file_time *ft);
int vfs_not_implemented_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
				  off_t offset);
int vfs_not_implemented_fallocate(vfs_handle_struct *handle, files_struct *fsp,
				  uint32_t mode, off_t offset, off_t len);
bool vfs_not_implemented_lock(vfs_handle_struct *handle, files_struct *fsp, int op,
			      off_t offset, off_t count, int type);
int vfs_not_implemented_kernel_flock(struct vfs_handle_struct *handle,
				     struct files_struct *fsp,
				     uint32_t share_access, uint32_t access_mask);
int vfs_not_implemented_fcntl(struct vfs_handle_struct *handle,
			      struct files_struct *fsp, int cmd, va_list cmd_arg);
int vfs_not_implemented_linux_setlease(struct vfs_handle_struct *handle,
				       struct files_struct *fsp, int leasetype);
bool vfs_not_implemented_getlock(vfs_handle_struct *handle, files_struct *fsp,
				 off_t *poffset, off_t *pcount, int *ptype,
				 pid_t *ppid);
int vfs_not_implemented_symlinkat(vfs_handle_struct *handle,
				const struct smb_filename *link_contents,
				struct files_struct *dirfsp,
				const struct smb_filename *new_smb_fname);
int vfs_not_implemented_vfs_readlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz);
int vfs_not_implemented_linkat(vfs_handle_struct *handle,
			struct files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			struct files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags);
int vfs_not_implemented_mknodat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev);
struct smb_filename *vfs_not_implemented_realpath(vfs_handle_struct *handle,
						  TALLOC_CTX *ctx,
						  const struct smb_filename *smb_fname);
int vfs_not_implemented_chflags(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint flags);
struct file_id vfs_not_implemented_file_id_create(vfs_handle_struct *handle,
						  const SMB_STRUCT_STAT *sbuf);
uint64_t vfs_not_implemented_fs_file_id(vfs_handle_struct *handle,
					const SMB_STRUCT_STAT *sbuf);
struct tevent_req *vfs_not_implemented_offload_read_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			struct files_struct *fsp,
			uint32_t fsctl,
			uint32_t ttl,
			off_t offset,
			size_t to_copy);
NTSTATUS vfs_not_implemented_offload_read_recv(struct tevent_req *req,
				       struct vfs_handle_struct *handle,
				       TALLOC_CTX *mem_ctx,
				       DATA_BLOB *_token_blob);
struct tevent_req *vfs_not_implemented_offload_write_send(
			struct vfs_handle_struct *handle,
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			uint32_t fsctl,
			DATA_BLOB *token,
			off_t transfer_offset,
			struct files_struct *dest_fsp,
			off_t dest_off,
			off_t num);
NTSTATUS vfs_not_implemented_offload_write_recv(struct vfs_handle_struct *handle,
						struct tevent_req *req,
						off_t *copied);
NTSTATUS vfs_not_implemented_get_compression(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct files_struct *fsp,
					     struct smb_filename *smb_fname,
					     uint16_t *_compression_fmt);
NTSTATUS vfs_not_implemented_set_compression(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     struct files_struct *fsp,
					     uint16_t compression_fmt);
NTSTATUS vfs_not_implemented_streaminfo(struct vfs_handle_struct *handle,
					struct files_struct *fsp,
					const struct smb_filename *smb_fname,
					TALLOC_CTX *mem_ctx,
					unsigned int *num_streams,
					struct stream_struct **streams);
int vfs_not_implemented_get_real_filename(struct vfs_handle_struct *handle,
					  const struct smb_filename *path,
					  const char *name,
					  TALLOC_CTX *mem_ctx,
					  char **found_name);
const char *vfs_not_implemented_connectpath(struct vfs_handle_struct *handle,
					    const struct smb_filename *smb_fname);
NTSTATUS vfs_not_implemented_brl_lock_windows(struct vfs_handle_struct *handle,
					      struct byte_range_lock *br_lck,
					      struct lock_struct *plock);
bool vfs_not_implemented_brl_unlock_windows(struct vfs_handle_struct *handle,
					    struct byte_range_lock *br_lck,
					    const struct lock_struct *plock);
bool vfs_not_implemented_strict_lock_check(struct vfs_handle_struct *handle,
					   struct files_struct *fsp,
					   struct lock_struct *plock);
NTSTATUS vfs_not_implemented_translate_name(struct vfs_handle_struct *handle,
					    const char *mapped_name,
					    enum vfs_translate_direction direction,
					    TALLOC_CTX *mem_ctx, char **pmapped_name);
NTSTATUS vfs_not_implemented_fsctl(struct vfs_handle_struct *handle,
				   struct files_struct *fsp,
				   TALLOC_CTX *ctx,
				   uint32_t function,
				   uint16_t req_flags,	/* Needed for UNICODE ... */
				   const uint8_t *_in_data,
				   uint32_t in_len,
				   uint8_t **_out_data,
				   uint32_t max_out_len, uint32_t *out_len);
NTSTATUS vfs_not_implemented_readdir_attr(struct vfs_handle_struct *handle,
					  const struct smb_filename *fname,
					  TALLOC_CTX *mem_ctx,
					  struct readdir_attr_data **pattr_data);
NTSTATUS vfs_not_implemented_get_dos_attributes(struct vfs_handle_struct *handle,
						struct smb_filename *smb_fname,
						uint32_t *dosmode);
struct tevent_req *vfs_not_implemented_get_dos_attributes_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			struct smb_filename *smb_fname);
NTSTATUS vfs_not_implemented_get_dos_attributes_recv(
			struct tevent_req *req,
			struct vfs_aio_state *aio_state,
			uint32_t *dosmode);
NTSTATUS vfs_not_implemented_fget_dos_attributes(struct vfs_handle_struct *handle,
						 struct files_struct *fsp,
						 uint32_t *dosmode);
NTSTATUS vfs_not_implemented_set_dos_attributes(struct vfs_handle_struct *handle,
						const struct smb_filename *smb_fname,
						uint32_t dosmode);
NTSTATUS vfs_not_implemented_fset_dos_attributes(struct vfs_handle_struct *handle,
						 struct files_struct *fsp,
						 uint32_t dosmode);
NTSTATUS vfs_not_implemented_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
					 uint32_t security_info,
					 TALLOC_CTX *mem_ctx,
					 struct security_descriptor **ppdesc);
NTSTATUS vfs_not_implemented_get_nt_acl_at(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			uint32_t security_info,
			TALLOC_CTX *mem_ctx,
			struct security_descriptor **ppdesc);
NTSTATUS vfs_not_implemented_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
					 uint32_t security_info_sent,
					 const struct security_descriptor *psd);
SMB_ACL_T vfs_not_implemented_sys_acl_get_file(vfs_handle_struct *handle,
					       const struct smb_filename *smb_fname,
					       SMB_ACL_TYPE_T type,
					       TALLOC_CTX *mem_ctx);
SMB_ACL_T vfs_not_implemented_sys_acl_get_fd(vfs_handle_struct *handle,
					     files_struct *fsp, TALLOC_CTX *mem_ctx);
int vfs_not_implemented_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob);
int vfs_not_implemented_sys_acl_blob_get_fd(vfs_handle_struct *handle,
				files_struct *fsp, TALLOC_CTX *mem_ctx,
				char **blob_description, DATA_BLOB *blob);
int vfs_not_implemented_sys_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl);
int vfs_not_implemented_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
				       SMB_ACL_T theacl);
int vfs_not_implemented_sys_acl_delete_def_file(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname);
ssize_t vfs_not_implemented_getxattr(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				const char *name,
				void *value,
				size_t size);
struct tevent_req *vfs_not_implemented_getxattrat_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			const struct smb_filename *smb_fname,
			const char *xattr_name,
			size_t alloc_hint);
ssize_t vfs_not_implemented_getxattrat_recv(struct tevent_req *req,
				    struct vfs_aio_state *aio_state,
				    TALLOC_CTX *mem_ctx,
				    uint8_t **xattr_value);
ssize_t vfs_not_implemented_fgetxattr(vfs_handle_struct *handle,
			      struct files_struct *fsp, const char *name,
			      void *value, size_t size);
ssize_t vfs_not_implemented_listxattr(vfs_handle_struct *handle,
				      const struct smb_filename *smb_fname,
				      char *list,
				      size_t size);
ssize_t vfs_not_implemented_flistxattr(vfs_handle_struct *handle,
				       struct files_struct *fsp, char *list,
				       size_t size);
int vfs_not_implemented_removexattr(vfs_handle_struct *handle,
				    const struct smb_filename *smb_fname,
				    const char *name);
int vfs_not_implemented_fremovexattr(vfs_handle_struct *handle,
				     struct files_struct *fsp, const char *name);
int vfs_not_implemented_setxattr(vfs_handle_struct *handle,
				 const struct smb_filename *smb_fname,
				 const char *name,
				 const void *value,
				 size_t size,
				 int flags);
int vfs_not_implemented_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp,
				  const char *name, const void *value, size_t size,
				  int flags);
bool vfs_not_implemented_aio_force(struct vfs_handle_struct *handle,
				   struct files_struct *fsp);
NTSTATUS vfs_not_implemented_audit_file(struct vfs_handle_struct *handle,
					struct smb_filename *file,
					struct security_acl *sacl,
					uint32_t access_requested,
					uint32_t access_denied);
NTSTATUS vfs_not_implemented_durable_cookie(struct vfs_handle_struct *handle,
					    struct files_struct *fsp,
					    TALLOC_CTX *mem_ctx,
					    DATA_BLOB *cookie);
NTSTATUS vfs_not_implemented_durable_disconnect(struct vfs_handle_struct *handle,
						struct files_struct *fsp,
						const DATA_BLOB old_cookie,
						TALLOC_CTX *mem_ctx,
						DATA_BLOB *new_cookie);
NTSTATUS vfs_not_implemented_durable_reconnect(struct vfs_handle_struct *handle,
					       struct smb_request *smb1req,
					       struct smbXsrv_open *op,
					       const DATA_BLOB old_cookie,
					       TALLOC_CTX *mem_ctx,
					       struct files_struct **fsp,
					       DATA_BLOB *new_cookie);
#endif /* _VFS_H */
