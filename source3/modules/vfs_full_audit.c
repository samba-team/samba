/* 
 * Auditing VFS module for samba.  Log selected file operations to syslog
 * facility.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) John H Terpstra, 2003
 * Copyright (C) Stefan (metze) Metzmacher, 2003
 * Copyright (C) Volker Lendecke, 2004
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This module implements parseable logging for all Samba VFS operations.
 *
 * You use it as follows:
 *
 * [tmp]
 * path = /tmp
 * vfs objects = full_audit
 * full_audit:prefix = %u|%I
 * full_audit:success = open opendir create_file
 * full_audit:failure = all
 *
 * vfs op can be "all" which means log all operations.
 * vfs op can be "none" which means no logging.
 *
 * This leads to syslog entries of the form:
 * smbd_audit: nobody|192.168.234.1|opendir|ok|/tmp
 * smbd_audit: nobody|192.168.234.1|create_file|fail (No such file or directory)|0x1|file|open|/ts/doesNotExist
 * smbd_audit: nobody|192.168.234.1|open|ok|w|/tmp/file.txt
 * smbd_audit: nobody|192.168.234.1|create_file|ok|0x3|file|open|/tmp/file.txt
 *
 * where "nobody" is the connected username and "192.168.234.1" is the
 * client's IP address. 
 *
 * Options:
 *
 * prefix: A macro expansion template prepended to the syslog entry.
 *
 * success: A list of VFS operations for which a successful completion should
 * be logged. Defaults to no logging at all. The special operation "all" logs
 * - you guessed it - everything.
 *
 * failure: A list of VFS operations for which failure to complete should be
 * logged. Defaults to logging everything.
 */


#include "includes.h"
#include "system/filesys.h"
#include "system/syslog.h"
#include "smbd/smbd.h"
#include "../librpc/gen_ndr/ndr_netlogon.h"
#include "auth.h"
#include "ntioctl.h"
#include "lib/param/loadparm.h"
#include "lib/util/bitmap.h"
#include "lib/util/tevent_unix.h"
#include "libcli/security/sddl.h"
#include "passdb/machine_sid.h"
#include "lib/util/tevent_ntstatus.h"

static int vfs_full_audit_debug_level = DBGC_VFS;

struct vfs_full_audit_private_data {
	struct bitmap *success_ops;
	struct bitmap *failure_ops;
	int syslog_facility;
	int syslog_priority;
	bool log_secdesc;
	bool do_syslog;
};

#undef DBGC_CLASS
#define DBGC_CLASS vfs_full_audit_debug_level

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
	SMB_VFS_OP_GET_DFS_REFERRALS,
	SMB_VFS_OP_CREATE_DFS_PATHAT,
	SMB_VFS_OP_READ_DFS_PATHAT,

	/* Directory operations */

	SMB_VFS_OP_FDOPENDIR,
	SMB_VFS_OP_READDIR,
	SMB_VFS_OP_SEEKDIR,
	SMB_VFS_OP_TELLDIR,
	SMB_VFS_OP_REWINDDIR,
	SMB_VFS_OP_MKDIRAT,
	SMB_VFS_OP_CLOSEDIR,

	/* File operations */

	SMB_VFS_OP_OPEN,
	SMB_VFS_OP_OPENAT,
	SMB_VFS_OP_CREATE_FILE,
	SMB_VFS_OP_CLOSE,
	SMB_VFS_OP_READ,
	SMB_VFS_OP_PREAD,
	SMB_VFS_OP_PREAD_SEND,
	SMB_VFS_OP_PREAD_RECV,
	SMB_VFS_OP_WRITE,
	SMB_VFS_OP_PWRITE,
	SMB_VFS_OP_PWRITE_SEND,
	SMB_VFS_OP_PWRITE_RECV,
	SMB_VFS_OP_LSEEK,
	SMB_VFS_OP_SENDFILE,
	SMB_VFS_OP_RECVFILE,
	SMB_VFS_OP_RENAMEAT,
	SMB_VFS_OP_FSYNC,
	SMB_VFS_OP_FSYNC_SEND,
	SMB_VFS_OP_FSYNC_RECV,
	SMB_VFS_OP_STAT,
	SMB_VFS_OP_FSTAT,
	SMB_VFS_OP_LSTAT,
	SMB_VFS_OP_GET_ALLOC_SIZE,
	SMB_VFS_OP_UNLINKAT,
	SMB_VFS_OP_CHMOD,
	SMB_VFS_OP_FCHMOD,
	SMB_VFS_OP_FCHOWN,
	SMB_VFS_OP_LCHOWN,
	SMB_VFS_OP_CHDIR,
	SMB_VFS_OP_GETWD,
	SMB_VFS_OP_NTIMES,
	SMB_VFS_OP_FTRUNCATE,
	SMB_VFS_OP_FALLOCATE,
	SMB_VFS_OP_LOCK,
	SMB_VFS_OP_KERNEL_FLOCK,
	SMB_VFS_OP_FCNTL,
	SMB_VFS_OP_LINUX_SETLEASE,
	SMB_VFS_OP_GETLOCK,
	SMB_VFS_OP_SYMLINKAT,
	SMB_VFS_OP_READLINKAT,
	SMB_VFS_OP_LINKAT,
	SMB_VFS_OP_MKNODAT,
	SMB_VFS_OP_REALPATH,
	SMB_VFS_OP_CHFLAGS,
	SMB_VFS_OP_FILE_ID_CREATE,
	SMB_VFS_OP_FS_FILE_ID,
	SMB_VFS_OP_STREAMINFO,
	SMB_VFS_OP_GET_REAL_FILENAME,
	SMB_VFS_OP_CONNECTPATH,
	SMB_VFS_OP_BRL_LOCK_WINDOWS,
	SMB_VFS_OP_BRL_UNLOCK_WINDOWS,
	SMB_VFS_OP_STRICT_LOCK_CHECK,
	SMB_VFS_OP_TRANSLATE_NAME,
	SMB_VFS_OP_FSCTL,
	SMB_VFS_OP_OFFLOAD_READ_SEND,
	SMB_VFS_OP_OFFLOAD_READ_RECV,
	SMB_VFS_OP_OFFLOAD_WRITE_SEND,
	SMB_VFS_OP_OFFLOAD_WRITE_RECV,
	SMB_VFS_OP_GET_COMPRESSION,
	SMB_VFS_OP_SET_COMPRESSION,
	SMB_VFS_OP_SNAP_CHECK_PATH,
	SMB_VFS_OP_SNAP_CREATE,
	SMB_VFS_OP_SNAP_DELETE,

	/* DOS attribute operations. */
	SMB_VFS_OP_GET_DOS_ATTRIBUTES,
	SMB_VFS_OP_GET_DOS_ATTRIBUTES_SEND,
	SMB_VFS_OP_GET_DOS_ATTRIBUTES_RECV,
	SMB_VFS_OP_FGET_DOS_ATTRIBUTES,
	SMB_VFS_OP_SET_DOS_ATTRIBUTES,
	SMB_VFS_OP_FSET_DOS_ATTRIBUTES,

	/* NT ACL operations. */

	SMB_VFS_OP_FGET_NT_ACL,
	SMB_VFS_OP_GET_NT_ACL_AT,
	SMB_VFS_OP_FSET_NT_ACL,
	SMB_VFS_OP_AUDIT_FILE,

	/* POSIX ACL operations. */

	SMB_VFS_OP_SYS_ACL_GET_FILE,
	SMB_VFS_OP_SYS_ACL_GET_FD,
	SMB_VFS_OP_SYS_ACL_BLOB_GET_FILE,
	SMB_VFS_OP_SYS_ACL_BLOB_GET_FD,
	SMB_VFS_OP_SYS_ACL_SET_FILE,
	SMB_VFS_OP_SYS_ACL_SET_FD,
	SMB_VFS_OP_SYS_ACL_DELETE_DEF_FILE,

	/* EA operations. */
	SMB_VFS_OP_GETXATTR,
	SMB_VFS_OP_GETXATTRAT_SEND,
	SMB_VFS_OP_GETXATTRAT_RECV,
	SMB_VFS_OP_FGETXATTR,
	SMB_VFS_OP_LISTXATTR,
	SMB_VFS_OP_FLISTXATTR,
	SMB_VFS_OP_REMOVEXATTR,
	SMB_VFS_OP_FREMOVEXATTR,
	SMB_VFS_OP_SETXATTR,
	SMB_VFS_OP_FSETXATTR,

	/* aio operations */
        SMB_VFS_OP_AIO_FORCE,

	/* offline operations */
	SMB_VFS_OP_IS_OFFLINE,
	SMB_VFS_OP_SET_OFFLINE,

	/* Durable handle operations. */
	SMB_VFS_OP_DURABLE_COOKIE,
	SMB_VFS_OP_DURABLE_DISCONNECT,
	SMB_VFS_OP_DURABLE_RECONNECT,

	SMB_VFS_OP_READDIR_ATTR,

	/* This should always be last enum value */

	SMB_VFS_OP_LAST
} vfs_op_type;

/* The following array *must* be in the same order as defined in vfs_op_type */

static struct {
	vfs_op_type type;
	const char *name;
} vfs_op_names[] = {
	{ SMB_VFS_OP_CONNECT,	"connect" },
	{ SMB_VFS_OP_DISCONNECT,	"disconnect" },
	{ SMB_VFS_OP_DISK_FREE,	"disk_free" },
	{ SMB_VFS_OP_GET_QUOTA,	"get_quota" },
	{ SMB_VFS_OP_SET_QUOTA,	"set_quota" },
	{ SMB_VFS_OP_GET_SHADOW_COPY_DATA,	"get_shadow_copy_data" },
	{ SMB_VFS_OP_STATVFS,	"statvfs" },
	{ SMB_VFS_OP_FS_CAPABILITIES,	"fs_capabilities" },
	{ SMB_VFS_OP_GET_DFS_REFERRALS,	"get_dfs_referrals" },
	{ SMB_VFS_OP_CREATE_DFS_PATHAT,	"create_dfs_pathat" },
	{ SMB_VFS_OP_READ_DFS_PATHAT,	"read_dfs_pathat" },
	{ SMB_VFS_OP_FDOPENDIR,	"fdopendir" },
	{ SMB_VFS_OP_READDIR,	"readdir" },
	{ SMB_VFS_OP_SEEKDIR,   "seekdir" },
	{ SMB_VFS_OP_TELLDIR,   "telldir" },
	{ SMB_VFS_OP_REWINDDIR, "rewinddir" },
	{ SMB_VFS_OP_MKDIRAT,	"mkdirat" },
	{ SMB_VFS_OP_CLOSEDIR,	"closedir" },
	{ SMB_VFS_OP_OPEN,	"open" },
	{ SMB_VFS_OP_OPENAT,	"openat" },
	{ SMB_VFS_OP_CREATE_FILE, "create_file" },
	{ SMB_VFS_OP_CLOSE,	"close" },
	{ SMB_VFS_OP_READ,	"read" },
	{ SMB_VFS_OP_PREAD,	"pread" },
	{ SMB_VFS_OP_PREAD_SEND,	"pread_send" },
	{ SMB_VFS_OP_PREAD_RECV,	"pread_recv" },
	{ SMB_VFS_OP_WRITE,	"write" },
	{ SMB_VFS_OP_PWRITE,	"pwrite" },
	{ SMB_VFS_OP_PWRITE_SEND,	"pwrite_send" },
	{ SMB_VFS_OP_PWRITE_RECV,	"pwrite_recv" },
	{ SMB_VFS_OP_LSEEK,	"lseek" },
	{ SMB_VFS_OP_SENDFILE,	"sendfile" },
	{ SMB_VFS_OP_RECVFILE,  "recvfile" },
	{ SMB_VFS_OP_RENAMEAT,	"renameat" },
	{ SMB_VFS_OP_FSYNC,	"fsync" },
	{ SMB_VFS_OP_FSYNC_SEND,	"fsync_send" },
	{ SMB_VFS_OP_FSYNC_RECV,	"fsync_recv" },
	{ SMB_VFS_OP_STAT,	"stat" },
	{ SMB_VFS_OP_FSTAT,	"fstat" },
	{ SMB_VFS_OP_LSTAT,	"lstat" },
	{ SMB_VFS_OP_GET_ALLOC_SIZE,	"get_alloc_size" },
	{ SMB_VFS_OP_UNLINKAT,	"unlinkat" },
	{ SMB_VFS_OP_CHMOD,	"chmod" },
	{ SMB_VFS_OP_FCHMOD,	"fchmod" },
	{ SMB_VFS_OP_FCHOWN,	"fchown" },
	{ SMB_VFS_OP_LCHOWN,	"lchown" },
	{ SMB_VFS_OP_CHDIR,	"chdir" },
	{ SMB_VFS_OP_GETWD,	"getwd" },
	{ SMB_VFS_OP_NTIMES,	"ntimes" },
	{ SMB_VFS_OP_FTRUNCATE,	"ftruncate" },
	{ SMB_VFS_OP_FALLOCATE,"fallocate" },
	{ SMB_VFS_OP_LOCK,	"lock" },
	{ SMB_VFS_OP_KERNEL_FLOCK,	"kernel_flock" },
	{ SMB_VFS_OP_FCNTL,	"fcntl" },
	{ SMB_VFS_OP_LINUX_SETLEASE, "linux_setlease" },
	{ SMB_VFS_OP_GETLOCK,	"getlock" },
	{ SMB_VFS_OP_SYMLINKAT,	"symlinkat" },
	{ SMB_VFS_OP_READLINKAT,"readlinkat" },
	{ SMB_VFS_OP_LINKAT,	"linkat" },
	{ SMB_VFS_OP_MKNODAT,	"mknodat" },
	{ SMB_VFS_OP_REALPATH,	"realpath" },
	{ SMB_VFS_OP_CHFLAGS,	"chflags" },
	{ SMB_VFS_OP_FILE_ID_CREATE,	"file_id_create" },
	{ SMB_VFS_OP_FS_FILE_ID,	"fs_file_id" },
	{ SMB_VFS_OP_STREAMINFO,	"streaminfo" },
	{ SMB_VFS_OP_GET_REAL_FILENAME, "get_real_filename" },
	{ SMB_VFS_OP_CONNECTPATH,	"connectpath" },
	{ SMB_VFS_OP_BRL_LOCK_WINDOWS,  "brl_lock_windows" },
	{ SMB_VFS_OP_BRL_UNLOCK_WINDOWS, "brl_unlock_windows" },
	{ SMB_VFS_OP_STRICT_LOCK_CHECK, "strict_lock_check" },
	{ SMB_VFS_OP_TRANSLATE_NAME,	"translate_name" },
	{ SMB_VFS_OP_FSCTL,		"fsctl" },
	{ SMB_VFS_OP_OFFLOAD_READ_SEND,	"offload_read_send" },
	{ SMB_VFS_OP_OFFLOAD_READ_RECV,	"offload_read_recv" },
	{ SMB_VFS_OP_OFFLOAD_WRITE_SEND,	"offload_write_send" },
	{ SMB_VFS_OP_OFFLOAD_WRITE_RECV,	"offload_write_recv" },
	{ SMB_VFS_OP_GET_COMPRESSION,	"get_compression" },
	{ SMB_VFS_OP_SET_COMPRESSION,	"set_compression" },
	{ SMB_VFS_OP_SNAP_CHECK_PATH, "snap_check_path" },
	{ SMB_VFS_OP_SNAP_CREATE, "snap_create" },
	{ SMB_VFS_OP_SNAP_DELETE, "snap_delete" },
	{ SMB_VFS_OP_GET_DOS_ATTRIBUTES, "get_dos_attributes" },
	{ SMB_VFS_OP_GET_DOS_ATTRIBUTES_SEND, "get_dos_attributes_send" },
	{ SMB_VFS_OP_GET_DOS_ATTRIBUTES_RECV, "get_dos_attributes_recv" },
	{ SMB_VFS_OP_FGET_DOS_ATTRIBUTES, "fget_dos_attributes" },
	{ SMB_VFS_OP_SET_DOS_ATTRIBUTES, "set_dos_attributes" },
	{ SMB_VFS_OP_FSET_DOS_ATTRIBUTES, "fset_dos_attributes" },
	{ SMB_VFS_OP_FGET_NT_ACL,	"fget_nt_acl" },
	{ SMB_VFS_OP_GET_NT_ACL_AT,	"get_nt_acl_at" },
	{ SMB_VFS_OP_FSET_NT_ACL,	"fset_nt_acl" },
	{ SMB_VFS_OP_AUDIT_FILE,	"audit_file" },
	{ SMB_VFS_OP_SYS_ACL_GET_FILE,	"sys_acl_get_file" },
	{ SMB_VFS_OP_SYS_ACL_GET_FD,	"sys_acl_get_fd" },
	{ SMB_VFS_OP_SYS_ACL_BLOB_GET_FILE,	"sys_acl_blob_get_file" },
	{ SMB_VFS_OP_SYS_ACL_BLOB_GET_FD,	"sys_acl_blob_get_fd" },
	{ SMB_VFS_OP_SYS_ACL_SET_FILE,	"sys_acl_set_file" },
	{ SMB_VFS_OP_SYS_ACL_SET_FD,	"sys_acl_set_fd" },
	{ SMB_VFS_OP_SYS_ACL_DELETE_DEF_FILE,	"sys_acl_delete_def_file" },
	{ SMB_VFS_OP_GETXATTR,	"getxattr" },
	{ SMB_VFS_OP_GETXATTRAT_SEND, "getxattrat_send" },
	{ SMB_VFS_OP_GETXATTRAT_RECV, "getxattrat_recv" },
	{ SMB_VFS_OP_FGETXATTR,	"fgetxattr" },
	{ SMB_VFS_OP_LISTXATTR,	"listxattr" },
	{ SMB_VFS_OP_FLISTXATTR,	"flistxattr" },
	{ SMB_VFS_OP_REMOVEXATTR,	"removexattr" },
	{ SMB_VFS_OP_FREMOVEXATTR,	"fremovexattr" },
	{ SMB_VFS_OP_SETXATTR,	"setxattr" },
	{ SMB_VFS_OP_FSETXATTR,	"fsetxattr" },
	{ SMB_VFS_OP_AIO_FORCE, "aio_force" },
	{ SMB_VFS_OP_IS_OFFLINE, "is_offline" },
	{ SMB_VFS_OP_SET_OFFLINE, "set_offline" },
	{ SMB_VFS_OP_DURABLE_COOKIE, "durable_cookie" },
	{ SMB_VFS_OP_DURABLE_DISCONNECT, "durable_disconnect" },
	{ SMB_VFS_OP_DURABLE_RECONNECT, "durable_reconnect" },
	{ SMB_VFS_OP_READDIR_ATTR,      "readdir_attr" },
	{ SMB_VFS_OP_LAST, NULL }
};

static int audit_syslog_facility(vfs_handle_struct *handle)
{
	static const struct enum_list enum_log_facilities[] = {
#ifdef LOG_AUTH
		{ LOG_AUTH,		"AUTH" },
#endif
#ifdef LOG_AUTHPRIV
		{ LOG_AUTHPRIV,		"AUTHPRIV" },
#endif
#ifdef LOG_AUDIT
		{ LOG_AUDIT,		"AUDIT" },
#endif
#ifdef LOG_CONSOLE
		{ LOG_CONSOLE,		"CONSOLE" },
#endif
#ifdef LOG_CRON
		{ LOG_CRON,		"CRON" },
#endif
#ifdef LOG_DAEMON
		{ LOG_DAEMON,		"DAEMON" },
#endif
#ifdef LOG_FTP
		{ LOG_FTP,		"FTP" },
#endif
#ifdef LOG_INSTALL
		{ LOG_INSTALL,		"INSTALL" },
#endif
#ifdef LOG_KERN
		{ LOG_KERN,		"KERN" },
#endif
#ifdef LOG_LAUNCHD
		{ LOG_LAUNCHD,		"LAUNCHD" },
#endif
#ifdef LOG_LFMT
		{ LOG_LFMT,		"LFMT" },
#endif
#ifdef LOG_LPR
		{ LOG_LPR,		"LPR" },
#endif
#ifdef LOG_MAIL
		{ LOG_MAIL,		"MAIL" },
#endif
#ifdef LOG_MEGASAFE
		{ LOG_MEGASAFE,		"MEGASAFE" },
#endif
#ifdef LOG_NETINFO
		{ LOG_NETINFO,		"NETINFO" },
#endif
#ifdef LOG_NEWS
		{ LOG_NEWS,		"NEWS" },
#endif
#ifdef LOG_NFACILITIES
		{ LOG_NFACILITIES,	"NFACILITIES" },
#endif
#ifdef LOG_NTP
		{ LOG_NTP,		"NTP" },
#endif
#ifdef LOG_RAS
		{ LOG_RAS,		"RAS" },
#endif
#ifdef LOG_REMOTEAUTH
		{ LOG_REMOTEAUTH,	"REMOTEAUTH" },
#endif
#ifdef LOG_SECURITY
		{ LOG_SECURITY,		"SECURITY" },
#endif
#ifdef LOG_SYSLOG
		{ LOG_SYSLOG,		"SYSLOG" },
#endif
#ifdef LOG_USER
		{ LOG_USER,		"USER" },
#endif
#ifdef LOG_UUCP
		{ LOG_UUCP,		"UUCP" },
#endif
		{ LOG_LOCAL0,		"LOCAL0" },
		{ LOG_LOCAL1,		"LOCAL1" },
		{ LOG_LOCAL2,		"LOCAL2" },
		{ LOG_LOCAL3,		"LOCAL3" },
		{ LOG_LOCAL4,		"LOCAL4" },
		{ LOG_LOCAL5,		"LOCAL5" },
		{ LOG_LOCAL6,		"LOCAL6" },
		{ LOG_LOCAL7,		"LOCAL7" },
		{ -1,			NULL }
	};

	int facility;

	facility = lp_parm_enum(SNUM(handle->conn), "full_audit", "facility", enum_log_facilities, LOG_USER);

	return facility;
}

static int audit_syslog_priority(vfs_handle_struct *handle)
{
	static const struct enum_list enum_log_priorities[] = {
		{ LOG_EMERG, "EMERG" },
		{ LOG_ALERT, "ALERT" },
		{ LOG_CRIT, "CRIT" },
		{ LOG_ERR, "ERR" },
		{ LOG_WARNING, "WARNING" },
		{ LOG_NOTICE, "NOTICE" },
		{ LOG_INFO, "INFO" },
		{ LOG_DEBUG, "DEBUG" },
		{ -1, NULL }
	};

	int priority;

	priority = lp_parm_enum(SNUM(handle->conn), "full_audit", "priority",
				enum_log_priorities, LOG_NOTICE);
	if (priority == -1) {
		priority = LOG_WARNING;
	}

	return priority;
}

static char *audit_prefix(TALLOC_CTX *ctx, connection_struct *conn)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();
	char *prefix = NULL;
	char *result;

	prefix = talloc_strdup(ctx,
			lp_parm_const_string(SNUM(conn), "full_audit",
					     "prefix", "%u|%I"));
	if (!prefix) {
		return NULL;
	}
	result = talloc_sub_full(ctx,
			lp_servicename(talloc_tos(), lp_sub, SNUM(conn)),
			conn->session_info->unix_info->unix_name,
			conn->connectpath,
			conn->session_info->unix_token->gid,
			conn->session_info->unix_info->sanitized_username,
			conn->session_info->info->domain_name,
			prefix);
	TALLOC_FREE(prefix);
	return result;
}

static bool log_success(struct vfs_full_audit_private_data *pd, vfs_op_type op)
{
	if (pd->success_ops == NULL) {
		return True;
	}

	return bitmap_query(pd->success_ops, op);
}

static bool log_failure(struct vfs_full_audit_private_data *pd, vfs_op_type op)
{
	if (pd->failure_ops == NULL)
		return True;

	return bitmap_query(pd->failure_ops, op);
}

static struct bitmap *init_bitmap(TALLOC_CTX *mem_ctx, const char **ops)
{
	struct bitmap *bm;

	if (ops == NULL) {
		return NULL;
	}

	bm = bitmap_talloc(mem_ctx, SMB_VFS_OP_LAST);
	if (bm == NULL) {
		DEBUG(0, ("Could not alloc bitmap -- "
			  "defaulting to logging everything\n"));
		return NULL;
	}

	for (; *ops != NULL; ops += 1) {
		int i;
		bool neg = false;
		const char *op;

		if (strequal(*ops, "all")) {
			for (i=0; i<SMB_VFS_OP_LAST; i++) {
				bitmap_set(bm, i);
			}
			continue;
		}

		if (strequal(*ops, "none")) {
			break;
		}

		op = ops[0];
		if (op[0] == '!') {
			neg = true;
			op += 1;
		}

		for (i=0; i<SMB_VFS_OP_LAST; i++) {
			if ((vfs_op_names[i].name == NULL)
			 || (vfs_op_names[i].type != i)) {
				smb_panic("vfs_full_audit.c: name table not "
					  "in sync with vfs_op_type enums\n");
			}
			if (strequal(op, vfs_op_names[i].name)) {
				if (neg) {
					bitmap_clear(bm, i);
				} else {
					bitmap_set(bm, i);
				}
				break;
			}
		}
		if (i == SMB_VFS_OP_LAST) {
			DEBUG(0, ("Could not find opname %s, logging all\n",
				  *ops));
			TALLOC_FREE(bm);
			return NULL;
		}
	}
	return bm;
}

static const char *audit_opname(vfs_op_type op)
{
	if (op >= SMB_VFS_OP_LAST)
		return "INVALID VFS OP";
	return vfs_op_names[op].name;
}

static TALLOC_CTX *tmp_do_log_ctx;
/*
 * Get us a temporary talloc context usable just for DEBUG arguments
 */
static TALLOC_CTX *do_log_ctx(void)
{
        if (tmp_do_log_ctx == NULL) {
                tmp_do_log_ctx = talloc_named_const(NULL, 0, "do_log_ctx");
        }
        return tmp_do_log_ctx;
}

static void do_log(vfs_op_type op, bool success, vfs_handle_struct *handle,
		   const char *format, ...) PRINTF_ATTRIBUTE(4, 5);

static void do_log(vfs_op_type op, bool success, vfs_handle_struct *handle,
		   const char *format, ...)
{
	struct vfs_full_audit_private_data *pd;
	fstring err_msg;
	char *audit_pre = NULL;
	va_list ap;
	char *op_msg = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, pd,
				struct vfs_full_audit_private_data,
				return;);

	if (success && (!log_success(pd, op)))
		goto out;

	if (!success && (!log_failure(pd, op)))
		goto out;

	if (success)
		fstrcpy(err_msg, "ok");
	else
		fstr_sprintf(err_msg, "fail (%s)", strerror(errno));

	va_start(ap, format);
	op_msg = talloc_vasprintf(talloc_tos(), format, ap);
	va_end(ap);

	if (!op_msg) {
		goto out;
	}

	audit_pre = audit_prefix(talloc_tos(), handle->conn);

	if (pd->do_syslog) {
		int priority;

		/*
		 * Specify the facility to interoperate with other syslog
		 * callers (smbd for example).
		 */
		priority = pd->syslog_priority | pd->syslog_facility;

		syslog(priority, "%s|%s|%s|%s\n",
		       audit_pre ? audit_pre : "",
		       audit_opname(op), err_msg, op_msg);
	} else {
		DEBUG(1, ("%s|%s|%s|%s\n",
			  audit_pre ? audit_pre : "",
			  audit_opname(op), err_msg, op_msg));
	}
 out:
	TALLOC_FREE(audit_pre);
	TALLOC_FREE(op_msg);
	TALLOC_FREE(tmp_do_log_ctx);
}

/**
 * Return a string using the do_log_ctx()
 */
static const char *smb_fname_str_do_log(struct connection_struct *conn,
				const struct smb_filename *smb_fname)
{
	char *fname = NULL;
	NTSTATUS status;

	if (smb_fname == NULL) {
		return "";
	}

	if (smb_fname->base_name[0] != '/') {
		char *abs_name = NULL;
		struct smb_filename *fname_copy = cp_smb_filename(
							do_log_ctx(),
							smb_fname);
		if (fname_copy == NULL) {
			return "";
		}

		if (!ISDOT(smb_fname->base_name)) {
			abs_name = talloc_asprintf(do_log_ctx(),
					"%s/%s",
					conn->cwd_fsp->fsp_name->base_name,
					smb_fname->base_name);
		} else {
			abs_name = talloc_strdup(do_log_ctx(),
					conn->cwd_fsp->fsp_name->base_name);
		}
		if (abs_name == NULL) {
			return "";
		}
		fname_copy->base_name = abs_name;
		smb_fname = fname_copy;
	}

	status = get_full_smb_filename(do_log_ctx(), smb_fname, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		return "";
	}
	return fname;
}

/**
 * Return an fsp debug string using the do_log_ctx()
 */
static const char *fsp_str_do_log(const struct files_struct *fsp)
{
	return smb_fname_str_do_log(fsp->conn, fsp->fsp_name);
}

/* Implementation of vfs_ops.  Pass everything on to the default
   operation but log event first. */

static int smb_full_audit_connect(vfs_handle_struct *handle,
			 const char *svc, const char *user)
{
	int result;
	const char *none[] = { "none" };
	struct vfs_full_audit_private_data *pd = NULL;

	result = SMB_VFS_NEXT_CONNECT(handle, svc, user);
	if (result < 0) {
		return result;
	}

	pd = talloc_zero(handle, struct vfs_full_audit_private_data);
	if (!pd) {
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	pd->syslog_facility = audit_syslog_facility(handle);
	if (pd->syslog_facility == -1) {
		DEBUG(1, ("%s: Unknown facility %s\n", __func__,
			  lp_parm_const_string(SNUM(handle->conn),
					       "full_audit", "facility",
					       "USER")));
		SMB_VFS_NEXT_DISCONNECT(handle);
		return -1;
	}

	pd->syslog_priority = audit_syslog_priority(handle);

	pd->log_secdesc = lp_parm_bool(SNUM(handle->conn),
				       "full_audit", "log_secdesc", false);

	pd->do_syslog = lp_parm_bool(SNUM(handle->conn),
				     "full_audit", "syslog", true);

#ifdef WITH_SYSLOG
	if (pd->do_syslog) {
		openlog("smbd_audit", 0, pd->syslog_facility);
	}
#endif

	pd->success_ops = init_bitmap(
		pd, lp_parm_string_list(SNUM(handle->conn), "full_audit",
					"success", none));
	pd->failure_ops = init_bitmap(
		pd, lp_parm_string_list(SNUM(handle->conn), "full_audit",
					"failure", none));

	/* Store the private data. */
	SMB_VFS_HANDLE_SET_DATA(handle, pd, NULL,
				struct vfs_full_audit_private_data, return -1);

	do_log(SMB_VFS_OP_CONNECT, True, handle,
	       "%s", svc);

	return 0;
}

static void smb_full_audit_disconnect(vfs_handle_struct *handle)
{
	const struct loadparm_substitution *lp_sub =
		loadparm_s3_global_substitution();

	SMB_VFS_NEXT_DISCONNECT(handle);

	do_log(SMB_VFS_OP_DISCONNECT, True, handle,
	       "%s", lp_servicename(talloc_tos(), lp_sub, SNUM(handle->conn)));

	/* The bitmaps will be disconnected when the private
	   data is deleted. */
}

static uint64_t smb_full_audit_disk_free(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint64_t *bsize,
				uint64_t *dfree,
				uint64_t *dsize)
{
	uint64_t result;

	result = SMB_VFS_NEXT_DISK_FREE(handle, smb_fname, bsize, dfree, dsize);

	/* Don't have a reasonable notion of failure here */

	do_log(SMB_VFS_OP_DISK_FREE,
	       True,
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static int smb_full_audit_get_quota(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				enum SMB_QUOTA_TYPE qtype,
				unid_t id,
				SMB_DISK_QUOTA *qt)
{
	int result;

	result = SMB_VFS_NEXT_GET_QUOTA(handle, smb_fname, qtype, id, qt);

	do_log(SMB_VFS_OP_GET_QUOTA,
	       (result >= 0),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static int smb_full_audit_set_quota(struct vfs_handle_struct *handle,
			   enum SMB_QUOTA_TYPE qtype, unid_t id,
			   SMB_DISK_QUOTA *qt)
{
	int result;

	result = SMB_VFS_NEXT_SET_QUOTA(handle, qtype, id, qt);

	do_log(SMB_VFS_OP_SET_QUOTA, (result >= 0), handle, "");

	return result;
}

static int smb_full_audit_get_shadow_copy_data(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				struct shadow_copy_data *shadow_copy_data,
				bool labels)
{
	int result;

	result = SMB_VFS_NEXT_GET_SHADOW_COPY_DATA(handle, fsp, shadow_copy_data, labels);

	do_log(SMB_VFS_OP_GET_SHADOW_COPY_DATA, (result >= 0), handle, "");

	return result;
}

static int smb_full_audit_statvfs(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				struct vfs_statvfs_struct *statbuf)
{
	int result;

	result = SMB_VFS_NEXT_STATVFS(handle, smb_fname, statbuf);

	do_log(SMB_VFS_OP_STATVFS, (result >= 0), handle, "");

	return result;
}

static uint32_t smb_full_audit_fs_capabilities(struct vfs_handle_struct *handle, enum timestamp_set_resolution *p_ts_res)
{
	int result;

	result = SMB_VFS_NEXT_FS_CAPABILITIES(handle, p_ts_res);

	do_log(SMB_VFS_OP_FS_CAPABILITIES, true, handle, "");

	return result;
}

static NTSTATUS smb_full_audit_get_dfs_referrals(
				struct vfs_handle_struct *handle,
				struct dfs_GetDFSReferral *r)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_GET_DFS_REFERRALS(handle, r);

	do_log(SMB_VFS_OP_GET_DFS_REFERRALS, NT_STATUS_IS_OK(status),
	       handle, "");

	return status;
}

static NTSTATUS smb_full_audit_create_dfs_pathat(struct vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const struct referral *reflist,
				size_t referral_count)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_CREATE_DFS_PATHAT(handle,
			dirfsp,
			smb_fname,
			reflist,
			referral_count);

	do_log(SMB_VFS_OP_CREATE_DFS_PATHAT,
		NT_STATUS_IS_OK(status),
		handle,
		"%s",
		smb_fname_str_do_log(handle->conn, smb_fname));

	return status;
}

static NTSTATUS smb_full_audit_read_dfs_pathat(struct vfs_handle_struct *handle,
			TALLOC_CTX *mem_ctx,
			struct files_struct *dirfsp,
			struct smb_filename *smb_fname,
			struct referral **ppreflist,
			size_t *preferral_count)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_READ_DFS_PATHAT(handle,
			mem_ctx,
			dirfsp,
			smb_fname,
			ppreflist,
			preferral_count);

	do_log(SMB_VFS_OP_READ_DFS_PATHAT,
		NT_STATUS_IS_OK(status),
		handle,
		"%s",
		smb_fname_str_do_log(handle->conn, smb_fname));

	return status;
}

static NTSTATUS smb_full_audit_snap_check_path(struct vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       const char *service_path,
					       char **base_volume)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_SNAP_CHECK_PATH(handle, mem_ctx, service_path,
					      base_volume);
	do_log(SMB_VFS_OP_SNAP_CHECK_PATH, NT_STATUS_IS_OK(status),
	       handle, "");

	return status;
}

static NTSTATUS smb_full_audit_snap_create(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   const char *base_volume,
					   time_t *tstamp,
					   bool rw,
					   char **base_path,
					   char **snap_path)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_SNAP_CREATE(handle, mem_ctx, base_volume, tstamp,
					  rw, base_path, snap_path);
	do_log(SMB_VFS_OP_SNAP_CREATE, NT_STATUS_IS_OK(status), handle, "");

	return status;
}

static NTSTATUS smb_full_audit_snap_delete(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   char *base_path,
					   char *snap_path)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_SNAP_DELETE(handle, mem_ctx, base_path,
					  snap_path);
	do_log(SMB_VFS_OP_SNAP_DELETE, NT_STATUS_IS_OK(status), handle, "");

	return status;
}

static DIR *smb_full_audit_fdopendir(vfs_handle_struct *handle,
			  files_struct *fsp, const char *mask, uint32_t attr)
{
	DIR *result;

	result = SMB_VFS_NEXT_FDOPENDIR(handle, fsp, mask, attr);

	do_log(SMB_VFS_OP_FDOPENDIR, (result != NULL), handle, "%s",
			fsp_str_do_log(fsp));

	return result;
}

static struct dirent *smb_full_audit_readdir(vfs_handle_struct *handle,
				    DIR *dirp, SMB_STRUCT_STAT *sbuf)
{
	struct dirent *result;

	result = SMB_VFS_NEXT_READDIR(handle, dirp, sbuf);

	/* This operation has no reasonable error condition
	 * (End of dir is also failure), so always succeed.
	 */
	do_log(SMB_VFS_OP_READDIR, True, handle, "");

	return result;
}

static void smb_full_audit_seekdir(vfs_handle_struct *handle,
			DIR *dirp, long offset)
{
	SMB_VFS_NEXT_SEEKDIR(handle, dirp, offset);

	do_log(SMB_VFS_OP_SEEKDIR, True, handle, "");
}

static long smb_full_audit_telldir(vfs_handle_struct *handle,
			DIR *dirp)
{
	long result;

	result = SMB_VFS_NEXT_TELLDIR(handle, dirp);

	do_log(SMB_VFS_OP_TELLDIR, True, handle, "");

	return result;
}

static void smb_full_audit_rewinddir(vfs_handle_struct *handle,
			DIR *dirp)
{
	SMB_VFS_NEXT_REWINDDIR(handle, dirp);

	do_log(SMB_VFS_OP_REWINDDIR, True, handle, "");
}

static int smb_full_audit_mkdirat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	int result;

	result = SMB_VFS_NEXT_MKDIRAT(handle,
			dirfsp,
			smb_fname,
			mode);

	do_log(SMB_VFS_OP_MKDIRAT,
	       (result >= 0),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static int smb_full_audit_closedir(vfs_handle_struct *handle,
			  DIR *dirp)
{
	int result;

	result = SMB_VFS_NEXT_CLOSEDIR(handle, dirp);
	
	do_log(SMB_VFS_OP_CLOSEDIR, (result >= 0), handle, "");

	return result;
}

static int smb_full_audit_openat(vfs_handle_struct *handle,
				 const struct files_struct *dirfsp,
				 const struct smb_filename *smb_fname,
				 struct files_struct *fsp,
				 int flags,
				 mode_t mode)
{
	int result;

	result = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, flags, mode);

	do_log(SMB_VFS_OP_OPENAT, (result >= 0), handle, "%s|%s",
	       ((flags & O_WRONLY) || (flags & O_RDWR))?"w":"r",
	       fsp_str_do_log(fsp));

	return result;
}

static NTSTATUS smb_full_audit_create_file(vfs_handle_struct *handle,
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
				      files_struct **result_fsp,
				      int *pinfo,
				      const struct smb2_create_blobs *in_context_blobs,
				      struct smb2_create_blobs *out_context_blobs)
{
	NTSTATUS result;
	const char* str_create_disposition;

	switch (create_disposition) {
	case FILE_SUPERSEDE:
		str_create_disposition = "supersede";
		break;
	case FILE_OVERWRITE_IF:
		str_create_disposition = "overwrite_if";
		break;
	case FILE_OPEN:
		str_create_disposition = "open";
		break;
	case FILE_OVERWRITE:
		str_create_disposition = "overwrite";
		break;
	case FILE_CREATE:
		str_create_disposition = "create";
		break;
	case FILE_OPEN_IF:
		str_create_disposition = "open_if";
		break;
	default:
		str_create_disposition = "unknown";
	}

	result = SMB_VFS_NEXT_CREATE_FILE(
		handle,					/* handle */
		req,					/* req */
		dirfsp,
		smb_fname,				/* fname */
		access_mask,				/* access_mask */
		share_access,				/* share_access */
		create_disposition,			/* create_disposition*/
		create_options,				/* create_options */
		file_attributes,			/* file_attributes */
		oplock_request,				/* oplock_request */
		lease,					/* lease */
		allocation_size,			/* allocation_size */
		private_flags,
		sd,					/* sd */
		ea_list,				/* ea_list */
		result_fsp,				/* result */
		pinfo,					/* pinfo */
		in_context_blobs, out_context_blobs);	/* create context */

	do_log(SMB_VFS_OP_CREATE_FILE, (NT_STATUS_IS_OK(result)), handle,
	       "0x%x|%s|%s|%s", access_mask,
	       create_options & FILE_DIRECTORY_FILE ? "dir" : "file",
	       str_create_disposition,
		smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static int smb_full_audit_close(vfs_handle_struct *handle, files_struct *fsp)
{
	int result;
	
	result = SMB_VFS_NEXT_CLOSE(handle, fsp);

	do_log(SMB_VFS_OP_CLOSE, (result >= 0), handle, "%s",
	       fsp_str_do_log(fsp));

	return result;
}

static ssize_t smb_full_audit_pread(vfs_handle_struct *handle, files_struct *fsp,
			   void *data, size_t n, off_t offset)
{
	ssize_t result;

	result = SMB_VFS_NEXT_PREAD(handle, fsp, data, n, offset);

	do_log(SMB_VFS_OP_PREAD, (result >= 0), handle, "%s",
	       fsp_str_do_log(fsp));

	return result;
}

struct smb_full_audit_pread_state {
	vfs_handle_struct *handle;
	files_struct *fsp;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void smb_full_audit_pread_done(struct tevent_req *subreq);

static struct tevent_req *smb_full_audit_pread_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	void *data, size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct smb_full_audit_pread_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_full_audit_pread_state);
	if (req == NULL) {
		do_log(SMB_VFS_OP_PREAD_SEND, false, handle, "%s",
		       fsp_str_do_log(fsp));
		return NULL;
	}
	state->handle = handle;
	state->fsp = fsp;

	subreq = SMB_VFS_NEXT_PREAD_SEND(state, ev, handle, fsp, data,
					 n, offset);
	if (tevent_req_nomem(subreq, req)) {
		do_log(SMB_VFS_OP_PREAD_SEND, false, handle, "%s",
		       fsp_str_do_log(fsp));
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_full_audit_pread_done, req);

	do_log(SMB_VFS_OP_PREAD_SEND, true, handle, "%s", fsp_str_do_log(fsp));
	return req;
}

static void smb_full_audit_pread_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_full_audit_pread_state *state = tevent_req_data(
		req, struct smb_full_audit_pread_state);

	state->ret = SMB_VFS_PREAD_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t smb_full_audit_pread_recv(struct tevent_req *req,
					 struct vfs_aio_state *vfs_aio_state)
{
	struct smb_full_audit_pread_state *state = tevent_req_data(
		req, struct smb_full_audit_pread_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		do_log(SMB_VFS_OP_PREAD_RECV, false, state->handle, "%s",
		       fsp_str_do_log(state->fsp));
		return -1;
	}

	do_log(SMB_VFS_OP_PREAD_RECV, (state->ret >= 0), state->handle, "%s",
	       fsp_str_do_log(state->fsp));

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static ssize_t smb_full_audit_pwrite(vfs_handle_struct *handle, files_struct *fsp,
			    const void *data, size_t n,
			    off_t offset)
{
	ssize_t result;

	result = SMB_VFS_NEXT_PWRITE(handle, fsp, data, n, offset);

	do_log(SMB_VFS_OP_PWRITE, (result >= 0), handle, "%s",
	       fsp_str_do_log(fsp));

	return result;
}

struct smb_full_audit_pwrite_state {
	vfs_handle_struct *handle;
	files_struct *fsp;
	ssize_t ret;
	struct vfs_aio_state vfs_aio_state;
};

static void smb_full_audit_pwrite_done(struct tevent_req *subreq);

static struct tevent_req *smb_full_audit_pwrite_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp,
	const void *data, size_t n, off_t offset)
{
	struct tevent_req *req, *subreq;
	struct smb_full_audit_pwrite_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_full_audit_pwrite_state);
	if (req == NULL) {
		do_log(SMB_VFS_OP_PWRITE_SEND, false, handle, "%s",
		       fsp_str_do_log(fsp));
		return NULL;
	}
	state->handle = handle;
	state->fsp = fsp;

	subreq = SMB_VFS_NEXT_PWRITE_SEND(state, ev, handle, fsp, data,
					 n, offset);
	if (tevent_req_nomem(subreq, req)) {
		do_log(SMB_VFS_OP_PWRITE_SEND, false, handle, "%s",
		       fsp_str_do_log(fsp));
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_full_audit_pwrite_done, req);

	do_log(SMB_VFS_OP_PWRITE_SEND, true, handle, "%s",
	       fsp_str_do_log(fsp));
	return req;
}

static void smb_full_audit_pwrite_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_full_audit_pwrite_state *state = tevent_req_data(
		req, struct smb_full_audit_pwrite_state);

	state->ret = SMB_VFS_PWRITE_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static ssize_t smb_full_audit_pwrite_recv(struct tevent_req *req,
					  struct vfs_aio_state *vfs_aio_state)
{
	struct smb_full_audit_pwrite_state *state = tevent_req_data(
		req, struct smb_full_audit_pwrite_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		do_log(SMB_VFS_OP_PWRITE_RECV, false, state->handle, "%s",
		       fsp_str_do_log(state->fsp));
		return -1;
	}

	do_log(SMB_VFS_OP_PWRITE_RECV, (state->ret >= 0), state->handle, "%s",
	       fsp_str_do_log(state->fsp));

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static off_t smb_full_audit_lseek(vfs_handle_struct *handle, files_struct *fsp,
			     off_t offset, int whence)
{
	ssize_t result;

	result = SMB_VFS_NEXT_LSEEK(handle, fsp, offset, whence);

	do_log(SMB_VFS_OP_LSEEK, (result != (ssize_t)-1), handle,
	       "%s", fsp_str_do_log(fsp));

	return result;
}

static ssize_t smb_full_audit_sendfile(vfs_handle_struct *handle, int tofd,
			      files_struct *fromfsp,
			      const DATA_BLOB *hdr, off_t offset,
			      size_t n)
{
	ssize_t result;

	result = SMB_VFS_NEXT_SENDFILE(handle, tofd, fromfsp, hdr, offset, n);

	do_log(SMB_VFS_OP_SENDFILE, (result >= 0), handle,
	       "%s", fsp_str_do_log(fromfsp));

	return result;
}

static ssize_t smb_full_audit_recvfile(vfs_handle_struct *handle, int fromfd,
		      files_struct *tofsp,
			      off_t offset,
			      size_t n)
{
	ssize_t result;

	result = SMB_VFS_NEXT_RECVFILE(handle, fromfd, tofsp, offset, n);

	do_log(SMB_VFS_OP_RECVFILE, (result >= 0), handle,
	       "%s", fsp_str_do_log(tofsp));

	return result;
}

static int smb_full_audit_renameat(vfs_handle_struct *handle,
				files_struct *srcfsp,
				const struct smb_filename *smb_fname_src,
				files_struct *dstfsp,
				const struct smb_filename *smb_fname_dst)
{
	int result;

	result = SMB_VFS_NEXT_RENAMEAT(handle,
				srcfsp,
				smb_fname_src,
				dstfsp,
				smb_fname_dst);

	do_log(SMB_VFS_OP_RENAMEAT, (result >= 0), handle, "%s|%s",
	       smb_fname_str_do_log(handle->conn, smb_fname_src),
	       smb_fname_str_do_log(handle->conn, smb_fname_dst));

	return result;
}

struct smb_full_audit_fsync_state {
	vfs_handle_struct *handle;
	files_struct *fsp;
	int ret;
	struct vfs_aio_state vfs_aio_state;
};

static void smb_full_audit_fsync_done(struct tevent_req *subreq);

static struct tevent_req *smb_full_audit_fsync_send(
	struct vfs_handle_struct *handle, TALLOC_CTX *mem_ctx,
	struct tevent_context *ev, struct files_struct *fsp)
{
	struct tevent_req *req, *subreq;
	struct smb_full_audit_fsync_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_full_audit_fsync_state);
	if (req == NULL) {
		do_log(SMB_VFS_OP_FSYNC_SEND, false, handle, "%s",
		       fsp_str_do_log(fsp));
		return NULL;
	}
	state->handle = handle;
	state->fsp = fsp;

	subreq = SMB_VFS_NEXT_FSYNC_SEND(state, ev, handle, fsp);
	if (tevent_req_nomem(subreq, req)) {
		do_log(SMB_VFS_OP_FSYNC_SEND, false, handle, "%s",
		       fsp_str_do_log(fsp));
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_full_audit_fsync_done, req);

	do_log(SMB_VFS_OP_FSYNC_SEND, true, handle, "%s", fsp_str_do_log(fsp));
	return req;
}

static void smb_full_audit_fsync_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_full_audit_fsync_state *state = tevent_req_data(
		req, struct smb_full_audit_fsync_state);

	state->ret = SMB_VFS_FSYNC_RECV(subreq, &state->vfs_aio_state);
	TALLOC_FREE(subreq);
	tevent_req_done(req);
}

static int smb_full_audit_fsync_recv(struct tevent_req *req,
				     struct vfs_aio_state *vfs_aio_state)
{
	struct smb_full_audit_fsync_state *state = tevent_req_data(
		req, struct smb_full_audit_fsync_state);

	if (tevent_req_is_unix_error(req, &vfs_aio_state->error)) {
		do_log(SMB_VFS_OP_FSYNC_RECV, false, state->handle, "%s",
		       fsp_str_do_log(state->fsp));
		return -1;
	}

	do_log(SMB_VFS_OP_FSYNC_RECV, (state->ret >= 0), state->handle, "%s",
	       fsp_str_do_log(state->fsp));

	*vfs_aio_state = state->vfs_aio_state;
	return state->ret;
}

static int smb_full_audit_stat(vfs_handle_struct *handle,
			       struct smb_filename *smb_fname)
{
	int result;
	
	result = SMB_VFS_NEXT_STAT(handle, smb_fname);

	do_log(SMB_VFS_OP_STAT, (result >= 0), handle, "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;    
}

static int smb_full_audit_fstat(vfs_handle_struct *handle, files_struct *fsp,
		       SMB_STRUCT_STAT *sbuf)
{
	int result;
	
	result = SMB_VFS_NEXT_FSTAT(handle, fsp, sbuf);

	do_log(SMB_VFS_OP_FSTAT, (result >= 0), handle, "%s",
	       fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_lstat(vfs_handle_struct *handle,
				struct smb_filename *smb_fname)
{
	int result;
	
	result = SMB_VFS_NEXT_LSTAT(handle, smb_fname);

	do_log(SMB_VFS_OP_LSTAT, (result >= 0), handle, "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;    
}

static uint64_t smb_full_audit_get_alloc_size(vfs_handle_struct *handle,
		       files_struct *fsp, const SMB_STRUCT_STAT *sbuf)
{
	uint64_t result;

	result = SMB_VFS_NEXT_GET_ALLOC_SIZE(handle, fsp, sbuf);

	do_log(SMB_VFS_OP_GET_ALLOC_SIZE, (result != (uint64_t)-1), handle,
			"%llu", (unsigned long long)result);

	return result;
}

static int smb_full_audit_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	int result;

	result = SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp,
			smb_fname,
			flags);

	do_log(SMB_VFS_OP_UNLINKAT, (result >= 0), handle, "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static int smb_full_audit_chmod(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				mode_t mode)
{
	int result;

	result = SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);

	do_log(SMB_VFS_OP_CHMOD,
	       (result >= 0),
	       handle,
	       "%s|%o",
	       smb_fname_str_do_log(handle->conn, smb_fname),
	       mode);

	return result;
}

static int smb_full_audit_fchmod(vfs_handle_struct *handle, files_struct *fsp,
			mode_t mode)
{
	int result;
	
	result = SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);

	do_log(SMB_VFS_OP_FCHMOD, (result >= 0), handle,
	       "%s|%o", fsp_str_do_log(fsp), mode);

	return result;
}

static int smb_full_audit_fchown(vfs_handle_struct *handle, files_struct *fsp,
			uid_t uid, gid_t gid)
{
	int result;

	result = SMB_VFS_NEXT_FCHOWN(handle, fsp, uid, gid);

	do_log(SMB_VFS_OP_FCHOWN, (result >= 0), handle, "%s|%ld|%ld",
	       fsp_str_do_log(fsp), (long int)uid, (long int)gid);

	return result;
}

static int smb_full_audit_lchown(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			uid_t uid,
			gid_t gid)
{
	int result;

	result = SMB_VFS_NEXT_LCHOWN(handle, smb_fname, uid, gid);

	do_log(SMB_VFS_OP_LCHOWN, (result >= 0), handle, "%s|%ld|%ld",
	       smb_fname->base_name, (long int)uid, (long int)gid);

	return result;
}

static int smb_full_audit_chdir(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int result;

	result = SMB_VFS_NEXT_CHDIR(handle, smb_fname);

	do_log(SMB_VFS_OP_CHDIR,
	       (result >= 0),
	       handle,
	       "chdir|%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static struct smb_filename *smb_full_audit_getwd(vfs_handle_struct *handle,
				TALLOC_CTX *ctx)
{
	struct smb_filename *result;

	result = SMB_VFS_NEXT_GETWD(handle, ctx);
	
	do_log(SMB_VFS_OP_GETWD, (result != NULL), handle, "%s",
		result == NULL? "" : result->base_name);

	return result;
}

static int smb_full_audit_ntimes(vfs_handle_struct *handle,
				 const struct smb_filename *smb_fname,
				 struct smb_file_time *ft)
{
	int result;
	time_t create_time = convert_timespec_to_time_t(ft->create_time);
	time_t atime = convert_timespec_to_time_t(ft->atime);
	time_t mtime = convert_timespec_to_time_t(ft->mtime);
	time_t ctime = convert_timespec_to_time_t(ft->ctime);
	const char *create_time_str = "";
	const char *atime_str = "";
	const char *mtime_str = "";
	const char *ctime_str = "";
	TALLOC_CTX *frame = talloc_stackframe();

	result = SMB_VFS_NEXT_NTIMES(handle, smb_fname, ft);

	if (create_time > 0) {
		create_time_str = timestring(frame, create_time);
	}
	if (atime > 0) {
		atime_str = timestring(frame, atime);
	}
	if (mtime > 0) {
		mtime_str = timestring(frame, mtime);
	}
	if (ctime > 0) {
		ctime_str = timestring(frame, ctime);
	}

	do_log(SMB_VFS_OP_NTIMES,
	       (result >= 0),
	       handle,
	       "%s|%s|%s|%s|%s",
	       smb_fname_str_do_log(handle->conn, smb_fname),
	       create_time_str,
	       atime_str,
	       mtime_str,
	       ctime_str);

	TALLOC_FREE(frame);

	return result;
}

static int smb_full_audit_ftruncate(vfs_handle_struct *handle, files_struct *fsp,
			   off_t len)
{
	int result;

	result = SMB_VFS_NEXT_FTRUNCATE(handle, fsp, len);

	do_log(SMB_VFS_OP_FTRUNCATE, (result >= 0), handle,
	       "%s", fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_fallocate(vfs_handle_struct *handle, files_struct *fsp,
			   uint32_t mode,
			   off_t offset,
			   off_t len)
{
	int result;

	result = SMB_VFS_NEXT_FALLOCATE(handle, fsp, mode, offset, len);

	do_log(SMB_VFS_OP_FALLOCATE, (result >= 0), handle,
	       "%s", fsp_str_do_log(fsp));

	return result;
}

static bool smb_full_audit_lock(vfs_handle_struct *handle, files_struct *fsp,
		       int op, off_t offset, off_t count, int type)
{
	bool result;

	result = SMB_VFS_NEXT_LOCK(handle, fsp, op, offset, count, type);

	do_log(SMB_VFS_OP_LOCK, result, handle, "%s", fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_kernel_flock(struct vfs_handle_struct *handle,
				       struct files_struct *fsp,
				       uint32_t share_access,
				       uint32_t access_mask)
{
	int result;

	result = SMB_VFS_NEXT_KERNEL_FLOCK(handle,
					   fsp,
					   share_access,
					   access_mask);

	do_log(SMB_VFS_OP_KERNEL_FLOCK, (result >= 0), handle, "%s",
	       fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_fcntl(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				int cmd, va_list cmd_arg)
{
	void *arg;
	va_list dup_cmd_arg;
	int result;

	va_copy(dup_cmd_arg, cmd_arg);
	arg = va_arg(dup_cmd_arg, void *);
	result = SMB_VFS_NEXT_FCNTL(handle, fsp, cmd, arg);
	va_end(dup_cmd_arg);

	do_log(SMB_VFS_OP_FCNTL, (result >= 0), handle, "%s",
	       fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_linux_setlease(vfs_handle_struct *handle, files_struct *fsp,
                                 int leasetype)
{
        int result;

        result = SMB_VFS_NEXT_LINUX_SETLEASE(handle, fsp, leasetype);

        do_log(SMB_VFS_OP_LINUX_SETLEASE, (result >= 0), handle, "%s",
	       fsp_str_do_log(fsp));

        return result;
}

static bool smb_full_audit_getlock(vfs_handle_struct *handle, files_struct *fsp,
		       off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid)
{
	bool result;

	result = SMB_VFS_NEXT_GETLOCK(handle, fsp, poffset, pcount, ptype, ppid);

	do_log(SMB_VFS_OP_GETLOCK, result, handle, "%s", fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_symlinkat(vfs_handle_struct *handle,
			const struct smb_filename *link_contents,
			struct files_struct *dirfsp,
			const struct smb_filename *new_smb_fname)
{
	int result;

	result = SMB_VFS_NEXT_SYMLINKAT(handle,
				link_contents,
				dirfsp,
				new_smb_fname);

	do_log(SMB_VFS_OP_SYMLINKAT,
	       (result >= 0),
	       handle,
	       "%s|%s",
	       link_contents->base_name,
	       smb_fname_str_do_log(handle->conn, new_smb_fname));

	return result;
}

static int smb_full_audit_readlinkat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			char *buf,
			size_t bufsiz)
{
	int result;

	result = SMB_VFS_NEXT_READLINKAT(handle,
			dirfsp,
			smb_fname,
			buf,
			bufsiz);

	do_log(SMB_VFS_OP_READLINKAT,
	       (result >= 0),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static int smb_full_audit_linkat(vfs_handle_struct *handle,
			files_struct *srcfsp,
			const struct smb_filename *old_smb_fname,
			files_struct *dstfsp,
			const struct smb_filename *new_smb_fname,
			int flags)
{
	int result;

	result = SMB_VFS_NEXT_LINKAT(handle,
			srcfsp,
			old_smb_fname,
			dstfsp,
			new_smb_fname,
			flags);

	do_log(SMB_VFS_OP_LINKAT,
	       (result >= 0),
	       handle,
	       "%s|%s",
	       smb_fname_str_do_log(handle->conn, old_smb_fname),
	       smb_fname_str_do_log(handle->conn, new_smb_fname));

	return result;
}

static int smb_full_audit_mknodat(vfs_handle_struct *handle,
			files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode,
			SMB_DEV_T dev)
{
	int result;

	result = SMB_VFS_NEXT_MKNODAT(handle,
				dirfsp,
				smb_fname,
				mode,
				dev);

	do_log(SMB_VFS_OP_MKNODAT,
	       (result >= 0),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static struct smb_filename *smb_full_audit_realpath(vfs_handle_struct *handle,
				TALLOC_CTX *ctx,
				const struct smb_filename *smb_fname)
{
	struct smb_filename *result_fname = NULL;

	result_fname = SMB_VFS_NEXT_REALPATH(handle, ctx, smb_fname);

	do_log(SMB_VFS_OP_REALPATH,
	       (result_fname != NULL),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result_fname;
}

static int smb_full_audit_chflags(vfs_handle_struct *handle,
			const struct smb_filename *smb_fname,
			unsigned int flags)
{
	int result;

	result = SMB_VFS_NEXT_CHFLAGS(handle, smb_fname, flags);

	do_log(SMB_VFS_OP_CHFLAGS,
	       (result != 0),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static struct file_id smb_full_audit_file_id_create(struct vfs_handle_struct *handle,
						    const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id_zero = { 0 };
	struct file_id result;
	struct file_id_buf idbuf;

	result = SMB_VFS_NEXT_FILE_ID_CREATE(handle, sbuf);

	do_log(SMB_VFS_OP_FILE_ID_CREATE,
	       !file_id_equal(&id_zero, &result),
	       handle,
	       "%s",
	       file_id_str_buf(result, &idbuf));

	return result;
}

static uint64_t smb_full_audit_fs_file_id(struct vfs_handle_struct *handle,
					  const SMB_STRUCT_STAT *sbuf)
{
	uint64_t result;

	result = SMB_VFS_NEXT_FS_FILE_ID(handle, sbuf);

	do_log(SMB_VFS_OP_FS_FILE_ID,
	       result != 0,
	       handle, "%" PRIu64, result);

	return result;
}

static NTSTATUS smb_full_audit_streaminfo(vfs_handle_struct *handle,
					  struct files_struct *fsp,
					  const struct smb_filename *smb_fname,
					  TALLOC_CTX *mem_ctx,
					  unsigned int *pnum_streams,
					  struct stream_struct **pstreams)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_STREAMINFO(handle, fsp, smb_fname, mem_ctx,
					 pnum_streams, pstreams);

	do_log(SMB_VFS_OP_STREAMINFO,
	       NT_STATUS_IS_OK(result),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static int smb_full_audit_get_real_filename(struct vfs_handle_struct *handle,
					    const struct smb_filename *path,
					    const char *name,
					    TALLOC_CTX *mem_ctx,
					    char **found_name)
{
	int result;

	result = SMB_VFS_NEXT_GET_REAL_FILENAME(handle, path, name, mem_ctx,
						found_name);

	do_log(SMB_VFS_OP_GET_REAL_FILENAME, (result == 0), handle,
	       "%s/%s->%s",
	       path->base_name, name, (result == 0) ? *found_name : "");

	return result;
}

static const char *smb_full_audit_connectpath(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname)
{
	const char *result;

	result = SMB_VFS_NEXT_CONNECTPATH(handle, smb_fname);

	do_log(SMB_VFS_OP_CONNECTPATH,
	       result != NULL,
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static NTSTATUS smb_full_audit_brl_lock_windows(struct vfs_handle_struct *handle,
					        struct byte_range_lock *br_lck,
					        struct lock_struct *plock)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_BRL_LOCK_WINDOWS(handle, br_lck, plock);

	do_log(SMB_VFS_OP_BRL_LOCK_WINDOWS, NT_STATUS_IS_OK(result), handle,
	    "%s:%llu-%llu. type=%d.",
	       fsp_str_do_log(brl_fsp(br_lck)),
	       (unsigned long long)plock->start,
	       (unsigned long long)plock->size,
	       plock->lock_type);

	return result;
}

static bool smb_full_audit_brl_unlock_windows(struct vfs_handle_struct *handle,
				              struct byte_range_lock *br_lck,
				              const struct lock_struct *plock)
{
	bool result;

	result = SMB_VFS_NEXT_BRL_UNLOCK_WINDOWS(handle, br_lck, plock);

	do_log(SMB_VFS_OP_BRL_UNLOCK_WINDOWS, (result == 0), handle,
	       "%s:%llu-%llu:%d", fsp_str_do_log(brl_fsp(br_lck)),
	       (unsigned long long)plock->start,
	       (unsigned long long)plock->size,
	       plock->lock_type);

	return result;
}

static bool smb_full_audit_strict_lock_check(struct vfs_handle_struct *handle,
					     struct files_struct *fsp,
					     struct lock_struct *plock)
{
	bool result;

	result = SMB_VFS_NEXT_STRICT_LOCK_CHECK(handle, fsp, plock);

	do_log(SMB_VFS_OP_STRICT_LOCK_CHECK, result, handle,
	       "%s:%llu-%llu:%d", fsp_str_do_log(fsp),
	       (unsigned long long)plock->start,
	       (unsigned long long)plock->size,
	       plock->lock_type);

	return result;
}

static NTSTATUS smb_full_audit_translate_name(struct vfs_handle_struct *handle,
					      const char *name,
					      enum vfs_translate_direction direction,
					      TALLOC_CTX *mem_ctx,
					      char **mapped_name)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_TRANSLATE_NAME(handle, name, direction, mem_ctx,
					     mapped_name);

	do_log(SMB_VFS_OP_TRANSLATE_NAME, NT_STATUS_IS_OK(result), handle, "");

	return result;
}

static NTSTATUS smb_full_audit_fsctl(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				TALLOC_CTX *ctx,
				uint32_t function,
				uint16_t req_flags,
				const uint8_t *_in_data,
				uint32_t in_len,
				uint8_t **_out_data,
				uint32_t max_out_len,
				uint32_t *out_len)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_FSCTL(handle,
				fsp,
				ctx,
				function,
				req_flags,
				_in_data,
				in_len,
				_out_data,
				max_out_len,
				out_len);

	do_log(SMB_VFS_OP_FSCTL, NT_STATUS_IS_OK(result), handle, "");

	return result;
}

static struct tevent_req *smb_full_audit_offload_read_send(
	TALLOC_CTX *mem_ctx,
	struct tevent_context *ev,
	struct vfs_handle_struct *handle,
	struct files_struct *fsp,
	uint32_t fsctl,
	uint32_t ttl,
	off_t offset,
	size_t to_copy)
{
	struct tevent_req *req = NULL;

	req = SMB_VFS_NEXT_OFFLOAD_READ_SEND(mem_ctx, ev, handle, fsp,
					     fsctl, ttl, offset, to_copy);

	do_log(SMB_VFS_OP_OFFLOAD_READ_SEND, req, handle, "");

	return req;
}

static NTSTATUS smb_full_audit_offload_read_recv(
	struct tevent_req *req,
	struct vfs_handle_struct *handle,
	TALLOC_CTX *mem_ctx,
	DATA_BLOB *_token_blob)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_OFFLOAD_READ_RECV(req, handle, mem_ctx,
						_token_blob);

	do_log(SMB_VFS_OP_OFFLOAD_READ_RECV, NT_STATUS_IS_OK(status), handle, "");

	return status;
}

static struct tevent_req *smb_full_audit_offload_write_send(struct vfs_handle_struct *handle,
							 TALLOC_CTX *mem_ctx,
							 struct tevent_context *ev,
							 uint32_t fsctl,
							 DATA_BLOB *token,
							 off_t transfer_offset,
							 struct files_struct *dest_fsp,
							 off_t dest_off,
							    off_t num)
{
	struct tevent_req *req;

	req = SMB_VFS_NEXT_OFFLOAD_WRITE_SEND(handle, mem_ctx, ev,
					   fsctl, token, transfer_offset,
					   dest_fsp, dest_off, num);

	do_log(SMB_VFS_OP_OFFLOAD_WRITE_SEND, req, handle, "");

	return req;
}

static NTSTATUS smb_full_audit_offload_write_recv(struct vfs_handle_struct *handle,
					       struct tevent_req *req,
					       off_t *copied)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_OFFLOAD_WRITE_RECV(handle, req, copied);

	do_log(SMB_VFS_OP_OFFLOAD_WRITE_RECV, NT_STATUS_IS_OK(result), handle, "");

	return result;
}

static NTSTATUS smb_full_audit_get_compression(vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct files_struct *fsp,
					       struct smb_filename *smb_fname,
					       uint16_t *_compression_fmt)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_GET_COMPRESSION(handle, mem_ctx, fsp, smb_fname,
					      _compression_fmt);

	do_log(SMB_VFS_OP_GET_COMPRESSION, NT_STATUS_IS_OK(result), handle,
	       "%s",
	       (fsp ? fsp_str_do_log(fsp) :
		smb_fname_str_do_log(handle->conn, smb_fname)));

	return result;
}

static NTSTATUS smb_full_audit_set_compression(vfs_handle_struct *handle,
					       TALLOC_CTX *mem_ctx,
					       struct files_struct *fsp,
					       uint16_t compression_fmt)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_SET_COMPRESSION(handle, mem_ctx, fsp,
					      compression_fmt);

	do_log(SMB_VFS_OP_SET_COMPRESSION, NT_STATUS_IS_OK(result), handle,
	       "%s", fsp_str_do_log(fsp));

	return result;
}

static NTSTATUS smb_full_audit_readdir_attr(struct vfs_handle_struct *handle,
					    const struct smb_filename *fname,
					    TALLOC_CTX *mem_ctx,
					    struct readdir_attr_data **pattr_data)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_READDIR_ATTR(handle, fname, mem_ctx, pattr_data);

	do_log(SMB_VFS_OP_READDIR_ATTR, NT_STATUS_IS_OK(status), handle, "%s",
	       smb_fname_str_do_log(handle->conn, fname));

	return status;
}

static NTSTATUS smb_full_audit_get_dos_attributes(
				struct vfs_handle_struct *handle,
				struct smb_filename *smb_fname,
				uint32_t *dosmode)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_GET_DOS_ATTRIBUTES(handle,
				smb_fname,
				dosmode);

	do_log(SMB_VFS_OP_GET_DOS_ATTRIBUTES,
		NT_STATUS_IS_OK(status),
		handle,
		"%s",
		smb_fname_str_do_log(handle->conn, smb_fname));

	return status;
}

struct smb_full_audit_get_dos_attributes_state {
	struct vfs_aio_state aio_state;
	vfs_handle_struct *handle;
	files_struct *dir_fsp;
	const struct smb_filename *smb_fname;
	uint32_t dosmode;
};

static void smb_full_audit_get_dos_attributes_done(struct tevent_req *subreq);

static struct tevent_req *smb_full_audit_get_dos_attributes_send(
		TALLOC_CTX *mem_ctx,
		struct tevent_context *ev,
		struct vfs_handle_struct *handle,
		files_struct *dir_fsp,
		struct smb_filename *smb_fname)
{
	struct tevent_req *req = NULL;
	struct smb_full_audit_get_dos_attributes_state *state = NULL;
	struct tevent_req *subreq = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_full_audit_get_dos_attributes_state);
	if (req == NULL) {
		do_log(SMB_VFS_OP_GET_DOS_ATTRIBUTES_SEND,
		       false,
		       handle,
		       "%s/%s",
		       fsp_str_do_log(dir_fsp),
		       smb_fname->base_name);
		return NULL;
	}
	*state = (struct smb_full_audit_get_dos_attributes_state) {
		.handle = handle,
		.dir_fsp = dir_fsp,
		.smb_fname = smb_fname,
	};

	subreq = SMB_VFS_NEXT_GET_DOS_ATTRIBUTES_SEND(mem_ctx,
						      ev,
						      handle,
						      dir_fsp,
						      smb_fname);
	if (tevent_req_nomem(subreq, req)) {
		do_log(SMB_VFS_OP_GET_DOS_ATTRIBUTES_SEND,
		       false,
		       handle,
		       "%s/%s",
		       fsp_str_do_log(dir_fsp),
		       smb_fname->base_name);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq,
				smb_full_audit_get_dos_attributes_done,
				req);

	do_log(SMB_VFS_OP_GET_DOS_ATTRIBUTES_SEND,
	       true,
	       handle,
	       "%s/%s",
	       fsp_str_do_log(dir_fsp),
	       smb_fname->base_name);

	return req;
}

static void smb_full_audit_get_dos_attributes_done(struct tevent_req *subreq)
{
	struct tevent_req *req =
		tevent_req_callback_data(subreq,
		struct tevent_req);
	struct smb_full_audit_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct smb_full_audit_get_dos_attributes_state);
	NTSTATUS status;

	status = SMB_VFS_NEXT_GET_DOS_ATTRIBUTES_RECV(subreq,
						      &state->aio_state,
						      &state->dosmode);
	TALLOC_FREE(subreq);
	if (tevent_req_nterror(req, status)) {
		return;
	}

	tevent_req_done(req);
	return;
}

static NTSTATUS smb_full_audit_get_dos_attributes_recv(struct tevent_req *req,
						struct vfs_aio_state *aio_state,
						uint32_t *dosmode)
{
	struct smb_full_audit_get_dos_attributes_state *state =
		tevent_req_data(req,
		struct smb_full_audit_get_dos_attributes_state);
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		do_log(SMB_VFS_OP_GET_DOS_ATTRIBUTES_RECV,
		       false,
		       state->handle,
		       "%s/%s",
		       fsp_str_do_log(state->dir_fsp),
		       state->smb_fname->base_name);
		tevent_req_received(req);
		return status;
	}

	do_log(SMB_VFS_OP_GET_DOS_ATTRIBUTES_RECV,
	       true,
	       state->handle,
	       "%s/%s",
	       fsp_str_do_log(state->dir_fsp),
	       state->smb_fname->base_name);

	*aio_state = state->aio_state;
	*dosmode = state->dosmode;
	tevent_req_received(req);
	return NT_STATUS_OK;
}

static NTSTATUS smb_full_audit_fget_dos_attributes(
				struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t *dosmode)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_FGET_DOS_ATTRIBUTES(handle,
				fsp,
				dosmode);

	do_log(SMB_VFS_OP_FGET_DOS_ATTRIBUTES,
		NT_STATUS_IS_OK(status),
		handle,
		"%s",
		fsp_str_do_log(fsp));

	return status;
}

static NTSTATUS smb_full_audit_set_dos_attributes(
				struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				uint32_t dosmode)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_SET_DOS_ATTRIBUTES(handle,
				smb_fname,
				dosmode);

	do_log(SMB_VFS_OP_SET_DOS_ATTRIBUTES,
		NT_STATUS_IS_OK(status),
		handle,
		"%s",
		smb_fname_str_do_log(handle->conn, smb_fname));

	return status;
}

static NTSTATUS smb_full_audit_fset_dos_attributes(
				struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				uint32_t dosmode)
{
	NTSTATUS status;

	status = SMB_VFS_NEXT_FSET_DOS_ATTRIBUTES(handle,
				fsp,
				dosmode);

	do_log(SMB_VFS_OP_FSET_DOS_ATTRIBUTES,
		NT_STATUS_IS_OK(status),
		handle,
		"%s",
		fsp_str_do_log(fsp));

	return status;
}

static NTSTATUS smb_full_audit_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
					   uint32_t security_info,
					   TALLOC_CTX *mem_ctx,
					   struct security_descriptor **ppdesc)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp, security_info,
					  mem_ctx, ppdesc);

	do_log(SMB_VFS_OP_FGET_NT_ACL, NT_STATUS_IS_OK(result), handle,
	       "%s", fsp_str_do_log(fsp));

	return result;
}

static NTSTATUS smb_full_audit_get_nt_acl_at(vfs_handle_struct *handle,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				uint32_t security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
				dirfsp,
				smb_fname,
				security_info,
				mem_ctx,
				ppdesc);

	do_log(SMB_VFS_OP_GET_NT_ACL_AT,
		NT_STATUS_IS_OK(result),
		handle,
	       "%s",
		smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static NTSTATUS smb_full_audit_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
			      uint32_t security_info_sent,
			      const struct security_descriptor *psd)
{
	struct vfs_full_audit_private_data *pd;
	NTSTATUS result;
	char *sd = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, pd,
				struct vfs_full_audit_private_data,
				return NT_STATUS_INTERNAL_ERROR);

	if (pd->log_secdesc) {
		sd = sddl_encode(talloc_tos(), psd, get_global_sam_sid());
	}

	result = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);

	do_log(SMB_VFS_OP_FSET_NT_ACL, NT_STATUS_IS_OK(result), handle,
	       "%s [%s]", fsp_str_do_log(fsp), sd ? sd : "");

	TALLOC_FREE(sd);

	return result;
}

static NTSTATUS smb_full_audit_audit_file(struct vfs_handle_struct *handle,
				struct smb_filename *file,
				struct security_acl *sacl,
				uint32_t access_requested,
				uint32_t access_denied)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_AUDIT_FILE(handle,
					file,
					sacl,
					access_requested,
					access_denied);

	do_log(SMB_VFS_OP_AUDIT_FILE, NT_STATUS_IS_OK(result), handle,
			"%s",
			smb_fname_str_do_log(handle->conn, file));

	return result;
}

static SMB_ACL_T smb_full_audit_sys_acl_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T type,
				TALLOC_CTX *mem_ctx)
{
	SMB_ACL_T result;

	result = SMB_VFS_NEXT_SYS_ACL_GET_FILE(handle, smb_fname,
				type, mem_ctx);

	do_log(SMB_VFS_OP_SYS_ACL_GET_FILE,
	       (result != NULL),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static SMB_ACL_T smb_full_audit_sys_acl_get_fd(vfs_handle_struct *handle,
					       files_struct *fsp, TALLOC_CTX *mem_ctx)
{
	SMB_ACL_T result;

	result = SMB_VFS_NEXT_SYS_ACL_GET_FD(handle, fsp, mem_ctx);

	do_log(SMB_VFS_OP_SYS_ACL_GET_FD, (result != NULL), handle,
	       "%s", fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_sys_acl_blob_get_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				TALLOC_CTX *mem_ctx,
				char **blob_description,
				DATA_BLOB *blob)
{
	int result;

	result = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle, smb_fname,
			mem_ctx, blob_description, blob);

	do_log(SMB_VFS_OP_SYS_ACL_BLOB_GET_FILE,
	       (result >= 0),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static int smb_full_audit_sys_acl_blob_get_fd(vfs_handle_struct *handle,
					      files_struct *fsp,
					      TALLOC_CTX *mem_ctx,
					      char **blob_description,
					      DATA_BLOB *blob)
{
	int result;

	result = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle, fsp, mem_ctx, blob_description, blob);

	do_log(SMB_VFS_OP_SYS_ACL_BLOB_GET_FD, (result >= 0), handle,
	       "%s", fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_sys_acl_set_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				SMB_ACL_TYPE_T acltype,
				SMB_ACL_T theacl)
{
	int result;

	result = SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle, smb_fname, acltype,
					       theacl);

	do_log(SMB_VFS_OP_SYS_ACL_SET_FILE,
	       (result >= 0),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static int smb_full_audit_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp,
				SMB_ACL_T theacl)
{
	int result;

	result = SMB_VFS_NEXT_SYS_ACL_SET_FD(handle, fsp, theacl);

	do_log(SMB_VFS_OP_SYS_ACL_SET_FD, (result >= 0), handle,
	       "%s", fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_sys_acl_delete_def_file(vfs_handle_struct *handle,
				const struct smb_filename *smb_fname)
{
	int result;

	result = SMB_VFS_NEXT_SYS_ACL_DELETE_DEF_FILE(handle, smb_fname);

	do_log(SMB_VFS_OP_SYS_ACL_DELETE_DEF_FILE,
	       (result >= 0),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static ssize_t smb_full_audit_getxattr(struct vfs_handle_struct *handle,
			      const struct smb_filename *smb_fname,
			      const char *name, void *value, size_t size)
{
	ssize_t result;

	result = SMB_VFS_NEXT_GETXATTR(handle, smb_fname, name, value, size);

	do_log(SMB_VFS_OP_GETXATTR,
	       (result >= 0),
	       handle,
	       "%s|%s",
	       smb_fname_str_do_log(handle->conn, smb_fname),
	       name);

	return result;
}

struct smb_full_audit_getxattrat_state {
	struct vfs_aio_state aio_state;
	vfs_handle_struct *handle;
	files_struct *dir_fsp;
	const struct smb_filename *smb_fname;
	const char *xattr_name;
	ssize_t xattr_size;
	uint8_t *xattr_value;
};

static void smb_full_audit_getxattrat_done(struct tevent_req *subreq);

static struct tevent_req *smb_full_audit_getxattrat_send(
			TALLOC_CTX *mem_ctx,
			struct tevent_context *ev,
			struct vfs_handle_struct *handle,
			files_struct *dir_fsp,
			const struct smb_filename *smb_fname,
			const char *xattr_name,
			size_t alloc_hint)
{
	struct tevent_req *req = NULL;
	struct tevent_req *subreq = NULL;
	struct smb_full_audit_getxattrat_state *state = NULL;

	req = tevent_req_create(mem_ctx, &state,
				struct smb_full_audit_getxattrat_state);
	if (req == NULL) {
		do_log(SMB_VFS_OP_GETXATTRAT_SEND,
		       false,
		       handle,
		       "%s/%s|%s",
		       fsp_str_do_log(dir_fsp),
		       smb_fname->base_name,
		       xattr_name);
		return NULL;
	}
	*state = (struct smb_full_audit_getxattrat_state) {
		.handle = handle,
		.dir_fsp = dir_fsp,
		.smb_fname = smb_fname,
		.xattr_name = xattr_name,
	};

	subreq = SMB_VFS_NEXT_GETXATTRAT_SEND(state,
					      ev,
					      handle,
					      dir_fsp,
					      smb_fname,
					      xattr_name,
					      alloc_hint);
	if (tevent_req_nomem(subreq, req)) {
		do_log(SMB_VFS_OP_GETXATTRAT_SEND,
		       false,
		       handle,
		       "%s/%s|%s",
		       fsp_str_do_log(dir_fsp),
		       smb_fname->base_name,
		       xattr_name);
		return tevent_req_post(req, ev);
	}
	tevent_req_set_callback(subreq, smb_full_audit_getxattrat_done, req);

	do_log(SMB_VFS_OP_GETXATTRAT_SEND,
	       true,
	       handle,
	       "%s/%s|%s",
	       fsp_str_do_log(dir_fsp),
	       smb_fname->base_name,
	       xattr_name);

	return req;
}

static void smb_full_audit_getxattrat_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct smb_full_audit_getxattrat_state *state = tevent_req_data(
		req, struct smb_full_audit_getxattrat_state);

	state->xattr_size = SMB_VFS_NEXT_GETXATTRAT_RECV(subreq,
							 &state->aio_state,
							 state,
							 &state->xattr_value);
	TALLOC_FREE(subreq);
	if (state->xattr_size == -1) {
		tevent_req_error(req, state->aio_state.error);
		return;
	}

	tevent_req_done(req);
}

static ssize_t smb_full_audit_getxattrat_recv(struct tevent_req *req,
					      struct vfs_aio_state *aio_state,
					      TALLOC_CTX *mem_ctx,
					      uint8_t **xattr_value)
{
	struct smb_full_audit_getxattrat_state *state = tevent_req_data(
		req, struct smb_full_audit_getxattrat_state);
	ssize_t xattr_size;

	if (tevent_req_is_unix_error(req, &aio_state->error)) {
		do_log(SMB_VFS_OP_GETXATTRAT_RECV,
		       false,
		       state->handle,
		       "%s/%s|%s",
		       fsp_str_do_log(state->dir_fsp),
		       state->smb_fname->base_name,
		       state->xattr_name);
		tevent_req_received(req);
		return -1;
	}

	do_log(SMB_VFS_OP_GETXATTRAT_RECV,
	       true,
	       state->handle,
	       "%s/%s|%s",
	       fsp_str_do_log(state->dir_fsp),
	       state->smb_fname->base_name,
	       state->xattr_name);

	*aio_state = state->aio_state;
	xattr_size = state->xattr_size;
	if (xattr_value != NULL) {
		*xattr_value = talloc_move(mem_ctx, &state->xattr_value);
	}

	tevent_req_received(req);
	return xattr_size;
}

static ssize_t smb_full_audit_fgetxattr(struct vfs_handle_struct *handle,
			       struct files_struct *fsp,
			       const char *name, void *value, size_t size)
{
	ssize_t result;

	result = SMB_VFS_NEXT_FGETXATTR(handle, fsp, name, value, size);

	do_log(SMB_VFS_OP_FGETXATTR, (result >= 0), handle,
	       "%s|%s", fsp_str_do_log(fsp), name);

	return result;
}

static ssize_t smb_full_audit_listxattr(struct vfs_handle_struct *handle,
				const struct smb_filename *smb_fname,
				char *list,
				size_t size)
{
	ssize_t result;

	result = SMB_VFS_NEXT_LISTXATTR(handle, smb_fname, list, size);

	do_log(SMB_VFS_OP_LISTXATTR,
	       (result >= 0),
	       handle,
	       "%s",
	       smb_fname_str_do_log(handle->conn, smb_fname));

	return result;
}

static ssize_t smb_full_audit_flistxattr(struct vfs_handle_struct *handle,
				struct files_struct *fsp, char *list,
				size_t size)
{
	ssize_t result;

	result = SMB_VFS_NEXT_FLISTXATTR(handle, fsp, list, size);

	do_log(SMB_VFS_OP_FLISTXATTR, (result >= 0), handle,
	       "%s", fsp_str_do_log(fsp));

	return result;
}

static int smb_full_audit_removexattr(struct vfs_handle_struct *handle,
			     const struct smb_filename *smb_fname,
			     const char *name)
{
	int result;

	result = SMB_VFS_NEXT_REMOVEXATTR(handle, smb_fname, name);

	do_log(SMB_VFS_OP_REMOVEXATTR,
	       (result >= 0),
	       handle,
	       "%s|%s",
	       smb_fname_str_do_log(handle->conn, smb_fname),
	       name);

	return result;
}

static int smb_full_audit_fremovexattr(struct vfs_handle_struct *handle,
			      struct files_struct *fsp,
			      const char *name)
{
	int result;

	result = SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);

	do_log(SMB_VFS_OP_FREMOVEXATTR, (result >= 0), handle,
	       "%s|%s", fsp_str_do_log(fsp), name);

	return result;
}

static int smb_full_audit_setxattr(struct vfs_handle_struct *handle,
			  const struct smb_filename *smb_fname,
			  const char *name, const void *value, size_t size,
			  int flags)
{
	int result;

	result = SMB_VFS_NEXT_SETXATTR(handle, smb_fname, name, value, size,
				       flags);

	do_log(SMB_VFS_OP_SETXATTR,
	       (result >= 0),
	       handle,
	       "%s|%s",
	       smb_fname_str_do_log(handle->conn, smb_fname),
	       name);

	return result;
}

static int smb_full_audit_fsetxattr(struct vfs_handle_struct *handle,
			   struct files_struct *fsp, const char *name,
			   const void *value, size_t size, int flags)
{
	int result;

	result = SMB_VFS_NEXT_FSETXATTR(handle, fsp, name, value, size, flags);

	do_log(SMB_VFS_OP_FSETXATTR, (result >= 0), handle,
	       "%s|%s", fsp_str_do_log(fsp), name);

	return result;
}

static bool smb_full_audit_aio_force(struct vfs_handle_struct *handle,
				     struct files_struct *fsp)
{
	bool result;

	result = SMB_VFS_NEXT_AIO_FORCE(handle, fsp);
	do_log(SMB_VFS_OP_AIO_FORCE, result, handle,
		"%s", fsp_str_do_log(fsp));

	return result;
}

static NTSTATUS smb_full_audit_durable_cookie(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				TALLOC_CTX *mem_ctx,
				DATA_BLOB *cookie)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_DURABLE_COOKIE(handle,
					fsp,
					mem_ctx,
					cookie);

	do_log(SMB_VFS_OP_DURABLE_COOKIE, NT_STATUS_IS_OK(result), handle,
			"%s", fsp_str_do_log(fsp));

	return result;
}

static NTSTATUS smb_full_audit_durable_disconnect(
				struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				const DATA_BLOB old_cookie,
				TALLOC_CTX *mem_ctx,
				DATA_BLOB *new_cookie)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_DURABLE_DISCONNECT(handle,
					fsp,
					old_cookie,
					mem_ctx,
					new_cookie);

	do_log(SMB_VFS_OP_DURABLE_DISCONNECT, NT_STATUS_IS_OK(result), handle,
			"%s", fsp_str_do_log(fsp));

	return result;
}

static NTSTATUS smb_full_audit_durable_reconnect(
				struct vfs_handle_struct *handle,
				struct smb_request *smb1req,
				struct smbXsrv_open *op,
				const DATA_BLOB old_cookie,
				TALLOC_CTX *mem_ctx,
				struct files_struct **fsp,
				DATA_BLOB *new_cookie)
{
	NTSTATUS result;

	result = SMB_VFS_NEXT_DURABLE_RECONNECT(handle,
					smb1req,
					op,
					old_cookie,
					mem_ctx,
					fsp,
					new_cookie);

	do_log(SMB_VFS_OP_DURABLE_RECONNECT,
			NT_STATUS_IS_OK(result),
			handle,
			"");

	return result;
}

static struct vfs_fn_pointers vfs_full_audit_fns = {

	/* Disk operations */

	.connect_fn = smb_full_audit_connect,
	.disconnect_fn = smb_full_audit_disconnect,
	.disk_free_fn = smb_full_audit_disk_free,
	.get_quota_fn = smb_full_audit_get_quota,
	.set_quota_fn = smb_full_audit_set_quota,
	.get_shadow_copy_data_fn = smb_full_audit_get_shadow_copy_data,
	.statvfs_fn = smb_full_audit_statvfs,
	.fs_capabilities_fn = smb_full_audit_fs_capabilities,
	.get_dfs_referrals_fn = smb_full_audit_get_dfs_referrals,
	.create_dfs_pathat_fn = smb_full_audit_create_dfs_pathat,
	.read_dfs_pathat_fn = smb_full_audit_read_dfs_pathat,
	.fdopendir_fn = smb_full_audit_fdopendir,
	.readdir_fn = smb_full_audit_readdir,
	.seekdir_fn = smb_full_audit_seekdir,
	.telldir_fn = smb_full_audit_telldir,
	.rewind_dir_fn = smb_full_audit_rewinddir,
	.mkdirat_fn = smb_full_audit_mkdirat,
	.closedir_fn = smb_full_audit_closedir,
	.openat_fn = smb_full_audit_openat,
	.create_file_fn = smb_full_audit_create_file,
	.close_fn = smb_full_audit_close,
	.pread_fn = smb_full_audit_pread,
	.pread_send_fn = smb_full_audit_pread_send,
	.pread_recv_fn = smb_full_audit_pread_recv,
	.pwrite_fn = smb_full_audit_pwrite,
	.pwrite_send_fn = smb_full_audit_pwrite_send,
	.pwrite_recv_fn = smb_full_audit_pwrite_recv,
	.lseek_fn = smb_full_audit_lseek,
	.sendfile_fn = smb_full_audit_sendfile,
	.recvfile_fn = smb_full_audit_recvfile,
	.renameat_fn = smb_full_audit_renameat,
	.fsync_send_fn = smb_full_audit_fsync_send,
	.fsync_recv_fn = smb_full_audit_fsync_recv,
	.stat_fn = smb_full_audit_stat,
	.fstat_fn = smb_full_audit_fstat,
	.lstat_fn = smb_full_audit_lstat,
	.get_alloc_size_fn = smb_full_audit_get_alloc_size,
	.unlinkat_fn = smb_full_audit_unlinkat,
	.chmod_fn = smb_full_audit_chmod,
	.fchmod_fn = smb_full_audit_fchmod,
	.fchown_fn = smb_full_audit_fchown,
	.lchown_fn = smb_full_audit_lchown,
	.chdir_fn = smb_full_audit_chdir,
	.getwd_fn = smb_full_audit_getwd,
	.ntimes_fn = smb_full_audit_ntimes,
	.ftruncate_fn = smb_full_audit_ftruncate,
	.fallocate_fn = smb_full_audit_fallocate,
	.lock_fn = smb_full_audit_lock,
	.kernel_flock_fn = smb_full_audit_kernel_flock,
	.fcntl_fn = smb_full_audit_fcntl,
	.linux_setlease_fn = smb_full_audit_linux_setlease,
	.getlock_fn = smb_full_audit_getlock,
	.symlinkat_fn = smb_full_audit_symlinkat,
	.readlinkat_fn = smb_full_audit_readlinkat,
	.linkat_fn = smb_full_audit_linkat,
	.mknodat_fn = smb_full_audit_mknodat,
	.realpath_fn = smb_full_audit_realpath,
	.chflags_fn = smb_full_audit_chflags,
	.file_id_create_fn = smb_full_audit_file_id_create,
	.fs_file_id_fn = smb_full_audit_fs_file_id,
	.offload_read_send_fn = smb_full_audit_offload_read_send,
	.offload_read_recv_fn = smb_full_audit_offload_read_recv,
	.offload_write_send_fn = smb_full_audit_offload_write_send,
	.offload_write_recv_fn = smb_full_audit_offload_write_recv,
	.get_compression_fn = smb_full_audit_get_compression,
	.set_compression_fn = smb_full_audit_set_compression,
	.snap_check_path_fn =  smb_full_audit_snap_check_path,
	.snap_create_fn = smb_full_audit_snap_create,
	.snap_delete_fn = smb_full_audit_snap_delete,
	.streaminfo_fn = smb_full_audit_streaminfo,
	.get_real_filename_fn = smb_full_audit_get_real_filename,
	.connectpath_fn = smb_full_audit_connectpath,
	.brl_lock_windows_fn = smb_full_audit_brl_lock_windows,
	.brl_unlock_windows_fn = smb_full_audit_brl_unlock_windows,
	.strict_lock_check_fn = smb_full_audit_strict_lock_check,
	.translate_name_fn = smb_full_audit_translate_name,
	.fsctl_fn = smb_full_audit_fsctl,
	.get_dos_attributes_fn = smb_full_audit_get_dos_attributes,
	.get_dos_attributes_send_fn = smb_full_audit_get_dos_attributes_send,
	.get_dos_attributes_recv_fn = smb_full_audit_get_dos_attributes_recv,
	.fget_dos_attributes_fn = smb_full_audit_fget_dos_attributes,
	.set_dos_attributes_fn = smb_full_audit_set_dos_attributes,
	.fset_dos_attributes_fn = smb_full_audit_fset_dos_attributes,
	.fget_nt_acl_fn = smb_full_audit_fget_nt_acl,
	.get_nt_acl_at_fn = smb_full_audit_get_nt_acl_at,
	.fset_nt_acl_fn = smb_full_audit_fset_nt_acl,
	.audit_file_fn = smb_full_audit_audit_file,
	.sys_acl_get_file_fn = smb_full_audit_sys_acl_get_file,
	.sys_acl_get_fd_fn = smb_full_audit_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = smb_full_audit_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = smb_full_audit_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = smb_full_audit_sys_acl_set_file,
	.sys_acl_set_fd_fn = smb_full_audit_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = smb_full_audit_sys_acl_delete_def_file,
	.getxattr_fn = smb_full_audit_getxattr,
	.getxattrat_send_fn = smb_full_audit_getxattrat_send,
	.getxattrat_recv_fn = smb_full_audit_getxattrat_recv,
	.fgetxattr_fn = smb_full_audit_fgetxattr,
	.listxattr_fn = smb_full_audit_listxattr,
	.flistxattr_fn = smb_full_audit_flistxattr,
	.removexattr_fn = smb_full_audit_removexattr,
	.fremovexattr_fn = smb_full_audit_fremovexattr,
	.setxattr_fn = smb_full_audit_setxattr,
	.fsetxattr_fn = smb_full_audit_fsetxattr,
	.aio_force_fn = smb_full_audit_aio_force,
	.durable_cookie_fn = smb_full_audit_durable_cookie,
	.durable_disconnect_fn = smb_full_audit_durable_disconnect,
	.durable_reconnect_fn = smb_full_audit_durable_reconnect,
	.readdir_attr_fn = smb_full_audit_readdir_attr

};

static_decl_vfs;
NTSTATUS vfs_full_audit_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret;

	smb_vfs_assert_all_fns(&vfs_full_audit_fns, "full_audit");

	ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "full_audit",
			       &vfs_full_audit_fns);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_full_audit_debug_level = debug_add_class("full_audit");
	if (vfs_full_audit_debug_level == -1) {
		vfs_full_audit_debug_level = DBGC_VFS;
		DEBUG(0, ("vfs_full_audit: Couldn't register custom debugging "
			  "class!\n"));
	} else {
		DEBUG(10, ("vfs_full_audit: Debug class number of "
			   "'full_audit': %d\n", vfs_full_audit_debug_level));
	}
	
	return ret;
}
