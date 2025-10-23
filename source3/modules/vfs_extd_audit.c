/*
 * Auditing VFS module for samba.  Log selected file operations to syslog
 * facility.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) John H Terpstra, 2003
 * Copyright (C) Stefan (metze) Metzmacher, 2003
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


#include "includes.h"
#include "system/filesys.h"
#include "system/syslog.h"
#include "smbd/smbd.h"
#include "lib/param/loadparm.h"

static int vfs_extd_audit_debug_level = DBGC_VFS;

#undef DBGC_CLASS
#define DBGC_CLASS vfs_extd_audit_debug_level

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

	facility = lp_parm_enum(SNUM(handle->conn), "extd_audit", "facility", enum_log_facilities, LOG_USER);

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

	priority = lp_parm_enum(SNUM(handle->conn), "extd_audit", "priority",
				enum_log_priorities, LOG_NOTICE);
	if (priority == -1) {
		priority = LOG_WARNING;
	}

	return priority;
}

/* Implementation of vfs_ops.  Pass everything on to the default
   operation but log event first. */

static int audit_connect(vfs_handle_struct *handle, const char *svc, const char *user)
{
	int result = SMB_VFS_NEXT_CONNECT(handle, svc, user);

	if (result < 0) {
		return result;
	}

	openlog("smbd_audit", LOG_PID, audit_syslog_facility(handle));

	if (lp_syslog() > 0) {
		syslog(audit_syslog_priority(handle),
		       "connect to service %s by user %s\n",
		       svc, user);
	}
	DEBUG(10, ("Connected to service %s as user %s\n",
	       svc, user));

	return 0;
}

static void audit_disconnect(vfs_handle_struct *handle)
{
	if (lp_syslog() > 0) {
		syslog(audit_syslog_priority(handle), "disconnected\n");
	}
	DEBUG(10, ("Disconnected from VFS module extd_audit\n"));
	SMB_VFS_NEXT_DISCONNECT(handle);

	return;
}

static int audit_mkdirat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			mode_t mode)
{
	struct smb_filename *full_fname = NULL;
	int result;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		errno = ENOMEM;
		return -1;
	}

	result = SMB_VFS_NEXT_MKDIRAT(handle,
			dirfsp,
			smb_fname,
			mode);

	if (lp_syslog() > 0) {
		syslog(audit_syslog_priority(handle), "mkdirat %s %s%s\n",
		       full_fname->base_name,
		       (result < 0) ? "failed: " : "",
		       (result < 0) ? strerror(errno) : "");
	}
	DEBUG(0, ("vfs_extd_audit: mkdirat %s %s %s\n",
	       full_fname->base_name,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	TALLOC_FREE(full_fname);
	return result;
}

static int audit_openat(vfs_handle_struct *handle,
			const struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			files_struct *fsp,
			const struct vfs_open_how *how)
{
	int ret;

	ret = SMB_VFS_NEXT_OPENAT(handle, dirfsp, smb_fname, fsp, how);

	if (lp_syslog() > 0) {
		syslog(audit_syslog_priority(handle),
		       "openat %s/%s (fd %d) %s%s%s\n",
		       smb_fname_str_dbg(fsp->fsp_name),
		       smb_fname->base_name,
		       ret,
		       ((how->flags & O_WRONLY) || (how->flags & O_RDWR)) ?
		       "for writing " : "",
		       (ret < 0) ? "failed: " : "",
		       (ret < 0) ? strerror(errno) : "");
	}
	DEBUG(2, ("vfs_extd_audit: open %s/%s %s %s\n",
	       smb_fname_str_dbg(fsp->fsp_name),
	       smb_fname_str_dbg(smb_fname),
	       (ret < 0) ? "failed: " : "",
	       (ret < 0) ? strerror(errno) : ""));

	return ret;
}

static int audit_close(vfs_handle_struct *handle, files_struct *fsp)
{
	int result;

	result = SMB_VFS_NEXT_CLOSE(handle, fsp);

	if (lp_syslog() > 0) {
		syslog(audit_syslog_priority(handle), "close fd %d %s%s\n",
		       fsp_get_pathref_fd(fsp),
		       (result < 0) ? "failed: " : "",
		       (result < 0) ? strerror(errno) : "");
	}
	DEBUG(2, ("vfs_extd_audit: close fd %d %s %s\n",
	       fsp_get_pathref_fd(fsp),
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static int audit_renameat(vfs_handle_struct *handle,
			  files_struct *src_dirfsp,
			  const struct smb_filename *smb_fname_src,
			  files_struct *dst_dirfsp,
			  const struct smb_filename *smb_fname_dst,
			  const struct vfs_rename_how *how)
{
	struct smb_filename *full_fname_src = NULL;
	struct smb_filename *full_fname_dst = NULL;
	int result;
	int saved_errno = 0;

	full_fname_src = full_path_from_dirfsp_atname(talloc_tos(),
						      src_dirfsp,
						      smb_fname_src);
	if (full_fname_src == NULL) {
		errno = ENOMEM;
		return -1;
	}

	full_fname_dst = full_path_from_dirfsp_atname(talloc_tos(),
						      dst_dirfsp,
						      smb_fname_dst);
	if (full_fname_dst == NULL) {
		TALLOC_FREE(full_fname_src);
		errno = ENOMEM;
		return -1;
	}

	result = SMB_VFS_NEXT_RENAMEAT(handle,
				       src_dirfsp,
				       smb_fname_src,
				       dst_dirfsp,
				       smb_fname_dst,
				       how);
	if (result == -1) {
		saved_errno = errno;
	}
	if (lp_syslog() > 0) {
		syslog(audit_syslog_priority(handle), "renameat %s -> %s %s%s\n",
		       full_fname_src->base_name,
		       full_fname_dst->base_name,
		       (result < 0) ? "failed: " : "",
		       (result < 0) ? strerror(saved_errno) : "");
	}
	DEBUG(1, ("vfs_extd_audit: renameat old: %s newname: %s  %s %s\n",
		smb_fname_str_dbg(full_fname_src),
		smb_fname_str_dbg(full_fname_dst),
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(saved_errno) : ""));

	TALLOC_FREE(full_fname_src);
	TALLOC_FREE(full_fname_dst);

	if (result == -1)  {
		errno = saved_errno;
	}
	return result;
}

static int audit_unlinkat(vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	struct smb_filename *full_fname = NULL;
	int result;

	full_fname = full_path_from_dirfsp_atname(talloc_tos(),
						  dirfsp,
						  smb_fname);
	if (full_fname == NULL) {
		return -1;
	}

	result = SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp,
			smb_fname,
			flags);

	if (lp_syslog() > 0) {
		syslog(audit_syslog_priority(handle), "unlinkat %s %s%s\n",
		       full_fname->base_name,
		       (result < 0) ? "failed: " : "",
		       (result < 0) ? strerror(errno) : "");
	}
	DBG_ERR("unlinkat %s %s %s\n",
	       smb_fname_str_dbg(full_fname),
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	TALLOC_FREE(full_fname);
	return result;
}

static int audit_fchmod(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	int result;

	result = SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);

	if (lp_syslog() > 0) {
		syslog(audit_syslog_priority(handle), "fchmod %s mode 0x%x %s%s\n",
		       fsp->fsp_name->base_name, mode,
		       (result < 0) ? "failed: " : "",
		       (result < 0) ? strerror(errno) : "");
	}
	DEBUG(1, ("vfs_extd_audit: fchmod %s mode 0x%x %s %s\n",
	       fsp_str_dbg(fsp), (unsigned int)mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static struct vfs_fn_pointers vfs_extd_audit_fns = {
	.connect_fn = audit_connect,
	.disconnect_fn = audit_disconnect,
	.mkdirat_fn = audit_mkdirat,
	.openat_fn = audit_openat,
	.close_fn = audit_close,
	.renameat_fn = audit_renameat,
	.unlinkat_fn = audit_unlinkat,
	.fchmod_fn = audit_fchmod,
};

static_decl_vfs;
NTSTATUS vfs_extd_audit_init(TALLOC_CTX *ctx)
{
	NTSTATUS ret = smb_register_vfs(SMB_VFS_INTERFACE_VERSION,
					"extd_audit", &vfs_extd_audit_fns);

	if (!NT_STATUS_IS_OK(ret))
		return ret;

	vfs_extd_audit_debug_level = debug_add_class("extd_audit");
	if (vfs_extd_audit_debug_level == -1) {
		vfs_extd_audit_debug_level = DBGC_VFS;
		DEBUG(0, ("vfs_extd_audit: Couldn't register custom debugging class!\n"));
	} else {
		DEBUG(10, ("vfs_extd_audit: Debug class number of 'extd_audit': %d\n", vfs_extd_audit_debug_level));
	}

	return ret;
}
