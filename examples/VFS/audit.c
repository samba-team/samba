/* 
 * Auditing VFS module for samba.  Log selected file operations to syslog
 * facility.
 *
 * Copyright (C) Tim Potter, 1999-2000
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "config.h"
#include <stdio.h>
#include <sys/stat.h>
#ifdef HAVE_UTIME_H
#include <utime.h>
#endif
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif
#include <syslog.h>
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <errno.h>
#include <string.h>
#include <includes.h>
#include <vfs.h>

#ifndef SYSLOG_FACILITY
#define SYSLOG_FACILITY   LOG_USER
#endif

#ifndef SYSLOG_PRIORITY
#define SYSLOG_PRIORITY   LOG_NOTICE
#endif

/* Function prototypes */

int audit_connect(struct connection_struct *conn, char *svc, char *user);
void audit_disconnect(struct connection_struct *conn);
DIR *audit_opendir(struct connection_struct *conn, const char *fname);
int audit_mkdir(struct connection_struct *conn, const char *path, mode_t mode);
int audit_rmdir(struct connection_struct *conn, const char *path);
int audit_open(struct connection_struct *conn, const char *fname, int flags, mode_t mode);
int audit_close(struct files_struct *fsp, int fd);
int audit_rename(struct connection_struct *conn, const char *old, const char *new);
int audit_unlink(struct connection_struct *conn, const char *path);
int audit_chmod(struct connection_struct *conn, const char *path, mode_t mode);
int audit_chmod_acl(struct connection_struct *conn, const char *name, mode_t mode);
int audit_fchmod(struct files_struct *fsp, int fd, mode_t mode);
int audit_fchmod_acl(struct files_struct *fsp, int fd, mode_t mode);

/* VFS operations */

extern struct vfs_ops default_vfs_ops;   /* For passthrough operation */

struct vfs_ops audit_ops = {
    
	/* Disk operations */

	audit_connect,
	audit_disconnect,
	NULL,                     /* disk free */

	/* Directory operations */

	audit_opendir,
	NULL,                     /* readdir */
	audit_mkdir,
	audit_rmdir,
	NULL,                     /* closedir */

	/* File operations */

	audit_open,
	audit_close,
	NULL,                     /* read  */
	NULL,                     /* write */
	NULL,                     /* lseek */
	audit_rename,
	NULL,                     /* fsync */
	NULL,                     /* stat  */
	NULL,                     /* fstat */
	NULL,                     /* lstat */
	audit_unlink,
	audit_chmod,
	audit_fchmod,
	NULL,                     /* chown */
	NULL,                     /* fchown */
	NULL,                     /* chdir */
	NULL,                     /* getwd */
	NULL,                     /* utime */
	NULL,                     /* ftruncate */
	NULL,                     /* lock */
	NULL,                     /* symlink */
	NULL,                     /* readlink */
	NULL,                     /* link */
	NULL,                     /* mknod */
	NULL,                     /* realpath */
	NULL,                     /* fget_nt_acl */
	NULL,                     /* get_nt_acl */
	NULL,                     /* fset_nt_acl */
	NULL,                      /* set_nt_acl */

	audit_chmod_acl,		/* chmod_acl */
	audit_fchmod_acl,		/* fchmod_acl */

	NULL,			/* sys_acl_get_entry */
	NULL,			/* sys_acl_get_tag_type */
	NULL,			/* sys_acl_get_permset */
	NULL,			/*sys_acl_get_qualifier */
	NULL,			/* sys_acl_get_file */
	NULL,			/* sys_acl_get_fd */
	NULL,			/* sys_acl_clear_perms */
	NULL,			/* sys_acl_add_perm */
	NULL,			/* sys_acl_to_text */
	NULL,			/* sys_acl_init */
	NULL,			/* sys_acl_create_entry */
	NULL,			/* sys_acl_set_tag_type */
	NULL,			/* sys_acl_set_qualifier */
	NULL,			/* sys_acl_set_permset */
	NULL,			/* sys_acl_valid */
	NULL,			/* sys_acl_set_file */
	NULL,			/* sys_acl_set_fd */
	NULL,			/* sys_acl_delete_def_file */
	NULL,			/* sys_acl_get_perm */
	NULL,			/* sys_acl_free_text */
	NULL,			/* sys_acl_free_acl */
	NULL			/* sys_acl_free_qualifier */
};

/* VFS initialisation function.  Return initialised vfs_ops structure
   back to SAMBA. */

struct vfs_ops *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops)
{
	struct vfs_ops tmp_ops;

	*vfs_version = SMB_VFS_INTERFACE_VERSION;
	memcpy(&tmp_ops, def_vfs_ops, sizeof(struct vfs_ops));

	tmp_ops.connect = audit_connect;
	tmp_ops.disconnect = audit_disconnect;
	tmp_ops.opendir = audit_opendir;
	tmp_ops.mkdir = audit_mkdir;
	tmp_ops.rmdir = audit_rmdir;
	tmp_ops.open = audit_open;
	tmp_ops.close = audit_close;
	tmp_ops.rename = audit_rename;
	tmp_ops.unlink = audit_unlink;
	tmp_ops.chmod = audit_chmod;
	tmp_ops.chmod_acl = audit_chmod_acl;
	tmp_ops.fchmod = audit_fchmod;
	tmp_ops.fchmod_acl = audit_fchmod_acl;

	memcpy(&audit_ops, &tmp_ops, sizeof(struct vfs_ops));

	openlog("smbd_audit", LOG_PID, SYSLOG_FACILITY);
	syslog(SYSLOG_PRIORITY, "VFS_INIT: vfs_ops loaded\n");
	return &audit_ops;
}

/* Implementation of vfs_ops.  Pass everything on to the default
   operation but log event first. */

int audit_connect(struct connection_struct *conn, char *svc, char *user)
{
	syslog(SYSLOG_PRIORITY, "connect to service %s by user %s\n", 
	       svc, user);

	return default_vfs_ops.connect(conn, svc, user);
}

void audit_disconnect(struct connection_struct *conn)
{
	syslog(SYSLOG_PRIORITY, "disconnected\n");
	default_vfs_ops.disconnect(conn);
}

DIR *audit_opendir(struct connection_struct *conn, const char *fname)
{
	DIR *result = default_vfs_ops.opendir(conn, fname);

	syslog(SYSLOG_PRIORITY, "opendir %s %s%s\n",
	       fname,
	       (result == NULL) ? "failed: " : "",
	       (result == NULL) ? strerror(errno) : "");

	return result;
}

int audit_mkdir(struct connection_struct *conn, const char *path, mode_t mode)
{
	int result = default_vfs_ops.mkdir(conn, path, mode);

	syslog(SYSLOG_PRIORITY, "mkdir %s %s%s\n", 
	       path,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;
}

int audit_rmdir(struct connection_struct *conn, const char *path)
{
	int result = default_vfs_ops.rmdir(conn, path);

	syslog(SYSLOG_PRIORITY, "rmdir %s %s%s\n", 
	       path, 
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;
}

int audit_open(struct connection_struct *conn, const char *fname, int flags, mode_t mode)
{
	int result = default_vfs_ops.open(conn, fname, flags, mode);

	syslog(SYSLOG_PRIORITY, "open %s (fd %d) %s%s%s\n", 
	       fname, result,
	       ((flags & O_WRONLY) || (flags & O_RDWR)) ? "for writing " : "", 
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;
}

int audit_close(struct files_struct *fsp, int fd)
{
	int result = default_vfs_ops.close(fsp, fd);

	syslog(SYSLOG_PRIORITY, "close fd %d %s%s\n",
	       fd,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;
}

int audit_rename(struct connection_struct *conn, const char *old, const char *new)
{
	int result = default_vfs_ops.rename(conn, old, new);

	syslog(SYSLOG_PRIORITY, "rename %s -> %s %s%s\n",
	       old, new,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;    
}

int audit_unlink(struct connection_struct *conn, const char *path)
{
	int result = default_vfs_ops.unlink(conn, path);

	syslog(SYSLOG_PRIORITY, "unlink %s %s%s\n",
	       path,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;
}

int audit_chmod(struct connection_struct *conn, const char *path, mode_t mode)
{
	int result = default_vfs_ops.chmod(conn, path, mode);

	syslog(SYSLOG_PRIORITY, "chmod %s mode 0x%x %s%s\n",
	       path, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;
}

int audit_chmod_acl(struct connection_struct *conn, const char *path, mode_t mode)
{
	int result = default_vfs_ops.chmod_acl(conn, path, mode);

	syslog(SYSLOG_PRIORITY, "chmod_acl %s mode 0x%x %s%s\n",
	       path, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;
}

int audit_fchmod(struct files_struct *fsp, int fd, mode_t mode)
{
	int result = default_vfs_ops.fchmod(fsp, fd, mode);

	syslog(SYSLOG_PRIORITY, "fchmod %s mode 0x%x %s%s\n",
	       fsp->fsp_name, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;
}

int audit_fchmod_acl(struct files_struct *fsp, int fd, mode_t mode)
{
	int result = default_vfs_ops.fchmod_acl(fsp, fd, mode);

	syslog(SYSLOG_PRIORITY, "fchmod_acl %s mode 0x%x %s%s\n",
	       fsp->fsp_name, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");

	return result;
}
