/* 
 * Auditing VFS module for samba.  Log selected file operations to syslog
 * facility.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) John H Terpstra, 2003
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

static int audit_connect(struct connection_struct *conn, const char *svc, const char *user);
static void audit_disconnect(struct connection_struct *conn);
static DIR *audit_opendir(struct connection_struct *conn, const char *fname);
static int audit_mkdir(struct connection_struct *conn, const char *path, mode_t mode);
static int audit_rmdir(struct connection_struct *conn, const char *path);
static int audit_open(struct connection_struct *conn, const char *fname, int flags, mode_t mode);
static int audit_close(struct files_struct *fsp, int fd);
static int audit_rename(struct connection_struct *conn, const char *old, const char *new);
static int audit_unlink(struct connection_struct *conn, const char *path);
static int audit_chmod(struct connection_struct *conn, const char *path, mode_t mode);
static int audit_chmod_acl(struct connection_struct *conn, const char *name, mode_t mode);
static int audit_fchmod(struct files_struct *fsp, int fd, mode_t mode);
static int audit_fchmod_acl(struct files_struct *fsp, int fd, mode_t mode);

/* VFS operations */

static struct vfs_ops default_vfs_ops;   /* For passthrough operation */
static struct smb_vfs_handle_struct *audit_handle;

static vfs_op_tuple audit_ops[] = {
    
	/* Disk operations */

	{audit_connect, 	SMB_VFS_OP_CONNECT, 	SMB_VFS_LAYER_LOGGER},
	{audit_disconnect, 	SMB_VFS_OP_DISCONNECT, 	SMB_VFS_LAYER_LOGGER},

	/* Directory operations */

	{audit_opendir, 	SMB_VFS_OP_OPENDIR, 	SMB_VFS_LAYER_LOGGER},
	{audit_mkdir, 		SMB_VFS_OP_MKDIR, 	SMB_VFS_LAYER_LOGGER},
	{audit_rmdir, 		SMB_VFS_OP_RMDIR, 	SMB_VFS_LAYER_LOGGER},

	/* File operations */

	{audit_open, 		SMB_VFS_OP_OPEN, 	SMB_VFS_LAYER_LOGGER},
	{audit_close, 		SMB_VFS_OP_CLOSE, 	SMB_VFS_LAYER_LOGGER},
	{audit_rename, 		SMB_VFS_OP_RENAME, 	SMB_VFS_LAYER_LOGGER},
	{audit_unlink, 		SMB_VFS_OP_UNLINK, 	SMB_VFS_LAYER_LOGGER},
	{audit_chmod, 		SMB_VFS_OP_CHMOD, 	SMB_VFS_LAYER_LOGGER},
	{audit_fchmod, 		SMB_VFS_OP_FCHMOD, 	SMB_VFS_LAYER_LOGGER},
	{audit_chmod_acl, 	SMB_VFS_OP_CHMOD_ACL, 	SMB_VFS_LAYER_LOGGER},
	{audit_fchmod_acl, 	SMB_VFS_OP_FCHMOD_ACL, 	SMB_VFS_LAYER_LOGGER},
	
	/* Finish VFS operations definition */
	
	{NULL, 			SMB_VFS_OP_NOOP, 	SMB_VFS_LAYER_NOOP}
};

/* VFS initialisation function.  Return vfs_op_tuple array back to SAMBA. */

vfs_op_tuple *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops, 
			struct smb_vfs_handle_struct *vfs_handle)
{
	*vfs_version = SMB_VFS_INTERFACE_VERSION;
	memcpy(&default_vfs_ops, def_vfs_ops, sizeof(struct vfs_ops));
	
	audit_handle = vfs_handle;

	openlog("smbd_audit", LOG_PID, SYSLOG_FACILITY);
	syslog(SYSLOG_PRIORITY, "VFS_INIT: vfs_ops loaded\n");

	return audit_ops;
}

/* VFS finalization function. */

void vfs_done(connection_struct *conn)
{
	syslog(SYSLOG_PRIORITY, "VFS_DONE: vfs module unloaded\n");
}

/* Implementation of vfs_ops.  Pass everything on to the default
   operation but log event first. */

static int audit_connect(struct connection_struct *conn, const char *svc, const char *user)
{
	syslog(SYSLOG_PRIORITY, "connect to service %s by user %s\n", 
	       svc, user);
	DEBUG(10, ("Connected to service %s as user %s\n",
	       svc, user));

	return default_vfs_ops.connect(conn, svc, user);
}

static void audit_disconnect(struct connection_struct *conn)
{
	syslog(SYSLOG_PRIORITY, "disconnected\n");
	DEBUG(10, ("Disconnected from VFS module extd_audit\n"));

	default_vfs_ops.disconnect(conn);
}

static DIR *audit_opendir(struct connection_struct *conn, const char *fname)
{
	DIR *result = default_vfs_ops.opendir(conn, fname);

	syslog(SYSLOG_PRIORITY, "opendir %s %s%s\n",
	       fname,
	       (result == NULL) ? "failed: " : "",
	       (result == NULL) ? strerror(errno) : "");
	DEBUG(1, ("vfs_extd_audit: opendir %s %s %s",
	       fname,
	       (result == NULL) ? "failed: " : "",
	       (result == NULL) ? strerror(errno) : ""));

	return result;
}

static int audit_mkdir(struct connection_struct *conn, const char *path, mode_t mode)
{
	int result = default_vfs_ops.mkdir(conn, path, mode);

	syslog(SYSLOG_PRIORITY, "mkdir %s %s%s\n", 
	       path,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(0, ("vfs_extd_audit: mkdir %s %s %s\n",
	       path,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static int audit_rmdir(struct connection_struct *conn, const char *path)
{
	int result = default_vfs_ops.rmdir(conn, path);

	syslog(SYSLOG_PRIORITY, "rmdir %s %s%s\n", 
	       path, 
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(0, ("vfs_extd_audit: rmdir %s %s %s\n",
               path,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static int audit_open(struct connection_struct *conn, const char *fname, int flags, mode_t mode)
{
	int result = default_vfs_ops.open(conn, fname, flags, mode);

	syslog(SYSLOG_PRIORITY, "open %s (fd %d) %s%s%s\n", 
	       fname, result,
	       ((flags & O_WRONLY) || (flags & O_RDWR)) ? "for writing " : "", 
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(2, ("vfs_extd_audit: open %s %s %s\n",
	       fname,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static int audit_close(struct files_struct *fsp, int fd)
{
	int result = default_vfs_ops.close(fsp, fd);

	syslog(SYSLOG_PRIORITY, "close fd %d %s%s\n",
	       fd,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(2, ("vfs_extd_audit: close fd %d %s %s\n",
	       fd,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static int audit_rename(struct connection_struct *conn, const char *old, const char *new)
{
	int result = default_vfs_ops.rename(conn, old, new);

	syslog(SYSLOG_PRIORITY, "rename %s -> %s %s%s\n",
	       old, new,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(1, ("vfs_extd_audit: rename old: %s new: %s  %s %s\n",
	       old, new,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;    
}

static int audit_unlink(struct connection_struct *conn, const char *path)
{
	int result = default_vfs_ops.unlink(conn, path);

	syslog(SYSLOG_PRIORITY, "unlink %s %s%s\n",
	       path,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(0, ("vfs_extd_audit: unlink %s %s %s\n",
	       path,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static int audit_chmod(struct connection_struct *conn, const char *path, mode_t mode)
{
	int result = default_vfs_ops.chmod(conn, path, mode);

	syslog(SYSLOG_PRIORITY, "chmod %s mode 0x%x %s%s\n",
	       path, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(1, ("vfs_extd_audit: chmod %s mode 0x%x %s %s\n",
	       path, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static int audit_chmod_acl(struct connection_struct *conn, const char *path, mode_t mode)
{
	int result = default_vfs_ops.chmod_acl(conn, path, mode);

	syslog(SYSLOG_PRIORITY, "chmod_acl %s mode 0x%x %s%s\n",
	       path, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(1, ("vfs_extd_audit: chmod_acl %s mode 0x%x %s %s\n",
	        path, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static int audit_fchmod(struct files_struct *fsp, int fd, mode_t mode)
{
	int result = default_vfs_ops.fchmod(fsp, fd, mode);

	syslog(SYSLOG_PRIORITY, "fchmod %s mode 0x%x %s%s\n",
	       fsp->fsp_name, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(1, ("vfs_extd_audit: fchmod %s mode 0x%x %s %s",
	       fsp->fsp_name,  mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}

static int audit_fchmod_acl(struct files_struct *fsp, int fd, mode_t mode)
{
	int result = default_vfs_ops.fchmod_acl(fsp, fd, mode);

	syslog(SYSLOG_PRIORITY, "fchmod_acl %s mode 0x%x %s%s\n",
	       fsp->fsp_name, mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : "");
	DEBUG(1, ("vfs_extd_audit: fchmod_acl %s mode 0x%x %s %s",
	       fsp->fsp_name,  mode,
	       (result < 0) ? "failed: " : "",
	       (result < 0) ? strerror(errno) : ""));

	return result;
}
