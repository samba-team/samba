/* 
 * Auditing VFS module for samba.  Log selected file operations to syslog
 * facility.
 *
 * Copyright (C) 2001, Brandon Stone, Amherst College, <bbstone@amherst.edu>.
 * Copyright (C) 2002, Jeremy Allison - modified to make a VFS module.
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
 
/* VFS operations */

extern struct vfs_ops default_vfs_ops;   /* For passthrough operation */

static int recycle_unlink(connection_struct *, const char *);
static int recycle_connect(struct connection_struct *conn, const char *service, const char *user);
static void recycle_disconnect(struct connection_struct *conn);

struct vfs_ops recycle_ops = {
    
	/* Disk operations */

	recycle_connect,		/* connect */
	recycle_disconnect,		/* disconnect */
	NULL,				/* disk free */

	/* Directory operations */

	NULL,				/* opendir */
	NULL,				/* readdir */
	NULL,				/* mkdir */
	NULL,				/* rmdir */
	NULL,				/* closedir */

	/* File operations */

	NULL,				/* open */
	NULL,				/* close */
	NULL,				/* read  */
	NULL,				/* write */
	NULL,				/* lseek */
	NULL,				/* rename */
	NULL,				/* fsync */
	NULL,				/* stat  */
	NULL,				/* fstat */
	NULL,				/* lstat */
	recycle_unlink,
	NULL,				/* chmod */
	NULL,				/* fchmod */
	NULL,				/* chown */
	NULL,				/* fchown */
	NULL,				/* chdir */
	NULL,				/* getwd */
	NULL,				/* utime */
	NULL,				/* ftruncate */
	NULL,				/* lock */
	NULL,				/* symlink */
	NULL,				/* readlink */
	NULL,				/* link */
	NULL,				/* mknod */
	NULL,				/* realpath */
	NULL,				/* fget_nt_acl */
	NULL,				/* get_nt_acl */
	NULL,				/* fset_nt_acl */
	NULL,				/* set_nt_acl */

	NULL,				/* chmod_acl */
	NULL,				/* fchmod_acl */

	NULL,				/* sys_acl_get_entry */
	NULL,				/* sys_acl_get_tag_type */
	NULL,				/* sys_acl_get_permset */
	NULL,				/* sys_acl_get_qualifier */
	NULL,				/* sys_acl_get_file */
	NULL,				/* sys_acl_get_fd */
	NULL,				/* sys_acl_clear_perms */
	NULL,				/* sys_acl_add_perm */
	NULL,				/* sys_acl_to_text */
	NULL,				/* sys_acl_init */
	NULL,				/* sys_acl_create_entry */
	NULL,				/* sys_acl_set_tag_type */
	NULL,				/* sys_acl_set_qualifier */
	NULL,				/* sys_acl_set_permset */
	NULL,				/* sys_acl_valid */
	NULL,				/* sys_acl_set_file */
	NULL,				/* sys_acl_set_fd */
	NULL,				/* sys_acl_delete_def_file */
	NULL,				/* sys_acl_get_perm */
	NULL,				/* sys_acl_free_text */
	NULL,				/* sys_acl_free_acl */
	NULL				/* sys_acl_free_qualifier */
};

/* VFS initialisation function.  Return initialised vfs_ops structure
   back to SAMBA. */

struct vfs_ops *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops)
{
	struct vfs_ops tmp_ops;

	*vfs_version = SMB_VFS_INTERFACE_VERSION;
	memcpy(&tmp_ops, def_vfs_ops, sizeof(struct vfs_ops));
	tmp_ops.unlink = recycle_unlink;
	tmp_ops.connect = recycle_connect;
	tmp_ops.disconnect = recycle_disconnect;
	memcpy(&recycle_ops, &tmp_ops, sizeof(struct vfs_ops));
	return &recycle_ops;
}

static int recycle_connect(struct connection_struct *conn, const char *service, const char *user)
{
	pstring opts_str;
	fstring recycle_bin;
	char *p;

	DEBUG(3,("recycle_connect: called for service %s as user %s\n", service, user));

	pstrcpy(opts_str, (const char *)lp_vfs_options(SNUM(conn)));
	if (!*opts_str) {
		DEBUG(3,("recycle_connect: No options listed (%s).\n", lp_vfs_options(SNUM(conn)) ));
		return 0; /* No options. */
	}

	p = opts_str;
	if (next_token(&p,recycle_bin,"=",sizeof(recycle_bin))) {
		if (!strequal("recycle", recycle_bin)) {
			DEBUG(3,("recycle_connect: option %s is not recycle\n", recycle_bin ));
			return -1;
		}
	}

	if (!next_token(&p,recycle_bin," \n",sizeof(recycle_bin))) {
		DEBUG(3,("recycle_connect: no option after recycle=\n"));
		return -1;
	}

	DEBUG(10,("recycle_connect: recycle name is %s\n", recycle_bin ));

	conn->vfs_private = (void *)strdup(recycle_bin);
	return 0;
}

static void recycle_disconnect(struct connection_struct *conn)
{
	SAFE_FREE(conn->vfs_private);
}

static BOOL recycle_XXX_exist(connection_struct *conn, const char *dname, BOOL isdir)
{
        SMB_STRUCT_STAT st;

        if (default_vfs_ops.stat(conn,dname,&st) != 0)
                return(False);

	if (isdir)
	        return S_ISDIR(st.st_mode) ? True : False;
	else
		return S_ISREG(st.st_mode) ? True : False;
}

static BOOL recycle_directory_exist(connection_struct *conn, const char *dname)
{
	return recycle_XXX_exist(conn, dname, True);
}

static BOOL recycle_file_exist(connection_struct *conn, const char *fname)
{
	return recycle_XXX_exist(conn, fname, False);
}

static SMB_OFF_T recycle_get_file_size(connection_struct *conn, const char *fname)
{
        SMB_STRUCT_STAT st;

        if (default_vfs_ops.stat(conn,fname,&st) != 0)
		return (SMB_OFF_T)-1;

	return(st.st_size);
}

/********************************************************************
 Check if file should be recycled
*********************************************************************/

static int recycle_unlink(connection_struct *conn, const char *inname)
{
	fstring recycle_bin;
	pstring fname;
	char *base, *ext;
	pstring bin;
	int i=1, len, addlen;
	int dir_mask=0700;
	SMB_BIG_UINT dfree,dsize,bsize;

	*recycle_bin = '\0';
	pstrcpy(fname, inname);

	if (conn->vfs_private)
		fstrcpy(recycle_bin, (const char *)conn->vfs_private);

	if(!*recycle_bin) {
		DEBUG(3, ("recycle bin: share parameter not set, purging %s...\n", fname));
		return default_vfs_ops.unlink(conn,fname);
	}

	if(recycle_get_file_size(conn, fname) == 0) {
		DEBUG(3, ("recycle bin: file %s is empty, purging...\n", fname));
		return default_vfs_ops.unlink(conn,fname);
	}

	base = strrchr(fname, '/') + 1;
	if(base == (char*)1)
		ext = strrchr(fname, '.');
	else
		ext = strrchr(base, '.');

	pstrcpy(bin, recycle_bin);
	pstrcat(bin, "/");
	pstrcat(bin, base);

	if(strcmp(fname,bin) == 0) {
		DEBUG(3, ("recycle bin: file %s exists, purging...\n", fname));
		return default_vfs_ops.unlink(conn,fname);
	}

	len = strlen(bin);
	addlen = sizeof(pstring)-len-1;
	while(recycle_file_exist(conn,bin)) {
		slprintf(bin+len, addlen, " (Copy #%d)", i++);
		pstrcat(bin, ext);
	}

	DEBUG(3, ("recycle bin: moving source=%s to  dest=%s\n", fname, bin));
	default_vfs_ops.disk_free(conn,".",True,&bsize,&dfree,&dsize);
	if((unsigned int)dfree > 0) {
		int ret;
		if(!recycle_directory_exist(conn,recycle_bin)) {
			DEBUG(3, ("recycle bin: directory %s nonexistant, creating...\n", recycle_bin));
			if (default_vfs_ops.mkdir(conn,recycle_bin,dir_mask) == -1) {
				DEBUG(3, ("recycle bin: unable to create directory %s. Error was %s\n",
					recycle_bin, strerror(errno) ));
			}
		}
		DEBUG(3, ("recycle bin: move %s -> %s\n", fname, bin));

		ret = default_vfs_ops.rename(conn, fname, bin);
		if (ret == -1)
			DEBUG(3, ("recycle bin: move error %d (%s)\n", errno, strerror(errno) ));
		return ret;
	} else { 
		DEBUG(3, ("recycle bin: move failed, purging...\n"));
		return default_vfs_ops.unlink(conn,fname);
	}
}
