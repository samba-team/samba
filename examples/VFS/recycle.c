/* 
 * Auditing VFS module for samba.  Log selected file operations to syslog
 * facility.
 *
 * Copyright (C) 2001, Brandon Stone, Amherst College, <bbstone@amherst.edu>.
 * Copyright (C) 2002, Jeremy Allison - modified to make a VFS module.
 * Copyright (C) 2002, Alexander Bokovoy - cascaded VFS adoption,
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

static struct vfs_ops default_vfs_ops;   /* For passthrough operation */
static struct smb_vfs_handle_struct *recycle_handle;
static int recycle_unlink(connection_struct *, const char *);
static int recycle_connect(struct connection_struct *conn, const char *service, const char *user);
static void recycle_disconnect(struct connection_struct *conn);

static vfs_op_tuple recycle_ops[] = {

	/* Disk operations */

	{recycle_connect,	SMB_VFS_OP_CONNECT,	SMB_VFS_LAYER_OPAQUE},
	{recycle_disconnect,	SMB_VFS_OP_DISCONNECT,	SMB_VFS_LAYER_OPAQUE},

	/* File operations */
	
	{recycle_unlink,	SMB_VFS_OP_UNLINK,	SMB_VFS_LAYER_OPAQUE},
	
	{NULL,			SMB_VFS_OP_NOOP,	SMB_VFS_LAYER_NOOP}
};

/* VFS initialisation function.  Return initialised vfs_op_tuple array back to SAMBA. */

vfs_op_tuple *vfs_init(int *vfs_version, struct vfs_ops *def_vfs_ops,
			struct smb_vfs_handle_struct *vfs_handle)
{
	*vfs_version = SMB_VFS_INTERFACE_VERSION;
	memcpy(&default_vfs_ops, def_vfs_ops, sizeof(struct vfs_ops));
	
	/* Remember vfs_id for storing private information at connect */
	recycle_handle = vfs_handle;

	return recycle_ops;
}

/* VFS finalization function. */
void vfs_done(connection_struct *conn)
{
	DEBUG(3,("vfs_done_recycle: called for connection %p\n",conn));
}

static int recycle_connect(struct connection_struct *conn, const char *service, const char *user)
{
	fstring recycle_bin;

	DEBUG(3,("recycle_connect: called for service %s as user %s\n", service, user));

	fstrcpy(recycle_bin, (const char *)lp_parm_string(lp_servicename(SNUM(conn)),"vfs","recycle bin"));
	if (!*recycle_bin) {
		DEBUG(3,("recycle_connect: No options listed (vfs:recycle bin).\n" ));
		return 0; /* No options. */
	}

	DEBUG(3,("recycle_connect: recycle name is %s\n", recycle_bin ));

	recycle_handle->data = (void *)strdup(recycle_bin);
	return 0;
}

static void recycle_disconnect(struct connection_struct *conn)
{
	SAFE_FREE(recycle_handle->data);
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
	int dir_mask=0770;
	SMB_BIG_UINT dfree,dsize,bsize;

	*recycle_bin = '\0';
	pstrcpy(fname, inname);

	if (recycle_handle->data)
		fstrcpy(recycle_bin, (const char *)recycle_handle->data);

	if(!*recycle_bin) {
		DEBUG(3, ("recycle bin: share parameter not set, purging %s...\n", fname));
		return default_vfs_ops.unlink(conn,fname);
	}

	if(recycle_get_file_size(conn, fname) == 0) {
		DEBUG(3, ("recycle bin: file %s is empty, purging...\n", fname));
		return default_vfs_ops.unlink(conn,fname);
	}

	base = strrchr(fname, '/');
	pstrcpy(bin, recycle_bin);
	pstrcat(bin, "/");

	if(base == NULL) {
		ext = strrchr(fname, '.');
		pstrcat(bin, fname);
	} else {
		ext = strrchr(base, '.');
		pstrcat(bin, base+1);
	}
	DEBUG(3, ("recycle bin: base %s, ext %s, fname %s, bin %s\n", base, ext, fname, bin));

	if(strcmp(fname,bin) == 0) {
		DEBUG(3, ("recycle bin: file %s exists, purging...\n", fname));
		return default_vfs_ops.unlink(conn,fname);
	}

	len = strlen(bin);
	if ( ext != NULL)
		len = len - strlen(ext);

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
		if (ret == -1) {
			DEBUG(3, ("recycle bin: move error %d (%s)\n", errno, strerror(errno) ));
			DEBUG(3, ("recycle bin: move failed, purging...\n"));
			return default_vfs_ops.unlink(conn,fname);
		}
		return ret;
	} else { 
		DEBUG(3, ("recycle bin: move failed, purging...\n"));
		return default_vfs_ops.unlink(conn,fname);
	}
}
