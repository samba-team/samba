/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend

   Copyright (C) Andrew Tridgell 2004

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
/*
  this implements most of the POSIX NTVFS backend
  This is the default backend
*/

#include "include/includes.h"
#include "vfs_posix.h"


/*
  connect to a share - used when a tree_connect operation comes
  in. For a disk based backend we needs to ensure that the base
  directory exists (tho it doesn't need to be accessible by the user,
  that comes later)
*/
static NTSTATUS pvfs_connect(struct smbsrv_request *req, const char *sharename)
{
	struct smbsrv_tcon *tcon = req->tcon;
	struct pvfs_state *pvfs;
	struct stat st;

	DEBUG(0,("WARNING: the posix vfs handler is incomplete - you probably want \"ntvfs handler = simple\"\n"));

	pvfs = talloc_named(tcon, sizeof(struct pvfs_state), "pvfs_connect(%s)", sharename);
	if (pvfs == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	pvfs->base_directory = talloc_strdup(pvfs, lp_pathname(tcon->service));

	/* the directory must exist. Note that we deliberately don't
	   check that it is readable */
	if (stat(pvfs->base_directory, &st) != 0 || !S_ISDIR(st.st_mode)) {
		DEBUG(0,("pvfs_connect: '%s' is not a directory, when connecting to [%s]\n", 
			 pvfs->base_directory, sharename));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	tcon->fs_type = talloc_strdup(tcon, "NTFS");
	tcon->dev_type = talloc_strdup(tcon, "A:");

	return NT_STATUS_OK;
}

/*
  disconnect from a share
*/
static NTSTATUS pvfs_disconnect(struct smbsrv_tcon *tcon)
{
	return NT_STATUS_OK;
}

/*
  delete a file - the dirtype specifies the file types to include in the search. 
  The name can contain CIFS wildcards, but rarely does (except with OS/2 clients)
*/
static NTSTATUS pvfs_unlink(struct smbsrv_request *req, struct smb_unlink *unl)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  ioctl interface - we don't do any
*/
static NTSTATUS pvfs_ioctl(struct smbsrv_request *req, union smb_ioctl *io)
{
	return NT_STATUS_INVALID_PARAMETER;
}

/*
  check if a directory exists
*/
static NTSTATUS pvfs_chkpath(struct smbsrv_request *req, struct smb_chkpath *cp)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  return info on a pathname
*/
static NTSTATUS pvfs_qpathinfo(struct smbsrv_request *req, union smb_fileinfo *info)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  query info on a open file
*/
static NTSTATUS pvfs_qfileinfo(struct smbsrv_request *req, union smb_fileinfo *info)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  open a file
*/
static NTSTATUS pvfs_open(struct smbsrv_request *req, union smb_open *io)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  create a directory
*/
static NTSTATUS pvfs_mkdir(struct smbsrv_request *req, union smb_mkdir *md)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  remove a directory
*/
static NTSTATUS pvfs_rmdir(struct smbsrv_request *req, struct smb_rmdir *rd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  rename a set of files
*/
static NTSTATUS pvfs_rename(struct smbsrv_request *req, union smb_rename *ren)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  copy a set of files
*/
static NTSTATUS pvfs_copy(struct smbsrv_request *req, struct smb_copy *cp)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  read from a file
*/
static NTSTATUS pvfs_read(struct smbsrv_request *req, union smb_read *rd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  write to a file
*/
static NTSTATUS pvfs_write(struct smbsrv_request *req, union smb_write *wr)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  seek in a file
*/
static NTSTATUS pvfs_seek(struct smbsrv_request *req, struct smb_seek *io)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  flush a file
*/
static NTSTATUS pvfs_flush(struct smbsrv_request *req, struct smb_flush *io)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  close a file
*/
static NTSTATUS pvfs_close(struct smbsrv_request *req, union smb_close *io)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  exit - closing files?
*/
static NTSTATUS pvfs_exit(struct smbsrv_request *req)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  lock a byte range
*/
static NTSTATUS pvfs_lock(struct smbsrv_request *req, union smb_lock *lck)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  set info on a pathname
*/
static NTSTATUS pvfs_setpathinfo(struct smbsrv_request *req, union smb_setfileinfo *st)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  set info on a open file
*/
static NTSTATUS pvfs_setfileinfo(struct smbsrv_request *req, 
				 union smb_setfileinfo *info)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}


/*
  return filesystem space info
*/
static NTSTATUS pvfs_fsinfo(struct smbsrv_request *req, union smb_fsinfo *fs)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  return print queue info
*/
static NTSTATUS pvfs_lpq(struct smbsrv_request *req, union smb_lpq *lpq)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/* 
   list files in a directory matching a wildcard pattern
*/
static NTSTATUS pvfs_search_first(struct smbsrv_request *req, union smb_search_first *io, 
				  void *search_private, 
				  BOOL (*callback)(void *, union smb_search_data *))
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* continue a search */
static NTSTATUS pvfs_search_next(struct smbsrv_request *req, union smb_search_next *io, 
				 void *search_private, 
				 BOOL (*callback)(void *, union smb_search_data *))
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* close a search */
static NTSTATUS pvfs_search_close(struct smbsrv_request *req, union smb_search_close *io)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* SMBtrans - not used on file shares */
static NTSTATUS pvfs_trans(struct smbsrv_request *req, struct smb_trans2 *trans2)
{
	return NT_STATUS_ACCESS_DENIED;
}

/*
  initialialise the POSIX disk backend, registering ourselves with the ntvfs subsystem
 */
NTSTATUS ntvfs_posix_init(void)
{
	NTSTATUS ret;
	struct ntvfs_ops ops;

	ZERO_STRUCT(ops);

	ops.type = NTVFS_DISK;
	
	/* fill in all the operations */
	ops.connect = pvfs_connect;
	ops.disconnect = pvfs_disconnect;
	ops.unlink = pvfs_unlink;
	ops.chkpath = pvfs_chkpath;
	ops.qpathinfo = pvfs_qpathinfo;
	ops.setpathinfo = pvfs_setpathinfo;
	ops.open = pvfs_open;
	ops.mkdir = pvfs_mkdir;
	ops.rmdir = pvfs_rmdir;
	ops.rename = pvfs_rename;
	ops.copy = pvfs_copy;
	ops.ioctl = pvfs_ioctl;
	ops.read = pvfs_read;
	ops.write = pvfs_write;
	ops.seek = pvfs_seek;
	ops.flush = pvfs_flush;	
	ops.close = pvfs_close;
	ops.exit = pvfs_exit;
	ops.lock = pvfs_lock;
	ops.setfileinfo = pvfs_setfileinfo;
	ops.qfileinfo = pvfs_qfileinfo;
	ops.fsinfo = pvfs_fsinfo;
	ops.lpq = pvfs_lpq;
	ops.search_first = pvfs_search_first;
	ops.search_next = pvfs_search_next;
	ops.search_close = pvfs_search_close;
	ops.trans = pvfs_trans;

	/* register ourselves with the NTVFS subsystem. We register
	   under the name 'default' as we wish to be the default
	   backend, and also register as 'posix' */
	ops.name = "default";
	ret = register_backend("ntvfs", &ops);

	ops.name = "posix";
	ret = register_backend("ntvfs", &ops);

	if (!NT_STATUS_IS_OK(ret)) {
		DEBUG(0,("Failed to register POSIX backend!\n"));
	}

	return ret;
}
