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
  setup config options for a posix share
*/
static void pvfs_setup_options(struct pvfs_state *pvfs)
{
	int snum = pvfs->tcon->service;

	if (lp_map_hidden(snum))     pvfs->flags |= PVFS_FLAG_MAP_HIDDEN;
	if (lp_map_archive(snum))    pvfs->flags |= PVFS_FLAG_MAP_ARCHIVE;
	if (lp_map_system(snum))     pvfs->flags |= PVFS_FLAG_MAP_SYSTEM;
	if (lp_readonly(snum))       pvfs->flags |= PVFS_FLAG_READONLY;
	if (lp_strict_sync(snum))    pvfs->flags |= PVFS_FLAG_STRICT_SYNC;
	if (lp_strict_locking(snum)) pvfs->flags |= PVFS_FLAG_STRICT_LOCKING;
	if (lp_ci_filesystem(snum))  pvfs->flags |= PVFS_FLAG_CI_FILESYSTEM;

	pvfs->share_name = talloc_strdup(pvfs, lp_servicename(snum));
}


/*
  connect to a share - used when a tree_connect operation comes
  in. For a disk based backend we needs to ensure that the base
  directory exists (tho it doesn't need to be accessible by the user,
  that comes later)
*/
static NTSTATUS pvfs_connect(struct ntvfs_module_context *ntvfs,
			     struct smbsrv_request *req, const char *sharename)
{
	struct smbsrv_tcon *tcon = req->tcon;
	struct pvfs_state *pvfs;
	struct stat st;
	char *base_directory;
	NTSTATUS status;

	pvfs = talloc_zero_p(tcon, struct pvfs_state);
	if (pvfs == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* for simplicity of path construction, remove any trailing slash now */
	base_directory = talloc_strdup(pvfs, lp_pathname(tcon->service));
	trim_string(base_directory, NULL, "/");

	pvfs->tcon = tcon;
	pvfs->base_directory = base_directory;

	/* the directory must exist. Note that we deliberately don't
	   check that it is readable */
	if (stat(pvfs->base_directory, &st) != 0 || !S_ISDIR(st.st_mode)) {
		DEBUG(0,("pvfs_connect: '%s' is not a directory, when connecting to [%s]\n", 
			 pvfs->base_directory, sharename));
		return NT_STATUS_BAD_NETWORK_NAME;
	}

	tcon->fs_type = talloc_strdup(tcon, "NTFS");
	tcon->dev_type = talloc_strdup(tcon, "A:");

	ntvfs->private_data = pvfs;

	pvfs->brl_context = brl_init(pvfs, 
				     pvfs->tcon->smb_conn->connection->server_id,  
				     pvfs->tcon->service,
				     pvfs->tcon->smb_conn->connection->messaging_ctx);
	if (pvfs->brl_context == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	pvfs->odb_context = odb_init(pvfs, 
				     pvfs->tcon->smb_conn->connection->server_id,  
				     pvfs->tcon->service,
				     pvfs->tcon->smb_conn->connection->messaging_ctx);
	if (pvfs->odb_context == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* allocate the fnum id -> ptr tree */
	pvfs->idtree_fnum = idr_init(pvfs);
	if (pvfs->idtree_fnum == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* allocate the search handle -> ptr tree */
	pvfs->idtree_search = idr_init(pvfs);
	if (pvfs->idtree_search == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pvfs_mangle_init(pvfs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	pvfs_setup_options(pvfs);

#ifdef SIGXFSZ
	/* who had the stupid idea to generate a signal on a large
	   file write instead of just failing it!? */
	BlockSignals(True, SIGXFSZ);
#endif

	return NT_STATUS_OK;
}

/*
  disconnect from a share
*/
static NTSTATUS pvfs_disconnect(struct ntvfs_module_context *ntvfs,
				struct smbsrv_tcon *tcon)
{
	return NT_STATUS_OK;
}

/*
  check if a directory exists
*/
static NTSTATUS pvfs_chkpath(struct ntvfs_module_context *ntvfs,
			     struct smbsrv_request *req, struct smb_chkpath *cp)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_filename *name;
	NTSTATUS status;

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, cp->in.path, 
				   PVFS_RESOLVE_NO_WILDCARD, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (!S_ISDIR(name->st.st_mode)) {
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	return NT_STATUS_OK;
}

/*
  copy a set of files
*/
static NTSTATUS pvfs_copy(struct ntvfs_module_context *ntvfs,
			  struct smbsrv_request *req, struct smb_copy *cp)
{
	DEBUG(0,("pvfs_copy not implemented\n"));
	return NT_STATUS_NOT_SUPPORTED;
}

/*
  return print queue info
*/
static NTSTATUS pvfs_lpq(struct ntvfs_module_context *ntvfs,
			 struct smbsrv_request *req, union smb_lpq *lpq)
{
	return NT_STATUS_NOT_SUPPORTED;
}

/* SMBtrans - not used on file shares */
static NTSTATUS pvfs_trans(struct ntvfs_module_context *ntvfs,
			   struct smbsrv_request *req, struct smb_trans2 *trans2)
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
	ops.openfile = pvfs_open;
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
	ops.logoff = pvfs_logoff;
	ops.async_setup = pvfs_async_setup;

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
