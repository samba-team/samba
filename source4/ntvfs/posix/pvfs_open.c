/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - open and close

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

#include "include/includes.h"
#include "vfs_posix.h"


/*
  find open file handle given fnum
*/
struct pvfs_file *pvfs_find_fd(struct pvfs_state *pvfs,
			       struct smbsrv_request *req, uint16_t fnum)
{
	struct pvfs_file *f;

	f = idr_find(pvfs->idtree_fnum, fnum);
	if (f == NULL) {
		return NULL;
	}

	if (req->session != f->session) {
		DEBUG(2,("pvfs_find_fd: attempt to use wrong session for fnum %d\n", 
			 fnum));
		return NULL;
	}

	return f;
}


/*
  cleanup a open directory handle
*/
static int pvfs_dir_fd_destructor(void *p)
{
	struct pvfs_file *f = p;
	DLIST_REMOVE(f->pvfs->open_files, f);
	idr_remove(f->pvfs->idtree_fnum, f->fnum);
	return 0;
}


/*
  open a directory
*/
static NTSTATUS pvfs_open_directory(struct pvfs_state *pvfs, 
				    struct smbsrv_request *req, 
				    struct pvfs_filename *name, 
				    union smb_open *io)
{
	struct pvfs_file *f;
	int fnum;
	NTSTATUS status;

	/* if the client says it must be a directory, and it isn't,
	   then fail */
	if (name->exists && !(name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY)) {
		return NT_STATUS_NOT_A_DIRECTORY;
	}

	f = talloc_p(req, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fnum = idr_get_new(pvfs->idtree_fnum, f, UINT16_MAX);
	if (fnum == -1) {
		talloc_free(f);
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	f->fnum = fnum;
	f->fd = -1;
	f->name = talloc_steal(f, name);
	f->session = req->session;
	f->smbpid = req->smbpid;
	f->pvfs = pvfs;
	f->pending_list = NULL;
	f->lock_count = 0;
	f->locking_key = data_blob(NULL, 0);

	/* setup a destructor to avoid leaks on abnormal termination */
	talloc_set_destructor(f, pvfs_dir_fd_destructor);

	switch (io->generic.in.open_disposition) {
	case NTCREATEX_DISP_OPEN_IF:
		break;

	case NTCREATEX_DISP_OPEN:
		if (!name->exists) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		break;

	case NTCREATEX_DISP_CREATE:
		if (name->exists) {
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
		break;

	case NTCREATEX_DISP_OVERWRITE_IF:
	case NTCREATEX_DISP_OVERWRITE:
	case NTCREATEX_DISP_SUPERSEDE:
	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (!name->exists) {
		if (mkdir(name->full_name, 0755) == -1) {
			return pvfs_map_errno(pvfs,errno);
		}
		status = pvfs_resolve_name(pvfs, req, io->ntcreatex.in.fname,
					   PVFS_RESOLVE_NO_WILDCARD, &name);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	if (!name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	DLIST_ADD(pvfs->open_files, f);

	/* the open succeeded, keep this handle permanently */
	talloc_steal(pvfs, f);

	ZERO_STRUCT(io->generic.out);
	
	io->generic.out.create_time  = name->dos.create_time;
	io->generic.out.access_time  = name->dos.access_time;
	io->generic.out.write_time   = name->dos.write_time;
	io->generic.out.change_time  = name->dos.change_time;
	io->generic.out.fnum         = f->fnum;
	io->generic.out.alloc_size   = 0;
	io->generic.out.size         = 0;
	io->generic.out.attrib       = name->dos.attrib;
	io->generic.out.is_directory = 1;

	return NT_STATUS_OK;
}


/*
  by using a destructor we make sure that abnormal cleanup will not 
  leak file descriptors (assuming at least the top level pointer is freed, which
  will cascade down to here)
*/
static int pvfs_fd_destructor(void *p)
{
	struct pvfs_file *f = p;

	DLIST_REMOVE(f->pvfs->open_files, f);

	pvfs_lock_close(f->pvfs, f);

	if (f->fd != -1) {
		close(f->fd);
		f->fd = -1;
	}

	idr_remove(f->pvfs->idtree_fnum, f->fnum);

	return 0;
}

/*
  open a file
  TODO: this is a temporary implementation derived from the simple backend
  its purpose is to allow other tests to run 
*/
NTSTATUS pvfs_open(struct ntvfs_module_context *ntvfs,
		   struct smbsrv_request *req, union smb_open *io)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	int fd, flags;
	struct pvfs_filename *name;
	struct pvfs_file *f;
	NTSTATUS status;
	struct {
		dev_t device;
		ino_t inode;
	} lock_context;
	int fnum;

	if (io->generic.level != RAW_OPEN_GENERIC) {
		return ntvfs_map_open(req, io, ntvfs);
	}

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, io->ntcreatex.in.fname,
				   PVFS_RESOLVE_NO_WILDCARD, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* directory opens are handled separately */
	if ((name->exists && (name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY)) ||
	    (io->generic.in.create_options & NTCREATEX_OPTIONS_DIRECTORY)) {
		return pvfs_open_directory(pvfs, req, name, io);
	}


	switch (io->generic.in.open_disposition) {
	case NTCREATEX_DISP_SUPERSEDE:
		if (!name->exists) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		flags = O_TRUNC;
		break;

	case NTCREATEX_DISP_OVERWRITE_IF:
		flags = O_CREAT | O_TRUNC;
		break;

	case NTCREATEX_DISP_OPEN:
		if (!name->exists) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		flags = 0;
		break;

	case NTCREATEX_DISP_OVERWRITE:
		if (!name->exists) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		flags = O_TRUNC;
		break;

	case NTCREATEX_DISP_CREATE:
		if (name->exists) {
			return NT_STATUS_OBJECT_NAME_COLLISION;
		}
		flags = O_CREAT | O_EXCL;
		break;

	case NTCREATEX_DISP_OPEN_IF:
		flags = O_CREAT;
		break;

	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	flags |= O_RDWR;

	f = talloc_p(req, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fnum = idr_get_new(pvfs->idtree_fnum, f, UINT16_MAX);
	if (fnum == -1) {
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	fd = open(name->full_name, flags, 0644);
	if (fd == -1) {
		if (errno == 0) {
			errno = ENOENT;
		}
		idr_remove(pvfs->idtree_fnum, fnum);
		return pvfs_map_errno(pvfs, errno);
	}

	/* re-resolve the open fd */
	status = pvfs_resolve_name_fd(pvfs, fd, name);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, fnum);
		return status;
	}

	f->fnum = fnum;
	f->fd = fd;
	f->name = talloc_steal(f, name);
	f->session = req->session;
	f->smbpid = req->smbpid;
	f->pvfs = pvfs;
	f->pending_list = NULL;
	f->lock_count = 0;

	/* we must zero here to take account of padding */
	ZERO_STRUCT(lock_context);
	lock_context.device = name->st.st_dev;
	lock_context.inode = name->st.st_ino;
	f->locking_key = data_blob_talloc(f, &lock_context, sizeof(lock_context));

	/* setup a destructor to avoid file descriptor leaks on
	   abnormal termination */
	talloc_set_destructor(f, pvfs_fd_destructor);

	DLIST_ADD(pvfs->open_files, f);

	ZERO_STRUCT(io->generic.out);
	
	io->generic.out.create_time = name->dos.create_time;
	io->generic.out.access_time = name->dos.access_time;
	io->generic.out.write_time = name->dos.write_time;
	io->generic.out.change_time = name->dos.change_time;
	io->generic.out.fnum = f->fnum;
	io->generic.out.alloc_size = name->dos.alloc_size;
	io->generic.out.size = name->st.st_size;
	io->generic.out.attrib = name->dos.attrib;
	io->generic.out.is_directory = (name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY)?1:0;

	/* success - keep the file handle */
	talloc_steal(pvfs, f);

	return NT_STATUS_OK;
}


/*
  close a file
*/
NTSTATUS pvfs_close(struct ntvfs_module_context *ntvfs,
		    struct smbsrv_request *req, union smb_close *io)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f;
	NTSTATUS status;

	if (io->generic.level != RAW_CLOSE_CLOSE) {
		return ntvfs_map_close(req, io, ntvfs);
	}

	f = pvfs_find_fd(pvfs, req, io->close.in.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (f->fd != -1 && 
	    close(f->fd) != 0) {
		status = pvfs_map_errno(pvfs, errno);
	} else {
		status = NT_STATUS_OK;
	}
	f->fd = -1;

	/* the destructor takes care of the rest */
	talloc_free(f);

	return status;
}


/*
  logoff - close all file descriptors open by a vuid
*/
NTSTATUS pvfs_logoff(struct ntvfs_module_context *ntvfs,
		     struct smbsrv_request *req)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f, *next;

	for (f=pvfs->open_files;f;f=next) {
		next = f->next;
		if (f->session == req->session) {
			DLIST_REMOVE(pvfs->open_files, f);
			talloc_free(f);
		}
	}

	return NT_STATUS_OK;
}


/*
  exit - close files for the current pid
*/
NTSTATUS pvfs_exit(struct ntvfs_module_context *ntvfs,
		   struct smbsrv_request *req)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f, *next;

	for (f=pvfs->open_files;f;f=next) {
		next = f->next;
		if (f->smbpid == req->smbpid) {
			DLIST_REMOVE(pvfs->open_files, f);
			talloc_free(f);
		}
	}

	return NT_STATUS_OK;
}
