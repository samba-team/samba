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
#include "system/time.h"
#include "system/filesys.h"

/*
  create file handles with convenient numbers for sniffers
*/
#define PVFS_MIN_FILE_FNUM 0x100
#define PVFS_MIN_NEW_FNUM  0x200
#define PVFS_MIN_DIR_FNUM  0x300

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

	if (f->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) {
		if (rmdir(f->name->full_name) != 0) {
			DEBUG(0,("pvfs_close: failed to rmdir '%s' - %s\n", 
				 f->name->full_name, strerror(errno)));
		}
	}

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
	uint32_t create_action;

	/* if the client says it must be a directory, and it isn't,
	   then fail */
	if (name->exists && !(name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY)) {
		return NT_STATUS_NOT_A_DIRECTORY;
	}

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

	f = talloc_p(req, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fnum = idr_get_new_above(pvfs->idtree_fnum, f, PVFS_MIN_DIR_FNUM, UINT16_MAX);
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
	f->create_options = io->generic.in.create_options;
	f->share_access = io->generic.in.share_access;
	f->seek_offset = 0;
	f->position = 0;

	DLIST_ADD(pvfs->open_files, f);

	/* TODO: should we check in the opendb? Do directory opens 
	   follow the share_access rules? */


	/* setup a destructor to avoid leaks on abnormal termination */
	talloc_set_destructor(f, pvfs_dir_fd_destructor);

	if (!name->exists) {
		uint32_t attrib = io->generic.in.file_attr | FILE_ATTRIBUTE_DIRECTORY;
		mode_t mode = pvfs_fileperms(pvfs, attrib);
		if (mkdir(name->full_name, mode) == -1) {
			return pvfs_map_errno(pvfs,errno);
		}
		status = pvfs_resolve_name(pvfs, req, io->ntcreatex.in.fname,
					   PVFS_RESOLVE_NO_WILDCARD, &name);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		create_action = NTCREATEX_ACTION_CREATED;
	} else {
		create_action = NTCREATEX_ACTION_EXISTED;
	}

	if (!name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* the open succeeded, keep this handle permanently */
	talloc_steal(pvfs, f);

	io->generic.out.oplock_level  = NO_OPLOCK;
	io->generic.out.fnum          = f->fnum;
	io->generic.out.create_action = create_action;
	io->generic.out.create_time   = name->dos.create_time;
	io->generic.out.access_time   = name->dos.access_time;
	io->generic.out.write_time    = name->dos.write_time;
	io->generic.out.change_time   = name->dos.change_time;
	io->generic.out.attrib        = name->dos.attrib;
	io->generic.out.alloc_size    = name->dos.alloc_size;
	io->generic.out.size          = name->st.st_size;
	io->generic.out.file_type     = FILE_TYPE_DISK;
	io->generic.out.ipc_state     = 0;
	io->generic.out.is_directory  = 1;

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
	struct odb_lock *lck;
	NTSTATUS status;

	DLIST_REMOVE(f->pvfs->open_files, f);

	pvfs_lock_close(f->pvfs, f);

	if (f->fd != -1) {
		close(f->fd);
		f->fd = -1;
	}

	idr_remove(f->pvfs->idtree_fnum, f->fnum);

	if (f->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) {
		if (unlink(f->name->full_name) != 0) {
			DEBUG(0,("pvfs_close: failed to delete '%s' - %s\n", 
				 f->name->full_name, strerror(errno)));
		}
	}

	lck = odb_lock(f, f->pvfs->odb_context, &f->locking_key);
	if (lck == NULL) {
		DEBUG(0,("Unable to lock opendb for close\n"));
		return 0;
	}

	status = odb_close_file(lck, f->fnum);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Unable to remove opendb entry for '%s' - %s\n", 
			 f->name->full_name, nt_errstr(status)));
	}

	talloc_free(lck);

	return 0;
}


/*
  form the lock context used for byte range locking and opendb
  locking. Note that we must zero here to take account of
  possible padding on some architectures
*/
static NTSTATUS pvfs_locking_key(struct pvfs_filename *name, 
				 TALLOC_CTX *mem_ctx, DATA_BLOB *key)
{
	struct {
		dev_t device;
		ino_t inode;
	} lock_context;
	ZERO_STRUCT(lock_context);

	lock_context.device = name->st.st_dev;
	lock_context.inode = name->st.st_ino;

	*key = data_blob_talloc(mem_ctx, &lock_context, sizeof(lock_context));
	if (key->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	
	return NT_STATUS_OK;
}


/*
  create a new file
*/
static NTSTATUS pvfs_create_file(struct pvfs_state *pvfs, 
				 struct smbsrv_request *req, 
				 struct pvfs_filename *name, 
				 union smb_open *io)
{
	struct pvfs_file *f;
	NTSTATUS status;
	int flags, fnum, fd;
	struct odb_lock *lck;
	uint32_t create_options = io->generic.in.create_options;
	uint32_t share_access = io->generic.in.share_access;
	uint32_t access_mask = io->generic.in.access_mask;
	mode_t mode;

	if ((io->ntcreatex.in.file_attr & FILE_ATTRIBUTE_READONLY) &&
	    (create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE)) {
		return NT_STATUS_CANNOT_DELETE;
	}
	
	if (access_mask & SEC_RIGHT_MAXIMUM_ALLOWED) {
		access_mask = GENERIC_RIGHTS_FILE_READ | GENERIC_RIGHTS_FILE_WRITE;
	}

	if ((access_mask & SA_RIGHT_FILE_READ_EXEC) &&
	    (access_mask & SA_RIGHT_FILE_WRITE_APPEND)) {
		flags = O_RDWR;
	} else if (access_mask & SA_RIGHT_FILE_WRITE_APPEND) {
		flags = O_WRONLY;
	} else {
		flags = O_RDONLY;
	}

	f = talloc_p(req, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fnum = idr_get_new_above(pvfs->idtree_fnum, f, PVFS_MIN_NEW_FNUM, UINT16_MAX);
	if (fnum == -1) {
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	mode = pvfs_fileperms(pvfs, io->ntcreatex.in.file_attr | FILE_ATTRIBUTE_ARCHIVE);

	/* create the file */
	fd = open(name->full_name, flags | O_CREAT | O_EXCL, mode);
	if (fd == -1) {
		idr_remove(pvfs->idtree_fnum, fnum);
		return pvfs_map_errno(pvfs, errno);
	}

	/* re-resolve the open fd */
	status = pvfs_resolve_name_fd(pvfs, fd, name);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
		return status;
	}

	/* form the lock context used for byte range locking and
	   opendb locking */
	status = pvfs_locking_key(name, f, &f->locking_key);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
		return status;
	}

	/* grab a lock on the open file record */
	lck = odb_lock(req, pvfs->odb_context, &f->locking_key);
	if (lck == NULL) {
		DEBUG(0,("pvfs_open: failed to lock file '%s' in opendb\n",
			 name->full_name));
		/* we were supposed to do a blocking lock, so something
		   is badly wrong! */
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = odb_open_file(lck, fnum, share_access, create_options, access_mask);
	if (!NT_STATUS_IS_OK(status)) {
		/* bad news, we must have hit a race */
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
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
	f->create_options = io->generic.in.create_options;
	f->share_access = io->generic.in.share_access;
	f->access_mask = access_mask;
	f->seek_offset = 0;
	f->position = 0;

	DLIST_ADD(pvfs->open_files, f);

	/* setup a destructor to avoid file descriptor leaks on
	   abnormal termination */
	talloc_set_destructor(f, pvfs_fd_destructor);

	io->generic.out.oplock_level  = NO_OPLOCK;
	io->generic.out.fnum          = f->fnum;
	io->generic.out.create_action = NTCREATEX_ACTION_CREATED;
	io->generic.out.create_time   = name->dos.create_time;
	io->generic.out.access_time   = name->dos.access_time;
	io->generic.out.write_time    = name->dos.write_time;
	io->generic.out.change_time   = name->dos.change_time;
	io->generic.out.attrib        = name->dos.attrib;
	io->generic.out.alloc_size    = name->dos.alloc_size;
	io->generic.out.size          = name->st.st_size;
	io->generic.out.file_type     = FILE_TYPE_DISK;
	io->generic.out.ipc_state     = 0;
	io->generic.out.is_directory  = 0;

	/* success - keep the file handle */
	talloc_steal(pvfs, f);

	return NT_STATUS_OK;
}


/*
  open a file
*/
NTSTATUS pvfs_open(struct ntvfs_module_context *ntvfs,
		   struct smbsrv_request *req, union smb_open *io)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	int fd, flags;
	struct pvfs_filename *name;
	struct pvfs_file *f;
	NTSTATUS status;
	int fnum;
	struct odb_lock *lck;
	uint32_t create_options;
	uint32_t share_access;
	uint32_t access_mask;

	/* use the generic mapping code to avoid implementing all the
	   different open calls. This won't allow openx to work
	   perfectly as the mapping code has no way of knowing if two
	   opens are on the same connection, so this will need to
	   change eventually */	   
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

	create_options = io->generic.in.create_options;
	share_access   = io->generic.in.share_access;
	access_mask    = io->generic.in.access_mask;

	if (access_mask & SEC_RIGHT_MAXIMUM_ALLOWED) {
		if (name->exists && (name->dos.attrib & FILE_ATTRIBUTE_READONLY)) {
			access_mask = GENERIC_RIGHTS_FILE_READ;
		} else {
			access_mask = GENERIC_RIGHTS_FILE_READ | GENERIC_RIGHTS_FILE_WRITE;
		}
	}

	/* certain create options are not allowed */
	if ((create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) &&
	    !(access_mask & STD_RIGHT_DELETE_ACCESS)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (io->generic.in.open_disposition) {
	case NTCREATEX_DISP_SUPERSEDE:
		flags = O_TRUNC;
		break;

	case NTCREATEX_DISP_OVERWRITE_IF:
		flags = O_TRUNC;
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
		flags = 0;
		break;

	case NTCREATEX_DISP_OPEN_IF:
		flags = 0;
		break;

	default:
		return NT_STATUS_INVALID_PARAMETER;
	}

	if ((access_mask & SA_RIGHT_FILE_READ_EXEC) &&
	    (access_mask & SA_RIGHT_FILE_WRITE_APPEND)) {
		flags |= O_RDWR;
	} else if (access_mask & SA_RIGHT_FILE_WRITE_APPEND) {
		flags |= O_WRONLY;
	} else {
		flags |= O_RDONLY;
	}

	/* handle creating a new file separately */
	if (!name->exists) {
		status = pvfs_create_file(pvfs, req, name, io);
		if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_COLLISION)) {
			return status;
		}

		/* we've hit a race - the file was created during this call */
		if (io->generic.in.open_disposition == NTCREATEX_DISP_CREATE) {
			return status;
		}

		/* try re-resolving the name */
		status = pvfs_resolve_name(pvfs, req, io->ntcreatex.in.fname,
					   PVFS_RESOLVE_NO_WILDCARD, &name);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		/* fall through to a normal open */
	}

	if ((name->dos.attrib & FILE_ATTRIBUTE_READONLY) &&
	    (create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE)) {
		return NT_STATUS_CANNOT_DELETE;
	}

	f = talloc_p(req, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* allocate a fnum */
	fnum = idr_get_new_above(pvfs->idtree_fnum, f, PVFS_MIN_FILE_FNUM, UINT16_MAX);
	if (fnum == -1) {
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	/* form the lock context used for byte range locking and
	   opendb locking */
	status = pvfs_locking_key(name, f, &f->locking_key);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, fnum);
		return status;
	}

	/* get a lock on this file before the actual open */
	lck = odb_lock(req, pvfs->odb_context, &f->locking_key);
	if (lck == NULL) {
		DEBUG(0,("pvfs_open: failed to lock file '%s' in opendb\n",
			 name->full_name));
		/* we were supposed to do a blocking lock, so something
		   is badly wrong! */
		idr_remove(pvfs->idtree_fnum, fnum);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	/* see if we are allowed to open at the same time as existing opens */
	status = odb_open_file(lck, fnum, share_access, create_options, access_mask);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, fnum);
		return status;
	}

	f->fnum = fnum;
	f->fd = -1;
	f->name = talloc_steal(f, name);
	f->session = req->session;
	f->smbpid = req->smbpid;
	f->pvfs = pvfs;
	f->pending_list = NULL;
	f->lock_count = 0;
	f->create_options = io->generic.in.create_options;
	f->share_access = io->generic.in.share_access;
	f->access_mask = access_mask;
	f->seek_offset = 0;
	f->position = 0;

	DLIST_ADD(pvfs->open_files, f);

	/* setup a destructor to avoid file descriptor leaks on
	   abnormal termination */
	talloc_set_destructor(f, pvfs_fd_destructor);

	/* do the actual open */
	fd = open(name->full_name, flags);
	if (fd == -1) {
		return pvfs_map_errno(pvfs, errno);
	}

	f->fd = fd;

	/* re-resolve the open fd */
	status = pvfs_resolve_name_fd(pvfs, fd, name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	io->generic.out.oplock_level  = NO_OPLOCK;
	io->generic.out.fnum          = f->fnum;
	io->generic.out.create_action = NTCREATEX_ACTION_EXISTED;
	io->generic.out.create_time   = name->dos.create_time;
	io->generic.out.access_time   = name->dos.access_time;
	io->generic.out.write_time    = name->dos.write_time;
	io->generic.out.change_time   = name->dos.change_time;
	io->generic.out.attrib        = name->dos.attrib;
	io->generic.out.alloc_size    = name->dos.alloc_size;
	io->generic.out.size          = name->st.st_size;
	io->generic.out.file_type     = FILE_TYPE_DISK;
	io->generic.out.ipc_state     = 0;
	io->generic.out.is_directory  = 0;

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
	struct utimbuf unix_times;

	if (io->generic.level == RAW_CLOSE_SPLCLOSE) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	if (io->generic.level != RAW_CLOSE_CLOSE) {
		return ntvfs_map_close(req, io, ntvfs);
	}

	f = pvfs_find_fd(pvfs, req, io->close.in.fnum);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!null_time(io->close.in.write_time)) {
		unix_times.actime = 0;
		unix_times.modtime = io->close.in.write_time;
		utime(f->name->full_name, &unix_times);
	}
	
	if (f->fd != -1 && 
	    close(f->fd) == -1) {
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


/*
  change the create options on an already open file
*/
NTSTATUS pvfs_change_create_options(struct pvfs_state *pvfs,
				    struct smbsrv_request *req, 
				    struct pvfs_file *f, uint32_t create_options)
{
	struct odb_lock *lck;
	NTSTATUS status;

	if (f->create_options == create_options) {
		return NT_STATUS_OK;
	}

	if ((f->name->dos.attrib & FILE_ATTRIBUTE_READONLY) &&
	    (create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE)) {
		return NT_STATUS_CANNOT_DELETE;
	}

	lck = odb_lock(req, pvfs->odb_context, &f->locking_key);
	if (lck == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = odb_set_create_options(lck, f->fnum, create_options);
	if (NT_STATUS_IS_OK(status)) {
		f->create_options = create_options;
	}

	return status;
}


/*
  determine if a file can be deleted, or if it is prevented by an
  already open file
*/
NTSTATUS pvfs_can_delete(struct pvfs_state *pvfs, struct pvfs_filename *name)
{
	NTSTATUS status;
	DATA_BLOB key;

	status = pvfs_locking_key(name, name, &key);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_NO_MEMORY;
	}

	status = odb_can_open(pvfs->odb_context, &key, 
			      NTCREATEX_SHARE_ACCESS_READ |
			      NTCREATEX_SHARE_ACCESS_WRITE | 
			      NTCREATEX_SHARE_ACCESS_DELETE, 
			      0, STD_RIGHT_DELETE_ACCESS);

	return status;
}
