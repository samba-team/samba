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

#include "includes.h"
#include "vfs_posix.h"
#include "system/dir.h"
#include "system/time.h"
#include "lib/util/dlinklist.h"
#include "messaging/messaging.h"
#include "librpc/gen_ndr/xattr.h"

/*
  find open file handle given fnum
*/
struct pvfs_file *pvfs_find_fd(struct pvfs_state *pvfs,
			       struct ntvfs_request *req, struct ntvfs_handle *h)
{
	void *p;
	struct pvfs_file *f;

	p = ntvfs_handle_get_backend_data(h, pvfs->ntvfs);
	if (!p) return NULL;

	f = talloc_get_type(p, struct pvfs_file);
	if (!f) return NULL;

	return f;
}

/*
  cleanup a open directory handle
*/
static int pvfs_dir_handle_destructor(struct pvfs_file_handle *h)
{
	int open_count;
	char *path = NULL;

	if (h->name->stream_name == NULL && 
	    pvfs_delete_on_close_set(h->pvfs, h, &open_count, &path) &&
	    open_count == 1) {
		NTSTATUS status;
		status = pvfs_xattr_unlink_hook(h->pvfs, path);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Warning: xattr unlink hook failed for '%s' - %s\n",
				 path, nt_errstr(status)));
		}
		if (rmdir(path) != 0) {
			DEBUG(0,("pvfs_dir_handle_destructor: failed to rmdir '%s' - %s\n", 
				 path, strerror(errno)));
		}
	}

	talloc_free(path);

	if (h->have_opendb_entry) {
		struct odb_lock *lck;
		NTSTATUS status;

		lck = odb_lock(h, h->pvfs->odb_context, &h->odb_locking_key);
		if (lck == NULL) {
			DEBUG(0,("Unable to lock opendb for close\n"));
			return 0;
		}

		status = odb_close_file(lck, h);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Unable to remove opendb entry for '%s' - %s\n", 
				 h->name->full_name, nt_errstr(status)));
		}

		talloc_free(lck);
	}

	return 0;
}

/*
  cleanup a open directory fnum
*/
static int pvfs_dir_fnum_destructor(struct pvfs_file *f)
{
	DLIST_REMOVE(f->pvfs->files.list, f);
	ntvfs_handle_remove_backend_data(f->ntvfs, f->pvfs->ntvfs);

	return 0;
}

/*
  setup any EAs and the ACL on newly created files/directories
*/
static NTSTATUS pvfs_open_setup_eas_acl(struct pvfs_state *pvfs,
					struct ntvfs_request *req,
					struct pvfs_filename *name,
					int fd,	struct pvfs_file *f,
					union smb_open *io)
{
	NTSTATUS status;

	/* setup any EAs that were asked for */
	if (io->ntcreatex.in.ea_list) {
		status = pvfs_setfileinfo_ea_set(pvfs, name, fd, 
						 io->ntcreatex.in.ea_list->num_eas,
						 io->ntcreatex.in.ea_list->eas);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	/* setup an initial sec_desc if requested */
	if (io->ntcreatex.in.sec_desc) {
		union smb_setfileinfo set;
/* 
 * TODO: set the full ACL! 
 *       - vista denies the creation of the file with NT_STATUS_PRIVILEGE_NOT_HELD,
 *         when a SACL is present on the sd,
 *         but the user doesn't have SeSecurityPrivilege
 *       - w2k3 allows it
 */
		set.set_secdesc.in.file.ntvfs = f->ntvfs;
		set.set_secdesc.in.secinfo_flags = SECINFO_DACL;
		set.set_secdesc.in.sd = io->ntcreatex.in.sec_desc;

		status = pvfs_acl_set(pvfs, req, name, fd, SEC_STD_WRITE_DAC, &set);
	} else {
		/* otherwise setup an inherited acl from the parent */
		status = pvfs_acl_inherit(pvfs, req, name, fd);
	}

	return status;
}

/*
  form the lock context used for opendb locking. Note that we must
  zero here to take account of possible padding on some architectures
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
  open a directory
*/
static NTSTATUS pvfs_open_directory(struct pvfs_state *pvfs, 
				    struct ntvfs_request *req, 
				    struct pvfs_filename *name, 
				    union smb_open *io)
{
	struct pvfs_file *f;
	struct ntvfs_handle *h;
	NTSTATUS status;
	uint32_t create_action;
	uint32_t access_mask = io->generic.in.access_mask;
	struct odb_lock *lck;
	BOOL del_on_close;
	uint32_t create_options;
	uint32_t share_access;

	create_options = io->generic.in.create_options;
	share_access   = io->generic.in.share_access;

	if (name->stream_name) {
		return NT_STATUS_NOT_A_DIRECTORY;
	}

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

	status = ntvfs_handle_new(pvfs->ntvfs, req, &h);
	NT_STATUS_NOT_OK_RETURN(status);

	f = talloc(h, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	f->handle = talloc(f, struct pvfs_file_handle);
	if (f->handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (name->exists) {
		/* check the security descriptor */
		status = pvfs_access_check(pvfs, req, name, &access_mask);
	} else {
		status = pvfs_access_check_create(pvfs, req, name, &access_mask);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	f->ntvfs         = h;
	f->pvfs          = pvfs;
	f->pending_list  = NULL;
	f->lock_count    = 0;
	f->share_access  = io->generic.in.share_access;
	f->impersonation = io->generic.in.impersonation;
	f->access_mask   = access_mask;
	f->brl_handle	 = NULL;
	f->notify_buffer = NULL;
	f->search        = NULL;

	f->handle->pvfs              = pvfs;
	f->handle->name              = talloc_steal(f->handle, name);
	f->handle->fd                = -1;
	f->handle->odb_locking_key   = data_blob(NULL, 0);
	f->handle->create_options    = io->generic.in.create_options;
	f->handle->seek_offset       = 0;
	f->handle->position          = 0;
	f->handle->mode              = 0;
	f->handle->sticky_write_time = False;
	f->handle->open_completed    = False;

	if ((create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) &&
	    pvfs_directory_empty(pvfs, f->handle->name)) {
		del_on_close = True;
	} else {
		del_on_close = False;
	}

	if (name->exists) {
		/* form the lock context used for opendb locking */
		status = pvfs_locking_key(name, f->handle, &f->handle->odb_locking_key);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* get a lock on this file before the actual open */
		lck = odb_lock(req, pvfs->odb_context, &f->handle->odb_locking_key);
		if (lck == NULL) {
			DEBUG(0,("pvfs_open: failed to lock file '%s' in opendb\n",
				 name->full_name));
			/* we were supposed to do a blocking lock, so something
			   is badly wrong! */
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		
		/* see if we are allowed to open at the same time as existing opens */
		status = odb_open_file(lck, f->handle, f->handle->name->stream_id,
				       share_access, access_mask, del_on_close, 
				       name->full_name, OPLOCK_NONE, NULL);

		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(lck);
			return status;
		}

		f->handle->have_opendb_entry = True;
	}

	DLIST_ADD(pvfs->files.list, f);

	/* setup destructors to avoid leaks on abnormal termination */
	talloc_set_destructor(f->handle, pvfs_dir_handle_destructor);
	talloc_set_destructor(f, pvfs_dir_fnum_destructor);

	if (!name->exists) {
		uint32_t attrib = io->generic.in.file_attr | FILE_ATTRIBUTE_DIRECTORY;
		mode_t mode = pvfs_fileperms(pvfs, attrib);

		if (mkdir(name->full_name, mode) == -1) {
			return pvfs_map_errno(pvfs,errno);
		}

		pvfs_xattr_unlink_hook(pvfs, name->full_name);

		status = pvfs_resolve_name(pvfs, req, io->ntcreatex.in.fname, 0, &name);
		if (!NT_STATUS_IS_OK(status)) {
			goto cleanup_delete;
		}

		status = pvfs_open_setup_eas_acl(pvfs, req, name, -1, f, io);
		if (!NT_STATUS_IS_OK(status)) {
			goto cleanup_delete;
		}

		/* form the lock context used for opendb locking */
		status = pvfs_locking_key(name, f->handle, &f->handle->odb_locking_key);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		lck = odb_lock(req, pvfs->odb_context, &f->handle->odb_locking_key);
		if (lck == NULL) {
			DEBUG(0,("pvfs_open: failed to lock file '%s' in opendb\n",
				 name->full_name));
			/* we were supposed to do a blocking lock, so something
			   is badly wrong! */
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}

		status = odb_open_file(lck, f->handle, f->handle->name->stream_id,
				       share_access, access_mask, del_on_close, 
				       name->full_name, OPLOCK_NONE, NULL);

		if (!NT_STATUS_IS_OK(status)) {
			goto cleanup_delete;
		}

		f->handle->have_opendb_entry = True;

		create_action = NTCREATEX_ACTION_CREATED;

		notify_trigger(pvfs->notify_context, 
			       NOTIFY_ACTION_ADDED, 
			       FILE_NOTIFY_CHANGE_DIR_NAME,
			       name->full_name);
	} else {
		create_action = NTCREATEX_ACTION_EXISTED;
	}

	if (!name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	/* the open succeeded, keep this handle permanently */
	status = ntvfs_handle_set_backend_data(h, pvfs->ntvfs, f);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup_delete;
	}

	f->handle->open_completed = True;

	io->generic.out.oplock_level  = OPLOCK_NONE;
	io->generic.out.file.ntvfs    = h;
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

cleanup_delete:
	rmdir(name->full_name);
	return status;
}

/*
  destroy a struct pvfs_file_handle
*/
static int pvfs_handle_destructor(struct pvfs_file_handle *h)
{
	int open_count;
	char *path = NULL;

	/* the write time is no longer sticky */
	if (h->sticky_write_time) {
		NTSTATUS status;
		status = pvfs_dosattrib_load(h->pvfs, h->name, h->fd);
		if (NT_STATUS_IS_OK(status)) {
			h->name->dos.flags &= ~XATTR_ATTRIB_FLAG_STICKY_WRITE_TIME;
			pvfs_dosattrib_save(h->pvfs, h->name, h->fd);
		}
	}
	
	if ((h->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) &&
	    h->name->stream_name) {
		NTSTATUS status;
		status = pvfs_stream_delete(h->pvfs, h->name, h->fd);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Failed to delete stream '%s' on close of '%s'\n",
				 h->name->stream_name, h->name->full_name));
		}
	}

	if (h->fd != -1) {
		if (close(h->fd) != 0) {
			DEBUG(0,("pvfs_handle_destructor: close(%d) failed for %s - %s\n",
				 h->fd, h->name->full_name, strerror(errno)));
		}
		h->fd = -1;
	}

	if (h->name->stream_name == NULL && 
	    h->open_completed &&
	    pvfs_delete_on_close_set(h->pvfs, h, &open_count, &path) &&
	    open_count == 1) {
		NTSTATUS status;
		status = pvfs_xattr_unlink_hook(h->pvfs, path);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Warning: xattr unlink hook failed for '%s' - %s\n",
				 path, nt_errstr(status)));
		}
		if (unlink(path) != 0) {
			DEBUG(0,("pvfs_close: failed to delete '%s' - %s\n", 
				 path, strerror(errno)));
		} else {
			notify_trigger(h->pvfs->notify_context, 
				       NOTIFY_ACTION_REMOVED, 
				       FILE_NOTIFY_CHANGE_FILE_NAME,
				       path);
		}
	}

	talloc_free(path);

	if (h->have_opendb_entry) {
		struct odb_lock *lck;
		NTSTATUS status;

		lck = odb_lock(h, h->pvfs->odb_context, &h->odb_locking_key);
		if (lck == NULL) {
			DEBUG(0,("Unable to lock opendb for close\n"));
			return 0;
		}

		status = odb_close_file(lck, h);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Unable to remove opendb entry for '%s' - %s\n", 
				 h->name->full_name, nt_errstr(status)));
		}

		talloc_free(lck);
	}

	return 0;
}


/*
  destroy a struct pvfs_file
*/
static int pvfs_fnum_destructor(struct pvfs_file *f)
{
	DLIST_REMOVE(f->pvfs->files.list, f);
	pvfs_lock_close(f->pvfs, f);
	ntvfs_handle_remove_backend_data(f->ntvfs, f->pvfs->ntvfs);

	return 0;
}


/*
  form the lock context used for byte range locking. This is separate
  from the locking key used for opendb locking as it needs to take
  account of file streams (each stream is a separate byte range
  locking space)
*/
static NTSTATUS pvfs_brl_locking_handle(TALLOC_CTX *mem_ctx,
					struct pvfs_filename *name,
					struct ntvfs_handle *ntvfs,
					struct brl_handle **_h)
{
	DATA_BLOB odb_key, key;
	NTSTATUS status;
	struct brl_handle *h;

	status = pvfs_locking_key(name, mem_ctx, &odb_key);
	NT_STATUS_NOT_OK_RETURN(status);

	if (name->stream_name == NULL) {
		key = odb_key;
	} else {
		key = data_blob_talloc(mem_ctx, NULL, 
				       odb_key.length + strlen(name->stream_name) + 1);
		NT_STATUS_HAVE_NO_MEMORY(key.data);
		memcpy(key.data, odb_key.data, odb_key.length);
		memcpy(key.data + odb_key.length, 
		       name->stream_name, strlen(name->stream_name) + 1);
		data_blob_free(&odb_key);
	}

	h = brl_create_handle(mem_ctx, ntvfs, &key);
	NT_STATUS_HAVE_NO_MEMORY(h);

	*_h = h;
	return NT_STATUS_OK;
}

/*
  create a new file
*/
static NTSTATUS pvfs_create_file(struct pvfs_state *pvfs, 
				 struct ntvfs_request *req, 
				 struct pvfs_filename *name, 
				 union smb_open *io)
{
	struct pvfs_file *f;
	NTSTATUS status;
	struct ntvfs_handle *h;
	int flags, fd;
	struct odb_lock *lck;
	uint32_t create_options = io->generic.in.create_options;
	uint32_t share_access = io->generic.in.share_access;
	uint32_t access_mask = io->generic.in.access_mask;
	mode_t mode;
	uint32_t attrib;
	BOOL del_on_close;
	struct pvfs_filename *parent;
	uint32_t oplock_level = OPLOCK_NONE, oplock_granted;

	if ((io->ntcreatex.in.file_attr & FILE_ATTRIBUTE_READONLY) &&
	    (create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE)) {
		return NT_STATUS_CANNOT_DELETE;
	}
	
	status = pvfs_access_check_create(pvfs, req, name, &access_mask);
	NT_STATUS_NOT_OK_RETURN(status);

	/* check that the parent isn't opened with delete on close set */
	status = pvfs_resolve_parent(pvfs, req, name, &parent);
	if (NT_STATUS_IS_OK(status)) {
		DATA_BLOB locking_key;
		status = pvfs_locking_key(parent, req, &locking_key);
		NT_STATUS_NOT_OK_RETURN(status);
		status = odb_get_delete_on_close(pvfs->odb_context, &locking_key, 
						 &del_on_close, NULL, NULL);
		NT_STATUS_NOT_OK_RETURN(status);
		if (del_on_close) {
			return NT_STATUS_DELETE_PENDING;
		}
	}

	if (access_mask & (SEC_FILE_WRITE_DATA | SEC_FILE_APPEND_DATA)) {
		flags = O_RDWR;
	} else {
		flags = O_RDONLY;
	}

	status = ntvfs_handle_new(pvfs->ntvfs, req, &h);
	NT_STATUS_NOT_OK_RETURN(status);

	f = talloc(h, struct pvfs_file);
	NT_STATUS_HAVE_NO_MEMORY(f);

	f->handle = talloc(f, struct pvfs_file_handle);
	NT_STATUS_HAVE_NO_MEMORY(f->handle);

	attrib = io->ntcreatex.in.file_attr | FILE_ATTRIBUTE_ARCHIVE;
	mode = pvfs_fileperms(pvfs, attrib);

	/* create the file */
	fd = open(name->full_name, flags | O_CREAT | O_EXCL, mode);
	if (fd == -1) {
		return pvfs_map_errno(pvfs, errno);
	}

	pvfs_xattr_unlink_hook(pvfs, name->full_name);

	/* if this was a stream create then create the stream as well */
	if (name->stream_name) {
		status = pvfs_stream_create(pvfs, name, fd);
		if (!NT_STATUS_IS_OK(status)) {
			close(fd);
			return status;
		}
	}

	/* re-resolve the open fd */
	status = pvfs_resolve_name_fd(pvfs, fd, name);
	if (!NT_STATUS_IS_OK(status)) {
		close(fd);
		return status;
	}

	name->dos.attrib = attrib;
	status = pvfs_dosattrib_save(pvfs, name, fd);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup_delete;
	}


	status = pvfs_open_setup_eas_acl(pvfs, req, name, fd, f, io);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup_delete;
	}

	/* form the lock context used for byte range locking and
	   opendb locking */
	status = pvfs_locking_key(name, f->handle, &f->handle->odb_locking_key);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup_delete;
	}

	status = pvfs_brl_locking_handle(f, name, h, &f->brl_handle);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup_delete;
	}

	/* grab a lock on the open file record */
	lck = odb_lock(req, pvfs->odb_context, &f->handle->odb_locking_key);
	if (lck == NULL) {
		DEBUG(0,("pvfs_open: failed to lock file '%s' in opendb\n",
			 name->full_name));
		/* we were supposed to do a blocking lock, so something
		   is badly wrong! */
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		goto cleanup_delete;
	}

	if (create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) {
		del_on_close = True;
	} else {
		del_on_close = False;
	}

	if (pvfs->flags & PVFS_FLAG_FAKE_OPLOCKS) {
		oplock_level = OPLOCK_NONE;
	} else if (io->ntcreatex.in.flags & NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK) {
		oplock_level = OPLOCK_BATCH;
	} else if (io->ntcreatex.in.flags & NTCREATEX_FLAGS_REQUEST_OPLOCK) {
		oplock_level = OPLOCK_EXCLUSIVE;
	}

	status = odb_open_file(lck, f->handle, name->stream_id,
			       share_access, access_mask, del_on_close, 
			       name->full_name, oplock_level, &oplock_granted);
	talloc_free(lck);
	if (!NT_STATUS_IS_OK(status)) {
		/* bad news, we must have hit a race - we don't delete the file
		   here as the most likely scenario is that someone else created 
		   the file at the same time */
		close(fd);
		return status;
	}

	if (pvfs->flags & PVFS_FLAG_FAKE_OPLOCKS) {
		oplock_granted = OPLOCK_BATCH;
	}

	f->ntvfs             = h;
	f->pvfs              = pvfs;
	f->pending_list      = NULL;
	f->lock_count        = 0;
	f->share_access      = io->generic.in.share_access;
	f->access_mask       = access_mask;
	f->impersonation     = io->generic.in.impersonation;
	f->notify_buffer     = NULL;
	f->search            = NULL;

	f->handle->pvfs              = pvfs;
	f->handle->name              = talloc_steal(f->handle, name);
	f->handle->fd                = fd;
	f->handle->create_options    = io->generic.in.create_options;
	f->handle->seek_offset       = 0;
	f->handle->position          = 0;
	f->handle->mode              = 0;
	f->handle->have_opendb_entry = True;
	f->handle->sticky_write_time = False;
	f->handle->open_completed    = False;

	DLIST_ADD(pvfs->files.list, f);

	/* setup a destructor to avoid file descriptor leaks on
	   abnormal termination */
	talloc_set_destructor(f, pvfs_fnum_destructor);
	talloc_set_destructor(f->handle, pvfs_handle_destructor);

	io->generic.out.oplock_level  = oplock_granted;
	io->generic.out.file.ntvfs    = f->ntvfs;
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
	status = ntvfs_handle_set_backend_data(h, pvfs->ntvfs, f);
	if (!NT_STATUS_IS_OK(status)) {
		goto cleanup_delete;
	}

	f->handle->open_completed = True;

	notify_trigger(pvfs->notify_context, 
		       NOTIFY_ACTION_ADDED, 
		       FILE_NOTIFY_CHANGE_FILE_NAME,
		       name->full_name);

	return NT_STATUS_OK;

cleanup_delete:
	close(fd);
	unlink(name->full_name);
	return status;
}


/*
  state of a pending open retry
*/
struct pvfs_open_retry {
	struct ntvfs_module_context *ntvfs;
	struct ntvfs_request *req;
	union smb_open *io;
	void *wait_handle;
	DATA_BLOB odb_locking_key;
};

/* destroy a pending open request */
static int pvfs_retry_destructor(struct pvfs_open_retry *r)
{
	struct pvfs_state *pvfs = r->ntvfs->private_data;
	if (r->odb_locking_key.data) {
		struct odb_lock *lck;
		lck = odb_lock(r->req, pvfs->odb_context, &r->odb_locking_key);
		if (lck != NULL) {
			odb_remove_pending(lck, r);
		}
		talloc_free(lck);
	}
	return 0;
}

/*
  retry an open
*/
static void pvfs_open_retry(void *private, enum pvfs_wait_notice reason)
{
	struct pvfs_open_retry *r = private;
	struct ntvfs_module_context *ntvfs = r->ntvfs;
	struct ntvfs_request *req = r->req;
	union smb_open *io = r->io;
	NTSTATUS status;

	/* w2k3 ignores SMBntcancel for outstanding open requests. It's probably
	   just a bug in their server, but we better do the same */
	if (reason == PVFS_WAIT_CANCEL) {
		return;
	}

	talloc_free(r->wait_handle);

	if (reason == PVFS_WAIT_TIMEOUT) {
		/* if it timed out, then give the failure
		   immediately */
		talloc_free(r);
		req->async_states->status = NT_STATUS_SHARING_VIOLATION;
		req->async_states->send_fn(req);
		return;
	}

	/* the pending odb entry is already removed. We use a null locking
	   key to indicate this */
	data_blob_free(&r->odb_locking_key);
	talloc_free(r);

	/* try the open again, which could trigger another retry setup
	   if it wants to, so we have to unmark the async flag so we
	   will know if it does a second async reply */
	req->async_states->state &= ~NTVFS_ASYNC_STATE_ASYNC;

	status = pvfs_open(ntvfs, req, io);
	if (req->async_states->state & NTVFS_ASYNC_STATE_ASYNC) {
		/* the 2nd try also replied async, so we don't send
		   the reply yet */
		return;
	}

	/* re-mark it async, just in case someone up the chain does
	   paranoid checking */
	req->async_states->state |= NTVFS_ASYNC_STATE_ASYNC;

	/* send the reply up the chain */
	req->async_states->status = status;
	req->async_states->send_fn(req);
}


/*
  special handling for openx DENY_DOS semantics

  This function attempts a reference open using an existing handle. If its allowed,
  then it returns NT_STATUS_OK, otherwise it returns any other code and normal
  open processing continues.
*/
static NTSTATUS pvfs_open_deny_dos(struct ntvfs_module_context *ntvfs,
				   struct ntvfs_request *req, union smb_open *io,
				   struct pvfs_file *f, struct odb_lock *lck)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f2;
	struct pvfs_filename *name;
	NTSTATUS status;

	/* search for an existing open with the right parameters. Note
	   the magic ntcreatex options flag, which is set in the
	   generic mapping code. This might look ugly, but its
	   actually pretty much now w2k does it internally as well. 
	   
	   If you look at the BASE-DENYDOS test you will see that a
	   DENY_DOS is a very special case, and in the right
	   circumstances you actually get the _same_ handle back
	   twice, rather than a new handle.
	*/
	for (f2=pvfs->files.list;f2;f2=f2->next) {
		if (f2 != f &&
		    f2->ntvfs->session_info == req->session_info &&
		    f2->ntvfs->smbpid == req->smbpid &&
		    (f2->handle->create_options & 
		     (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS |
		      NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) &&
		    (f2->access_mask & SEC_FILE_WRITE_DATA) &&
		    strcasecmp_m(f2->handle->name->original_name, 
			       io->generic.in.fname)==0) {
			break;
		}
	}

	if (!f2) {
		return NT_STATUS_SHARING_VIOLATION;
	}

	/* quite an insane set of semantics ... */
	if (is_exe_filename(io->generic.in.fname) &&
	    (f2->handle->create_options & NTCREATEX_OPTIONS_PRIVATE_DENY_DOS)) {
		return NT_STATUS_SHARING_VIOLATION;
	}

	/*
	  setup a reference to the existing handle
	 */
	talloc_free(f->handle);
	f->handle = talloc_reference(f, f2->handle);

	talloc_free(lck);

	name = f->handle->name;

	io->generic.out.oplock_level  = OPLOCK_NONE;
	io->generic.out.file.ntvfs    = f->ntvfs;
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
 
	status = ntvfs_handle_set_backend_data(f->ntvfs, ntvfs, f);
	NT_STATUS_NOT_OK_RETURN(status);

	return NT_STATUS_OK;
}



/*
  setup for a open retry after a sharing violation
*/
static NTSTATUS pvfs_open_setup_retry(struct ntvfs_module_context *ntvfs,
				      struct ntvfs_request *req, 
				      union smb_open *io,
				      struct pvfs_file *f,
				      struct odb_lock *lck)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_open_retry *r;
	NTSTATUS status;
	struct timeval end_time;

	if (io->generic.in.create_options & 
	    (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS | NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) {
		/* see if we can satisfy the request using the special DENY_DOS
		   code */
		status = pvfs_open_deny_dos(ntvfs, req, io, f, lck);
		if (NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	r = talloc(req, struct pvfs_open_retry);
	if (r == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->ntvfs = ntvfs;
	r->req = req;
	r->io = io;
	r->odb_locking_key = data_blob_talloc(r, 
					      f->handle->odb_locking_key.data, 
					      f->handle->odb_locking_key.length);

	end_time = timeval_add(&req->statistics.request_time, 0, pvfs->sharing_violation_delay);

	/* setup a pending lock */
	status = odb_open_file_pending(lck, r);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	talloc_free(lck);
	talloc_free(f);

	talloc_set_destructor(r, pvfs_retry_destructor);

	r->wait_handle = pvfs_wait_message(pvfs, req, MSG_PVFS_RETRY_OPEN, end_time, 
					   pvfs_open_retry, r);
	if (r->wait_handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	talloc_steal(pvfs, r);

	return NT_STATUS_OK;
}

/*
  open a file
*/
NTSTATUS pvfs_open(struct ntvfs_module_context *ntvfs,
		   struct ntvfs_request *req, union smb_open *io)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	int flags;
	struct pvfs_filename *name;
	struct pvfs_file *f;
	struct ntvfs_handle *h;
	NTSTATUS status;
	int fd;
	struct odb_lock *lck;
	uint32_t create_options;
	uint32_t share_access;
	uint32_t access_mask;
	BOOL del_on_close;
	BOOL stream_existed, stream_truncate=False;
	uint32_t oplock_level = OPLOCK_NONE, oplock_granted;

	/* use the generic mapping code to avoid implementing all the
	   different open calls. */
	if (io->generic.level != RAW_OPEN_GENERIC &&
	    io->generic.level != RAW_OPEN_NTTRANS_CREATE) {
		return ntvfs_map_open(ntvfs, req, io);
	}

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, io->ntcreatex.in.fname, 
				   PVFS_RESOLVE_STREAMS, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* directory opens are handled separately */
	if ((name->exists && (name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY)) ||
	    (io->generic.in.create_options & NTCREATEX_OPTIONS_DIRECTORY)) {
		return pvfs_open_directory(pvfs, req, name, io);
	}

	/* FILE_ATTRIBUTE_DIRECTORY is ignored if the above test for directory
	   open doesn't match */
	io->generic.in.file_attr &= ~FILE_ATTRIBUTE_DIRECTORY;

	create_options = io->generic.in.create_options;
	share_access   = io->generic.in.share_access;
	access_mask    = io->generic.in.access_mask;

	/* certain create options are not allowed */
	if ((create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) &&
	    !(access_mask & SEC_STD_DELETE)) {
		return NT_STATUS_INVALID_PARAMETER;
	}

	flags = 0;

	switch (io->generic.in.open_disposition) {
	case NTCREATEX_DISP_SUPERSEDE:
	case NTCREATEX_DISP_OVERWRITE_IF:
		if (name->stream_name == NULL) {
			flags = O_TRUNC;
		} else {
			stream_truncate = True;
		}
		break;

	case NTCREATEX_DISP_OPEN:
		if (!name->stream_exists) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		flags = 0;
		break;

	case NTCREATEX_DISP_OVERWRITE:
		if (!name->stream_exists) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		if (name->stream_name == NULL) {
			flags = O_TRUNC;
		} else {
			stream_truncate = True;
		}
		break;

	case NTCREATEX_DISP_CREATE:
		if (name->stream_exists) {
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
		status = pvfs_resolve_name(pvfs, req, io->ntcreatex.in.fname, 0, &name);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
		/* fall through to a normal open */
	}

	if ((name->dos.attrib & FILE_ATTRIBUTE_READONLY) &&
	    (create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE)) {
		return NT_STATUS_CANNOT_DELETE;
	}

	/* check the security descriptor */
	status = pvfs_access_check(pvfs, req, name, &access_mask);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = ntvfs_handle_new(pvfs->ntvfs, req, &h);
	NT_STATUS_NOT_OK_RETURN(status);

	f = talloc(h, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	f->handle = talloc(f, struct pvfs_file_handle);
	if (f->handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	f->ntvfs         = h;
	f->pvfs          = pvfs;
	f->pending_list  = NULL;
	f->lock_count    = 0;
	f->share_access  = io->generic.in.share_access;
	f->access_mask   = access_mask;
	f->impersonation = io->generic.in.impersonation;
	f->notify_buffer = NULL;
	f->search        = NULL;

	f->handle->pvfs              = pvfs;
	f->handle->fd                = -1;
	f->handle->name              = talloc_steal(f->handle, name);
	f->handle->create_options    = io->generic.in.create_options;
	f->handle->seek_offset       = 0;
	f->handle->position          = 0;
	f->handle->mode              = 0;
	f->handle->have_opendb_entry = False;
	f->handle->sticky_write_time = False;
	f->handle->open_completed    = False;

	/* form the lock context used for byte range locking and
	   opendb locking */
	status = pvfs_locking_key(name, f->handle, &f->handle->odb_locking_key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = pvfs_brl_locking_handle(f, name, h, &f->brl_handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* get a lock on this file before the actual open */
	lck = odb_lock(req, pvfs->odb_context, &f->handle->odb_locking_key);
	if (lck == NULL) {
		DEBUG(0,("pvfs_open: failed to lock file '%s' in opendb\n",
			 name->full_name));
		/* we were supposed to do a blocking lock, so something
		   is badly wrong! */
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	DLIST_ADD(pvfs->files.list, f);

	/* setup a destructor to avoid file descriptor leaks on
	   abnormal termination */
	talloc_set_destructor(f, pvfs_fnum_destructor);
	talloc_set_destructor(f->handle, pvfs_handle_destructor);

	/* 
	 * Only SMB2 takes care of the delete_on_close,
	 * on existing files
	 */
	if (create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE &&
	    req->ctx->protocol == PROTOCOL_SMB2) {
		del_on_close = True;
	} else {
		del_on_close = False;
	}

	if (pvfs->flags & PVFS_FLAG_FAKE_OPLOCKS) {
		oplock_level = OPLOCK_NONE;
	} else if (io->ntcreatex.in.flags & NTCREATEX_FLAGS_REQUEST_BATCH_OPLOCK) {
		oplock_level = OPLOCK_BATCH;
	} else if (io->ntcreatex.in.flags & NTCREATEX_FLAGS_REQUEST_OPLOCK) {
		oplock_level = OPLOCK_EXCLUSIVE;
	}

	/* see if we are allowed to open at the same time as existing opens */
	status = odb_open_file(lck, f->handle, f->handle->name->stream_id,
			       share_access, access_mask, del_on_close,
			       name->full_name, oplock_level, &oplock_granted);

	/* on a sharing violation we need to retry when the file is closed by 
	   the other user, or after 1 second */
	if (NT_STATUS_EQUAL(status, NT_STATUS_SHARING_VIOLATION) &&
	    (req->async_states->state & NTVFS_ASYNC_STATE_MAY_ASYNC)) {
		return pvfs_open_setup_retry(ntvfs, req, io, f, lck);
	}

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(lck);
		return status;
	}

	if (pvfs->flags & PVFS_FLAG_FAKE_OPLOCKS) {
		oplock_granted = OPLOCK_BATCH;
	}

	f->handle->have_opendb_entry = True;

	if (access_mask & (SEC_FILE_WRITE_DATA | SEC_FILE_APPEND_DATA)) {
		flags |= O_RDWR;
	} else {
		flags |= O_RDONLY;
	}

	/* do the actual open */
	fd = open(f->handle->name->full_name, flags);
	if (fd == -1) {
		talloc_free(lck);
		return pvfs_map_errno(f->pvfs, errno);
	}

	f->handle->fd = fd;

	stream_existed = name->stream_exists;

	/* if this was a stream create then create the stream as well */
	if (!name->stream_exists) {
		status = pvfs_stream_create(pvfs, f->handle->name, fd);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(lck);
			return status;
		}
		if (stream_truncate) {
			status = pvfs_stream_truncate(pvfs, f->handle->name, fd, 0);
			if (!NT_STATUS_IS_OK(status)) {
				talloc_free(lck);
				return status;
			}
		}
	}

	/* re-resolve the open fd */
	status = pvfs_resolve_name_fd(f->pvfs, fd, f->handle->name);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(lck);
		return status;
	}

	if (f->handle->name->stream_id == 0 &&
	    (io->generic.in.open_disposition == NTCREATEX_DISP_OVERWRITE ||
	     io->generic.in.open_disposition == NTCREATEX_DISP_OVERWRITE_IF)) {
		/* for overwrite we need to replace file permissions */
		uint32_t attrib = io->ntcreatex.in.file_attr | FILE_ATTRIBUTE_ARCHIVE;
		mode_t mode = pvfs_fileperms(pvfs, attrib);
		if (fchmod(fd, mode) == -1) {
			talloc_free(lck);
			return pvfs_map_errno(pvfs, errno);
		}
		name->dos.attrib = attrib;
		status = pvfs_dosattrib_save(pvfs, name, fd);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(lck);
			return status;
		}
	}
	    
	talloc_free(lck);

	status = ntvfs_handle_set_backend_data(h, ntvfs, f);
	NT_STATUS_NOT_OK_RETURN(status);

	/* mark the open as having completed fully, so delete on close
	   can now be used */
	f->handle->open_completed     = True;

	io->generic.out.oplock_level  = oplock_granted;
	io->generic.out.file.ntvfs    = h;
	io->generic.out.create_action = stream_existed?
		NTCREATEX_ACTION_EXISTED:NTCREATEX_ACTION_CREATED;
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

	return NT_STATUS_OK;
}


/*
  close a file
*/
NTSTATUS pvfs_close(struct ntvfs_module_context *ntvfs,
		    struct ntvfs_request *req, union smb_close *io)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f;
	struct utimbuf unix_times;

	if (io->generic.level == RAW_CLOSE_SPLCLOSE) {
		return NT_STATUS_DOS(ERRSRV, ERRerror);
	}

	if (io->generic.level != RAW_CLOSE_CLOSE) {
		return ntvfs_map_close(ntvfs, req, io);
	}

	f = pvfs_find_fd(pvfs, req, io->close.in.file.ntvfs);
	if (!f) {
		return NT_STATUS_INVALID_HANDLE;
	}

	if (!null_time(io->close.in.write_time)) {
		unix_times.actime = 0;
		unix_times.modtime = io->close.in.write_time;
		utime(f->handle->name->full_name, &unix_times);
	} else if (f->handle->sticky_write_time) {
		unix_times.actime = 0;
		unix_times.modtime = nt_time_to_unix(f->handle->name->dos.write_time);
		utime(f->handle->name->full_name, &unix_times);
	}

	talloc_free(f);

	return NT_STATUS_OK;
}


/*
  logoff - close all file descriptors open by a vuid
*/
NTSTATUS pvfs_logoff(struct ntvfs_module_context *ntvfs,
		     struct ntvfs_request *req)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f, *next;

	for (f=pvfs->files.list;f;f=next) {
		next = f->next;
		if (f->ntvfs->session_info == req->session_info) {
			talloc_free(f);
		}
	}

	return NT_STATUS_OK;
}


/*
  exit - close files for the current pid
*/
NTSTATUS pvfs_exit(struct ntvfs_module_context *ntvfs,
		   struct ntvfs_request *req)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f, *next;

	for (f=pvfs->files.list;f;f=next) {
		next = f->next;
		if (f->ntvfs->session_info == req->session_info &&
		    f->ntvfs->smbpid == req->smbpid) {
			talloc_free(f);
		}
	}

	return NT_STATUS_OK;
}


/*
  change the delete on close flag on an already open file
*/
NTSTATUS pvfs_set_delete_on_close(struct pvfs_state *pvfs,
				  struct ntvfs_request *req, 
				  struct pvfs_file *f, BOOL del_on_close)
{
	struct odb_lock *lck;
	NTSTATUS status;

	if ((f->handle->name->dos.attrib & FILE_ATTRIBUTE_READONLY) && del_on_close) {
		return NT_STATUS_CANNOT_DELETE;
	}
	
	if ((f->handle->name->dos.attrib & FILE_ATTRIBUTE_DIRECTORY) &&
	    !pvfs_directory_empty(pvfs, f->handle->name)) {
		return NT_STATUS_DIRECTORY_NOT_EMPTY;
	}

	if (del_on_close) {
		f->handle->create_options |= NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	} else {
		f->handle->create_options &= ~NTCREATEX_OPTIONS_DELETE_ON_CLOSE;
	}
	
	lck = odb_lock(req, pvfs->odb_context, &f->handle->odb_locking_key);
	if (lck == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = odb_set_delete_on_close(lck, del_on_close);

	talloc_free(lck);

	return status;
}


/*
  determine if a file can be deleted, or if it is prevented by an
  already open file
*/
NTSTATUS pvfs_can_delete(struct pvfs_state *pvfs, 
			 struct ntvfs_request *req,
			 struct pvfs_filename *name,
			 struct odb_lock **lckp)
{
	NTSTATUS status;
	DATA_BLOB key;
	struct odb_lock *lck;

	status = pvfs_locking_key(name, name, &key);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_NO_MEMORY;
	}

	lck = odb_lock(req, pvfs->odb_context, &key);
	if (lck == NULL) {
		DEBUG(0,("Unable to lock opendb for can_delete\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = odb_can_open(lck,
			      NTCREATEX_SHARE_ACCESS_READ |
			      NTCREATEX_SHARE_ACCESS_WRITE | 
			      NTCREATEX_SHARE_ACCESS_DELETE, 
			      NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 
			      SEC_STD_DELETE);

	if (NT_STATUS_IS_OK(status)) {
		status = pvfs_access_check_simple(pvfs, req, name, SEC_STD_DELETE);
	}

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(lck);
		*lckp = lck;
	} else if (lckp != NULL) {
		*lckp = lck;
	}

	return status;
}

/*
  determine if a file can be renamed, or if it is prevented by an
  already open file
*/
NTSTATUS pvfs_can_rename(struct pvfs_state *pvfs, 
			 struct ntvfs_request *req,
			 struct pvfs_filename *name,
			 struct odb_lock **lckp)
{
	NTSTATUS status;
	DATA_BLOB key;
	struct odb_lock *lck;

	status = pvfs_locking_key(name, name, &key);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_NO_MEMORY;
	}

	lck = odb_lock(req, pvfs->odb_context, &key);
	if (lck == NULL) {
		DEBUG(0,("Unable to lock opendb for can_stat\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = odb_can_open(lck,
			      NTCREATEX_SHARE_ACCESS_READ |
			      NTCREATEX_SHARE_ACCESS_WRITE,
			      0,
			      SEC_STD_DELETE);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(lck);
		*lckp = lck;
	} else if (lckp != NULL) {
		*lckp = lck;
	}

	return status;
}

/*
  determine if file meta data can be accessed, or if it is prevented by an
  already open file
*/
NTSTATUS pvfs_can_stat(struct pvfs_state *pvfs, 
		       struct ntvfs_request *req,
		       struct pvfs_filename *name)
{
	NTSTATUS status;
	DATA_BLOB key;
	struct odb_lock *lck;

	status = pvfs_locking_key(name, name, &key);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_NO_MEMORY;
	}

	lck = odb_lock(req, pvfs->odb_context, &key);
	if (lck == NULL) {
		DEBUG(0,("Unable to lock opendb for can_stat\n"));
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = odb_can_open(lck,
			      NTCREATEX_SHARE_ACCESS_READ |
			      NTCREATEX_SHARE_ACCESS_WRITE,
			      0, 0);

	return status;
}


/*
  determine if delete on close is set on 
*/
BOOL pvfs_delete_on_close_set(struct pvfs_state *pvfs, struct pvfs_file_handle *h, 
			      int *open_count, char **path)
{
	NTSTATUS status;
	BOOL del_on_close;

	status = odb_get_delete_on_close(pvfs->odb_context, &h->odb_locking_key, 
					 &del_on_close, open_count, path);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1,("WARNING: unable to determine delete on close status for open file\n"));
		return False;
	}

	return del_on_close;
}
