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
#include "system/time.h"
#include "system/filesys.h"
#include "dlinklist.h"
#include "messages.h"

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

	if (f->fnum != fnum) {
		smb_panic("pvfs_find_fd: idtree_fnum corruption\n");
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
static int pvfs_dir_handle_destructor(void *p)
{
	struct pvfs_file_handle *h = p;

	if (h->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) {
		if (rmdir(h->name->full_name) != 0) {
			DEBUG(0,("pvfs_close: failed to rmdir '%s' - %s\n", 
				 h->name->full_name, strerror(errno)));
		}
	}

	return 0;
}

/*
  cleanup a open directory fnum
*/
static int pvfs_dir_fnum_destructor(void *p)
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
	uint32_t create_action;

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

	f = talloc_p(req, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	f->handle = talloc_p(f, struct pvfs_file_handle);
	if (f->handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fnum = idr_get_new_above(pvfs->idtree_fnum, f, PVFS_MIN_DIR_FNUM, UINT16_MAX);
	if (fnum == -1) {
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	f->fnum          = fnum;
	f->session       = req->session;
	f->smbpid        = req->smbpid;
	f->pvfs          = pvfs;
	f->pending_list  = NULL;
	f->lock_count    = 0;
	f->share_access  = io->generic.in.share_access;
	f->impersonation = io->generic.in.impersonation;

	f->handle->pvfs           = pvfs;
	f->handle->name           = talloc_steal(f->handle, name);
	f->handle->fd             = -1;
	f->handle->odb_locking_key    = data_blob(NULL, 0);
	f->handle->brl_locking_key    = data_blob(NULL, 0);
	f->handle->create_options = io->generic.in.create_options;
	f->handle->seek_offset    = 0;
	f->handle->position       = 0;
	f->handle->mode           = 0;

	DLIST_ADD(pvfs->open_files, f);

	/* TODO: should we check in the opendb? Do directory opens 
	   follow the share_access rules? */

	/* setup destructors to avoid leaks on abnormal termination */
	talloc_set_destructor(f->handle, pvfs_dir_handle_destructor);
	talloc_set_destructor(f, pvfs_dir_fnum_destructor);

	if (!name->exists) {
		uint32_t attrib = io->generic.in.file_attr | FILE_ATTRIBUTE_DIRECTORY;
		mode_t mode = pvfs_fileperms(pvfs, attrib);
		if (mkdir(name->full_name, mode) == -1) {
			return pvfs_map_errno(pvfs,errno);
		}
		status = pvfs_resolve_name(pvfs, req, io->ntcreatex.in.fname, 0, &name);
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
  destroy a struct pvfs_file_handle
*/
static int pvfs_handle_destructor(void *p)
{
	struct pvfs_file_handle *h = p;

	if (h->fd != -1) {
		if (close(h->fd) != 0) {
			DEBUG(0,("pvfs_handle_destructor: close(%d) failed for %s - %s\n",
				 h->fd, h->name->full_name, strerror(errno)));
		}
		h->fd = -1;
	}

	if (h->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) {
		if (unlink(h->name->full_name) != 0) {
			DEBUG(0,("pvfs_close: failed to delete '%s' - %s\n", 
				 h->name->full_name, strerror(errno)));
		}
	}

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
static int pvfs_fnum_destructor(void *p)
{
	struct pvfs_file *f = p;

	DLIST_REMOVE(f->pvfs->open_files, f);
	pvfs_lock_close(f->pvfs, f);
	idr_remove(f->pvfs->idtree_fnum, f->fnum);

	return 0;
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
  form the lock context used for byte range locking. This is separate
  from the locking key used for opendb locking as it needs to take
  account of file streams (each stream is a separate byte range
  locking space)
*/
static NTSTATUS pvfs_brl_locking_key(struct pvfs_filename *name, 
				     TALLOC_CTX *mem_ctx, DATA_BLOB *key)
{
	DATA_BLOB odb_key;
	NTSTATUS status;
	status = pvfs_locking_key(name, mem_ctx, &odb_key);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (name->stream_name == NULL) {
		*key = odb_key;
		return NT_STATUS_OK;
	}
	*key = data_blob_talloc(mem_ctx, NULL, 
				odb_key.length + strlen(name->stream_name) + 1);
	if (key->data == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	memcpy(key->data, odb_key.data, odb_key.length);
	memcpy(key->data + odb_key.length, 
	       name->stream_name, strlen(name->stream_name)+1);
	data_blob_free(&odb_key);
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
	uint32_t attrib;

	if ((io->ntcreatex.in.file_attr & FILE_ATTRIBUTE_READONLY) &&
	    (create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE)) {
		return NT_STATUS_CANNOT_DELETE;
	}
	
	if (access_mask & SEC_RIGHT_MAXIMUM_ALLOWED) {
		access_mask = GENERIC_RIGHTS_FILE_READ | GENERIC_RIGHTS_FILE_WRITE;
	}

	if (access_mask & SA_RIGHT_FILE_WRITE_APPEND) {
		flags = O_RDWR;
	} else {
		flags = O_RDONLY;
	}

	f = talloc_p(req, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	f->handle = talloc_p(f, struct pvfs_file_handle);
	if (f->handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	fnum = idr_get_new_above(pvfs->idtree_fnum, f, PVFS_MIN_NEW_FNUM, UINT16_MAX);
	if (fnum == -1) {
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	attrib = io->ntcreatex.in.file_attr | FILE_ATTRIBUTE_ARCHIVE;
	mode = pvfs_fileperms(pvfs, attrib);

	/* create the file */
	fd = open(name->full_name, flags | O_CREAT | O_EXCL, mode);
	if (fd == -1) {
		idr_remove(pvfs->idtree_fnum, fnum);
		return pvfs_map_errno(pvfs, errno);
	}

	/* if this was a stream create then create the stream as well */
	if (name->stream_name) {
		status = pvfs_stream_create(pvfs, name, fd);
		if (!NT_STATUS_IS_OK(status)) {
			idr_remove(pvfs->idtree_fnum, fnum);
			close(fd);
			return status;
		}
	}

	/* re-resolve the open fd */
	status = pvfs_resolve_name_fd(pvfs, fd, name);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
		return status;
	}

	name->dos.attrib = attrib;
	status = pvfs_dosattrib_save(pvfs, name, fd);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
		return status;
	}

	/* form the lock context used for byte range locking and
	   opendb locking */
	status = pvfs_locking_key(name, f->handle, &f->handle->odb_locking_key);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
		return status;
	}

	status = pvfs_brl_locking_key(name, f->handle, &f->handle->brl_locking_key);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
		return status;
	}

	/* grab a lock on the open file record */
	lck = odb_lock(req, pvfs->odb_context, &f->handle->odb_locking_key);
	if (lck == NULL) {
		DEBUG(0,("pvfs_open: failed to lock file '%s' in opendb\n",
			 name->full_name));
		/* we were supposed to do a blocking lock, so something
		   is badly wrong! */
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = odb_open_file(lck, f->handle, name->stream_id,
			       share_access, create_options, access_mask);
	talloc_free(lck);
	if (!NT_STATUS_IS_OK(status)) {
		/* bad news, we must have hit a race */
		idr_remove(pvfs->idtree_fnum, fnum);
		close(fd);
		return status;
	}

	f->fnum              = fnum;
	f->session           = req->session;
	f->smbpid            = req->smbpid;
	f->pvfs              = pvfs;
	f->pending_list      = NULL;
	f->lock_count        = 0;
	f->share_access      = io->generic.in.share_access;
	f->access_mask       = access_mask;
	f->impersonation     = io->generic.in.impersonation;

	f->handle->pvfs              = pvfs;
	f->handle->name              = talloc_steal(f->handle, name);
	f->handle->fd                = fd;
	f->handle->create_options    = io->generic.in.create_options;
	f->handle->seek_offset       = 0;
	f->handle->position          = 0;
	f->handle->mode              = 0;
	f->handle->have_opendb_entry = True;

	DLIST_ADD(pvfs->open_files, f);

	/* setup a destructor to avoid file descriptor leaks on
	   abnormal termination */
	talloc_set_destructor(f, pvfs_fnum_destructor);
	talloc_set_destructor(f->handle, pvfs_handle_destructor);

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
  state of a pending open retry
*/
struct pvfs_open_retry {
	struct ntvfs_module_context *ntvfs;
	struct smbsrv_request *req;
	union smb_open *io;
	void *wait_handle;
	DATA_BLOB odb_locking_key;
};

/* destroy a pending open request */
static int pvfs_retry_destructor(void *ptr)
{
	struct pvfs_open_retry *r = ptr;
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
	struct smbsrv_request *req = r->req;
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
				   struct smbsrv_request *req, union smb_open *io,
				   struct pvfs_file *f, struct odb_lock *lck)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_file *f2;
	struct pvfs_filename *name;

	/* search for an existing open with the right parameters. Note
	   the magic ntcreatex options flag, which is set in the
	   generic mapping code. This might look ugly, but its
	   actually pretty much now w2k does it internally as well. 
	   
	   If you look at the BASE-DENYDOS test you will see that a
	   DENY_DOS is a very special case, and in the right
	   circumstances you actually get the _same_ handle back
	   twice, rather than a new handle.
	*/
	for (f2=pvfs->open_files;f2;f2=f2->next) {
		if (f2 != f &&
		    f2->session == req->session &&
		    f2->smbpid == req->smbpid &&
		    (f2->handle->create_options & 
		     (NTCREATEX_OPTIONS_PRIVATE_DENY_DOS |
		      NTCREATEX_OPTIONS_PRIVATE_DENY_FCB)) &&
		    (f2->access_mask & SA_RIGHT_FILE_WRITE_DATA) &&
		    StrCaseCmp(f2->handle->name->original_name, 
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

	io->generic.out.oplock_level  = NO_OPLOCK;
	io->generic.out.fnum	      = f->fnum;
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

	talloc_steal(f->pvfs, f);

	return NT_STATUS_OK;
}



/*
  setup for a open retry after a sharing violation
*/
static NTSTATUS pvfs_open_setup_retry(struct ntvfs_module_context *ntvfs,
				      struct smbsrv_request *req, 
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

	r = talloc_p(req, struct pvfs_open_retry);
	if (r == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	r->ntvfs = ntvfs;
	r->req = req;
	r->io = io;
	r->odb_locking_key = data_blob_talloc(r, 
					      f->handle->odb_locking_key.data, 
					      f->handle->odb_locking_key.length);

	end_time = timeval_add(&req->request_time, 0, pvfs->sharing_violation_delay);

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
  special handling for t2open
*/
static NTSTATUS pvfs_open_t2open(struct ntvfs_module_context *ntvfs,
				 struct smbsrv_request *req, union smb_open *io)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	struct pvfs_filename *name;
	NTSTATUS status;

	status = pvfs_resolve_name(pvfs, req, io->t2open.in.fname, 0, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (io->t2open.in.open_func & OPENX_OPEN_FUNC_CREATE) {
		if (!name->stream_exists) return NT_STATUS_ACCESS_DENIED;
	}
	if (io->t2open.in.open_func & OPENX_OPEN_FUNC_TRUNC) {
		if (name->stream_exists) return NT_STATUS_ACCESS_DENIED;
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if ((io->t2open.in.open_func & 0xF) == OPENX_OPEN_FUNC_FAIL) {
		if (!name->stream_exists) return NT_STATUS_ACCESS_DENIED;
		return NT_STATUS_OBJECT_NAME_COLLISION;
	}

	talloc_free(name);

	return ntvfs_map_open(req, io, ntvfs);
}

/*
  open a file
*/
NTSTATUS pvfs_open(struct ntvfs_module_context *ntvfs,
		   struct smbsrv_request *req, union smb_open *io)
{
	struct pvfs_state *pvfs = ntvfs->private_data;
	int flags;
	struct pvfs_filename *name;
	struct pvfs_file *f;
	NTSTATUS status;
	int fnum, fd;
	struct odb_lock *lck;
	uint32_t create_options;
	uint32_t share_access;
	uint32_t access_mask;
	BOOL stream_existed;

	if (io->generic.level == RAW_OPEN_T2OPEN) {
		return pvfs_open_t2open(ntvfs, req, io);
	}

	/* use the generic mapping code to avoid implementing all the
	   different open calls. */
	if (io->generic.level != RAW_OPEN_GENERIC) {
		return ntvfs_map_open(req, io, ntvfs);
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
		if (!name->stream_exists) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		flags = 0;
		break;

	case NTCREATEX_DISP_OVERWRITE:
		if (!name->stream_exists) {
			return NT_STATUS_OBJECT_NAME_NOT_FOUND;
		}
		flags = O_TRUNC;
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

	if (access_mask & SA_RIGHT_FILE_WRITE_APPEND) {
		flags |= O_RDWR;
	} else {
		flags |= O_RDONLY;
	}

	if (io->generic.in.file_attr & FILE_ATTRIBUTE_DIRECTORY) {
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

	f = talloc_p(req, struct pvfs_file);
	if (f == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	f->handle = talloc_p(f, struct pvfs_file_handle);
	if (f->handle == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* allocate a fnum */
	fnum = idr_get_new_above(pvfs->idtree_fnum, f, PVFS_MIN_FILE_FNUM, UINT16_MAX);
	if (fnum == -1) {
		return NT_STATUS_TOO_MANY_OPENED_FILES;
	}

	f->fnum          = fnum;
	f->session       = req->session;
	f->smbpid        = req->smbpid;
	f->pvfs          = pvfs;
	f->pending_list  = NULL;
	f->lock_count    = 0;
	f->share_access  = io->generic.in.share_access;
	f->access_mask   = access_mask;
	f->impersonation = io->generic.in.impersonation;

	f->handle->pvfs              = pvfs;
	f->handle->fd                = -1;
	f->handle->name              = talloc_steal(f->handle, name);
	f->handle->create_options    = io->generic.in.create_options;
	f->handle->seek_offset       = 0;
	f->handle->position          = 0;
	f->handle->have_opendb_entry = False;

	/* form the lock context used for byte range locking and
	   opendb locking */
	status = pvfs_locking_key(name, f->handle, &f->handle->odb_locking_key);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, f->fnum);
		return status;
	}

	status = pvfs_brl_locking_key(name, f->handle, &f->handle->brl_locking_key);
	if (!NT_STATUS_IS_OK(status)) {
		idr_remove(pvfs->idtree_fnum, f->fnum);
		return status;
	}

	/* get a lock on this file before the actual open */
	lck = odb_lock(req, pvfs->odb_context, &f->handle->odb_locking_key);
	if (lck == NULL) {
		DEBUG(0,("pvfs_open: failed to lock file '%s' in opendb\n",
			 name->full_name));
		/* we were supposed to do a blocking lock, so something
		   is badly wrong! */
		idr_remove(pvfs->idtree_fnum, fnum);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	DLIST_ADD(pvfs->open_files, f);

	/* setup a destructor to avoid file descriptor leaks on
	   abnormal termination */
	talloc_set_destructor(f, pvfs_fnum_destructor);
	talloc_set_destructor(f->handle, pvfs_handle_destructor);


	/* see if we are allowed to open at the same time as existing opens */
	status = odb_open_file(lck, f->handle, f->handle->name->stream_id,
			       share_access, create_options, access_mask);

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

	f->handle->have_opendb_entry = True;

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

	io->generic.out.oplock_level  = NO_OPLOCK;
	io->generic.out.fnum	      = f->fnum;
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

	/* success - keep the file handle */
	talloc_steal(f->pvfs, f);

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
		utime(f->handle->name->full_name, &unix_times);
	}
	
	talloc_free(f);

	return NT_STATUS_OK;
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

	if (f->handle->create_options == create_options) {
		return NT_STATUS_OK;
	}

	if ((f->handle->name->dos.attrib & FILE_ATTRIBUTE_READONLY) &&
	    (create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE)) {
		return NT_STATUS_CANNOT_DELETE;
	}

	lck = odb_lock(req, pvfs->odb_context, &f->handle->odb_locking_key);
	if (lck == NULL) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	status = odb_set_create_options(lck, f->handle, create_options);
	if (NT_STATUS_IS_OK(status)) {
		f->handle->create_options = create_options;
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
			      NTCREATEX_OPTIONS_DELETE_ON_CLOSE, 
			      STD_RIGHT_DELETE_ACCESS);

	return status;
}

/*
  determine if a file can be renamed, or if it is prevented by an
  already open file
*/
NTSTATUS pvfs_can_rename(struct pvfs_state *pvfs, struct pvfs_filename *name)
{
	NTSTATUS status;
	DATA_BLOB key;

	status = pvfs_locking_key(name, name, &key);
	if (!NT_STATUS_IS_OK(status)) {
		return NT_STATUS_NO_MEMORY;
	}

	status = odb_can_open(pvfs->odb_context, &key, 
			      NTCREATEX_SHARE_ACCESS_READ |
			      NTCREATEX_SHARE_ACCESS_WRITE,
			      0,
			      STD_RIGHT_DELETE_ACCESS);

	return status;
}
