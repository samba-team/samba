/* 
   Unix SMB/CIFS implementation.

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
  this is the open files database. It implements shared storage of
  what files are open between server instances, and implements the rules
  of shared access to files.

  The caller needs to provide a file_key, which specifies what file
  they are talking about. This needs to be a unique key across all
  filesystems, and is usually implemented in terms of a device/inode
  pair.

  Before any operations can be performed the caller needs to establish
  a lock on the record associated with file_key. That is done by
  calling odb_lock(). The caller releases this lock by calling
  talloc_free() on the returned handle.

  All other operations on a record are done by passing the odb_lock()
  handle back to this module. The handle contains internal
  information about what file_key is being operated on.
*/

#include "includes.h"
#include "system/filesys.h"
#include "lib/tdb/include/tdb.h"
#include "messaging/messaging.h"
#include "db_wrap.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_opendb.h"
#include "ntvfs/ntvfs.h"
#include "ntvfs/common/ntvfs_common.h"
#include "cluster/cluster.h"

struct odb_context {
	struct tdb_wrap *w;
	struct ntvfs_context *ntvfs_ctx;
	BOOL oplocks;
};

/*
  an odb lock handle. You must obtain one of these using odb_lock() before doing
  any other operations. 
*/
struct odb_lock {
	struct odb_context *odb;
	TDB_DATA key;
};

/*
  Open up the openfiles.tdb database. Close it down using
  talloc_free(). We need the messaging_ctx to allow for pending open
  notifications.
*/
_PUBLIC_ struct odb_context *odb_init(TALLOC_CTX *mem_ctx, 
				      struct ntvfs_context *ntvfs_ctx)
{
	struct odb_context *odb;

	odb = talloc(mem_ctx, struct odb_context);
	if (odb == NULL) {
		return NULL;
	}

	odb->w = cluster_tdb_tmp_open(odb, "openfiles.tdb", TDB_DEFAULT);
	if (odb->w == NULL) {
		talloc_free(odb);
		return NULL;
	}

	odb->ntvfs_ctx = ntvfs_ctx;

	/* leave oplocks disabled by default until the code is working */
	odb->oplocks = lp_parm_bool(-1, "opendb", "oplocks", False);

	return odb;
}

/*
  destroy a lock on the database
*/
static int odb_lock_destructor(struct odb_lock *lck)
{
	tdb_chainunlock(lck->odb->w->tdb, lck->key);
	return 0;
}

/*
  get a lock on a entry in the odb. This call returns a lock handle,
  which the caller should unlock using talloc_free().
*/
_PUBLIC_ struct odb_lock *odb_lock(TALLOC_CTX *mem_ctx,
				   struct odb_context *odb, DATA_BLOB *file_key)
{
	struct odb_lock *lck;

	lck = talloc(mem_ctx, struct odb_lock);
	if (lck == NULL) {
		return NULL;
	}

	lck->odb = talloc_reference(lck, odb);
	lck->key.dptr = talloc_memdup(lck, file_key->data, file_key->length);
	lck->key.dsize = file_key->length;
	if (lck->key.dptr == NULL) {
		talloc_free(lck);
		return NULL;
	}

	if (tdb_chainlock(odb->w->tdb, lck->key) != 0) {
		talloc_free(lck);
		return NULL;
	}

	talloc_set_destructor(lck, odb_lock_destructor);
	
	return lck;
}

/*
  determine if two odb_entry structures conflict

  return NT_STATUS_OK on no conflict
*/
static NTSTATUS share_conflict(struct opendb_entry *e1, struct opendb_entry *e2)
{
	/* if either open involves no read.write or delete access then
	   it can't conflict */
	if (!(e1->access_mask & (SEC_FILE_WRITE_DATA |
				 SEC_FILE_APPEND_DATA |
				 SEC_FILE_READ_DATA |
				 SEC_FILE_EXECUTE |
				 SEC_STD_DELETE))) {
		return NT_STATUS_OK;
	}
	if (!(e2->access_mask & (SEC_FILE_WRITE_DATA |
				 SEC_FILE_APPEND_DATA |
				 SEC_FILE_READ_DATA |
				 SEC_FILE_EXECUTE |
				 SEC_STD_DELETE))) {
		return NT_STATUS_OK;
	}

	/* data IO access masks. This is skipped if the two open handles
	   are on different streams (as in that case the masks don't
	   interact) */
	if (e1->stream_id != e2->stream_id) {
		return NT_STATUS_OK;
	}

#define CHECK_MASK(am, right, sa, share) \
	if (((am) & (right)) && !((sa) & (share))) return NT_STATUS_SHARING_VIOLATION

	CHECK_MASK(e1->access_mask, SEC_FILE_WRITE_DATA | SEC_FILE_APPEND_DATA,
		   e2->share_access, NTCREATEX_SHARE_ACCESS_WRITE);
	CHECK_MASK(e2->access_mask, SEC_FILE_WRITE_DATA | SEC_FILE_APPEND_DATA,
		   e1->share_access, NTCREATEX_SHARE_ACCESS_WRITE);
	
	CHECK_MASK(e1->access_mask, SEC_FILE_READ_DATA | SEC_FILE_EXECUTE,
		   e2->share_access, NTCREATEX_SHARE_ACCESS_READ);
	CHECK_MASK(e2->access_mask, SEC_FILE_READ_DATA | SEC_FILE_EXECUTE,
		   e1->share_access, NTCREATEX_SHARE_ACCESS_READ);

	CHECK_MASK(e1->access_mask, SEC_STD_DELETE,
		   e2->share_access, NTCREATEX_SHARE_ACCESS_DELETE);
	CHECK_MASK(e2->access_mask, SEC_STD_DELETE,
		   e1->share_access, NTCREATEX_SHARE_ACCESS_DELETE);

	return NT_STATUS_OK;
}

/*
  pull a record, translating from the db format to the opendb_file structure defined
  in opendb.idl
*/
static NTSTATUS odb_pull_record(struct odb_lock *lck, struct opendb_file *file)
{
	struct odb_context *odb = lck->odb;
	TDB_DATA dbuf;
	DATA_BLOB blob;
	NTSTATUS status;
		
	dbuf = tdb_fetch(odb->w->tdb, lck->key);
	if (dbuf.dptr == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	blob.data = dbuf.dptr;
	blob.length = dbuf.dsize;

	status = ndr_pull_struct_blob(&blob, lck, file, (ndr_pull_flags_fn_t)ndr_pull_opendb_file);

	free(dbuf.dptr);

	return status;
}

/*
  push a record, translating from the opendb_file structure defined in opendb.idl
*/
static NTSTATUS odb_push_record(struct odb_lock *lck, struct opendb_file *file)
{
	struct odb_context *odb = lck->odb;
	TDB_DATA dbuf;
	DATA_BLOB blob;
	NTSTATUS status;
	int ret;

	if (file->num_entries == 0) {
		ret = tdb_delete(odb->w->tdb, lck->key);
		if (ret != 0) {
			return NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
		return NT_STATUS_OK;
	}

	status = ndr_push_struct_blob(&blob, lck, file, (ndr_push_flags_fn_t)ndr_push_opendb_file);
	NT_STATUS_NOT_OK_RETURN(status);

	dbuf.dptr = blob.data;
	dbuf.dsize = blob.length;
		
	ret = tdb_store(odb->w->tdb, lck->key, dbuf, TDB_REPLACE);
	data_blob_free(&blob);
	if (ret != 0) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	return NT_STATUS_OK;
}

/*
  send an oplock break to a client
*/
static NTSTATUS odb_oplock_break_send(struct odb_context *odb, struct opendb_entry *e)
{
	/* tell the server handling this open file about the need to send the client
	   a break */
	return messaging_send_ptr(odb->ntvfs_ctx->msg_ctx, e->server, 
				  MSG_NTVFS_OPLOCK_BREAK, e->file_handle);
}

/*
  register an open file in the open files database. This implements the share_access
  rules

  Note that the path is only used by the delete on close logic, not
  for comparing with other filenames
*/
_PUBLIC_ NTSTATUS odb_open_file(struct odb_lock *lck, void *file_handle,
				uint32_t stream_id, uint32_t share_access, 
				uint32_t access_mask, BOOL delete_on_close,
				const char *path, 
				uint32_t oplock_level, uint32_t *oplock_granted)
{
	struct odb_context *odb = lck->odb;
	struct opendb_entry e;
	int i;
	struct opendb_file file;
	NTSTATUS status;

	if (odb->oplocks == False) {
		oplock_level = OPLOCK_NONE;
	}

	status = odb_pull_record(lck, &file);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/* initialise a blank structure */
		ZERO_STRUCT(file);
		file.path = path;
	} else {
		NT_STATUS_NOT_OK_RETURN(status);
	}

	/* see if it conflicts */
	e.server          = odb->ntvfs_ctx->server_id;
	e.file_handle     = file_handle;
	e.stream_id       = stream_id;
	e.share_access    = share_access;
	e.access_mask     = access_mask;
	e.delete_on_close = delete_on_close;
	e.oplock_level    = OPLOCK_NONE;
		
	/* see if anyone has an oplock, which we need to break */
	for (i=0;i<file.num_entries;i++) {
		if (file.entries[i].oplock_level == OPLOCK_BATCH) {
			/* a batch oplock caches close calls, which
			   means the client application might have
			   already closed the file. We have to allow
			   this close to propogate by sending a oplock
			   break request and suspending this call
			   until the break is acknowledged or the file
			   is closed */
			odb_oplock_break_send(odb, &file.entries[i]);
			return NT_STATUS_OPLOCK_NOT_GRANTED;
		}
	}

	if (file.delete_on_close || 
	    (file.num_entries != 0 && delete_on_close)) {
		/* while delete on close is set, no new opens are allowed */
		return NT_STATUS_DELETE_PENDING;
	}

	/* check for sharing violations */
	for (i=0;i<file.num_entries;i++) {
		status = share_conflict(&file.entries[i], &e);
		NT_STATUS_NOT_OK_RETURN(status);
	}

	/* we now know the open could succeed, but we need to check
	   for any exclusive oplocks. We can't grant a second open
	   till these are broken. Note that we check for batch oplocks
	   before checking for sharing violations, and check for
	   exclusive oplocks afterwards. */
	for (i=0;i<file.num_entries;i++) {
		if (file.entries[i].oplock_level == OPLOCK_EXCLUSIVE) {
			odb_oplock_break_send(odb, &file.entries[i]);
			return NT_STATUS_OPLOCK_NOT_GRANTED;
		}
	}

	/*
	  possibly grant an exclusive or batch oplock if this is the only client
	  with the file open. We don't yet grant levelII oplocks.
	*/
	if (oplock_granted != NULL) {
		if ((oplock_level == OPLOCK_BATCH ||
		     oplock_level == OPLOCK_EXCLUSIVE) &&
		    file.num_entries == 0) {
			(*oplock_granted) = oplock_level;
		} else {
			(*oplock_granted) = OPLOCK_NONE;
		}
		e.oplock_level = (*oplock_granted);
	}

	/* it doesn't conflict, so add it to the end */
	file.entries = talloc_realloc(lck, file.entries, struct opendb_entry, 
				      file.num_entries+1);
	NT_STATUS_HAVE_NO_MEMORY(file.entries);

	file.entries[file.num_entries] = e;
	file.num_entries++;

	return odb_push_record(lck, &file);
}


/*
  register a pending open file in the open files database
*/
_PUBLIC_ NTSTATUS odb_open_file_pending(struct odb_lock *lck, void *private)
{
	struct odb_context *odb = lck->odb;
	struct opendb_file file;
	NTSTATUS status;
		
	status = odb_pull_record(lck, &file);
	NT_STATUS_NOT_OK_RETURN(status);

	file.pending = talloc_realloc(lck, file.pending, struct opendb_pending, 
				      file.num_pending+1);
	NT_STATUS_HAVE_NO_MEMORY(file.pending);

	file.pending[file.num_pending].server = odb->ntvfs_ctx->server_id;
	file.pending[file.num_pending].notify_ptr = private;

	file.num_pending++;

	return odb_push_record(lck, &file);
}


/*
  remove a opendb entry
*/
_PUBLIC_ NTSTATUS odb_close_file(struct odb_lock *lck, void *file_handle)
{
	struct odb_context *odb = lck->odb;
	struct opendb_file file;
	int i;
	NTSTATUS status;

	status = odb_pull_record(lck, &file);
	NT_STATUS_NOT_OK_RETURN(status);

	/* find the entry, and delete it */
	for (i=0;i<file.num_entries;i++) {
		if (file_handle == file.entries[i].file_handle &&
		    cluster_id_equal(&odb->ntvfs_ctx->server_id, &file.entries[i].server)) {
			if (file.entries[i].delete_on_close) {
				file.delete_on_close = True;
			}
			if (i < file.num_entries-1) {
				memmove(file.entries+i, file.entries+i+1, 
					(file.num_entries - (i+1)) * 
					sizeof(struct opendb_entry));
			}
			break;
		}
	}

	if (i == file.num_entries) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	/* send any pending notifications, removing them once sent */
	for (i=0;i<file.num_pending;i++) {
		messaging_send_ptr(odb->ntvfs_ctx->msg_ctx, file.pending[i].server, 
				   MSG_PVFS_RETRY_OPEN, 
				   file.pending[i].notify_ptr);
	}
	file.num_pending = 0;

	file.num_entries--;
	
	return odb_push_record(lck, &file);
}


/*
  remove a pending opendb entry
*/
_PUBLIC_ NTSTATUS odb_remove_pending(struct odb_lock *lck, void *private)
{
	struct odb_context *odb = lck->odb;
	int i;
	NTSTATUS status;
	struct opendb_file file;

	status = odb_pull_record(lck, &file);
	NT_STATUS_NOT_OK_RETURN(status);

	/* find the entry, and delete it */
	for (i=0;i<file.num_pending;i++) {
		if (private == file.pending[i].notify_ptr &&
		    cluster_id_equal(&odb->ntvfs_ctx->server_id, &file.pending[i].server)) {
			if (i < file.num_pending-1) {
				memmove(file.pending+i, file.pending+i+1, 
					(file.num_pending - (i+1)) * 
					sizeof(struct opendb_pending));
			}
			break;
		}
	}

	if (i == file.num_pending) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	file.num_pending--;
	
	return odb_push_record(lck, &file);
}


/*
  rename the path in a open file
*/
_PUBLIC_ NTSTATUS odb_rename(struct odb_lock *lck, const char *path)
{
	struct opendb_file file;
	NTSTATUS status;

	status = odb_pull_record(lck, &file);
	if (NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_NOT_FOUND, status)) {
		/* not having the record at all is OK */
		return NT_STATUS_OK;
	}
	NT_STATUS_NOT_OK_RETURN(status);

	file.path = path;
	return odb_push_record(lck, &file);
}

/*
  update delete on close flag on an open file
*/
_PUBLIC_ NTSTATUS odb_set_delete_on_close(struct odb_lock *lck, BOOL del_on_close)
{
	NTSTATUS status;
	struct opendb_file file;

	status = odb_pull_record(lck, &file);
	NT_STATUS_NOT_OK_RETURN(status);

	file.delete_on_close = del_on_close;

	return odb_push_record(lck, &file);
}

/*
  return the current value of the delete_on_close bit, and how many
  people still have the file open
*/
_PUBLIC_ NTSTATUS odb_get_delete_on_close(struct odb_context *odb, 
					  DATA_BLOB *key, BOOL *del_on_close, 
					  int *open_count, char **path)
{
	NTSTATUS status;
	struct opendb_file file;
	struct odb_lock *lck;

	lck = odb_lock(odb, odb, key);
	NT_STATUS_HAVE_NO_MEMORY(lck);

	status = odb_pull_record(lck, &file);
	if (NT_STATUS_EQUAL(NT_STATUS_OBJECT_NAME_NOT_FOUND, status)) {
		talloc_free(lck);
		(*del_on_close) = False;
		return NT_STATUS_OK;
	}
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(lck);
		return status;
	}

	(*del_on_close) = file.delete_on_close;
	if (open_count != NULL) {
		(*open_count) = file.num_entries;
	}
	if (path != NULL) {
		*path = talloc_strdup(odb, file.path);
		NT_STATUS_HAVE_NO_MEMORY(*path);
		if (file.num_entries == 1 && file.entries[0].delete_on_close) {
			(*del_on_close) = True;
		}
	}

	talloc_free(lck);

	return NT_STATUS_OK;
}


/*
  determine if a file can be opened with the given share_access,
  create_options and access_mask
*/
_PUBLIC_ NTSTATUS odb_can_open(struct odb_lock *lck,
			       uint32_t share_access, uint32_t create_options, 
			       uint32_t access_mask)
{
	struct odb_context *odb = lck->odb;
	NTSTATUS status;
	struct opendb_file file;
	struct opendb_entry e;
	int i;

	status = odb_pull_record(lck, &file);
	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		return NT_STATUS_OK;
	}
	NT_STATUS_NOT_OK_RETURN(status);

	if ((create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) && 
	    file.num_entries != 0) {
		return NT_STATUS_SHARING_VIOLATION;
	}

	if (file.delete_on_close) {
		return NT_STATUS_DELETE_PENDING;
	}

	e.server       = odb->ntvfs_ctx->server_id;
	e.file_handle  = NULL;
	e.stream_id    = 0;
	e.share_access = share_access;
	e.access_mask  = access_mask;
		
	for (i=0;i<file.num_entries;i++) {
		status = share_conflict(&file.entries[i], &e);
		if (!NT_STATUS_IS_OK(status)) {
			/* note that we discard the error code
			   here. We do this as unless we are actually
			   doing an open (which comes via a different
			   function), we need to return a sharing
			   violation */
			return NT_STATUS_SHARING_VIOLATION;
		}
	}

	return NT_STATUS_OK;
}
