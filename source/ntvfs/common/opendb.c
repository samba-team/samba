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
#include "messages.h"
#include "librpc/gen_ndr/ndr_security.h"

struct odb_context {
	struct tdb_wrap *w;
	servid_t server;
	struct messaging_context *messaging_ctx;
};

/* 
   the database is indexed by a file_key, and contains entries of the
   following form
*/
struct odb_entry {
	servid_t server;
	void     *file_handle;
	uint32_t stream_id;
	uint32_t share_access;
	uint32_t create_options;
	uint32_t access_mask;
	void	 *notify_ptr;
	BOOL     pending;
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
struct odb_context *odb_init(TALLOC_CTX *mem_ctx, servid_t server, 
			     struct messaging_context *messaging_ctx)
{
	char *path;
	struct odb_context *odb;

	odb = talloc_p(mem_ctx, struct odb_context);
	if (odb == NULL) {
		return NULL;
	}

	path = smbd_tmp_path(odb, "openfiles.tdb");
	odb->w = tdb_wrap_open(odb, path, 0,  
			       TDB_DEFAULT,
			       O_RDWR|O_CREAT, 0600);
	talloc_free(path);
	if (odb->w == NULL) {
		talloc_free(odb);
		return NULL;
	}

	odb->server = server;
	odb->messaging_ctx = messaging_ctx;

	return odb;
}

/*
  destroy a lock on the database
*/
static int odb_lock_destructor(void *ptr)
{
	struct odb_lock *lck = ptr;
	tdb_chainunlock(lck->odb->w->tdb, lck->key);
	return 0;
}

/*
  get a lock on a entry in the odb. This call returns a lock handle,
  which the caller should unlock using talloc_free().
*/
struct odb_lock *odb_lock(TALLOC_CTX *mem_ctx,
			  struct odb_context *odb, DATA_BLOB *file_key)
{
	struct odb_lock *lck;

	lck = talloc_p(mem_ctx, struct odb_lock);
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
*/
static BOOL share_conflict(struct odb_entry *e1, struct odb_entry *e2)
{
#define CHECK_MASK(am, sa, right, share) if (((am) & (right)) && !((sa) & (share))) return True

	if (e1->pending || e2->pending) return False;

	/* if either open involves no read.write or delete access then
	   it can't conflict */
	if (!(e1->access_mask & (SEC_FILE_WRITE_DATA |
				 SEC_FILE_APPEND_DATA |
				 SEC_FILE_READ_DATA |
				 SEC_FILE_EXECUTE |
				 SEC_STD_DELETE))) {
		return False;
	}
	if (!(e2->access_mask & (SEC_FILE_WRITE_DATA |
				 SEC_FILE_APPEND_DATA |
				 SEC_FILE_READ_DATA |
				 SEC_FILE_EXECUTE |
				 SEC_STD_DELETE))) {
		return False;
	}

	/* data IO access masks. This is skipped if the two open handles
	   are on different streams (as in that case the masks don't
	   interact) */
	if (e1->stream_id != e2->stream_id) {
		return False;
	}

	CHECK_MASK(e1->access_mask, e2->share_access, 
		   SEC_FILE_WRITE_DATA | SEC_FILE_APPEND_DATA,
		   NTCREATEX_SHARE_ACCESS_WRITE);
	CHECK_MASK(e2->access_mask, e1->share_access, 
		   SEC_FILE_WRITE_DATA | SEC_FILE_APPEND_DATA,
		   NTCREATEX_SHARE_ACCESS_WRITE);
	
	CHECK_MASK(e1->access_mask, e2->share_access, 
		   SEC_FILE_READ_DATA | SEC_FILE_EXECUTE,
		   NTCREATEX_SHARE_ACCESS_READ);
	CHECK_MASK(e2->access_mask, e1->share_access, 
		   SEC_FILE_READ_DATA | SEC_FILE_EXECUTE,
		   NTCREATEX_SHARE_ACCESS_READ);

	CHECK_MASK(e1->access_mask, e2->share_access, 
		   SEC_STD_DELETE,
		   NTCREATEX_SHARE_ACCESS_DELETE);
	CHECK_MASK(e2->access_mask, e1->share_access, 
		   SEC_STD_DELETE,
		   NTCREATEX_SHARE_ACCESS_DELETE);

	/* if a delete is pending then a second open is not allowed */
	if ((e1->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) ||
	    (e2->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE)) {
		return True;
	}

	return False;
}

/*
  register an open file in the open files database. This implements the share_access
  rules
*/
NTSTATUS odb_open_file(struct odb_lock *lck, void *file_handle,
		       uint32_t stream_id,
		       uint32_t share_access, uint32_t create_options,
		       uint32_t access_mask)
{
	struct odb_context *odb = lck->odb;
	TDB_DATA dbuf;
	struct odb_entry e;
	int i, count;
	struct odb_entry *elist;
		
	dbuf = tdb_fetch(odb->w->tdb, lck->key);

	e.server         = odb->server;
	e.file_handle    = file_handle;
	e.stream_id      = stream_id;
	e.share_access   = share_access;
	e.create_options = create_options;
	e.access_mask    = access_mask;
	e.notify_ptr	 = NULL;
	e.pending        = False;

	/* check the existing file opens to see if they
	   conflict */
	elist = (struct odb_entry *)dbuf.dptr;
	count = dbuf.dsize / sizeof(struct odb_entry);

	for (i=0;i<count;i++) {
		if (share_conflict(elist+i, &e)) {
			if (dbuf.dptr) free(dbuf.dptr);
			return NT_STATUS_SHARING_VIOLATION;
		}
	}

	elist = realloc_p(dbuf.dptr, struct odb_entry, count+1);
	if (elist == NULL) {
		if (dbuf.dptr) free(dbuf.dptr);
		return NT_STATUS_NO_MEMORY;
	}

	dbuf.dptr = (char *)elist;
	dbuf.dsize = (count+1) * sizeof(struct odb_entry);

	memcpy(dbuf.dptr + (count*sizeof(struct odb_entry)),
	       &e, sizeof(struct odb_entry));

	if (tdb_store(odb->w->tdb, lck->key, dbuf, TDB_REPLACE) != 0) {
		free(dbuf.dptr);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	free(dbuf.dptr);
	return NT_STATUS_OK;
}


/*
  register a pending open file in the open files database
*/
NTSTATUS odb_open_file_pending(struct odb_lock *lck, void *private)
{
	struct odb_context *odb = lck->odb;
	TDB_DATA dbuf;
	struct odb_entry e;
	struct odb_entry *elist;
	int count;
		
	dbuf = tdb_fetch(odb->w->tdb, lck->key);

	e.server         = odb->server;
	e.file_handle    = NULL;
	e.stream_id      = 0;
	e.share_access   = 0;
	e.create_options = 0;
	e.access_mask    = 0;
	e.notify_ptr	 = private;
	e.pending        = True;

	/* check the existing file opens to see if they
	   conflict */
	elist = (struct odb_entry *)dbuf.dptr;
	count = dbuf.dsize / sizeof(struct odb_entry);

	elist = realloc_p(dbuf.dptr, struct odb_entry, count+1);
	if (elist == NULL) {
		if (dbuf.dptr) free(dbuf.dptr);
		return NT_STATUS_NO_MEMORY;
	}

	dbuf.dptr = (char *)elist;
	dbuf.dsize = (count+1) * sizeof(struct odb_entry);

	memcpy(dbuf.dptr + (count*sizeof(struct odb_entry)),
	       &e, sizeof(struct odb_entry));

	if (tdb_store(odb->w->tdb, lck->key, dbuf, TDB_REPLACE) != 0) {
		free(dbuf.dptr);
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	free(dbuf.dptr);
	return NT_STATUS_OK;
}


/*
  remove a opendb entry
*/
NTSTATUS odb_close_file(struct odb_lock *lck, void *file_handle)
{
	struct odb_context *odb = lck->odb;
	TDB_DATA dbuf;
	struct odb_entry *elist;
	int i, count;
	NTSTATUS status;

	dbuf = tdb_fetch(odb->w->tdb, lck->key);

	if (dbuf.dptr == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	elist = (struct odb_entry *)dbuf.dptr;
	count = dbuf.dsize / sizeof(struct odb_entry);

	/* send any pending notifications, removing them once sent */
	for (i=0;i<count;i++) {
		if (elist[i].pending) {
			messaging_send_ptr(odb->messaging_ctx, elist[i].server, 
					   MSG_PVFS_RETRY_OPEN, elist[i].notify_ptr);
			memmove(&elist[i], &elist[i+1], sizeof(struct odb_entry)*(count-(i+1)));
			i--;
			count--;
		}
	}

	/* find the entry, and delete it */
	for (i=0;i<count;i++) {
		if (file_handle == elist[i].file_handle &&
		    odb->server == elist[i].server) {
			if (i < count-1) {
				memmove(elist+i, elist+i+1, 
					(count - (i+1)) * sizeof(struct odb_entry));
			}
			break;
		}
	}

	status = NT_STATUS_OK;

	if (i == count) {
		status = NT_STATUS_UNSUCCESSFUL;
	} else if (count == 1) {
		if (tdb_delete(odb->w->tdb, lck->key) != 0) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else {
		dbuf.dsize = (count-1) * sizeof(struct odb_entry);
		if (tdb_store(odb->w->tdb, lck->key, dbuf, TDB_REPLACE) != 0) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	free(dbuf.dptr);

	return status;
}


/*
  remove a pending opendb entry
*/
NTSTATUS odb_remove_pending(struct odb_lock *lck, void *private)
{
	struct odb_context *odb = lck->odb;
	TDB_DATA dbuf;
	struct odb_entry *elist;
	int i, count;
	NTSTATUS status;

	dbuf = tdb_fetch(odb->w->tdb, lck->key);

	if (dbuf.dptr == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	elist = (struct odb_entry *)dbuf.dptr;
	count = dbuf.dsize / sizeof(struct odb_entry);

	/* find the entry, and delete it */
	for (i=0;i<count;i++) {
		if (private == elist[i].notify_ptr &&
		    odb->server == elist[i].server) {
			if (i < count-1) {
				memmove(elist+i, elist+i+1, 
					(count - (i+1)) * sizeof(struct odb_entry));
			}
			break;
		}
	}

	status = NT_STATUS_OK;

	if (i == count) {
		status = NT_STATUS_UNSUCCESSFUL;
	} else if (count == 1) {
		if (tdb_delete(odb->w->tdb, lck->key) != 0) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	} else {
		dbuf.dsize = (count-1) * sizeof(struct odb_entry);
		if (tdb_store(odb->w->tdb, lck->key, dbuf, TDB_REPLACE) != 0) {
			status = NT_STATUS_INTERNAL_DB_CORRUPTION;
		}
	}

	free(dbuf.dptr);

	return status;
}


/*
  update create options on an open file
*/
NTSTATUS odb_set_create_options(struct odb_lock *lck, 
				void *file_handle, uint32_t create_options)
{
	struct odb_context *odb = lck->odb;
	TDB_DATA dbuf;
	struct odb_entry *elist;
	int i, count;
	NTSTATUS status;

	dbuf = tdb_fetch(odb->w->tdb, lck->key);
	if (dbuf.dptr == NULL) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	elist = (struct odb_entry *)dbuf.dptr;
	count = dbuf.dsize / sizeof(struct odb_entry);

	/* find the entry, and modify it */
	for (i=0;i<count;i++) {
		if (file_handle == elist[i].file_handle &&
		    odb->server == elist[i].server) {
			elist[i].create_options = create_options;
			break;
		}
	}

	if (tdb_store(odb->w->tdb, lck->key, dbuf, TDB_REPLACE) != 0) {
		status = NT_STATUS_INTERNAL_DB_CORRUPTION;
	} else {
		status = NT_STATUS_OK;
	}

	free(dbuf.dptr);

	return status;
}


/*
  determine if a file can be opened with the given share_access,
  create_options and access_mask
*/
NTSTATUS odb_can_open(struct odb_context *odb, DATA_BLOB *key, 
		      uint32_t share_access, uint32_t create_options, 
		      uint32_t access_mask)
{
	TDB_DATA dbuf;
	TDB_DATA kbuf;
	struct odb_entry *elist;
	int i, count;
	struct odb_entry e;

	kbuf.dptr = (char *)key->data;
	kbuf.dsize = key->length;

	dbuf = tdb_fetch(odb->w->tdb, kbuf);
	if (dbuf.dptr == NULL) {
		return NT_STATUS_OK;
	}

	elist = (struct odb_entry *)dbuf.dptr;
	count = dbuf.dsize / sizeof(struct odb_entry);

	if (count == 0) {
		free(dbuf.dptr);
		return NT_STATUS_OK;
	}

	e.server         = odb->server;
	e.file_handle    = NULL;
	e.stream_id      = 0;
	e.share_access   = share_access;
	e.create_options = create_options;
	e.access_mask    = access_mask;
	e.notify_ptr	 = NULL;
	e.pending	 = False;

	for (i=0;i<count;i++) {
		if (share_conflict(elist+i, &e)) {
			if (dbuf.dptr) free(dbuf.dptr);
			return NT_STATUS_SHARING_VIOLATION;
		}
	}

	free(dbuf.dptr);
	return NT_STATUS_OK;
}
