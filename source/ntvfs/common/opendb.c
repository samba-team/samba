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

struct odb_context {
	struct tdb_wrap *w;
	servid_t server;
	uint16_t tid;
	void *messaging_ctx;
};

/* 
   the database is indexed by a file_key, and contains entries of the
   following form
*/
struct odb_entry {
	servid_t server;
	uint16_t tid;
	uint16_t fnum;
	uint32_t share_access;
	uint32_t create_options;
	uint32_t access_mask;
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
struct odb_context *odb_init(TALLOC_CTX *mem_ctx, servid_t server, uint16_t tid, 
			     void *messaging_ctx)
{
	char *path;
	struct odb_context *odb;

	odb = talloc_p(mem_ctx, struct odb_context);
	if (odb == NULL) {
		return NULL;
	}

	path = lock_path(odb, "openfiles.tdb");
	odb->w = tdb_wrap_open(odb, path, 0,  
			       TDB_DEFAULT|TDB_CLEAR_IF_FIRST,
			       O_RDWR|O_CREAT, 0600);
	talloc_free(path);
	if (odb->w == NULL) {
		talloc_free(odb);
		return NULL;
	}

	odb->server = server;
	odb->tid = tid;
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

	lck->odb = odb;
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
	uint32_t m1, m2;

	m1 = e1->access_mask & (SA_RIGHT_FILE_WRITE_DATA | SA_RIGHT_FILE_READ_DATA);
	m2 = e2->share_access & 
		(NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_READ);

	if ((m1 & m2) != m1) {
		return True;
	}

	m1 = e2->access_mask & (SA_RIGHT_FILE_WRITE_DATA | SA_RIGHT_FILE_READ_DATA);
	m2 = e1->share_access & 
		(NTCREATEX_SHARE_ACCESS_WRITE | NTCREATEX_SHARE_ACCESS_READ);

	if ((m1 & m2) != m1) {
		return True;
	}

	if ((e1->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE) ||
	    (e2->create_options & NTCREATEX_OPTIONS_DELETE_ON_CLOSE)) {
		return True;
	}

	if ((e1->access_mask & STD_RIGHT_DELETE_ACCESS) &&
	    !(e2->share_access & NTCREATEX_SHARE_ACCESS_DELETE)) {
		return True;
	}
	    

	return False;
}

/*
  register an open file in the open files database. This implements the share_access
  rules
*/
NTSTATUS odb_open_file(struct odb_lock *lck, uint16_t fnum, 
		       uint32_t share_access, uint32_t create_options,
		       uint32_t access_mask)
{
	struct odb_context *odb = lck->odb;
	TDB_DATA dbuf;
	struct odb_entry e;
	char *tp;
	int i, count;
	struct odb_entry *elist;
		
	dbuf = tdb_fetch(odb->w->tdb, lck->key);

	e.server         = odb->server;
	e.tid            = odb->tid;
	e.fnum           = fnum;
	e.share_access   = share_access;
	e.create_options = create_options;
	e.access_mask    = access_mask;

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

	tp = Realloc(dbuf.dptr, (count+1) * sizeof(struct odb_entry));
	if (tp == NULL) {
		if (dbuf.dptr) free(dbuf.dptr);
		return NT_STATUS_NO_MEMORY;
	}

	dbuf.dptr = tp;
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
NTSTATUS odb_close_file(struct odb_lock *lck, uint16_t fnum)
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
		if (fnum == elist[i].fnum &&
		    odb->server == elist[i].server &&
		    odb->tid == elist[i].tid) {
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
				uint16_t fnum, uint32_t create_options)
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
		if (fnum == elist[i].fnum &&
		    odb->server == elist[i].server &&
		    odb->tid == elist[i].tid) {
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
  determine if a file is open
*/
BOOL odb_is_open(struct odb_context *odb, DATA_BLOB *key)
{
	TDB_DATA dbuf;
	TDB_DATA kbuf;

	kbuf.dptr = key->data;
	kbuf.dsize = key->length;

	dbuf = tdb_fetch(odb->w->tdb, kbuf);
	if (dbuf.dptr == NULL) {
		return False;
	}
	free(dbuf.dptr);
	return True;
}
