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
	uint32_t desired_access;
	uint32_t create_options;
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
