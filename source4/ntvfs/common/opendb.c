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
#include "ntvfs/ntvfs.h"
#include "ntvfs/common/ntvfs_common.h"
#include "cluster/cluster.h"

static const struct opendb_ops *ops;

/*
  set the odb backend ops
*/
void odb_set_ops(const struct opendb_ops *new_ops)
{
	ops = new_ops;
}

/*
  Open up the openfiles.tdb database. Close it down using
  talloc_free(). We need the messaging_ctx to allow for pending open
  notifications.
*/
_PUBLIC_ struct odb_context *odb_init(TALLOC_CTX *mem_ctx, 
				      struct ntvfs_context *ntvfs_ctx)
{
	if (ops == NULL) {
		odb_tdb_init_ops();
	}
	return ops->odb_init(mem_ctx, ntvfs_ctx);
}

/*
  get a lock on a entry in the odb. This call returns a lock handle,
  which the caller should unlock using talloc_free().
*/
_PUBLIC_ struct odb_lock *odb_lock(TALLOC_CTX *mem_ctx,
				   struct odb_context *odb, DATA_BLOB *file_key)
{
	return ops->odb_lock(mem_ctx, odb, file_key);
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
	return ops->odb_open_file(lck, file_handle, stream_id, share_access,
				  access_mask, delete_on_close, path, oplock_level,
				  oplock_granted);
}


/*
  register a pending open file in the open files database
*/
_PUBLIC_ NTSTATUS odb_open_file_pending(struct odb_lock *lck, void *private)
{
	return ops->odb_open_file_pending(lck, private);
}


/*
  remove a opendb entry
*/
_PUBLIC_ NTSTATUS odb_close_file(struct odb_lock *lck, void *file_handle)
{
	return ops->odb_close_file(lck, file_handle);
}


/*
  remove a pending opendb entry
*/
_PUBLIC_ NTSTATUS odb_remove_pending(struct odb_lock *lck, void *private)
{
	return ops->odb_remove_pending(lck, private);
}


/*
  rename the path in a open file
*/
_PUBLIC_ NTSTATUS odb_rename(struct odb_lock *lck, const char *path)
{
	return ops->odb_rename(lck, path);
}

/*
  update delete on close flag on an open file
*/
_PUBLIC_ NTSTATUS odb_set_delete_on_close(struct odb_lock *lck, BOOL del_on_close)
{
	return ops->odb_set_delete_on_close(lck, del_on_close);
}

/*
  return the current value of the delete_on_close bit, and how many
  people still have the file open
*/
_PUBLIC_ NTSTATUS odb_get_delete_on_close(struct odb_context *odb, 
					  DATA_BLOB *key, BOOL *del_on_close, 
					  int *open_count, char **path)
{
	return ops->odb_get_delete_on_close(odb, key, del_on_close, open_count, path);
}


/*
  determine if a file can be opened with the given share_access,
  create_options and access_mask
*/
_PUBLIC_ NTSTATUS odb_can_open(struct odb_lock *lck,
			       uint32_t share_access, uint32_t create_options, 
			       uint32_t access_mask)
{
	return ops->odb_can_open(lck, share_access, create_options, access_mask);
}
