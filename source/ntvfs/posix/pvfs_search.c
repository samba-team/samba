/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - directory search functions

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
   list files in a directory matching a wildcard pattern - old SMBsearch interface
*/
static NTSTATUS pvfs_search_first_old(struct smbsrv_request *req, union smb_search_first *io, 
				      void *search_private, 
				      BOOL (*callback)(void *, union smb_search_data *))
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* continue a old style search */
static NTSTATUS pvfs_search_next_old(struct smbsrv_request *req, union smb_search_next *io, 
				     void *search_private, 
				     BOOL (*callback)(void *, union smb_search_data *))
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* close a old style search */
static NTSTATUS pvfs_search_close_old(struct smbsrv_request *req, union smb_search_close *io)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  fill in a single search result for a given info level
*/
static NTSTATUS fill_search_info(struct pvfs_state *pvfs,
				 enum smb_search_level level,
				 const char *unix_path,
				 const char *fname, 
				 uint16_t search_attrib,
				 uint32_t dir_index,
				 union smb_search_data *file)
{
	struct pvfs_filename *name;
	NTSTATUS status;

	status = pvfs_resolve_partial(pvfs, file, unix_path, fname, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!pvfs_match_attrib(pvfs, name, search_attrib)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	switch (level) {
	case RAW_SEARCH_STANDARD:
		file->standard.resume_key   = dir_index;
		file->standard.create_time  = nt_time_to_unix(name->dos.create_time);
		file->standard.access_time  = nt_time_to_unix(name->dos.access_time);
		file->standard.write_time   = nt_time_to_unix(name->dos.write_time);
		file->standard.size         = name->st.st_size;
		file->standard.alloc_size   = name->dos.alloc_size;
		file->standard.attrib       = name->dos.attrib;
		file->standard.name.s       = fname;
		break;

	case RAW_SEARCH_EA_SIZE:
		file->ea_size.resume_key   = dir_index;
		file->ea_size.create_time  = nt_time_to_unix(name->dos.create_time);
		file->ea_size.access_time  = nt_time_to_unix(name->dos.access_time);
		file->ea_size.write_time   = nt_time_to_unix(name->dos.write_time);
		file->ea_size.size         = name->st.st_size;
		file->ea_size.alloc_size   = name->dos.alloc_size;
		file->ea_size.attrib       = name->dos.attrib;
		file->ea_size.ea_size      = name->dos.ea_size;
		file->ea_size.name.s       = fname;
		break;

	case RAW_SEARCH_DIRECTORY_INFO:
		file->directory_info.file_index   = dir_index;
		file->directory_info.create_time  = name->dos.create_time;
		file->directory_info.access_time  = name->dos.access_time;
		file->directory_info.write_time   = name->dos.write_time;
		file->directory_info.change_time  = name->dos.change_time;
		file->directory_info.size         = name->st.st_size;
		file->directory_info.alloc_size   = name->dos.alloc_size;
		file->directory_info.attrib       = name->dos.attrib;
		file->directory_info.name.s       = fname;
		break;

	case RAW_SEARCH_FULL_DIRECTORY_INFO:
		file->full_directory_info.file_index   = dir_index;
		file->full_directory_info.create_time  = name->dos.create_time;
		file->full_directory_info.access_time  = name->dos.access_time;
		file->full_directory_info.write_time   = name->dos.write_time;
		file->full_directory_info.change_time  = name->dos.change_time;
		file->full_directory_info.size         = name->st.st_size;
		file->full_directory_info.alloc_size   = name->dos.alloc_size;
		file->full_directory_info.attrib       = name->dos.attrib;
		file->full_directory_info.ea_size      = name->dos.ea_size;
		file->full_directory_info.name.s       = fname;
		break;

	case RAW_SEARCH_NAME_INFO:
		file->name_info.file_index   = dir_index;
		file->name_info.name.s       = fname;
		break;

	case RAW_SEARCH_BOTH_DIRECTORY_INFO:
		file->both_directory_info.file_index   = dir_index;
		file->both_directory_info.create_time  = name->dos.create_time;
		file->both_directory_info.access_time  = name->dos.access_time;
		file->both_directory_info.write_time   = name->dos.write_time;
		file->both_directory_info.change_time  = name->dos.change_time;
		file->both_directory_info.size         = name->st.st_size;
		file->both_directory_info.alloc_size   = name->dos.alloc_size;
		file->both_directory_info.attrib       = name->dos.attrib;
		file->both_directory_info.ea_size      = name->dos.ea_size;
		file->both_directory_info.short_name.s = pvfs_short_name(pvfs, name);
		file->both_directory_info.name.s       = fname;
		break;

	case RAW_SEARCH_ID_FULL_DIRECTORY_INFO:
		file->id_full_directory_info.file_index   = dir_index;
		file->id_full_directory_info.create_time  = name->dos.create_time;
		file->id_full_directory_info.access_time  = name->dos.access_time;
		file->id_full_directory_info.write_time   = name->dos.write_time;
		file->id_full_directory_info.change_time  = name->dos.change_time;
		file->id_full_directory_info.size         = name->st.st_size;
		file->id_full_directory_info.alloc_size   = name->dos.alloc_size;
		file->id_full_directory_info.attrib       = name->dos.attrib;
		file->id_full_directory_info.ea_size      = name->dos.ea_size;
		file->id_full_directory_info.file_id      = name->dos.file_id;
		file->id_full_directory_info.name.s       = fname;
		break;

	case RAW_SEARCH_ID_BOTH_DIRECTORY_INFO:
		file->id_both_directory_info.file_index   = dir_index;
		file->id_both_directory_info.create_time  = name->dos.create_time;
		file->id_both_directory_info.access_time  = name->dos.access_time;
		file->id_both_directory_info.write_time   = name->dos.write_time;
		file->id_both_directory_info.change_time  = name->dos.change_time;
		file->id_both_directory_info.size         = name->st.st_size;
		file->id_both_directory_info.alloc_size   = name->dos.alloc_size;
		file->id_both_directory_info.attrib       = name->dos.attrib;
		file->id_both_directory_info.ea_size      = name->dos.ea_size;
		file->id_both_directory_info.file_id      = name->dos.file_id;
		file->id_both_directory_info.short_name.s = pvfs_short_name(pvfs, name);
		file->id_both_directory_info.name.s       = fname;
		break;

	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	return NT_STATUS_OK;
}

/*
  return the next available search handle
*/
static NTSTATUS pvfs_next_search_handle(struct pvfs_state *pvfs, uint16_t *handle)
{
	struct pvfs_search_state *search;

	if (pvfs->search.num_active_searches >= 0x10000) {
		return NT_STATUS_INSUFFICIENT_RESOURCES;
	}

	(*handle) = pvfs->search.next_search_handle;
	for (search=pvfs->search.open_searches;search;search=search->next) {
		if (*handle == search->handle) {
			*handle = ((*handle)+1) & 0xFFFF;
			continue;
		} 
	}
	pvfs->search.next_search_handle = ((*handle)+1) & 0xFFFF;

	return NT_STATUS_OK;
}


/*
  the search fill loop
*/
static NTSTATUS pvfs_search_fill(struct pvfs_state *pvfs, TALLOC_CTX *mem_ctx, 
				 uint_t max_count, 
				 struct pvfs_search_state *search,
				 enum smb_search_level level,
				 uint_t *reply_count,
				 void *search_private, 
				 BOOL (*callback)(void *, union smb_search_data *))
{
	int i;
	struct pvfs_dir *dir = search->dir;
	NTSTATUS status;

	*reply_count = 0;

	for (i = search->current_index; i < dir->count;i++) {
		union smb_search_data *file;

		file = talloc_p(mem_ctx, union smb_search_data);
		if (!file) {
			return NT_STATUS_NO_MEMORY;
		}

		status = fill_search_info(pvfs, level, dir->unix_path, dir->names[i], 
					  search->search_attrib, i, file);
		if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
			talloc_free(file);
			continue;
		}

		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(file);
			search->current_index = i;
			return status;
		}

		if (!callback(search_private, file)) {
			talloc_free(file);
			break;
		}
		(*reply_count)++;
		talloc_free(file);

		/* note that this deliberately allows a reply_count of
		   1 for a max_count of 0. w2k3 allows this too. */
		if (*reply_count >= max_count) break;
	}

	search->current_index = i;

	return NT_STATUS_OK;
}

/* 
   list files in a directory matching a wildcard pattern
*/
NTSTATUS pvfs_search_first(struct smbsrv_request *req, union smb_search_first *io, 
			   void *search_private, 
			   BOOL (*callback)(void *, union smb_search_data *))
{
	struct pvfs_dir *dir;
	struct pvfs_state *pvfs = req->tcon->ntvfs_private;
	struct pvfs_search_state *search;
	uint_t reply_count;
	uint16_t search_attrib;
	const char *pattern;
	NTSTATUS status;
	struct pvfs_filename *name;

	if (io->generic.level >= RAW_SEARCH_SEARCH) {
		return pvfs_search_first_old(req, io, search_private, callback);
	}

	search_attrib = io->t2ffirst.in.search_attrib;
	pattern       = io->t2ffirst.in.pattern;

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, pattern, 0, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->has_wildcard && !name->exists) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	/* we initially make search a child of the request, then if we
	   need to keep it long term we steal it for the private
	   structure */
	search = talloc_p(req, struct pvfs_search_state);
	if (!search) {
		return NT_STATUS_NO_MEMORY;
	}

	dir = talloc_p(search, struct pvfs_dir);
	if (!dir) {
		return NT_STATUS_NO_MEMORY;
	}

	/* do the actual directory listing */
	status = pvfs_list(pvfs, name, dir);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* we need to give a handle back to the client so it
	   can continue a search */
	status = pvfs_next_search_handle(pvfs, &search->handle);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	search->dir = dir;
	search->current_index = 0;
	search->search_attrib = search_attrib;

	status = pvfs_search_fill(pvfs, req, io->t2ffirst.in.max_count, search, io->generic.level,
				  &reply_count, search_private, callback);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* not matching any entries is an error */
	if (reply_count == 0) {
		return NT_STATUS_NO_SUCH_FILE;
	}

	io->t2ffirst.out.count = reply_count;
	io->t2ffirst.out.handle = search->handle;
	io->t2ffirst.out.end_of_search = (search->current_index == dir->count) ? 1 : 0;

	/* work out if we are going to keep the search state
	   and allow for a search continue */
	if ((io->t2ffirst.in.flags & FLAG_TRANS2_FIND_CLOSE) ||
	    ((io->t2ffirst.in.flags & FLAG_TRANS2_FIND_CLOSE_IF_END) && 
	     io->t2ffirst.out.end_of_search)) {
		talloc_free(search);
	} else {
		pvfs->search.num_active_searches++;
		pvfs->search.next_search_handle++;
		talloc_steal(pvfs, search);
		DLIST_ADD(pvfs->search.open_searches, search);
	}

	return NT_STATUS_OK;
}

/* continue a search */
NTSTATUS pvfs_search_next(struct smbsrv_request *req, union smb_search_next *io, 
			  void *search_private, 
			  BOOL (*callback)(void *, union smb_search_data *))
{
	struct pvfs_state *pvfs = req->tcon->ntvfs_private;
	struct pvfs_search_state *search;
	struct pvfs_dir *dir;
	uint_t reply_count;
	uint16_t handle;
	NTSTATUS status;
	int i;

	if (io->generic.level >= RAW_SEARCH_SEARCH) {
		return pvfs_search_next_old(req, io, search_private, callback);
	}

	handle = io->t2fnext.in.handle;

	for (search=pvfs->search.open_searches; search; search = search->next) {
		if (search->handle == handle) break;
	}
	
	if (!search) {
		/* we didn't find the search handle */
		return NT_STATUS_INVALID_HANDLE;
	}

	dir = search->dir;

	/* the client might be asking for something other than just continuing
	   with the search */
	if (!(io->t2fnext.in.flags & FLAG_TRANS2_FIND_CONTINUE) &&
	    io->t2fnext.in.last_name && *io->t2fnext.in.last_name) {
		/* look backwards first */
		for (i=search->current_index; i > 0; i--) {
			if (strcmp(io->t2fnext.in.last_name, dir->names[i-1]) == 0) {
				search->current_index = i;
				goto found;
			}
		}

		/* then look forwards */
		for (i=search->current_index+1; i <= dir->count; i++) {
			if (strcmp(io->t2fnext.in.last_name, dir->names[i-1]) == 0) {
				search->current_index = i;
				goto found;
			}
		}
	}

found:	
	status = pvfs_search_fill(pvfs, req, io->t2fnext.in.max_count, search, io->generic.level,
				  &reply_count, search_private, callback);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* not matching any entries is an error */
	if (reply_count == 0) {
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	io->t2fnext.out.count = reply_count;
	io->t2fnext.out.end_of_search = (search->current_index == dir->count) ? 1 : 0;

	/* work out if we are going to keep the search state */
	if ((io->t2fnext.in.flags & FLAG_TRANS2_FIND_CLOSE) ||
	    ((io->t2fnext.in.flags & FLAG_TRANS2_FIND_CLOSE_IF_END) && 
	     io->t2fnext.out.end_of_search)) {
		DLIST_REMOVE(pvfs->search.open_searches, search);
		talloc_free(search);
	}

	return NT_STATUS_OK;
}

/* close a search */
NTSTATUS pvfs_search_close(struct smbsrv_request *req, union smb_search_close *io)
{
	struct pvfs_state *pvfs = req->tcon->ntvfs_private;
	struct pvfs_search_state *search;
	uint16_t handle;

	if (io->generic.level >= RAW_SEARCH_SEARCH) {
		return pvfs_search_close_old(req, io);
	}

	handle = io->findclose.in.handle;

	for (search=pvfs->search.open_searches; search; search = search->next) {
		if (search->handle == handle) break;
	}
	
	if (!search) {
		/* we didn't find the search handle */
		return NT_STATUS_INVALID_HANDLE;
	}

	DLIST_REMOVE(pvfs->search.open_searches, search);
	talloc_free(search);

	return NT_STATUS_OK;
}

