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
  fill in a single search result for a given info level
*/
static NTSTATUS fill_search_info(struct pvfs_state *pvfs,
				 enum smb_search_level level,
				 const char *unix_path,
				 const char *name, 
				 uint16_t search_attrib,
				 uint32_t dir_index,
				 union smb_search_data *file)
{
	struct pvfs_file_info *finfo;
	NTSTATUS status;

	finfo = talloc_p((TALLOC_CTX *)file, struct pvfs_file_info);
	if (!finfo) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pvfs_relative_file_info_cs(pvfs, unix_path, name, finfo);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(finfo);
		return status;
	}
	
	switch (level) {

	case RAW_SEARCH_BOTH_DIRECTORY_INFO:
		file->both_directory_info.file_index   = dir_index;
		file->both_directory_info.create_time  = finfo->create_time;
		file->both_directory_info.access_time  = finfo->access_time;
		file->both_directory_info.write_time   = finfo->write_time;
		file->both_directory_info.change_time  = finfo->change_time;
		file->both_directory_info.size         = finfo->size;
		file->both_directory_info.alloc_size   = finfo->alloc_size;
		file->both_directory_info.attrib       = finfo->attrib;
		file->both_directory_info.ea_size      = finfo->ea_size;
		file->both_directory_info.short_name.s = pvfs_short_name(pvfs, (TALLOC_CTX *)file, 
									 unix_path, name);
		file->both_directory_info.name.s       = name;
		break;
	}

	talloc_free(finfo);

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
   list files in a directory matching a wildcard pattern
*/
NTSTATUS pvfs_search_first(struct smbsrv_request *req, union smb_search_first *io, 
			   void *search_private, 
			   BOOL (*callback)(void *, union smb_search_data *))
{
	struct pvfs_dir *dir;
	struct pvfs_state *pvfs = req->tcon->ntvfs_private;
	struct pvfs_search_state *search;
	union smb_search_data *file;
	uint16_t max_count, reply_count;
	uint16_t search_attrib;
	const char *pattern;
	int i;
	NTSTATUS status;
	struct pvfs_filename *name;

	switch (io->generic.level) {
	case RAW_SEARCH_SEARCH:
		max_count     = io->search_first.in.max_count;
		search_attrib = io->search_first.in.search_attrib;
		pattern       = io->search_first.in.pattern;
		break;

	case RAW_SEARCH_STANDARD:
	case RAW_SEARCH_EA_SIZE:
	case RAW_SEARCH_DIRECTORY_INFO:
	case RAW_SEARCH_FULL_DIRECTORY_INFO:
	case RAW_SEARCH_NAME_INFO:
	case RAW_SEARCH_BOTH_DIRECTORY_INFO:
	case RAW_SEARCH_ID_FULL_DIRECTORY_INFO:
	case RAW_SEARCH_ID_BOTH_DIRECTORY_INFO:
	case RAW_SEARCH_UNIX_INFO:
		max_count     = io->t2ffirst.in.max_count;
		search_attrib = io->t2ffirst.in.search_attrib;
		pattern       = io->t2ffirst.in.pattern;
		break;

	case RAW_SEARCH_FCLOSE:
	case RAW_SEARCH_GENERIC:
		DEBUG(0,("WARNING: Invalid search class %d in pvfs_search_first\n", io->generic.level));
		return NT_STATUS_INVALID_INFO_CLASS;
	}

	/* resolve the cifs name to a posix name */
	status = pvfs_resolve_name(pvfs, req, pattern, 0, &name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (!name->has_wildcard && !name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
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

	if (dir->count < max_count) {
		max_count = dir->count;
	}

	file = talloc_p(req, union smb_search_data);
	if (!file) {
		return NT_STATUS_NO_MEMORY;
	}

	/* note that fill_search_info() can fail, if for example a
	   file disappears during a search or we don't have sufficient
	   permissions to stat() it, or the search_attrib does not
	   match the files attribute. In that case the name is ignored
	   and the search continues. */
	for (i=reply_count=0; i < dir->count && reply_count < max_count;i++) {
		status = fill_search_info(pvfs, io->generic.level, dir->unix_path, dir->names[i], 
					  search_attrib, i, file);
		if (NT_STATUS_IS_OK(status)) {
			if (!callback(search_private, file)) {
				break;
			}
			reply_count++;
		}
	}

	/* not matching any entries is an error */
	if (reply_count == 0) {
		return NT_STATUS_NO_MORE_ENTRIES;
	}

	search->current_index = i;

	if (io->generic.level == RAW_SEARCH_SEARCH) {
		io->search_first.out.count = reply_count;
		DEBUG(0,("TODO: handle RAW_SEARCH_SEARCH continue\n"));
	} else {
		io->t2ffirst.out.count = reply_count;
		io->t2ffirst.out.handle = search->handle;
		io->t2ffirst.out.end_of_search = (i == dir->count) ? 1 : 0;
		/* work out if we are going to keep the search state
		   and allow for a search continue */
		if ((io->t2ffirst.in.flags & FLAG_TRANS2_FIND_CLOSE) ||
		    ((io->t2ffirst.in.flags & FLAG_TRANS2_FIND_CLOSE_IF_END) && (i == dir->count))) {
			talloc_free(search);
		} else {
			pvfs->search.num_active_searches++;
			pvfs->search.next_search_handle++;
			talloc_steal(pvfs, search);
			DLIST_ADD(pvfs->search.open_searches, search);
		}
	}

	return NT_STATUS_OK;
}

/* continue a search */
NTSTATUS pvfs_search_next(struct smbsrv_request *req, union smb_search_next *io, 
			  void *search_private, 
			  BOOL (*callback)(void *, union smb_search_data *))
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* close a search */
NTSTATUS pvfs_search_close(struct smbsrv_request *req, union smb_search_close *io)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

