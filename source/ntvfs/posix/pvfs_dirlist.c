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
  directory listing functions for posix backend
*/

#include "includes.h"
#include "vfs_posix.h"
#include "system/dir.h"

#define NAME_CACHE_SIZE 100

struct name_cache_entry {
	char *name;
	off_t offset;
};

struct pvfs_dir {
	struct pvfs_state *pvfs;
	BOOL no_wildcard;
	char *single_name;
	const char *pattern;
	off_t offset;
	DIR *dir;
	const char *unix_path;
	BOOL end_of_search;
	struct name_cache_entry *name_cache;
	uint32_t name_cache_index;
};

/*
  a special directory listing case where the pattern has no wildcard. We can just do a single stat()
  thus avoiding the more expensive directory scan
*/
static NTSTATUS pvfs_list_no_wildcard(struct pvfs_state *pvfs, struct pvfs_filename *name, 
				      const char *pattern, struct pvfs_dir *dir)
{
	if (!name->exists) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	dir->pvfs = pvfs;
	dir->no_wildcard = True;
	dir->end_of_search = False;
	dir->unix_path = talloc_strdup(dir, name->full_name);
	if (!dir->unix_path) {
		return NT_STATUS_NO_MEMORY;
	}

	dir->single_name = talloc_strdup(dir, pattern);
	if (!dir->single_name) {
		return NT_STATUS_NO_MEMORY;
	}

	dir->dir = NULL;
	dir->offset = 0;
	dir->pattern = NULL;

	return NT_STATUS_OK;
}

/*
  destroy an open search
*/
static int pvfs_dirlist_destructor(void *ptr)
{
	struct pvfs_dir *dir = ptr;
	if (dir->dir) closedir(dir->dir);
	return 0;
}

/*
  start to read a directory 

  if the pattern matches no files then we return NT_STATUS_OK, with dir->count = 0
*/
NTSTATUS pvfs_list_start(struct pvfs_state *pvfs, struct pvfs_filename *name, 
			 TALLOC_CTX *mem_ctx, struct pvfs_dir **dirp)
{
	char *pattern;
	struct pvfs_dir *dir;

	(*dirp) = talloc_zero_p(mem_ctx, struct pvfs_dir);
	if (*dirp == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	
	dir = *dirp;

	/* split the unix path into a directory + pattern */
	pattern = strrchr(name->full_name, '/');
	if (!pattern) {
		/* this should not happen, as pvfs_unix_path is supposed to 
		   return an absolute path */
		return NT_STATUS_UNSUCCESSFUL;
	}

	*pattern++ = 0;

	if (!name->has_wildcard) {
		return pvfs_list_no_wildcard(pvfs, name, pattern, dir);
	}

	dir->unix_path = talloc_strdup(dir, name->full_name);
	if (!dir->unix_path) {
		return NT_STATUS_NO_MEMORY;
	}

	dir->pattern = talloc_strdup(dir, pattern);
	if (dir->pattern == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	
	dir->dir = opendir(name->full_name);
	if (!dir->dir) { 
		return pvfs_map_errno(pvfs, errno); 
	}

	dir->pvfs = pvfs;
	dir->no_wildcard = False;
	dir->end_of_search = False;
	dir->offset = 0;
	dir->name_cache = talloc_zero_array_p(dir, 
					      struct name_cache_entry, 
					      NAME_CACHE_SIZE);
	if (dir->name_cache == NULL) {
		talloc_free(dir);
		return NT_STATUS_NO_MEMORY;
	}

	talloc_set_destructor(dir, pvfs_dirlist_destructor);

	return NT_STATUS_OK;
}

/* 
   return the next entry
*/
const char *pvfs_list_next(struct pvfs_dir *dir, uint_t *ofs)
{
	struct dirent *de;

	/* non-wildcard searches are easy */
	if (dir->no_wildcard) {
		dir->end_of_search = True;
		if (*ofs != 0) return NULL;
		(*ofs)++;
		return dir->single_name;
	}

	if (*ofs != dir->offset) {
		seekdir(dir->dir, *ofs);
		dir->offset = *ofs;
	}
	
	while ((de = readdir(dir->dir))) {
		const char *dname = de->d_name;
		struct name_cache_entry *e;

		if (ms_fnmatch(dir->pattern, dname, 
			       dir->pvfs->tcon->smb_conn->negotiate.protocol) != 0) {
			char *short_name = pvfs_short_name_component(dir->pvfs, dname);
			if (short_name == NULL ||
			    ms_fnmatch(dir->pattern, short_name, 
				       dir->pvfs->tcon->smb_conn->negotiate.protocol) != 0) {
				talloc_free(short_name);
				continue;
			}
			talloc_free(short_name);
		}

		dir->offset = telldir(dir->dir);
		(*ofs) = dir->offset;

		dir->name_cache_index = (dir->name_cache_index+1) % NAME_CACHE_SIZE;
		e = &dir->name_cache[dir->name_cache_index];

		if (e->name) talloc_free(e->name);

		e->name = talloc_strdup(dir, de->d_name);
		e->offset = dir->offset;

		return e->name;
	}

	dir->end_of_search = True;
	pvfs_list_hibernate(dir);
	return NULL;
}

/* 
   put the directory to sleep. Used between search calls to give the
   right directory change semantics
*/
void pvfs_list_hibernate(struct pvfs_dir *dir)
{
	if (dir->dir) {
		closedir(dir->dir);
		dir->dir = NULL;
	}
}


/* 
   wake up the directory search
*/
NTSTATUS pvfs_list_wakeup(struct pvfs_dir *dir, uint_t *ofs)
{
	if (dir->no_wildcard ||
	    dir->dir != NULL) {
		return NT_STATUS_OK;
	}

	dir->dir = opendir(dir->unix_path);
	if (dir->dir == NULL) {
		dir->end_of_search = True;
		return pvfs_map_errno(dir->pvfs, errno);
	}

	seekdir(dir->dir, *ofs);
	dir->offset = telldir(dir->dir);
	if (dir->offset != *ofs) {
		DEBUG(0,("pvfs_list_wakeup: search offset changed %u -> %u\n", 
			 *ofs, (unsigned)dir->offset));
	}

	return NT_STATUS_OK;
}



/*
  return unix directory of an open search
*/
const char *pvfs_list_unix_path(struct pvfs_dir *dir)
{
	return dir->unix_path;
}

/*
  return True if end of search has been reached
*/
BOOL pvfs_list_eos(struct pvfs_dir *dir, uint_t ofs)
{
	return dir->end_of_search;
}

/*
  seek to the given name
*/
NTSTATUS pvfs_list_seek(struct pvfs_dir *dir, const char *name, uint_t *ofs)
{
	struct dirent *de;
	NTSTATUS status;
	int i;

	status = pvfs_list_wakeup(dir, ofs);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i=dir->name_cache_index;i>=0;i--) {
		struct name_cache_entry *e = &dir->name_cache[i];
		if (e->name && StrCaseCmp(name, e->name) == 0) {
			*ofs = e->offset;
			return NT_STATUS_OK;
		}
	}
	for (i=NAME_CACHE_SIZE-1;i>dir->name_cache_index;i--) {
		struct name_cache_entry *e = &dir->name_cache[i];
		if (e->name && StrCaseCmp(name, e->name) == 0) {
			*ofs = e->offset;
			return NT_STATUS_OK;
		}
	}

	rewinddir(dir->dir);

	while ((de = readdir(dir->dir))) {
		if (StrCaseCmp(name, de->d_name) == 0) {
			dir->offset = telldir(dir->dir);
			*ofs = dir->offset;
			return NT_STATUS_OK;
		}
	}

	dir->end_of_search = True;

	pvfs_list_hibernate(dir);

	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}
