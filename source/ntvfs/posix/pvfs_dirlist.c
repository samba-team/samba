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

	dir->count = 0;
	dir->unix_path = talloc_strdup(dir, name->full_name);
	if (!dir->unix_path) {
		return NT_STATUS_NO_MEMORY;
	}

	dir->names = talloc_array_p(dir, const char *, 1);
	if (!dir->names) {
		return NT_STATUS_NO_MEMORY;
	}

	dir->names[0] = talloc_strdup(dir, pattern);
	if (!dir->names[0]) {
		return NT_STATUS_NO_MEMORY;
	}

	dir->count = 1;

	return NT_STATUS_OK;
}

/*
  read a directory and find all matching file names, returning them in
  the structure *dir. The returned names are relative to the directory

  if the pattern matches no files then we return NT_STATUS_OK, with dir->count = 0
*/
NTSTATUS pvfs_list(struct pvfs_state *pvfs, struct pvfs_filename *name, struct pvfs_dir *dir)
{
	DIR *odir;
	struct dirent *dent;
	uint_t allocated = 0;
	char *pattern;

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

	dir->names = NULL;
	dir->count = 0;
	dir->unix_path = talloc_strdup(dir, name->full_name);
	if (!dir->unix_path) {
		return NT_STATUS_NO_MEMORY;
	}
	
	odir = opendir(name->full_name);
	if (!odir) { 
		return pvfs_map_errno(pvfs, errno); 
	}

	while ((dent = readdir(odir))) {
		uint_t i = dir->count;
		const char *dname = dent->d_name;

		if (ms_fnmatch(pattern, dname, 
			       pvfs->tcon->smb_conn->negotiate.protocol) != 0) {
			char *short_name = pvfs_short_name_component(pvfs, dname);
			if (short_name == NULL ||
			    ms_fnmatch(pattern, short_name, 
				       pvfs->tcon->smb_conn->negotiate.protocol) != 0) {
				talloc_free(short_name);
				continue;
			}
			talloc_free(short_name);
		}

		if (dir->count >= allocated) {
			allocated = (allocated + 100) * 1.2;
			dir->names = talloc_realloc_p(dir, dir->names, const char *, allocated);
			if (!dir->names) { 
				closedir(odir);
				return NT_STATUS_NO_MEMORY;
			}
		}

		dir->names[i] = talloc_strdup(dir, dname);
		if (!dir->names[i]) { 
			closedir(odir);
			return NT_STATUS_NO_MEMORY;
		}
		
		dir->count++;
	}

	closedir(odir);

	return NT_STATUS_OK;
}

