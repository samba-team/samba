/* 
   Unix SMB/CIFS implementation.

   simple NTVFS filesystem backend

   Copyright (C) Andrew Tridgell 2003

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
  utility functions for simple backend
*/

#include "includes.h"
#include "svfs.h"

/*
  convert a windows path to a unix path - don't do any manging or case sensitive handling
*/
char *svfs_unix_path(struct request_context *req, const char *name)
{
	struct svfs_private *private = req->conn->ntvfs_private;
	char *ret;

	if (*name != '\\') {
		ret = talloc_asprintf(req->mem_ctx, "%s/%s", private->connectpath, name);
	} else {
		ret = talloc_asprintf(req->mem_ctx, "%s%s", private->connectpath, name);
	}
	all_string_sub(ret, "\\", "/", 0);

	strlower(ret);

	return ret;
}


/*
  read a directory and find all matching file names and stat info
  returned names are separate unix and DOS names. The returned names
  are relative to the directory
*/
struct svfs_dir *svfs_list(TALLOC_CTX *mem_ctx, struct request_context *req, const char *pattern)
{
	char *unix_path;
	char *p, *mask;
	struct svfs_dir *dir;
	DIR *odir;
	struct dirent *dent;
	uint_t allocated = 0;
	char *low_mask;

	unix_path = svfs_unix_path(req, pattern);
	if (!unix_path) { return NULL; }

	dir = talloc(mem_ctx, sizeof(struct svfs_dir));
	if (!dir) { return NULL; }

	dir->count = 0;
	dir->files = 0;

	/* find the base directory */
	p = strrchr(unix_path, '/');
	if (!p) { return NULL; }

	dir->unix_dir = talloc_strndup(mem_ctx, unix_path, PTR_DIFF(p, unix_path));
	if (!dir->unix_dir) { return NULL; }

	/* the wildcard pattern is the last part */
	mask = p+1;

	low_mask = talloc_strdup(mem_ctx, mask);
	if (!low_mask) { return NULL; }
	strlower(low_mask);

	odir = opendir(dir->unix_dir);
	if (!odir) { return NULL; }

	while ((dent = readdir(odir))) {
		uint_t i = dir->count;
		char *full_name;
		char *low_name;

		low_name = talloc_strdup(mem_ctx, dent->d_name);
		if (!low_name) { continue; }
		strlower(low_name);

		/* check it matches the wildcard pattern */
		if (ms_fnmatch(low_mask, low_name, PROTOCOL_NT1) != 0) {
			continue;
		}
		
		if (dir->count >= allocated) {
			allocated = (allocated + 100) * 1.2;
			dir->files = talloc_realloc(mem_ctx, dir->files, allocated * sizeof(dir->files[0]));
			if (!dir->files) { 
				closedir(odir);
				return NULL;
			}
		}

		dir->files[i].name = low_name;
		if (!dir->files[i].name) { continue; }

		asprintf(&full_name, "%s/%s", dir->unix_dir, dir->files[i].name);
		if (!full_name) { continue; }

		if (stat(full_name, &dir->files[i].st) == 0) { 
			dir->count++;
		}

		free(full_name); 
	}

	closedir(odir);

	return dir;
}


/*
  convert a unix stat struct to a dos attrib
*/
uint32_t svfs_file_attrib(struct stat *st)
{
	if (S_ISDIR(st->st_mode)) {
		return FILE_ATTRIBUTE_DIRECTORY;
	}
	return 0;
}
