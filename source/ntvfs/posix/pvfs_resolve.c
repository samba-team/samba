/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - filename resolution

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
  this is the core code for converting a filename from the format as
  given by a client to a posix filename, including any case-matching
  required, and checks for legal characters
*/


#include "include/includes.h"
#include "vfs_posix.h"

/*
  compare two filename components. This is where the name mangling hook will go
*/
static int component_compare(struct pvfs_state *pvfs, const char *comp, const char *name)
{
	int ret;

	ret = StrCaseCmp(comp, name);

	if (ret != 0) {
		char *shortname = pvfs_short_name_component(pvfs, name);
		if (shortname) {
			ret = StrCaseCmp(comp, shortname);
			talloc_free(shortname);
		}
	}

	return ret;
}

/*
  search for a filename in a case insensitive fashion

  TODO: add a cache for previously resolved case-insensitive names
  TODO: add mangled name support
*/
static NTSTATUS pvfs_case_search(struct pvfs_state *pvfs, struct pvfs_filename *name)
{
	/* break into a series of components */
	int num_components;
	char **components;
	char *p, *partial_name;
	int i;

	/* break up the full name info pathname components */
	num_components=2;
	p = name->full_name + strlen(pvfs->base_directory) + 1;

	for (;*p;p++) {
		if (*p == '/') {
			num_components++;
		}
	}

	components = talloc_array_p(name, char *, num_components);
	p = name->full_name + strlen(pvfs->base_directory);
	*p++ = 0;

	components[0] = name->full_name;

	for (i=1;i<num_components;i++) {
		components[i] = p;
		p = strchr(p, '/');
		if (p) *p++ = 0;
		if (pvfs_is_reserved_name(pvfs, components[i])) {
			return NT_STATUS_ACCESS_DENIED;
		}
	}

	partial_name = talloc_strdup(name, components[0]);
	if (!partial_name) {
		return NT_STATUS_NO_MEMORY;
	}

	/* for each component, check if it exists as-is, and if not then
	   do a directory scan */
	for (i=1;i<num_components;i++) {
		char *test_name;
		DIR *dir;
		struct dirent *de;
		char *long_component;

		/* possibly remap from the short name cache */
		long_component = pvfs_mangled_lookup(pvfs, name, components[i]);
		if (long_component) {
			components[i] = long_component;
		}

		test_name = talloc_asprintf(name, "%s/%s", partial_name, components[i]);
		if (!test_name) {
			return NT_STATUS_NO_MEMORY;
		}

		/* check if this component exists as-is */
		if (stat(test_name, &name->st) == 0) {
			if (i<num_components-1 && !S_ISDIR(name->st.st_mode)) {
				return NT_STATUS_NOT_A_DIRECTORY;
			}
			talloc_free(partial_name);
			partial_name = test_name;
			if (i == num_components - 1) {
				name->exists = True;
			}
			continue;
		}
		
		dir = opendir(partial_name);
		if (!dir) {
			return pvfs_map_errno(pvfs, errno);
		}

		while ((de = readdir(dir))) {
			if (component_compare(pvfs, components[i], de->d_name) == 0) {
				break;
			}
		}

		if (!de) {
			if (i < num_components-1) {
				closedir(dir);
				return NT_STATUS_OBJECT_NAME_NOT_FOUND;
			}
		} else {
			components[i] = talloc_strdup(name, de->d_name);
		}
		test_name = talloc_asprintf(name, "%s/%s", partial_name, components[i]);
		talloc_free(partial_name);
		partial_name = test_name;

		closedir(dir);
	}

	if (!name->exists) {
		if (stat(partial_name, &name->st) == 0) {
			name->exists = True;
		}
	}

	talloc_free(name->full_name);
	name->full_name = partial_name;

	if (name->exists) {
		return pvfs_fill_dos_info(pvfs, name);
	}

	return NT_STATUS_OK;
}


/*
  convert a CIFS pathname to a unix pathname. Note that this does NOT
  take into account case insensitivity, and in fact does not access
  the filesystem at all. It is merely a reformatting and charset
  checking routine.

  errors are returned if the filename is illegal given the flags
*/
static NTSTATUS pvfs_unix_path(struct pvfs_state *pvfs, const char *cifs_name,
			       uint_t flags, struct pvfs_filename *name)
{
	char *ret, *p;
	size_t len;

	name->original_name = talloc_strdup(name, cifs_name);
	name->stream_name = NULL;
	name->has_wildcard = False;

	while (*cifs_name == '\\') {
		cifs_name++;
	}

	if (*cifs_name == 0) {
		name->full_name = talloc_asprintf(name, "%s/.", pvfs->base_directory);
		if (name->full_name == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}

	ret = talloc_asprintf(name, "%s/%s", pvfs->base_directory, cifs_name);
	if (ret == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	p = ret + strlen(pvfs->base_directory) + 1;

	len = strlen(cifs_name);
	if (len>0 && p[len-1] == '\\') {
		p[len-1] = 0;
		len--;
	}
	if (len>1 && p[len-1] == '.' && p[len-2] == '\\') {
		return NT_STATUS_OBJECT_NAME_INVALID;
	}

	/* now do an in-place conversion of '\' to '/', checking
	   for legal characters */
	while (*p) {
		size_t c_size;
		codepoint_t c = next_codepoint(p, &c_size);
		switch (c) {
		case '\\':
			if (name->has_wildcard) {
				/* wildcards are only allowed in the last part
				   of a name */
				return NT_STATUS_ILLEGAL_CHARACTER;
			}
			*p = '/';
			break;
		case ':':
			if (!(flags & PVFS_RESOLVE_STREAMS)) {
				return NT_STATUS_ILLEGAL_CHARACTER;
			}
			name->stream_name = talloc_strdup(name, p+1);
			if (name->stream_name == NULL) {
				return NT_STATUS_NO_MEMORY;
			}
			*p-- = 0;
			break;
		case '*':
		case '>':
		case '<':
		case '?':
		case '"':
			if (flags & PVFS_RESOLVE_NO_WILDCARD) {
				return NT_STATUS_ILLEGAL_CHARACTER;
			}
			name->has_wildcard = True;
			break;
		case '/':
		case '|':
			return NT_STATUS_ILLEGAL_CHARACTER;
		}

		p += c_size;
	}

	name->full_name = ret;

	return NT_STATUS_OK;
}


/*
  resolve a name from relative client format to a struct pvfs_filename
  the memory for the filename is made as a talloc child of 'name'

  flags include:
     PVFS_RESOLVE_NO_WILDCARD = wildcards are considered illegal characters
     PVFS_RESOLVE_STREAMS     = stream names are allowed

     TODO: add reserved name checking (for things like LPT1)
     TODO: ../ collapsing, and outside share checking
*/
NTSTATUS pvfs_resolve_name(struct pvfs_state *pvfs, TALLOC_CTX *mem_ctx,
			   const char *cifs_name,
			   uint_t flags, struct pvfs_filename **name)
{
	NTSTATUS status;

	*name = talloc_p(mem_ctx, struct pvfs_filename);
	if (*name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	(*name)->exists = False;

	/* do the basic conversion to a unix formatted path,
	   also checking for allowable characters */
	status = pvfs_unix_path(pvfs, cifs_name, flags, *name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* if it has a wildcard then no point doing a stat() */
	if ((*name)->has_wildcard) {
		return NT_STATUS_OK;
	}

	/* if we can stat() the full name now then we are done */
	if (stat((*name)->full_name, &(*name)->st) == 0) {
		(*name)->exists = True;
		return pvfs_fill_dos_info(pvfs, *name);
	}

	/* the filesystem might be case insensitive, in which
	   case a search is pointless */
	if (pvfs->flags & PVFS_FLAG_CI_FILESYSTEM) {
		return NT_STATUS_OK;
	}

	/* search for a matching filename */
	status = pvfs_case_search(pvfs, *name);

	return status;
}


/*
  do a partial resolve, returning a pvfs_filename structure given a
  base path and a relative component. It is an error if the file does
  not exist. No case-insensitive matching is done.

  this is used in places like directory searching where we need a pvfs_filename
  to pass to a function, but already know the unix base directory and component
*/
NTSTATUS pvfs_resolve_partial(struct pvfs_state *pvfs, TALLOC_CTX *mem_ctx,
			      const char *unix_dir, const char *fname,
			      struct pvfs_filename **name)
{
	NTSTATUS status;

	*name = talloc_p(mem_ctx, struct pvfs_filename);
	if (*name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	(*name)->full_name = talloc_asprintf(*name, "%s/%s", unix_dir, fname);
	if ((*name)->full_name == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (stat((*name)->full_name, &(*name)->st) == -1) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	(*name)->exists = True;
	(*name)->has_wildcard = False;
	(*name)->original_name = talloc_strdup(*name, fname);
	(*name)->stream_name = NULL;

	status = pvfs_fill_dos_info(pvfs, *name);

	return status;
}


/*
  fill in the pvfs_filename info for an open file, given the current
  info for a (possibly) non-open file. This is used by places that need
  to update the pvfs_filename stat information, and by pvfs_open()
*/
NTSTATUS pvfs_resolve_name_fd(struct pvfs_state *pvfs, int fd,
			      struct pvfs_filename *name)
{
	if (fstat(fd, &name->st) == -1) {
		return NT_STATUS_INVALID_HANDLE;
	}

	name->exists = True;
	
	return pvfs_fill_dos_info(pvfs, name);
}
