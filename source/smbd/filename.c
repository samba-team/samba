/*
   Unix SMB/CIFS implementation.
   filename handling routines
   Copyright (C) Andrew Tridgell 1992-1998
   Copyright (C) Jeremy Allison 1999-2007
   Copyright (C) Ying Chen 2000
   Copyright (C) Volker Lendecke 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * New hash table stat cache code added by Ying Chen.
 */

#include "includes.h"

static NTSTATUS build_stream_path(TALLOC_CTX *mem_ctx,
				  connection_struct *conn,
				  const char *orig_path,
				  const char *basepath,
				  const char *streamname,
				  SMB_STRUCT_STAT *pst,
				  char **path);

/****************************************************************************
 Mangle the 2nd name and check if it is then equal to the first name.
****************************************************************************/

static bool mangled_equal(const char *name1,
			const char *name2,
			const struct share_params *p)
{
	char mname[13];

	if (!name_to_8_3(name2, mname, False, p)) {
		return False;
	}
	return strequal(name1, mname);
}

/****************************************************************************
 Cope with the differing wildcard and non-wildcard error cases.
****************************************************************************/

static NTSTATUS determine_path_error(const char *name,
			bool allow_wcard_last_component)
{
	const char *p;

	if (!allow_wcard_last_component) {
		/* Error code within a pathname. */
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	/* We're terminating here so we
	 * can be a little slower and get
	 * the error code right. Windows
	 * treats the last part of the pathname
	 * separately I think, so if the last
	 * component is a wildcard then we treat
	 * this ./ as "end of component" */

	p = strchr(name, '/');

	if (!p && (ms_has_wild(name) || ISDOT(name))) {
		/* Error code at the end of a pathname. */
		return NT_STATUS_OBJECT_NAME_INVALID;
	} else {
		/* Error code within a pathname. */
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}
}

/****************************************************************************
This routine is called to convert names from the dos namespace to unix
namespace. It needs to handle any case conversions, mangling, format
changes etc.

We assume that we have already done a chdir() to the right "root" directory
for this service.

The function will return an NTSTATUS error if some part of the name except for
the last part cannot be resolved, else NT_STATUS_OK.

Note NT_STATUS_OK doesn't mean the name exists or is valid, just that we didn't
get any fatal errors that should immediately terminate the calling
SMB processing whilst resolving.

If the saved_last_component != 0, then the unmodified last component
of the pathname is returned there. If saved_last_component == 0 then nothing
is returned there.

If last_component_wcard is true then a MS wildcard was detected and
should be allowed in the last component of the path only.

On exit from unix_convert, if *pst was not null, then the file stat
struct will be returned if the file exists and was found, if not this
stat struct will be filled with zeros (and this can be detected by checking
for nlinks = 0, which can never be true for any file).
****************************************************************************/

NTSTATUS unix_convert(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *orig_path,
			bool allow_wcard_last_component,
			char **pp_conv_path,
			char **pp_saved_last_component,
			SMB_STRUCT_STAT *pst)
{
	SMB_STRUCT_STAT st;
	char *start, *end;
	char *dirpath = NULL;
	char *name = NULL;
	char *stream = NULL;
	bool component_was_mangled = False;
	bool name_has_wildcard = False;
	bool posix_pathnames = false;
	NTSTATUS result;
	int ret = -1;

	SET_STAT_INVALID(*pst);
	*pp_conv_path = NULL;
	if(pp_saved_last_component) {
		*pp_saved_last_component = NULL;
	}

	if (conn->printer) {
		/* we don't ever use the filenames on a printer share as a
			filename - so don't convert them */
		if (!(*pp_conv_path = talloc_strdup(ctx,orig_path))) {
			return NT_STATUS_NO_MEMORY;
		}
		return NT_STATUS_OK;
	}

	DEBUG(5, ("unix_convert called on file \"%s\"\n", orig_path));

	/*
	 * Conversion to basic unix format is already done in
	 * check_path_syntax().
	 */

	/*
	 * Names must be relative to the root of the service - any leading /.
	 * and trailing /'s should have been trimmed by check_path_syntax().
	 */

#ifdef DEVELOPER
	SMB_ASSERT(*orig_path != '/');
#endif

	/*
	 * If we trimmed down to a single '\0' character
	 * then we should use the "." directory to avoid
	 * searching the cache, but not if we are in a
	 * printing share.
	 * As we know this is valid we can return true here.
	 */

	if (!*orig_path) {
		if (!(name = talloc_strdup(ctx,"."))) {
			return NT_STATUS_NO_MEMORY;
		}
		if (SMB_VFS_STAT(conn,name,&st) == 0) {
			*pst = st;
		} else {
			return map_nt_error_from_unix(errno);
		}
		DEBUG(5,("conversion finished \"\" -> %s\n",name));
		goto done;
	}

	if (orig_path[0] == '.' && (orig_path[1] == '/' ||
				orig_path[1] == '\0')) {
		/* Start of pathname can't be "." only. */
		if (orig_path[1] == '\0' || orig_path[2] == '\0') {
			result = NT_STATUS_OBJECT_NAME_INVALID;
		} else {
			result =determine_path_error(
				&orig_path[2], allow_wcard_last_component);
		}
		return result;
	}

	if (!(name = talloc_strdup(ctx, orig_path))) {
		DEBUG(0, ("talloc_strdup failed\n"));
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * Large directory fix normalization. If we're case sensitive, and
	 * the case preserving parameters are set to "no", normalize the case of
	 * the incoming filename from the client WHETHER IT EXISTS OR NOT !
	 * This is in conflict with the current (3.0.20) man page, but is
	 * what people expect from the "large directory howto". I'll update
	 * the man page. Thanks to jht@samba.org for finding this. JRA.
	 */

	if (conn->case_sensitive && !conn->case_preserve &&
			!conn->short_case_preserve) {
		strnorm(name, lp_defaultcase(SNUM(conn)));
	}

	/*
	 * Ensure saved_last_component is valid even if file exists.
	 */

	if(pp_saved_last_component) {
		end = strrchr_m(name, '/');
		if (end) {
			*pp_saved_last_component = talloc_strdup(ctx, end + 1);
		} else {
			*pp_saved_last_component = talloc_strdup(ctx,
							name);
		}
	}

	posix_pathnames = lp_posix_pathnames();

	if (!posix_pathnames) {
		stream = strchr_m(name, ':');

		if (stream != NULL) {
			char *tmp = talloc_strdup(ctx, stream);
			if (tmp == NULL) {
				TALLOC_FREE(name);
				return NT_STATUS_NO_MEMORY;
			}
			*stream = '\0';
			stream = tmp;
		}
	}

	start = name;

	/* If we're providing case insentive semantics or
	 * the underlying filesystem is case insensitive,
	 * then a case-normalized hit in the stat-cache is
	 * authoratitive. JRA.
	 */

	if((!conn->case_sensitive || !(conn->fs_capabilities & FILE_CASE_SENSITIVE_SEARCH)) &&
			stat_cache_lookup(conn, &name, &dirpath, &start, &st)) {
		*pst = st;
		goto done;
	}

	/*
	 * Make sure "dirpath" is an allocated string, we use this for
	 * building the directories with asprintf and free it.
	 */

	if ((dirpath == NULL) && (!(dirpath = talloc_strdup(ctx,"")))) {
		DEBUG(0, ("talloc_strdup failed\n"));
		TALLOC_FREE(name);
		return NT_STATUS_NO_MEMORY;
	}

	/*
	 * stat the name - if it exists then we are all done!
	 */

	if (posix_pathnames) {
		ret = SMB_VFS_LSTAT(conn,name,&st);
	} else {
		ret = SMB_VFS_STAT(conn,name,&st);
	}

	if (ret == 0) {
		/* Ensure we catch all names with in "/."
		   this is disallowed under Windows. */
		const char *p = strstr(name, "/."); /* mb safe. */
		if (p) {
			if (p[2] == '/') {
				/* Error code within a pathname. */
				result = NT_STATUS_OBJECT_PATH_NOT_FOUND;
				goto fail;
			} else if (p[2] == '\0') {
				/* Error code at the end of a pathname. */
				result = NT_STATUS_OBJECT_NAME_INVALID;
				goto fail;
			}
		}
		stat_cache_add(orig_path, name, conn->case_sensitive);
		DEBUG(5,("conversion finished %s -> %s\n",orig_path, name));
		*pst = st;
		goto done;
	}

	DEBUG(5,("unix_convert begin: name = %s, dirpath = %s, start = %s\n",
				name, dirpath, start));

	/*
	 * A special case - if we don't have any mangling chars and are case
	 * sensitive or the underlying filesystem is case insentive then searching
	 * won't help.
	 */

	if ((conn->case_sensitive || !(conn->fs_capabilities & FILE_CASE_SENSITIVE_SEARCH)) &&
			!mangle_is_mangled(name, conn->params)) {
		goto done;
	}

	/*
	 * is_mangled() was changed to look at an entire pathname, not
	 * just a component. JRA.
	 */

	if (mangle_is_mangled(start, conn->params)) {
		component_was_mangled = True;
	}

	/*
	 * Now we need to recursively match the name against the real
	 * directory structure.
	 */

	/*
	 * Match each part of the path name separately, trying the names
	 * as is first, then trying to scan the directory for matching names.
	 */

	for (; start ; start = (end?end+1:(char *)NULL)) {
		/*
		 * Pinpoint the end of this section of the filename.
		 */
		/* mb safe. '/' can't be in any encoded char. */
		end = strchr(start, '/');

		/*
		 * Chop the name at this point.
		 */
		if (end) {
			*end = 0;
		}

		if (pp_saved_last_component) {
			TALLOC_FREE(*pp_saved_last_component);
			*pp_saved_last_component = talloc_strdup(ctx,
							end ? end + 1 : start);
			if (!*pp_saved_last_component) {
				DEBUG(0, ("talloc failed\n"));
				return NT_STATUS_NO_MEMORY;
			}
		}

		/* The name cannot have a component of "." */

		if (ISDOT(start)) {
			if (!end)  {
				/* Error code at the end of a pathname. */
				result = NT_STATUS_OBJECT_NAME_INVALID;
			} else {
				result = determine_path_error(end+1,
						allow_wcard_last_component);
			}
			goto fail;
		}

		/* The name cannot have a wildcard if it's not
		   the last component. */

		name_has_wildcard = ms_has_wild(start);

		/* Wildcard not valid anywhere. */
		if (name_has_wildcard && !allow_wcard_last_component) {
			result = NT_STATUS_OBJECT_NAME_INVALID;
			goto fail;
		}

		/* Wildcards never valid within a pathname. */
		if (name_has_wildcard && end) {
			result = NT_STATUS_OBJECT_NAME_INVALID;
			goto fail;
		}

		/*
		 * Check if the name exists up to this point.
		 */

		if (posix_pathnames) {
			ret = SMB_VFS_LSTAT(conn,name, &st);
		} else {
			ret = SMB_VFS_STAT(conn,name, &st);
		}

		if (ret == 0) {
			/*
			 * It exists. it must either be a directory or this must
			 * be the last part of the path for it to be OK.
			 */
			if (end && !(st.st_mode & S_IFDIR)) {
				/*
				 * An intermediate part of the name isn't
				 * a directory.
				 */
				DEBUG(5,("Not a dir %s\n",start));
				*end = '/';
				/*
				 * We need to return the fact that the
				 * intermediate name resolution failed. This
				 * is used to return an error of ERRbadpath
				 * rather than ERRbadfile. Some Windows
				 * applications depend on the difference between
				 * these two errors.
				 */
				result = NT_STATUS_OBJECT_PATH_NOT_FOUND;
				goto fail;
			}

			if (!end) {
				/*
				 * We just scanned for, and found the end of
				 * the path. We must return the valid stat
				 * struct. JRA.
				 */

				*pst = st;
			}

		} else {
			char *found_name = NULL;

			/* Stat failed - ensure we don't use it. */
			SET_STAT_INVALID(st);

			/*
			 * Reset errno so we can detect
			 * directory open errors.
			 */
			errno = 0;

			/*
			 * Try to find this part of the path in the directory.
			 */

			if (name_has_wildcard ||
			    (SMB_VFS_GET_REAL_FILENAME(
				     conn, dirpath, start,
				     talloc_tos(), &found_name) == -1)) {
				char *unmangled;

				if (end) {
					/*
					 * An intermediate part of the name
					 * can't be found.
					 */
					DEBUG(5,("Intermediate not found %s\n",
							start));
					*end = '/';

					/*
					 * We need to return the fact that the
					 * intermediate name resolution failed.
					 * This is used to return an error of
					 * ERRbadpath rather than ERRbadfile.
					 * Some Windows applications depend on
					 * the difference between these two
					 * errors.
					 */

					/*
					 * ENOENT, ENOTDIR and ELOOP all map
					 * to NT_STATUS_OBJECT_PATH_NOT_FOUND
					 * in the filename walk.
					 */

					if (errno == ENOENT ||
							errno == ENOTDIR ||
							errno == ELOOP) {
						result =
						NT_STATUS_OBJECT_PATH_NOT_FOUND;
					}
					else {
						result =
						map_nt_error_from_unix(errno);
					}
					goto fail;
				}

				/* ENOENT is the only valid error here. */
				if ((errno != 0) && (errno != ENOENT)) {
					/*
					 * ENOTDIR and ELOOP both map to
					 * NT_STATUS_OBJECT_PATH_NOT_FOUND
					 * in the filename walk.
					 */
					if (errno == ENOTDIR ||
							errno == ELOOP) {
						result =
						NT_STATUS_OBJECT_PATH_NOT_FOUND;
					}
					else {
						result =
						map_nt_error_from_unix(errno);
					}
					goto fail;
				}

				/*
				 * Just the last part of the name doesn't exist.
				 * We need to strupper() or strlower() it as
				 * this conversion may be used for file creation
				 * purposes. Fix inspired by
				 * Thomas Neumann <t.neumann@iku-ag.de>.
				 */
				if (!conn->case_preserve ||
				    (mangle_is_8_3(start, False,
						   conn->params) &&
						 !conn->short_case_preserve)) {
					strnorm(start,
						lp_defaultcase(SNUM(conn)));
				}

				/*
				 * check on the mangled stack to see if we can
				 * recover the base of the filename.
				 */

				if (mangle_is_mangled(start, conn->params)
				    && mangle_lookup_name_from_8_3(ctx,
					    		start,
							&unmangled,
							conn->params)) {
					char *tmp;
					size_t start_ofs = start - name;

					if (*dirpath != '\0') {
						tmp = talloc_asprintf(ctx,
							"%s/%s", dirpath,
							unmangled);
						TALLOC_FREE(unmangled);
					}
					else {
						tmp = unmangled;
					}
					if (tmp == NULL) {
						DEBUG(0, ("talloc failed\n"));
						return NT_STATUS_NO_MEMORY;
					}
					TALLOC_FREE(name);
					name = tmp;
					start = name + start_ofs;
					end = start + strlen(start);
				}

				DEBUG(5,("New file %s\n",start));
				goto done;
			}


			/*
			 * Restore the rest of the string. If the string was
			 * mangled the size may have changed.
			 */
			if (end) {
				char *tmp;
				size_t start_ofs = start - name;

				if (*dirpath != '\0') {
					tmp = talloc_asprintf(ctx,
						"%s/%s/%s", dirpath,
						found_name, end+1);
				}
				else {
					tmp = talloc_asprintf(ctx,
						"%s/%s", found_name,
						end+1);
				}
				if (tmp == NULL) {
					DEBUG(0, ("talloc_asprintf failed\n"));
					return NT_STATUS_NO_MEMORY;
				}
				TALLOC_FREE(name);
				name = tmp;
				start = name + start_ofs;
				end = start + strlen(found_name);
				*end = '\0';
			} else {
				char *tmp;
				size_t start_ofs = start - name;

				if (*dirpath != '\0') {
					tmp = talloc_asprintf(ctx,
						"%s/%s", dirpath,
						found_name);
				} else {
					tmp = talloc_strdup(ctx,
						found_name);
				}
				if (tmp == NULL) {
					DEBUG(0, ("talloc failed\n"));
					return NT_STATUS_NO_MEMORY;
				}
				TALLOC_FREE(name);
				name = tmp;
				start = name + start_ofs;

				/*
				 * We just scanned for, and found the end of
				 * the path. We must return a valid stat struct
				 * if it exists. JRA.
				 */

				if (posix_pathnames) {
					ret = SMB_VFS_LSTAT(conn,name, &st);
				} else {
					ret = SMB_VFS_STAT(conn,name, &st);
				}

				if (ret == 0) {
					*pst = st;
				} else {
					SET_STAT_INVALID(st);
				}
			}

			TALLOC_FREE(found_name);
		} /* end else */

#ifdef DEVELOPER
		/*
		 * This sucks!
		 * We should never provide different behaviors
		 * depending on DEVELOPER!!!
		 */
		if (VALID_STAT(st)) {
			bool delete_pending;
			get_file_infos(vfs_file_id_from_sbuf(conn, &st),
				       &delete_pending, NULL);
			if (delete_pending) {
				result = NT_STATUS_DELETE_PENDING;
				goto fail;
			}
		}
#endif

		/*
		 * Add to the dirpath that we have resolved so far.
		 */

		if (*dirpath != '\0') {
			char *tmp = talloc_asprintf(ctx,
					"%s/%s", dirpath, start);
			if (!tmp) {
				DEBUG(0, ("talloc_asprintf failed\n"));
				return NT_STATUS_NO_MEMORY;
			}
			TALLOC_FREE(dirpath);
			dirpath = tmp;
		}
		else {
			TALLOC_FREE(dirpath);
			if (!(dirpath = talloc_strdup(ctx,start))) {
				DEBUG(0, ("talloc_strdup failed\n"));
				return NT_STATUS_NO_MEMORY;
			}
		}

		/*
		 * Don't cache a name with mangled or wildcard components
		 * as this can change the size.
		 */

		if(!component_was_mangled && !name_has_wildcard) {
			stat_cache_add(orig_path, dirpath,
					conn->case_sensitive);
		}

		/*
		 * Restore the / that we wiped out earlier.
		 */
		if (end) {
			*end = '/';
		}
	}

	/*
	 * Don't cache a name with mangled or wildcard components
	 * as this can change the size.
	 */

	if(!component_was_mangled && !name_has_wildcard) {
		stat_cache_add(orig_path, name, conn->case_sensitive);
	}

	/*
	 * The name has been resolved.
	 */

	DEBUG(5,("conversion finished %s -> %s\n",orig_path, name));

 done:
	if (stream != NULL) {
		char *tmp = NULL;

		result = build_stream_path(ctx, conn, orig_path, name, stream,
					   pst, &tmp);
		if (!NT_STATUS_IS_OK(result)) {
			goto fail;
		}

		DEBUG(10, ("build_stream_path returned %s\n", tmp));

		TALLOC_FREE(name);
		name = tmp;
	}
	*pp_conv_path = name;
	TALLOC_FREE(dirpath);
	return NT_STATUS_OK;
 fail:
	DEBUG(10, ("dirpath = [%s] start = [%s]\n", dirpath, start));
	if (*dirpath != '\0') {
		*pp_conv_path = talloc_asprintf(ctx,
				"%s/%s", dirpath, start);
	} else {
		*pp_conv_path = talloc_strdup(ctx, start);
	}
	if (!*pp_conv_path) {
		DEBUG(0, ("talloc_asprintf failed\n"));
		return NT_STATUS_NO_MEMORY;
	}
	TALLOC_FREE(name);
	TALLOC_FREE(dirpath);
	return result;
}

/****************************************************************************
 Check a filename - possibly calling check_reduced_name.
 This is called by every routine before it allows an operation on a filename.
 It does any final confirmation necessary to ensure that the filename is
 a valid one for the user to access.
****************************************************************************/

NTSTATUS check_name(connection_struct *conn, const char *name)
{
	if (IS_VETO_PATH(conn, name))  {
		/* Is it not dot or dot dot. */
		if (!((name[0] == '.') && (!name[1] ||
					(name[1] == '.' && !name[2])))) {
			DEBUG(5,("check_name: file path name %s vetoed\n",
						name));
			return map_nt_error_from_unix(ENOENT);
		}
	}

	if (!lp_widelinks(SNUM(conn)) || !lp_symlinks(SNUM(conn))) {
		NTSTATUS status = check_reduced_name(conn,name);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(5,("check_name: name %s failed with %s\n",name,
						nt_errstr(status)));
			return status;
		}
	}

	return NT_STATUS_OK;
}

/****************************************************************************
 Check if two filenames are equal.
 This needs to be careful about whether we are case sensitive.
****************************************************************************/

static bool fname_equal(const char *name1, const char *name2,
		bool case_sensitive)
{
	/* Normal filename handling */
	if (case_sensitive) {
		return(strcmp(name1,name2) == 0);
	}

	return(strequal(name1,name2));
}

/****************************************************************************
 Scan a directory to find a filename, matching without case sensitivity.
 If the name looks like a mangled name then try via the mangling functions
****************************************************************************/

int get_real_filename(connection_struct *conn, const char *path,
		      const char *name, TALLOC_CTX *mem_ctx,
		      char **found_name)
{
	struct smb_Dir *cur_dir;
	const char *dname;
	bool mangled;
	char *unmangled_name = NULL;
	long curpos;

	mangled = mangle_is_mangled(name, conn->params);

	/* handle null paths */
	if ((path == NULL) || (*path == 0)) {
		path = ".";
	}

	/* If we have a case-sensitive filesystem, it doesn't do us any
	 * good to search for a name. If a case variation of the name was
	 * there, then the original stat(2) would have found it.
	 */
	if (!mangled && !(conn->fs_capabilities & FILE_CASE_SENSITIVE_SEARCH)) {
		errno = ENOENT;
		return -1;
	}

	/*
	 * The incoming name can be mangled, and if we de-mangle it
	 * here it will not compare correctly against the filename (name2)
	 * read from the directory and then mangled by the name_to_8_3()
	 * call. We need to mangle both names or neither.
	 * (JRA).
	 *
	 * Fix for bug found by Dina Fine. If in case sensitive mode then
	 * the mangle cache is no good (3 letter extension could be wrong
	 * case - so don't demangle in this case - leave as mangled and
	 * allow the mangling of the directory entry read (which is done
	 * case insensitively) to match instead. This will lead to more
	 * false positive matches but we fail completely without it. JRA.
	 */

	if (mangled && !conn->case_sensitive) {
		mangled = !mangle_lookup_name_from_8_3(talloc_tos(), name,
						       &unmangled_name,
						       conn->params);
		if (!mangled) {
			/* Name is now unmangled. */
			name = unmangled_name;
		}
	}

	/* open the directory */
	if (!(cur_dir = OpenDir(talloc_tos(), conn, path, NULL, 0))) {
		DEBUG(3,("scan dir didn't open dir [%s]\n",path));
		TALLOC_FREE(unmangled_name);
		return -1;
	}

	/* now scan for matching names */
	curpos = 0;
	while ((dname = ReadDirName(cur_dir, &curpos))) {

		/* Is it dot or dot dot. */
		if (ISDOT(dname) || ISDOTDOT(dname)) {
			continue;
		}

		/*
		 * At this point dname is the unmangled name.
		 * name is either mangled or not, depending on the state
		 * of the "mangled" variable. JRA.
		 */

		/*
		 * Check mangled name against mangled name, or unmangled name
		 * against unmangled name.
		 */

		if ((mangled && mangled_equal(name,dname,conn->params)) ||
			fname_equal(name, dname, conn->case_sensitive)) {
			/* we've found the file, change it's name and return */
			*found_name = talloc_strdup(mem_ctx, dname);
			TALLOC_FREE(unmangled_name);
			TALLOC_FREE(cur_dir);
			if (!*found_name) {
				errno = ENOMEM;
				return -1;
			}
			return 0;
		}
	}

	TALLOC_FREE(unmangled_name);
	TALLOC_FREE(cur_dir);
	errno = ENOENT;
	return -1;
}

static NTSTATUS build_stream_path(TALLOC_CTX *mem_ctx,
				  connection_struct *conn,
				  const char *orig_path,
				  const char *basepath,
				  const char *streamname,
				  SMB_STRUCT_STAT *pst,
				  char **path)
{
	SMB_STRUCT_STAT st;
	char *result = NULL;
	NTSTATUS status;
	unsigned int i, num_streams;
	struct stream_struct *streams = NULL;

	result = talloc_asprintf(mem_ctx, "%s%s", basepath, streamname);
	if (result == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (SMB_VFS_STAT(conn, result, &st) == 0) {
		*pst = st;
		*path = result;
		return NT_STATUS_OK;
	}

	if (errno != ENOENT) {
		status = map_nt_error_from_unix(errno);
		DEBUG(10, ("vfs_stat failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	status = SMB_VFS_STREAMINFO(conn, NULL, basepath, mem_ctx,
				    &num_streams, &streams);

	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		SET_STAT_INVALID(*pst);
		*path = result;
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("vfs_streaminfo failed: %s\n", nt_errstr(status)));
		goto fail;
	}

	for (i=0; i<num_streams; i++) {
		DEBUG(10, ("comparing [%s] and [%s]: ",
			   streamname, streams[i].name));
		if (fname_equal(streamname, streams[i].name,
				conn->case_sensitive)) {
			DEBUGADD(10, ("equal\n"));
			break;
		}
		DEBUGADD(10, ("not equal\n"));
	}

	if (i == num_streams) {
		SET_STAT_INVALID(*pst);
		*path = result;
		TALLOC_FREE(streams);
		return NT_STATUS_OK;
	}

	TALLOC_FREE(result);

	result = talloc_asprintf(mem_ctx, "%s%s", basepath, streams[i].name);
	if (result == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	SET_STAT_INVALID(*pst);

	if (SMB_VFS_STAT(conn, result, pst) == 0) {
		stat_cache_add(orig_path, result, conn->case_sensitive);
	}

	*path = result;
	TALLOC_FREE(streams);
	return NT_STATUS_OK;

 fail:
	TALLOC_FREE(result);
	TALLOC_FREE(streams);
	return status;
}
