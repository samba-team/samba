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
#include "system/filesys.h"
#include "fake_file.h"
#include "smbd/smbd.h"
#include "smbd/globals.h"
#include "lib/util/memcache.h"

uint32_t ucf_flags_from_smb_request(struct smb_request *req)
{
	uint32_t ucf_flags = 0;

	if (req == NULL) {
		return 0;
	}

	if (req->posix_pathnames) {
		ucf_flags |= UCF_POSIX_PATHNAMES;

		if (!req->sconn->using_smb2) {
			ucf_flags |= UCF_LCOMP_LNK_OK;
		}
	}
	if (req->flags2 & FLAGS2_DFS_PATHNAMES) {
		ucf_flags |= UCF_DFS_PATHNAME;
	}
	if (req->flags2 & FLAGS2_REPARSE_PATH) {
		ucf_flags |= UCF_GMT_PATHNAME;
	}

	return ucf_flags;
}

uint32_t filename_create_ucf_flags(struct smb_request *req, uint32_t create_disposition)
{
	uint32_t ucf_flags = 0;

	ucf_flags |= ucf_flags_from_smb_request(req);

	switch (create_disposition) {
	case FILE_OPEN:
	case FILE_OVERWRITE:
		break;
	case FILE_SUPERSEDE:
	case FILE_CREATE:
	case FILE_OPEN_IF:
	case FILE_OVERWRITE_IF:
		ucf_flags |= UCF_PREP_CREATEFILE;
		break;
	}

	return ucf_flags;
}

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

/*
 * Strip a valid @GMT-token from any incoming filename path,
 * adding any NTTIME encoded in the pathname into the
 * twrp field of the passed in smb_fname.
 *
 * Valid @GMT-tokens look like @GMT-YYYY-MM-DD-HH-MM-SS
 * at the *start* of a pathname component.
 *
 * If twrp is passed in then smb_fname->twrp is set to that
 * value, and the @GMT-token part of the filename is removed
 * and does not change the stored smb_fname->twrp.
 *
 */

NTSTATUS canonicalize_snapshot_path(struct smb_filename *smb_fname,
				    uint32_t ucf_flags,
				    NTTIME twrp)
{
	bool found;

	if (twrp != 0) {
		smb_fname->twrp = twrp;
	}

	if (!(ucf_flags & UCF_GMT_PATHNAME)) {
		return NT_STATUS_OK;
	}

	found = extract_snapshot_token(smb_fname->base_name, &twrp);
	if (!found) {
		return NT_STATUS_OK;
	}

	if (smb_fname->twrp == 0) {
		smb_fname->twrp = twrp;
	}

	return NT_STATUS_OK;
}

static bool strnorm(char *s, int case_default)
{
	if (case_default == CASE_UPPER)
		return strupper_m(s);
	else
		return strlower_m(s);
}

/*
 * Utility function to normalize case on an incoming client filename
 * if required on this connection struct.
 * Performs an in-place case conversion guaranteed to stay the same size.
 */

static NTSTATUS normalize_filename_case(connection_struct *conn,
					char *filename,
					uint32_t ucf_flags)
{
	bool ok;

	if (ucf_flags & UCF_POSIX_PATHNAMES) {
		/*
		 * POSIX never normalizes filename case.
		 */
		return NT_STATUS_OK;
	}
	if (!conn->case_sensitive) {
		return NT_STATUS_OK;
	}
	if (conn->case_preserve) {
		return NT_STATUS_OK;
	}
	if (conn->short_case_preserve) {
		return NT_STATUS_OK;
	}
	ok = strnorm(filename, lp_default_case(SNUM(conn)));
	if (!ok) {
		return NT_STATUS_INVALID_PARAMETER;
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

static bool sname_equal(const char *name1, const char *name2,
		bool case_sensitive)
{
	bool match;
	const char *s1 = NULL;
	const char *s2 = NULL;
	size_t n1;
	size_t n2;
	const char *e1 = NULL;
	const char *e2 = NULL;
	char *c1 = NULL;
	char *c2 = NULL;

	match = fname_equal(name1, name2, case_sensitive);
	if (match) {
		return true;
	}

	if (name1[0] != ':') {
		return false;
	}
	if (name2[0] != ':') {
		return false;
	}
	s1 = &name1[1];
	e1 = strchr(s1, ':');
	if (e1 == NULL) {
		n1 = strlen(s1);
	} else {
		n1 = PTR_DIFF(e1, s1);
	}
	s2 = &name2[1];
	e2 = strchr(s2, ':');
	if (e2 == NULL) {
		n2 = strlen(s2);
	} else {
		n2 = PTR_DIFF(e2, s2);
	}

	/* Normal filename handling */
	if (case_sensitive) {
		return (strncmp(s1, s2, n1) == 0);
	}

	/*
	 * We can't use strnequal() here
	 * as it takes the number of codepoints
	 * and not the number of bytes.
	 *
	 * So we make a copy before calling
	 * strequal().
	 *
	 * Note that we TALLOC_FREE() in reverse order
	 * in order to avoid memory fragmentation.
	 */

	c1 = talloc_strndup(talloc_tos(), s1, n1);
	c2 = talloc_strndup(talloc_tos(), s2, n2);
	if (c1 == NULL || c2 == NULL) {
		TALLOC_FREE(c2);
		TALLOC_FREE(c1);
		return (strncmp(s1, s2, n1) == 0);
	}

	match = strequal(c1, c2);
	TALLOC_FREE(c2);
	TALLOC_FREE(c1);
	return match;
}

/****************************************************************************
 Scan a directory to find a filename, matching without case sensitivity.
 If the name looks like a mangled name then try via the mangling functions
****************************************************************************/

NTSTATUS get_real_filename_full_scan_at(struct files_struct *dirfsp,
					const char *name,
					bool mangled,
					TALLOC_CTX *mem_ctx,
					char **found_name)
{
	struct connection_struct *conn = dirfsp->conn;
	struct smb_Dir *cur_dir = NULL;
	const char *dname = NULL;
	char *talloced = NULL;
	char *unmangled_name = NULL;
	NTSTATUS status;

	/* If we have a case-sensitive filesystem, it doesn't do us any
	 * good to search for a name. If a case variation of the name was
	 * there, then the original stat(2) would have found it.
	 */
	if (!mangled && !(conn->fs_capabilities & FILE_CASE_SENSITIVE_SEARCH)) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
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
	status = OpenDir_from_pathref(talloc_tos(), dirfsp, NULL, 0, &cur_dir);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_NOTICE("scan dir didn't open dir [%s]: %s\n",
			   fsp_str_dbg(dirfsp),
			   nt_errstr(status));
		TALLOC_FREE(unmangled_name);
		return status;
	}

	/* now scan for matching names */
	while ((dname = ReadDirName(cur_dir, &talloced))) {

		/* Is it dot or dot dot. */
		if (ISDOT(dname) || ISDOTDOT(dname)) {
			TALLOC_FREE(talloced);
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
				TALLOC_FREE(talloced);
				return NT_STATUS_NO_MEMORY;
			}
			TALLOC_FREE(talloced);
			return NT_STATUS_OK;
		}
		TALLOC_FREE(talloced);
	}

	TALLOC_FREE(unmangled_name);
	TALLOC_FREE(cur_dir);
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

/****************************************************************************
 Wrapper around the vfs get_real_filename and the full directory scan
 fallback.
****************************************************************************/

NTSTATUS get_real_filename_at(struct files_struct *dirfsp,
			      const char *name,
			      TALLOC_CTX *mem_ctx,
			      char **found_name)
{
	struct connection_struct *conn = dirfsp->conn;
	NTSTATUS status;
	bool mangled;

	mangled = mangle_is_mangled(name, conn->params);

	if (mangled) {
		status = get_real_filename_full_scan_at(
			dirfsp, name, mangled, mem_ctx, found_name);
		return status;
	}

	/* Try the vfs first to take advantage of case-insensitive stat. */
	status = SMB_VFS_GET_REAL_FILENAME_AT(
		dirfsp->conn, dirfsp, name, mem_ctx, found_name);

	/*
	 * If the case-insensitive stat was successful, or returned an error
	 * other than EOPNOTSUPP then there is no need to fall back on the
	 * full directory scan.
	 */
	if (NT_STATUS_IS_OK(status) ||
	    !NT_STATUS_EQUAL(status, NT_STATUS_NOT_SUPPORTED)) {
		return status;
	}

	status = get_real_filename_full_scan_at(
		dirfsp, name, mangled, mem_ctx, found_name);
	return status;
}

/*
 * Create the memcache-key for GETREALFILENAME_CACHE: This supplements
 * the stat cache for the last component to be looked up. Cache
 * contents is the correctly capitalized translation of the parameter
 * "name" as it exists on disk. This is indexed by inode of the dirfsp
 * and name, and contrary to stat_cahce_lookup() it does not
 * vfs_stat() the last component. This will be taken care of by an
 * attempt to do a openat_pathref_fsp().
 */
static bool get_real_filename_cache_key(
	TALLOC_CTX *mem_ctx,
	struct files_struct *dirfsp,
	const char *name,
	DATA_BLOB *_key)
{
	struct file_id fid = vfs_file_id_from_sbuf(
		dirfsp->conn, &dirfsp->fsp_name->st);
	char *upper = NULL;
	uint8_t *key = NULL;
	size_t namelen, keylen;

	upper = talloc_strdup_upper(mem_ctx, name);
	if (upper == NULL) {
		return false;
	}
	namelen = talloc_get_size(upper);

	keylen = namelen + sizeof(fid);
	if (keylen < sizeof(fid)) {
		TALLOC_FREE(upper);
		return false;
	}

	key = talloc_size(mem_ctx, keylen);
	if (key == NULL) {
		TALLOC_FREE(upper);
		return false;
	}

	memcpy(key, &fid, sizeof(fid));
	memcpy(key + sizeof(fid), upper, namelen);
	TALLOC_FREE(upper);

	*_key = (DATA_BLOB) { .data = key, .length = keylen, };
	return true;
}

/*
 * Lightweight function to just get last component
 * for rename / enumerate directory calls.
 */

char *get_original_lcomp(TALLOC_CTX *ctx,
			connection_struct *conn,
			const char *filename_in,
			uint32_t ucf_flags)
{
	char *last_slash = NULL;
	char *orig_lcomp;
	NTSTATUS status;

	last_slash = strrchr(filename_in, '/');
	if (last_slash != NULL) {
		orig_lcomp = talloc_strdup(ctx, last_slash+1);
	} else {
		orig_lcomp = talloc_strdup(ctx, filename_in);
	}
	if (orig_lcomp == NULL) {
		return NULL;
	}
	status = normalize_filename_case(conn, orig_lcomp, ucf_flags);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(orig_lcomp);
		return NULL;
	}
	return orig_lcomp;
}

/*
 * Deal with the SMB1 semantics of sending a pathname with a
 * wildcard as the terminal component for a SMB1search or
 * trans2 findfirst.
 */

NTSTATUS filename_convert_smb1_search_path(TALLOC_CTX *ctx,
					   connection_struct *conn,
					   char *name_in,
					   uint32_t ucf_flags,
					   struct files_struct **_dirfsp,
					   struct smb_filename **_smb_fname_out,
					   char **_mask_out)
{
	NTSTATUS status;
	char *p = NULL;
	char *mask = NULL;
	struct smb_filename *smb_fname = NULL;
	NTTIME twrp = 0;

	*_smb_fname_out = NULL;
	*_dirfsp = NULL;
	*_mask_out = NULL;

	DBG_DEBUG("name_in: %s\n", name_in);

	if (ucf_flags & UCF_GMT_PATHNAME) {
		extract_snapshot_token(name_in, &twrp);
		ucf_flags &= ~UCF_GMT_PATHNAME;
	}

	/* Get the original lcomp. */
	mask = get_original_lcomp(ctx,
				  conn,
				  name_in,
				  ucf_flags);
	if (mask == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	if (mask[0] == '\0') {
		/* Windows and OS/2 systems treat search on the root as * */
		TALLOC_FREE(mask);
		mask = talloc_strdup(ctx, "*");
		if (mask == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	DBG_DEBUG("mask = %s\n", mask);

	/*
	 * Remove the terminal component so
	 * filename_convert_dirfsp never sees the mask.
	 */
	p = strrchr_m(name_in,'/');
	if (p == NULL) {
		/* filename_convert_dirfsp handles a '\0' name. */
		name_in[0] = '\0';
	} else {
		*p = '\0';
	}

	DBG_DEBUG("For filename_convert_dirfsp: name_in = %s\n",
		name_in);

	/* Convert the parent directory path. */
	status = filename_convert_dirfsp(ctx,
					 conn,
					 name_in,
					 ucf_flags,
					 twrp,
					 _dirfsp,
					 &smb_fname);

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("filename_convert error for %s: %s\n",
			name_in,
			nt_errstr(status));
	}

	*_smb_fname_out = talloc_move(ctx, &smb_fname);
	*_mask_out = talloc_move(ctx, &mask);

	return status;
}

/*
 * Get the correct capitalized stream name hanging off
 * base_fsp. Equivalent of get_real_filename(), but for streams.
 */
static NTSTATUS get_real_stream_name(
	TALLOC_CTX *mem_ctx,
	struct files_struct *base_fsp,
	const char *stream_name,
	char **_found)
{
	unsigned int i, num_streams = 0;
	struct stream_struct *streams = NULL;
	NTSTATUS status;

	status = vfs_fstreaminfo(
		base_fsp, talloc_tos(), &num_streams, &streams);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	for (i=0; i<num_streams; i++) {
		bool equal = sname_equal(stream_name, streams[i].name, false);

		DBG_DEBUG("comparing [%s] and [%s]: %sequal\n",
			  stream_name,
			  streams[i].name,
			  equal ? "" : "not ");

		if (equal) {
			*_found = talloc_move(mem_ctx, &streams[i].name);
			TALLOC_FREE(streams);
			return NT_STATUS_OK;
		}
	}

	TALLOC_FREE(streams);
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}

static bool filename_split_lcomp(
	TALLOC_CTX *mem_ctx,
	const char *name_in,
	bool posix,
	char **_dirname,
	const char **_fname_rel,
	const char **_streamname)
{
	const char *lcomp = NULL;
	const char *fname_rel = NULL;
	const char *streamname = NULL;
	char *dirname = NULL;

	if (name_in[0] == '\0') {
		fname_rel = ".";
		dirname = talloc_strdup(mem_ctx, "");
		if (dirname == NULL) {
			return false;
		}
		goto done;
	}

	lcomp = strrchr_m(name_in, '/');
	if (lcomp != NULL) {
		fname_rel = lcomp+1;
		dirname = talloc_strndup(mem_ctx, name_in, lcomp - name_in);
		if (dirname == NULL) {
			return false;
		}
		goto find_stream;
	}

	/*
	 * No slash, dir is emtpy
	 */
	dirname = talloc_strdup(mem_ctx, "");
	if (dirname == NULL) {
		return false;
	}

	if (!posix && (name_in[0] == ':')) {
		/*
		 * Special case for stream on root directory
		 */
		fname_rel = ".";
		streamname = name_in;
		goto done;
	}

	fname_rel = name_in;

find_stream:
	if (!posix) {
		streamname = strchr_m(fname_rel, ':');

		if (streamname != NULL) {
			fname_rel = talloc_strndup(
				mem_ctx,
				fname_rel,
				streamname - fname_rel);
			if (fname_rel == NULL) {
				TALLOC_FREE(dirname);
				return false;
			}
		}
	}

done:
	*_dirname = dirname;
	*_fname_rel = fname_rel;
	*_streamname = streamname;
	return true;
}

/*
 * Create the correct capitalization of a file name to be created.
 */
static NTSTATUS filename_convert_normalize_new(
	TALLOC_CTX *mem_ctx,
	struct connection_struct *conn,
	char *name_in,
	char **_normalized)
{
	char *name = name_in;

	*_normalized = NULL;

	if (!conn->case_preserve ||
	    (mangle_is_8_3(name, false,
			   conn->params) &&
	     !conn->short_case_preserve)) {

		char *normalized = talloc_strdup(mem_ctx, name);
		if (normalized == NULL) {
			return NT_STATUS_NO_MEMORY;
		}

		strnorm(normalized, lp_default_case(SNUM(conn)));
		name = normalized;
	}

	if (mangle_is_mangled(name, conn->params)) {
		bool found;
		char *unmangled = NULL;

		found = mangle_lookup_name_from_8_3(
			mem_ctx, name, &unmangled, conn->params);
		if (found) {
			name = unmangled;
		}
	}

	if (name != name_in) {
		*_normalized = name;
	}

	return NT_STATUS_OK;
}

/*
 * Open smb_fname_rel->fsp as a pathref fsp with a case insensitive
 * fallback using GETREALFILENAME_CACHE and get_real_filename_at() if
 * the first attempt based on the filename sent by the client gives
 * ENOENT.
 */
static NTSTATUS openat_pathref_fsp_case_insensitive(
	struct files_struct *dirfsp,
	struct smb_filename *smb_fname_rel,
	uint32_t ucf_flags)
{
	const bool posix = (ucf_flags & UCF_POSIX_PATHNAMES);
	DATA_BLOB cache_key = { .data = NULL, };
	char *found_name = NULL;
	NTSTATUS status;
	bool ok;

	SET_STAT_INVALID(smb_fname_rel->st);

	/* Check veto files - only looks at last component. */
	if (IS_VETO_PATH(dirfsp->conn, smb_fname_rel->base_name)) {
		DBG_DEBUG("veto files rejecting last component %s\n",
			  smb_fname_str_dbg(smb_fname_rel));
		return NT_STATUS_NETWORK_OPEN_RESTRICTION;
	}

	status = openat_pathref_fsp(dirfsp, smb_fname_rel);

	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}

	if (VALID_STAT(smb_fname_rel->st)) {
		/*
		 * We got an error although the object existed. Might
		 * be a symlink we don't want.
		 */
		return status;
	}

	if (!NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * Only retry on ENOENT
		 */
		return status;
	}

	if (posix || dirfsp->conn->case_sensitive) {
		/*
		 * Only return case insensitive if required
		 */
		return status;
	}

	if (lp_stat_cache()) {
		char *base_name = smb_fname_rel->base_name;
		DATA_BLOB value = { .data = NULL };

		ok = get_real_filename_cache_key(
			talloc_tos(), dirfsp, base_name, &cache_key);
		if (!ok) {
			/*
			 * probably ENOMEM, just bail
			 */
			return status;
		}

		DO_PROFILE_INC(statcache_lookups);

		ok = memcache_lookup(
			NULL, GETREALFILENAME_CACHE, cache_key, &value);
		if (!ok) {
			DO_PROFILE_INC(statcache_misses);
			goto lookup;
		}
		DO_PROFILE_INC(statcache_hits);

		TALLOC_FREE(smb_fname_rel->base_name);
		smb_fname_rel->base_name = talloc_memdup(
			smb_fname_rel, value.data, value.length);
		if (smb_fname_rel->base_name == NULL) {
			TALLOC_FREE(cache_key.data);
			return NT_STATUS_NO_MEMORY;
		}

		if (IS_VETO_PATH(dirfsp->conn, smb_fname_rel->base_name)) {
			DBG_DEBUG("veto files rejecting last component %s\n",
				  smb_fname_str_dbg(smb_fname_rel));
			TALLOC_FREE(cache_key.data);
			return NT_STATUS_NETWORK_OPEN_RESTRICTION;
		}

		status = openat_pathref_fsp(dirfsp, smb_fname_rel);
		if (NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(cache_key.data);
			return NT_STATUS_OK;
		}

		memcache_delete(NULL, GETREALFILENAME_CACHE, cache_key);
	}

lookup:
	status = get_real_filename_at(
		dirfsp, smb_fname_rel->base_name, smb_fname_rel, &found_name);
	if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED) &&
	    (ucf_flags & UCF_PREP_CREATEFILE)) {
		/*
		 * dropbox
		 */
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}

	if (NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(smb_fname_rel->base_name);
		smb_fname_rel->base_name = found_name;

		if (IS_VETO_PATH(dirfsp->conn, smb_fname_rel->base_name)) {
			DBG_DEBUG("veto files rejecting last component %s\n",
				smb_fname_str_dbg(smb_fname_rel));
			return NT_STATUS_NETWORK_OPEN_RESTRICTION;
		}

		status = openat_pathref_fsp(dirfsp, smb_fname_rel);
	}

	if (NT_STATUS_IS_OK(status) && (cache_key.data != NULL)) {
		DATA_BLOB value = {
			.data = (uint8_t *)smb_fname_rel->base_name,
			.length = strlen(smb_fname_rel->base_name) + 1,
		};

		memcache_add(NULL, GETREALFILENAME_CACHE, cache_key, value);
	}

	TALLOC_FREE(cache_key.data);

	return status;
}

static const char *previous_slash(const char *name_in, const char *slash)
{
	const char *prev = name_in;

	while (true) {
		const char *next = strchr_m(prev, '/');

		SMB_ASSERT(next != NULL); /* we have at least one slash */

		if (next == slash) {
			break;
		}

		prev = next+1;
	};

	if (prev == name_in) {
		/* no previous slash */
		return NULL;
	}

	return prev;
}

static char *symlink_target_path(
	TALLOC_CTX *mem_ctx,
	const char *name_in,
	const char *substitute,
	size_t unparsed)
{
	size_t name_in_len = strlen(name_in);
	const char *p_unparsed = NULL;
	const char *parent = NULL;
	char *ret;

	SMB_ASSERT(unparsed <= name_in_len);

	p_unparsed = name_in + (name_in_len - unparsed);

	if (substitute[0] == '/') {
		ret = talloc_asprintf(mem_ctx, "%s%s", substitute, p_unparsed);
		return ret;
	}

	if (unparsed == 0) {
		parent = strrchr_m(name_in, '/');
	} else {
		parent = previous_slash(name_in, p_unparsed);
	}

	if (parent == NULL) {
		/* no previous slash */
		parent = name_in;
	}

	ret = talloc_asprintf(
		mem_ctx,
		"%.*s%s%s",
		(int)(parent - name_in),
		name_in,
		substitute,
		p_unparsed);
	return ret;
}

static NTSTATUS safe_symlink_target_path(
	TALLOC_CTX *mem_ctx,
	const char *connectpath,
	const char *name_in,
	const char *substitute,
	size_t unparsed,
	char **_name_out)
{
	char *target = NULL;
	char *abs_target = NULL;
	char *abs_target_canon = NULL;
	const char *relative = NULL;
	char *name_out = NULL;
	NTSTATUS status = NT_STATUS_NO_MEMORY;
	bool in_share;

	target = symlink_target_path(mem_ctx, name_in, substitute, unparsed);
	if (target == NULL) {
		goto fail;
	}

	DBG_DEBUG("name_in: %s, substitute: %s, unparsed: %zu, target=%s\n",
		  name_in,
		  substitute,
		  unparsed,
		  target);

	if (target[0] == '/') {
		abs_target = target;
	} else {
		abs_target = talloc_asprintf(
			target, "%s/%s", connectpath, target);
		if (abs_target == NULL) {
			goto fail;
		}
	}

	abs_target_canon = canonicalize_absolute_path(target, abs_target);
	if (abs_target_canon == NULL) {
		goto fail;
	}

	DBG_DEBUG("abs_target_canon=%s\n", abs_target_canon);

	in_share = subdir_of(
		connectpath, strlen(connectpath), abs_target_canon, &relative);
	if (!in_share) {
		DBG_DEBUG("wide link to %s\n", abs_target_canon);
		status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		goto fail;
	}

	name_out = talloc_strdup(mem_ctx, relative);
	if (name_out == NULL) {
		goto fail;
	}

	status = NT_STATUS_OK;
	*_name_out = name_out;
fail:
	TALLOC_FREE(target);
	return status;
}

/*
 * Split up name_in as sent by the client into a directory pathref fsp
 * and a relative smb_filename.
 */
static NTSTATUS filename_convert_dirfsp_nosymlink(
	TALLOC_CTX *mem_ctx,
	connection_struct *conn,
	const char *name_in,
	uint32_t ucf_flags,
	NTTIME twrp,
	struct files_struct **_dirfsp,
	struct smb_filename **_smb_fname,
	char **_substitute,
	size_t *_unparsed)
{
	struct smb_filename *smb_dirname = NULL;
	struct smb_filename *smb_fname_rel = NULL;
	struct smb_filename *smb_fname = NULL;
	const bool posix = (ucf_flags & UCF_POSIX_PATHNAMES);
	char *dirname = NULL;
	const char *fname_rel = NULL;
	const char *streamname = NULL;
	char *saved_streamname = NULL;
	struct files_struct *base_fsp = NULL;
	bool ok;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;

	SMB_ASSERT(!(ucf_flags & UCF_DFS_PATHNAME));

	if (is_fake_file_path(name_in)) {
		smb_fname = synthetic_smb_fname_split(mem_ctx, name_in, posix);
		if (smb_fname == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		smb_fname->st = (SMB_STRUCT_STAT) { .st_ex_nlink = 1 };
		smb_fname->st.st_ex_btime =
			(struct timespec){0, SAMBA_UTIME_OMIT};
		smb_fname->st.st_ex_atime =
			(struct timespec){0, SAMBA_UTIME_OMIT};
		smb_fname->st.st_ex_mtime =
			(struct timespec){0, SAMBA_UTIME_OMIT};
		smb_fname->st.st_ex_ctime =
			(struct timespec){0, SAMBA_UTIME_OMIT};

		*_dirfsp = conn->cwd_fsp;
		*_smb_fname = smb_fname;
		return NT_STATUS_OK;
	}

	/*
	 * Catch an invalid path of "." before we
	 * call filename_split_lcomp(). We need to
	 * do this as filename_split_lcomp() will
	 * use "." for the missing relative component
	 * when an empty name_in path is sent by
	 * the client.
	 */
	if (ISDOT(name_in)) {
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto fail;
	}

	ok = filename_split_lcomp(
		talloc_tos(),
		name_in,
		posix,
		&dirname,
		&fname_rel,
		&streamname);
	if (!ok) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if ((streamname != NULL) &&
	    ((conn->fs_capabilities & FILE_NAMED_STREAMS) == 0)) {
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto fail;
	}

	if (!posix) {
		bool name_has_wild = ms_has_wild(dirname);
		name_has_wild |= ms_has_wild(fname_rel);
		if (name_has_wild) {
			status = NT_STATUS_OBJECT_NAME_INVALID;
			goto fail;
		}
	}

	if (dirname[0] == '\0') {
		status = synthetic_pathref(
			mem_ctx,
			conn->cwd_fsp,
			".",
			NULL,
			NULL,
			0,
			posix ? SMB_FILENAME_POSIX_PATH : 0,
			&smb_dirname);
	} else {
		char *substitute = NULL;
		size_t unparsed = 0;

		status = normalize_filename_case(conn, dirname, ucf_flags);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("normalize_filename_case %s failed: %s\n",
				dirname,
				nt_errstr(status));
			goto fail;
		}

		status = openat_pathref_dirfsp_nosymlink(
			mem_ctx,
			conn,
			dirname,
			0,
			posix,
			&smb_dirname,
			&unparsed,
			&substitute);

		if (NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK)) {

			size_t name_in_len = strlen(name_in);
			size_t dirname_len = strlen(dirname);

			SMB_ASSERT(name_in_len >= dirname_len);

			*_substitute = substitute;
			*_unparsed = unparsed + (name_in_len - dirname_len);

			goto fail;
		}
	}

	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("opening directory %s failed: %s\n",
			  dirname,
			  nt_errstr(status));
		TALLOC_FREE(dirname);

		if (NT_STATUS_EQUAL(status, NT_STATUS_PATH_NOT_COVERED)) {
			/* MS-DFS error must propagate back out. */
			goto fail;
		}

		if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			/*
			 * Except ACCESS_DENIED, everything else leads
			 * to PATH_NOT_FOUND.
			 */
			status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		}

		goto fail;
	}

	if (!VALID_STAT_OF_DIR(smb_dirname->st)) {
		status = NT_STATUS_OBJECT_PATH_NOT_FOUND;
		goto fail;
	}

	/*
	 * Only look at bad last component values
	 * once we know we have a valid directory. That
	 * way we won't confuse error messages from
	 * opening the directory path with error
	 * messages from a bad last component.
	 */

	/* Relative filename can't be empty */
	if (fname_rel[0] == '\0') {
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto fail;
	}

	/* Relative filename can't be ".." */
	if (ISDOTDOT(fname_rel)) {
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto fail;
	}
	/* Relative name can only be dot if directory is empty. */
	if (ISDOT(fname_rel) && dirname[0] != '\0') {
		status = NT_STATUS_OBJECT_NAME_INVALID;
		goto fail;
	}

	TALLOC_FREE(dirname);

	smb_fname_rel = synthetic_smb_fname(
		mem_ctx,
		fname_rel,
		streamname,
		NULL,
		twrp,
		posix ? SMB_FILENAME_POSIX_PATH : 0);
	if (smb_fname_rel == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto fail;
	}

	if ((conn->fs_capabilities & FILE_NAMED_STREAMS) &&
	    is_named_stream(smb_fname_rel)) {
		/*
		 * Find the base_fsp first without the stream.
		 */
		saved_streamname = smb_fname_rel->stream_name;
		smb_fname_rel->stream_name = NULL;
	}

	status = normalize_filename_case(
		conn, smb_fname_rel->base_name, ucf_flags);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("normalize_filename_case %s failed: %s\n",
			smb_fname_rel->base_name,
			nt_errstr(status));
		goto fail;
	}

	status = openat_pathref_fsp_case_insensitive(
		smb_dirname->fsp, smb_fname_rel, ucf_flags);

	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND) &&
	    VALID_STAT(smb_fname_rel->st) &&
	    S_ISLNK(smb_fname_rel->st.st_ex_mode)) {

		/*
		 * If we're on an MSDFS share, see if this is
		 * an MSDFS link.
		 */
		if (lp_host_msdfs() &&
		    lp_msdfs_root(SNUM(conn)) &&
		    is_msdfs_link(smb_dirname->fsp, smb_fname_rel))
		{
			status = NT_STATUS_PATH_NOT_COVERED;
			goto fail;
		}

#if defined(WITH_SMB1SERVER)
		/*
		 * In SMB1 posix mode, if this is a symlink,
		 * allow access to the name with a NULL smb_fname->fsp.
		 */
		if (ucf_flags & UCF_LCOMP_LNK_OK) {
			SMB_ASSERT(smb_fname_rel->fsp == NULL);
			SMB_ASSERT(streamname == NULL);

			smb_fname = full_path_from_dirfsp_atname(
				mem_ctx,
				smb_dirname->fsp,
				smb_fname_rel);
			if (smb_fname == NULL) {
				status = NT_STATUS_NO_MEMORY;
				goto fail;
			}
			goto done;
		}
#endif
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND) &&
	    !VALID_STAT(smb_fname_rel->st)) {

		char *normalized = NULL;

		/*
		 * Creating a new file
		 */

		status = filename_convert_normalize_new(
			smb_fname_rel,
			conn,
			smb_fname_rel->base_name,
			&normalized);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("filename_convert_normalize_new failed: "
				  "%s\n",
				  nt_errstr(status));
			goto fail;
		}
		if (normalized != NULL) {
			smb_fname_rel->base_name = normalized;
		}

		smb_fname_rel->stream_name = saved_streamname;

		smb_fname = full_path_from_dirfsp_atname(
			mem_ctx, smb_dirname->fsp, smb_fname_rel);
		if (smb_fname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		goto done;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_OPEN_RESTRICTION)) {
		/* A vetoed file, pretend it's not there  */
		status = NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

	if (saved_streamname == NULL) {
		/* smb_fname must be allocated off mem_ctx. */
		smb_fname = cp_smb_filename(mem_ctx,
					    smb_fname_rel->fsp->fsp_name);
		if (smb_fname == NULL) {
			goto fail;
		}
		status = move_smb_fname_fsp_link(smb_fname, smb_fname_rel);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		goto done;
	}

	base_fsp = smb_fname_rel->fsp;
	smb_fname_fsp_unlink(smb_fname_rel);
	SET_STAT_INVALID(smb_fname_rel->st);

	smb_fname_rel->stream_name = saved_streamname;

	status = open_stream_pathref_fsp(&base_fsp, smb_fname_rel);

	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND) &&
	    !conn->case_sensitive) {
		char *found = NULL;

		status = get_real_stream_name(
			smb_fname_rel,
			base_fsp,
			smb_fname_rel->stream_name,
			&found);

		if (NT_STATUS_IS_OK(status)) {
			smb_fname_rel->stream_name = found;
			found = NULL;
			status = open_stream_pathref_fsp(
				&base_fsp, smb_fname_rel);
		}
	}

	if (NT_STATUS_IS_OK(status)) {
		/* smb_fname must be allocated off mem_ctx. */
		smb_fname = cp_smb_filename(mem_ctx,
					    smb_fname_rel->fsp->fsp_name);
		if (smb_fname == NULL) {
			goto fail;
		}
		status = move_smb_fname_fsp_link(smb_fname, smb_fname_rel);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}
		goto done;
	}

	if (NT_STATUS_EQUAL(status, NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		/*
		 * Creating a new stream
		 *
		 * We should save the already-open base fsp for
		 * create_file_unixpath() somehow.
		 */
		smb_fname = full_path_from_dirfsp_atname(
			mem_ctx, smb_dirname->fsp, smb_fname_rel);
		if (smb_fname == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto fail;
		}
		/*
		 * When open_stream_pathref_fsp() returns
		 * NT_STATUS_OBJECT_NAME_NOT_FOUND, smb_fname_rel->fsp
		 * has been set to NULL, so we must free base_fsp separately
		 * to prevent fd-leaks when opening a stream that doesn't
		 * exist.
		 */
		fd_close(base_fsp);
		file_free(NULL, base_fsp);
		base_fsp = NULL;
		goto done;
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto fail;
	}

done:
	*_dirfsp = smb_dirname->fsp;
	*_smb_fname = smb_fname;

	smb_fname_fsp_unlink(smb_fname_rel);
	TALLOC_FREE(smb_fname_rel);
	return NT_STATUS_OK;

fail:
	/*
	 * If open_stream_pathref_fsp() returns an error, smb_fname_rel->fsp
	 * has been set to NULL, so we must free base_fsp separately
	 * to prevent fd-leaks when opening a stream that doesn't
	 * exist.
	 */
	if (base_fsp != NULL) {
		fd_close(base_fsp);
		file_free(NULL, base_fsp);
		base_fsp = NULL;
	}
	TALLOC_FREE(dirname);
	TALLOC_FREE(smb_dirname);
	TALLOC_FREE(smb_fname_rel);
	return status;
}

NTSTATUS filename_convert_dirfsp(
	TALLOC_CTX *mem_ctx,
	connection_struct *conn,
	const char *name_in,
	uint32_t ucf_flags,
	NTTIME twrp,
	struct files_struct **_dirfsp,
	struct smb_filename **_smb_fname)
{
	char *substitute = NULL;
	size_t unparsed = 0;
	NTSTATUS status;
	char *target = NULL;
	size_t symlink_redirects = 0;

next:
	if (symlink_redirects > 40) {
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	status = filename_convert_dirfsp_nosymlink(
		mem_ctx,
		conn,
		name_in,
		ucf_flags,
		twrp,
		_dirfsp,
		_smb_fname,
		&substitute,
		&unparsed);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_STOPPED_ON_SYMLINK)) {
		return status;
	}

	if (!lp_follow_symlinks(SNUM(conn))) {
		return NT_STATUS_OBJECT_PATH_NOT_FOUND;
	}

	/*
	 * Right now, SMB2 and SMB1 always traverse symlinks
	 * within the share. SMB1+POSIX traverses non-terminal
	 * symlinks within the share.
	 *
	 * When we add SMB2+POSIX we need to return
	 * a NT_STATUS_STOPPED_ON_SYMLINK error here, using the
	 * symlink target data read below if SMB2+POSIX has
	 * UCF_POSIX_PATHNAMES set to cause the client to
	 * resolve all symlinks locally.
	 */

	status = safe_symlink_target_path(
		mem_ctx,
		conn->connectpath,
		name_in,
		substitute,
		unparsed,
		&target);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	name_in = target;

	symlink_redirects += 1;

	goto next;
}

/*
 * Build the full path from a dirfsp and dirfsp relative name
 */
struct smb_filename *full_path_from_dirfsp_atname(
	TALLOC_CTX *mem_ctx,
	const struct files_struct *dirfsp,
	const struct smb_filename *atname)
{
	struct smb_filename *fname = NULL;
	char *path = NULL;

	if (dirfsp == dirfsp->conn->cwd_fsp ||
	    ISDOT(dirfsp->fsp_name->base_name) ||
	    atname->base_name[0] == '/')
	{
		path = talloc_strdup(mem_ctx, atname->base_name);
	} else {
		path = talloc_asprintf(mem_ctx, "%s/%s",
				       dirfsp->fsp_name->base_name,
				       atname->base_name);
	}
	if (path == NULL) {
		return NULL;
	}

	fname = synthetic_smb_fname(mem_ctx,
				    path,
				    atname->stream_name,
				    &atname->st,
				    atname->twrp,
				    atname->flags);
	TALLOC_FREE(path);
	if (fname == NULL) {
		return NULL;
	}

	return fname;
}
