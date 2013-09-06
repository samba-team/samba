/*
   Unix SMB/CIFS implementation.
   Filename utility functions.
   Copyright (C) Tim Prouty 2009

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
#include "includes.h"

/**
 * XXX: This is temporary and there should be no callers of this outside of
 * this file once smb_filename is plumbed through all path based operations.
 * The one legitimate caller currently is smb_fname_str_dbg(), which this
 * could be made static for.
 */
NTSTATUS get_full_smb_filename(TALLOC_CTX *ctx,
			       const struct smb_filename *smb_fname,
			       char **full_name)
{
	if (smb_fname->stream_name) {
		/* stream_name must always be NULL if there is no stream. */
		SMB_ASSERT(smb_fname->stream_name[0] != '\0');

		*full_name = talloc_asprintf(ctx, "%s%s", smb_fname->base_name,
					     smb_fname->stream_name);
	} else {
		*full_name = talloc_strdup(ctx, smb_fname->base_name);
	}

	if (!*full_name) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

/**
 * There are actually legitimate callers of this such as functions that
 * enumerate streams using the vfs_streaminfo interface and then want to
 * operate on each stream.
 */
struct smb_filename *synthetic_smb_fname(TALLOC_CTX *mem_ctx,
					 const char *base_name,
					 const char *stream_name,
					 const SMB_STRUCT_STAT *psbuf)
{
	struct smb_filename smb_fname_loc = { 0, };

	/* Setup the base_name/stream_name. */
	smb_fname_loc.base_name = discard_const_p(char, base_name);
	smb_fname_loc.stream_name = discard_const_p(char, stream_name);

	/* Copy the psbuf if one was given. */
	if (psbuf)
		smb_fname_loc.st = *psbuf;

	/* Let cp_smb_filename() do the heavy lifting. */
	return cp_smb_filename(mem_ctx, &smb_fname_loc);
}

/**
 * XXX: This is temporary and there should be no callers of this once
 * smb_filename is plumbed through all path based operations.
 */
struct smb_filename *synthetic_smb_fname_split(TALLOC_CTX *ctx,
					       const char *fname,
					       const SMB_STRUCT_STAT *psbuf)
{
	const char *stream_name = NULL;
	char *base_name = NULL;
	struct smb_filename *ret;

	if (!lp_posix_pathnames()) {
		stream_name = strchr_m(fname, ':');
	}

	/* Setup the base_name/stream_name. */
	if (stream_name) {
		base_name = talloc_strndup(ctx, fname,
					   PTR_DIFF(stream_name, fname));
	} else {
		base_name = talloc_strdup(ctx, fname);
	}

	if (!base_name) {
		return NULL;
	}

	ret = synthetic_smb_fname(ctx, base_name, stream_name, psbuf);
	TALLOC_FREE(base_name);
	return ret;
}

/**
 * Return a string using the talloc_tos()
 */
const char *smb_fname_str_dbg(const struct smb_filename *smb_fname)
{
	char *fname = NULL;
	NTSTATUS status;

	if (smb_fname == NULL) {
		return "";
	}
	status = get_full_smb_filename(talloc_tos(), smb_fname, &fname);
	if (!NT_STATUS_IS_OK(status)) {
		return "";
	}
	return fname;
}

/**
 * Return a debug string of the path name of an fsp using the talloc_tos().
 */
const char *fsp_str_dbg(const struct files_struct *fsp)
{
	return smb_fname_str_dbg(fsp->fsp_name);
}

/**
 * Create a debug string for the fnum of an fsp.
 *
 * This is allocated to talloc_tos() or a string constant
 * in certain corner cases. The returned string should
 * hence not be free'd directly but only via the talloc stack.
 */
const char *fsp_fnum_dbg(const struct files_struct *fsp)
{
	char *str;

	if (fsp == NULL) {
		return "fnum [fsp is NULL]";
	}

	if (fsp->fnum == FNUM_FIELD_INVALID) {
		return "fnum [invalid value]";
	}

	str = talloc_asprintf(talloc_tos(), "fnum %llu",
			      (unsigned long long)fsp->fnum);
	if (str == NULL) {
		DEBUG(1, ("%s: talloc_asprintf failed\n", __FUNCTION__));
		return "fnum [talloc failed!]";
	}

	return str;
}

struct smb_filename *cp_smb_filename(TALLOC_CTX *mem_ctx,
				     const struct smb_filename *in)
{
	struct smb_filename *out;
	size_t base_len = 0;
	size_t stream_len = 0;
	size_t lcomp_len = 0;
	int num = 0;

	/* stream_name must always be NULL if there is no stream. */
	if (in->stream_name) {
		SMB_ASSERT(in->stream_name[0] != '\0');
	}

	if (in->base_name != NULL) {
		base_len = strlen(in->base_name) + 1;
		num += 1;
	}
	if (in->stream_name != NULL) {
		stream_len = strlen(in->stream_name) + 1;
		num += 1;
	}
	if (in->original_lcomp != NULL) {
		lcomp_len = strlen(in->original_lcomp) + 1;
		num += 1;
	}

	out = talloc_pooled_object(mem_ctx, struct smb_filename,
				num, stream_len + base_len + lcomp_len);
	if (out == NULL) {
		return NULL;
	}
	ZERO_STRUCTP(out);

	/*
	 * The following allocations cannot fails as we
	 * pre-allocated space for them in the out pooled
	 * object.
	 */
	if (in->base_name != NULL) {
		out->base_name = talloc_memdup(
				out, in->base_name, base_len);
	}
	if (in->stream_name != NULL) {
		out->stream_name = talloc_memdup(
				out, in->stream_name, stream_len);
	}
	if (in->original_lcomp != NULL) {
		out->original_lcomp = talloc_memdup(
				out, in->original_lcomp, lcomp_len);
	}
	out->st = in->st;
	return out;
}

/****************************************************************************
 Simple check to determine if the filename is a stream.
 ***************************************************************************/
bool is_ntfs_stream_smb_fname(const struct smb_filename *smb_fname)
{
	/* stream_name must always be NULL if there is no stream. */
	if (smb_fname->stream_name) {
		SMB_ASSERT(smb_fname->stream_name[0] != '\0');
	}

	if (lp_posix_pathnames()) {
		return false;
	}

	return smb_fname->stream_name != NULL;
}

/****************************************************************************
 Returns true if the filename's stream == "::$DATA"
 ***************************************************************************/
bool is_ntfs_default_stream_smb_fname(const struct smb_filename *smb_fname)
{
	if (!is_ntfs_stream_smb_fname(smb_fname)) {
		return false;
	}

	return strcasecmp_m(smb_fname->stream_name, "::$DATA") == 0;
}

/****************************************************************************
 Filter out Windows invalid EA names (list probed from Windows 2012).
****************************************************************************/

static char bad_ea_name_chars[] = "\"*+,/:;<=>?[\\]|";

bool is_invalid_windows_ea_name(const char *name)
{
	int i;
	/* EA name is pulled as ascii so we can examine
	   individual bytes here. */
	for (i = 0; name[i] != 0; i++) {
		int val = (name[i] & 0xff);
		if (val < ' ' || strchr(bad_ea_name_chars, val)) {
			return true;
		}
	}
	return false;
}

bool ea_list_has_invalid_name(struct ea_list *ea_list)
{
	if (lp_posix_pathnames()) {
		return false;
	}

	for (;ea_list; ea_list = ea_list->next) {
		if (is_invalid_windows_ea_name(ea_list->ea.name)) {
			return true;
		}
	}
	return false;
}
