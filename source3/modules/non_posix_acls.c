/*
   Unix SMB/CIFS implementation.
   Access Control List handling
   Copyright (C) Andrew Bartlett 2012.

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
#include "../librpc/gen_ndr/ndr_xattr.h"
#include "modules/non_posix_acls.h"

int non_posix_sys_acl_blob_get_file_helper(vfs_handle_struct *handle,
					   const char *path_p,
					   DATA_BLOB acl_as_blob,
					   TALLOC_CTX *mem_ctx,
					   DATA_BLOB *blob)
{
	int ret;
	TALLOC_CTX *frame = talloc_stackframe();
	struct xattr_sys_acl_hash_wrapper acl_wrapper = {};
	struct smb_filename *smb_fname;

	smb_fname = synthetic_smb_fname(frame, path_p, NULL, NULL);
	if (smb_fname == NULL) {
		TALLOC_FREE(frame);
		errno = ENOMEM;
		return -1;
	}

	acl_wrapper.acl_as_blob = acl_as_blob;

	ret = smb_vfs_call_stat(handle, smb_fname);
	if (ret == -1) {
		TALLOC_FREE(frame);
		return -1;
	}

	acl_wrapper.owner = smb_fname->st.st_ex_uid;
	acl_wrapper.group = smb_fname->st.st_ex_gid;
	acl_wrapper.mode = smb_fname->st.st_ex_mode;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_struct_blob(blob, mem_ctx,
							  &acl_wrapper,
							  (ndr_push_flags_fn_t)ndr_push_xattr_sys_acl_hash_wrapper))) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	TALLOC_FREE(frame);
	return 0;
}

int non_posix_sys_acl_blob_get_fd_helper(vfs_handle_struct *handle,
					 files_struct *fsp,
					 DATA_BLOB acl_as_blob,
					 TALLOC_CTX *mem_ctx,
					 DATA_BLOB *blob)
{
	SMB_STRUCT_STAT sbuf;
	TALLOC_CTX *frame;
	struct xattr_sys_acl_hash_wrapper acl_wrapper;
	int ret;

	frame = talloc_stackframe();

	acl_wrapper.acl_as_blob = acl_as_blob;

	if (!VALID_STAT(fsp->fsp_name->st)) {
		ret = smb_vfs_call_fstat(handle, fsp, &sbuf);
		if (ret == -1) {
			TALLOC_FREE(frame);
			return -1;
		}
	} else {
		sbuf = fsp->fsp_name->st;
	}

	acl_wrapper.owner = sbuf.st_ex_uid;
	acl_wrapper.group = sbuf.st_ex_gid;
	acl_wrapper.mode = sbuf.st_ex_mode;

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_push_struct_blob(blob, mem_ctx,
							  &acl_wrapper,
							  (ndr_push_flags_fn_t)ndr_push_xattr_sys_acl_hash_wrapper))) {
		errno = EINVAL;
		TALLOC_FREE(frame);
		return -1;
	}

	TALLOC_FREE(frame);
	return 0;
}
