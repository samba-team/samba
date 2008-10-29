/*
 * Store Windows ACLs in xattrs.
 *
 * Copyright (C) Volker Lendecke, 2008
 * Copyright (C) Jeremy Allison, 2008
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/* NOTE: This is an experimental module, not yet finished. JRA. */

#include "includes.h"
#include "librpc/gen_ndr/xattr.h"
#include "librpc/gen_ndr/ndr_xattr.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static NTSTATUS parse_acl_blob(const DATA_BLOB *pblob,
				const struct timespec cts,
				uint32 security_info,
				struct security_descriptor **ppdesc)
{
	TALLOC_CTX *ctx = talloc_tos();
	struct xattr_NTACL xacl;
	enum ndr_err_code ndr_err;
	size_t sd_size;

	ndr_err = ndr_pull_struct_blob(pblob, ctx, NULL, &xacl,
			(ndr_pull_flags_fn_t)ndr_pull_xattr_NTACL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("parse_acl_blob: ndr_pull_xattr_NTACL failed: %s\n",
			ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);;
	}

	if (xacl.version != 2) {
		return NT_STATUS_REVISION_MISMATCH;
	}

#if 0
	{
		struct timespec ts;
		/* Arg. This doesn't work. Too many activities
		 * change the ctime. May have to roll back to
		 * version 1.
		 */
		/*
		 * Check that the ctime timestamp is ealier
		 * than the stored timestamp.
		 */

		ts = nt_time_to_unix_timespec(&xacl.info.sd_ts->last_changed);

		if (timespec_compare(&cts, &ts) > 0) {
			DEBUG(5, ("parse_acl_blob: stored ACL out of date "
				"(%s > %s.\n",
				timestring(ctx, cts.tv_sec),
				timestring(ctx, ts.tv_sec)));
			return NT_STATUS_EA_CORRUPT_ERROR;
		}
	}
#endif

	*ppdesc = make_sec_desc(ctx, SEC_DESC_REVISION, SEC_DESC_SELF_RELATIVE,
			(security_info & OWNER_SECURITY_INFORMATION)
			? xacl.info.sd_ts->sd->owner_sid : NULL,
			(security_info & GROUP_SECURITY_INFORMATION)
			? xacl.info.sd_ts->sd->group_sid : NULL,
			(security_info & SACL_SECURITY_INFORMATION)
			? xacl.info.sd_ts->sd->sacl : NULL,
			(security_info & DACL_SECURITY_INFORMATION)
			? xacl.info.sd_ts->sd->dacl : NULL,
			&sd_size);

	TALLOC_FREE(xacl.info.sd);

	return (*ppdesc != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;
}

static NTSTATUS get_acl_blob(TALLOC_CTX *ctx,
			vfs_handle_struct *handle,
			files_struct *fsp,
			const char *name,
			DATA_BLOB *pblob)
{
	size_t size = 1024;
	uint8_t *val = NULL;
	uint8_t *tmp;
	ssize_t sizeret;
	int saved_errno = 0;

	ZERO_STRUCTP(pblob);

  again:

	tmp = TALLOC_REALLOC_ARRAY(ctx, val, uint8_t, size);
	if (tmp == NULL) {
		TALLOC_FREE(val);
		return NT_STATUS_NO_MEMORY;
	}
	val = tmp;

	become_root();
	if (fsp && fsp->fh->fd != -1) {
		sizeret = SMB_VFS_FGETXATTR(fsp, XATTR_NTACL_NAME, val, size);
	} else {
		sizeret = SMB_VFS_GETXATTR(handle->conn, name,
					XATTR_NTACL_NAME, val, size);
	}
	if (sizeret == -1) {
		saved_errno = errno;
	}
	unbecome_root();

	/* Max ACL size is 65536 bytes. */
	if (sizeret == -1) {
		errno = saved_errno;
		if ((errno == ERANGE) && (size != 65536)) {
			/* Too small, try again. */
			size = 65536;
			goto again;
		}

		/* Real error - exit here. */
		TALLOC_FREE(val);
		return map_nt_error_from_unix(errno);
	}

	pblob->data = val;
	pblob->length = sizeret;
	return NT_STATUS_OK;
}

static NTSTATUS create_acl_blob(const SEC_DESC *psd, DATA_BLOB *pblob)
{
	struct xattr_NTACL xacl;
	struct security_descriptor_timestamp sd_ts;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *ctx = talloc_tos();
	struct timespec curr = timespec_current();

	ZERO_STRUCT(xacl);
	ZERO_STRUCT(sd_ts);

	/* Horrid hack as setting an xattr changes the ctime
 	 * on Linux. This gives a race of 1 second during
 	 * which we would not see a POSIX ACL set.
 	 */
	curr.tv_sec += 1;

	xacl.version = 2;
	xacl.info.sd_ts = &sd_ts;
	xacl.info.sd_ts->sd = CONST_DISCARD(SEC_DESC *, psd);
	unix_timespec_to_nt_time(&xacl.info.sd_ts->last_changed, curr);

	DEBUG(10, ("create_acl_blob: timestamp stored as %s\n",
		timestring(ctx, curr.tv_sec) ));

	ndr_err = ndr_push_struct_blob(
			pblob, ctx, NULL, &xacl,
			(ndr_push_flags_fn_t)ndr_push_xattr_NTACL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("create_acl_blob: ndr_push_xattr_NTACL failed: %s\n",
			ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);;
	}

	return NT_STATUS_OK;
}

static NTSTATUS store_acl_blob(files_struct *fsp,
				DATA_BLOB *pblob)
{
	int ret;
	int saved_errno = 0;

	DEBUG(10,("store_acl_blob: storing blob length %u on file %s\n",
			(unsigned int)pblob->length, fsp->fsp_name));

	become_root();
	if (fsp->fh->fd != -1) {
		ret = SMB_VFS_FSETXATTR(fsp, XATTR_NTACL_NAME,
			pblob->data, pblob->length, 0);
	} else {
		ret = SMB_VFS_SETXATTR(fsp->conn, fsp->fsp_name,
				XATTR_NTACL_NAME,
				pblob->data, pblob->length, 0);
	}
	if (ret) {
		saved_errno = errno;
	}
	unbecome_root();
	if (ret) {
		errno = saved_errno;
		DEBUG(5, ("store_acl_blob: setting attr failed for file %s"
			"with error %s\n",
			fsp->fsp_name,
			strerror(errno) ));
		return map_nt_error_from_unix(errno);
	}
	return NT_STATUS_OK;
}


static NTSTATUS get_nt_acl_xattr_internal(vfs_handle_struct *handle,
					files_struct *fsp,
					const char *name,
				        uint32 security_info,
					SEC_DESC **ppdesc)
{
	TALLOC_CTX *ctx = talloc_tos();
	DATA_BLOB blob;
	SMB_STRUCT_STAT sbuf;
	NTSTATUS status;

	if (fsp && name == NULL) {
		name = fsp->fsp_name;
	}

	DEBUG(10, ("get_nt_acl_xattr_internal: name=%s\n", name));

	status = get_acl_blob(ctx, handle, fsp, name, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("get_acl_blob returned %s\n", nt_errstr(status)));
		return status;
	}

	if (fsp && fsp->fh->fd != -1) {
		if (SMB_VFS_FSTAT(fsp, &sbuf) == -1) {
			return map_nt_error_from_unix(errno);
		}
	} else {
		if (SMB_VFS_STAT(handle->conn, name, &sbuf) == -1) {
			return map_nt_error_from_unix(errno);
		}
	}

	status = parse_acl_blob(&blob, get_ctimespec(&sbuf),
			security_info, ppdesc);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("parse_acl_blob returned %s\n",
				nt_errstr(status)));
		return status;
	}

	TALLOC_FREE(blob.data);
	return status;
}

static int mkdir_acl_xattr(vfs_handle_struct *handle,  const char *path, mode_t mode)
{
	return SMB_VFS_NEXT_MKDIR(handle, path, mode);
}

/*********************************************************************
 * Currently this only works for existing files. Need to work on
 * inheritance for new files.
*********************************************************************/

static NTSTATUS inherit_new_acl(vfs_handle_struct *handle,
					const char *fname,
					files_struct *fsp)
{
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status;
	SEC_DESC *parent_desc = NULL;
	SEC_DESC *psd = NULL;
	DATA_BLOB blob;
	size_t size;
	char *parent_name;

	if (!parent_dirname_talloc(ctx,
				fname,
				&parent_name,
				NULL)) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10,("inherit_new_acl: check directory %s\n",
			parent_name));

	status = get_nt_acl_xattr_internal(handle,
					NULL,
					parent_name,
					DACL_SECURITY_INFORMATION,
					&parent_desc);
        if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("inherit_new_acl: directory %s failed "
			"to get acl %s\n",
			parent_name,
			nt_errstr(status) ));
		return status;
	}

	/* Create an inherited descriptor from the parent. */
	status = se_create_child_secdesc(ctx,
				&psd,
				&size,
				parent_desc,
				&handle->conn->server_info->ptok->user_sids[PRIMARY_USER_SID_INDEX],
				&handle->conn->server_info->ptok->user_sids[PRIMARY_GROUP_SID_INDEX],
				false);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = create_acl_blob(psd, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return store_acl_blob(fsp, &blob);
}

/*********************************************************************
 Check ACL on open. For new files inherit from parent directory.
*********************************************************************/

static int open_acl_xattr(vfs_handle_struct *handle,
					const char *fname,
					files_struct *fsp,
					int flags,
					mode_t mode)
{
	uint32_t access_granted = 0;
	SEC_DESC *pdesc = NULL;
	bool file_existed = true;
	NTSTATUS status = get_nt_acl_xattr_internal(handle,
					NULL,
					fname,
					(OWNER_SECURITY_INFORMATION |
					 GROUP_SECURITY_INFORMATION |
					 DACL_SECURITY_INFORMATION),
					&pdesc);
        if (NT_STATUS_IS_OK(status)) {
		/* See if we can access it. */
		if (!se_access_check(pdesc,
					handle->conn->server_info->ptok,
					fsp->access_mask,
					&access_granted,
					&status)) {
			errno = map_errno_from_nt_status(status);
			return -1;
		}
        } else if (NT_STATUS_EQUAL(status,NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		file_existed = false;
	}

	DEBUG(10,("open_acl_xattr: get_nt_acl_attr_internal for "
		"file %s returned %s\n",
		fname,
		nt_errstr(status) ));

	fsp->fh->fd = SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode);

	if (!file_existed && fsp->fh->fd != -1) {
		/* File was created. Inherit from parent directory. */
		string_set(&fsp->fsp_name, fname);
		inherit_new_acl(handle, fname, fsp);
	}

	return fsp->fh->fd;
}

static NTSTATUS fget_nt_acl_xattr(vfs_handle_struct *handle, files_struct *fsp,
        uint32 security_info, SEC_DESC **ppdesc)
{
	NTSTATUS status = get_nt_acl_xattr_internal(handle, fsp,
				NULL, security_info, ppdesc);
	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}
	return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp,
			security_info, ppdesc);
}

static NTSTATUS get_nt_acl_xattr(vfs_handle_struct *handle,
        const char *name, uint32 security_info, SEC_DESC **ppdesc)
{
	NTSTATUS status = get_nt_acl_xattr_internal(handle, NULL,
				name, security_info, ppdesc);
	if (NT_STATUS_IS_OK(status)) {
		return NT_STATUS_OK;
	}
	return SMB_VFS_NEXT_GET_NT_ACL(handle, name,
			security_info, ppdesc);
}

static NTSTATUS fset_nt_acl_xattr(vfs_handle_struct *handle, files_struct *fsp,
        uint32 security_info_sent, const SEC_DESC *psd)
{
	NTSTATUS status;
	DATA_BLOB blob;

	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if ((security_info_sent & DACL_SECURITY_INFORMATION) &&
			psd->dacl != NULL &&
			(psd->type & (SE_DESC_DACL_AUTO_INHERITED|
				SE_DESC_DACL_AUTO_INHERIT_REQ))==
				(SE_DESC_DACL_AUTO_INHERITED|
				SE_DESC_DACL_AUTO_INHERIT_REQ) ) {
		SEC_DESC *new_psd = NULL;
		status = append_parent_acl(fsp, psd, &new_psd);
		if (!NT_STATUS_IS_OK(status)) {
			/* Lower level acl set succeeded,
			 * so still return OK. */
			return NT_STATUS_OK;
		}
		psd = new_psd;
	}

	create_acl_blob(psd, &blob);
	store_acl_blob(fsp, &blob);

	return NT_STATUS_OK;
}

/* VFS operations structure */

static vfs_op_tuple skel_op_tuples[] =
{
	{SMB_VFS_OP(mkdir_acl_xattr), SMB_VFS_OP_MKDIR, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(open_acl_xattr),  SMB_VFS_OP_OPEN,  SMB_VFS_LAYER_TRANSPARENT},

        /* NT File ACL operations */

	{SMB_VFS_OP(fget_nt_acl_xattr),SMB_VFS_OP_FGET_NT_ACL,SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(get_nt_acl_xattr), SMB_VFS_OP_GET_NT_ACL, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(fset_nt_acl_xattr),SMB_VFS_OP_FSET_NT_ACL,SMB_VFS_LAYER_TRANSPARENT},

        {SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_acl_xattr_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "acl_xattr", skel_op_tuples);
}
