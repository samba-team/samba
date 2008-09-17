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
	struct timespec ts;

	ndr_err = ndr_pull_struct_blob(pblob, ctx, &xacl,
			(ndr_pull_flags_fn_t)ndr_pull_xattr_NTACL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("parse_acl_blob: ndr_pull_xattr_NTACL failed: %s\n",
			ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);;
	}

	if (xacl.version != 2) {
		return NT_STATUS_REVISION_MISMATCH;
	}

	/*
	 * Check that the ctime timestamp is ealier
	 * than the stored timestamp.
	 */

	ts = nt_time_to_unix_timespec(&xacl.info.sd_ts->last_changed);

	if (timespec_compare(&cts, &ts) > 0) {
		DEBUG(5, ("parse_acl_blob: stored ACL out of date.\n"));
		return NT_STATUS_EA_CORRUPT_ERROR;
	}

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
	int saved_errno;

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

static int mkdir_acl_xattr(vfs_handle_struct *handle,  const char *path, mode_t mode)
{
	return SMB_VFS_NEXT_MKDIR(handle, path, mode);
}

static int rmdir_acl_xattr(vfs_handle_struct *handle,  const char *path)
{
	return SMB_VFS_NEXT_RMDIR(handle, path);
}

static int open_acl_xattr(vfs_handle_struct *handle,  const char *fname, files_struct *fsp, int flags, mode_t mode)
{
	return SMB_VFS_NEXT_OPEN(handle, fname, fsp, flags, mode);
}

static int unlink_acl_xattr(vfs_handle_struct *handle,  const char *fname)
{
	return SMB_VFS_NEXT_UNLINK(handle, fname);
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

static NTSTATUS create_acl_blob(SEC_DESC *psd, DATA_BLOB *pblob)
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
	xacl.info.sd_ts->sd = psd;
	unix_timespec_to_nt_time(&xacl.info.sd_ts->last_changed, curr);

	ndr_err = ndr_push_struct_blob(
			pblob, ctx, &xacl,
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
	int saved_errno;

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

static NTSTATUS fset_nt_acl_xattr(vfs_handle_struct *handle, files_struct *fsp,
        uint32 security_info_sent, SEC_DESC *psd)
{
	NTSTATUS status;
	DATA_BLOB blob;

	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	create_acl_blob(psd, &blob);
	store_acl_blob(fsp, &blob);

	return NT_STATUS_OK;
}

/* VFS operations structure */

static vfs_op_tuple skel_op_tuples[] =
{
	{SMB_VFS_OP(mkdir_acl_xattr), SMB_VFS_OP_MKDIR, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(rmdir_acl_xattr), SMB_VFS_OP_RMDIR, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(open_acl_xattr),  SMB_VFS_OP_OPEN,  SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(unlink_acl_xattr),SMB_VFS_OP_UNLINK,SMB_VFS_LAYER_TRANSPARENT},

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
