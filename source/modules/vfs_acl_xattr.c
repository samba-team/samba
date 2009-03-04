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

/*******************************************************************
 Parse out a struct security_descriptor from a DATA_BLOB.
*******************************************************************/

static NTSTATUS parse_acl_blob(const DATA_BLOB *pblob,
				uint32 security_info,
				struct security_descriptor **ppdesc)
{
	TALLOC_CTX *ctx = talloc_tos();
	struct xattr_NTACL xacl;
	enum ndr_err_code ndr_err;
	size_t sd_size;

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

	*ppdesc = make_sec_desc(ctx, SEC_DESC_REVISION, xacl.info.sd_hs->sd->type | SEC_DESC_SELF_RELATIVE,
			(security_info & OWNER_SECURITY_INFORMATION)
			? xacl.info.sd_hs->sd->owner_sid : NULL,
			(security_info & GROUP_SECURITY_INFORMATION)
			? xacl.info.sd_hs->sd->group_sid : NULL,
			(security_info & SACL_SECURITY_INFORMATION)
			? xacl.info.sd_hs->sd->sacl : NULL,
			(security_info & DACL_SECURITY_INFORMATION)
			? xacl.info.sd_hs->sd->dacl : NULL,
			&sd_size);

	TALLOC_FREE(xacl.info.sd);

	return (*ppdesc != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;
}

/*******************************************************************
 Pull a security descriptor into a DATA_BLOB from a xattr.
*******************************************************************/

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

/*******************************************************************
 Create a DATA_BLOB from a security descriptor.
*******************************************************************/

static NTSTATUS create_acl_blob(const struct security_descriptor *psd, DATA_BLOB *pblob)
{
	struct xattr_NTACL xacl;
	struct security_descriptor_hash sd_hs;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *ctx = talloc_tos();

	ZERO_STRUCT(xacl);
	ZERO_STRUCT(sd_hs);

	xacl.version = 2;
	xacl.info.sd_hs = &sd_hs;
	xacl.info.sd_hs->sd = CONST_DISCARD(struct security_descriptor *, psd);
	memset(&xacl.info.sd_hs->hash[0], '\0', 16);

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

/*******************************************************************
 Store a DATA_BLOB into an xattr given an fsp pointer.
*******************************************************************/

static NTSTATUS store_acl_blob_fsp(vfs_handle_struct *handle,
				files_struct *fsp,
				DATA_BLOB *pblob)
{
	int ret;
	int saved_errno = 0;

	DEBUG(10,("store_acl_blob_fsp: storing blob length %u on file %s\n",
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
		DEBUG(5, ("store_acl_blob_fsp: setting attr failed for file %s"
			"with error %s\n",
			fsp->fsp_name,
			strerror(errno) ));
		return map_nt_error_from_unix(errno);
	}
	return NT_STATUS_OK;
}

/*******************************************************************
 Store a DATA_BLOB into an xattr given a pathname.
*******************************************************************/

static NTSTATUS store_acl_blob_pathname(vfs_handle_struct *handle,
					const char *fname,
					DATA_BLOB *pblob)
{
	connection_struct *conn = handle->conn;
	int ret;
	int saved_errno = 0;

	DEBUG(10,("store_acl_blob_pathname: storing blob "
			"length %u on file %s\n",
			(unsigned int)pblob->length, fname));

	become_root();
	ret = SMB_VFS_SETXATTR(conn, fname,
				XATTR_NTACL_NAME,
				pblob->data, pblob->length, 0);
	if (ret) {
		saved_errno = errno;
	}
	unbecome_root();
	if (ret) {
		errno = saved_errno;
		DEBUG(5, ("store_acl_blob_pathname: setting attr failed "
			"for file %s with error %s\n",
			fname,
			strerror(errno) ));
		return map_nt_error_from_unix(errno);
	}
	return NT_STATUS_OK;
}

/*******************************************************************
 Store a DATA_BLOB into an xattr given a pathname.
*******************************************************************/

static NTSTATUS get_nt_acl_xattr_internal(vfs_handle_struct *handle,
					files_struct *fsp,
					const char *name,
				        uint32 security_info,
					struct security_descriptor **ppdesc)
{
	TALLOC_CTX *ctx = talloc_tos();
	DATA_BLOB blob;
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

	status = parse_acl_blob(&blob, security_info, ppdesc);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("parse_acl_blob returned %s\n",
				nt_errstr(status)));
		return status;
	}

	TALLOC_FREE(blob.data);
	return status;
}

/*********************************************************************
 Create a default security descriptor for a file in case no inheritance
 exists. All permissions to the owner and SYSTEM.
*********************************************************************/

static struct security_descriptor *default_file_sd(TALLOC_CTX *mem_ctx,
						SMB_STRUCT_STAT *psbuf)
{
	struct dom_sid owner_sid, group_sid;
	size_t sd_size;
	struct security_ace *pace = NULL;
	struct security_acl *pacl = NULL;

	uid_to_sid(&owner_sid, psbuf->st_uid);
	gid_to_sid(&group_sid, psbuf->st_gid);

	pace = TALLOC_ARRAY(mem_ctx, struct security_ace, 2);
	if (!pace) {
		return NULL;
	}

	init_sec_ace(&pace[0], &owner_sid, SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_ALL, 0);
	init_sec_ace(&pace[1], &global_sid_System, SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_ALL, 0);

	pacl = make_sec_acl(mem_ctx,
				NT4_ACL_REVISION,
				2,
				pace);
	if (!pacl) {
		return NULL;
	}
	return make_sec_desc(mem_ctx,
			SECURITY_DESCRIPTOR_REVISION_1,
			SEC_DESC_SELF_RELATIVE|SEC_DESC_DACL_PRESENT,
			&owner_sid,
			&group_sid,
			NULL,
                        pacl,
			&sd_size);
}

/*********************************************************************
*********************************************************************/

static NTSTATUS inherit_new_acl(vfs_handle_struct *handle,
					const char *fname,
					files_struct *fsp,
					bool container)
{
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status;
	struct security_descriptor *parent_desc = NULL;
	struct security_descriptor *psd = NULL;
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
					(OWNER_SECURITY_INFORMATION |
					 GROUP_SECURITY_INFORMATION |
					 DACL_SECURITY_INFORMATION),
					&parent_desc);
        if (NT_STATUS_IS_OK(status)) {
		/* Create an inherited descriptor from the parent. */

		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("inherit_new_acl: parent acl is:\n"));
			NDR_PRINT_DEBUG(security_descriptor, parent_desc);
		}

		status = se_create_child_secdesc(ctx,
				&psd,
				&size,
				parent_desc,
				&handle->conn->server_info->ptok->user_sids[PRIMARY_USER_SID_INDEX],
				&handle->conn->server_info->ptok->user_sids[PRIMARY_GROUP_SID_INDEX],
				container);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("inherit_new_acl: child acl is:\n"));
			NDR_PRINT_DEBUG(security_descriptor, psd);
		}

	} else {
		DEBUG(10,("inherit_new_acl: directory %s failed "
			"to get acl %s\n",
			parent_name,
			nt_errstr(status) ));
	}

	if (!psd || psd->dacl == NULL) {
		SMB_STRUCT_STAT sbuf;
		int ret;

		TALLOC_FREE(psd);
		if (fsp && !fsp->is_directory && fsp->fh->fd != -1) {
			ret = SMB_VFS_FSTAT(fsp, &sbuf);
		} else {
			if (fsp && fsp->posix_open) {
				ret = SMB_VFS_LSTAT(handle->conn,fname, &sbuf);
			} else {
				ret = SMB_VFS_STAT(handle->conn,fname, &sbuf);
			}
		}
		if (ret == -1) {
			return map_nt_error_from_unix(errno);
		}
		psd = default_file_sd(ctx, &sbuf);
		if (!psd) {
			return NT_STATUS_NO_MEMORY;
		}

		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("inherit_new_acl: default acl is:\n"));
			NDR_PRINT_DEBUG(security_descriptor, psd);
		}
	}

	status = create_acl_blob(psd, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (fsp) {
		return store_acl_blob_fsp(handle, fsp, &blob);
	} else {
		return store_acl_blob_pathname(handle, fname, &blob);
	}
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
	struct security_descriptor *pdesc = NULL;
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
		status = smb1_file_se_access_check(pdesc,
					handle->conn->server_info->ptok,
					fsp->access_mask,
					&access_granted);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10,("open_acl_xattr: file %s open "
				"refused with error %s\n",
				fname,
				nt_errstr(status) ));
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
		inherit_new_acl(handle, fname, fsp, false);
	}

	return fsp->fh->fd;
}

static int mkdir_acl_xattr(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	int ret = SMB_VFS_NEXT_MKDIR(handle, path, mode);

	if (ret == -1) {
		return ret;
	}
	/* New directory - inherit from parent. */
	inherit_new_acl(handle, path, NULL, true);
	return ret;
}

/*********************************************************************
 Fetch a security descriptor given an fsp.
*********************************************************************/

static NTSTATUS fget_nt_acl_xattr(vfs_handle_struct *handle, files_struct *fsp,
        uint32 security_info, struct security_descriptor **ppdesc)
{
	NTSTATUS status = get_nt_acl_xattr_internal(handle, fsp,
				NULL, security_info, ppdesc);
	if (NT_STATUS_IS_OK(status)) {
		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("fget_nt_acl_xattr: returning xattr sd for file %s\n",
				fsp->fsp_name));
			NDR_PRINT_DEBUG(security_descriptor, *ppdesc);
		}
		return NT_STATUS_OK;
	}

	DEBUG(10,("fget_nt_acl_xattr: failed to get xattr sd for file %s, Error %s\n",
			fsp->fsp_name,
			nt_errstr(status) ));

	return SMB_VFS_NEXT_FGET_NT_ACL(handle, fsp,
			security_info, ppdesc);
}

/*********************************************************************
 Fetch a security descriptor given a pathname.
*********************************************************************/

static NTSTATUS get_nt_acl_xattr(vfs_handle_struct *handle,
        const char *name, uint32 security_info, struct security_descriptor **ppdesc)
{
	NTSTATUS status = get_nt_acl_xattr_internal(handle, NULL,
				name, security_info, ppdesc);
	if (NT_STATUS_IS_OK(status)) {
		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("get_nt_acl_xattr: returning xattr sd for file %s\n",
				name));
			NDR_PRINT_DEBUG(security_descriptor, *ppdesc);
		}
		return NT_STATUS_OK;
	}

	DEBUG(10,("get_nt_acl_xattr: failed to get xattr sd for file %s, Error %s\n",
			name,
			nt_errstr(status) ));

	return SMB_VFS_NEXT_GET_NT_ACL(handle, name,
			security_info, ppdesc);
}

/*********************************************************************
 Store a security descriptor given an fsp.
*********************************************************************/

static NTSTATUS fset_nt_acl_xattr(vfs_handle_struct *handle, files_struct *fsp,
        uint32 security_info_sent, const struct security_descriptor *psd)
{
	NTSTATUS status;
	DATA_BLOB blob;

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("fset_nt_acl_xattr: incoming sd for file %s\n",
			fsp->fsp_name));
		NDR_PRINT_DEBUG(security_descriptor,
			CONST_DISCARD(struct security_descriptor *,psd));
	}

	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Ensure owner and group are set. */
	if (!psd->owner_sid || !psd->group_sid) {
		int ret;
		SMB_STRUCT_STAT sbuf;
		DOM_SID owner_sid, group_sid;
		struct security_descriptor *nc_psd = dup_sec_desc(talloc_tos(), psd);

		if (!nc_psd) {
			return NT_STATUS_OK;
		}
		if (fsp->is_directory || fsp->fh->fd == -1) {
			if (fsp->posix_open) {
				ret = SMB_VFS_LSTAT(fsp->conn,fsp->fsp_name, &sbuf);
			} else {
				ret = SMB_VFS_STAT(fsp->conn,fsp->fsp_name, &sbuf);
			}
		} else {
			ret = SMB_VFS_FSTAT(fsp, &sbuf);
		}
		if (ret == -1) {
			/* Lower level acl set succeeded,
			 * so still return OK. */
			return NT_STATUS_OK;
		}
		create_file_sids(&sbuf, &owner_sid, &group_sid);
		/* This is safe as nc_psd is discarded at fn exit. */
		nc_psd->owner_sid = &owner_sid;
		nc_psd->group_sid = &group_sid;
		security_info_sent |= (OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION);
		psd = nc_psd;
	}

#if 0
	if ((security_info_sent & DACL_SECURITY_INFORMATION) &&
			psd->dacl != NULL &&
			(psd->type & (SE_DESC_DACL_AUTO_INHERITED|
				SE_DESC_DACL_AUTO_INHERIT_REQ))==
				(SE_DESC_DACL_AUTO_INHERITED|
				SE_DESC_DACL_AUTO_INHERIT_REQ) ) {
		struct security_descriptor *new_psd = NULL;
		status = append_parent_acl(fsp, psd, &new_psd);
		if (!NT_STATUS_IS_OK(status)) {
			/* Lower level acl set succeeded,
			 * so still return OK. */
			return NT_STATUS_OK;
		}
		psd = new_psd;
	}
#endif

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("fset_nt_acl_xattr: storing xattr sd for file %s\n",
			fsp->fsp_name));
		NDR_PRINT_DEBUG(security_descriptor,
			CONST_DISCARD(struct security_descriptor *,psd));
	}
	create_acl_blob(psd, &blob);
	store_acl_blob_fsp(handle, fsp, &blob);

	return NT_STATUS_OK;
}

/*********************************************************************
 Remove a Windows ACL - we're setting the underlying POSIX ACL.
*********************************************************************/

static int sys_acl_set_file_xattr(vfs_handle_struct *handle,
                              const char *name,
                              SMB_ACL_TYPE_T type,
                              SMB_ACL_T theacl)
{
	int ret = SMB_VFS_NEXT_SYS_ACL_SET_FILE(handle,
						name,
						type,
						theacl);
	if (ret == -1) {
		return -1;
	}

	become_root();
	SMB_VFS_REMOVEXATTR(handle->conn, name, XATTR_NTACL_NAME);
	unbecome_root();

	return ret;
}

/*********************************************************************
 Remove a Windows ACL - we're setting the underlying POSIX ACL.
*********************************************************************/

static int sys_acl_set_fd_xattr(vfs_handle_struct *handle,
                            files_struct *fsp,
                            SMB_ACL_T theacl)
{
	int ret = SMB_VFS_NEXT_SYS_ACL_SET_FD(handle,
						fsp,
						theacl);
	if (ret == -1) {
		return -1;
	}

	become_root();
	SMB_VFS_FREMOVEXATTR(fsp, XATTR_NTACL_NAME);
	unbecome_root();

	return ret;
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

	/* POSIX ACL operations. */
	{SMB_VFS_OP(sys_acl_set_file_xattr), SMB_VFS_OP_SYS_ACL_SET_FILE, SMB_VFS_LAYER_TRANSPARENT},
	{SMB_VFS_OP(sys_acl_set_fd_xattr), SMB_VFS_OP_SYS_ACL_SET_FD, SMB_VFS_LAYER_TRANSPARENT},

	{SMB_VFS_OP(NULL), SMB_VFS_OP_NOOP, SMB_VFS_LAYER_NOOP}
};

NTSTATUS vfs_acl_xattr_init(void)
{
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "acl_xattr", skel_op_tuples);
}
