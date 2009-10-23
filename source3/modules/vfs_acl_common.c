/*
 * Store Windows ACLs in data store - common functions.
 * #included into modules/vfs_acl_xattr.c and modules/vfs_acl_tdb.c
 *
 * Copyright (C) Volker Lendecke, 2008
 * Copyright (C) Jeremy Allison, 2009
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

static NTSTATUS create_acl_blob(const struct security_descriptor *psd,
			DATA_BLOB *pblob,
			uint16_t hash_type,
			uint8_t hash[XATTR_SD_HASH_SIZE]);

static NTSTATUS get_acl_blob(TALLOC_CTX *ctx,
			vfs_handle_struct *handle,
			files_struct *fsp,
			const char *name,
			DATA_BLOB *pblob);

static NTSTATUS store_acl_blob_fsp(vfs_handle_struct *handle,
			files_struct *fsp,
			DATA_BLOB *pblob);

static NTSTATUS store_acl_blob_pathname(vfs_handle_struct *handle,
			const char *fname,
			DATA_BLOB *pblob);

#define HASH_SECURITY_INFO (OWNER_SECURITY_INFORMATION | \
				GROUP_SECURITY_INFORMATION | \
				DACL_SECURITY_INFORMATION | \
				SACL_SECURITY_INFORMATION)

/*******************************************************************
 Hash a security descriptor.
*******************************************************************/

static NTSTATUS hash_sd_sha256(struct security_descriptor *psd,
			uint8_t *hash)
{
	DATA_BLOB blob;
	SHA256_CTX tctx;
	NTSTATUS status;

	memset(hash, '\0', XATTR_SD_HASH_SIZE);
	status = create_acl_blob(psd, &blob, XATTR_SD_HASH_TYPE_SHA256, hash);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	SHA256_Init(&tctx);
	SHA256_Update(&tctx, blob.data, blob.length);
	SHA256_Final(hash, &tctx);

	return NT_STATUS_OK;
}

/*******************************************************************
 Parse out a struct security_descriptor from a DATA_BLOB.
*******************************************************************/

static NTSTATUS parse_acl_blob(const DATA_BLOB *pblob,
				struct security_descriptor **ppdesc,
				uint16_t *p_hash_type,
				uint8_t hash[XATTR_SD_HASH_SIZE])
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

	switch (xacl.version) {
		case 2:
			*ppdesc = make_sec_desc(ctx, SEC_DESC_REVISION,
					xacl.info.sd_hs2->sd->type | SEC_DESC_SELF_RELATIVE,
					xacl.info.sd_hs2->sd->owner_sid,
					xacl.info.sd_hs2->sd->group_sid,
					xacl.info.sd_hs2->sd->sacl,
					xacl.info.sd_hs2->sd->dacl,
					&sd_size);
			/* No hash - null out. */
			*p_hash_type = XATTR_SD_HASH_TYPE_NONE;
			memset(hash, '\0', XATTR_SD_HASH_SIZE);
			break;
		case 3:
			*ppdesc = make_sec_desc(ctx, SEC_DESC_REVISION,
					xacl.info.sd_hs3->sd->type | SEC_DESC_SELF_RELATIVE,
					xacl.info.sd_hs3->sd->owner_sid,
					xacl.info.sd_hs3->sd->group_sid,
					xacl.info.sd_hs3->sd->sacl,
					xacl.info.sd_hs3->sd->dacl,
					&sd_size);
			*p_hash_type = xacl.info.sd_hs3->hash_type;
			/* Current version 3. */
			memcpy(hash, xacl.info.sd_hs3->hash, XATTR_SD_HASH_SIZE);
			break;
		default:
			return NT_STATUS_REVISION_MISMATCH;
	}

	TALLOC_FREE(xacl.info.sd);

	return (*ppdesc != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;
}

/*******************************************************************
 Create a DATA_BLOB from a security descriptor.
*******************************************************************/

static NTSTATUS create_acl_blob(const struct security_descriptor *psd,
			DATA_BLOB *pblob,
			uint16_t hash_type,
			uint8_t hash[XATTR_SD_HASH_SIZE])
{
	struct xattr_NTACL xacl;
	struct security_descriptor_hash_v3 sd_hs3;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *ctx = talloc_tos();

	ZERO_STRUCT(xacl);
	ZERO_STRUCT(sd_hs3);

	xacl.version = 3;
	xacl.info.sd_hs3 = &sd_hs3;
	xacl.info.sd_hs3->sd = CONST_DISCARD(struct security_descriptor *, psd);
	xacl.info.sd_hs3->hash_type = hash_type;
	memcpy(&xacl.info.sd_hs3->hash[0], hash, XATTR_SD_HASH_SIZE);

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

/*******************************************************************
 Store a DATA_BLOB into an xattr given a pathname.
*******************************************************************/

static NTSTATUS get_nt_acl_internal(vfs_handle_struct *handle,
				files_struct *fsp,
				const char *name,
			        uint32_t security_info,
				struct security_descriptor **ppdesc)
{
	DATA_BLOB blob;
	NTSTATUS status;
	uint16_t hash_type;
	uint8_t hash[XATTR_SD_HASH_SIZE];
	uint8_t hash_tmp[XATTR_SD_HASH_SIZE];
	struct security_descriptor *pdesc_next = NULL;

	if (fsp && name == NULL) {
		name = fsp->fsp_name->base_name;
	}

	DEBUG(10, ("get_nt_acl_internal: name=%s\n", name));

	status = get_acl_blob(talloc_tos(), handle, fsp, name, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("get_acl_blob returned %s\n", nt_errstr(status)));
		return status;
	}

	status = parse_acl_blob(&blob, ppdesc,
				&hash_type, &hash[0]);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("parse_acl_blob returned %s\n",
				nt_errstr(status)));
		return status;
	}

	/* Ensure the hash type is one we know. */
	switch (hash_type) {
		case XATTR_SD_HASH_TYPE_NONE:
			/* No hash, goto return blob sd. */
			goto out;
		case XATTR_SD_HASH_TYPE_SHA256:
			break;
		default:
			return NT_STATUS_REVISION_MISMATCH;
	}

	/* Get the full underlying sd, then hash. */
	if (fsp) {
		status = SMB_VFS_NEXT_FGET_NT_ACL(handle,
				fsp,
				HASH_SECURITY_INFO,
				&pdesc_next);
	} else {
		status = SMB_VFS_NEXT_GET_NT_ACL(handle,
				name,
				HASH_SECURITY_INFO,
				&pdesc_next);
	}

	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	status = hash_sd_sha256(pdesc_next, hash_tmp);
	if (!NT_STATUS_IS_OK(status)) {
		goto out;
	}

	if (memcmp(&hash[0], &hash_tmp[0], XATTR_SD_HASH_SIZE) == 0) {
		TALLOC_FREE(pdesc_next);
		/* Hash matches, return blob sd. */
		goto out;
	}

	/* Hash doesn't match, return underlying sd. */

	if (!(security_info & OWNER_SECURITY_INFORMATION)) {
		pdesc_next->owner_sid = NULL;
	}
	if (!(security_info & GROUP_SECURITY_INFORMATION)) {
		pdesc_next->group_sid = NULL;
	}
	if (!(security_info & DACL_SECURITY_INFORMATION)) {
		pdesc_next->dacl = NULL;
	}
	if (!(security_info & SACL_SECURITY_INFORMATION)) {
		pdesc_next->sacl = NULL;
	}

	TALLOC_FREE(*ppdesc);
	*ppdesc = pdesc_next;

  out:

	if (!(security_info & OWNER_SECURITY_INFORMATION)) {
		(*ppdesc)->owner_sid = NULL;
	}
	if (!(security_info & GROUP_SECURITY_INFORMATION)) {
		(*ppdesc)->group_sid = NULL;
	}
	if (!(security_info & DACL_SECURITY_INFORMATION)) {
		(*ppdesc)->dacl = NULL;
	}
	if (!(security_info & SACL_SECURITY_INFORMATION)) {
		(*ppdesc)->sacl = NULL;
	}

	TALLOC_FREE(blob.data);
	return status;
}

/*********************************************************************
 Create a default security descriptor for a file in case no inheritance
 exists. All permissions to the owner and SYSTEM.
*********************************************************************/

static struct security_descriptor *default_file_sd(TALLOC_CTX *mem_ctx,
						SMB_STRUCT_STAT *psbuf,
						bool force_inherit)
{
	struct dom_sid owner_sid, group_sid;
	size_t sd_size;
	struct security_ace *pace = NULL;
	struct security_acl *pacl = NULL;

	uid_to_sid(&owner_sid, psbuf->st_ex_uid);
	gid_to_sid(&group_sid, psbuf->st_ex_gid);

	pace = TALLOC_ARRAY(mem_ctx, struct security_ace, 2);
	if (!pace) {
		return NULL;
	}

	/* If force_inherit is set, this means we are initializing the ACEs for
	 * a container and we want the ACEs for owner_sid and "SYSTEM" to be
	 * inheritable by their children (See Bug #6802).
	 */

	init_sec_ace(&pace[0], &owner_sid, SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_ALL, (force_inherit ?
					(SEC_ACE_FLAG_OBJECT_INHERIT|
					SEC_ACE_FLAG_CONTAINER_INHERIT) :
					0));

	init_sec_ace(&pace[1], &global_sid_System, SEC_ACE_TYPE_ACCESS_ALLOWED,
			SEC_RIGHTS_FILE_ALL, (force_inherit ?
					(SEC_ACE_FLAG_OBJECT_INHERIT|
					SEC_ACE_FLAG_CONTAINER_INHERIT) :
					0));

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
					struct smb_filename *smb_fname,
					files_struct *fsp,
					bool container)
{
	TALLOC_CTX *ctx = talloc_tos();
	NTSTATUS status;
	struct security_descriptor *parent_desc = NULL;
	struct security_descriptor *psd = NULL;
	struct security_descriptor *pdesc_next = NULL;
	DATA_BLOB blob;
	size_t size;
	char *parent_name;
	bool force_inherit = false;
	uint8_t hash[XATTR_SD_HASH_SIZE];

	if (!parent_dirname(ctx, smb_fname->base_name, &parent_name, NULL)) {
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(10,("inherit_new_acl: check directory %s\n",
			parent_name));

	status = get_nt_acl_internal(handle,
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

		TALLOC_FREE(psd);
		if (fsp) {
			status = vfs_stat_fsp(fsp);
			smb_fname->st = fsp->fsp_name->st;
		} else {
			int ret;
			if (lp_posix_pathnames()) {
				ret = SMB_VFS_LSTAT(handle->conn, smb_fname);
			} else {
				ret = SMB_VFS_STAT(handle->conn, smb_fname);
			}
			if (ret == -1) {
				status = map_nt_error_from_unix(errno);
			}
		}
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		/* If we get here, we could have the following possibilities:
		 *	1. No ACLs exist on the parent container.
		 *	2. ACLs exist on the parent container but they were
		 *	not inheritable.
		 *
		 *	Check to see if case #1 occurred.
		 *
		 */
		if (container &&
			(parent_desc == NULL || parent_desc->dacl == NULL)) {

			/* If no parent descriptor exists, then there were
			 * no ACLs on the parent and then we must create
			 * the ACLs on this newly created folder so that they
			 * will be inherited by their children (See Bug #6802).
			 */

			force_inherit = true;
		}

		psd = default_file_sd(ctx, &smb_fname->st, force_inherit);
		if (!psd) {
			return NT_STATUS_NO_MEMORY;
		}

		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("inherit_new_acl: default acl is:\n"));
			NDR_PRINT_DEBUG(security_descriptor, psd);
		}
	}

	/* Object exists. Read the current SD to get the hash. */
	if (fsp) {
		status = SMB_VFS_NEXT_FGET_NT_ACL(handle,
				fsp,
				HASH_SECURITY_INFO,
				&pdesc_next);
	} else {
		status = SMB_VFS_NEXT_GET_NT_ACL(handle,
				smb_fname->base_name,
				HASH_SECURITY_INFO,
				&pdesc_next);
	}

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = hash_sd_sha256(pdesc_next, hash);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = create_acl_blob(psd, &blob, XATTR_SD_HASH_TYPE_SHA256, hash);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if (fsp) {
		return store_acl_blob_fsp(handle, fsp, &blob);
	} else {
		return store_acl_blob_pathname(handle, smb_fname->base_name,
					       &blob);
	}
}

/*********************************************************************
 Check ACL on open. For new files inherit from parent directory.
*********************************************************************/

static int open_acl_common(vfs_handle_struct *handle,
			struct smb_filename *smb_fname,
			files_struct *fsp,
			int flags,
			mode_t mode)
{
	uint32_t access_granted = 0;
	struct security_descriptor *pdesc = NULL;
	bool file_existed = true;
	char *fname = NULL;
	NTSTATUS status;

	if (fsp->base_fsp) {
		/* Stream open. Base filename open already did the ACL check. */
		DEBUG(10,("open_acl_common: stream open on %s\n",
			smb_fname_str_dbg(smb_fname) ));
		return SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);
	}

	status = get_full_smb_filename(talloc_tos(), smb_fname,
				       &fname);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	status = get_nt_acl_internal(handle,
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
				smb_fname_str_dbg(smb_fname),
				nt_errstr(status) ));
			errno = map_errno_from_nt_status(status);
			return -1;
		}
        } else if (NT_STATUS_EQUAL(status,NT_STATUS_OBJECT_NAME_NOT_FOUND)) {
		file_existed = false;
	}

	DEBUG(10,("open_acl_xattr: get_nt_acl_attr_internal for "
		"file %s returned %s\n",
		smb_fname_str_dbg(smb_fname),
		nt_errstr(status) ));

	fsp->fh->fd = SMB_VFS_NEXT_OPEN(handle, smb_fname, fsp, flags, mode);

	if (!file_existed && fsp->fh->fd != -1) {
		/* File was created. Inherit from parent directory. */
		status = fsp_set_smb_fname(fsp, smb_fname);
		if (!NT_STATUS_IS_OK(status)) {
			errno = map_errno_from_nt_status(status);
			return -1;
		}
		inherit_new_acl(handle, smb_fname, fsp, false);
	}

	return fsp->fh->fd;
}

static int mkdir_acl_common(vfs_handle_struct *handle, const char *path, mode_t mode)
{
	struct smb_filename *smb_fname = NULL;
	int ret = SMB_VFS_NEXT_MKDIR(handle, path, mode);
	NTSTATUS status;

	if (ret == -1) {
		return ret;
	}

	status = create_synthetic_smb_fname(talloc_tos(), path, NULL, NULL,
					    &smb_fname);
	if (!NT_STATUS_IS_OK(status)) {
		errno = map_errno_from_nt_status(status);
		return -1;
	}

	/* New directory - inherit from parent. */
	inherit_new_acl(handle, smb_fname, NULL, true);
	TALLOC_FREE(smb_fname);
	return ret;
}

/*********************************************************************
 Fetch a security descriptor given an fsp.
*********************************************************************/

static NTSTATUS fget_nt_acl_common(vfs_handle_struct *handle, files_struct *fsp,
        uint32_t security_info, struct security_descriptor **ppdesc)
{
	return get_nt_acl_internal(handle, fsp,
				NULL, security_info, ppdesc);
}

/*********************************************************************
 Fetch a security descriptor given a pathname.
*********************************************************************/

static NTSTATUS get_nt_acl_common(vfs_handle_struct *handle,
        const char *name, uint32_t security_info, struct security_descriptor **ppdesc)
{
	return get_nt_acl_internal(handle, NULL,
				name, security_info, ppdesc);
}

/*********************************************************************
 Store a security descriptor given an fsp.
*********************************************************************/

static NTSTATUS fset_nt_acl_common(vfs_handle_struct *handle, files_struct *fsp,
        uint32_t security_info_sent, const struct security_descriptor *psd)
{
	NTSTATUS status;
	DATA_BLOB blob;
	struct security_descriptor *pdesc_next = NULL;
	uint8_t hash[XATTR_SD_HASH_SIZE];

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("fset_nt_acl_xattr: incoming sd for file %s\n",
			  fsp_str_dbg(fsp)));
		NDR_PRINT_DEBUG(security_descriptor,
			CONST_DISCARD(struct security_descriptor *,psd));
	}

	/* Ensure owner and group are set. */
	if (!psd->owner_sid || !psd->group_sid) {
		DOM_SID owner_sid, group_sid;
		struct security_descriptor *nc_psd = dup_sec_desc(talloc_tos(), psd);

		if (!nc_psd) {
			return NT_STATUS_OK;
		}
		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			/* Lower level acl set succeeded,
			 * so still return OK. */
			return NT_STATUS_OK;
		}
		create_file_sids(&fsp->fsp_name->st, &owner_sid, &group_sid);
		/* This is safe as nc_psd is discarded at fn exit. */
		nc_psd->owner_sid = &owner_sid;
		nc_psd->group_sid = &group_sid;
		security_info_sent |= (OWNER_SECURITY_INFORMATION|GROUP_SECURITY_INFORMATION);
		psd = nc_psd;
	}

	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	/* Get the full underlying sd, then hash. */
	status = SMB_VFS_NEXT_FGET_NT_ACL(handle,
				fsp,
				HASH_SECURITY_INFO,
				&pdesc_next);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = hash_sd_sha256(pdesc_next, hash);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("fset_nt_acl_xattr: storing xattr sd for file %s\n",
			  fsp_str_dbg(fsp)));
		NDR_PRINT_DEBUG(security_descriptor,
			CONST_DISCARD(struct security_descriptor *,psd));
	}
	create_acl_blob(psd, &blob, XATTR_SD_HASH_TYPE_SHA256, hash);
	store_acl_blob_fsp(handle, fsp, &blob);

	return NT_STATUS_OK;
}
