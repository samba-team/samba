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

#include "smbd/smbd.h"
#include "system/filesys.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "../lib/util/bitmap.h"

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

#define HASH_SECURITY_INFO (SECINFO_OWNER | \
				SECINFO_GROUP | \
				SECINFO_DACL | \
				SECINFO_SACL)

/*******************************************************************
 Hash a security descriptor.
*******************************************************************/

static NTSTATUS hash_blob_sha256(DATA_BLOB blob,
				 uint8_t *hash)
{
	SHA256_CTX tctx;

	memset(hash, '\0', XATTR_SD_HASH_SIZE);

	samba_SHA256_Init(&tctx);
	samba_SHA256_Update(&tctx, blob.data, blob.length);
	samba_SHA256_Final(hash, &tctx);

	return NT_STATUS_OK;
}

/*******************************************************************
 Hash a security descriptor.
*******************************************************************/

static NTSTATUS hash_sd_sha256(struct security_descriptor *psd,
			uint8_t *hash)
{
	DATA_BLOB blob;
	NTSTATUS status;

	memset(hash, '\0', XATTR_SD_HASH_SIZE);
	status = create_acl_blob(psd, &blob, XATTR_SD_HASH_TYPE_SHA256, hash);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	return hash_blob_sha256(blob, hash);
}

/*******************************************************************
 Parse out a struct security_descriptor from a DATA_BLOB.
*******************************************************************/

static NTSTATUS parse_acl_blob(const DATA_BLOB *pblob,
			       TALLOC_CTX *mem_ctx,
			       struct security_descriptor **ppdesc,
			       uint16_t *p_hash_type,
			       uint16_t *p_version,
			       uint8_t hash[XATTR_SD_HASH_SIZE],
			       uint8_t sys_acl_hash[XATTR_SD_HASH_SIZE])
{
	struct xattr_NTACL xacl;
	enum ndr_err_code ndr_err;
	size_t sd_size;
	TALLOC_CTX *frame = talloc_stackframe();

	ndr_err = ndr_pull_struct_blob(pblob, frame, &xacl,
			(ndr_pull_flags_fn_t)ndr_pull_xattr_NTACL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("parse_acl_blob: ndr_pull_xattr_NTACL failed: %s\n",
			ndr_errstr(ndr_err)));
		TALLOC_FREE(frame);
		return ndr_map_error2ntstatus(ndr_err);
	}

	*p_version = xacl.version;

	switch (xacl.version) {
		case 1:
			*ppdesc = make_sec_desc(mem_ctx, SD_REVISION,
					xacl.info.sd->type | SEC_DESC_SELF_RELATIVE,
					xacl.info.sd->owner_sid,
					xacl.info.sd->group_sid,
					xacl.info.sd->sacl,
					xacl.info.sd->dacl,
					&sd_size);
			/* No hash - null out. */
			*p_hash_type = XATTR_SD_HASH_TYPE_NONE;
			memset(hash, '\0', XATTR_SD_HASH_SIZE);
			break;
		case 2:
			*ppdesc = make_sec_desc(mem_ctx, SD_REVISION,
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
			*ppdesc = make_sec_desc(mem_ctx, SD_REVISION,
					xacl.info.sd_hs3->sd->type | SEC_DESC_SELF_RELATIVE,
					xacl.info.sd_hs3->sd->owner_sid,
					xacl.info.sd_hs3->sd->group_sid,
					xacl.info.sd_hs3->sd->sacl,
					xacl.info.sd_hs3->sd->dacl,
					&sd_size);
			*p_hash_type = xacl.info.sd_hs3->hash_type;
			/* Current version 3 (if no sys acl hash available). */
			memcpy(hash, xacl.info.sd_hs3->hash, XATTR_SD_HASH_SIZE);
			break;
		case 4:
			*ppdesc = make_sec_desc(mem_ctx, SD_REVISION,
					xacl.info.sd_hs4->sd->type | SEC_DESC_SELF_RELATIVE,
					xacl.info.sd_hs4->sd->owner_sid,
					xacl.info.sd_hs4->sd->group_sid,
					xacl.info.sd_hs4->sd->sacl,
					xacl.info.sd_hs4->sd->dacl,
					&sd_size);
			*p_hash_type = xacl.info.sd_hs4->hash_type;
			/* Current version 4. */
			memcpy(hash, xacl.info.sd_hs4->hash, XATTR_SD_HASH_SIZE);
			memcpy(sys_acl_hash, xacl.info.sd_hs4->sys_acl_hash, XATTR_SD_HASH_SIZE);
			break;
		default:
			TALLOC_FREE(frame);
			return NT_STATUS_REVISION_MISMATCH;
	}

	TALLOC_FREE(frame);

	return (*ppdesc != NULL) ? NT_STATUS_OK : NT_STATUS_NO_MEMORY;
}

/*******************************************************************
 Create a DATA_BLOB from a hash of the security descriptor storead at
 the system layer and the NT ACL we wish to preserve
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
	xacl.info.sd_hs3->sd = discard_const_p(struct security_descriptor, psd);
	xacl.info.sd_hs3->hash_type = hash_type;
	memcpy(&xacl.info.sd_hs3->hash[0], hash, XATTR_SD_HASH_SIZE);

	ndr_err = ndr_push_struct_blob(
			pblob, ctx, &xacl,
			(ndr_push_flags_fn_t)ndr_push_xattr_NTACL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("create_acl_blob: ndr_push_xattr_NTACL failed: %s\n",
			ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Create a DATA_BLOB from a hash of the security descriptors 
 (system and NT) stored at the system layer and the NT ACL we wish 
 to preserve.
*******************************************************************/

static NTSTATUS create_sys_acl_blob(const struct security_descriptor *psd,
				    DATA_BLOB *pblob,
				    uint16_t hash_type,
				    uint8_t hash[XATTR_SD_HASH_SIZE],
				    const char *description,
				    uint8_t sys_acl_hash[XATTR_SD_HASH_SIZE])
{
	struct xattr_NTACL xacl;
	struct security_descriptor_hash_v4 sd_hs4;
	enum ndr_err_code ndr_err;
	TALLOC_CTX *ctx = talloc_tos();
	NTTIME nttime_now;
	struct timeval now = timeval_current();
	nttime_now = timeval_to_nttime(&now);

	ZERO_STRUCT(xacl);
	ZERO_STRUCT(sd_hs4);

	xacl.version = 4;
	xacl.info.sd_hs4 = &sd_hs4;
	xacl.info.sd_hs4->sd = discard_const_p(struct security_descriptor, psd);
	xacl.info.sd_hs4->hash_type = hash_type;
	memcpy(&xacl.info.sd_hs4->hash[0], hash, XATTR_SD_HASH_SIZE);
	xacl.info.sd_hs4->description = description;
	xacl.info.sd_hs4->time = nttime_now;
	memcpy(&xacl.info.sd_hs4->sys_acl_hash[0], sys_acl_hash, XATTR_SD_HASH_SIZE);

	ndr_err = ndr_push_struct_blob(
			pblob, ctx, &xacl,
			(ndr_push_flags_fn_t)ndr_push_xattr_NTACL);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(5, ("create_acl_blob: ndr_push_xattr_NTACL failed: %s\n",
			ndr_errstr(ndr_err)));
		return ndr_map_error2ntstatus(ndr_err);
	}

	return NT_STATUS_OK;
}

/*******************************************************************
 Add in 3 inheritable components for a non-inheritable directory ACL.
 CREATOR_OWNER/CREATOR_GROUP/WORLD.
*******************************************************************/

static NTSTATUS add_directory_inheritable_components(vfs_handle_struct *handle,
                                const char *name,
				SMB_STRUCT_STAT *psbuf,
				struct security_descriptor *psd)
{
	struct connection_struct *conn = handle->conn;
	int num_aces = (psd->dacl ? psd->dacl->num_aces : 0);
	struct smb_filename smb_fname;
	enum security_ace_type acltype;
	uint32_t access_mask;
	mode_t dir_mode;
	mode_t file_mode;
	mode_t mode;
	struct security_ace *new_ace_list;

	if (psd->dacl) {
		new_ace_list = talloc_zero_array(psd->dacl,
						 struct security_ace,
						 num_aces + 3);
	} else {
		/*
		 * make_sec_acl() at the bottom of this function
		 * dupliates new_ace_list
		 */
		new_ace_list = talloc_zero_array(talloc_tos(),
						 struct security_ace,
						 num_aces + 3);
	}

	if (new_ace_list == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* Fake a quick smb_filename. */
	ZERO_STRUCT(smb_fname);
	smb_fname.st = *psbuf;
	smb_fname.base_name = discard_const_p(char, name);

	dir_mode = unix_mode(conn,
			FILE_ATTRIBUTE_DIRECTORY, &smb_fname, NULL);
	file_mode = unix_mode(conn,
			FILE_ATTRIBUTE_ARCHIVE, &smb_fname, NULL);

	mode = dir_mode | file_mode;

	DEBUG(10, ("add_directory_inheritable_components: directory %s, "
		"mode = 0%o\n",
		name,
		(unsigned int)mode ));

	if (num_aces) {
		memcpy(new_ace_list, psd->dacl->aces,
			num_aces * sizeof(struct security_ace));
	}
	access_mask = map_canon_ace_perms(SNUM(conn), &acltype,
				mode & 0700, false);

	init_sec_ace(&new_ace_list[num_aces],
			&global_sid_Creator_Owner,
			acltype,
			access_mask,
			SEC_ACE_FLAG_CONTAINER_INHERIT|
				SEC_ACE_FLAG_OBJECT_INHERIT|
				SEC_ACE_FLAG_INHERIT_ONLY);
	access_mask = map_canon_ace_perms(SNUM(conn), &acltype,
				(mode << 3) & 0700, false);
	init_sec_ace(&new_ace_list[num_aces+1],
			&global_sid_Creator_Group,
			acltype,
			access_mask,
			SEC_ACE_FLAG_CONTAINER_INHERIT|
				SEC_ACE_FLAG_OBJECT_INHERIT|
				SEC_ACE_FLAG_INHERIT_ONLY);
	access_mask = map_canon_ace_perms(SNUM(conn), &acltype,
				(mode << 6) & 0700, false);
	init_sec_ace(&new_ace_list[num_aces+2],
			&global_sid_World,
			acltype,
			access_mask,
			SEC_ACE_FLAG_CONTAINER_INHERIT|
				SEC_ACE_FLAG_OBJECT_INHERIT|
				SEC_ACE_FLAG_INHERIT_ONLY);
	if (psd->dacl) {
		psd->dacl->aces = new_ace_list;
		psd->dacl->num_aces += 3;
		psd->dacl->size += new_ace_list[num_aces].size +
			new_ace_list[num_aces+1].size +
			new_ace_list[num_aces+2].size;
	} else {
		psd->dacl = make_sec_acl(psd,
				NT4_ACL_REVISION,
				3,
				new_ace_list);
		if (psd->dacl == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
	}
	return NT_STATUS_OK;
}

/*******************************************************************
 Pull a DATA_BLOB from an xattr given a pathname.
 If the hash doesn't match, or doesn't exist - return the underlying
 filesystem sd.
*******************************************************************/

static NTSTATUS get_nt_acl_internal(vfs_handle_struct *handle,
				    files_struct *fsp,
				    const char *name,
				    uint32_t security_info,
				    TALLOC_CTX *mem_ctx,
				    struct security_descriptor **ppdesc)
{
	DATA_BLOB blob = data_blob_null;
	NTSTATUS status;
	uint16_t hash_type = XATTR_SD_HASH_TYPE_NONE;
	uint16_t xattr_version = 0;
	uint8_t hash[XATTR_SD_HASH_SIZE];
	uint8_t sys_acl_hash[XATTR_SD_HASH_SIZE];
	uint8_t hash_tmp[XATTR_SD_HASH_SIZE];
	uint8_t sys_acl_hash_tmp[XATTR_SD_HASH_SIZE];
	struct security_descriptor *psd = NULL;
	struct security_descriptor *pdesc_next = NULL;
	bool ignore_file_system_acl = lp_parm_bool(SNUM(handle->conn),
						ACL_MODULE_NAME,
						"ignore system acls",
						false);
	TALLOC_CTX *frame = talloc_stackframe();

	if (fsp && name == NULL) {
		name = fsp->fsp_name->base_name;
	}

	DEBUG(10, ("get_nt_acl_internal: name=%s\n", name));

	status = get_acl_blob(frame, handle, fsp, name, &blob);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("get_nt_acl_internal: get_acl_blob returned %s\n",
			nt_errstr(status)));
		psd = NULL;
		goto out;
	} else {
		status = parse_acl_blob(&blob, mem_ctx, &psd,
					&hash_type, &xattr_version, &hash[0], &sys_acl_hash[0]);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("parse_acl_blob returned %s\n",
				   nt_errstr(status)));
			psd = NULL;
			goto out;
		}
	}

	/* Ensure we don't leak psd if we don't choose it.
	 *
	 * We don't allocate it onto frame as it is preferred not to
	 * steal from a talloc pool.
	 */
	talloc_steal(frame, psd);

	/* determine which type of xattr we got */
	switch (xattr_version) {
	case 1:
	case 2:
		/* These xattr types are unilatteral, they do not
		 * require confirmation of the hash.  In particular,
		 * the NTVFS file server uses version 1, but
		 * 'samba-tool ntacl' can set these as well */
		goto out;
	case 3:
	case 4:
		if (ignore_file_system_acl) {
			goto out;
		}

		break;
	default:
		DEBUG(10, ("get_nt_acl_internal: ACL blob revision "
			   "mismatch (%u) for file %s\n",
			   (unsigned int)hash_type,
			   name));
		TALLOC_FREE(psd);
		psd = NULL;
		goto out;
	}

	/* determine which type of xattr we got */
	if (hash_type != XATTR_SD_HASH_TYPE_SHA256) {
		DEBUG(10, ("get_nt_acl_internal: ACL blob hash type "
			   "(%u) unexpected for file %s\n",
			   (unsigned int)hash_type,
			   name));
		TALLOC_FREE(psd);
		psd = NULL;
		goto out;
	}

	/* determine which type of xattr we got */
	switch (xattr_version) {
	case 4:
	{
		int ret;
		char *sys_acl_blob_description;
		DATA_BLOB sys_acl_blob;
		if (fsp) {
			/* Get the full underlying sd, then hash. */
			ret = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle,
							       fsp,
							       frame,
							       &sys_acl_blob_description,
							       &sys_acl_blob);
		} else {
			/* Get the full underlying sd, then hash. */
			ret = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle,
								 name,
								 frame,
								 &sys_acl_blob_description,
								 &sys_acl_blob);
		}

		/* If we fail to get the ACL blob (for some reason) then this
		 * is not fatal, we just work based on the NT ACL only */
		if (ret == 0) {
			status = hash_blob_sha256(sys_acl_blob, sys_acl_hash_tmp);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(frame);
				return status;
			}

			if (memcmp(&sys_acl_hash[0], &sys_acl_hash_tmp[0], 
				   XATTR_SD_HASH_SIZE) == 0) {
				/* Hash matches, return blob sd. */
				DEBUG(10, ("get_nt_acl_internal: blob hash "
					   "matches for file %s\n",
					   name ));
				goto out;
			}
		}

		/* Otherwise, fall though and see if the NT ACL hash matches */
	}
	case 3:
		/* Get the full underlying sd for the hash
		   or to return as backup. */
		if (fsp) {
			status = SMB_VFS_NEXT_FGET_NT_ACL(handle,
							  fsp,
							  HASH_SECURITY_INFO,
							  mem_ctx,
							  &pdesc_next);
		} else {
			status = SMB_VFS_NEXT_GET_NT_ACL(handle,
							 name,
							 HASH_SECURITY_INFO,
							 mem_ctx,
							 &pdesc_next);
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("get_nt_acl_internal: get_next_acl for file %s "
				   "returned %s\n",
				   name,
				   nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}

		/* Ensure we don't leak psd_next if we don't choose it.
		 *
		 * We don't allocate it onto frame as it is preferred not to
		 * steal from a talloc pool.
		 */
		talloc_steal(frame, pdesc_next);

		status = hash_sd_sha256(pdesc_next, hash_tmp);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(psd);
			psd = pdesc_next;
			goto out;
		}

		if (memcmp(&hash[0], &hash_tmp[0], XATTR_SD_HASH_SIZE) == 0) {
			/* Hash matches, return blob sd. */
			DEBUG(10, ("get_nt_acl_internal: blob hash "
				   "matches for file %s\n",
				   name ));
			goto out;
		}

		/* Hash doesn't match, return underlying sd. */
		DEBUG(10, ("get_nt_acl_internal: blob hash "
			   "does not match for file %s - returning "
			   "file system SD mapping.\n",
			   name ));

		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("get_nt_acl_internal: acl for blob hash for %s is:\n",
				  name ));
			NDR_PRINT_DEBUG(security_descriptor, pdesc_next);
		}

		TALLOC_FREE(psd);
		psd = pdesc_next;
	}
  out:

	if (psd == NULL) {
		/* Get the full underlying sd, as we failed to get the
		 * blob for the hash, or the revision/hash type wasn't
		 * known */
		if (fsp) {
			status = SMB_VFS_NEXT_FGET_NT_ACL(handle,
							  fsp,
							  security_info,
							  mem_ctx,
							  &pdesc_next);
		} else {
			status = SMB_VFS_NEXT_GET_NT_ACL(handle,
							 name,
							 security_info,
							 mem_ctx,
							 &pdesc_next);
		}

		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("get_nt_acl_internal: get_next_acl for file %s "
				   "returned %s\n",
				   name,
				   nt_errstr(status)));
			TALLOC_FREE(frame);
			return status;
		}

		/* Ensure we don't leak psd_next if we don't choose it.
		 *
		 * We don't allocate it onto frame as it is preferred not to
		 * steal from a talloc pool.
		 */
		talloc_steal(frame, pdesc_next);
		psd = pdesc_next;
	}

	if (psd != pdesc_next) {
		/* We're returning the blob, throw
 		 * away the filesystem SD. */
		TALLOC_FREE(pdesc_next);
	} else {
		SMB_STRUCT_STAT sbuf;
		SMB_STRUCT_STAT *psbuf = &sbuf;
		bool is_directory = false;
		/*
		 * We're returning the underlying ACL from the
		 * filesystem. If it's a directory, and has no
		 * inheritable ACE entries we have to fake them.
		 */
		if (fsp) {
			status = vfs_stat_fsp(fsp);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(frame);
				return status;
			}
			psbuf = &fsp->fsp_name->st;
		} else {
			/*
			 * https://bugzilla.samba.org/show_bug.cgi?id=11249
			 *
			 * We are currently guaranteed that 'name' here is
			 * a smb_fname->base_name, which *cannot* contain
			 * a stream name (':'). vfs_stat_smb_fname() splits
			 * a name into a base name + stream name, which
			 * when we get here we know we've already done.
			 * So we have to call the stat or lstat VFS
			 * calls directly here. Else, a base_name that
			 * contains a ':' (from a demangled name) will
			 * get split again.
			 *
			 * FIXME.
			 * This uglyness will go away once smb_fname
			 * is fully plumbed through the VFS.
			 */
			int ret = vfs_stat_smb_basename(handle->conn,
						name,
						&sbuf);
			if (ret == -1) {
				TALLOC_FREE(frame);
				return map_nt_error_from_unix(errno);
			}
		}
		is_directory = S_ISDIR(psbuf->st_ex_mode);

		if (ignore_file_system_acl) {
			TALLOC_FREE(pdesc_next);
			status = make_default_filesystem_acl(mem_ctx,
						name,
						psbuf,
						&psd);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(frame);
				return status;
			}
		} else {
			if (is_directory &&
				!sd_has_inheritable_components(psd,
							true)) {
				status = add_directory_inheritable_components(
							handle,
							name,
							psbuf,
							psd);
				if (!NT_STATUS_IS_OK(status)) {
					TALLOC_FREE(frame);
					return status;
				}
			}
			/* The underlying POSIX module always sets
			   the ~SEC_DESC_DACL_PROTECTED bit, as ACLs
			   can't be inherited in this way under POSIX.
			   Remove it for Windows-style ACLs. */
			psd->type &= ~SEC_DESC_DACL_PROTECTED;
		}
	}

	if (!(security_info & SECINFO_OWNER)) {
		psd->owner_sid = NULL;
	}
	if (!(security_info & SECINFO_GROUP)) {
		psd->group_sid = NULL;
	}
	if (!(security_info & SECINFO_DACL)) {
		psd->type &= ~SEC_DESC_DACL_PRESENT;
		psd->dacl = NULL;
	}
	if (!(security_info & SECINFO_SACL)) {
		psd->type &= ~SEC_DESC_SACL_PRESENT;
		psd->sacl = NULL;
	}

	TALLOC_FREE(blob.data);

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("get_nt_acl_internal: returning acl for %s is:\n",
			name ));
		NDR_PRINT_DEBUG(security_descriptor, psd);
	}

	/* The VFS API is that the ACL is expected to be on mem_ctx */
	*ppdesc = talloc_move(mem_ctx, &psd);

	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

/*********************************************************************
 Fetch a security descriptor given an fsp.
*********************************************************************/

static NTSTATUS fget_nt_acl_common(vfs_handle_struct *handle,
				   files_struct *fsp,
				   uint32_t security_info,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **ppdesc)
{
	return get_nt_acl_internal(handle, fsp,
				   NULL, security_info, mem_ctx, ppdesc);
}

/*********************************************************************
 Fetch a security descriptor given a pathname.
*********************************************************************/

static NTSTATUS get_nt_acl_common(vfs_handle_struct *handle,
				  const char *name,
				  uint32_t security_info,
				  TALLOC_CTX *mem_ctx,
				  struct security_descriptor **ppdesc)
{
	return get_nt_acl_internal(handle, NULL,
				   name, security_info, mem_ctx, ppdesc);
}

/*********************************************************************
 Store a security descriptor given an fsp.
*********************************************************************/

static NTSTATUS fset_nt_acl_common(vfs_handle_struct *handle, files_struct *fsp,
        uint32_t security_info_sent, const struct security_descriptor *orig_psd)
{
	NTSTATUS status;
	int ret;
	DATA_BLOB blob, sys_acl_blob;
	struct security_descriptor *pdesc_next = NULL;
	struct security_descriptor *psd = NULL;
	uint8_t hash[XATTR_SD_HASH_SIZE];
	uint8_t sys_acl_hash[XATTR_SD_HASH_SIZE];
	bool chown_needed = false;
	char *sys_acl_description;
	TALLOC_CTX *frame = talloc_stackframe();

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("fset_nt_acl_xattr: incoming sd for file %s\n",
			  fsp_str_dbg(fsp)));
		NDR_PRINT_DEBUG(security_descriptor,
			discard_const_p(struct security_descriptor, orig_psd));
	}

	status = get_nt_acl_internal(handle, fsp,
			NULL,
			SECINFO_OWNER|SECINFO_GROUP|SECINFO_DACL|SECINFO_SACL,
				     frame,
			&psd);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	psd->revision = orig_psd->revision;
	/* All our SD's are self relative. */
	psd->type = orig_psd->type | SEC_DESC_SELF_RELATIVE;

	if ((security_info_sent & SECINFO_OWNER) && (orig_psd->owner_sid != NULL)) {
		if (!dom_sid_equal(orig_psd->owner_sid, psd->owner_sid)) {
			/* We're changing the owner. */
			chown_needed = true;
		}
		psd->owner_sid = orig_psd->owner_sid;
	}
	if ((security_info_sent & SECINFO_GROUP) && (orig_psd->group_sid != NULL)) {
		if (!dom_sid_equal(orig_psd->group_sid, psd->group_sid)) {
			/* We're changing the group. */
			chown_needed = true;
		}
		psd->group_sid = orig_psd->group_sid;
	}
	if (security_info_sent & SECINFO_DACL) {
		if (security_descriptor_with_ms_nfs(orig_psd)) {
			/*
			 * If the sd contains a MS NFS SID, do
			 * nothing, it's a chmod() request from OS X
			 * with AAPL context.
			 */
			TALLOC_FREE(frame);
			return NT_STATUS_OK;
		}
		psd->dacl = orig_psd->dacl;
		psd->type |= SEC_DESC_DACL_PRESENT;
	}
	if (security_info_sent & SECINFO_SACL) {
		psd->sacl = orig_psd->sacl;
		psd->type |= SEC_DESC_SACL_PRESENT;
	}

	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	if (!NT_STATUS_IS_OK(status)) {
		if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			TALLOC_FREE(frame);
			return status;
		}
		/* We got access denied here. If we're already root,
		   or we didn't need to do a chown, or the fsp isn't
		   open with WRITE_OWNER access, just return. */
		if (get_current_uid(handle->conn) == 0 ||
				chown_needed == false ||
				!(fsp->access_mask & SEC_STD_WRITE_OWNER)) {
			TALLOC_FREE(frame);
			return NT_STATUS_ACCESS_DENIED;
		}

		DEBUG(10,("fset_nt_acl_common: overriding chown on file %s "
			"for sid %s\n",
			fsp_str_dbg(fsp),
			sid_string_tos(psd->owner_sid)
			));

		/* Ok, we failed to chown and we have
		   SEC_STD_WRITE_OWNER access - override. */
		become_root();
		status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp,
				security_info_sent, psd);
		unbecome_root();
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(frame);
			return status;
		}
	}

	/* Get the full underlying sd, then hash. */
	status = SMB_VFS_NEXT_FGET_NT_ACL(handle,
					  fsp,
					  HASH_SECURITY_INFO,
					  frame,
					  &pdesc_next);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	status = hash_sd_sha256(pdesc_next, hash);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	/* Get the full underlying sd, then hash. */
	ret = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle,
					       fsp,
					       frame,
					       &sys_acl_description,
					       &sys_acl_blob);

	/* If we fail to get the ACL blob (for some reason) then this
	 * is not fatal, we just work based on the NT ACL only */
	if (ret != 0) {
		if (DEBUGLEVEL >= 10) {
			DEBUG(10,("fset_nt_acl_xattr: storing xattr sd for file %s\n",
				  fsp_str_dbg(fsp)));
			NDR_PRINT_DEBUG(security_descriptor,
					discard_const_p(struct security_descriptor, psd));

			DEBUG(10,("fset_nt_acl_xattr: storing has in xattr sd based on \n"));
			NDR_PRINT_DEBUG(security_descriptor,
					discard_const_p(struct security_descriptor, pdesc_next));
		}
		status = create_acl_blob(psd, &blob, XATTR_SD_HASH_TYPE_SHA256, hash);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("fset_nt_acl_xattr: create_acl_blob failed\n"));
			TALLOC_FREE(frame);
			return status;
		}

		status = store_acl_blob_fsp(handle, fsp, &blob);

		TALLOC_FREE(frame);
		return status;
	}

	status = hash_blob_sha256(sys_acl_blob, sys_acl_hash);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	if (DEBUGLEVEL >= 10) {
		DEBUG(10,("fset_nt_acl_xattr: storing xattr sd for file %s based on system ACL\n",
			  fsp_str_dbg(fsp)));
		NDR_PRINT_DEBUG(security_descriptor,
				discard_const_p(struct security_descriptor, psd));

		DEBUG(10,("fset_nt_acl_xattr: storing hash in xattr sd based on system ACL and:\n"));
		NDR_PRINT_DEBUG(security_descriptor,
				discard_const_p(struct security_descriptor, pdesc_next));
	}

	/* We store hashes of both the sys ACL blob and the NT
	 * security desciptor mapped from that ACL so as to improve
	 * our chances against some inadvertant change breaking the
	 * hash used */
	status = create_sys_acl_blob(psd, &blob, XATTR_SD_HASH_TYPE_SHA256, hash, 
				     sys_acl_description, sys_acl_hash);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10, ("fset_nt_acl_xattr: create_sys_acl_blob failed\n"));
		TALLOC_FREE(frame);
		return status;
	}

	status = store_acl_blob_fsp(handle, fsp, &blob);

	TALLOC_FREE(frame);
	return status;
}

static int acl_common_remove_object(vfs_handle_struct *handle,
					const char *path,
					bool is_directory)
{
	connection_struct *conn = handle->conn;
	struct file_id id;
	files_struct *fsp = NULL;
	int ret = 0;
	char *parent_dir = NULL;
	const char *final_component = NULL;
	struct smb_filename local_fname;
	int saved_errno = 0;
	char *saved_dir = NULL;

	saved_dir = vfs_GetWd(talloc_tos(),conn);
	if (!saved_dir) {
		saved_errno = errno;
		goto out;
	}

	if (!parent_dirname(talloc_tos(), path,
			&parent_dir, &final_component)) {
		saved_errno = ENOMEM;
		goto out;
	}

	DEBUG(10,("acl_common_remove_object: removing %s %s/%s\n",
		is_directory ? "directory" : "file",
		parent_dir, final_component ));

 	/* cd into the parent dir to pin it. */
	ret = vfs_ChDir(conn, parent_dir);
	if (ret == -1) {
		saved_errno = errno;
		goto out;
	}

	ZERO_STRUCT(local_fname);
	local_fname.base_name = discard_const_p(char, final_component);

	/* Must use lstat here. */
	ret = SMB_VFS_LSTAT(conn, &local_fname);
	if (ret == -1) {
		saved_errno = errno;
		goto out;
	}

	/* Ensure we have this file open with DELETE access. */
	id = vfs_file_id_from_sbuf(conn, &local_fname.st);
	for (fsp = file_find_di_first(conn->sconn, id); fsp;
		     fsp = file_find_di_next(fsp)) {
		if (fsp->access_mask & DELETE_ACCESS &&
				fsp->delete_on_close) {
			/* We did open this for delete,
			 * allow the delete as root.
			 */
			break;
		}
	}

	if (!fsp) {
		DEBUG(10,("acl_common_remove_object: %s %s/%s "
			"not an open file\n",
			is_directory ? "directory" : "file",
			parent_dir, final_component ));
		saved_errno = EACCES;
		goto out;
	}

	become_root();
	if (is_directory) {
		ret = SMB_VFS_NEXT_RMDIR(handle, final_component);
	} else {
		ret = SMB_VFS_NEXT_UNLINK(handle, &local_fname);
	}
	unbecome_root();

	if (ret == -1) {
		saved_errno = errno;
	}

  out:

	TALLOC_FREE(parent_dir);

	if (saved_dir) {
		vfs_ChDir(conn, saved_dir);
	}
	if (saved_errno) {
		errno = saved_errno;
	}
	return ret;
}

static int rmdir_acl_common(struct vfs_handle_struct *handle,
				const char *path)
{
	int ret;

	/* Try the normal rmdir first. */
	ret = SMB_VFS_NEXT_RMDIR(handle, path);
	if (ret == 0) {
		return 0;
	}
	if (errno == EACCES || errno == EPERM) {
		/* Failed due to access denied,
		   see if we need to root override. */
		return acl_common_remove_object(handle,
						path,
						true);
	}

	DEBUG(10,("rmdir_acl_common: unlink of %s failed %s\n",
		path,
		strerror(errno) ));
	return -1;
}

static int unlink_acl_common(struct vfs_handle_struct *handle,
			const struct smb_filename *smb_fname)
{
	int ret;

	/* Try the normal unlink first. */
	ret = SMB_VFS_NEXT_UNLINK(handle, smb_fname);
	if (ret == 0) {
		return 0;
	}
	if (errno == EACCES || errno == EPERM) {
		/* Failed due to access denied,
		   see if we need to root override. */

		/* Don't do anything fancy for streams. */
		if (smb_fname->stream_name) {
			return -1;
		}
		return acl_common_remove_object(handle,
					smb_fname->base_name,
					false);
	}

	DEBUG(10,("unlink_acl_common: unlink of %s failed %s\n",
		smb_fname->base_name,
		strerror(errno) ));
	return -1;
}

static int chmod_acl_module_common(struct vfs_handle_struct *handle,
			const char *path, mode_t mode)
{
	if (lp_posix_pathnames()) {
		/* Only allow this on POSIX pathnames. */
		return SMB_VFS_NEXT_CHMOD(handle, path, mode);
	}
	return 0;
}

static int fchmod_acl_module_common(struct vfs_handle_struct *handle,
			struct files_struct *fsp, mode_t mode)
{
	if (fsp->posix_open) {
		/* Only allow this on POSIX opens. */
		return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
	}
	return 0;
}

static int chmod_acl_acl_module_common(struct vfs_handle_struct *handle,
			const char *name, mode_t mode)
{
	if (lp_posix_pathnames()) {
		/* Only allow this on POSIX pathnames. */
		return SMB_VFS_NEXT_CHMOD_ACL(handle, name, mode);
	}
	return 0;
}

static int fchmod_acl_acl_module_common(struct vfs_handle_struct *handle,
			struct files_struct *fsp, mode_t mode)
{
	if (fsp->posix_open) {
		/* Only allow this on POSIX opens. */
		return SMB_VFS_NEXT_FCHMOD_ACL(handle, fsp, mode);
	}
	return 0;
}
