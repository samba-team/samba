/*
 * Store Windows ACLs in data store - common functions.
 * #included into modules/vfs_acl_xattr.c and modules/vfs_acl_tdb.c
 *
 * Copyright (C) Volker Lendecke, 2008
 * Copyright (C) Jeremy Allison, 2009
 * Copyright (C) Ralph Böhme, 2016
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

#include "includes.h"
#include "vfs_acl_common.h"
#include "smbd/smbd.h"
#include "system/filesys.h"
#include "librpc/gen_ndr/ndr_xattr.h"
#include "../libcli/security/security.h"
#include "../librpc/gen_ndr/ndr_security.h"
#include "../lib/util/bitmap.h"
#include "passdb/lookup_sid.h"

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

static NTSTATUS create_acl_blob(const struct security_descriptor *psd,
			DATA_BLOB *pblob,
			uint16_t hash_type,
			uint8_t hash[XATTR_SD_HASH_SIZE]);

#define HASH_SECURITY_INFO (SECINFO_OWNER | \
				SECINFO_GROUP | \
				SECINFO_DACL | \
				SECINFO_SACL)

bool init_acl_common_config(vfs_handle_struct *handle,
			    const char *module_name)
{
	struct acl_common_config *config = NULL;
	const struct enum_list *default_acl_style_list = NULL;

	default_acl_style_list = get_default_acl_style_list();

	config = talloc_zero(handle->conn, struct acl_common_config);
	if (config == NULL) {
		DBG_ERR("talloc_zero() failed\n");
		errno = ENOMEM;
		return false;
	}

	config->ignore_system_acls = lp_parm_bool(SNUM(handle->conn),
						  module_name,
						  "ignore system acls",
						  false);
	config->default_acl_style = lp_parm_enum(SNUM(handle->conn),
						 module_name,
						 "default acl style",
						 default_acl_style_list,
						 DEFAULT_ACL_POSIX);

	SMB_VFS_HANDLE_SET_DATA(handle, config, NULL,
				struct acl_common_config,
				return false);

	return true;
}


/*******************************************************************
 Hash a security descriptor.
*******************************************************************/

static NTSTATUS hash_blob_sha256(DATA_BLOB blob,
				 uint8_t *hash)
{
	int rc;

	ZERO_ARRAY_LEN(hash, XATTR_SD_HASH_SIZE);

	rc = gnutls_hash_fast(GNUTLS_DIG_SHA256,
			      blob.data,
			      blob.length,
			      hash);
	if (rc < 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

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
		DBG_INFO("ndr_pull_xattr_NTACL failed: %s\n",
			 ndr_errstr(ndr_err));
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
		DBG_INFO("ndr_push_xattr_NTACL failed: %s\n",
			 ndr_errstr(ndr_err));
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
		DBG_INFO("ndr_push_xattr_NTACL failed: %s\n",
			 ndr_errstr(ndr_err));
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

	DBG_DEBUG("directory %s, mode = 0%o\n", name, (unsigned int)mode);

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

/**
 * Validate an ACL blob
 *
 * This validates an ACL blob against the underlying filesystem ACL. If this
 * function returns NT_STATUS_OK ppsd can be
 *
 * 1. the ACL from the blob (psd_from_fs=false), or
 * 2. the ACL from the fs (psd_from_fs=true), or
 * 3. NULL (!)
 *
 * If the return value is anything else then NT_STATUS_OK, ppsd is set to NULL
 * and psd_from_fs set to false.
 *
 * Returning the underlying filesystem ACL in case no. 2 is really just an
 * optimisation, because some validations have to fetch the filesytem ACL as
 * part of the validation, so we already have it available and callers might
 * need it as well.
 **/
static NTSTATUS validate_nt_acl_blob(TALLOC_CTX *mem_ctx,
				vfs_handle_struct *handle,
				struct files_struct *fsp,
				struct files_struct *dirfsp,
				const struct smb_filename *smb_fname,
				const DATA_BLOB *blob,
				struct security_descriptor **ppsd,
				bool *psd_is_from_fs)
{
	NTSTATUS status;
	uint16_t hash_type = XATTR_SD_HASH_TYPE_NONE;
	uint16_t xattr_version = 0;
	uint8_t hash[XATTR_SD_HASH_SIZE];
	uint8_t sys_acl_hash[XATTR_SD_HASH_SIZE];
	uint8_t hash_tmp[XATTR_SD_HASH_SIZE];
	uint8_t sys_acl_hash_tmp[XATTR_SD_HASH_SIZE];
	struct security_descriptor *psd = NULL;
	struct security_descriptor *psd_blob = NULL;
	struct security_descriptor *psd_fs = NULL;
	char *sys_acl_blob_description = NULL;
	DATA_BLOB sys_acl_blob = { 0 };
	struct acl_common_config *config = NULL;

	*ppsd = NULL;
	*psd_is_from_fs = false;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct acl_common_config,
				return NT_STATUS_UNSUCCESSFUL);

	status = parse_acl_blob(blob,
				mem_ctx,
				&psd_blob,
				&hash_type,
				&xattr_version,
				&hash[0],
				&sys_acl_hash[0]);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("parse_acl_blob returned %s\n", nt_errstr(status));
		goto fail;
	}

	/* determine which type of xattr we got */
	switch (xattr_version) {
	case 1:
	case 2:
		/* These xattr types are unilatteral, they do not
		 * require confirmation of the hash.  In particular,
		 * the NTVFS file server uses version 1, but
		 * 'samba-tool ntacl' can set these as well */
		*ppsd = psd_blob;
		return NT_STATUS_OK;
	case 3:
	case 4:
		if (config->ignore_system_acls) {
			*ppsd = psd_blob;
			return NT_STATUS_OK;
		}

		break;
	default:
		DBG_DEBUG("ACL blob revision mismatch (%u) for file %s\n",
			  (unsigned int)hash_type, smb_fname->base_name);
		TALLOC_FREE(psd_blob);
		return NT_STATUS_OK;
	}

	/* determine which type of xattr we got */
	if (hash_type != XATTR_SD_HASH_TYPE_SHA256) {
		DBG_DEBUG("ACL blob hash type (%u) unexpected for file %s\n",
			  (unsigned int)hash_type, smb_fname->base_name);
		TALLOC_FREE(psd_blob);
		return NT_STATUS_OK;
	}

	/* determine which type of xattr we got */
	switch (xattr_version) {
	case 4:
	{
		int ret;
		if (fsp) {
			/* Get the full underlying sd, then hash. */
			ret = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FD(handle,
							       fsp,
							       mem_ctx,
							       &sys_acl_blob_description,
							       &sys_acl_blob);
		} else {
			/* Get the full underlying sd, then hash. */
			ret = SMB_VFS_NEXT_SYS_ACL_BLOB_GET_FILE(handle,
						 smb_fname,
						 mem_ctx,
						 &sys_acl_blob_description,
						 &sys_acl_blob);
		}

		/* If we fail to get the ACL blob (for some reason) then this
		 * is not fatal, we just work based on the NT ACL only */
		if (ret == 0) {
			status = hash_blob_sha256(sys_acl_blob, sys_acl_hash_tmp);
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}

			TALLOC_FREE(sys_acl_blob_description);
			TALLOC_FREE(sys_acl_blob.data);

			if (memcmp(&sys_acl_hash[0], &sys_acl_hash_tmp[0], 
				   XATTR_SD_HASH_SIZE) == 0) {
				/* Hash matches, return blob sd. */
				DBG_DEBUG("blob hash matches for file %s\n",
					  smb_fname->base_name);
				*ppsd = psd_blob;
				return NT_STATUS_OK;
			}
		}

		/* Otherwise, fall though and see if the NT ACL hash matches */
		FALL_THROUGH;
	}
	case 3:
		/* Get the full underlying sd for the hash
		   or to return as backup. */
		if (fsp) {
			status = SMB_VFS_NEXT_FGET_NT_ACL(handle,
							  fsp,
							  HASH_SECURITY_INFO,
							  mem_ctx,
							  &psd_fs);
		} else {
			status = SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
							dirfsp,
							smb_fname,
							HASH_SECURITY_INFO,
							mem_ctx,
							&psd_fs);
		}

		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("get_next_acl for file %s returned %s\n",
				  smb_fname->base_name, nt_errstr(status));
			goto fail;
		}

		status = hash_sd_sha256(psd_fs, hash_tmp);
		if (!NT_STATUS_IS_OK(status)) {
			TALLOC_FREE(psd_blob);
			*ppsd = psd_fs;
			*psd_is_from_fs = true;
			return NT_STATUS_OK;
		}

		if (memcmp(&hash[0], &hash_tmp[0], XATTR_SD_HASH_SIZE) == 0) {
			/* Hash matches, return blob sd. */
			DBG_DEBUG("blob hash matches for file %s\n",
				  smb_fname->base_name);
			*ppsd = psd_blob;
			return NT_STATUS_OK;
		}

		/* Hash doesn't match, return underlying sd. */
		DBG_DEBUG("blob hash does not match for file %s - returning "
			  "file system SD mapping.\n",
			  smb_fname->base_name);

		if (DEBUGLEVEL >= 10) {
			DBG_DEBUG("acl for blob hash for %s is:\n",
				  smb_fname->base_name);
			NDR_PRINT_DEBUG(security_descriptor, psd_fs);
		}

		TALLOC_FREE(psd_blob);
		*ppsd = psd_fs;
		*psd_is_from_fs = true;
	}

	return NT_STATUS_OK;

fail:
	TALLOC_FREE(psd);
	TALLOC_FREE(psd_blob);
	TALLOC_FREE(psd_fs);
	TALLOC_FREE(sys_acl_blob_description);
	TALLOC_FREE(sys_acl_blob.data);
	return status;
}

/*******************************************************************
 Pull a DATA_BLOB from an xattr given an fsp.
 If the hash doesn't match, or doesn't exist - return the underlying
 filesystem sd.
*******************************************************************/

NTSTATUS fget_nt_acl_common(
	NTSTATUS (*fget_acl_blob_fn)(TALLOC_CTX *ctx,
				    vfs_handle_struct *handle,
				    files_struct *fsp,
				    DATA_BLOB *pblob),
	vfs_handle_struct *handle,
	files_struct *fsp,
	uint32_t security_info,
	TALLOC_CTX *mem_ctx,
	struct security_descriptor **ppdesc)
{
	DATA_BLOB blob = data_blob_null;
	NTSTATUS status;
	struct security_descriptor *psd = NULL;
	const struct smb_filename *smb_fname = fsp->fsp_name;
	bool psd_is_from_fs = false;
	struct acl_common_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct acl_common_config,
				return NT_STATUS_UNSUCCESSFUL);

	DBG_DEBUG("name=%s\n", smb_fname->base_name);

	status = fget_acl_blob_fn(mem_ctx, handle, fsp, &blob);
	if (NT_STATUS_IS_OK(status)) {
		status = validate_nt_acl_blob(mem_ctx,
					handle,
					fsp,
					NULL,
					smb_fname,
					&blob,
					&psd,
					&psd_is_from_fs);
		TALLOC_FREE(blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("ACL validation for [%s] failed\n",
				  smb_fname->base_name);
			goto fail;
		}
	}

	if (psd == NULL) {
		/* Get the full underlying sd, as we failed to get the
		 * blob for the hash, or the revision/hash type wasn't
		 * known */

		if (config->ignore_system_acls) {
			status = vfs_stat_fsp(fsp);
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}

			status = make_default_filesystem_acl(
				mem_ctx,
				config->default_acl_style,
				smb_fname->base_name,
				&fsp->fsp_name->st,
				&psd);
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}
		} else {
			status = SMB_VFS_NEXT_FGET_NT_ACL(handle,
							  fsp,
							  security_info,
							  mem_ctx,
							  &psd);

			if (!NT_STATUS_IS_OK(status)) {
				DBG_DEBUG("get_next_acl for file %s "
					  "returned %s\n",
					  smb_fname->base_name,
					  nt_errstr(status));
				goto fail;
			}

			psd_is_from_fs = true;
		}
	}

	if (psd_is_from_fs) {
		status = vfs_stat_fsp(fsp);
		if (!NT_STATUS_IS_OK(status)) {
			goto fail;
		}

		/*
		 * We're returning the underlying ACL from the
		 * filesystem. If it's a directory, and has no
		 * inheritable ACE entries we have to fake them.
		 */

		if (fsp->fsp_flags.is_directory &&
				!sd_has_inheritable_components(psd, true)) {
			status = add_directory_inheritable_components(
				handle,
				smb_fname->base_name,
				&fsp->fsp_name->st,
				psd);
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}
		}

		/*
		 * The underlying POSIX module always sets the
		 * ~SEC_DESC_DACL_PROTECTED bit, as ACLs can't be inherited in
		 * this way under POSIX. Remove it for Windows-style ACLs.
		 */
		psd->type &= ~SEC_DESC_DACL_PROTECTED;
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

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("returning acl for %s is:\n",
			  smb_fname->base_name);
		NDR_PRINT_DEBUG(security_descriptor, psd);
	}

	*ppdesc = psd;

	return NT_STATUS_OK;

fail:
	TALLOC_FREE(psd);
	return status;
}

/*******************************************************************
 Pull a DATA_BLOB from an xattr given a pathname.
 If the hash doesn't match, or doesn't exist - return the underlying
 filesystem sd.
*******************************************************************/

NTSTATUS get_nt_acl_common_at(
	NTSTATUS (*get_acl_blob_at_fn)(TALLOC_CTX *ctx,
				    vfs_handle_struct *handle,
				    struct files_struct *dirfsp,
				    const struct smb_filename *smb_fname,
				    DATA_BLOB *pblob),
	vfs_handle_struct *handle,
	struct files_struct *dirfsp,
	const struct smb_filename *smb_fname_in,
	uint32_t security_info,
	TALLOC_CTX *mem_ctx,
	struct security_descriptor **ppdesc)
{
	DATA_BLOB blob = data_blob_null;
	NTSTATUS status;
	struct security_descriptor *psd = NULL;
	bool psd_is_from_fs = false;
	struct acl_common_config *config = NULL;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct acl_common_config,
				return NT_STATUS_UNSUCCESSFUL);

	DBG_DEBUG("name=%s\n", smb_fname_in->base_name);

	status = get_acl_blob_at_fn(mem_ctx,
				handle,
				dirfsp,
				smb_fname_in,
				&blob);
	if (NT_STATUS_IS_OK(status)) {
		status = validate_nt_acl_blob(mem_ctx,
					handle,
					NULL,
					dirfsp,
					smb_fname_in,
					&blob,
					&psd,
					&psd_is_from_fs);
		TALLOC_FREE(blob.data);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_DEBUG("ACL validation for [%s] failed\n",
				  smb_fname_in->base_name);
			goto fail;
		}
	}

	if (psd == NULL) {
		/* Get the full underlying sd, as we failed to get the
		 * blob for the hash, or the revision/hash type wasn't
		 * known */

		if (config->ignore_system_acls) {
			SMB_STRUCT_STAT sbuf;
			int ret;

			ret = vfs_stat_smb_basename(handle->conn,
					smb_fname_in,
					&sbuf);
			if (ret == -1) {
				status = map_nt_error_from_unix(errno);
				goto fail;
			}

			status = make_default_filesystem_acl(
				mem_ctx,
				config->default_acl_style,
				smb_fname_in->base_name,
				&sbuf,
				&psd);
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}
		} else {
			status = SMB_VFS_NEXT_GET_NT_ACL_AT(handle,
						dirfsp,
						smb_fname_in,
						security_info,
						mem_ctx,
						&psd);

			if (!NT_STATUS_IS_OK(status)) {
				DBG_DEBUG("get_next_acl for file %s "
					  "returned %s\n",
					  smb_fname_in->base_name,
					  nt_errstr(status));
				goto fail;
			}

			psd_is_from_fs = true;
		}
	}

	if (psd_is_from_fs) {
		SMB_STRUCT_STAT sbuf;
		bool is_directory = false;
		int ret;

		/*
		 * We're returning the underlying ACL from the
		 * filesystem. If it's a directory, and has no
		 * inheritable ACE entries we have to fake them.
		 */

		ret = vfs_stat_smb_basename(handle->conn,
				smb_fname_in,
				&sbuf);
		if (ret == -1) {
			status = map_nt_error_from_unix(errno);
			goto fail;
		}

		is_directory = S_ISDIR(sbuf.st_ex_mode);

		if (is_directory && !sd_has_inheritable_components(psd, true)) {
			status = add_directory_inheritable_components(
				handle,
				smb_fname_in->base_name,
				&sbuf,
				psd);
			if (!NT_STATUS_IS_OK(status)) {
				goto fail;
			}
		}

		/*
		 * The underlying POSIX module always sets the
		 * ~SEC_DESC_DACL_PROTECTED bit, as ACLs can't be inherited in
		 * this way under POSIX. Remove it for Windows-style ACLs.
		 */
		psd->type &= ~SEC_DESC_DACL_PROTECTED;
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

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("returning acl for %s is:\n",
			  smb_fname_in->base_name);
		NDR_PRINT_DEBUG(security_descriptor, psd);
	}

	*ppdesc = psd;

	return NT_STATUS_OK;

fail:
	TALLOC_FREE(psd);
	return status;
}

/*********************************************************************
 Set the underlying ACL (e.g. POSIX ACLS, POSIX owner, etc)
*********************************************************************/
static NTSTATUS set_underlying_acl(vfs_handle_struct *handle, files_struct *fsp,
				   struct security_descriptor *psd,
				   uint32_t security_info_sent,
				   bool chown_needed)
{
	NTSTATUS status;
	const struct security_token *token = NULL;
	struct dom_sid_buf buf;

	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	if (!NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
		return status;
	}

	/* We got access denied here. If we're already root,
	   or we didn't need to do a chown, or the fsp isn't
	   open with WRITE_OWNER access, just return. */
	if (get_current_uid(handle->conn) == 0 || chown_needed == false ||
	    !(fsp->access_mask & SEC_STD_WRITE_OWNER)) {
		return NT_STATUS_ACCESS_DENIED;
	}

	/*
	 * Only allow take-ownership, not give-ownership. That's the way Windows
	 * implements SEC_STD_WRITE_OWNER. MS-FSA 2.1.5.16 just states: If
	 * InputBuffer.OwnerSid is not a valid owner SID for a file in the
	 * objectstore, as determined in an implementation specific manner, the
	 * object store MUST return STATUS_INVALID_OWNER.
	 */
	token = get_current_nttok(fsp->conn);
	if (!security_token_is_sid(token, psd->owner_sid)) {
		return NT_STATUS_INVALID_OWNER;
	}

	DBG_DEBUG("overriding chown on file %s for sid %s\n",
		  fsp_str_dbg(fsp),
		  dom_sid_str_buf(psd->owner_sid, &buf));

	/* Ok, we failed to chown and we have
	   SEC_STD_WRITE_OWNER access - override. */
	become_root();
	status = SMB_VFS_NEXT_FSET_NT_ACL(handle, fsp, security_info_sent, psd);
	unbecome_root();

	return status;
}

/*********************************************************************
 Store a v3 security descriptor
*********************************************************************/
static NTSTATUS store_v3_blob(
	NTSTATUS (*store_acl_blob_fsp_fn)(vfs_handle_struct *handle,
					  files_struct *fsp,
					  DATA_BLOB *pblob),
	vfs_handle_struct *handle, files_struct *fsp,
	struct security_descriptor *psd,
	struct security_descriptor *pdesc_next,
	uint8_t hash[XATTR_SD_HASH_SIZE])
{
	NTSTATUS status;
	DATA_BLOB blob;

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("storing xattr sd for file %s\n",
			  fsp_str_dbg(fsp));
		NDR_PRINT_DEBUG(
		    security_descriptor,
		    discard_const_p(struct security_descriptor, psd));

		if (pdesc_next != NULL) {
			DBG_DEBUG("storing xattr sd based on \n");
			NDR_PRINT_DEBUG(
			    security_descriptor,
			    discard_const_p(struct security_descriptor,
					    pdesc_next));
		} else {
			DBG_DEBUG("ignoring underlying sd\n");
		}
	}
	status = create_acl_blob(psd, &blob, XATTR_SD_HASH_TYPE_SHA256, hash);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_DEBUG("create_acl_blob failed\n");
		return status;
	}

	status = store_acl_blob_fsp_fn(handle, fsp, &blob);
	return status;
}

/*********************************************************************
 Store a security descriptor given an fsp.
*********************************************************************/

NTSTATUS fset_nt_acl_common(
	NTSTATUS (*fget_acl_blob_fn)(TALLOC_CTX *ctx,
				    vfs_handle_struct *handle,
				    files_struct *fsp,
				    DATA_BLOB *pblob),
	NTSTATUS (*store_acl_blob_fsp_fn)(vfs_handle_struct *handle,
					  files_struct *fsp,
					  DATA_BLOB *pblob),
	const char *module_name,
	vfs_handle_struct *handle, files_struct *fsp,
	uint32_t security_info_sent,
	const struct security_descriptor *orig_psd)
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
	bool ignore_file_system_acl = lp_parm_bool(
	    SNUM(handle->conn), module_name, "ignore system acls", false);

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("incoming sd for file %s\n", fsp_str_dbg(fsp));
		NDR_PRINT_DEBUG(security_descriptor,
			discard_const_p(struct security_descriptor, orig_psd));
	}

	status = fget_nt_acl_common(fget_acl_blob_fn, handle, fsp,
			SECINFO_OWNER|SECINFO_GROUP|SECINFO_DACL|SECINFO_SACL,
				     frame,
			&psd);

	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	psd->revision = orig_psd->revision;
	if (security_info_sent & SECINFO_DACL) {
		psd->type = orig_psd->type;
		/* All our SD's are self relative. */
		psd->type |= SEC_DESC_SELF_RELATIVE;
	}

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

	if (ignore_file_system_acl) {
		if (chown_needed) {
			/* send only ownership stuff to lower layer */
			security_info_sent &= (SECINFO_OWNER | SECINFO_GROUP);
			status = set_underlying_acl(handle, fsp, psd,
						    security_info_sent, true);
			if (!NT_STATUS_IS_OK(status)) {
				TALLOC_FREE(frame);
				return status;
			}
		}
		ZERO_ARRAY(hash);
		status = store_v3_blob(store_acl_blob_fsp_fn, handle, fsp, psd,
				       NULL, hash);

		TALLOC_FREE(frame);
		return status;
	}

	status = set_underlying_acl(handle, fsp, psd, security_info_sent,
				    chown_needed);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
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
		status = store_v3_blob(store_acl_blob_fsp_fn, handle, fsp, psd,
				       pdesc_next, hash);

		TALLOC_FREE(frame);
		return status;
	}

	status = hash_blob_sha256(sys_acl_blob, sys_acl_hash);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(frame);
		return status;
	}

	if (DEBUGLEVEL >= 10) {
		DBG_DEBUG("storing xattr sd for file %s based on system ACL\n",
			  fsp_str_dbg(fsp));
		NDR_PRINT_DEBUG(security_descriptor,
				discard_const_p(struct security_descriptor, psd));

		DBG_DEBUG("storing hash in xattr sd based on system ACL and:\n");
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
		DBG_DEBUG("create_sys_acl_blob failed\n");
		TALLOC_FREE(frame);
		return status;
	}

	status = store_acl_blob_fsp_fn(handle, fsp, &blob);

	TALLOC_FREE(frame);
	return status;
}

static int acl_common_remove_object(vfs_handle_struct *handle,
					const struct smb_filename *smb_fname,
					bool is_directory)
{
	connection_struct *conn = handle->conn;
	struct file_id id;
	files_struct *fsp = NULL;
	int ret = 0;
	struct smb_filename *local_fname = NULL;
	struct smb_filename *parent_dir_fname = NULL;
	int saved_errno = 0;
	struct smb_filename *saved_dir_fname = NULL;
	bool ok;

	saved_dir_fname = vfs_GetWd(talloc_tos(),conn);
	if (saved_dir_fname == NULL) {
		saved_errno = errno;
		goto out;
	}

	ok = parent_smb_fname(talloc_tos(),
			      smb_fname,
			      &parent_dir_fname,
			      &local_fname);
	if (!ok) {
		saved_errno = ENOMEM;
		goto out;
	}

	DBG_DEBUG("removing %s %s/%s\n", is_directory ? "directory" : "file",
		  smb_fname_str_dbg(parent_dir_fname),
		  smb_fname_str_dbg(local_fname));

 	/* cd into the parent dir to pin it. */
	ret = vfs_ChDir(conn, parent_dir_fname);
	if (ret == -1) {
		saved_errno = errno;
		goto out;
	}

	/* Must use lstat here. */
	ret = SMB_VFS_LSTAT(conn, local_fname);
	if (ret == -1) {
		saved_errno = errno;
		goto out;
	}

	/* Ensure we have this file open with DELETE access. */
	id = vfs_file_id_from_sbuf(conn, &local_fname->st);
	for (fsp = file_find_di_first(conn->sconn, id); fsp;
		     fsp = file_find_di_next(fsp)) {
		if (fsp->access_mask & DELETE_ACCESS &&
		    fsp->fsp_flags.delete_on_close)
		{
			/* We did open this for delete,
			 * allow the delete as root.
			 */
			break;
		}
	}

	if (!fsp) {
		DBG_DEBUG("%s %s/%s not an open file\n",
			  is_directory ? "directory" : "file",
			  smb_fname_str_dbg(parent_dir_fname),
			  smb_fname_str_dbg(local_fname));
		saved_errno = EACCES;
		goto out;
	}

	become_root();
	if (is_directory) {
		ret = SMB_VFS_NEXT_UNLINKAT(handle,
				conn->cwd_fsp,
				local_fname,
				AT_REMOVEDIR);
	} else {
		ret = SMB_VFS_NEXT_UNLINKAT(handle,
				conn->cwd_fsp,
				local_fname,
				0);
	}
	unbecome_root();

	if (ret == -1) {
		saved_errno = errno;
	}

  out:

	TALLOC_FREE(parent_dir_fname);

	if (saved_dir_fname) {
		vfs_ChDir(conn, saved_dir_fname);
		TALLOC_FREE(saved_dir_fname);
	}
	if (saved_errno) {
		errno = saved_errno;
	}
	return ret;
}

int rmdir_acl_common(struct vfs_handle_struct *handle,
		struct files_struct *dirfsp,
		const struct smb_filename *smb_fname)
{
	int ret;

	/* Try the normal rmdir first. */
	ret = SMB_VFS_NEXT_UNLINKAT(handle,
			dirfsp,
			smb_fname,
			AT_REMOVEDIR);
	if (ret == 0) {
		return 0;
	}
	if (errno == EACCES || errno == EPERM) {
		/* Failed due to access denied,
		   see if we need to root override. */
		return acl_common_remove_object(handle,
						smb_fname,
						true);
	}

	DBG_DEBUG("unlink of %s failed %s\n",
		  smb_fname->base_name,
		  strerror(errno));
	return -1;
}

int unlink_acl_common(struct vfs_handle_struct *handle,
			struct files_struct *dirfsp,
			const struct smb_filename *smb_fname,
			int flags)
{
	int ret;

	/* Try the normal unlink first. */
	ret = SMB_VFS_NEXT_UNLINKAT(handle,
				dirfsp,
				smb_fname,
				flags);
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
					smb_fname,
					false);
	}

	DBG_DEBUG("unlink of %s failed %s\n",
		  smb_fname->base_name,
		  strerror(errno));
	return -1;
}

int chmod_acl_module_common(struct vfs_handle_struct *handle,
			    const struct smb_filename *smb_fname,
			    mode_t mode)
{
	if (smb_fname->flags & SMB_FILENAME_POSIX_PATH) {
		/* Only allow this on POSIX pathnames. */
		return SMB_VFS_NEXT_CHMOD(handle, smb_fname, mode);
	}
	return 0;
}

int fchmod_acl_module_common(struct vfs_handle_struct *handle,
			     struct files_struct *fsp, mode_t mode)
{
	if (fsp->posix_flags & FSP_POSIX_FLAGS_OPEN) {
		/* Only allow this on POSIX opens. */
		return SMB_VFS_NEXT_FCHMOD(handle, fsp, mode);
	}
	return 0;
}
