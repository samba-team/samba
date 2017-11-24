/*
 * Convert NFSv4 acls stored per http://www.suse.de/~agruen/nfs4acl/ to NT acls and vice versa.
 *
 * Copyright (C) Jiri Sasek, 2007
 * based on the foobar.c module which is copyrighted by Volker Lendecke
 * based on pvfs_acl_nfs4.c  Copyright (C) Andrew Tridgell 2006
 *
 * based on vfs_fake_acls:
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Andrew Bartlett, 2002,2012
 * Copyright (C) Ralph Boehme 2017
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
 *
 */

#include "includes.h"
#include "system/filesys.h"
#include "smbd/smbd.h"
#include "nfs4_acls.h"
#include "librpc/gen_ndr/ndr_nfs4acl.h"
#include "nfs4acl_xattr.h"
#include "nfs4acl_xattr_ndr.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

static struct nfs4acl *nfs4acl_blob2acl(DATA_BLOB *blob, TALLOC_CTX *mem_ctx)
{
	enum ndr_err_code ndr_err;
	struct nfs4acl *acl = talloc_zero(mem_ctx, struct nfs4acl);

	if (acl == NULL) {
		errno = ENOMEM;
		return NULL;
	}

	ndr_err = ndr_pull_struct_blob(blob, acl, acl,
		(ndr_pull_flags_fn_t)ndr_pull_nfs4acl);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("ndr_pull_acl_t failed: %s\n", ndr_errstr(ndr_err));
		TALLOC_FREE(acl);
		return NULL;
	}
	return acl;
}

static DATA_BLOB nfs4acl_acl2blob(TALLOC_CTX *mem_ctx, struct nfs4acl *acl)
{
	enum ndr_err_code ndr_err;
	DATA_BLOB blob;

	ndr_err = ndr_push_struct_blob(&blob, mem_ctx, acl,
		(ndr_push_flags_fn_t)ndr_push_nfs4acl);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DBG_ERR("ndr_push_acl_t failed: %s\n", ndr_errstr(ndr_err));
		return data_blob_null;
	}
	return blob;
}

static uint16_t nfs4acl_to_smb4acl_flags(uint8_t nfs4acl_flags)
{
	uint16_t smb4acl_flags = SEC_DESC_SELF_RELATIVE;

	if (nfs4acl_flags & ACL4_AUTO_INHERIT) {
		smb4acl_flags |= SEC_DESC_DACL_AUTO_INHERITED;
	}
	if (nfs4acl_flags & ACL4_PROTECTED) {
		smb4acl_flags |= SEC_DESC_DACL_PROTECTED;
	}
	if (nfs4acl_flags & ACL4_DEFAULTED) {
		smb4acl_flags |= SEC_DESC_DACL_DEFAULTED;
	}

	return smb4acl_flags;
}

NTSTATUS nfs4acl_ndr_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl *nfs4acl = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	TALLOC_CTX *frame = talloc_stackframe();
	struct nfs4acl_config *config = NULL;
	int i;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	nfs4acl = nfs4acl_blob2acl(blob, frame);
	if (nfs4acl == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_INTERNAL_ERROR;
	}

	smb4acl = smb_create_smb4acl(mem_ctx);
	if (smb4acl == NULL) {
		TALLOC_FREE(frame);
		return NT_STATUS_NO_MEMORY;
	}

	if (config->nfs_version > ACL4_XATTR_VERSION_40 &&
	    nfs4acl->a_version > ACL4_XATTR_VERSION_40)
	{
		uint16_t smb4acl_flags;

		smb4acl_flags = nfs4acl_to_smb4acl_flags(nfs4acl->a_flags);
		smbacl4_set_controlflags(smb4acl, smb4acl_flags);
	}

	for (i = 0; i < nfs4acl->a_count; i++) {
		SMB_ACE4PROP_T aceprop;

		aceprop.aceType  = (uint32_t) nfs4acl->ace[i].e_type;
		aceprop.aceFlags = (uint32_t) nfs4acl->ace[i].e_flags;
		aceprop.aceMask  = (uint32_t) nfs4acl->ace[i].e_mask;
		aceprop.who.id   = (uint32_t) nfs4acl->ace[i].e_id;

		if (!strcmp(nfs4acl->ace[i].e_who,
			    NFS4ACL_XATTR_OWNER_WHO)) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_OWNER;
		} else if (!strcmp(nfs4acl->ace[i].e_who,
				   NFS4ACL_XATTR_GROUP_WHO)) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_GROUP;
		} else if (!strcmp(nfs4acl->ace[i].e_who,
				   NFS4ACL_XATTR_EVERYONE_WHO)) {
			aceprop.flags = SMB_ACE4_ID_SPECIAL;
			aceprop.who.special_id = SMB_ACE4_WHO_EVERYONE;
		} else {
			aceprop.flags = 0;
		}

		if (smb_add_ace4(smb4acl, &aceprop) == NULL) {
			TALLOC_FREE(frame);
			return NT_STATUS_NO_MEMORY;
		}
	}

	*_smb4acl = smb4acl;
	TALLOC_FREE(frame);
	return NT_STATUS_OK;
}

static uint8_t smb4acl_to_nfs4acl_flags(uint16_t smb4acl_flags)
{
	uint8_t flags = 0;

	if (smb4acl_flags & SEC_DESC_DACL_AUTO_INHERITED) {
		flags |= ACL4_AUTO_INHERIT;
	}
	if (smb4acl_flags & SEC_DESC_DACL_PROTECTED) {
		flags |= ACL4_PROTECTED;
	}
	if (smb4acl_flags & SEC_DESC_DACL_DEFAULTED) {
		flags |= ACL4_DEFAULTED;
	}

	return flags;
}

static bool nfs4acl_smb4acl2nfs4acl(vfs_handle_struct *handle,
				    TALLOC_CTX *mem_ctx,
				    struct SMB4ACL_T *smbacl,
				    struct nfs4acl **_nfs4acl,
				    bool denymissingspecial)
{
	struct nfs4acl_config *config = NULL;
	struct nfs4acl *nfs4acl = NULL;
	struct SMB4ACE_T *smbace = NULL;
	bool have_special_id = false;
	int i;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return false);

	nfs4acl = talloc_zero(mem_ctx, struct nfs4acl);
	if (nfs4acl == NULL) {
		errno = ENOMEM;
		return false;
	}

	nfs4acl->a_count = smb_get_naces(smbacl);

	nfs4acl->ace = talloc_zero_array(nfs4acl, struct nfs4ace,
					 nfs4acl->a_count);
	if (nfs4acl->ace == NULL) {
		TALLOC_FREE(nfs4acl);
		errno = ENOMEM;
		return false;
	}

	nfs4acl->a_version = config->nfs_version;
	if (nfs4acl->a_version > ACL4_XATTR_VERSION_40) {
		uint16_t smb4acl_flags;
		uint8_t flags;

		smb4acl_flags = smbacl4_get_controlflags(smbacl);
		flags = smb4acl_to_nfs4acl_flags(smb4acl_flags);
		nfs4acl->a_flags = flags;
	}

	for (smbace = smb_first_ace4(smbacl), i = 0;
	     smbace != NULL;
	     smbace = smb_next_ace4(smbace), i++)
	{
		SMB_ACE4PROP_T *aceprop = smb_get_ace4(smbace);

		nfs4acl->ace[i].e_type        = aceprop->aceType;
		nfs4acl->ace[i].e_flags       = aceprop->aceFlags;
		nfs4acl->ace[i].e_mask        = aceprop->aceMask;
		nfs4acl->ace[i].e_id          = aceprop->who.id;
		if(aceprop->flags & SMB_ACE4_ID_SPECIAL) {
			switch(aceprop->who.special_id) {
			case SMB_ACE4_WHO_EVERYONE:
				nfs4acl->ace[i].e_who =
					NFS4ACL_XATTR_EVERYONE_WHO;
				break;
			case SMB_ACE4_WHO_OWNER:
				nfs4acl->ace[i].e_who =
					NFS4ACL_XATTR_OWNER_WHO;
				break;
			case SMB_ACE4_WHO_GROUP:
				nfs4acl->ace[i].e_who =
					NFS4ACL_XATTR_GROUP_WHO;
				break;
			default:
				DBG_DEBUG("unsupported special_id %d\n",
					  aceprop->who.special_id);
				continue; /* don't add it !!! */
			}
			have_special_id = true;
		} else {
			nfs4acl->ace[i].e_who = "";
		}
	}

	if (!have_special_id && denymissingspecial) {
		TALLOC_FREE(nfs4acl);
		errno = EACCES;
		return false;
	}

	SMB_ASSERT(i == nfs4acl->a_count);

	*_nfs4acl = nfs4acl;
	return true;
}

NTSTATUS nfs4acl_smb4acl_to_ndr_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smb4acl,
				     DATA_BLOB *_blob)
{
	struct nfs4acl *nfs4acl = NULL;
	DATA_BLOB blob;
	bool denymissingspecial;
	bool ok;

	denymissingspecial = lp_parm_bool(SNUM(handle->conn),
					  "nfs4acl_xattr",
					  "denymissingspecial", false);

	ok = nfs4acl_smb4acl2nfs4acl(handle, talloc_tos(), smb4acl, &nfs4acl,
				     denymissingspecial);
	if (!ok) {
		DBG_ERR("Failed to convert smb ACL to nfs4 ACL.\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	blob = nfs4acl_acl2blob(mem_ctx, nfs4acl);
	TALLOC_FREE(nfs4acl);
	if (blob.data == NULL) {
		DBG_ERR("Failed to convert ACL to linear blob for xattr\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	*_blob = blob;
	return NT_STATUS_OK;
}
