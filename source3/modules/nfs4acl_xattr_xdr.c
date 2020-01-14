/*
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
#include "smbd/proto.h"
#include "libcli/security/security_descriptor.h"
#include "libcli/security/security_token.h"
#include "nfs4_acls.h"
#include "nfs4acl_xattr.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#ifdef HAVE_RPC_XDR_H
/* <rpc/xdr.h> uses TRUE and FALSE */
#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif

#ifdef HAVE_RPC_TYPES_H
#include <rpc/types.h>
#endif
#include <rpc/xdr.h>
#include "nfs41acl.h"
#include "nfs4acl_xattr_xdr.h"
#include "nfs4acl_xattr_util.h"

static unsigned nfs4acli_get_naces(nfsacl41i *nacl)
{
	return nacl->na41_aces.na41_aces_len;
}

static void nfs4acli_set_naces(nfsacl41i *nacl, unsigned naces)
{
	nacl->na41_aces.na41_aces_len = naces;
}

static unsigned nfs4acli_get_flags(nfsacl41i *nacl)
{
	return nacl->na41_flag;
}

static void nfs4acli_set_flags(nfsacl41i *nacl, unsigned flags)
{
	nacl->na41_flag = flags;
}

static size_t nfs4acli_get_xdrblob_size(nfsacl41i *nacl)
{
	size_t acl_size;
	size_t aces_size;
	unsigned naces = nfs4acli_get_naces(nacl);

	acl_size = sizeof(aclflag4) + sizeof(unsigned);

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %u", naces);
		return 0;
	}

	aces_size = naces * sizeof(struct nfsace4i);
	if (acl_size + aces_size < acl_size) {
		return 0;
	}
	acl_size += aces_size;

	return acl_size;
}

static size_t nfs4acli_get_xdrblob_naces(size_t _blobsize)
{
	size_t blobsize = _blobsize;

	blobsize -= sizeof(aclflag4);
	blobsize -= sizeof(unsigned);
	if (blobsize > _blobsize) {
		return 0;
	}
	return (blobsize / sizeof(struct nfsace4i));
}

static nfsacl41i *nfs4acli_alloc(TALLOC_CTX *mem_ctx, unsigned naces)
{
	size_t acl_size = sizeof(nfsacl41i) + (naces * sizeof(struct nfsace4i));
	nfsacl41i *nacl = NULL;

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %d\n", naces);
		return NULL;
	}

	nacl = talloc_zero_size(mem_ctx, acl_size);
	if (nacl == NULL) {
		DBG_ERR("talloc_zero_size failed\n");
		return NULL;
	}

	nfs4acli_set_naces(nacl, naces);
	nacl->na41_aces.na41_aces_val =
		(nfsace4i *)((char *)nacl + sizeof(nfsacl41i));

	return nacl;
}

static nfsace4i *nfs4acli_get_ace(nfsacl41i *nacl, size_t n)
{
	return &nacl->na41_aces.na41_aces_val[n];
}

static bool smb4acl_to_nfs4acli(vfs_handle_struct *handle,
				TALLOC_CTX *mem_ctx,
				struct SMB4ACL_T *smb4acl,
				nfsacl41i **_nacl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACE_T *smb4ace = NULL;
	size_t smb4naces = 0;
	nfsacl41i *nacl = NULL;
	uint16_t smb4acl_flags = 0;
	unsigned nacl_flags = 0;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return false);

	smb4naces = smb_get_naces(smb4acl);
	nacl = nfs4acli_alloc(mem_ctx, smb4naces);
	nfs4acli_set_naces(nacl, 0);

	if (config->nfs_version > ACL4_XATTR_VERSION_40) {
		smb4acl_flags = smbacl4_get_controlflags(smb4acl);
		nacl_flags = smb4acl_to_nfs4acl_flags(smb4acl_flags);
		nfs4acli_set_flags(nacl, nacl_flags);
	}

	smb4ace = smb_first_ace4(smb4acl);
	while (smb4ace != NULL) {
		SMB_ACE4PROP_T *ace4prop = smb_get_ace4(smb4ace);
		size_t nace_count = nfs4acli_get_naces(nacl);
		nfsace4i *nace = nfs4acli_get_ace(nacl, nace_count);

		nace->type = ace4prop->aceType;
		nace->flag = ace4prop->aceFlags;
		nace->access_mask = ace4prop->aceMask;

		if (ace4prop->flags & SMB_ACE4_ID_SPECIAL) {
			nace->iflag |= ACEI4_SPECIAL_WHO;

			switch (ace4prop->who.special_id) {
			case SMB_ACE4_WHO_OWNER:
				nace->who = ACE4_SPECIAL_OWNER;
				break;

			case SMB_ACE4_WHO_GROUP:
				nace->who = ACE4_SPECIAL_GROUP;
				break;

			case SMB_ACE4_WHO_EVERYONE:
				nace->who = ACE4_SPECIAL_EVERYONE;
				break;

			default:
				DBG_ERR("Unsupported special id [%d]\n",
					ace4prop->who.special_id);
				continue;
			}
		} else {
			if (ace4prop->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) {
				nace->flag |= ACE4_IDENTIFIER_GROUP;
				nace->who = ace4prop->who.gid;
			} else {
				nace->who = ace4prop->who.uid;
			}
		}

		nace_count++;
		nfs4acli_set_naces(nacl, nace_count);
		smb4ace = smb_next_ace4(smb4ace);
	}

	*_nacl = nacl;
	return true;
}

NTSTATUS nfs4acl_smb4acl_to_xdr_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smb4acl,
				     DATA_BLOB *_blob)
{
	nfsacl41i *nacl = NULL;
	XDR xdr = {0};
	size_t aclblobsize;
	DATA_BLOB blob;
	bool ok;

	ok = smb4acl_to_nfs4acli(handle, talloc_tos(), smb4acl, &nacl);
	if (!ok) {
		DBG_ERR("smb4acl_to_nfs4acl failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	aclblobsize = nfs4acli_get_xdrblob_size(nacl);
	if (aclblobsize == 0) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	blob = data_blob_talloc(mem_ctx, NULL, aclblobsize);
	if (blob.data == NULL) {
		TALLOC_FREE(nacl);
		return NT_STATUS_NO_MEMORY;
	}

	xdrmem_create(&xdr, (char *)blob.data, blob.length, XDR_ENCODE);

	ok = xdr_nfsacl41i(&xdr, nacl);
	TALLOC_FREE(nacl);
	if (!ok) {
		DBG_ERR("xdr_nfs4acl41 failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	*_blob = blob;
	return NT_STATUS_OK;
}

static NTSTATUS nfs4acl_xdr_blob_to_nfs4acli(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     DATA_BLOB *blob,
					     nfsacl41i **_nacl)
{
	struct nfs4acl_config *config = NULL;
	nfsacl41i *nacl = NULL;
	size_t naces;
	XDR xdr = {0};
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	naces = nfs4acli_get_xdrblob_naces(blob->length);
	nacl = nfs4acli_alloc(mem_ctx, naces);

	xdrmem_create(&xdr, (char *)blob->data, blob->length, XDR_DECODE);

	ok = xdr_nfsacl41i(&xdr, nacl);
	if (!ok) {
		DBG_ERR("xdr_nfs4acl41 failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (config->nfs_version == ACL4_XATTR_VERSION_40) {
		nacl->na41_flag = 0;
	}

	*_nacl = nacl;
	return NT_STATUS_OK;
}

static NTSTATUS nfs4acli_to_smb4acl(struct vfs_handle_struct *handle,
				    TALLOC_CTX *mem_ctx,
				    nfsacl41i *nacl,
				    struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	unsigned nfsacl41_flag = 0;
	uint16_t smb4acl_flags = 0;
	unsigned naces = nfs4acli_get_naces(nacl);
	unsigned i;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	smb4acl = smb_create_smb4acl(mem_ctx);
	if (smb4acl == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (config->nfs_version > ACL4_XATTR_VERSION_40) {
		nfsacl41_flag = nfs4acli_get_flags(nacl);
		smb4acl_flags = nfs4acl_to_smb4acl_flags(nfsacl41_flag);
		smbacl4_set_controlflags(smb4acl, smb4acl_flags);
	}

	DBG_DEBUG("flags [%x] nace [%u]\n", smb4acl_flags, naces);

	for (i = 0; i < naces; i++) {
		nfsace4i *nace = nfs4acli_get_ace(nacl, i);
		SMB_ACE4PROP_T smbace = { 0 };

		DBG_DEBUG("type [%d] iflag [%x] flag [%x] mask [%x] who [%d]\n",
			  nace->type, nace->iflag, nace->flag,
			  nace->access_mask, nace->who);

		smbace.aceType = nace->type;
		smbace.aceFlags = nace->flag;
		smbace.aceMask = nace->access_mask;

		if (nace->iflag & ACEI4_SPECIAL_WHO) {
			smbace.flags |= SMB_ACE4_ID_SPECIAL;

			switch (nace->who) {
			case ACE4_SPECIAL_OWNER:
				smbace.who.special_id = SMB_ACE4_WHO_OWNER;
				break;

			case ACE4_SPECIAL_GROUP:
				smbace.who.special_id = SMB_ACE4_WHO_GROUP;
				break;

			case ACE4_SPECIAL_EVERYONE:
				smbace.who.special_id = SMB_ACE4_WHO_EVERYONE;
				break;

			default:
				DBG_ERR("Unknown special id [%d]\n", nace->who);
				continue;
			}
		} else {
			if (nace->flag & ACE4_IDENTIFIER_GROUP) {
				smbace.who.gid = nace->who;
			} else {
				smbace.who.uid = nace->who;
			}
		}

		smb_add_ace4(smb4acl, &smbace);
	}

	*_smb4acl = smb4acl;
	return NT_STATUS_OK;
}

NTSTATUS nfs4acl_xdr_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl_config *config = NULL;
	nfsacl41i *nacl = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	status = nfs4acl_xdr_blob_to_nfs4acli(handle, talloc_tos(), blob, &nacl);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = nfs4acli_to_smb4acl(handle, mem_ctx, nacl, &smb4acl);
	TALLOC_FREE(nacl);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_smb4acl = smb4acl;
	return NT_STATUS_OK;
}

#else /* !HAVE_RPC_XDR_H */
#include "nfs4acl_xattr_xdr.h"
NTSTATUS nfs4acl_xdr_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl)
{
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS nfs4acl_smb4acl_to_xdr_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smbacl,
				     DATA_BLOB *blob)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif /* HAVE_RPC_XDR_H */
