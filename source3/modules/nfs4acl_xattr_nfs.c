/*
 * Copyright (C) Ralph Boehme 2018
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
#include "system/passwd.h"
#include "libcli/security/security_descriptor.h"
#include "libcli/security/security_token.h"

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

#include "nfs4_acls.h"
#include "nfs41acl.h"
#include "nfs4acl_xattr.h"
#include "nfs4acl_xattr_nfs.h"
#include "nfs4acl_xattr_util.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

#define OVERFLOW_CHECK(val1, val2) ((val1) + (val2) < (val1))
#define XDR_UTF8STR_ALIGNMENT 4
#define XDR_UTF8STR_ALIGN(l) \
	(((l) + ((XDR_UTF8STR_ALIGNMENT) - 1)) & ~((XDR_UTF8STR_ALIGNMENT) - 1))

static struct nfs4_to_smb4_id_map {
	const char *nfs4_id;
	uint32_t smb4_id;
} nfs4_to_smb4_id_map[] = {
	{"OWNER@",		SMB_ACE4_WHO_OWNER},
	{"GROUP@",		SMB_ACE4_WHO_GROUP},
	{"EVERYONE@",		SMB_ACE4_WHO_EVERYONE},
	{"INTERACTIVE@",	SMB_ACE4_WHO_INTERACTIVE},
	{"NETWORK@",		SMB_ACE4_WHO_NETWORK},
	{"DIALUP@",		SMB_ACE4_WHO_DIALUP},
	{"BATCH@",		SMB_ACE4_WHO_BATCH},
	{"ANONYMOUS@",		SMB_ACE4_WHO_ANONYMOUS},
	{"AUTHENTICATED@",	SMB_ACE4_WHO_AUTHENTICATED},
	{"SERVICE@",		SMB_ACE4_WHO_SERVICE},
};

static bool is_special_nfs4_id(const char *nfs4_id)
{
	char *at = NULL;

	at = strchr(nfs4_id, '@');
	if (at == NULL) {
		return false;
	}
	if (at[1] != '\0') {
		return false;
	}
	return true;
}

static bool map_special_nfs4_to_smb4_id(const char *nfs4_id, uint32_t *smb4_id)
{
	size_t i;
	int cmp;

	for (i = 0; i < ARRAY_SIZE(nfs4_to_smb4_id_map); i++) {
		cmp = strcmp(nfs4_to_smb4_id_map[i].nfs4_id, nfs4_id);
		if (cmp != 0) {
			continue;
		}
		*smb4_id = nfs4_to_smb4_id_map[i].smb4_id;
		return true;
	}
	return false;
}

static bool map_special_smb4_to_nfs4_id(uint32_t smb4_id, const char **nfs4_id)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(nfs4_to_smb4_id_map); i++) {
		if (nfs4_to_smb4_id_map[i].smb4_id != smb4_id) {
			continue;
		}
		*nfs4_id = nfs4_to_smb4_id_map[i].nfs4_id;
		return true;
	}
	return false;
}

static unsigned nfs40acl_get_naces(nfsacl40 *nacl)
{
	return nacl->na40_aces.na40_aces_len;
}

static unsigned nfs41acl_get_naces(nfsacl41 *nacl)
{
	return nacl->na41_aces.na41_aces_len;
}

static void nfs40acl_set_naces(nfsacl40 *nacl, unsigned naces)
{
	nacl->na40_aces.na40_aces_len = naces;
}

static void nfs41acl_set_naces(nfsacl41 *nacl, unsigned naces)
{
	nacl->na41_aces.na41_aces_len = naces;
}

static unsigned nfs41acl_get_flags(nfsacl41 *nacl)
{
	return nacl->na41_flag;
}

static void nfs41acl_set_flags(nfsacl41 *nacl, unsigned flags)
{
	nacl->na41_flag = flags;
}

static nfsace4 *nfs40acl_get_ace(nfsacl40 *nacl, size_t n)
{
	return &nacl->na40_aces.na40_aces_val[n];
}

static nfsace4 *nfs41acl_get_ace(nfsacl41 *nacl, size_t n)
{
	return &nacl->na41_aces.na41_aces_val[n];
}

static size_t nfs40acl_get_xdrblob_size(nfsacl40 *nacl)
{
	size_t acl_size;
	size_t aces_size;
	size_t identifier_size;
	unsigned i;
	unsigned naces = nfs40acl_get_naces(nacl);

	/* ACE structure minus actual identifier strings */
	struct nfsace4_size {
		acetype4 type;
		aceflag4 flag;
		acemask4 access_mask;
		u_int who_length;
	};

	/*
	 * acl_size =
	 *   sizeof(ace_count) +
	 *   (ace_count * (sizeof(nfsace4_size)) +
	 *   length of all identifiers strings
	 */

	acl_size = sizeof(unsigned);

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %u", naces);
		return 0;
	}

	aces_size = naces * sizeof(struct nfsace4_size);

	if (OVERFLOW_CHECK(acl_size, aces_size)) {
		DBG_ERR("Integer Overflow error\n");
		return 0;
	}
	acl_size += aces_size;

	identifier_size = 0;
	for (i = 0;  i < naces; i++) {
		nfsace4 *nace = nfs40acl_get_ace(nacl, i);
		size_t string_size = nace->who.utf8string_len;
		size_t id_size;

		id_size = XDR_UTF8STR_ALIGN(string_size);

		if (OVERFLOW_CHECK(identifier_size, id_size)) {
			DBG_ERR("Integer Overflow error\n");
			return 0;
		}
		identifier_size += id_size;
	}

	if (OVERFLOW_CHECK(acl_size, identifier_size)) {
		DBG_ERR("Integer Overflow error\n");
		return 0;
	}
	acl_size += identifier_size;

	DBG_DEBUG("acl_size: %zd\n", acl_size);
	return acl_size;
}

static size_t nfs41acl_get_xdrblob_size(nfsacl41 *nacl)
{
	size_t acl_size;
	size_t aces_size;
	size_t identifier_size;
	unsigned i;
	unsigned naces = nfs41acl_get_naces(nacl);

	/* ACE structure minus actual identifier strings */
	struct nfsace4_size {
		acetype4 type;
		aceflag4 flag;
		acemask4 access_mask;
		u_int who_length;
	};

	/*
	 * acl_size =
	 *   sizeof(acl_flag) +
	 *   sizeof(ace_count) +
	 *   (ace_count * (sizeof(nfsace4_size)) +
	 *   length of all identifiers strings
	 */

	acl_size = 2 * sizeof(unsigned);

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %u", naces);
		return 0;
	}

	aces_size = naces * sizeof(struct nfsace4_size);

	if (OVERFLOW_CHECK(acl_size, aces_size)) {
		DBG_ERR("Integer Overflow error\n");
		return 0;
	}
	acl_size += aces_size;

	identifier_size = 0;
	for (i = 0;  i < naces; i++) {
		nfsace4 *nace = nfs41acl_get_ace(nacl, i);
		size_t string_size = nace->who.utf8string_len;
		size_t id_size;

		id_size = XDR_UTF8STR_ALIGN(string_size);

		if (OVERFLOW_CHECK(identifier_size, id_size)) {
			DBG_ERR("Integer Overflow error\n");
			return 0;
		}
		identifier_size += id_size;
	}

	if (OVERFLOW_CHECK(acl_size, identifier_size)) {
		DBG_ERR("Integer Overflow error\n");
		return 0;
	}
	acl_size += identifier_size;

	DBG_DEBUG("acl_size: %zd\n", acl_size);
	return acl_size;
}

static nfsacl40 *nfs40acl_alloc(TALLOC_CTX *mem_ctx, unsigned naces)
{
	size_t acl_size;
	size_t aces_size;
	nfsacl40 *nacl = NULL;

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %d\n", naces);
		return NULL;
	}

	acl_size = sizeof(nfsacl40);
	aces_size = (naces * sizeof(struct nfsace4));

	if (OVERFLOW_CHECK(acl_size, aces_size)) {
		DBG_ERR("Integer Overflow error\n");
		return NULL;
	}
	acl_size += aces_size;

	nacl = talloc_zero_size(mem_ctx, acl_size);
	if (nacl == NULL) {
		DBG_ERR("talloc_zero_size failed\n");
		return NULL;
	}

	nfs40acl_set_naces(nacl, naces);
	nacl->na40_aces.na40_aces_val =
		(nfsace4 *)((uint8_t *)nacl + sizeof(nfsacl40));

	return nacl;
}

static nfsacl41 *nfs41acl_alloc(TALLOC_CTX *mem_ctx, unsigned naces)
{
	size_t acl_size;
	size_t aces_size;
	nfsacl41 *nacl = NULL;

	if (naces > NFS4ACL_XDR_MAX_ACES) {
		DBG_ERR("Too many ACEs: %d\n", naces);
		return NULL;
	}

	acl_size = sizeof(nfsacl41);
	aces_size = (naces * sizeof(struct nfsace4));

	if (OVERFLOW_CHECK(acl_size, aces_size)) {
		DBG_ERR("Integer Overflow error\n");
		return NULL;
	}
	acl_size += aces_size;

	nacl = talloc_zero_size(mem_ctx, acl_size);
	if (nacl == NULL) {
		DBG_ERR("talloc_zero_size failed\n");
		return NULL;
	}

	nfs41acl_set_naces(nacl, naces);
	nacl->na41_aces.na41_aces_val =
		(nfsace4 *)((uint8_t *)nacl + sizeof(nfsacl41));

	return nacl;
}

static bool create_special_id(TALLOC_CTX *mem_ctx,
			      nfsace4 *nace,
			      const char *id)
{
	char *s = talloc_strdup(mem_ctx, id);

	if (s == NULL) {
		DBG_ERR("talloc_memdup failed\n");
		return false;
	}
	nace->who.utf8string_val = s;
	nace->who.utf8string_len = talloc_get_size(s) - 1;
	return true;
}

static bool map_smb4_to_nfs4_id(TALLOC_CTX *mem_ctx,
				struct nfs4acl_config *config,
				nfsace4 *nace,
				SMB_ACE4PROP_T *sace)
{
	const char *nfs4_id = NULL;
	const char *name = NULL;
	char *ace_name = NULL;
	uid_t id;
	bool ok;

	if (sace->flags & SMB_ACE4_ID_SPECIAL) {
		ok = map_special_smb4_to_nfs4_id(sace->who.special_id,
						 &nfs4_id);
		if (!ok) {
			DBG_ERR("Unsupported special id [%"PRIu32"]\n",
				sace->who.special_id);
			return false;
		}

		ok = create_special_id(mem_ctx, nace, nfs4_id);
		if (!ok) {
			return false;
		}
		DBG_DEBUG("Special id [%s]\n", nace->who.utf8string_val);
		return true;
	}

	if (sace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) {
		nace->flag |= ACE4_IDENTIFIER_GROUP;
	}

	if (config->nfs4_id_numeric) {
		char *strid = NULL;

		if (sace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) {
			id = sace->who.gid;
		} else {
			id = sace->who.uid;
		}

		strid = talloc_asprintf(mem_ctx, "%jd", (intmax_t)id);
		if (strid == NULL) {
			DBG_ERR("talloc_asprintf failed\n");
			return false;
		}
		nace->who.utf8string_val = strid;
		nace->who.utf8string_len = talloc_get_size(strid) - 1;
		DBG_DEBUG("Numeric id [%s]\n", nace->who.utf8string_val);
		return true;
	}

	if (sace->aceFlags & SMB_ACE4_IDENTIFIER_GROUP) {
		struct group *grp = NULL;

		grp = getgrgid(sace->who.gid);
		if (grp == NULL) {
			DBG_ERR("Unknown gid [%jd]\n", (intmax_t)sace->who.gid);
			return false;
		}
		name = grp->gr_name;
	} else {
		struct passwd *pwd = NULL;

		pwd = getpwuid(sace->who.uid);
		if (pwd == NULL) {
			DBG_ERR("Unknown uid [%jd]\n", (intmax_t)sace->who.uid);
			return false;
		}
		name = pwd->pw_name;
	}

	ace_name = talloc_strdup(mem_ctx, name);
	if (ace_name == NULL) {
		DBG_ERR("talloc_asprintf failed\n");
		return false;
	}
	nace->who.utf8string_val = ace_name;
	nace->who.utf8string_len = talloc_get_size(ace_name) - 1;

	DBG_DEBUG("id [%s]\n", nace->who.utf8string_val);
	return true;
}

static bool smb4acl_to_nfs40acl(vfs_handle_struct *handle,
			       TALLOC_CTX *mem_ctx,
			       struct SMB4ACL_T *smb4acl,
			       nfsacl40 **_nacl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACE_T *smb4ace = NULL;
	nfsacl40 *nacl = NULL;
	size_t naces = smb_get_naces(smb4acl);
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return false);

	nacl = nfs40acl_alloc(mem_ctx, naces);
	nfs40acl_set_naces(nacl, 0);

	smb4ace = smb_first_ace4(smb4acl);
	while (smb4ace != NULL) {
		SMB_ACE4PROP_T *ace4prop = smb_get_ace4(smb4ace);
		size_t nace_count = nfs40acl_get_naces(nacl);
		nfsace4 *nace = nfs40acl_get_ace(nacl, nace_count);

		nace->type = ace4prop->aceType;
		nace->flag = ace4prop->aceFlags;
		nace->access_mask = ace4prop->aceMask;

		ok = map_smb4_to_nfs4_id(nacl, config, nace, ace4prop);
		if (!ok) {
			smb4ace = smb_next_ace4(smb4ace);
			continue;
		}

		nace_count++;
		nfs40acl_set_naces(nacl, nace_count);
		smb4ace = smb_next_ace4(smb4ace);
	}

	*_nacl = nacl;
	return true;
}

static bool smb4acl_to_nfs41acl(vfs_handle_struct *handle,
			       TALLOC_CTX *mem_ctx,
			       struct SMB4ACL_T *smb4acl,
			       nfsacl41 **_nacl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACE_T *smb4ace = NULL;
	nfsacl41 *nacl = NULL;
	size_t naces = smb_get_naces(smb4acl);
	uint16_t smb4acl_flags;
	unsigned nacl_flags;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return false);

	nacl = nfs41acl_alloc(mem_ctx, naces);
	nfs41acl_set_naces(nacl, 0);

	smb4acl_flags = smbacl4_get_controlflags(smb4acl);
	nacl_flags = smb4acl_to_nfs4acl_flags(smb4acl_flags);
	nfs41acl_set_flags(nacl, nacl_flags);

	smb4ace = smb_first_ace4(smb4acl);
	while (smb4ace != NULL) {
		SMB_ACE4PROP_T *ace4prop = smb_get_ace4(smb4ace);
		size_t nace_count = nfs41acl_get_naces(nacl);
		nfsace4 *nace = nfs41acl_get_ace(nacl, nace_count);

		nace->type = ace4prop->aceType;
		nace->flag = ace4prop->aceFlags;
		nace->access_mask = ace4prop->aceMask;

		ok = map_smb4_to_nfs4_id(nacl, config, nace, ace4prop);
		if (!ok) {
			smb4ace = smb_next_ace4(smb4ace);
			continue;
		}

		nace_count++;
		nfs41acl_set_naces(nacl, nace_count);
		smb4ace = smb_next_ace4(smb4ace);
	}

	*_nacl = nacl;
	return true;
}

NTSTATUS nfs4acl_smb4acl_to_nfs_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smb4acl,
				     DATA_BLOB *_blob)
{
	struct nfs4acl_config *config = NULL;
	nfsacl40 *nacl40 = NULL;
	nfsacl41 *nacl41 = NULL;
	XDR xdr = {0};
	size_t aclblobsize;
	DATA_BLOB blob;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	if (config->nfs_version == ACL4_XATTR_VERSION_40) {
		ok = smb4acl_to_nfs40acl(handle, mem_ctx, smb4acl, &nacl40);
		if (!ok) {
			DBG_ERR("smb4acl_to_nfs4acl failed\n");
			return NT_STATUS_INTERNAL_ERROR;
		}

		aclblobsize = nfs40acl_get_xdrblob_size(nacl40);
		if (aclblobsize == 0) {
			DBG_ERR("Error calculating XDR blob size\n");
			return NT_STATUS_INTERNAL_ERROR;
		}
	} else {
		ok = smb4acl_to_nfs41acl(handle, mem_ctx, smb4acl, &nacl41);
		if (!ok) {
			DBG_ERR("smb4acl_to_nfs4acl failed\n");
			return NT_STATUS_INTERNAL_ERROR;
		}

		aclblobsize = nfs41acl_get_xdrblob_size(nacl41);
		if (aclblobsize == 0) {
			DBG_ERR("Error calculating XDR blob size\n");
			return NT_STATUS_INTERNAL_ERROR;
		}
	}

	blob = data_blob_talloc(mem_ctx, NULL, aclblobsize);
	if (blob.data == NULL) {
		TALLOC_FREE(nacl40);
		TALLOC_FREE(nacl41);
		return NT_STATUS_NO_MEMORY;
	}

	xdrmem_create(&xdr, (char *)blob.data, blob.length, XDR_ENCODE);

	if (config->nfs_version == ACL4_XATTR_VERSION_40) {
		ok = xdr_nfsacl40(&xdr, nacl40);
		TALLOC_FREE(nacl40);
		if (!ok) {
			DBG_ERR("xdr_nfs4acl40 failed\n");
			return NT_STATUS_NO_MEMORY;
		}
	} else {
		ok = xdr_nfsacl41(&xdr, nacl41);
		TALLOC_FREE(nacl41);
		if (!ok) {
			DBG_ERR("xdr_nfs4acl40 failed\n");
			return NT_STATUS_NO_MEMORY;
		}
	}

	*_blob = blob;
	return NT_STATUS_OK;
}

static NTSTATUS nfs4acl_nfs_blob_to_nfs40acl(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     DATA_BLOB *blob,
					     nfsacl40 **_nacl)
{
	nfsacl40 *nacl = NULL;
	XDR xdr = {0};
	bool ok;

	nacl = talloc_zero_size(mem_ctx, sizeof(nfsacl40));
	if (nacl == NULL) {
		DBG_ERR("talloc_zero_size failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	xdrmem_create(&xdr, (char *)blob->data, blob->length, XDR_DECODE);

	ok = xdr_nfsacl40(&xdr, nacl);
	if (!ok) {
		DBG_ERR("xdr_nfsacl40 failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	DBG_DEBUG("naces = %d \n", nacl->na40_aces.na40_aces_len);

	*_nacl = nacl;
	return NT_STATUS_OK;
}

static NTSTATUS nfs4acl_nfs_blob_to_nfs41acl(struct vfs_handle_struct *handle,
					     TALLOC_CTX *mem_ctx,
					     DATA_BLOB *blob,
					     nfsacl41 **_nacl)
{
	nfsacl41 *nacl = NULL;
	XDR xdr = {0};
	bool ok;

	nacl = talloc_zero_size(mem_ctx, sizeof(nfsacl41));
	if (nacl == NULL) {
		DBG_ERR("talloc_zero_size failed\n");
		return NT_STATUS_NO_MEMORY;
	}

	xdrmem_create(&xdr, (char *)blob->data, blob->length, XDR_DECODE);

	ok = xdr_nfsacl41(&xdr, nacl);
	if (!ok) {
		DBG_ERR("xdr_nfsacl40 failed\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	DBG_DEBUG("naces = %d \n", nacl->na41_aces.na41_aces_len);

	*_nacl = nacl;
	return NT_STATUS_OK;
}

static bool map_ace_nfs4_to_smb4(struct nfs4acl_config *config,
				 const nfsace4 *nace,
				 SMB_ACE4PROP_T *sace)
{
	char *name = NULL;
	char *p = NULL;
	uint32_t smb4_id;
	bool ok;

	name = talloc_strndup(talloc_tos(),
			      nace->who.utf8string_val,
			      nace->who.utf8string_len);
	if (name == NULL) {
		return false;
	}

	sace->aceType = nace->type;
	sace->aceFlags = nace->flag;
	sace->aceMask = nace->access_mask;

	if (is_special_nfs4_id(name)) {
		ok = map_special_nfs4_to_smb4_id(name, &smb4_id);
		if (!ok) {
			DBG_WARNING("Unknown special id [%s]\n", name);
			return false;
		}
		sace->flags |= SMB_ACE4_ID_SPECIAL;
		sace->who.special_id = smb4_id;
		return true;
	}

	p = strtok(name, "@");
	if (p == NULL && !config->nfs4_id_numeric) {
		DBG_ERR("Unqualified name [%s]\n", name);
		TALLOC_FREE(name);
		return false;
	}

	/*
	 * nametouid() and nametogid() work with both names and numbers...
	 */

	if (nace->flag & ACE4_IDENTIFIER_GROUP) {
		sace->who.gid = nametogid(name);
		if (sace->who.gid == (gid_t)-1) {
			DBG_ERR("converting id [%s] failed\n", name);
			TALLOC_FREE(name);
			return false;
		}
		TALLOC_FREE(name);
		return true;
	}

	sace->who.uid = nametouid(name);
	if (sace->who.uid == (gid_t)-1) {
		DBG_ERR("converting id [%s] failed\n", name);
		TALLOC_FREE(name);
		return false;
	}
	TALLOC_FREE(name);
	return true;
}

static NTSTATUS nfs40acl_to_smb4acl(struct vfs_handle_struct *handle,
				   TALLOC_CTX *mem_ctx,
				   nfsacl40 *nacl,
				   struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	unsigned naces = nfs40acl_get_naces(nacl);
	unsigned int i;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	smb4acl = smb_create_smb4acl(mem_ctx);
	if (smb4acl == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	DBG_DEBUG("nace [%u]\n", naces);

	for (i = 0; i < naces; i++) {
		nfsace4 *nace = nfs40acl_get_ace(nacl, i);
		SMB_ACE4PROP_T sace = { 0 };

		DBG_DEBUG("type [%d] flag [%x] mask [%x] who [%*s]\n",
			  nace->type, nace->flag,
			  nace->access_mask,
			  nace->who.utf8string_len,
			  nace->who.utf8string_val);

		ok = map_ace_nfs4_to_smb4(config, nace, &sace);
		if (!ok) {
			continue;
		}

		smb_add_ace4(smb4acl, &sace);
	}

	*_smb4acl = smb4acl;
	return NT_STATUS_OK;
}

static NTSTATUS nfs41acl_to_smb4acl(struct vfs_handle_struct *handle,
				   TALLOC_CTX *mem_ctx,
				   nfsacl41 *nacl,
				   struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	unsigned nfsacl41_flag = 0;
	uint16_t smb4acl_flags = 0;
	unsigned naces = nfs41acl_get_naces(nacl);
	unsigned int i;
	bool ok;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	smb4acl = smb_create_smb4acl(mem_ctx);
	if (smb4acl == NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	nfsacl41_flag = nfs41acl_get_flags(nacl);
	smb4acl_flags = nfs4acl_to_smb4acl_flags(nfsacl41_flag);
	smbacl4_set_controlflags(smb4acl, smb4acl_flags);

	DBG_DEBUG("flags [%x] nace [%u]\n", smb4acl_flags, naces);

	for (i = 0; i < naces; i++) {
		nfsace4 *nace = nfs41acl_get_ace(nacl, i);
		SMB_ACE4PROP_T sace = { 0 };

		DBG_DEBUG("type [%d] flag [%x] mask [%x] who [%*s]\n",
			  nace->type, nace->flag,
			  nace->access_mask,
			  nace->who.utf8string_len,
			  nace->who.utf8string_val);

		ok = map_ace_nfs4_to_smb4(config, nace, &sace);
		if (!ok) {
			continue;
		}

		smb_add_ace4(smb4acl, &sace);
	}

	*_smb4acl = smb4acl;
	return NT_STATUS_OK;
}

NTSTATUS nfs4acl_nfs_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl)
{
	struct nfs4acl_config *config = NULL;
	struct SMB4ACL_T *smb4acl = NULL;
	NTSTATUS status;

	SMB_VFS_HANDLE_GET_DATA(handle, config,
				struct nfs4acl_config,
				return NT_STATUS_INTERNAL_ERROR);

	if (config->nfs_version == ACL4_XATTR_VERSION_40) {
		nfsacl40 *nacl = NULL;

		status = nfs4acl_nfs_blob_to_nfs40acl(handle,
						      talloc_tos(),
						      blob,
						      &nacl);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = nfs40acl_to_smb4acl(handle, mem_ctx, nacl, &smb4acl);
		TALLOC_FREE(nacl);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	} else {
		nfsacl41 *nacl = NULL;

		status = nfs4acl_nfs_blob_to_nfs41acl(handle,
						      talloc_tos(),
						      blob,
						      &nacl);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = nfs41acl_to_smb4acl(handle, mem_ctx, nacl, &smb4acl);
		TALLOC_FREE(nacl);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	*_smb4acl = smb4acl;
	return NT_STATUS_OK;
}

#else /* !HAVE_RPC_XDR_H */
#include "nfs4acl_xattr_nfs.h"
NTSTATUS nfs4acl_nfs_blob_to_smb4(struct vfs_handle_struct *handle,
				  TALLOC_CTX *mem_ctx,
				  DATA_BLOB *blob,
				  struct SMB4ACL_T **_smb4acl)
{
	return NT_STATUS_NOT_SUPPORTED;
}

NTSTATUS nfs4acl_smb4acl_to_nfs_blob(vfs_handle_struct *handle,
				     TALLOC_CTX *mem_ctx,
				     struct SMB4ACL_T *smbacl,
				     DATA_BLOB *blob)
{
	return NT_STATUS_NOT_SUPPORTED;
}
#endif /* HAVE_RPC_XDR_H */
