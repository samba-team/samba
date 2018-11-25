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
#include "libcli/security/security_descriptor.h"

#ifdef HAVE_RPC_XDR_H
/* <rpc/xdr.h> uses TRUE and FALSE */
#ifdef TRUE
#undef TRUE
#endif

#ifdef FALSE
#undef FALSE
#endif
#endif

#include "nfs4_acls.h"
#include "nfs41acl.h"
#include "nfs4acl_xattr_util.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_VFS

unsigned smb4acl_to_nfs4acl_flags(uint16_t smb4acl_flags)
{
	unsigned nfs4acl_flags = 0;

	if (smb4acl_flags & SEC_DESC_DACL_AUTO_INHERITED) {
		nfs4acl_flags |= ACL4_AUTO_INHERIT;
	}
	if (smb4acl_flags & SEC_DESC_DACL_PROTECTED) {
		nfs4acl_flags |= ACL4_PROTECTED;
	}
	if (smb4acl_flags & SEC_DESC_DACL_DEFAULTED) {
		nfs4acl_flags |= ACL4_DEFAULTED;
	}

	return nfs4acl_flags;
}

uint16_t nfs4acl_to_smb4acl_flags(unsigned nfsacl41_flags)
{
	uint16_t smb4acl_flags = SEC_DESC_SELF_RELATIVE;

	if (nfsacl41_flags & ACL4_AUTO_INHERIT) {
		smb4acl_flags |= SEC_DESC_DACL_AUTO_INHERITED;
	}
	if (nfsacl41_flags & ACL4_PROTECTED) {
		smb4acl_flags |= SEC_DESC_DACL_PROTECTED;
	}
	if (nfsacl41_flags & ACL4_DEFAULTED) {
		smb4acl_flags |= SEC_DESC_DACL_DEFAULTED;
	}

	return smb4acl_flags;
}
