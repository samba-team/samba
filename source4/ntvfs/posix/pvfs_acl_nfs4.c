/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - NT ACLs mapped to NFS4 ACLs, as per
   http://www.suse.de/~agruen/nfs4acl/

   Copyright (C) Andrew Tridgell 2006

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "vfs_posix.h"
#include "lib/util/unix_privs.h"
#include "librpc/gen_ndr/ndr_nfs4acl.h"
#include "libcli/security/security.h"

#define ACE4_IDENTIFIER_GROUP 0x40

/*
  load the current ACL from system.nfs4acl
*/
static NTSTATUS pvfs_acl_load_nfs4(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd,
				   TALLOC_CTX *mem_ctx,
				   struct security_descriptor **psd)
{
	NTSTATUS status;
	struct nfs4acl *acl;
	struct security_descriptor *sd;
	int i;

	acl = talloc_zero(mem_ctx, struct nfs4acl);
	NT_STATUS_HAVE_NO_MEMORY(acl);

	status = pvfs_xattr_ndr_load(pvfs, mem_ctx, name->full_name, fd, 
				     NFS4ACL_XATTR_NAME,
				     acl, ndr_pull_nfs4acl);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(acl);
		return status;
	}

	*psd = security_descriptor_initialise(mem_ctx);
	NT_STATUS_HAVE_NO_MEMORY(*psd);

	sd = *psd;

	sd->type |= acl->a_flags;
	status = sidmap_uid_to_sid(pvfs->sidmap, sd, name->st.st_uid, &sd->owner_sid);
	NT_STATUS_NOT_OK_RETURN(status);
	status = sidmap_gid_to_sid(pvfs->sidmap, sd, name->st.st_gid, &sd->group_sid);
	NT_STATUS_NOT_OK_RETURN(status);

	for (i=0;i<acl->a_count;i++) {
		struct nfs4ace *a = &acl->ace[i];
		struct security_ace ace;
		struct dom_sid *sid;
		ace.type = a->e_type;
		ace.flags = a->e_flags;
		ace.access_mask = a->e_mask;
		if (a->e_flags & ACE4_IDENTIFIER_GROUP) {
			status = sidmap_gid_to_sid(pvfs->sidmap, sd, a->e_id, &sid);
		} else {
			status = sidmap_uid_to_sid(pvfs->sidmap, sd, a->e_id, &sid);
		}
		NT_STATUS_NOT_OK_RETURN(status);
		ace.trustee = *sid;
		security_descriptor_dacl_add(sd, &ace);
	}

	return NT_STATUS_OK;
}

/*
  save the acl for a file into system.nfs4acl
*/
static NTSTATUS pvfs_acl_save_nfs4(struct pvfs_state *pvfs, struct pvfs_filename *name, int fd,
				   struct security_descriptor *sd)
{
	NTSTATUS status;
	void *privs;
	struct nfs4acl acl;
	int i;
	TALLOC_CTX *tmp_ctx;

	tmp_ctx = talloc_new(pvfs);
	NT_STATUS_HAVE_NO_MEMORY(tmp_ctx);

	acl.a_version = 0;
	acl.a_flags   = sd->type;
	acl.a_count   = sd->dacl?sd->dacl->num_aces:0;
	acl.a_owner_mask = 0;
	acl.a_group_mask = 0;
	acl.a_other_mask = 0;

	acl.ace = talloc_array(tmp_ctx, struct nfs4ace, acl.a_count);
	if (!acl.ace) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<acl.a_count;i++) {
		struct nfs4ace *a = &acl.ace[i];
		struct security_ace *ace = &sd->dacl->aces[i];
		a->e_type  = ace->type;
		a->e_flags = ace->flags;
		a->e_mask  = ace->access_mask;
		if (sidmap_sid_is_group(pvfs->sidmap, &ace->trustee)) {
			gid_t gid;
			a->e_flags |= ACE4_IDENTIFIER_GROUP;
			status = sidmap_sid_to_unixgid(pvfs->sidmap, &ace->trustee, &gid);
			if (!NT_STATUS_IS_OK(status)) {
				talloc_free(tmp_ctx);
				return status;
			}
			a->e_id = gid;
		} else {
			uid_t uid;
			status = sidmap_sid_to_unixuid(pvfs->sidmap, &ace->trustee, &uid);
			if (!NT_STATUS_IS_OK(status)) {
				talloc_free(tmp_ctx);
				return status;
			}
			a->e_id = uid;
		}
		a->e_who   = "";
	}

	privs = root_privileges();
	status = pvfs_xattr_ndr_save(pvfs, name->full_name, fd, 
				     NFS4ACL_XATTR_NAME, 
				     &acl, ndr_push_nfs4acl);
	talloc_free(privs);

	talloc_free(tmp_ctx);
	return status;
}


/*
  initialise pvfs acl NFS4 backend
*/
NTSTATUS pvfs_acl_nfs4_init(void)
{
	struct pvfs_acl_ops ops = {
		.name = "nfs4acl",
		.acl_load = pvfs_acl_load_nfs4,
		.acl_save = pvfs_acl_save_nfs4
	};
	return pvfs_acl_register(&ops);
}
