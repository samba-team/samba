/* 
   Unix SMB/CIFS implementation.

   POSIX NTVFS backend - ACL support

   Copyright (C) Andrew Tridgell 2004

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "auth/auth.h"
#include "system/filesys.h"
#include "vfs_posix.h"
#include "librpc/gen_ndr/ndr_xattr.h"


/*
  setup a default ACL for a file
*/
static NTSTATUS pvfs_default_acl(struct pvfs_state *pvfs,
				 struct smbsrv_request *req,
				 struct pvfs_filename *name, int fd, 
				 struct xattr_NTACL *acl)
{
	struct security_descriptor *sd;
	struct nt_user_token *token = req->session->session_info->nt_user_token;
	int i;

	sd = security_descriptor_initialise(req);
	if (sd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	/* nasty hack to get a reasonable sec desc - should be based on posix uid/gid
	   and perms */
	if (token->num_sids > 0) {
		sd->owner_sid = token->user_sids[0];
	}
	if (token->num_sids > 1) {
		sd->group_sid = token->user_sids[1];
	}

	for (i=0;i<token->num_sids;i++) {
		struct security_ace ace;
		NTSTATUS status;

		ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
		ace.flags = 0;
		ace.access_mask = SEC_RIGHTS_FULL_CTRL | STD_RIGHT_ALL_ACCESS;
		ace.trustee = *token->user_sids[i];

		status = security_descriptor_dacl_add(sd, &ace);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}
	
	acl->version = 1;
	acl->info.sd = sd;

	return NT_STATUS_OK;
}
				 

/*
  omit any security_descriptor elements not specified in the given
  secinfo flags
*/
static void normalise_sd_flags(struct security_descriptor *sd, uint32_t secinfo_flags)
{
	if (!(secinfo_flags & OWNER_SECURITY_INFORMATION)) {
		sd->owner_sid = NULL;
	}
	if (!(secinfo_flags & GROUP_SECURITY_INFORMATION)) {
		sd->group_sid = NULL;
	}
	if (!(secinfo_flags & DACL_SECURITY_INFORMATION)) {
		sd->dacl = NULL;
	}
	if (!(secinfo_flags & SACL_SECURITY_INFORMATION)) {
		sd->sacl = NULL;
	}
}

/*
  answer a setfileinfo for an ACL
*/
NTSTATUS pvfs_acl_set(struct pvfs_state *pvfs, 
		      struct smbsrv_request *req,
		      struct pvfs_filename *name, int fd, 
		      union smb_setfileinfo *info)
{
	struct xattr_NTACL *acl;
	uint32_t secinfo_flags = info->set_secdesc.in.secinfo_flags;
	struct security_descriptor *new_sd, *sd;
	NTSTATUS status;

	acl = talloc_p(req, struct xattr_NTACL);
	if (acl == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pvfs_acl_load(pvfs, name, fd, acl);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		status = pvfs_default_acl(pvfs, req, name, fd, acl);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch (acl->version) {
	case 1:
		sd = acl->info.sd;
		break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	new_sd = info->set_secdesc.in.sd;

	/* only set the elements that have been specified */
	if (secinfo_flags & OWNER_SECURITY_INFORMATION) {
		sd->owner_sid = new_sd->owner_sid;
	}
	if (secinfo_flags & GROUP_SECURITY_INFORMATION) {
		sd->group_sid = new_sd->group_sid;
	}
	if (secinfo_flags & DACL_SECURITY_INFORMATION) {
		sd->dacl = new_sd->dacl;
	}
	if (secinfo_flags & SACL_SECURITY_INFORMATION) {
		sd->sacl = new_sd->sacl;
	}

	status = pvfs_acl_save(pvfs, name, fd, acl);

	return status;
}


/*
  answer a fileinfo query for the ACL
*/
NTSTATUS pvfs_acl_query(struct pvfs_state *pvfs, 
			struct smbsrv_request *req,
			struct pvfs_filename *name, int fd, 
			union smb_fileinfo *info)
{
	struct xattr_NTACL *acl;
	NTSTATUS status;
	struct security_descriptor *sd;

	acl = talloc_p(req, struct xattr_NTACL);
	if (acl == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pvfs_acl_load(pvfs, name, fd, acl);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		status = pvfs_default_acl(pvfs, req, name, fd, acl);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch (acl->version) {
	case 1:
		sd = acl->info.sd;
		break;
	default:
		return NT_STATUS_INVALID_LEVEL;
	}

	normalise_sd_flags(sd, info->query_secdesc.in.secinfo_flags);

	info->query_secdesc.out.sd = sd;

	return NT_STATUS_OK;
}

