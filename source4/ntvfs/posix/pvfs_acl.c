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
	int i;
	struct security_ace ace;
	NTSTATUS status;
	const char *sid_names[] = {
		SID_BUILTIN_ADMINISTRATORS,
		SID_CREATOR_OWNER,
		SID_CREATOR_GROUP,
		SID_WORLD
	};
	uint32_t access_masks[4];
	mode_t mode;

	sd = security_descriptor_initialise(req);
	if (sd == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = sidmap_uid_to_sid(pvfs->sidmap, sd, name->st.st_uid, &sd->owner_sid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	status = sidmap_gid_to_sid(pvfs->sidmap, sd, name->st.st_gid, &sd->group_sid);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	sd->type |= SEC_DESC_DACL_PRESENT;

	/*
	  we provide 4 ACEs
	    - Administrator
	    - Owner
	    - Group
	    - Everyone
	 */
	access_masks[0] = SEC_RIGHTS_FULL_CTRL | STD_RIGHT_ALL_ACCESS;
	access_masks[1] = 0;
	access_masks[2] = 0;
	access_masks[3] = 0;

	mode = name->st.st_mode;

	if (mode & S_IRUSR) {
		access_masks[1] |= 
			SA_RIGHT_FILE_READ_DATA | 
			SA_RIGHT_FILE_READ_EA |
			SA_RIGHT_FILE_READ_ATTRIBUTES |
			SA_RIGHT_FILE_EXECUTE |
			STD_RIGHT_SYNCHRONIZE_ACCESS |
			STD_RIGHT_READ_CONTROL_ACCESS;
	}
	if (mode & S_IWUSR) {
		access_masks[1] |= 
			SA_RIGHT_FILE_WRITE_DATA | 
			SA_RIGHT_FILE_APPEND_DATA |
			SA_RIGHT_FILE_WRITE_EA |
			SA_RIGHT_FILE_WRITE_ATTRIBUTES |
			STD_RIGHT_DELETE_ACCESS;
	}

	if (mode & S_IRGRP) {
		access_masks[2] |= 
			SA_RIGHT_FILE_READ_DATA | 
			SA_RIGHT_FILE_READ_EA |
			SA_RIGHT_FILE_READ_ATTRIBUTES |
			SA_RIGHT_FILE_EXECUTE |
			STD_RIGHT_SYNCHRONIZE_ACCESS |
			STD_RIGHT_READ_CONTROL_ACCESS;
	}
	if (mode & S_IWGRP) {
		access_masks[2] |= 
			SA_RIGHT_FILE_WRITE_DATA | 
			SA_RIGHT_FILE_APPEND_DATA |
			SA_RIGHT_FILE_WRITE_EA |
			SA_RIGHT_FILE_WRITE_ATTRIBUTES;
	}

	if (mode & S_IROTH) {
		access_masks[3] |= 
			SA_RIGHT_FILE_READ_DATA | 
			SA_RIGHT_FILE_READ_EA |
			SA_RIGHT_FILE_READ_ATTRIBUTES |
			SA_RIGHT_FILE_EXECUTE |
			STD_RIGHT_SYNCHRONIZE_ACCESS |
			STD_RIGHT_READ_CONTROL_ACCESS;
	}
	if (mode & S_IWOTH) {
		access_masks[3] |= 
			SA_RIGHT_FILE_WRITE_DATA | 
			SA_RIGHT_FILE_APPEND_DATA |
			SA_RIGHT_FILE_WRITE_EA |
			SA_RIGHT_FILE_WRITE_ATTRIBUTES;
	}

	ace.type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	ace.flags = 0;

	for (i=0;i<ARRAY_SIZE(sid_names);i++) {
		struct dom_sid *sid;

		ace.access_mask = access_masks[i];

		sid = dom_sid_parse_talloc(sd, sid_names[i]);
		if (sid == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		ace.trustee = *sid;

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

