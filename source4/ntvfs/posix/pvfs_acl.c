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
  map a single access_mask from generic to specific bits for files/dirs
*/
static uint32_t pvfs_translate_mask(uint32_t access_mask)
{
	if (access_mask & SEC_MASK_GENERIC) {
		if (access_mask & SEC_GENERIC_READ)    access_mask |= SEC_RIGHTS_FILE_READ;
		if (access_mask & SEC_GENERIC_WRITE)   access_mask |= SEC_RIGHTS_FILE_WRITE;
		if (access_mask & SEC_GENERIC_EXECUTE) access_mask |= SEC_RIGHTS_FILE_EXECUTE;
		if (access_mask & SEC_GENERIC_ALL)     access_mask |= SEC_RIGHTS_FILE_ALL;
		access_mask &= ~SEC_MASK_GENERIC;
	}
	return access_mask;
}


/*
  map any generic access bits in the given acl
  this relies on the fact that the mappings for files and directories
  are the same
*/
static void pvfs_translate_generic_bits(struct security_acl *acl)
{
	unsigned i;

	for (i=0;i<acl->num_aces;i++) {
		struct security_ace *ace = &acl->aces[i];
		ace->access_mask = pvfs_translate_mask(ace->access_mask);
	}
}


/*
  setup a default ACL for a file
*/
static NTSTATUS pvfs_default_acl(struct pvfs_state *pvfs,
				 struct smbsrv_request *req,
				 struct pvfs_filename *name, int fd, 
				 struct xattr_NTACL *acl)
{
	struct security_descriptor *sd;
	NTSTATUS status;
	struct security_ace aces[4];
	mode_t mode;
	struct dom_sid *sid;
	int i;

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
	aces[0].access_mask = SEC_RIGHTS_FILE_ALL;
	aces[1].access_mask = 0;
	aces[2].access_mask = 0;
	aces[3].access_mask = 0;

	mode = name->st.st_mode;

	if (mode & S_IRUSR) {
		aces[1].access_mask |= 
			SEC_FILE_READ_DATA | 
			SEC_FILE_READ_EA |
			SEC_FILE_READ_ATTRIBUTE |
			SEC_FILE_EXECUTE |
			SEC_STD_SYNCHRONIZE |
			SEC_STD_READ_CONTROL;
	}
	if (mode & S_IWUSR) {
		aces[1].access_mask |= 
			SEC_FILE_WRITE_DATA | 
			SEC_FILE_APPEND_DATA |
			SEC_FILE_WRITE_EA |
			SEC_FILE_WRITE_ATTRIBUTE |
			SEC_STD_DELETE;
	}

	if (mode & S_IRGRP) {
		aces[2].access_mask |= 
			SEC_FILE_READ_DATA | 
			SEC_FILE_READ_EA |
			SEC_FILE_READ_ATTRIBUTE |
			SEC_FILE_EXECUTE |
			SEC_STD_SYNCHRONIZE |
			SEC_STD_READ_CONTROL;
	}
	if (mode & S_IWGRP) {
		aces[2].access_mask |= 
			SEC_FILE_WRITE_DATA | 
			SEC_FILE_APPEND_DATA |
			SEC_FILE_WRITE_EA |
			SEC_FILE_WRITE_ATTRIBUTE;
	}

	if (mode & S_IROTH) {
		aces[3].access_mask |= 
			SEC_FILE_READ_DATA | 
			SEC_FILE_READ_EA |
			SEC_FILE_READ_ATTRIBUTE |
			SEC_FILE_EXECUTE |
			SEC_STD_SYNCHRONIZE |
			SEC_STD_READ_CONTROL;
	}
	if (mode & S_IWOTH) {
		aces[3].access_mask |= 
			SEC_FILE_WRITE_DATA | 
			SEC_FILE_APPEND_DATA |
			SEC_FILE_WRITE_EA |
			SEC_FILE_WRITE_ATTRIBUTE;
	}

	sid = dom_sid_parse_talloc(sd, SID_BUILTIN_ADMINISTRATORS);
	if (sid == NULL) return NT_STATUS_NO_MEMORY;

	aces[0].type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	aces[0].flags = 0;
	aces[0].trustee = *sid;

	aces[1].type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	aces[1].flags = 0;
	aces[1].trustee = *sd->owner_sid;

	aces[2].type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	aces[2].flags = 0;
	aces[2].trustee = *sd->group_sid;

	sid = dom_sid_parse_talloc(sd, SID_WORLD);
	if (sid == NULL) return NT_STATUS_NO_MEMORY;

	aces[3].type = SEC_ACE_TYPE_ACCESS_ALLOWED;
	aces[3].flags = 0;
	aces[3].trustee = *sid;

	for (i=0;i<4;i++) {
		security_descriptor_dacl_add(sd, &aces[i]);
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
	if (!(secinfo_flags & SECINFO_OWNER)) {
		sd->owner_sid = NULL;
	}
	if (!(secinfo_flags & SECINFO_GROUP)) {
		sd->group_sid = NULL;
	}
	if (!(secinfo_flags & SECINFO_DACL)) {
		sd->dacl = NULL;
	}
	if (!(secinfo_flags & SECINFO_SACL)) {
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
		return NT_STATUS_INVALID_ACL;
	}

	new_sd = info->set_secdesc.in.sd;

	/* only set the elements that have been specified */
	if (secinfo_flags & SECINFO_OWNER) {
		sd->owner_sid = new_sd->owner_sid;
	}
	if (secinfo_flags & SECINFO_GROUP) {
		sd->group_sid = new_sd->group_sid;
	}
	if (secinfo_flags & SECINFO_DACL) {
		sd->dacl = new_sd->dacl;
		pvfs_translate_generic_bits(sd->dacl);
	}
	if (secinfo_flags & SECINFO_SACL) {
		sd->sacl = new_sd->sacl;
		pvfs_translate_generic_bits(sd->sacl);
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
		return NT_STATUS_INVALID_ACL;
	}

	normalise_sd_flags(sd, info->query_secdesc.in.secinfo_flags);

	info->query_secdesc.out.sd = sd;

	return NT_STATUS_OK;
}


/*
  default access check function based on unix permissions
  doing this saves on building a full security descriptor
  for the common case of access check on files with no 
  specific NT ACL
*/
NTSTATUS pvfs_access_check_unix(struct pvfs_state *pvfs, 
				struct smbsrv_request *req,
				struct pvfs_filename *name,
				uint32_t *access_mask)
{
	uid_t uid = geteuid();
	uint32_t max_bits = SEC_RIGHTS_FILE_READ | SEC_FILE_ALL;

	/* owner and root get extra permissions */
	if (uid == 0 || uid == name->st.st_uid) {
		max_bits |= SEC_STD_ALL;
	}

	if (*access_mask == SEC_FLAG_MAXIMUM_ALLOWED) {
		*access_mask = max_bits;
		return NT_STATUS_OK;
	}

	if (*access_mask & ~max_bits) {
		return NT_STATUS_ACCESS_DENIED;
	}

	return NT_STATUS_OK;
}


/*
  check the security descriptor on a file, if any
  
  *access_mask is modified with the access actually granted
*/
NTSTATUS pvfs_access_check(struct pvfs_state *pvfs, 
			   struct smbsrv_request *req,
			   struct pvfs_filename *name,
			   uint32_t *access_mask)
{
	struct security_token *token = req->session->session_info->security_token;
	struct xattr_NTACL *acl;
	NTSTATUS status;
	struct security_descriptor *sd;

	acl = talloc_p(req, struct xattr_NTACL);
	if (acl == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	status = pvfs_acl_load(pvfs, name, -1, acl);
	if (NT_STATUS_EQUAL(status, NT_STATUS_NOT_FOUND)) {
		talloc_free(acl);
		return pvfs_access_check_unix(pvfs, req, name, access_mask);
	}
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	switch (acl->version) {
	case 1:
		sd = acl->info.sd;
		break;
	default:
		return NT_STATUS_INVALID_ACL;
	}

	/* expand the generic access bits to file specific bits */
	*access_mask = pvfs_translate_mask(*access_mask);

	/* check the acl against the required access mask */
	status = sec_access_check(sd, token, *access_mask, access_mask);

	/* this bit is always granted, even if not asked for */
	*access_mask |= SEC_FILE_READ_ATTRIBUTE;

	talloc_free(acl);
	
	return status;
}
