/* 
   Unix SMB/CIFS implementation.

   security descriptror utility functions

   Copyright (C) Andrew Tridgell 		2004
      
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
#include "librpc/gen_ndr/ndr_security.h"

/*
  return a blank security descriptor (no owners, dacl or sacl)
*/
struct security_descriptor *security_descriptor_initialise(TALLOC_CTX *mem_ctx)
{
	struct security_descriptor *sd;

	sd = talloc_p(mem_ctx, struct security_descriptor);
	if (!sd) {
		return NULL;
	}

	sd->revision = SD_REVISION;
	/* we mark as self relative, even though it isn't while it remains
	   a pointer in memory because this simplifies the ndr code later.
	   All SDs that we store/emit are in fact SELF_RELATIVE
	*/
	sd->type = SEC_DESC_SELF_RELATIVE;

	sd->owner_sid = NULL;
	sd->group_sid = NULL;
	sd->sacl = NULL;
	sd->dacl = NULL;

	return sd;
}

/* 
   talloc and copy a security descriptor
 */
struct security_descriptor *security_descriptor_copy(TALLOC_CTX *mem_ctx, 
						     const struct security_descriptor *osd)
{
	struct security_descriptor *nsd;

	/* FIXME */
	DEBUG(1, ("security_descriptor_copy(): sorry unimplemented yet\n"));
	nsd = NULL;

	return nsd;
}

NTSTATUS security_check_dacl(struct security_token *st, 
			     struct security_descriptor *sd, 
			     uint32 access_mask)
{
	size_t i,y;
	NTSTATUS status = NT_STATUS_ACCESS_DENIED;

	DEBUG(1, ("security_check_dacl(): sorry untested yet\n"));
	return status;

	if (!sd->dacl) {
		return NT_STATUS_INVALID_ACL;
	}

	for (i=0; i < st->num_sids; i++) {
		for (y=0; y < sd->dacl->num_aces; y++) {
			if (dom_sid_equal(&st->sids[i], &sd->dacl->aces[y].trustee)) {
				switch (sd->dacl->aces[y].type) {
					case SEC_ACE_TYPE_ACCESS_ALLOWED:
						if (access_mask & sd->dacl->aces[y].access_mask) {
							status = NT_STATUS_OK;
						}
						break;
					case SEC_ACE_TYPE_ACCESS_DENIED:
						if (access_mask & sd->dacl->aces[y].access_mask) {
							return NT_STATUS_ACCESS_DENIED;
						}
						break;
					default:
						return NT_STATUS_INVALID_ACL;
				}
			}
		}
	}

	return status;
}


/*
  add an ACE to the DACL of a security_descriptor
*/
NTSTATUS security_descriptor_dacl_add(struct security_descriptor *sd, 
				      const struct security_ace *ace)
{
	if (sd->dacl == NULL) {
		sd->dacl = talloc_p(sd, struct security_acl);
		if (sd->dacl == NULL) {
			return NT_STATUS_NO_MEMORY;
		}
		sd->dacl->revision = NT4_ACL_REVISION;
		sd->dacl->size     = 0;
		sd->dacl->num_aces = 0;
		sd->dacl->aces     = NULL;
	}

	sd->dacl->aces = talloc_realloc_p(sd->dacl, sd->dacl->aces, 
					  struct security_ace, sd->dacl->num_aces+1);
	if (sd->dacl->aces == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	sd->dacl->aces[sd->dacl->num_aces] = *ace;
	sd->dacl->aces[sd->dacl->num_aces].trustee.sub_auths = 
		talloc_memdup(sd->dacl->aces, 
			      sd->dacl->aces[sd->dacl->num_aces].trustee.sub_auths,
			      sizeof(uint32_t) * 
			      sd->dacl->aces[sd->dacl->num_aces].trustee.num_auths);
	if (sd->dacl->aces[sd->dacl->num_aces].trustee.sub_auths == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	
	sd->dacl->num_aces++;

	return NT_STATUS_OK;
}


/*
  delete the ACE corresponding to the given trustee in the DACL of a security_descriptor
*/
NTSTATUS security_descriptor_dacl_del(struct security_descriptor *sd, 
				      struct dom_sid *trustee)
{
	int i;

	if (sd->dacl == NULL) {
		return NT_STATUS_OBJECT_NAME_NOT_FOUND;
	}
	
	for (i=0;i<sd->dacl->num_aces;i++) {
		if (dom_sid_equal(trustee, &sd->dacl->aces[i].trustee)) {
			memmove(&sd->dacl->aces[i], &sd->dacl->aces[i+1],
				sizeof(sd->dacl->aces[i]) * (sd->dacl->num_aces - (i+1)));
			sd->dacl->num_aces--;
			if (sd->dacl->num_aces == 0) {
				sd->dacl->aces = NULL;
			}
			return NT_STATUS_OK;
		}
	}
	return NT_STATUS_OBJECT_NAME_NOT_FOUND;
}


/*
  compare two security ace structures
*/
BOOL security_ace_equal(const struct security_ace *ace1, 
			const struct security_ace *ace2)
{
	if (ace1 == ace2) return True;
	if (!ace1 || !ace2) return False;
	if (ace1->type != ace2->type) return False;
	if (ace1->flags != ace2->flags) return False;
	if (ace1->access_mask != ace2->access_mask) return False;
	if (!dom_sid_equal(&ace1->trustee, &ace2->trustee)) return False;

	return True;	
}


/*
  compare two security acl structures
*/
BOOL security_acl_equal(const struct security_acl *acl1, 
			const struct security_acl *acl2)
{
	int i;

	if (acl1 == acl2) return True;
	if (!acl1 || !acl2) return False;
	if (acl1->revision != acl2->revision) return False;
	if (acl1->num_aces != acl2->num_aces) return False;

	for (i=0;i<acl1->num_aces;i++) {
		if (!security_ace_equal(&acl1->aces[i], &acl2->aces[i])) return False;
	}
	return True;	
}

/*
  compare two security descriptors.
*/
BOOL security_descriptor_equal(const struct security_descriptor *sd1, 
			       const struct security_descriptor *sd2)
{
	if (sd1 == sd2) return True;
	if (!sd1 || !sd2) return False;
	if (sd1->revision != sd2->revision) return False;
	if (sd1->type != sd2->type) return False;

	if (!dom_sid_equal(sd1->owner_sid, sd2->owner_sid)) return False;
	if (!dom_sid_equal(sd1->group_sid, sd2->group_sid)) return False;
	if (!security_acl_equal(sd1->sacl, sd2->sacl))      return False;
	if (!security_acl_equal(sd1->dacl, sd2->dacl))      return False;

	return True;	
}
