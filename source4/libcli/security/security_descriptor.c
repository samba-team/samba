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

NTSTATUS security_check_dacl(struct security_token *st, struct security_descriptor *sd, uint32 access_mask)
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
