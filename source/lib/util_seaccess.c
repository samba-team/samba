/*
   Unix SMB/Netbios implementation.
   Version 2.0
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000.
   Copyright (C) Tim Potter 2000.
   Copyright (C) Re-written by Jeremy Allison 2000.

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
#include "nterr.h"
#include "sids.h"

/**********************************************************************************
 Check if this ACE has a SID in common with the token.
**********************************************************************************/

static BOOL token_sid_in_ace(const NT_USER_TOKEN *token, const SEC_ACE *ace)
{
	size_t i;

	for (i = 0; i < token->num_sids; i++) {
		if (sid_equal(&ace->trustee, &token->user_sids[i]))
			return True;
	}

	return False;
}

/*********************************************************************************
 Check an ACE against a SID.  We return the remaining needed permission
 bits not yet granted. Zero means permission allowed (no more needed bits).
**********************************************************************************/

static uint32 check_ace(SEC_ACE *ace, NT_USER_TOKEN *token, uint32 acc_desired, 
			NTSTATUS *status)
{
	uint32 mask = ace->info.mask;

	/*
	 * Inherit only is ignored.
	 */

	if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY) {
		return acc_desired;
	}

	/*
	 * If this ACE has no SID in common with the token,
	 * ignore it as it cannot be used to make an access
	 * determination.
	 */

	if (!token_sid_in_ace( token, ace))
		return acc_desired;	

	switch (ace->type) {
		case SEC_ACE_TYPE_ACCESS_ALLOWED:
			/*
			 * This is explicitly allowed.
			 * Remove the bits from the remaining
			 * access required. Return the remaining
			 * bits needed.
			 */
			acc_desired &= ~mask;
			break;
		case SEC_ACE_TYPE_ACCESS_DENIED:
			/*
			 * This is explicitly denied.
			 * If any bits match terminate here,
			 * we are denied.
			 */
			if (acc_desired & mask) {
				*status = NT_STATUS_ACCESS_DENIED;
				return 0xFFFFFFFF;
			}
			break;
		case SEC_ACE_TYPE_SYSTEM_ALARM:
		case SEC_ACE_TYPE_SYSTEM_AUDIT:
			*status = NT_STATUS_NOT_IMPLEMENTED;
			return 0xFFFFFFFF;
		default:
			*status = NT_STATUS_INVALID_PARAMETER;
			return 0xFFFFFFFF;
	}

	return acc_desired;
}

/*********************************************************************************
 Maximum access was requested. Calculate the max possible. Fail if it doesn't
 include other bits requested.
**********************************************************************************/ 

static BOOL get_max_access( SEC_ACL *the_acl, NT_USER_TOKEN *token, uint32 *granted, 
			    uint32 desired, 
			    NTSTATUS *status)
{
	uint32 acc_denied = 0;
	uint32 acc_granted = 0;
	size_t i;
	
	for ( i = 0 ; i < the_acl->num_aces; i++) {
		SEC_ACE *ace = &the_acl->ace[i];
		uint32 mask = ace->info.mask;

		if (!token_sid_in_ace( token, ace))
			continue;

		switch (ace->type) {
			case SEC_ACE_TYPE_ACCESS_ALLOWED:
				acc_granted |= (mask & ~acc_denied);
				break;
			case SEC_ACE_TYPE_ACCESS_DENIED:
				acc_denied |= (mask & ~acc_granted);
				break;
			case SEC_ACE_TYPE_SYSTEM_ALARM:
			case SEC_ACE_TYPE_SYSTEM_AUDIT:
				*status = NT_STATUS_NOT_IMPLEMENTED;
				*granted = 0;
				return False;
			default:
				*status = NT_STATUS_INVALID_PARAMETER;
				*granted = 0;
				return False;
		}                           
	}

	/*
	 * If we were granted no access, or we desired bits that we
	 * didn't get, then deny.
	 */

	if ((acc_granted == 0) || ((acc_granted & desired) != desired)) {
		*status = NT_STATUS_ACCESS_DENIED;
		*granted = 0;
		return False;
	}

	/*
	 * Return the access we did get.
	 */

	*granted = acc_granted;
	*status = NT_STATUS_OK;
	return True;
}

/* Map generic access rights to object specific rights.  This technique is
   used to give meaning to assigning read, write, execute and all access to
   objects.  Each type of object has its own mapping of generic to object
   specific access rights. */

void se_map_generic(uint32 *access_mask, struct generic_mapping *mapping)
{
	uint32 old_mask = *access_mask;

	if (*access_mask & GENERIC_READ_ACCESS) {
		*access_mask &= ~GENERIC_READ_ACCESS;
		*access_mask |= mapping->generic_read;
	}

	if (*access_mask & GENERIC_WRITE_ACCESS) {
		*access_mask &= ~GENERIC_WRITE_ACCESS;
		*access_mask |= mapping->generic_write;
	}

	if (*access_mask & GENERIC_EXECUTE_ACCESS) {
		*access_mask &= ~GENERIC_EXECUTE_ACCESS;
		*access_mask |= mapping->generic_execute;
	}

	if (*access_mask & GENERIC_ALL_ACCESS) {
		*access_mask &= ~GENERIC_ALL_ACCESS;
		*access_mask |= mapping->generic_all;
	}

	if (old_mask != *access_mask) {
		DEBUG(10, ("se_map_generic(): mapped mask 0x%08x to 0x%08x\n",
			   old_mask, *access_mask));
	}
}

/* Map standard access rights to object specific rights.  This technique is
   used to give meaning to assigning read, write, execute and all access to
   objects.  Each type of object has its own mapping of standard to object
   specific access rights. */

void se_map_standard(uint32 *access_mask, struct standard_mapping *mapping)
{
	uint32 old_mask = *access_mask;

	if (*access_mask & READ_CONTROL_ACCESS) {
		*access_mask &= ~READ_CONTROL_ACCESS;
		*access_mask |= mapping->std_read;
	}

	if (*access_mask & (DELETE_ACCESS|WRITE_DAC_ACCESS|WRITE_OWNER_ACCESS|SYNCHRONIZE_ACCESS)) {
		*access_mask &= ~(DELETE_ACCESS|WRITE_DAC_ACCESS|WRITE_OWNER_ACCESS|SYNCHRONIZE_ACCESS);
		*access_mask |= mapping->std_all;
	}

	if (old_mask != *access_mask) {
		DEBUG(10, ("se_map_standard(): mapped mask 0x%08x to 0x%08x\n",
			   old_mask, *access_mask));
	}
}

/*****************************************************************************
 Check access rights of a user against a security descriptor.  Look at
 each ACE in the security descriptor until an access denied ACE denies
 any of the desired rights to the user or any of the users groups, or one
 or more ACEs explicitly grant all requested access rights.  See
 "Access-Checking" document in MSDN.
*****************************************************************************/ 

BOOL se_access_check(SEC_DESC *sd, NT_USER_TOKEN *token,
		     uint32 acc_desired, uint32 *acc_granted, 
		     NTSTATUS *status)
{
	extern NT_USER_TOKEN anonymous_token;
	size_t i;
	SEC_ACL *the_acl;
	fstring sid_str;
	uint32 tmp_acc_desired = acc_desired;

	if (!status || !acc_granted)
		return False;

	if (!token)
		token = &anonymous_token;

	*status = NT_STATUS_OK;
	*acc_granted = 0;

	DEBUG(10,("se_access_check: requested access 0x%08x, for NT token with %u entries and first sid %s.\n",
		 (unsigned int)acc_desired, (unsigned int)token->num_sids,
		sid_to_string(sid_str, &token->user_sids[0])));

	/*
	 * No security descriptor or security descriptor with no DACL
	 * present allows all access.
	 */

	/* ACL must have something in it */

	if (!sd || (sd && (!(sd->type & SEC_DESC_DACL_PRESENT) || sd->dacl == NULL))) {
		*status = NT_STATUS_OK;
		*acc_granted = acc_desired;
		DEBUG(5, ("se_access_check: no sd or blank DACL, access allowed\n"));
		return True;
	}

	/* The user sid is the first in the token */

	DEBUG(3, ("se_access_check: user sid is %s\n", sid_to_string(sid_str, &token->user_sids[PRIMARY_USER_SID_INDEX]) ));

	for (i = 1; i < token->num_sids; i++) {
		DEBUG(3, ("se_access_check: also %s\n",
			  sid_to_string(sid_str, &token->user_sids[i])));
	}

	/* Is the token the owner of the SID ? */

	if (sd->owner_sid) {
		for (i = 0; i < token->num_sids; i++) {
			if (sid_equal(&token->user_sids[i], sd->owner_sid)) {
				/*
				 * The owner always has SEC_RIGHTS_WRITE_DAC & READ_CONTROL.
				 */
				if (tmp_acc_desired & WRITE_DAC_ACCESS)
					tmp_acc_desired &= ~WRITE_DAC_ACCESS;
				if (tmp_acc_desired & READ_CONTROL_ACCESS)
					tmp_acc_desired &= ~READ_CONTROL_ACCESS;
			}
		}
	}

	the_acl = sd->dacl;

	if (tmp_acc_desired & MAXIMUM_ALLOWED_ACCESS) {
		tmp_acc_desired &= ~MAXIMUM_ALLOWED_ACCESS;
		return get_max_access( the_acl, token, acc_granted, tmp_acc_desired, 
				       status);
	}

	for ( i = 0 ; i < the_acl->num_aces && tmp_acc_desired != 0; i++) {
		SEC_ACE *ace = &the_acl->ace[i];

		DEBUG(10,("se_access_check: ACE %u: type %d, flags = 0x%02x, SID = %s mask = %x, current desired = %x\n",
			  (unsigned int)i, ace->type, ace->flags,
			  sid_to_string(sid_str, &ace->trustee),
			  (unsigned int) ace->info.mask, 
			  (unsigned int)tmp_acc_desired ));

		tmp_acc_desired = check_ace( ace, token, tmp_acc_desired, status);
		if (NT_STATUS_V(*status)) {
			*acc_granted = 0;
			DEBUG(5,("se_access_check: ACE %u denied with status %s.\n", (unsigned int)i, get_nt_error_msg(*status)));
			return False;
		}
	}

	/*
	 * If there are no more desired permissions left then
	 * access was allowed.
	 */

	if (tmp_acc_desired == 0) {
		*acc_granted = acc_desired;
		*status = NT_STATUS_OK;
		DEBUG(5,("se_access_check: access (%x) granted.\n", (unsigned int)acc_desired ));
		return True;
	}
		
	*acc_granted = 0;
	*status = NT_STATUS_ACCESS_DENIED;
	DEBUG(5,("se_access_check: access (%x) denied.\n", (unsigned int)acc_desired ));
	return False;
}

/* Create a child security descriptor using another security descriptor as
   the parent container.  This child object can either be a container or
   non-container object. */

SEC_DESC_BUF *se_create_child_secdesc(TALLOC_CTX *ctx, SEC_DESC *parent_ctr, 
				      BOOL child_container)
{
	SEC_DESC_BUF *sdb;
	SEC_DESC *sd;
	SEC_ACL *new_dacl, *the_acl;
	SEC_ACE *new_ace_list = NULL;
	int new_ace_list_ndx = 0, i;
	size_t size;

	/* Currently we only process the dacl when creating the child.  The
	   sacl should also be processed but this is left out as sacls are
	   not implemented in Samba at the moment.*/

	the_acl = parent_ctr->dacl;

	if (!(new_ace_list = talloc(ctx, sizeof(SEC_ACE) * the_acl->num_aces))) 
		return NULL;

	for (i = 0; the_acl && i < the_acl->num_aces; i++) {
		SEC_ACE *ace = &the_acl->ace[i];
		SEC_ACE *new_ace = &new_ace_list[new_ace_list_ndx];
		uint8 new_flags = 0;
		BOOL inherit = False;
		fstring sid_str;

		/* The OBJECT_INHERIT_ACE flag causes the ACE to be
		   inherited by non-container children objects.  Container
		   children objects will inherit it as an INHERIT_ONLY
		   ACE. */

		if (ace->flags & SEC_ACE_FLAG_OBJECT_INHERIT) {

			if (!child_container) {
				new_flags |= SEC_ACE_FLAG_OBJECT_INHERIT;
			} else {
				new_flags |= SEC_ACE_FLAG_INHERIT_ONLY;
			}

			inherit = True;
		}

		/* The CONAINER_INHERIT_ACE flag means all child container
		   objects will inherit and use the ACE. */

		if (ace->flags & SEC_ACE_FLAG_CONTAINER_INHERIT) {
			if (!child_container) {
				inherit = False;
			} else {
				new_flags |= SEC_ACE_FLAG_CONTAINER_INHERIT;
			}
		}

		/* The INHERIT_ONLY_ACE is not used by the se_access_check()
		   function for the parent container, but is inherited by
		   all child objects as a normal ACE. */

		if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY) {
			/* Move along, nothing to see here */
		}

		/* The SEC_ACE_FLAG_NO_PROPAGATE_INHERIT flag means the ACE
		   is inherited by child objects but not grandchildren
		   objects.  We clear the object inherit and container
		   inherit flags in the inherited ACE. */

		if (ace->flags & SEC_ACE_FLAG_NO_PROPAGATE_INHERIT) {
			new_flags &= ~(SEC_ACE_FLAG_OBJECT_INHERIT |
				       SEC_ACE_FLAG_CONTAINER_INHERIT);
		}

		/* Add ACE to ACE list */

		if (!inherit)
			continue;

		init_sec_access(&new_ace->info, ace->info.mask);
		init_sec_ace(new_ace, &ace->trustee, ace->type,
			     new_ace->info, new_flags);

		sid_to_string(sid_str, &ace->trustee);

		DEBUG(5, ("se_create_child_secdesc(): %s:%d/0x%02x/0x%08x "
			  " inherited as %s:%d/0x%02x/0x%08x\n", sid_str,
			  ace->type, ace->flags, ace->info.mask,
			  sid_str, new_ace->type, new_ace->flags,
			  new_ace->info.mask));

		new_ace_list_ndx++;
	}

	/* Create child security descriptor to return */
	
	new_dacl = make_sec_acl(ctx, ACL_REVISION, new_ace_list_ndx, new_ace_list);

	/* Use the existing user and group sids.  I don't think this is
	   correct.  Perhaps the user and group should be passed in as
	   parameters by the caller? */

	sd = make_sec_desc(ctx, SEC_DESC_REVISION,
			   parent_ctr->owner_sid,
			   parent_ctr->grp_sid,
			   parent_ctr->sacl,
			   new_dacl, &size);

	sdb = make_sec_desc_buf(ctx, size, sd);

	return sdb;
}
