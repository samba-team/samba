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

extern int DEBUGLEVEL;

/*
 * Guest token used when there is no NT_USER_TOKEN available.
 */

static DOM_SID builtin_guest = {
	1, /* sid_rev_num */
	2, /* num_auths */
	{ 0, 0, 0, 0, 0, 5}, /* id_auth[6] */
	{ 32, 546, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} /* sub_auth[15] */
};

static NT_USER_TOKEN guest_token = {
	1,
	&builtin_guest
};

/**********************************************************************************
 Check if this ACE has a SID in common with the token.
**********************************************************************************/

static BOOL token_sid_in_ace( NT_USER_TOKEN *token, SEC_ACE *ace)
{
	size_t i;

	for (i = 0; i < token->num_sids; i++) {
		if (sid_equal(&ace->sid, &token->user_sids[i])) {
			return True;
		}
	}

	return False;
}

/*********************************************************************************
 Check an ACE against a SID.  We return the remaining needed permission
 bits not yet granted. Zero means permission allowed (no more needed bits).
**********************************************************************************/

static uint32 check_ace(SEC_ACE *ace, NT_USER_TOKEN *token, uint32 acc_desired, uint32 *status)
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

static BOOL get_max_access( SEC_ACL *acl, NT_USER_TOKEN *token, uint32 *granted, uint32 desired, uint32 *status)
{
	uint32 acc_denied = 0;
	uint32 acc_granted = 0;
	size_t i;
	
	for ( i = 0 ; i < acl->num_aces; i++) {
		SEC_ACE *ace = &acl->ace[i];
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
	*status = NT_STATUS_NOPROBLEMO;
	return True;
}

/*********************************************************************************
 Check access rights of a user against a security descriptor.  Look at
 each ACE in the security descriptor until an access denied ACE denies
 any of the desired rights to the user or any of the users groups, or one
 or more ACEs explicitly grant all requested access rights.  See
 "Access-Checking" document in MSDN.
**********************************************************************************/ 

BOOL se_access_check(SEC_DESC *sd, struct current_user *user,
		     uint32 acc_desired, uint32 *acc_granted, uint32 *status)
{
	size_t i;
	SEC_ACL *acl;
	fstring sid_str;
	NT_USER_TOKEN *token = user->nt_user_token ? user->nt_user_token : &guest_token;
	uint32 tmp_acc_desired = acc_desired;

	if (!status || !acc_granted)
		return False;

	*status = NT_STATUS_NOPROBLEMO;
	*acc_granted = 0;

	/*
	 * No security descriptor or security descriptor with no DACL
	 * present allows all access.
	 */

	/* ACL must have something in it */

	if (!sd || (sd && (!(sd->type & SEC_DESC_DACL_PRESENT) || sd->dacl == NULL))) {
		*status = NT_STATUS_NOPROBLEMO;
		*acc_granted = acc_desired;
		DEBUG(3, ("se_access_check: no sd or blank DACL, access allowed\n"));
		return True;
	}


	/* We must know the owner sid */

	if (sd->owner_sid == NULL) {
		DEBUG(1, ("no owner for security descriptor\n"));
		*acc_granted = 0;
		*status = NT_STATUS_ACCESS_DENIED;
		return False;
	}

	/* The user sid is the first in the token */

	DEBUG(3, ("se_access_check: user sid is %s\n", sid_to_string(sid_str, &token->user_sids[0]) ));

	/* Is the token the owner of the SID ? */

	for (i = 0; i < token->num_sids; i++) {
		if (sid_equal(&token->user_sids[i], sd->owner_sid)) {
			/*
			 * The owner always has SEC_RIGHTS_WRITE_DAC.
			 */
			if (tmp_acc_desired & SEC_RIGHTS_WRITE_DAC)
				tmp_acc_desired &= ~SEC_RIGHTS_WRITE_DAC;
		}
	}

	acl = sd->dacl;

	if (tmp_acc_desired & SEC_RIGHTS_MAXIMUM_ALLOWED) {
		tmp_acc_desired &= ~SEC_RIGHTS_MAXIMUM_ALLOWED;
		return get_max_access( acl, token, acc_granted, tmp_acc_desired, status);
	}

	for ( i = 0 ; i < acl->num_aces && tmp_acc_desired != 0; i++) {
		tmp_acc_desired = check_ace( &acl->ace[i], token, tmp_acc_desired, status);
		if (*status != NT_STATUS_NOPROBLEMO) {
			*acc_granted = 0;
			return False;
		}
	}

	/*
	 * If there are no more desired permissions left then
	 * access was allowed.
	 */

	if (tmp_acc_desired == 0) {
		*acc_granted = acc_desired;
		*status = NT_STATUS_NOPROBLEMO;
		return True;
	}
		
	*acc_granted = 0;
	*status = NT_STATUS_ACCESS_DENIED;
	return False;
}
