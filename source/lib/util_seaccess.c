/*
   Unix SMB/Netbios implementation.
   Version 2.0
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000.

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

static uint32 acegrant(uint32 mask, uint32 *acc_req, uint32 *acc_grant, uint32 *acc_deny)
{
	/* maximum allowed: grant what's in the ace */
	if ((*acc_req) == SEC_RIGHTS_MAXIMUM_ALLOWED)
	{
		(*acc_grant) |= mask & ~(*acc_deny);
	}
	else
	{
		(*acc_grant) |= (*acc_req) & mask;
		(*acc_req) &= ~(*acc_grant);
	}
	if ((*acc_req) == 0x0)
	{
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_NOPROBLEMO;
}

static uint32 acedeny(uint32 mask, uint32 *acc_req, uint32 *acc_grant, uint32 *acc_deny)
{
	/* maximum allowed: grant what's in the ace */
	if ((*acc_req) == SEC_RIGHTS_MAXIMUM_ALLOWED)
	{
		(*acc_deny) |= mask & ~(*acc_grant);
	}
	else
	{
		if ((*acc_req) & mask)
		{
			return NT_STATUS_ACCESS_DENIED;
		}
#if 0
		(*acc_deny) |= (*acc_req) & mask;
		(*acc_req) &= ~(*acc_deny);
#endif
	}
	if ((*acc_req) == 0x0)
	{
		return NT_STATUS_ACCESS_DENIED;
	}
	return NT_STATUS_NOPROBLEMO;
}

static BOOL check_ace(const SEC_ACE *ace, BOOL is_owner,
			const DOM_SID *sid,
			uint32 *acc_req,
			uint32 *acc_grant,
			uint32 *acc_deny,
			uint32 *status)
{
	uint32 mask = ace->info.mask;

	if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY)
	{
		/* inherit only is ignored */
		return False;
	}

	/* only owner allowed write-owner rights */
	if (!is_owner)
	{
		mask &= (~SEC_RIGHTS_WRITE_OWNER);
	}

	switch (ace->type)
	{
		case SEC_ACE_TYPE_ACCESS_ALLOWED:
		{
			/* everyone - or us */
			if (sid_equal(&ace->sid, &global_sid_S_1_1_0) ||
			    sid_equal(&ace->sid, sid))
			{
				(*status) = acegrant(mask, acc_req, acc_grant, acc_deny);
				if ((*status) != NT_STATUS_NOPROBLEMO)
				{
					return True;
				}

			}
			break;
		}
		case SEC_ACE_TYPE_ACCESS_DENIED:
		{
			/* everyone - or us */
			if (sid_equal(&ace->sid, &global_sid_S_1_1_0) ||
			    sid_equal(&ace->sid, sid))
			{
				(*status) = acedeny(mask, acc_req, acc_grant, acc_deny);
				if ((*status) != NT_STATUS_NOPROBLEMO)
				{
					return True;
				}
			}
			break;
		}
		case SEC_ACE_TYPE_SYSTEM_AUDIT:
		{
			(*status) = NT_STATUS_NOT_IMPLEMENTED;
			return True;
		}
		case SEC_ACE_TYPE_SYSTEM_ALARM:
		{
			(*status) = NT_STATUS_NOT_IMPLEMENTED;
			return True;
		}
		default:
		{
			(*status) = NT_STATUS_INVALID_PARAMETER;
			return True;
		}
	}
	return False;
}

/***********************************************************************
 checks access_requested rights of user against sd.  returns access granted
 and a status code if the grant succeeded, error message if it failed.

 the previously_granted access rights requires some explanation: if you
 open a policy handle with a set of permissions, you cannot then perform
 operations that require more privileges than those requested.  pass in
 the [previously granted] permissions from the open_policy_hnd call as
 prev_grant_acc, and this function will do the checking for you.
 ***********************************************************************/
BOOL se_access_check(const SEC_DESC * sd, const NET_USER_INFO_3 * user,
		     uint32 acc_req, uint32 prev_grant_acc,
		     uint32 * acc_grant,
		     uint32 * status)
{
	int num_aces;
	int num_groups;
	DOM_SID usr_sid;
	DOM_SID grp_sid;
	DOM_SID **grp_sids = NULL;
	uint32 ngrp_sids = 0;
	BOOL is_owner;
	BOOL is_system;
	const SEC_ACL *acl = NULL;
	uint32 grnt;
	uint32 deny;

	if (status == NULL)
	{
		return False;
	}

	if (prev_grant_acc == SEC_RIGHTS_MAXIMUM_ALLOWED)
	{
		prev_grant_acc = 0xffffffff;
	}
	
	/* cannot request any more than previously requested access */
	acc_req &= prev_grant_acc;

	if (acc_req == 0x0)
	{
		(*status) = NT_STATUS_ACCESS_DENIED;
		return False;
	}

	/* we must know the owner sid */
	if (sd->owner_sid == NULL)
	{
		return False;
	}

	(*status) = NT_STATUS_NOPROBLEMO;

	/* create user sid */
	sid_copy(&grp_sid, &user->dom_sid.sid);
	sid_append_rid(&grp_sid, user->group_id);

	/* create group sid */
	sid_copy(&usr_sid, &user->dom_sid.sid);
	sid_append_rid(&usr_sid, user->user_id);

	/* preparation: check owner sid, create array of group sids */
	is_owner = sid_equal(&usr_sid, sd->owner_sid);
	add_sid_to_array(&ngrp_sids, &grp_sids, &grp_sid);

	for (num_groups = 0; num_groups < user->num_groups; num_groups++)
	{
		sid_copy(&grp_sid, &user->dom_sid.sid);
		sid_append_rid(&grp_sid, user->gids[num_groups].g_rid);
		add_sid_to_array(&ngrp_sids, &grp_sids, &grp_sid);
	}

	/* check for system acl or user (discretionary) acl */
	is_system = sid_equal(&usr_sid, &global_sid_system);
	if (is_system)
	{
		acl = sd->sacl;
	}
	else
	{
		acl = sd->dacl;
	}

	/* acl must have something in it */
	if (acl == NULL || acl->ace == NULL || acl->num_aces == 0)
	{
		return False;
	}

	/*
	 * OK!  we have an ACE, it has at least one thing in it,
	 * we have a user sid, we have an array of group sids.
	 * let's go!
	 */

	deny = 0;
	grnt = 0;

	/* check each ace */
	for (num_aces = 0; num_aces < acl->num_aces; num_aces++)
	{
		const SEC_ACE *ace = &acl->ace[num_aces];

		/* first check the user sid */
		if (check_ace(ace, is_owner, &usr_sid, &acc_req,
			      &grnt, &deny, status))
		{
			free_sid_array(ngrp_sids, grp_sids);
			return (*status) != NT_STATUS_NOPROBLEMO;
		}
		/* now check the group sids */
		for (num_groups = 0; num_groups < ngrp_sids; num_groups++)
		{
			if (check_ace(ace, False, grp_sids[num_groups],
					&acc_req, &grnt, &deny, status))
			{
				free_sid_array(ngrp_sids, grp_sids);
				return (*status) != NT_STATUS_NOPROBLEMO;
			}
		}
	}

	if (grnt == 0x0 && (*status) == NT_STATUS_NOPROBLEMO)
	{
		(*status) = NT_STATUS_ACCESS_DENIED;
	}
	else if (acc_grant != NULL)
	{
		(*acc_grant) = grnt;
	}

	free_sid_array(ngrp_sids, grp_sids);
	return (*status) != NT_STATUS_NOPROBLEMO;
}

