/*
   Unix SMB/Netbios implementation.
   Version 2.0
   Copyright (C) Luke Kenneth Casson Leighton 1996-2000.
   Copyright (C) Tim Potter 2000.

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

/* Process an access allowed ACE */

static BOOL ace_grant(uint32 mask, uint32 *acc_desired, uint32 *acc_granted)
{
	uint32 matches;

	/* If there are any matches in the ACE mask and desired access,
	   turn them off in the desired access and on in the granted
	   mask. */ 

	if (*acc_desired == SEC_RIGHTS_MAXIMUM_ALLOWED) {
		matches = mask;
		*acc_desired = mask;
	} else {
		matches = mask & *acc_desired;
	}

	if (matches) {
		*acc_desired = *acc_desired & ~matches;
		*acc_granted = *acc_granted | matches;
	}

	return *acc_desired == 0;
}

/* Process an access denied ACE */

static BOOL ace_deny(uint32 mask, uint32 *acc_desired, uint32 *acc_granted)
{
	uint32 matches;

	/* If there are any matches in the ACE mask and the desired access,
	   all bits are turned off in the desired and granted mask. */

	if (*acc_desired == SEC_RIGHTS_MAXIMUM_ALLOWED) {
		matches = mask;
	} else {
		matches = mask & *acc_desired;
	}

	if (matches) {
		*acc_desired = *acc_granted = 0;
	}

	return *acc_desired == 0;
}

/* Check an ACE against a SID.  We return true if the ACE clears all the
   permission bits in the access desired mask.  This indicates that we have
   make a decision to deny or allow access and the status is updated
   accordingly. */

static BOOL check_ace(SEC_ACE *ace, BOOL is_owner, DOM_SID *sid, 
		      uint32 *acc_desired, uint32 *acc_granted, 
		      uint32 *status)
{
	uint32 mask = ace->info.mask;

	/* Inherit only is ignored */

	if (ace->flags & SEC_ACE_FLAG_INHERIT_ONLY) {
		return False;
	}

	/* Some debugging stuff */

	if (DEBUGLEVEL >= 3) {
		fstring ace_sid_str, sid_str;
		fstring ace_name, ace_name_dom, name, name_dom;
		uint8 name_type;
		
		sid_to_string(sid_str, sid);
		sid_to_string(ace_sid_str, &ace->sid);

	        if (!winbind_lookup_sid(sid, name_dom, name, &name_type)) {
			fstrcpy(name_dom, "UNKNOWN");
			fstrcpy(name, "UNKNOWN");
		}

		if (!winbind_lookup_sid(&ace->sid, ace_name_dom, ace_name, 
					&name_type)) {
			fstrcpy(ace_name_dom, "UNKNOWN");
			fstrcpy(ace_name, "UNKNOWN");
		}

		DEBUG(3, ("checking %s ACE sid %s (%s%s%s) mask 0x%08x "
			  "against sid %s (%s%s%s)\n",
			  (ace->type == SEC_ACE_TYPE_ACCESS_ALLOWED) ? 
			  "allowed" : ((ace->type ==
					SEC_ACE_TYPE_ACCESS_DENIED) ?
				       "denied" : "unknown"),
			  ace_sid_str, ace_name_dom, lp_winbind_separator(),
			  ace_name, mask, sid_str, name_dom,
			  lp_winbind_separator(), name));
	}

	/* Only owner allowed write-owner rights */

	if (!is_owner) {
		mask &= (~SEC_RIGHTS_WRITE_OWNER);
	}

	/* Check the ACE value.  This updates the access_desired and
	   access_granted values appropriately. */

	switch (ace->type) {

		/* Access allowed ACE */

		case SEC_ACE_TYPE_ACCESS_ALLOWED: {

			/* Everyone - or us */

			if (sid_equal(&ace->sid, global_sid_everyone) ||
			    sid_equal(&ace->sid, sid)) {

				/* Return true if access has been allowed */

				if (ace_grant(mask, acc_desired, 
					      acc_granted)) {
					*status = NT_STATUS_NO_PROBLEMO;
					DEBUG(3, ("access granted\n"));
					return True;
				}
			}

			break;
		}

		/* Access denied ACE */

		case SEC_ACE_TYPE_ACCESS_DENIED: {

			/* Everyone - or us */

			if (sid_equal(&ace->sid, global_sid_everyone) ||
			    sid_equal(&ace->sid, sid)) {
				
				/* Return false if access has been denied */

				if (ace_deny(mask, acc_desired, 
					     acc_granted)) {
					*status = NT_STATUS_ACCESS_DENIED;
					DEBUG(3, ("access denied\n"));
					return True;
				}
			}

			break;
		}

		/* Unimplemented ACE types.  These are ignored. */

		case SEC_ACE_TYPE_SYSTEM_ALARM:
		case SEC_ACE_TYPE_SYSTEM_AUDIT: {
			*status = NT_STATUS_NOT_IMPLEMENTED;
			return False;
		}

		/* Unknown ACE type */

		default: {
			*status = NT_STATUS_INVALID_PARAMETER;
			return False;
		}
	}

	/* There are still some bits set in the access desired mask that
	   haven't been cleared by an ACE.  More checking is required. */

	return False;
}

/* Check access rights of a user against a security descriptor.  Look at
   each ACE in the security descriptor until an access denied ACE denies
   any of the desired rights to the user or any of the users groups, or one
   or more ACEs explicitly grant all requested access rights.  See
   "Access-Checking" document in MSDN. */ 

BOOL se_access_check(SEC_DESC *sd, uid_t uid, gid_t gid, int ngroups,
		     gid_t *groups, uint32 acc_desired, 
		     uint32 *acc_granted, uint32 *status)
{
	DOM_SID user_sid, group_sid;
	DOM_SID **group_sids = NULL;
	int i, j, ngroup_sids = 0;
	SEC_ACL *acl;
	uint8 check_ace_type;

	if (!status || !acc_granted) return False;

	*status = NT_STATUS_ACCESS_DENIED;
	*acc_granted = 0;

	/* No security descriptor allows all access */

	if (!sd) {
		*status = NT_STATUS_NOPROBLEMO;
		*acc_granted = acc_desired;
		acc_desired = 0;

                goto done;
	}

	/* If desired access mask is empty then no access is allowed */

	if (acc_desired == 0) {
		goto done;
	}

	/* We must know the owner sid */

	if (sd->owner_sid == NULL) {
		DEBUG(1, ("no owner for security descriptor\n"));
		goto done;
	}

	/* Create user sid */

	if (!winbind_uid_to_sid(uid, &user_sid)) {
		DEBUG(3, ("could not lookup sid for uid %d\n", uid));
	}

	/* If we're the owner, then we can do anything */

	if (sid_equal(&user_sid, sd->owner_sid)) {
		*status = NT_STATUS_NOPROBLEMO;
		*acc_granted = acc_desired;
		acc_desired = 0;

                goto done;
	}

	/* Create group sid */

	if (!winbind_gid_to_sid(gid, &group_sid)) {
		DEBUG(3, ("could not lookup sid for gid %d\n", gid));
	}

	/* Create array of group sids */

	add_sid_to_array(&ngroup_sids, &group_sids, &group_sid);

	for (i = 0; i < ngroups; i++) {
		if (groups[i] != gid) {
			if (winbind_gid_to_sid(groups[i], &group_sid)) {

				/* If we're a group member then we can also
				   do anything */

				if (sid_equal(&group_sid, sd->grp_sid)) {
					*status = NT_STATUS_NOPROBLEMO;
					*acc_granted = acc_desired;
					acc_desired = 0;

					goto done;
				}

				add_sid_to_array(&ngroup_sids, &group_sids, 
						 &group_sid);
			} else {
				DEBUG(3, ("could not lookup sid for gid %d\n", 
					  gid));
			}
		}
	}

        /* ACL must have something in it */

	acl = sd->dacl;

        if (acl == NULL || acl->ace == NULL || acl->num_aces == 0) {

		/* Checks against a NULL ACL succeed and return access
		   granted = access requested. */

		*status = NT_STATUS_NOPROBLEMO;
		*acc_granted = acc_desired;
		acc_desired = 0;

                goto done;
        }

	/* Check each ACE in ACL.  We break out of the loop if an ACE is
	   either explicitly denied or explicitly allowed by the
	   check_ace2() function.  We also check the Access Denied ACEs
	   before Access allowed ones as the Platform SDK documentation is
	   unclear whether ACEs in a ACL are necessarily always in this
	   order.  See the discussion on "Order of ACEs in a DACL" in
	   MSDN. */

	check_ace_type = SEC_ACE_TYPE_ACCESS_DENIED;

    check_aces:

        for (i = 0; i < acl->num_aces; i++) {
                SEC_ACE *ace = &acl->ace[i];
		BOOL is_group_owner;

		/* Check user sid */

                if (ace->type == check_ace_type &&
		    check_ace(ace, False, &user_sid, &acc_desired,
			      acc_granted, status)) {
			goto done;
                }

                /* Check group sids */

                for (j = 0; j < ngroup_sids; j++) {

			is_group_owner = sd->grp_sid ? 
				sid_equal(group_sids[j], sd->grp_sid) : False;

                        if (ace->type == check_ace_type &&
			    check_ace(ace, is_group_owner, group_sids[j], 
				      &acc_desired, acc_granted, status)) {
				goto done;
                        }
                }
        }

	/* Check access allowed ACEs */

	if (check_ace_type == SEC_ACE_TYPE_ACCESS_DENIED) {
		check_ace_type = SEC_ACE_TYPE_ACCESS_ALLOWED;
		goto check_aces;
	}

 done:
        free_sid_array(ngroup_sids, group_sids);
	
	/* If any access desired bits are still on, return access denied
	   and turn off any bits already granted. */

	if (acc_desired) {
		*acc_granted = 0;
		*status = NT_STATUS_ACCESS_DENIED;
	}

        return *status == NT_STATUS_NOPROBLEMO;
}
