/* 
 *  Unix SMB/CIFS implementation.
 *  Group Policy Object Support
 *  Copyright (C) Guenther Deschner 2007
 *  
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *  
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "includes.h"

	/* When modifiying security filtering with gpmc.msc (on w2k3) the
	 * following ACE is created in the DACL:

------- ACE (type: 0x05, flags: 0x02, size: 0x38, mask: 0x100, object flags: 0x1)
access SID: $SID 
access type: ALLOWED OBJECT
Permissions:
	[Apply Group Policy] (0x00000100)

------- ACE (type: 0x00, flags: 0x02, size: 0x24, mask: 0x20014)
access SID:  $SID
access type: ALLOWED
Permissions:
	[List Contents] (0x00000004)
	[Read All Properties] (0x00000010)
	[Read Permissions] (0x00020000)

	 * by default all "Authenticated Users" (S-1-5-11) have an ALLOW
	 * OBJECT ace with SEC_RIGHTS_APPLY_GROUP_POLICY mask */


/****************************************************************
****************************************************************/

static BOOL gpo_sd_check_agp_access_bits(uint32 access_mask)
{
	return (access_mask & SEC_RIGHTS_APPLY_GROUP_POLICY);
}

#if 0
/****************************************************************
****************************************************************/

static BOOL gpo_sd_check_read_access_bits(uint32 access_mask)
{
	uint32 read_bits = SEC_RIGHTS_LIST_CONTENTS |
			   SEC_RIGHTS_READ_ALL_PROP |
			   SEC_RIGHTS_READ_PERMS;

	return (read_bits == (access_mask & read_bits));
}
#endif

/****************************************************************
****************************************************************/

static BOOL gpo_sd_check_trustee_in_sid_token(const DOM_SID *trustee, 
					      const struct GPO_SID_TOKEN *token)
{
	int i;

	if (sid_equal(trustee, &token->object_sid)) {
		return True;
	}

	if (sid_equal(trustee, &token->primary_group_sid)) {
		return True;
	}

	for (i = 0; i < token->num_token_sids; i++) {
		if (sid_equal(trustee, &token->token_sids[i])) {
			return True;
		}
	}

	return False;
}

/****************************************************************
****************************************************************/

static NTSTATUS gpo_sd_check_ace_denied_object(const SEC_ACE *ace, 
					       const struct GPO_SID_TOKEN *token) 
{
	if (gpo_sd_check_agp_access_bits(ace->access_mask) &&
	    gpo_sd_check_trustee_in_sid_token(&ace->trustee, token)) {
		DEBUG(10,("gpo_sd_check_ace_denied_object: Access denied as of ace for %s\n", 
			sid_string_static(&ace->trustee)));
		return NT_STATUS_ACCESS_DENIED;
	}

	return STATUS_MORE_ENTRIES;
}

/****************************************************************
****************************************************************/

static NTSTATUS gpo_sd_check_ace_allowed_object(const SEC_ACE *ace, 
						const struct GPO_SID_TOKEN *token) 
{
	if (gpo_sd_check_agp_access_bits(ace->access_mask) && 
	    gpo_sd_check_trustee_in_sid_token(&ace->trustee, token)) {
		DEBUG(10,("gpo_sd_check_ace_allowed_object: Access granted as of ace for %s\n", 
			sid_string_static(&ace->trustee)));
		return NT_STATUS_OK;
	}

	return STATUS_MORE_ENTRIES;
}

/****************************************************************
****************************************************************/

static NTSTATUS gpo_sd_check_ace(const SEC_ACE *ace, 
				 const struct GPO_SID_TOKEN *token) 
{
	switch (ace->type) {
		case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT:
			return gpo_sd_check_ace_denied_object(ace, token);
		case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT:
			return gpo_sd_check_ace_allowed_object(ace, token);
		default:
			return STATUS_MORE_ENTRIES;
	}
}

/****************************************************************
****************************************************************/

NTSTATUS gpo_apply_security_filtering(const struct GROUP_POLICY_OBJECT *gpo, 
				      const struct GPO_SID_TOKEN *token)
{
	SEC_DESC *sd = gpo->security_descriptor;
	SEC_ACL *dacl = NULL;
	NTSTATUS status = NT_STATUS_ACCESS_DENIED;
	int i;

	if (!token) {
		return NT_STATUS_INVALID_USER_BUFFER;
	}

	if (!sd) {
		return NT_STATUS_INVALID_SECURITY_DESCR;
	}

	dacl = sd->dacl;
	if (!dacl) {
		return NT_STATUS_INVALID_SECURITY_DESCR;
	}

	/* check all aces and only return NT_STATUS_OK (== Access granted) or
	 * NT_STATUS_ACCESS_DENIED ( == Access denied) - the default is to
	 * deny access */

	for (i = 0; i < dacl->num_aces; i ++) {

		status = gpo_sd_check_ace(&dacl->aces[i], token);

		if (NT_STATUS_EQUAL(status, NT_STATUS_ACCESS_DENIED)) {
			return status;
		} else if (NT_STATUS_IS_OK(status)) {
			return status;
		}

		continue;
	}

	return NT_STATUS_ACCESS_DENIED;
}
