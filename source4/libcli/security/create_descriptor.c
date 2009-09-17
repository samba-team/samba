/*
   Copyright (C) Nadezhda Ivanova 2009

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 *  Name: create_descriptor
 *
 *  Component: routines for calculating and creating security descriptors
 *  as described in MS-DTYP 2.5.2.2
 *
 *  Description:
 *
 *
 *  Author: Nadezhda Ivanova
 */
#include "includes.h"
#include "libcli/security/security.h"

/* the mapping function for generic rights for DS.(GA,GR,GW,GX)
 * The mapping function is passed as an argument to the
 * descriptor calculating routine and depends on the security
 * manager that calls the calculating routine.
 * TODO: need similar mappings for the file system and
 * registry security managers in order to make this code
 * generic for all security managers
 */

uint32_t map_generic_rights_ds(uint32_t access_mask)
{
	if (access_mask & SEC_GENERIC_ALL){
		access_mask |= SEC_ADS_GENERIC_ALL;
		access_mask = ~SEC_GENERIC_ALL;
	}

	if (access_mask & SEC_GENERIC_EXECUTE){
		access_mask |= SEC_ADS_GENERIC_EXECUTE;
		access_mask = ~SEC_GENERIC_EXECUTE;
	}

	if (access_mask & SEC_GENERIC_WRITE){
		access_mask |= SEC_ADS_GENERIC_WRITE;
		access_mask &= ~SEC_GENERIC_WRITE;
	}

	if (access_mask & SEC_GENERIC_READ){
		access_mask |= SEC_ADS_GENERIC_READ;
		access_mask &= ~SEC_GENERIC_READ;
	}

	return access_mask;
}

struct security_descriptor *create_security_descriptor(TALLOC_CTX *mem_ctx,
						       struct security_descriptor *parent_sd,
						       struct security_descriptor *creator_sd,
						       bool is_container,
						       struct GUID *object_list,
						       uint32_t inherit_flags,
						       struct security_token *token,
						       struct dom_sid *default_owner, /* valid only for DS, NULL for the other RSs */
						       struct dom_sid *default_group, /* valid only for DS, NULL for the other RSs */
						       uint32_t (*generic_map)(uint32_t access_mask))
{
	struct security_descriptor *new_sd;
	struct dom_sid *new_owner = NULL;
	struct dom_sid *new_group = NULL;

	new_sd = security_descriptor_initialise(mem_ctx);
	if (!new_sd)
		return NULL;
	if (!creator_sd || !creator_sd->owner_sid){
		if (inherit_flags & SEC_OWNER_FROM_PARENT)
			new_owner = parent_sd->owner_sid;
		else if (!default_owner)
			new_owner = token->user_sid;
		else
			new_owner = default_owner;
	}
	else
		new_owner = creator_sd->owner_sid;

	if (!creator_sd || !creator_sd->group_sid){
		if (inherit_flags & SEC_GROUP_FROM_PARENT && parent_sd)
			new_group = parent_sd->group_sid;
		else if (!default_group)
			new_group = token->group_sid;
		else new_group = default_group;
	}
	else
		new_group = creator_sd->group_sid;

	new_sd->owner_sid = talloc_memdup(new_sd, new_owner, sizeof(struct dom_sid));
	new_sd->group_sid = talloc_memdup(new_sd, new_group, sizeof(struct dom_sid));
	if (!new_sd->owner_sid || !new_sd->group_sid){
		talloc_free(new_sd);
		return NULL;
	}
	/* Todo remove */
	if (creator_sd && creator_sd->type & SEC_DESC_DACL_PRESENT){
		new_sd->dacl = security_acl_dup(new_sd, creator_sd->dacl);
		new_sd->type |= SEC_DESC_DACL_PRESENT;
	}
	return new_sd;
}
