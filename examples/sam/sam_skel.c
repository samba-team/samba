/*
   Unix SMB/CIFS implementation.
   this is a skeleton for SAM backend modules.
	
   Copyright (C) Stefan (metze) Metzmacher		2002

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

static int sam_skel_debug_level = DBGC_ALL;

#undef DBGC_CLASS
#define DBGC_CLASS sam_skel_debug_level

/* define the version of the SAM interface */ 
SAM_MODULE_VERSIONING_MAGIC


/* General API */

NTSTATUS sam_skel_get_sec_desc(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const DOM_SID *sid, SEC_DESC **sd)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_set_sec_desc(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const DOM_SID *sid, const SEC_DESC *sd)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

	
NTSTATUS sam_skel_lookup_sid(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const DOM_SID *sid, char **name, uint32 *type)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_lookup_name(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const char *name, DOM_SID **sid, uint32 *type)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

	
/* Domain API */

NTSTATUS sam_skel_update_domain(const struct sam_methods *sam_method, const SAM_DOMAIN_HANDLE *domain)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_get_domain_handle(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, SAM_DOMAIN_HANDLE **domain)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* Account API */

NTSTATUS sam_skel_create_account(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, SAM_ACCOUNT_HANDLE **account)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_add_account(const struct sam_methods *sam_method, const SAM_ACCOUNT_HANDLE *account)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_update_account(const struct sam_methods *sam_method, const SAM_ACCOUNT_HANDLE *account)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_delete_account(const struct sam_methods *sam_method, const SAM_ACCOUNT_HANDLE *account)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_enum_accounts(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, int32 *account_count, SAM_ACCOUNT_ENUM **accounts)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}


NTSTATUS sam_skel_get_account_by_sid(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *accountsid, SAM_ACCOUNT_HANDLE **account)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_get_account_by_name(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *name, SAM_ACCOUNT_HANDLE **account)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* Group API */

NTSTATUS sam_skel_create_group(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const uint32 type, SAM_GROUP_HANDLE **group)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_add_group(const struct sam_methods *sam_method, const SAM_GROUP_HANDLE *group)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_update_group(const struct sam_methods *sam_method, const SAM_GROUP_HANDLE *group)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_delete_group(const struct sam_methods *sam_method, const SAM_GROUP_HANDLE *group)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_enum_groups(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const uint32 type, uint32 *groups_count, SAM_GROUP_ENUM **groups)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_get_group_by_sid(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const DOM_SID *groupsid, SAM_GROUP_HANDLE **group)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_get_group_by_name(const struct sam_methods *sam_method, const NT_USER_TOKEN *access_token, const uint32 access_desired, const char *name, SAM_GROUP_HANDLE **group)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}


NTSTATUS sam_skel_add_member_to_group(const struct sam_methods *sam_method, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_delete_member_from_group(const struct sam_methods *sam_method, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_skel_enum_groupmembers(const struct sam_methods *sam_method, const SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}


NTSTATUS sam_skel_get_groups_of_account(const struct sam_methods *sam_method, const SAM_ACCOUNT_HANDLE *account, const uint32 type, uint32 *group_count, SAM_GROUP_ENUM **groups)
{
	DEBUG(0,("sam_skel: %s was called!\n",__FUNCTION__));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_init(const SAM_CONTEXT *sam_context, SAM_METHODS **sam_method, const char *location)
{
	NTSTATUS nt_status;

	if (!NT_STATUS_IS_OK(nt_status = make_sam_methods(sam_context->mem_ctx, sam_method))) {
		return nt_status;
	}

	(*sam_method)->backendname = "sam_skel";

	/* Functions your SAM module doesn't provide should be set 
	 * to NULL */

	(*sam_method)->sam_get_sec_desc = sam_skel_get_sec_desc;
	(*sam_method)->sam_set_sec_desc = sam_skel_set_sec_desc;
	
	(*sam_method)->sam_lookup_sid = sam_skel_lookup_sid;
	(*sam_method)->sam_lookup_name = sam_skel_lookup_name;
	
	/* Domain API */

	(*sam_method)->sam_update_domain = sam_skel_update_domain;
	(*sam_method)->sam_get_domain_handle = sam_skel_get_domain_handle;

	/* Account API */

	(*sam_method)->sam_create_account = sam_skel_create_account;
	(*sam_method)->sam_add_account = sam_skel_add_account;
	(*sam_method)->sam_update_account = sam_skel_update_account;
	(*sam_method)->sam_delete_account = sam_skel_delete_account;
	(*sam_method)->sam_enum_accounts = sam_skel_enum_accounts;

	(*sam_method)->sam_get_account_by_sid = sam_skel_get_account_by_sid;
	(*sam_method)->sam_get_account_by_name = sam_skel_get_account_by_name;

	/* Group API */

	(*sam_method)->sam_create_group = sam_skel_create_group;
	(*sam_method)->sam_add_group = sam_skel_add_group;
	(*sam_method)->sam_update_group = sam_skel_update_group;
	(*sam_method)->sam_delete_group = sam_skel_delete_group;
	(*sam_method)->sam_enum_groups = sam_skel_enum_groups;
	(*sam_method)->sam_get_group_by_sid = sam_skel_get_group_by_sid;
	(*sam_method)->sam_get_group_by_name = sam_skel_get_group_by_name;

	(*sam_method)->sam_add_member_to_group = sam_skel_add_member_to_group;
	(*sam_method)->sam_delete_member_from_group = sam_skel_delete_member_from_group;
	(*sam_method)->sam_enum_groupmembers = sam_skel_enum_groupmembers;

	(*sam_method)->sam_get_groups_of_account = sam_skel_get_groups_of_account;

	(*sam_method)->free_private_data = NULL;


	sam_skel_debug_level = debug_add_class("sam_skel");
	if (sam_skel_debug_level == -1) {
		sam_skel_debug_level = DBGC_ALL;
		DEBUG(0, ("sam_skel: Couldn't register custom debugging class!\n"));
	} else DEBUG(0, ("sam_skel: Debug class number of 'sam_skel': %d\n", sam_skel_debug_level));
    
	DEBUG(0, ("Initializing sam_skel\n"));
	if (location)
		DEBUG(10, ("Location: %s\n", location));

	return NT_STATUS_OK;
}
