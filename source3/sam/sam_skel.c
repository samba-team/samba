/*
   Unix SMB/CIFS implementation.
   this is a skeleton for SAM backend modules.
	
   Copyright (C) Stefan (metze) Metzmacher		2002
   Copyright (C) Jelmer Vernooij			2002
   Copyright (C) Andrew Bartlett			2002

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

static int sam_skel_debug_level = DBGC_SAM;

#undef DBGC_CLASS
#define DBGC_CLASS sam_skel_debug_level

/* define the version of the SAM interface */ 
SAM_MODULE_VERSIONING_MAGIC

/* General API */

static NTSTATUS sam_skel_get_sec_desc(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, const DOM_SID *sid, SEC_DESC **sd)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_set_sec_desc(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, const DOM_SID *sid, const SEC_DESC *sd)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

	
static NTSTATUS sam_skel_lookup_sid(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, TALLOC_CTX *mem_ctx, const DOM_SID *sid, char **name, uint32 *type)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_lookup_name(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, const char *name, DOM_SID *sid, uint32 *type)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

	
/* Domain API */

static NTSTATUS sam_skel_update_domain(const SAM_METHODS *sam_methods, const SAM_DOMAIN_HANDLE *domain)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_get_domain_handle(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, uint32 access_desired, SAM_DOMAIN_HANDLE **domain)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* Account API */

static NTSTATUS sam_skel_create_account(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *account_name, uint16 acct_ctrl, SAM_ACCOUNT_HANDLE **account)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_add_account(const SAM_METHODS *sam_methods, const SAM_ACCOUNT_HANDLE *account)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_update_account(const SAM_METHODS *sam_methods, const SAM_ACCOUNT_HANDLE *account)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_delete_account(const SAM_METHODS *sam_methods, const SAM_ACCOUNT_HANDLE *account)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_enum_accounts(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, uint16 acct_ctrl, uint32 *account_count, SAM_ACCOUNT_ENUM **accounts)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS sam_skel_get_account_by_sid(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, uint32 access_desired, const DOM_SID *accountsid, SAM_ACCOUNT_HANDLE **account)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_get_account_by_name(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *name, SAM_ACCOUNT_HANDLE **account)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}


/* Group API */

static NTSTATUS sam_skel_create_group(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *account_name, uint16 group_ctrl, SAM_GROUP_HANDLE **group)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_add_group(const SAM_METHODS *sam_methods, const SAM_GROUP_HANDLE *group)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_update_group(const SAM_METHODS *sam_methods, const SAM_GROUP_HANDLE *group)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_delete_group(const SAM_METHODS *sam_methods, const SAM_GROUP_HANDLE *group)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_enum_groups(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, uint16 group_ctrl, uint32 *groups_count, SAM_GROUP_ENUM **groups)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_get_group_by_sid(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, uint32 access_desired, const DOM_SID *groupsid, SAM_GROUP_HANDLE **group)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_get_group_by_name(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, uint32 access_desired, const char *name, SAM_GROUP_HANDLE **group)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS sam_skel_add_member_to_group(const SAM_METHODS *sam_methods, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_delete_member_from_group(const SAM_METHODS *sam_methods, const SAM_GROUP_HANDLE *group, const SAM_GROUP_MEMBER *member)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS sam_skel_enum_groupmembers(const SAM_METHODS *sam_methods, const SAM_GROUP_HANDLE *group, uint32 *members_count, SAM_GROUP_MEMBER **members)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}


static NTSTATUS sam_skel_get_groups_of_sid(const SAM_METHODS *sam_methods, const NT_USER_TOKEN *access_token, const DOM_SID **sids, uint16 group_ctrl, uint32 *group_count, SAM_GROUP_ENUM **groups)
{
	DEBUG(0,("sam_skel: %s was called!\n",FUNCTION_MACRO));
	return NT_STATUS_NOT_IMPLEMENTED;
}

NTSTATUS sam_init_skel(SAM_METHODS *sam_methods, const char *module_params)
{
	/* Functions your SAM module doesn't provide should be set 
	 * to NULL */

	sam_methods->sam_get_sec_desc = sam_skel_get_sec_desc;
	sam_methods->sam_set_sec_desc = sam_skel_set_sec_desc;
	
	sam_methods->sam_lookup_sid = sam_skel_lookup_sid;
	sam_methods->sam_lookup_name = sam_skel_lookup_name;
	
	/* Domain API */

	sam_methods->sam_update_domain = sam_skel_update_domain;
	sam_methods->sam_get_domain_handle = sam_skel_get_domain_handle;

	/* Account API */

	sam_methods->sam_create_account = sam_skel_create_account;
	sam_methods->sam_add_account = sam_skel_add_account;
	sam_methods->sam_update_account = sam_skel_update_account;
	sam_methods->sam_delete_account = sam_skel_delete_account;
	sam_methods->sam_enum_accounts = sam_skel_enum_accounts;

	sam_methods->sam_get_account_by_sid = sam_skel_get_account_by_sid;
	sam_methods->sam_get_account_by_name = sam_skel_get_account_by_name;

	/* Group API */

	sam_methods->sam_create_group = sam_skel_create_group;
	sam_methods->sam_add_group = sam_skel_add_group;
	sam_methods->sam_update_group = sam_skel_update_group;
	sam_methods->sam_delete_group = sam_skel_delete_group;
	sam_methods->sam_enum_groups = sam_skel_enum_groups;
	sam_methods->sam_get_group_by_sid = sam_skel_get_group_by_sid;
	sam_methods->sam_get_group_by_name = sam_skel_get_group_by_name;

	sam_methods->sam_add_member_to_group = sam_skel_add_member_to_group;
	sam_methods->sam_delete_member_from_group = sam_skel_delete_member_from_group;
	sam_methods->sam_enum_groupmembers = sam_skel_enum_groupmembers;

	sam_methods->sam_get_groups_of_sid = sam_skel_get_groups_of_sid;

	sam_methods->free_private_data = NULL;


	sam_skel_debug_level = debug_add_class("sam_skel");
	if (sam_skel_debug_level == -1) {
		sam_skel_debug_level = DBGC_SAM;
		DEBUG(0, ("sam_skel: Couldn't register custom debugging class!\n"));
	} else DEBUG(2, ("sam_skel: Debug class number of 'sam_skel': %d\n", sam_skel_debug_level));
    
	if(module_params)
		DEBUG(0, ("Starting 'sam_skel' with parameters '%s' for domain %s\n", module_params, sam_methods->domain_name));
	else
		DEBUG(0, ("Starting 'sam_skel' for domain %s without paramters\n", sam_methods->domain_name));

	return NT_STATUS_OK;
}
