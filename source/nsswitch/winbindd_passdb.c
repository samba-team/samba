/* 
   Unix SMB/CIFS implementation.

   Winbind rpc backend functions

   Copyright (C) Tim Potter 2000-2001,2003
   Copyright (C) Simo Sorce 2003
   
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

#include "winbindd.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_WINBIND


/* Query display info for a domain.  This returns enough information plus a
   bit extra to give an overview of domain users for the User Manager
   application. */
static NTSTATUS query_user_list(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32 *num_entries, 
			       WINBIND_USERINFO **info)
{
	SAM_ACCOUNT *sam_account = NULL;
	NTSTATUS result;
	uint32 i;

	DEBUG(3,("pdb: query_user_list\n"));

	if (!NT_STATUS_IS_OK(result = pdb_init_sam(&sam_account))) {
		return result;
	}

	i = 0;
	*info = NULL;
	
	if (pdb_setsampwent(False)) {
	
		while (pdb_getsampwent(sam_account)) {
		
			/* we return only nua accounts, or we will have duplicates */
			if (!idmap_check_sid_is_in_free_range(pdb_get_user_sid(sam_account))) {
				continue;
			}

			*info = talloc_realloc(mem_ctx, *info, (i + 1) * sizeof(WINBIND_USERINFO));
			if (!(*info)) {
				DEBUG(0,("query_user_list: out of memory!\n"));
				result = NT_STATUS_NO_MEMORY;
				break;
			}

			(*info)[i].user_sid = talloc(mem_ctx, sizeof(DOM_SID));
			(*info)[i].group_sid = talloc(mem_ctx, sizeof(DOM_SID));
			if (!((*info)[i].user_sid) || !((*info)[i].group_sid)) {
				DEBUG(0,("query_user_list: out of memory!\n"));
				result = NT_STATUS_NO_MEMORY;
				break;
			}
			sid_copy((*info)[i].user_sid, pdb_get_user_sid(sam_account));
			sid_copy((*info)[i].group_sid, pdb_get_group_sid(sam_account));

			(*info)[i].acct_name = talloc_strdup(mem_ctx, pdb_get_username(sam_account));
			(*info)[i].full_name = talloc_strdup(mem_ctx, pdb_get_fullname(sam_account));
			if (!((*info)[i].acct_name) || !((*info)[i].full_name)) {
				DEBUG(0,("query_user_list: out of memory!\n"));
				result = NT_STATUS_NO_MEMORY;
				break;
			}

			i++;

			if (!NT_STATUS_IS_OK(pdb_reset_sam(sam_account))) {
				result = NT_STATUS_UNSUCCESSFUL;
				break;
			}
		}

		*num_entries = i;
		result = NT_STATUS_OK;
	
	} else {
		result = NT_STATUS_UNSUCCESSFUL;
	}

	pdb_free_sam(&sam_account);
	return result;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	NTSTATUS result = NT_STATUS_OK;

	DEBUG(3,("pdb: enum_dom_groups (group support not implemented)\n"));

	*num_entries = 0;
	*info = 0;

	return result;	
}

/* List all domain groups */

static NTSTATUS enum_local_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	NTSTATUS result = NT_STATUS_OK;

	DEBUG(3,("pdb: enum_local_groups (group support not implemented)\n"));

	*num_entries = 0;
	*info = 0;

	return result;	
}

/* convert a single name to a sid in a domain */
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const char *name,
			    DOM_SID *sid,
			    enum SID_NAME_USE *type)
{
	SAM_ACCOUNT *sam_account = NULL;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	DEBUG(3,("pdb: name_to_sid name=%s (group support not implemented)\n", name));

	if (NT_STATUS_IS_OK(pdb_init_sam(&sam_account))) {
		if (!pdb_getsampwnam(sam_account, name)) {
			result = NT_STATUS_UNSUCCESSFUL;
	 	} else { /* it is a sam user */
			sid_copy(sid, pdb_get_user_sid(sam_account));
			*type = SID_NAME_USER;
			result = NT_STATUS_OK;
		}
	}

	pdb_free_sam(&sam_account);
	return result;	
}

/*
  convert a domain SID to a user or group name
*/
static NTSTATUS sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    DOM_SID *sid,
			    char **name,
			    enum SID_NAME_USE *type)
{
	SAM_ACCOUNT *sam_account = NULL;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 id;

	DEBUG(3,("pdb: sid_to_name sid=%s\n", sid_string_static(sid)));

	if (NT_STATUS_IS_OK(sid_to_uid(sid, &id))) { /* this is a user */

		if (!NT_STATUS_IS_OK(result = pdb_init_sam(&sam_account))) {
			return result;
		}
	
		if (!pdb_getsampwsid(sam_account, sid)) {
			pdb_free_sam(&sam_account);
			return NT_STATUS_UNSUCCESSFUL;
 		}
	
		*name = talloc_strdup(mem_ctx, pdb_get_username(sam_account));	
		if (!(*name)) {
			DEBUG(0,("query_user: out of memory!\n"));
			pdb_free_sam(&sam_account);
			return NT_STATUS_NO_MEMORY;
		}

		pdb_free_sam(&sam_account);
		*type = SID_NAME_USER;
		result = NT_STATUS_OK;

	} else if (NT_STATUS_IS_OK(sid_to_gid(sid, &id))) { /* this is a group */
		
		DEBUG(3,("pdb: sid_to_name: group support not implemented\n"));
		result = NT_STATUS_UNSUCCESSFUL;
	}

	return result;
}

/* Lookup user information from a rid or username. */
static NTSTATUS query_user(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   DOM_SID *user_sid, 
			   WINBIND_USERINFO *user_info)
{
	SAM_ACCOUNT *sam_account = NULL;
	NTSTATUS result;

	DEBUG(3,("pdb: query_user sid=%s\n", sid_string_static(user_sid)));

	if (!NT_STATUS_IS_OK(result = pdb_init_sam(&sam_account))) {
		return result;
	}
	
	if (!pdb_getsampwsid(sam_account, user_sid)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_UNSUCCESSFUL;
 	}

	/* we return only nua accounts, or we will have duplicates */
	if (!idmap_check_sid_is_in_free_range(user_sid)) {
		pdb_free_sam(&sam_account);
		return NT_STATUS_UNSUCCESSFUL;
	}

	user_info->user_sid = talloc(mem_ctx, sizeof(DOM_SID));
	user_info->group_sid = talloc(mem_ctx, sizeof(DOM_SID));
	if (!(user_info->user_sid) || !(user_info->group_sid)) {
		DEBUG(0,("query_user: out of memory!\n"));
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}
	sid_copy(user_info->user_sid, pdb_get_user_sid(sam_account));
	sid_copy(user_info->group_sid, pdb_get_group_sid(sam_account));

	user_info->acct_name = talloc_strdup(mem_ctx, pdb_get_username(sam_account));
	user_info->full_name = talloc_strdup(mem_ctx, pdb_get_fullname(sam_account));
	if (!(user_info->acct_name) || !(user_info->full_name)) {
		DEBUG(0,("query_user: out of memory!\n"));
		pdb_free_sam(&sam_account);
		return NT_STATUS_NO_MEMORY;
	}

	pdb_free_sam(&sam_account);
	return NT_STATUS_OK;
}                                   

/* Lookup groups a user is a member of.  I wish Unix had a call like this! */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  DOM_SID *user_sid,
				  uint32 *num_groups, DOM_SID ***user_gids)
{
	NTSTATUS result = NT_STATUS_OK;

	DEBUG(3,("pdb: lookup_usergroups (group support not implemented)\n"));

	num_groups = 0;
	user_gids = 0;

	return result;
}


/* Lookup group membership given a rid.   */
static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				DOM_SID *group_sid, uint32 *num_names, 
				DOM_SID ***sid_mem, char ***names, 
				uint32 **name_types)
{
        NTSTATUS result = NT_STATUS_NOT_IMPLEMENTED;

	DEBUG(3,("pdb: lookup_groupmem (group support not implemented)\n"));

	num_names = 0;
	sid_mem = 0;
	names = 0;
	name_types = 0;

        return result;
}

/* find the sequence number for a domain */
static NTSTATUS sequence_number(struct winbindd_domain *domain, uint32 *seq)
{
	/* FIXME: we fake up the seq_num untill our passdb support it */
	static uint32 seq_num;

	DEBUG(3,("pdb: sequence_number\n"));

	*seq = seq_num++;

	return NT_STATUS_OK;
}

/* get a list of trusted domains */
static NTSTATUS trusted_domains(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_domains,
				char ***names,
				char ***alt_names,
				DOM_SID **dom_sids)
{
	NTSTATUS result = NT_STATUS_NOT_IMPLEMENTED;

	DEBUG(3,("pdb: trusted_domains (todo!)\n"));

	return result;
}

/* find the domain sid for a domain */
static NTSTATUS domain_sid(struct winbindd_domain *domain, DOM_SID *sid)
{
	DEBUG(3,("pdb: domain_sid\n"));

	if (strcmp(domain->name, lp_workgroup())) {
		return NT_STATUS_INVALID_PARAMETER;
	} else {
		sid_copy(sid, get_global_sam_sid());
		return NT_STATUS_OK;
	}
}

/* find alternate names list for the domain 
 * should we look for netbios aliases?? 
				SSS	*/
static NTSTATUS alternate_name(struct winbindd_domain *domain)
{
	DEBUG(3,("pdb: alternate_name\n"));

	return NT_STATUS_OK;
}


/* the rpc backend methods are exposed via this structure */
struct winbindd_methods passdb_methods = {
	False,
	query_user_list,
	enum_dom_groups,
	enum_local_groups,
	name_to_sid,
	sid_to_name,
	query_user,
	lookup_usergroups,
	lookup_groupmem,
	sequence_number,
	trusted_domains,
	domain_sid,
	alternate_name
};
