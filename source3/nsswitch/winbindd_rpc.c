/* 
   Unix SMB/Netbios implementation.

   Winbind rpc backend functions

   Copyright (C) Tim Potter 2000-2001
   Copyright (C) Andrew Tridgell 2001
   
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

/* Query display info for a domain.  This returns enough information plus a
   bit extra to give an overview of domain users for the User Manager
   application. */
static NTSTATUS query_user_list(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32 *start_ndx, uint32 *num_entries, 
			       WINBIND_USERINFO **info)
{
	CLI_POLICY_HND *hnd;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND dom_pol;
	BOOL got_dom_pol = False;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	SAM_DISPINFO_CTR ctr;
	SAM_DISPINFO_1 info1;
	int i;

	/* Get sam handle */

	if (!(hnd = cm_get_sam_handle(domain->name)))
		goto done;

	/* Get domain handle */

	result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
					des_access, &domain->sid, &dom_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;

	ctr.sam.info1 = &info1;

	/* Query display info level 1 */
	result = cli_samr_query_dispinfo(hnd->cli, mem_ctx,
					&dom_pol, start_ndx, 1,
					num_entries, 0xffff, &ctr);

	/* now map the result into the WINBIND_USERINFO structure */
	(*info) = (WINBIND_USERINFO *)talloc(mem_ctx, (*num_entries)*sizeof(WINBIND_USERINFO));
	if (!(*info)) {
		return NT_STATUS_NO_MEMORY;
	}

	for (i=0;i<*num_entries;i++) {
		(*info)[i].acct_name = unistr2_tdup(mem_ctx, &info1.str[i].uni_acct_name);
		(*info)[i].full_name = unistr2_tdup(mem_ctx, &info1.str[i].uni_full_name);
		(*info)[i].user_rid = info1.sam[i].rid_user;
		/* For the moment we set the primary group for every user to be the
		   Domain Users group.  There are serious problems with determining
		   the actual primary group for large domains.  This should really
		   be made into a 'winbind force group' smb.conf parameter or
		   something like that. */ 
		(*info)[i].group_rid = DOMAIN_GROUP_RID_USERS;
	}

 done:

	if (got_dom_pol)
		cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

	return result;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *start_ndx, uint32 *num_entries, 
				struct acct_info **info)
{
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	CLI_POLICY_HND *hnd;
	POLICY_HND dom_pol;
	NTSTATUS status;

	*num_entries = 0;

	if (!(hnd = cm_get_sam_handle(domain->name))) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = cli_samr_open_domain(hnd->cli, mem_ctx,
				      &hnd->pol, des_access, &domain->sid, &dom_pol);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = cli_samr_enum_dom_groups(hnd->cli, mem_ctx, &dom_pol,
					  start_ndx,
					  0x8000, /* buffer size? */
					  info, num_entries);

	cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

	return status;
}

/* convert a single name to a sid in a domain */
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    const char *name,
			    DOM_SID *sid,
			    enum SID_NAME_USE *type)
{
	TALLOC_CTX *mem_ctx;
	CLI_POLICY_HND *hnd;
	NTSTATUS status;
	DOM_SID *sids = NULL;
	uint32 *types = NULL;
	int num_sids;

	if (!(mem_ctx = talloc_init()))
		return NT_STATUS_NO_MEMORY;
        
	if (!(hnd = cm_get_lsa_handle(domain->name)))
		return NT_STATUS_UNSUCCESSFUL;
        
	status = cli_lsa_lookup_names(hnd->cli, mem_ctx, &hnd->pol, 1, &name, 
				      &sids, &types, &num_sids);
        
	/* Return rid and type if lookup successful */        
	if (NT_STATUS_IS_OK(status)) {
		sid_copy(sid, &sids[0]);
		*type = types[0];
	}

	talloc_destroy(mem_ctx);
	return status;
}

/*
  convert a domain SID to a user or group name
*/
NTSTATUS winbindd_rpc_sid_to_name(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  DOM_SID *sid,
				  char **name,
				  enum SID_NAME_USE *type)
{
	CLI_POLICY_HND *hnd;
	char **names;
	uint32 *types;
	int num_names;
	NTSTATUS status;

	if (!(hnd = cm_get_lsa_handle(domain->name)))
		return NT_STATUS_UNSUCCESSFUL;
        
	status = cli_lsa_lookup_sids(hnd->cli, mem_ctx, &hnd->pol,
				     1, sid, &names, &types, 
				     &num_names);

	if (NT_STATUS_IS_OK(status)) {
		*type = types[0];
		*name = names[0];
		DEBUG(5,("Mapped sid to %s\n", *name));
	}

	return status;
}


/* the rpc backend methods are exposed via this structure */
struct winbindd_methods msrpc_methods = {
	query_user_list,
	enum_dom_groups,
	name_to_sid,
	winbindd_rpc_sid_to_name
};

