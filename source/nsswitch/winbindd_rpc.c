/* 
   Unix SMB/CIFS implementation.

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
			       uint32 *num_entries, 
			       WINBIND_USERINFO **info)
{
	CLI_POLICY_HND *hnd;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND dom_pol;
	BOOL got_dom_pol = False;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	int i;

	*num_entries = 0;
	*info = NULL;

	/* Get sam handle */

	if (!(hnd = cm_get_sam_handle(domain->name)))
		goto done;

	/* Get domain handle */

	result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
					des_access, &domain->sid, &dom_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;

	i = 0;
	do {
		SAM_DISPINFO_CTR ctr;
		SAM_DISPINFO_1 info1;
		uint32 count = 0, start=i;
		int j;
		TALLOC_CTX *ctx2;

		ctr.sam.info1 = &info1;

		ctx2 = talloc_init_named("winbindd dispinfo");
		if (!ctx2) {
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}
		
		/* Query display info level 1 */
		result = cli_samr_query_dispinfo(hnd->cli, ctx2,
						 &dom_pol, &start, 1,
						 &count, 0xFFFF, &ctr);

		if (!NT_STATUS_IS_OK(result) && 
		    !NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES)) break;

		(*num_entries) += count;

		/* now map the result into the WINBIND_USERINFO structure */
		(*info) = talloc_realloc(mem_ctx, *info,
					 (*num_entries)*sizeof(WINBIND_USERINFO));
		if (!(*info)) {
			result = NT_STATUS_NO_MEMORY;
			talloc_destroy(ctx2);
			goto done;
		}

		for (j=0;j<count;i++, j++) {
			(*info)[i].acct_name = unistr2_tdup(mem_ctx, &info1.str[j].uni_acct_name);
			(*info)[i].full_name = unistr2_tdup(mem_ctx, &info1.str[j].uni_full_name);
			(*info)[i].user_rid = info1.sam[j].rid_user;
			/* For the moment we set the primary group for
			   every user to be the Domain Users group.
			   There are serious problems with determining
			   the actual primary group for large domains.
			   This should really be made into a 'winbind
			   force group' smb.conf parameter or
			   something like that. */
			(*info)[i].group_rid = DOMAIN_GROUP_RID_USERS;
		}

		talloc_destroy(ctx2);
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

 done:

	if (got_dom_pol)
		cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

	return result;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	CLI_POLICY_HND *hnd;
	POLICY_HND dom_pol;
	NTSTATUS status;

	*num_entries = 0;
	*info = NULL;

	if (!(hnd = cm_get_sam_handle(domain->name))) {
		return NT_STATUS_UNSUCCESSFUL;
	}

	status = cli_samr_open_domain(hnd->cli, mem_ctx,
				      &hnd->pol, des_access, &domain->sid, &dom_pol);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	do {
		struct acct_info *info2 = NULL;
		uint32 count = 0, start = *num_entries;
		TALLOC_CTX *mem_ctx2;

		mem_ctx2 = talloc_init_named("enum_dom_groups[rpc]");

		status = cli_samr_enum_dom_groups(hnd->cli, mem_ctx2, &dom_pol,
						  &start,
						  0xFFFF, /* buffer size? */
						  &info2, &count);

		if (!NT_STATUS_IS_OK(status) && 
		    !NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
			talloc_destroy(mem_ctx2);
			break;
		}

		(*info) = talloc_realloc(mem_ctx, *info, 
					 sizeof(**info) * ((*num_entries) + count));
		if (! *info) {
			talloc_destroy(mem_ctx2);
			cli_samr_close(hnd->cli, mem_ctx, &dom_pol);
			return NT_STATUS_NO_MEMORY;
		}

		memcpy(&(*info)[*num_entries], info2, count*sizeof(*info2));
		(*num_entries) += count;
		talloc_destroy(mem_ctx2);
	} while (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES));

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
	const char *full_name;

	if (!(mem_ctx = talloc_init_named("name_to_sid[rpc] for [%s]\\[%s]", domain->name, name))) {
		DEBUG(0, ("talloc_init failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}
        
	if (!(hnd = cm_get_lsa_handle(domain->name))) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_UNSUCCESSFUL;
	}
        
	full_name = talloc_asprintf(mem_ctx, "%s\\%s", domain->name, name);
	
	if (!full_name) {
		DEBUG(0, ("talloc_asprintf failed!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	status = cli_lsa_lookup_names(hnd->cli, mem_ctx, &hnd->pol, 1, 
				      &full_name, &sids, &types, &num_sids);
        
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
static NTSTATUS sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    DOM_SID *sid,
			    char **name,
			    enum SID_NAME_USE *type)
{
	CLI_POLICY_HND *hnd;
	char **domains;
	char **names;
	uint32 *types;
	int num_names;
	NTSTATUS status;

	if (!(hnd = cm_get_lsa_handle(domain->name)))
		return NT_STATUS_UNSUCCESSFUL;
        
	status = cli_lsa_lookup_sids(hnd->cli, mem_ctx, &hnd->pol,
				     1, sid, &domains, &names, &types, 
				     &num_names);

	if (NT_STATUS_IS_OK(status)) {
		*type = types[0];
		*name = names[0];
		DEBUG(5,("Mapped sid to [%s]\\[%s]\n", domains[0], *name));

		/* Paranoia */
		if (strcasecmp(domain->name, domains[0]) != 0) {
			DEBUG(1, ("domain name from domain param and PDC lookup return differ! (%s vs %s)\n", domain->name, domains[0]));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}
	return status;
}

/* Lookup user information from a rid or username. */
static NTSTATUS query_user(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   uint32 user_rid, 
			   WINBIND_USERINFO *user_info)
{
	CLI_POLICY_HND *hnd;
	NTSTATUS result;
	POLICY_HND dom_pol, user_pol;
	BOOL got_dom_pol = False, got_user_pol = False;
	SAM_USERINFO_CTR *ctr;

	/* Get sam handle */
	if (!(hnd = cm_get_sam_handle(domain->name)))
		goto done;

	/* Get domain handle */

	result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
				      SEC_RIGHTS_MAXIMUM_ALLOWED, 
				      &domain->sid, &dom_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;

	/* Get user handle */
	result = cli_samr_open_user(hnd->cli, mem_ctx, &dom_pol,
				    SEC_RIGHTS_MAXIMUM_ALLOWED, user_rid, &user_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_user_pol = True;

	/* Get user info */
	result = cli_samr_query_userinfo(hnd->cli, mem_ctx, &user_pol, 
					 0x15, &ctr);

	cli_samr_close(hnd->cli, mem_ctx, &user_pol);
	got_user_pol = False;

	user_info->group_rid = ctr->info.id21->group_rid;
	user_info->acct_name = unistr2_tdup(mem_ctx, 
					    &ctr->info.id21->uni_user_name);
	user_info->full_name = unistr2_tdup(mem_ctx, 
					    &ctr->info.id21->uni_full_name);

 done:
	/* Clean up policy handles */
	if (got_user_pol)
		cli_samr_close(hnd->cli, mem_ctx, &user_pol);

	if (got_dom_pol)
		cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

	return result;
}                                   

/* Lookup groups a user is a member of.  I wish Unix had a call like this! */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  uint32 user_rid, 
				  uint32 *num_groups, uint32 **user_gids)
{
	CLI_POLICY_HND *hnd;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND dom_pol, user_pol;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	BOOL got_dom_pol = False, got_user_pol = False;
	DOM_GID *user_groups;
	int i;

	*num_groups = 0;

	/* First try cached universal groups from logon */
	*user_gids = uni_group_cache_fetch(&domain->sid, user_rid, mem_ctx, num_groups);
	if((*num_groups > 0) && *user_gids) {
		return NT_STATUS_OK;
	} else {
	    *user_gids = NULL;
	    *num_groups = 0;
	}

	/* Get sam handle */
	if (!(hnd = cm_get_sam_handle(domain->name)))
		goto done;

	/* Get domain handle */
	result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
					des_access, &domain->sid, &dom_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;

	/* Get user handle */
	result = cli_samr_open_user(hnd->cli, mem_ctx, &dom_pol,
					des_access, user_rid, &user_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_user_pol = True;

	/* Query user rids */
	result = cli_samr_query_usergroups(hnd->cli, mem_ctx, &user_pol, 
					   num_groups, &user_groups);

	if (!NT_STATUS_IS_OK(result) || (*num_groups) == 0)
		goto done;

	(*user_gids) = talloc(mem_ctx, sizeof(uint32) * (*num_groups));
	for (i=0;i<(*num_groups);i++) {
		(*user_gids)[i] = user_groups[i].g_rid;
	}
	
 done:
	/* Clean up policy handles */
	if (got_user_pol)
		cli_samr_close(hnd->cli, mem_ctx, &user_pol);

	if (got_dom_pol)
		cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

	return result;
}


/* Lookup group membership given a rid.   */
static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 group_rid, uint32 *num_names, 
				uint32 **rid_mem, char ***names, 
				uint32 **name_types)
{
        CLI_POLICY_HND *hnd;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        uint32 i, total_names = 0;
        POLICY_HND dom_pol, group_pol;
        uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
        BOOL got_dom_pol = False, got_group_pol = False;

	*num_names = 0;

        /* Get sam handle */

        if (!(hnd = cm_get_sam_handle(domain->name)))
                goto done;

        /* Get domain handle */

        result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
                                      des_access, &domain->sid, &dom_pol);

        if (!NT_STATUS_IS_OK(result))
                goto done;

        got_dom_pol = True;

        /* Get group handle */

        result = cli_samr_open_group(hnd->cli, mem_ctx, &dom_pol,
                                     des_access, group_rid, &group_pol);

        if (!NT_STATUS_IS_OK(result))
                goto done;

        got_group_pol = True;

        /* Step #1: Get a list of user rids that are the members of the
           group. */

        result = cli_samr_query_groupmem(hnd->cli, mem_ctx,
                                         &group_pol, num_names, rid_mem,
                                         name_types);

        if (!NT_STATUS_IS_OK(result))
                goto done;

        /* Step #2: Convert list of rids into list of usernames.  Do this
           in bunches of ~1000 to avoid crashing NT4.  It looks like there
           is a buffer overflow or something like that lurking around
           somewhere. */

#define MAX_LOOKUP_RIDS 900

        *names = talloc_zero(mem_ctx, *num_names * sizeof(char *));
        *name_types = talloc_zero(mem_ctx, *num_names * sizeof(uint32));

        for (i = 0; i < *num_names; i += MAX_LOOKUP_RIDS) {
                int num_lookup_rids = MIN(*num_names - i, MAX_LOOKUP_RIDS);
                uint32 tmp_num_names = 0;
                char **tmp_names = NULL;
                uint32 *tmp_types = NULL;

                /* Lookup a chunk of rids */

                result = cli_samr_lookup_rids(hnd->cli, mem_ctx,
                                              &dom_pol, 1000, /* flags */
                                              num_lookup_rids,
                                              &(*rid_mem)[i],
                                              &tmp_num_names,
                                              &tmp_names, &tmp_types);

                if (!NT_STATUS_IS_OK(result))
                        goto done;

                /* Copy result into array.  The talloc system will take
                   care of freeing the temporary arrays later on. */

                memcpy(&(*names)[i], tmp_names, sizeof(char *) * 
                       tmp_num_names);

                memcpy(&(*name_types)[i], tmp_types, sizeof(uint32) *
                       tmp_num_names);

                total_names += tmp_num_names;
        }

        *num_names = total_names;

 done:
        if (got_group_pol)
                cli_samr_close(hnd->cli, mem_ctx, &group_pol);

        if (got_dom_pol)
                cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

        return result;
}

/* find the sequence number for a domain */
static NTSTATUS sequence_number(struct winbindd_domain *domain, uint32 *seq)
{
	TALLOC_CTX *mem_ctx;
	CLI_POLICY_HND *hnd;
	SAM_UNK_CTR ctr;
	uint16 switch_value = 2;
	NTSTATUS result;
	uint32 seqnum = DOM_SEQUENCE_NONE;
	POLICY_HND dom_pol;
	BOOL got_dom_pol = False;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;

	*seq = DOM_SEQUENCE_NONE;

	if (!(mem_ctx = talloc_init_named("sequence_number[rpc]")))
		return NT_STATUS_NO_MEMORY;

	/* Get sam handle */

	if (!(hnd = cm_get_sam_handle(domain->name)))
		goto done;

	/* Get domain handle */

	result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol, 
				      des_access, &domain->sid, &dom_pol);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;

	/* Query domain info */

	result = cli_samr_query_dom_info(hnd->cli, mem_ctx, &dom_pol,
					 switch_value, &ctr);

	if (NT_STATUS_IS_OK(result)) {
		seqnum = ctr.info.inf2.seq_num;
		DEBUG(10,("domain_sequence_number: for domain %s is %u\n", domain->name, (unsigned)seqnum ));
	} else {
		DEBUG(10,("domain_sequence_number: failed to get sequence number (%u) for domain %s\n",
			(unsigned)seqnum, domain->name ));
	}

  done:

	if (got_dom_pol)
		cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

	talloc_destroy(mem_ctx);

	*seq = seqnum;

	return result;
}

/* get a list of trusted domains */
static NTSTATUS trusted_domains(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_domains,
				char ***names,
				DOM_SID **dom_sids)
{
	CLI_POLICY_HND *hnd;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 enum_ctx = 0;

	*num_domains = 0;

	if (!(hnd = cm_get_lsa_handle(lp_workgroup())))
		goto done;

	result = cli_lsa_enum_trust_dom(hnd->cli, mem_ctx,
					&hnd->pol, &enum_ctx, num_domains, 
					names, dom_sids);
done:
	return result;
}

/* find the domain sid for a domain */
static NTSTATUS domain_sid(struct winbindd_domain *domain, DOM_SID *sid)
{
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	CLI_POLICY_HND *hnd;
	fstring level5_dom;

	if (!(mem_ctx = talloc_init_named("domain_sid[rpc]")))
		return NT_STATUS_NO_MEMORY;

	/* Get sam handle */
	if (!(hnd = cm_get_lsa_handle(domain->name)))
		goto done;

	status = cli_lsa_query_info_policy(hnd->cli, mem_ctx,
					   &hnd->pol, 0x05, level5_dom, sid);

done:
	talloc_destroy(mem_ctx);
	return status;
}

/* the rpc backend methods are exposed via this structure */
struct winbindd_methods msrpc_methods = {
	False,
	query_user_list,
	enum_dom_groups,
	name_to_sid,
	sid_to_name,
	query_user,
	lookup_usergroups,
	lookup_groupmem,
	sequence_number,
	trusted_domains,
	domain_sid
};
