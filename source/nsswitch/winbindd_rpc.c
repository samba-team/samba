/* 
   Unix SMB/CIFS implementation.

   Winbind rpc backend functions

   Copyright (C) Tim Potter 2000-2001,2003
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

#include "includes.h"
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
	CLI_POLICY_HND *hnd;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND dom_pol;
	BOOL got_dom_pol = False;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	unsigned int i, start_idx, retry;
	uint32 loop_count;

	DEBUG(3,("rpc: query_user_list\n"));

	*num_entries = 0;
	*info = NULL;

	retry = 0;
	do {
		/* Get sam handle */

		if ( !NT_STATUS_IS_OK(result = cm_get_sam_handle(domain, &hnd)) )
			return result;

		/* Get domain handle */

		result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
						des_access, &domain->sid, &dom_pol);

	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) && hnd && hnd->cli && hnd->cli->fd == -1);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;

	i = start_idx = 0;
	loop_count = 0;

	do {
		TALLOC_CTX *ctx2;
		uint32 num_dom_users, j;
		uint32 max_entries, max_size;
		SAM_DISPINFO_CTR ctr;
		SAM_DISPINFO_1 info1;

		ZERO_STRUCT( ctr );
		ZERO_STRUCT( info1 );
		ctr.sam.info1 = &info1;
	
		if (!(ctx2 = talloc_init("winbindd enum_users"))) {
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}		

		/* this next bit is copied from net_user_list_internal() */

		get_query_dispinfo_params( loop_count, &max_entries, &max_size );

		result = cli_samr_query_dispinfo(hnd->cli, mem_ctx, &dom_pol,
			&start_idx, 1, &num_dom_users, max_entries, max_size, &ctr);

		loop_count++;

		*num_entries += num_dom_users;

		*info = talloc_realloc( mem_ctx, *info, 
			(*num_entries) * sizeof(WINBIND_USERINFO));

		if (!(*info)) {
			result = NT_STATUS_NO_MEMORY;
			talloc_destroy(ctx2);
			goto done;
		}

		for (j = 0; j < num_dom_users; i++, j++) {
			fstring username, fullname;
			uint32 rid = ctr.sam.info1->sam[j].rid_user;
			
			unistr2_to_ascii( username, &(&ctr.sam.info1->str[j])->uni_acct_name, sizeof(username)-1);
			unistr2_to_ascii( fullname, &(&ctr.sam.info1->str[j])->uni_full_name, sizeof(fullname)-1);
			
			(*info)[i].acct_name = talloc_strdup(mem_ctx, username );
			(*info)[i].full_name = talloc_strdup(mem_ctx, fullname );
			(*info)[i].user_sid = rid_to_talloced_sid(domain, mem_ctx, rid );
			
			/* For the moment we set the primary group for
			   every user to be the Domain Users group.
			   There are serious problems with determining
			   the actual primary group for large domains.
			   This should really be made into a 'winbind
			   force group' smb.conf parameter or
			   something like that. */
			   
			(*info)[i].group_sid = rid_to_talloced_sid(domain, 
				mem_ctx, DOMAIN_GROUP_RID_USERS);
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
	uint32 start = 0;
	int retry;
	NTSTATUS result;

	*num_entries = 0;
	*info = NULL;

	DEBUG(3,("rpc: enum_dom_groups\n"));

	retry = 0;
	do {
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain, &hnd)))
			return result;

		status = cli_samr_open_domain(hnd->cli, mem_ctx,
					      &hnd->pol, des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(status) && (retry++ < 1) && hnd && hnd->cli && hnd->cli->fd == -1);

	if (!NT_STATUS_IS_OK(status))
		return status;

	do {
		struct acct_info *info2 = NULL;
		uint32 count = 0;
		TALLOC_CTX *mem_ctx2;

		mem_ctx2 = talloc_init("enum_dom_groups[rpc]");

		/* start is updated by this call. */
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

/* List all domain groups */

static NTSTATUS enum_local_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	CLI_POLICY_HND *hnd;
	POLICY_HND dom_pol;
	NTSTATUS result;
	int retry;

	*num_entries = 0;
	*info = NULL;

	retry = 0;
	do {
		if ( !NT_STATUS_IS_OK(result = cm_get_sam_handle(domain, &hnd)) )
			return result;

		result = cli_samr_open_domain( hnd->cli, mem_ctx, &hnd->pol, 
						des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) && hnd && hnd->cli && hnd->cli->fd == -1);

	if ( !NT_STATUS_IS_OK(result))
		return result;

	do {
		struct acct_info *info2 = NULL;
		uint32 count = 0, start = *num_entries;
		TALLOC_CTX *mem_ctx2;

		mem_ctx2 = talloc_init("enum_dom_local_groups[rpc]");

		result = cli_samr_enum_als_groups( hnd->cli, mem_ctx2, &dom_pol,
					  &start, 0xFFFF, &info2, &count);
					  
		if ( !NT_STATUS_IS_OK(result) 
			&& !NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES) ) 
		{
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
	} while (NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES));

	cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

	return result;
}

/* convert a single name to a sid in a domain */
NTSTATUS msrpc_name_to_sid(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const char *domain_name,
			    const char *name,
			    DOM_SID *sid,
			    enum SID_NAME_USE *type)
{
	CLI_POLICY_HND *hnd;
	NTSTATUS result;
	DOM_SID *sids = NULL;
	uint32 *types = NULL;
	const char *full_name;
	int retry;

	DEBUG(3,("rpc: name_to_sid name=%s\n", name));

	full_name = talloc_asprintf(mem_ctx, "%s\\%s", domain_name, name);
	
	if (!full_name) {
		DEBUG(0, ("talloc_asprintf failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}

	DEBUG(3,("name_to_sid [rpc] %s for domain %s\n", name, domain_name ));

	retry = 0;
	do {
		if (!NT_STATUS_IS_OK(result = cm_get_lsa_handle(domain, &hnd))) {
			return result;
		}
        
		result = cli_lsa_lookup_names(hnd->cli, mem_ctx, &hnd->pol, 1, 
					      &full_name, &sids, &types);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);
        
	/* Return rid and type if lookup successful */

	if (NT_STATUS_IS_OK(result)) {
		sid_copy(sid, &sids[0]);
		*type = (enum SID_NAME_USE)types[0];
	}

	return result;
}

/*
  convert a domain SID to a user or group name
*/
NTSTATUS msrpc_sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const DOM_SID *sid,
			    char **domain_name,
			    char **name,
			    enum SID_NAME_USE *type)
{
	CLI_POLICY_HND *hnd;
	char **domains;
	char **names;
	uint32 *types;
	NTSTATUS result;
	int retry;

	DEBUG(3,("sid_to_name [rpc] %s for domain %s\n", sid_string_static(sid),
			domain->name ));

	retry = 0;
	do {
		if (!NT_STATUS_IS_OK(result = cm_get_lsa_handle(domain, &hnd)))
			return result;
        
		result = cli_lsa_lookup_sids(hnd->cli, mem_ctx, &hnd->pol,
					     1, sid, &domains, &names, &types);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);

	if (NT_STATUS_IS_OK(result)) {
		*type = (enum SID_NAME_USE)types[0];
		*domain_name = domains[0];
		*name = names[0];
		DEBUG(5,("Mapped sid to [%s]\\[%s]\n", domains[0], *name));
	}

	return result;
}

/* Lookup user information from a rid or username. */
static NTSTATUS query_user(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   const DOM_SID *user_sid, 
			   WINBIND_USERINFO *user_info)
{
	CLI_POLICY_HND *hnd = NULL;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND dom_pol, user_pol;
	BOOL got_dom_pol = False, got_user_pol = False;
	SAM_USERINFO_CTR *ctr;
	int retry;
	fstring sid_string;
	uint32 user_rid;
	NET_USER_INFO_3 *user;

	DEBUG(3,("rpc: query_user rid=%s\n", sid_to_string(sid_string, user_sid)));
	if (!sid_peek_check_rid(&domain->sid, user_sid, &user_rid)) {
		goto done;
	}
	
	/* try netsamlogon cache first */
			
	if ( (user = netsamlogon_cache_get( mem_ctx, user_sid )) != NULL ) 
	{
				
		DEBUG(5,("query_user: Cache lookup succeeded for %s\n", 
			sid_string_static(user_sid)));
			
		user_info->user_sid  = rid_to_talloced_sid( domain, mem_ctx, user_rid );
		user_info->group_sid = rid_to_talloced_sid( domain, mem_ctx, user->group_rid );
				
		user_info->acct_name = unistr2_tdup(mem_ctx, &user->uni_user_name);
		user_info->full_name = unistr2_tdup(mem_ctx, &user->uni_full_name);
								
		SAFE_FREE(user);
				
		return NT_STATUS_OK;
	}
	
	/* no cache; hit the wire */
		
	retry = 0;
	do {
		/* Get sam handle; if we fail here there is no hope */
		
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain, &hnd))) 
			goto done;
			
		/* Get domain handle */

		result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
					      SEC_RIGHTS_MAXIMUM_ALLOWED, 
					      &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);

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

	if (!NT_STATUS_IS_OK(result))
		goto done;

	cli_samr_close(hnd->cli, mem_ctx, &user_pol);
	got_user_pol = False;

	user_info->user_sid = rid_to_talloced_sid(domain, mem_ctx, user_rid);
	user_info->group_sid = rid_to_talloced_sid(domain, mem_ctx, ctr->info.id21->group_rid);
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
				  const DOM_SID *user_sid,
				  uint32 *num_groups, DOM_SID ***user_grpsids)
{
	CLI_POLICY_HND *hnd;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	POLICY_HND dom_pol, user_pol;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	BOOL got_dom_pol = False, got_user_pol = False;
	DOM_GID *user_groups;
	unsigned int i;
	unsigned int retry;
	fstring sid_string;
	uint32 user_rid;
	NET_USER_INFO_3 *user;

	DEBUG(3,("rpc: lookup_usergroups sid=%s\n", sid_to_string(sid_string, user_sid)));

	*num_groups = 0;
	*user_grpsids = NULL;

	/* so lets see if we have a cached user_info_3 */
	
	if ( (user = netsamlogon_cache_get( mem_ctx, user_sid )) != NULL )
	{
		DEBUG(5,("query_user: Cache lookup succeeded for %s\n", 
			sid_string_static(user_sid)));
			
		*num_groups = user->num_groups;
				
		(*user_grpsids) = talloc(mem_ctx, sizeof(DOM_SID*) * (*num_groups));
		for (i=0;i<(*num_groups);i++) {
			(*user_grpsids)[i] = rid_to_talloced_sid(domain, mem_ctx, user->gids[i].g_rid);
		}
				
		SAFE_FREE(user);
				
		return NT_STATUS_OK;
	}

	/* no cache; hit the wire */
	
	retry = 0;
	do {
		/* Get sam handle; if we fail here there is no hope */
		
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain, &hnd))) 		
			goto done;

		/* Get domain handle */
		
		result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
					      des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) && 
			hnd && hnd->cli && hnd->cli->fd == -1);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;


	if (!sid_peek_check_rid(&domain->sid, user_sid, &user_rid)) {
		goto done;
	}

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

	(*user_grpsids) = talloc(mem_ctx, sizeof(DOM_SID*) * (*num_groups));
	if (!(*user_grpsids)) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0;i<(*num_groups);i++) {
		(*user_grpsids)[i] = rid_to_talloced_sid(domain, mem_ctx, user_groups[i].g_rid);
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
				const DOM_SID *group_sid, uint32 *num_names, 
				DOM_SID ***sid_mem, char ***names, 
				uint32 **name_types)
{
        CLI_POLICY_HND *hnd = NULL;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        uint32 i, total_names = 0;
        POLICY_HND dom_pol, group_pol;
        uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
        BOOL got_dom_pol = False, got_group_pol = False;
	uint32 *rid_mem = NULL;
	uint32 group_rid;
	int retry;
	unsigned int j;
	fstring sid_string;

	DEBUG(10,("rpc: lookup_groupmem %s sid=%s\n", domain->name, sid_to_string(sid_string, group_sid)));

	if (!sid_peek_check_rid(&domain->sid, group_sid, &group_rid)) {
		goto done;
	}

	*num_names = 0;

	retry = 0;
	do {
	        /* Get sam handle */
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain, &hnd)))
			goto done;

		/* Get domain handle */

		result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
				des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) && hnd && hnd->cli && hnd->cli->fd == -1);

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
                                         &group_pol, num_names, &rid_mem,
                                         name_types);

        if (!NT_STATUS_IS_OK(result))
                goto done;

	if (!*num_names) {
		names = NULL;
		name_types = NULL;
		sid_mem = NULL;
		goto done;
	}

        /* Step #2: Convert list of rids into list of usernames.  Do this
           in bunches of ~1000 to avoid crashing NT4.  It looks like there
           is a buffer overflow or something like that lurking around
           somewhere. */

#define MAX_LOOKUP_RIDS 900

        *names = talloc_zero(mem_ctx, *num_names * sizeof(char *));
        *name_types = talloc_zero(mem_ctx, *num_names * sizeof(uint32));
        *sid_mem = talloc_zero(mem_ctx, *num_names * sizeof(DOM_SID *));

	for (j=0;j<(*num_names);j++) {
		(*sid_mem)[j] = rid_to_talloced_sid(domain, mem_ctx, (rid_mem)[j]);
	}
	
	if (*num_names>0 && (!*names || !*name_types)) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

        for (i = 0; i < *num_names; i += MAX_LOOKUP_RIDS) {
                int num_lookup_rids = MIN(*num_names - i, MAX_LOOKUP_RIDS);
                uint32 tmp_num_names = 0;
                char **tmp_names = NULL;
                uint32 *tmp_types = NULL;

                /* Lookup a chunk of rids */

                result = cli_samr_lookup_rids(hnd->cli, mem_ctx,
                                              &dom_pol, 1000, /* flags */
                                              num_lookup_rids,
                                              &rid_mem[i],
                                              &tmp_num_names,
                                              &tmp_names, &tmp_types);

		/* see if we have a real error (and yes the STATUS_SOME_UNMAPPED is
		   the one returned from 2k) */
		
                if (!NT_STATUS_IS_OK(result) && NT_STATUS_V(result) != NT_STATUS_V(STATUS_SOME_UNMAPPED))
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

 	result = NT_STATUS_OK;
	
done:
        if (got_group_pol)
                cli_samr_close(hnd->cli, mem_ctx, &group_pol);

        if (got_dom_pol)
                cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

        return result;
}

#ifdef HAVE_LDAP

#include <ldap.h>

static SIG_ATOMIC_T gotalarm;

/***************************************************************
 Signal function to tell us we timed out.
****************************************************************/

static void gotalarm_sig(void)
{
	gotalarm = 1;
}

static LDAP *ldap_open_with_timeout(const char *server, int port, unsigned int to)
{
	LDAP *ldp = NULL;

	/* Setup timeout */
	gotalarm = 0;
	CatchSignal(SIGALRM, SIGNAL_CAST gotalarm_sig);
	alarm(to);
	/* End setup timeout. */

	ldp = ldap_open(server, port);

	/* Teardown timeout. */
	CatchSignal(SIGALRM, SIGNAL_CAST SIG_IGN);
	alarm(0);

	return ldp;
}

static int get_ldap_seq(const char *server, int port, uint32 *seq)
{
	int ret = -1;
	struct timeval to;
	char *attrs[] = {"highestCommittedUSN", NULL};
	LDAPMessage *res = NULL;
	char **values = NULL;
	LDAP *ldp = NULL;

	*seq = DOM_SEQUENCE_NONE;

	/*
	 * 10 second timeout on open. This is needed as the search timeout
	 * doesn't seem to apply to doing an open as well. JRA.
	 */

	if ((ldp = ldap_open_with_timeout(server, port, 10)) == NULL)
		return -1;

	/* Timeout if no response within 20 seconds. */
	to.tv_sec = 10;
	to.tv_usec = 0;

	if (ldap_search_st(ldp, "", LDAP_SCOPE_BASE, "(objectclass=*)", &attrs[0], 0, &to, &res))
		goto done;

	if (ldap_count_entries(ldp, res) != 1)
		goto done;

	values = ldap_get_values(ldp, res, "highestCommittedUSN");
	if (!values || !values[0])
		goto done;

	*seq = atoi(values[0]);
	ret = 0;

  done:

	if (values)
		ldap_value_free(values);
	if (res)
		ldap_msgfree(res);
	if (ldp)
		ldap_unbind(ldp);
	return ret;
}

/**********************************************************************
 Get the sequence number for a Windows AD native mode domain using
 LDAP queries
**********************************************************************/

static int get_ldap_sequence_number( const char* domain, uint32 *seq)
{
	int ret = -1;
	int i, port = LDAP_PORT;
	struct ip_service *ip_list = NULL;
	int count;
	
	if ( !get_sorted_dc_list(domain, &ip_list, &count, False) ) {
		DEBUG(3, ("Could not look up dc's for domain %s\n", domain));
		return False;
	}

	/* Finally return first DC that we can contact */

	for (i = 0; i < count; i++) {
		fstring ipstr;

		/* since the is an LDAP lookup, default to the LDAP_PORT is not set */
		port = (ip_list[i].port!= PORT_NONE) ? ip_list[i].port : LDAP_PORT;

		fstrcpy( ipstr, inet_ntoa(ip_list[i].ip) );
		
		if (is_zero_ip(ip_list[i].ip))
			continue;

		if ( (ret = get_ldap_seq( ipstr, port,  seq)) == 0 )
			goto done;

		/* add to failed connection cache */
		add_failed_connection_entry( domain, ipstr, NT_STATUS_UNSUCCESSFUL );
	}

done:
	if ( ret == 0 ) {
		DEBUG(3, ("get_ldap_sequence_number: Retrieved sequence number for Domain (%s) from DC (%s:%d)\n", 
			domain, inet_ntoa(ip_list[i].ip), port));
	}

	SAFE_FREE(ip_list);

	return ret;
}

#endif /* HAVE_LDAP */

/* find the sequence number for a domain */
static NTSTATUS sequence_number(struct winbindd_domain *domain, uint32 *seq)
{
	TALLOC_CTX *mem_ctx;
	CLI_POLICY_HND *hnd;
	SAM_UNK_CTR ctr;
	uint16 switch_value = 2;
	NTSTATUS result;
	POLICY_HND dom_pol;
	BOOL got_dom_pol = False;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	int retry;

	DEBUG(10,("rpc: fetch sequence_number for %s\n", domain->name));

	*seq = DOM_SEQUENCE_NONE;

	if (!(mem_ctx = talloc_init("sequence_number[rpc]")))
		return NT_STATUS_NO_MEMORY;

	retry = 0;
	do {
#ifdef HAVE_LDAP
		if ( domain->native_mode ) 
		{
			DEBUG(8,("using get_ldap_seq() to retrieve the sequence number\n"));

			if ( get_ldap_sequence_number( domain->name, seq ) == 0 ) {			
				result = NT_STATUS_OK;
				DEBUG(10,("domain_sequence_number: LDAP for domain %s is %u\n",
					domain->name, *seq));
				goto done;
			}

			DEBUG(10,("domain_sequence_number: failed to get LDAP sequence number for domain %s\n",
			domain->name ));
		}
#endif /* HAVE_LDAP */
	        /* Get sam handle */
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain, &hnd)))
			goto done;

		/* Get domain handle */
		result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol, 
				      des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) && hnd && hnd->cli && hnd->cli->fd == -1);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;

	/* Query domain info */

	result = cli_samr_query_dom_info(hnd->cli, mem_ctx, &dom_pol,
					 switch_value, &ctr);

	if (NT_STATUS_IS_OK(result)) {
		*seq = ctr.info.inf2.seq_num;
		DEBUG(10,("domain_sequence_number: for domain %s is %u\n", domain->name, (unsigned)*seq));
	} else {
		DEBUG(10,("domain_sequence_number: failed to get sequence number (%u) for domain %s\n",
			(unsigned)*seq, domain->name ));
	}

  done:

	if (got_dom_pol)
		cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

	talloc_destroy(mem_ctx);

	return result;
}

/* get a list of trusted domains */
static NTSTATUS trusted_domains(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_domains,
				char ***names,
				char ***alt_names,
				DOM_SID **dom_sids)
{
	CLI_POLICY_HND *hnd;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	uint32 enum_ctx = 0;
	int retry;

	DEBUG(3,("rpc: trusted_domains\n"));

	*num_domains = 0;
	*alt_names = NULL;

	retry = 0;
	do {
		if (!NT_STATUS_IS_OK(result = cm_get_lsa_handle(find_our_domain(), &hnd)))
			goto done;

		result = cli_lsa_enum_trust_dom(hnd->cli, mem_ctx,
						&hnd->pol, &enum_ctx,
						num_domains, names, dom_sids);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&  hnd && hnd->cli && hnd->cli->fd == -1);

done:
	return result;
}

/* find the domain sid for a domain */
static NTSTATUS domain_sid(struct winbindd_domain *domain, DOM_SID *sid)
{
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *mem_ctx;
	CLI_POLICY_HND *hnd;
	char *level5_dom;
	DOM_SID *alloc_sid;
	int retry;

	DEBUG(3,("rpc: domain_sid\n"));

	if (!(mem_ctx = talloc_init("domain_sid[rpc]")))
		return NT_STATUS_NO_MEMORY;

	retry = 0;
	do {
		/* Get lsa handle */
		if (!NT_STATUS_IS_OK(result = cm_get_lsa_handle(domain, &hnd)))
			goto done;

		result = cli_lsa_query_info_policy(hnd->cli, mem_ctx,
					   &hnd->pol, 0x05, &level5_dom, &alloc_sid);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&  hnd && hnd->cli && hnd->cli->fd == -1);

	if (NT_STATUS_IS_OK(result)) {
		if (alloc_sid) {
			sid_copy(sid, alloc_sid);
		} else {
			result = NT_STATUS_NO_MEMORY;
		}
	}

done:
	talloc_destroy(mem_ctx);
	return result;
}

/* find alternate names list for the domain - none for rpc */
static NTSTATUS alternate_name(struct winbindd_domain *domain)
{
	return NT_STATUS_OK;
}


/* the rpc backend methods are exposed via this structure */
struct winbindd_methods msrpc_methods = {
	False,
	query_user_list,
	enum_dom_groups,
	enum_local_groups,
	msrpc_name_to_sid,
	msrpc_sid_to_name,
	query_user,
	lookup_usergroups,
	lookup_groupmem,
	sequence_number,
	trusted_domains,
	domain_sid,
	alternate_name
};
