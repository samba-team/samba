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

/*******************************************************************
 Duplicate a UNISTR2 string into a UNIX codepage null terminated char*
 using a talloc context
********************************************************************/

static char *unistr2_tdup(TALLOC_CTX *ctx, const UNISTR2 *str)
{
	char *s;
	int maxlen = (str->uni_str_len+1)*4;
	if (!str->buffer)
		return NULL;
	s = (char *)talloc(ctx, maxlen); /* convervative */
	if (!s)
		return NULL;
	unistr2_to_unix(s, str, maxlen);
	return s;
}

/* Query display info for a domain.  This returns enough information plus a
   bit extra to give an overview of domain users for the User Manager
   application. */
static NTSTATUS query_user_list(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32 *num_entries, 
			       WINBIND_USERINFO **info)
{
	CLI_POLICY_HND *hnd;
	NTSTATUS result;
	POLICY_HND dom_pol;
	BOOL got_dom_pol = False;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	int i, loop_count = 0;
	int retry;

	*num_entries = 0;
	*info = NULL;

	retry = 0;
	do {
		/* Get sam handle */

		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain->name, &hnd)))
			goto done;

		/* Get domain handle */

		result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
					des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;

	i = 0;
	do {
		SAM_DISPINFO_CTR ctr;
		SAM_DISPINFO_1 info1;
		uint32 count = 0, start=i, max_entries, max_size;
		int j;
		TALLOC_CTX *ctx2;

		ctr.sam.info1 = &info1;

		ctx2 = talloc_init_named("winbindd dispinfo");
		if (!ctx2) {
			result = NT_STATUS_NO_MEMORY;
			goto done;
		}
		
		get_query_dispinfo_params(
			loop_count, &max_entries, &max_size);

		/* Query display info level 1 */
		result = cli_samr_query_dispinfo(
			hnd->cli, ctx2, &dom_pol, &start, 1, &count, 
			max_entries, max_size, &ctr);

		loop_count++;

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
			/* unistr2_tdup converts to UNIX charset. */
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

/* List all domain groups */

static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	CLI_POLICY_HND *hnd;
	POLICY_HND dom_pol;
	NTSTATUS result;
	uint32 start = 0;
	int retry;

	*num_entries = 0;
	*info = NULL;

	retry = 0;
	do {
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain->name, &hnd)))
			return result;

		result = cli_samr_open_domain(hnd->cli, mem_ctx,
				      &hnd->pol, des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);

	if (!NT_STATUS_IS_OK(result))
		return result;

	do {
		struct acct_info *info2 = NULL;
		uint32 count = 0;
		TALLOC_CTX *mem_ctx2;

		mem_ctx2 = talloc_init_named("enum_dom_groups[rpc]");

		/* This call updates 'start' */
		result = cli_samr_enum_dom_groups(
			hnd->cli, mem_ctx2, &dom_pol, &start,
			0xFFFF, /* buffer size? */ &info2, &count);

		if (!NT_STATUS_IS_OK(result) && 
		    !NT_STATUS_EQUAL(result, STATUS_MORE_ENTRIES)) {
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
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    const char *name,
			    DOM_SID *sid,
			    enum SID_NAME_USE *type)
{
	TALLOC_CTX *mem_ctx;
	CLI_POLICY_HND *hnd;
	NTSTATUS result;
	DOM_SID *sids = NULL;
	uint32 *types = NULL;
	const char *full_name;
	int retry;

	if (!(mem_ctx = talloc_init_named("name_to_sid[rpc] for [%s]\\[%s]", domain->name, name))) {
		DEBUG(0, ("talloc_init failed!\n"));
		return NT_STATUS_NO_MEMORY;
	}
        
	full_name = talloc_asprintf(mem_ctx, "%s\\%s", domain->name, name);
	
	if (!full_name) {
		DEBUG(0, ("talloc_asprintf failed!\n"));
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	retry = 0;
	do {
		if (!NT_STATUS_IS_OK(result = cm_get_lsa_handle(domain->name, &hnd))) {
			talloc_destroy(mem_ctx);
			return NT_STATUS_UNSUCCESSFUL;
		}
        
		result = cli_lsa_lookup_names(hnd->cli, mem_ctx, &hnd->pol, 1, 
				      &full_name, &sids, &types);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);
        
	/* Return rid and type if lookup successful */

	if (NT_STATUS_IS_OK(result)) {
		sid_copy(sid, &sids[0]);
		*type = types[0];
	}

	talloc_destroy(mem_ctx);
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
	CLI_POLICY_HND *hnd;
	char **domains;
	char **names;
	uint32 *types;
	NTSTATUS result;
	int retry;
		
	retry = 0;
	do {
		if (!NT_STATUS_IS_OK(result = cm_get_lsa_handle(domain->name, &hnd)))
			return NT_STATUS_UNSUCCESSFUL;
        
		result = cli_lsa_lookup_sids(hnd->cli, mem_ctx, &hnd->pol,
				     1, sid, &domains, &names, &types);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);

	if (NT_STATUS_IS_OK(result)) {
		*type = types[0];
		*name = names[0];
		DEBUG(5,("Mapped sid to [%s]\\[%s]\n", domains[0], *name));

		/* Paranoia */
		if (strcasecmp(domain->name, domains[0]) != 0) {
			DEBUG(1, ("domain name from domain param and PDC lookup return differ! (%s vs %s)\n", domain->name, domains[0]));
			return NT_STATUS_UNSUCCESSFUL;
		}
	}

	return result;
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
	int retry;

	retry = 0;
	do {
		/* Get sam handle */
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain->name, &hnd)))
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

	user_info->user_rid = user_rid;
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
	NTSTATUS result;
	POLICY_HND dom_pol, user_pol;
	uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
	BOOL got_dom_pol = False, got_user_pol = False;
	DOM_GID *user_groups;
	int i;
	int retry;

	*num_groups = 0;
	*user_gids = NULL;

	retry = 0;
	do {
		/* Get sam handle */
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain->name, &hnd)))
			goto done;

		/* Get domain handle */
		result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
				      des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);

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
        NTSTATUS result;
        uint32 i, total_names = 0;
        POLICY_HND dom_pol, group_pol;
        uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
        BOOL got_dom_pol = False, got_group_pol = False;
	int retry;

	*num_names = 0;

	retry = 0;
	do {
	        /* Get sam handle */
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain->name, &hnd)))
			goto done;

		/* Get domain handle */
		result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
				des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);

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

#ifdef WITH_HORRIBLE_LDAP_NATIVE_MODE_HACK
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

int get_ldap_seq(const char *server, uint32 *seq)
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

	if ((ldp = ldap_open_with_timeout(server, LDAP_PORT, 10)) == NULL)
		return -1;

#if 0
	/* As per tridge comment this doesn't seem to be needed. JRA */
	if ((err = ldap_simple_bind_s(ldp, NULL, NULL)) != 0)
		goto done;
#endif

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
#endif /* WITH_HORRIBLE_LDAP_NATIVE_MODE_HACK */

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
	int retry;

	*seq = DOM_SEQUENCE_NONE;

	if (!(mem_ctx = talloc_init_named("sequence_number[rpc]")))
		return NT_STATUS_NO_MEMORY;

	retry = 0;
	do {
		/* Get sam handle */
		if (!NT_STATUS_IS_OK(result = cm_get_sam_handle(domain->name, &hnd)))
			goto done;

#ifdef WITH_HORRIBLE_LDAP_NATIVE_MODE_HACK
		if (get_ldap_seq( inet_ntoa(hnd->cli->dest_ip), seq) == 0) {
			result = NT_STATUS_OK;
			seqnum = *seq;
			DEBUG(10,("domain_sequence_number: LDAP for domain %s is %u\n",
					domain->name, (unsigned)seqnum ));
			goto done;
		}

		DEBUG(10,("domain_sequence_number: failed to get LDAP sequence number (%u) for domain %s\n",
		(unsigned)seqnum, domain->name ));

#endif /* WITH_HORRIBLE_LDAP_NATIVE_MODE_HACK */

		/* Get domain handle */
		result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol, 
				      des_access, &domain->sid, &dom_pol);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	got_dom_pol = True;

	/* Query domain info */

	result = cli_samr_query_dom_info(hnd->cli, mem_ctx, &dom_pol,
					 switch_value, &ctr);

	if (NT_STATUS_IS_OK(result)) {
		seqnum = ctr.info.inf2.seq_num;
		seqnum += ctr.info.inf2.num_domain_usrs;
		seqnum += ctr.info.inf2.num_domain_grps;
		seqnum += ctr.info.inf2.num_local_grps;
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
	NTSTATUS result;
	uint32 enum_ctx = 0;
	int retry;

	*num_domains = 0;

	retry = 0;
	do {
		if (!NT_STATUS_IS_OK(result = cm_get_lsa_handle(lp_workgroup(), &hnd)))
			goto done;

		result = cli_lsa_enum_trust_dom(hnd->cli, mem_ctx,
					&hnd->pol, &enum_ctx, num_domains, 
					names, dom_sids);
	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);
done:
	return result;
}

/* find the domain sid for a domain */
static NTSTATUS domain_sid(struct winbindd_domain *domain, DOM_SID *sid)
{
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;
	CLI_POLICY_HND *hnd;
	fstring level5_dom;
	int retry;

	if (!(mem_ctx = talloc_init_named("domain_sid[rpc]")))
		return NT_STATUS_NO_MEMORY;

	retry = 0;
	do {
		/* Get lsa handle */
		if (!NT_STATUS_IS_OK(result = cm_get_lsa_handle(domain->name, &hnd)))
			goto done;

		result = cli_lsa_query_info_policy(hnd->cli, mem_ctx,
				&hnd->pol, 0x05, level5_dom, sid);

	} while (!NT_STATUS_IS_OK(result) && (retry++ < 1) &&
			hnd && hnd->cli && hnd->cli->fd == -1);
done:
	talloc_destroy(mem_ctx);
	return result;
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
