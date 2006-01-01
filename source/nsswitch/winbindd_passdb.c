/* 
   Unix SMB/CIFS implementation.

   Winbind rpc backend functions

   Copyright (C) Tim Potter 2000-2001,2003
   Copyright (C) Simo Sorce 2003
   Copyright (C) Volker Lendecke 2004
   
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

static void add_member(const char *domain, const char *user,
	   char **pp_members, size_t *p_num_members)
{
	fstring name;

	fill_domain_username(name, domain, user);
	safe_strcat(name, ",", sizeof(name)-1);
	string_append(pp_members, name);
	*p_num_members += 1;
}

/**********************************************************************
 Add member users resulting from sid. Expand if it is a domain group.
**********************************************************************/

static void add_expanded_sid(const DOM_SID *sid, char **pp_members, size_t *p_num_members)
{
	DOM_SID dom_sid;
	uint32 rid;
	struct winbindd_domain *domain;
	size_t i;

	char *domain_name = NULL;
	char *name = NULL;
	enum SID_NAME_USE type;

	uint32 num_names;
	DOM_SID *sid_mem;
	char **names;
	uint32 *types;

	NTSTATUS result;

	TALLOC_CTX *mem_ctx = talloc_init("add_expanded_sid");

	if (mem_ctx == NULL) {
		DEBUG(1, ("talloc_init failed\n"));
		return;
	}

	sid_copy(&dom_sid, sid);
	sid_split_rid(&dom_sid, &rid);

	domain = find_lookup_domain_from_sid(sid);

	if (domain == NULL) {
		DEBUG(3, ("Could not find domain for sid %s\n",
			  sid_string_static(sid)));
		goto done;
	}

	result = domain->methods->sid_to_name(domain, mem_ctx, sid,
					      &domain_name, &name, &type);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(3, ("sid_to_name failed for sid %s\n",
			  sid_string_static(sid)));
		goto done;
	}

	DEBUG(10, ("Found name %s, type %d\n", name, type));

	if (type == SID_NAME_USER) {
		add_member(domain_name, name, pp_members, p_num_members);
		goto done;
	}

	if (type != SID_NAME_DOM_GRP) {
		DEBUG(10, ("Alias member %s neither user nor group, ignore\n",
			   name));
		goto done;
	}

	/* Expand the domain group, this must be done via the target domain */

	domain = find_domain_from_sid(sid);

	if (domain == NULL) {
		DEBUG(3, ("Could not find domain from SID %s\n",
			  sid_string_static(sid)));
		goto done;
	}

	result = domain->methods->lookup_groupmem(domain, mem_ctx,
						  sid, &num_names,
						  &sid_mem, &names,
						  &types);

	if (!NT_STATUS_IS_OK(result)) {
		DEBUG(10, ("Could not lookup group members for %s: %s\n",
			   name, nt_errstr(result)));
		goto done;
	}

	for (i=0; i<num_names; i++) {
		DEBUG(10, ("Adding group member SID %s\n",
			   sid_string_static(&sid_mem[i])));

		if (types[i] != SID_NAME_USER) {
			DEBUG(1, ("Hmmm. Member %s of group %s is no user. "
				  "Ignoring.\n", names[i], name));
			continue;
		}

		add_member(domain->name, names[i], pp_members, p_num_members);
	}

 done:
	talloc_destroy(mem_ctx);
	return;
}

BOOL fill_passdb_alias_grmem(struct winbindd_domain *domain,
			     DOM_SID *group_sid, 
			     size_t *num_gr_mem, char **gr_mem, size_t *gr_mem_len)
{
	DOM_SID *members;
	size_t i, num_members;

	*num_gr_mem = 0;
	*gr_mem = NULL;
	*gr_mem_len = 0;

	if (!pdb_enum_aliasmem(group_sid, &members, &num_members))
		return True;

	for (i=0; i<num_members; i++) {
		add_expanded_sid(&members[i], gr_mem, num_gr_mem);
	}

	SAFE_FREE(members);

	if (*gr_mem != NULL) {
		size_t len;

		/* We have at least one member, strip off the last "," */
		len = strlen(*gr_mem);
		(*gr_mem)[len-1] = '\0';
		*gr_mem_len = len;
	}

	return True;
}

/* Query display info for a domain.  This returns enough information plus a
   bit extra to give an overview of domain users for the User Manager
   application. */
static NTSTATUS query_user_list(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32 *num_entries, 
			       WINBIND_USERINFO **info)
{
	/* We don't have users */
	*num_entries = 0;
	*info = NULL;
	return NT_STATUS_OK;
}

/* list all domain groups */
static NTSTATUS enum_dom_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	/* We don't have domain groups */
	*num_entries = 0;
	*info = NULL;
	return NT_STATUS_OK;
}

/* List all domain groups */

static NTSTATUS enum_local_groups(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_entries, 
				struct acct_info **info)
{
	struct pdb_search *search;
	struct samr_displayentry *aliases;
	int i;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;

	search = pdb_search_aliases(&domain->sid);
	if (search == NULL) goto done;

	*num_entries = pdb_search_entries(search, 0, 0xffffffff, &aliases);
	if (*num_entries == 0) goto done;

	*info = TALLOC_ARRAY(mem_ctx, struct acct_info, *num_entries);
	if (*info == NULL) {
		result = NT_STATUS_NO_MEMORY;
		goto done;
	}

	for (i=0; i<*num_entries; i++) {
		fstrcpy((*info)[i].acct_name, aliases[i].account_name);
		fstrcpy((*info)[i].acct_desc, aliases[i].description);
		(*info)[i].rid = aliases[i].rid;
	}

	result = NT_STATUS_OK;
 done:
	pdb_search_destroy(search);
	return result;
}

/* convert a single name to a sid in a domain */
static NTSTATUS name_to_sid(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const char *domain_name,
			    const char *name,
			    DOM_SID *sid,
			    enum SID_NAME_USE *type)
{
	DEBUG(10, ("Finding name %s\n", name));

	if (!pdb_find_alias(name, sid))
		return NT_STATUS_NONE_MAPPED;

	if (sid_check_is_in_builtin(sid))
		*type = SID_NAME_WKN_GRP;
	else
		*type = SID_NAME_ALIAS;

	return NT_STATUS_OK;
}

/*
  convert a domain SID to a user or group name
*/
static NTSTATUS sid_to_name(struct winbindd_domain *domain,
			    TALLOC_CTX *mem_ctx,
			    const DOM_SID *sid,
			    char **domain_name,
			    char **name,
			    enum SID_NAME_USE *type)
{
	const char *dom, *nam;

	DEBUG(10, ("Converting SID %s\n", sid_string_static(sid)));

	/* Paranoia check */
	if (!sid_check_is_in_builtin(sid) &&
	    !sid_check_is_in_our_domain(sid)) {
		DEBUG(0, ("Possible deadlock: Trying to lookup SID %s with "
			  "passdb backend\n", sid_string_static(sid)));
		return NT_STATUS_NONE_MAPPED;
	}

	if (!lookup_sid(mem_ctx, sid, &dom, &nam, type)) {
		return NT_STATUS_NONE_MAPPED;
	}

	*domain_name = talloc_strdup(mem_ctx, dom);
	*name = talloc_strdup(mem_ctx, nam);

	return NT_STATUS_OK;
}

static NTSTATUS lookupsids(struct winbindd_domain *domain,
			   TALLOC_CTX *mem_ctx,
			   uint32 num_sids, const DOM_SID *sids,
			   char ***domain_names, char ***names,
			   enum SID_NAME_USE **types)
{
	return NT_STATUS_UNSUCCESSFUL;
}


/* Lookup user information from a rid or username. */
static NTSTATUS query_user(struct winbindd_domain *domain, 
			   TALLOC_CTX *mem_ctx, 
			   const DOM_SID *user_sid,
			   WINBIND_USERINFO *user_info)
{
	return NT_STATUS_NO_SUCH_USER;
}

/* Lookup groups a user is a member of.  I wish Unix had a call like this! */
static NTSTATUS lookup_usergroups(struct winbindd_domain *domain,
				  TALLOC_CTX *mem_ctx,
				  const DOM_SID *user_sid,
				  uint32 *num_groups, DOM_SID **user_gids)
{
	return NT_STATUS_NO_SUCH_USER;
}

static NTSTATUS lookup_useraliases(struct winbindd_domain *domain,
				   TALLOC_CTX *mem_ctx,
				   uint32 num_sids, const DOM_SID *sids,
				   uint32 *p_num_aliases, uint32 **rids)
{
	BOOL result;
	size_t num_aliases = 0;

	result = pdb_enum_alias_memberships(mem_ctx, &domain->sid,
					    sids, num_sids, rids, &num_aliases);

	*p_num_aliases = num_aliases;
	return result ? NT_STATUS_OK : NT_STATUS_UNSUCCESSFUL;
}

/* Lookup group membership given a rid.   */
static NTSTATUS lookup_groupmem(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				const DOM_SID *group_sid, uint32 *num_names, 
				DOM_SID **sid_mem, char ***names, 
				uint32 **name_types)
{
	return NT_STATUS_OK;
}

static NTSTATUS query_aliasmem(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32 alias_rid,
			       uint32 *num_members,
			       DOM_SID **members)
{
	/* This needs fixing! */
	return NT_STATUS_NO_SUCH_ALIAS;
}

static NTSTATUS query_groupmem(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       uint32 group_rid,
			       uint32 *num_members,
			       uint32 **members)
{
	return NT_STATUS_NO_SUCH_GROUP;
}

/* find the sequence number for a domain */
static NTSTATUS sequence_number(struct winbindd_domain *domain, uint32 *seq)
{
	BOOL result;
	time_t seq_num;

	result = pdb_get_seq_num(&seq_num);
	if (!result) {
		*seq = 1;
	}

	*seq = (int) seq_num;
	/* *seq = 1; */
	return NT_STATUS_OK;
}

static NTSTATUS lockout_policy(struct winbindd_domain *domain,
			       TALLOC_CTX *mem_ctx,
			       SAM_UNK_INFO_12 *lockout_policy)
{
	/* actually we have that */
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS password_policy(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				SAM_UNK_INFO_1 *password_policy)
{
	/* actually we have that */
	return NT_STATUS_NOT_IMPLEMENTED;
}

/* get a list of trusted domains */
static NTSTATUS trusted_domains(struct winbindd_domain *domain,
				TALLOC_CTX *mem_ctx,
				uint32 *num_domains,
				char ***names,
				char ***alt_names,
				DOM_SID **dom_sids)
{
	NTSTATUS nt_status;
	int enum_ctx = 0;
	int num_sec_domains;
	TRUSTDOM **domains;
	*num_domains = 0;
	*names = NULL;
	*alt_names = NULL;
	*dom_sids = NULL;
	do {
		int i;
		nt_status = secrets_get_trusted_domains(mem_ctx, &enum_ctx, 1,
							&num_sec_domains,
							&domains);
		*names = TALLOC_REALLOC_ARRAY(mem_ctx, *names, char *,
					num_sec_domains + *num_domains);
		*alt_names = TALLOC_REALLOC_ARRAY(mem_ctx, *alt_names, char *,
					    num_sec_domains + *num_domains);
		*dom_sids = TALLOC_REALLOC_ARRAY(mem_ctx, *dom_sids, DOM_SID,
					   num_sec_domains + *num_domains);

		for (i=0; i< num_sec_domains; i++) {
			if (pull_ucs2_talloc(mem_ctx, &(*names)[*num_domains],
					     domains[i]->name) == -1) {
				return NT_STATUS_NO_MEMORY;
			}
			(*alt_names)[*num_domains] = NULL;
			(*dom_sids)[*num_domains] = domains[i]->sid;
			(*num_domains)++;
		}

	} while (NT_STATUS_EQUAL(nt_status, STATUS_MORE_ENTRIES));

	if (NT_STATUS_EQUAL(nt_status, NT_STATUS_NO_MORE_ENTRIES)) {
		return NT_STATUS_OK;
	}
	return nt_status;
}

/* the rpc backend methods are exposed via this structure */
struct winbindd_methods passdb_methods = {
	False,
	query_user_list,
	enum_dom_groups,
	enum_local_groups,
	name_to_sid,
	sid_to_name,
	lookupsids,
	query_user,
	lookup_usergroups,
	lookup_useraliases,
	lookup_groupmem,
	query_aliasmem,
	query_groupmem,
	sequence_number,
	lockout_policy,
	password_policy,
	trusted_domains,
};
