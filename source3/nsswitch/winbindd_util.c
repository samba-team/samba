/* 
   Unix SMB/Netbios implementation.

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000-2001
   Copyright (C) 2001 by Martin Pool <mbp@samba.org>
   
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
#include "sids.h"

/**
 * @file winbindd_util.c
 *
 * Winbind daemon for NT domain authentication nss module.
 **/


/**
 * Used to clobber name fields that have an undefined value.
 *
 * Correct code should never look at a field that has this value.
 **/
static const fstring name_deadbeef = "<deadbeef>";


/* Globals for domain list stuff */
struct winbindd_domain *domain_list = NULL;

/* Given a domain name, return the struct winbindd domain info for it 
   if it is actually working. */

struct winbindd_domain *find_domain_from_name(char *domain_name)
{
	struct winbindd_domain *tmp;

	if (domain_list == NULL)
		get_domain_info();

	/* Search through list */

	for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
		if (strcasecmp(domain_name, tmp->name) == 0)
			return tmp;
	}

	/* Not found */

	return NULL;
}

/* Given a domain sid, return the struct winbindd domain info for it */

struct winbindd_domain *find_domain_from_sid(DOM_SID *sid)
{
	struct winbindd_domain *tmp;

	if (domain_list == NULL)
		get_domain_info();

	/* Search through list */
	for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
		if (sid_compare_domain(sid, &tmp->sid) == 0)
			return tmp;
	}

	/* Not found */

	return NULL;
}

/* Add a trusted domain to our list of domains */

static struct winbindd_domain *add_trusted_domain(char *domain_name,
                                                  DOM_SID *domain_sid,
						  struct winbindd_methods *methods)
{
	struct winbindd_domain *domain, *tmp;
        
	for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
		if (strcmp(domain_name, tmp->name) == 0) {
			DEBUG(3, ("domain %s already in domain list\n", domain_name));
			return tmp;
		}
	}
        
	DEBUG(1, ("adding domain %s\n", domain_name));
        
	/* Create new domain entry */
        
	if ((domain = (struct winbindd_domain *)malloc(sizeof(*domain))) == NULL)
		return NULL;

	/* Fill in fields */
        
	ZERO_STRUCTP(domain);
	fstrcpy(domain->name, domain_name);
	sid_copy(&domain->sid, domain_sid);
        domain->methods = methods;
	domain->sequence_number = DOM_SEQUENCE_NONE;
	domain->last_seq_check = 0;

	/* Link to domain list */
        
	DLIST_ADD(domain_list, domain);
        
	return domain;
}

/* Look up global info for the winbind daemon */

BOOL get_domain_info(void)
{
	uint32 enum_ctx = 0, num_doms = 0;
	char **domains = NULL;
	DOM_SID *sids = NULL, domain_sid;
	NTSTATUS result;
	CLI_POLICY_HND *hnd;
	int i;
	fstring level5_dom;
	BOOL rv = False;
	TALLOC_CTX *mem_ctx;
	extern struct winbindd_methods cache_methods;

	DEBUG(1, ("getting trusted domain list\n"));

	if (!(mem_ctx = talloc_init()))
		return False;

	/* Add our workgroup - keep handle to look up trusted domains */

	if (!(hnd = cm_get_lsa_handle(lp_workgroup())))
		goto done;

	result = cli_lsa_query_info_policy(hnd->cli, mem_ctx,
					&hnd->pol, 0x05, level5_dom, &domain_sid);

	if (!NT_STATUS_IS_OK(result))
		goto done;

	add_trusted_domain(lp_workgroup(), &domain_sid, &cache_methods);
	
	/* Enumerate list of trusted domains */	

	if (!(hnd = cm_get_lsa_handle(lp_workgroup())))
		goto done;

	result = cli_lsa_enum_trust_dom(hnd->cli, mem_ctx,
					&hnd->pol, &enum_ctx, &num_doms, &domains, &sids);
	
	if (!NT_STATUS_IS_OK(result))
		goto done;
	
	/* Add each domain to the trusted domain list */

	for(i = 0; i < num_doms; i++)
		add_trusted_domain(domains[i], &sids[i], &cache_methods);

	rv = True;	

 done:

	talloc_destroy(mem_ctx);

	return rv;
}


/* Connect to a domain controller using get_any_dc_name() to discover 
   the domain name and sid */

BOOL lookup_domain_sid(char *domain_name, struct winbindd_domain *domain)
{
	fstring level5_dom;
	uint32 enum_ctx = 0, num_doms = 0;
	char **domains = NULL;
	DOM_SID *sids = NULL;
	CLI_POLICY_HND *hnd;
	NTSTATUS result;
	BOOL rv = False;
	TALLOC_CTX *mem_ctx;
        
	DEBUG(1, ("looking up sid for domain %s\n", domain_name));
        
	if (!(mem_ctx = talloc_init()))
		return False;
        
	if (!(hnd = cm_get_lsa_handle(domain_name)))
		goto done;
        
	/* Do a level 5 query info policy if we are looking up the SID for
		our own domain. */
        
	if (strequal(domain_name, lp_workgroup())) {
                
		result = cli_lsa_query_info_policy(hnd->cli, mem_ctx,
						&hnd->pol, 0x05, level5_dom,
						&domain->sid);
                
			rv = NT_STATUS_IS_OK(result);
			goto done;
	} 
        
	/* Use lsaenumdomains to get sid for this domain */
        
	result = cli_lsa_enum_trust_dom(hnd->cli, mem_ctx, &hnd->pol,
						&enum_ctx, &num_doms, &domains, &sids);
        
	/* Look for domain name */
        
	if (NT_STATUS_IS_OK(result) && domains && sids) {
		BOOL found = False;
		int i;
                
		for(i = 0; i < num_doms; i++) {
			if (strequal(domain_name, domains[i])) {
				sid_copy(&domain->sid, &sids[i]);
				found = True;
				break;
			}
		}
                
		rv = found;
		goto done;
	}
      
	rv = False;             /* An error occured with a trusted domain */

 done:

	talloc_destroy(mem_ctx);

	return rv;
}

/* Lookup a sid in a domain from a name */

BOOL winbindd_lookup_sid_by_name(struct winbindd_domain *domain, 
				 const char *name, DOM_SID *sid, enum SID_NAME_USE *type)
{
	NTSTATUS result;
        
	/* Don't bother with machine accounts */
        
	if (name[strlen(name) - 1] == '$')
		return False;

	/* Lookup name */
	result = domain->methods->name_to_sid(domain, name, sid, type);
        
	/* Return rid and type if lookup successful */
	if (!NT_STATUS_IS_OK(result)) {
		*type = SID_NAME_UNKNOWN;
	}

	return NT_STATUS_IS_OK(result);
}

/**
 * @brief Lookup a name in a domain from a sid.
 *
 * @param sid Security ID you want to look up.
 *
 * @param name On success, set to the name corresponding to @p sid.
 * 
 * @param type On success, contains the type of name: alias, group or
 * user.
 *
 * @retval True if the name exists, in which case @p name and @p type
 * are set, otherwise False.
 **/
BOOL winbindd_lookup_name_by_sid(DOM_SID *sid,
				 fstring name,
				 enum SID_NAME_USE *type)
{
	char *names;
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;
	BOOL rv = False;
	struct winbindd_domain *domain;

	domain = find_domain_from_sid(sid);
	if (!domain) {
		DEBUG(1,("Can't find domain from sid\n"));
		return False;
	}

	/* Lookup name */

	if (!(mem_ctx = talloc_init()))
		return False;
        
	result = domain->methods->sid_to_name(domain, mem_ctx, sid, &names, type);

	/* Return name and type if successful */
        
	if ((rv = NT_STATUS_IS_OK(result))) {
		fstrcpy(name, names);
	} else {
		*type = SID_NAME_UNKNOWN;
		fstrcpy(name, name_deadbeef);
	}
        
	talloc_destroy(mem_ctx);

	return rv;
}


/* Free state information held for {set,get,end}{pw,gr}ent() functions */

void free_getent_state(struct getent_state *state)
{
	struct getent_state *temp;

	/* Iterate over state list */

	temp = state;

	while(temp != NULL) {
		struct getent_state *next;

		/* Free sam entries then list entry */

		SAFE_FREE(state->sam_entries);
		DLIST_REMOVE(state, state);
		next = temp->next;

		SAFE_FREE(temp);
		temp = next;
	}
}

/* Initialise trusted domain info */

BOOL winbindd_param_init(void)
{
    /* Parse winbind uid and winbind_gid parameters */

    if (!lp_winbind_uid(&server_state.uid_low, &server_state.uid_high)) {
            DEBUG(0, ("winbind uid range missing or invalid\n"));
            return False;
    }

    if (!lp_winbind_gid(&server_state.gid_low, &server_state.gid_high)) {
            DEBUG(0, ("winbind gid range missing or invalid\n"));
            return False;
    }
    
    return True;
}

/* Check if a domain is present in a comma-separated list of domains */

BOOL check_domain_env(char *domain_env, char *domain)
{
	fstring name;
	char *tmp = domain_env;

	while(next_token(&tmp, name, ",", sizeof(fstring))) {
		if (strequal(name, domain))
			return True;
	}

	return False;
}

/* Parse a string of the form DOMAIN/user into a domain and a user */

BOOL parse_domain_user(const char *domuser, fstring domain, fstring user)
{
	char *p = strchr(domuser,*lp_winbind_separator());

	if (!p)
		return False;
	
	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;
	strupper(domain);
	return True;
}
