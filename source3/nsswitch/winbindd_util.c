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
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;
	extern struct winbindd_methods cache_methods;
	struct winbindd_domain *domain;
	DOM_SID *dom_sids;
	char **names;
	int num_domains = 0;

	if (!(mem_ctx = talloc_init()))
		return False;

	domain = add_trusted_domain(lp_workgroup(), &cache_methods);

	/* now we *must* get the domain sid for our primary domain. Go into a holding
	   pattern until that is available */
	result = cache_methods.domain_sid(domain, &domain->sid);
	while (!NT_STATUS_IS_OK(result)) {
		sleep(10);
		DEBUG(1,("Retrying startup domain sid fetch for %s\n",
			 domain->name));
		result = cache_methods.domain_sid(domain, &domain->sid);
	}

	DEBUG(1, ("getting trusted domain list\n"));

	result = cache_methods.trusted_domains(domain, mem_ctx, &num_domains,
					       &names, &dom_sids);

	/* Add each domain to the trusted domain list */
	if (NT_STATUS_IS_OK(result)) {
		int i;
		for(i = 0; i < num_domains; i++) {
			domain = add_trusted_domain(names[i], &cache_methods);
			if (domain) {
				sid_copy(&domain->sid, &dom_sids[i]);
			}
		}
	}

	talloc_destroy(mem_ctx);
	return True;
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
