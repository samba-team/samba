/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon for ntdom nss module

   Copyright (C) Tim Potter 2000
   
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
		if (strcmp(domain_name, tmp->name) == 0)
			return tmp;
	}

	/* Not found */

	return NULL;
}

/* Given a domain name, return the struct winbindd domain info for it */

struct winbindd_domain *find_domain_from_sid(DOM_SID *sid)
{
	struct winbindd_domain *tmp;

	if (domain_list == NULL)
		get_domain_info();

	/* Search through list */

	for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
		if (sid_equal(sid, &tmp->sid))
			return tmp;
	}

	/* Not found */

	return NULL;
}

/* Add a trusted domain to our list of domains */

static struct winbindd_domain *add_trusted_domain(char *domain_name,
                                                  DOM_SID *domain_sid)
{
        struct winbindd_domain *domain, *tmp;
        
        for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
                if (strcmp(domain_name, tmp->name) == 0) {
                        DEBUG(3, ("domain %s already in domain list\n",
                                  domain_name));
                        return tmp;
                }
        }
        
        DEBUG(1, ("adding domain %s\n", domain_name));
        
        /* Create new domain entry */
        
        if ((domain = (struct winbindd_domain *)
             malloc(sizeof(*domain))) == NULL)
                return NULL;

        /* Fill in fields */
        
        ZERO_STRUCTP(domain);
        fstrcpy(domain->name, domain_name);
        sid_copy(&domain->sid, domain_sid);
        
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

	add_trusted_domain(lp_workgroup(), &domain_sid);
	
	/* Enumerate list of trusted domains */	

	if (!(hnd = cm_get_lsa_handle(lp_workgroup())))
		goto done;

	result = cli_lsa_enum_trust_dom(hnd->cli, mem_ctx,
						&hnd->pol, &enum_ctx, &num_doms, &domains, &sids);
	
	if (!NT_STATUS_IS_OK(result))
		goto done;
	
	/* Add each domain to the trusted domain list */

	for(i = 0; i < num_doms; i++)
		add_trusted_domain(domains[i], &sids[i]);

	rv = True;	

 done:

	talloc_destroy(mem_ctx);

	return rv;
}

/* Free global domain info */

void free_domain_info(void)
{
        struct winbindd_domain *domain;

        /* Free list of domains */

        if (domain_list) {
                struct winbindd_domain *next_domain;

                domain = domain_list;

                while(domain) {
                        next_domain = domain->next;
                        free(domain);
                        domain = next_domain;
                }
        }
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

/* Store a SID in a domain indexed by name in the cache. */

static void store_sid_by_name_in_cache(fstring name, DOM_SID *sid, enum SID_NAME_USE type)
{
	fstring domain_str;
	char *p;
	struct winbindd_sid sid_val;
	struct winbindd_domain *domain;

	/* Get name from domain. */
	fstrcpy( domain_str, name);
	p = strchr(domain_str, '\\');
	if (p)
		*p = '\0';

	if ((domain = find_domain_from_name(domain_str)) == NULL)
        return;

	sid_to_string(sid_val.sid, sid);
	sid_val.type = (int)type;

	winbindd_store_sid_cache_entry(domain, name, &sid_val);
}

/* Lookup a SID in a domain indexed by name in the cache. */

static BOOL winbindd_lookup_sid_by_name_in_cache(fstring name, DOM_SID *sid, enum SID_NAME_USE *type)
{
	fstring domain_str;
	char *p;
	struct winbindd_sid sid_ret;
	struct winbindd_domain *domain;

	/* Get name from domain. */
	fstrcpy( domain_str, name);
	p = strchr(domain_str, '\\');
	if (p)
		*p = '\0';

	if ((domain = find_domain_from_name(domain_str)) == NULL)
        return False;

	if (!winbindd_fetch_sid_cache_entry(domain, name, &sid_ret))
		return False;

	string_to_sid( sid, sid_ret.sid);
	*type = (enum SID_NAME_USE)sid_ret.type;

	DEBUG(10,("winbindd_lookup_sid_by_name_in_cache: Cache hit for name %s. SID = %s\n",
		name, sid_ret.sid ));

	return True;
}

/* Store a name in a domain indexed by SID in the cache. */

static void store_name_by_sid_in_cache(DOM_SID *sid, fstring name, enum SID_NAME_USE type)
{
	fstring sid_str;
	uint32 rid;
	DOM_SID domain_sid;
	struct winbindd_name name_val;
	struct winbindd_domain *domain;

	/* Split sid into domain sid and user rid */
	sid_copy(&domain_sid, sid);
	sid_split_rid(&domain_sid, &rid);

	if ((domain = find_domain_from_sid(&domain_sid)) == NULL)
        return;

	sid_to_string(sid_str, sid);
	fstrcpy( name_val.name, name );
	name_val.type = (int)type;

	winbindd_store_name_cache_entry(domain, sid_str, &name_val);
}

/* Lookup a name in a domain indexed by SID in the cache. */

static BOOL winbindd_lookup_name_by_sid_in_cache(DOM_SID *sid, fstring name, enum SID_NAME_USE *type)
{
	fstring sid_str;
	uint32 rid;
	DOM_SID domain_sid;
	struct winbindd_name name_ret;
	struct winbindd_domain *domain;

	/* Split sid into domain sid and user rid */
	sid_copy(&domain_sid, sid);
	sid_split_rid(&domain_sid, &rid);

	if ((domain = find_domain_from_sid(&domain_sid)) == NULL)
        return False;

	sid_to_string(sid_str, sid);

	if (!winbindd_fetch_name_cache_entry(domain, sid_str, &name_ret))
		return False;

	fstrcpy( name, name_ret.name );
	*type = (enum SID_NAME_USE)name_ret.type;

	DEBUG(10,("winbindd_lookup_name_by_sid_in_cache: Cache hit for SID = %s, name %s\n",
		sid_str, name ));

	return True;
}

/* Lookup a sid in a domain from a name */

BOOL winbindd_lookup_sid_by_name(char *name, DOM_SID *sid, enum SID_NAME_USE *type)
{
	int num_sids = 0, num_names = 1;
	DOM_SID *sids = NULL;
	uint32 *types = NULL;
	CLI_POLICY_HND *hnd;
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;
	BOOL rv = False;
        
	/* Don't bother with machine accounts */
        
	if (name[strlen(name) - 1] == '$')
		return False;

	/* First check cache. */
	if (winbindd_lookup_sid_by_name_in_cache(name, sid, type)) {
		if (*type == SID_NAME_USE_NONE)
			return False; /* Negative cache hit. */
		return True;
	}

	/* Lookup name */
        
	if (!(mem_ctx = talloc_init()))
		return False;
        
	if (!(hnd = cm_get_lsa_handle(lp_workgroup())))
		goto done;
        
	result = cli_lsa_lookup_names(hnd->cli, mem_ctx, &hnd->pol, 
				num_names, (char **)&name, &sids, 
				&types, &num_sids);
        
	/* Return rid and type if lookup successful */
        
	if (NT_STATUS_IS_OK(result)) {
                
		/* Return sid */
                
		if ((sid != NULL) && (sids != NULL))
			sid_copy(sid, &sids[0]);
                
		/* Return name type */
                
		if ((type != NULL) && (types != NULL))
			*type = types[0];

		/* Store the forward and reverse map of this lookup in the cache. */
		store_sid_by_name_in_cache(name, &sids[0], types[0]);
		store_name_by_sid_in_cache(&sids[0], name, types[0]);
	} else {
		/* JRA. Here's where we add the -ve cache store with a name type of SID_NAME_USE_NONE. */
		DOM_SID nullsid;

		ZERO_STRUCT(nullsid);
		store_sid_by_name_in_cache(name, &nullsid, SID_NAME_USE_NONE);
	}

	rv = NT_STATUS_IS_OK(result);

 done:
	talloc_destroy(mem_ctx);
        
	return rv;
}

/* Lookup a name in a domain from a sid */

BOOL winbindd_lookup_name_by_sid(DOM_SID *sid, fstring name, enum SID_NAME_USE *type)
{
	int num_sids = 1, num_names = 0;
	uint32 *types = NULL;
	char **names;
	CLI_POLICY_HND *hnd;
	NTSTATUS result;
	TALLOC_CTX *mem_ctx;
	BOOL rv = False;

	/* First check cache. */
	if (winbindd_lookup_name_by_sid_in_cache(sid, name, type)) {
		if (*type == SID_NAME_USE_NONE)
			return False; /* Negative cache hit. */
		return True;
	}

	/* Lookup name */

	if (!(mem_ctx = talloc_init()))
		return False;
        
	if (!(hnd = cm_get_lsa_handle(lp_workgroup())))
		goto done;
        
	result = cli_lsa_lookup_sids(hnd->cli, mem_ctx, &hnd->pol,
							num_sids, sid, &names, &types, 
							&num_names);

	/* Return name and type if successful */
        
	if (NT_STATUS_IS_OK(result)) {
                
		/* Return name */
                
		if ((names != NULL) && (name != NULL))
			fstrcpy(name, names[0]);
                
		/* Return name type */

		if ((type != NULL) && (types != NULL))
			*type = types[0];

		store_sid_by_name_in_cache(names[0], sid, types[0]);
		store_name_by_sid_in_cache(sid, names[0], types[0]);
	} else {
		/* JRA. Here's where we add the -ve cache store with a name type of SID_NAME_USE_NONE. */
		fstring sidstr;

		sid_to_string(sidstr, sid);
		store_name_by_sid_in_cache(sidstr, "", SID_NAME_USE_NONE);
	}

	rv = NT_STATUS_IS_OK(result);
        
 done:

	talloc_destroy(mem_ctx);

	return rv;
}

/* Lookup user information from a rid */

BOOL winbindd_lookup_userinfo(struct winbindd_domain *domain, 
                              TALLOC_CTX *mem_ctx, uint32 user_rid, 
                              SAM_USERINFO_CTR **user_info)
{
        CLI_POLICY_HND *hnd;
        uint16 info_level = 0x15;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
        POLICY_HND dom_pol, user_pol;
        BOOL got_dom_pol = False, got_user_pol = False;

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

        /* Get user info */

        result = cli_samr_query_userinfo(hnd->cli, mem_ctx, &user_pol, 
                                         info_level, user_info);

        cli_samr_close(hnd->cli, mem_ctx, &user_pol);

 done:
        /* Clean up policy handles */

        if (got_user_pol)
                cli_samr_close(hnd->cli, mem_ctx, &user_pol);

        if (got_dom_pol)
                cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

        return NT_STATUS_IS_OK(result);
}                                   

/* Lookup groups a user is a member of.  I wish Unix had a call like this! */

BOOL winbindd_lookup_usergroups(struct winbindd_domain *domain,
				uint32 user_rid, uint32 *num_groups,
				DOM_GID **user_groups)
{
        TALLOC_CTX *mem_ctx;
	CLI_POLICY_HND *hnd;
	NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        POLICY_HND dom_pol, user_pol;
        uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;
        BOOL got_dom_pol = False, got_user_pol = False;

        if (!(mem_ctx = talloc_init()))
                return False;

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
                                           num_groups, user_groups);

 done:
        /* Clean up policy handles */

        if (got_user_pol)
                cli_samr_close(hnd->cli, mem_ctx, &user_pol);

        if (got_dom_pol)
                cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

        talloc_destroy(mem_ctx);

        return NT_STATUS_IS_OK(result);
}

/* Lookup group membership given a rid.   */

BOOL winbindd_lookup_groupmem(struct winbindd_domain *domain,
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

        *names = talloc(mem_ctx, *num_names * sizeof(char *));
        *name_types = talloc(mem_ctx, *num_names * sizeof(uint32));

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

        return NT_STATUS_IS_OK(result);
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

/* Parse list of arguments to winbind uid or winbind gid parameters */

static BOOL parse_id_list(char *paramstr, BOOL is_user)
{
    uid_t id_low, id_high = 0;

    /* Give a nicer error message if no parameters specified */

    if (strequal(paramstr, "")) {
        DEBUG(0, ("winbind %s parameter missing\n", is_user ? "uid" : "gid"));
        return False;
    }
    
    /* Parse entry */

    if (sscanf(paramstr, "%u-%u", &id_low, &id_high) != 2) {
        DEBUG(0, ("winbind %s parameter invalid\n", 
                  is_user ? "uid" : "gid"));
        return False;
    }
    
    /* Store id info */
    
    if (is_user) {
        server_state.uid_low = id_low;
        server_state.uid_high = id_high;
    } else {
        server_state.gid_low = id_low;
        server_state.gid_high = id_high;
    }

    return True;
}

/* Initialise trusted domain info */

BOOL winbindd_param_init(void)
{
    /* Parse winbind uid and winbind_gid parameters */

    if (!(parse_id_list(lp_winbind_uid(), True) &&
          parse_id_list(lp_winbind_gid(), False)))
        return False;

    /* Check for reversed uid and gid ranges */
        
    if (server_state.uid_low > server_state.uid_high) {
        DEBUG(0, ("uid range invalid\n"));
        return False;
    }
    
    if (server_state.gid_low > server_state.gid_high) {
        DEBUG(0, ("gid range invalid\n"));
        return False;
    }
    
    return True;
}

/* Query display info for a domain.  This returns enough information plus a
   bit extra to give an overview of domain users for the User Manager
   application. */

NTSTATUS winbindd_query_dispinfo(struct winbindd_domain *domain,
                                 TALLOC_CTX *mem_ctx,
				 uint32 *start_ndx, uint16 info_level, 
				 uint32 *num_entries, SAM_DISPINFO_CTR *ctr)
{
        CLI_POLICY_HND *hnd;
        NTSTATUS result = NT_STATUS_UNSUCCESSFUL;
        POLICY_HND dom_pol;
        BOOL got_dom_pol = False;
        uint32 des_access = SEC_RIGHTS_MAXIMUM_ALLOWED;

        /* Get sam handle */

        if (!(hnd = cm_get_sam_handle(domain->name)))
                goto done;

        /* Get domain handle */

        result = cli_samr_open_domain(hnd->cli, mem_ctx, &hnd->pol,
                                      des_access, &domain->sid, &dom_pol);

        if (!NT_STATUS_IS_OK(result))
                goto done;

        got_dom_pol = True;

        /* Query display info */

        result = cli_samr_query_dispinfo(hnd->cli, mem_ctx,
                                         &dom_pol, start_ndx, info_level,
                                         num_entries, 0xffff, ctr);

 done:
        if (got_dom_pol)
                cli_samr_close(hnd->cli, mem_ctx, &dom_pol);

        return result;
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

void parse_domain_user(char *domuser, fstring domain, fstring user)
{
	char *p;
	char *sep = lp_winbind_separator();

	if (!sep) 
                sep = "\\";

	p = strchr(domuser,*sep);

	if (!p) 
                p = strchr(domuser,'\\');

	if (!p) {
		fstrcpy(domain,"");
		fstrcpy(user, domuser);
		return;
	}
	
	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;
	strupper(domain);
}
