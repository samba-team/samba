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

static const fstring name_deadbeef = "<deadbeef>";

/* Debug connection state */

void debug_conn_state(void)
{
	struct winbindd_domain *domain;

	DEBUG(3, ("server: dc=%s, pwdb_init=%d, lsa_hnd=%d\n", 
		  server_state.controller,
		  server_state.pwdb_initialised,
		  server_state.lsa_handle_open));

	for (domain = domain_list; domain; domain = domain->next) {
		DEBUG(3, ("%s: dc=%s, got_sid=%d, sam_hnd=%d sam_dom_hnd=%d\n",
			  domain->name, domain->controller,
			  domain->got_domain_info, domain->sam_handle_open,
			  domain->sam_dom_handle_open));
	}
}

/* Add a trusted domain to our list of domains */

static struct winbindd_domain *add_trusted_domain(char *domain_name)
{
    struct winbindd_domain *domain, *tmp;

    for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
	    if (strcmp(domain_name, tmp->name) == 0) {
		    DEBUG(3, ("domain %s already in trusted list\n",
			      domain_name));
		    return tmp;
	    }
    }

    DEBUG(1, ("adding trusted domain %s\n", domain_name));

    /* Create new domain entry */

    if ((domain = (struct winbindd_domain *)malloc(sizeof(*domain))) == NULL) {
        return NULL;
    }

    /* Fill in fields */

    ZERO_STRUCTP(domain);

    if (domain_name) {
        fstrcpy(domain->name, domain_name);
    }

    /* Link to domain list */

    DLIST_ADD(domain_list, domain);

    return domain;
}

/* Look up global info for the winbind daemon */

static BOOL get_trusted_domains(void)
{
	uint32 enum_ctx = 0;
	uint32 num_doms = 0;
	char **domains = NULL;
	DOM_SID **sids = NULL;
	BOOL result;
	int i;
	
	DEBUG(1, ("getting trusted domain list\n"));

	/* Add our workgroup - keep handle to look up trusted domains */
	if (!add_trusted_domain(lp_workgroup())) {
		DEBUG(0, ("could not add record for domain %s\n", 
			  lp_workgroup()));
		return False;
	}
	
	/* Enumerate list of trusted domains */	
	result = lsa_enum_trust_dom(&server_state.lsa_handle, &enum_ctx,
				    &num_doms, &domains, &sids);
	
	if (!result || !domains) return False;
	
        /* Add each domain to the trusted domain list */
	for(i = 0; i < num_doms; i++) {
		if (!add_trusted_domain(domains[i])) {
			DEBUG(0, ("could not add record for domain %s\n", 
				  domains[i]));
			result = False;
		}
	}
	
	/* Free memory */	
	free_char_array(num_doms, domains);
	free_sid_array(num_doms, sids);
	
	return True;
}

/* Open sam and sam domain handles */

static BOOL open_sam_handles(struct winbindd_domain *domain)
{
	/* Get domain info (sid and controller name) */

	if (!domain->got_domain_info) {
		domain->got_domain_info = get_domain_info(domain);
		if (!domain->got_domain_info) return False;
	}

	/* Shut down existing sam handles */

	if (domain->sam_dom_handle_open) {
		samr_close(&domain->sam_dom_handle);
		domain->sam_dom_handle_open = False;
	}

	if (domain->sam_handle_open) {
		samr_close(&domain->sam_handle);
		domain->sam_handle_open = False;
	}

	/* Open sam handle */

	domain->sam_handle_open = 
		samr_connect(domain->controller, 
			     SEC_RIGHTS_MAXIMUM_ALLOWED, 
			     &domain->sam_handle);

	if (!domain->sam_handle_open) return False;

	/* Open sam domain handle */

	domain->sam_dom_handle_open =
		samr_open_domain(&domain->sam_handle, 
				 SEC_RIGHTS_MAXIMUM_ALLOWED, 
				 &domain->sid, 
				 &domain->sam_dom_handle);

	if (!domain->sam_dom_handle_open) return False;
	
	return True;
}

/* Return true if the SAM domain handles are open and responding.  */

BOOL domain_handles_open(struct winbindd_domain *domain)
{
	time_t t;
	BOOL result;

	/* Check we haven't checked too recently */

	t = time(NULL);

	if ((t - domain->last_check) < WINBINDD_ESTABLISH_LOOP) {
		return domain->sam_handle_open &&
			domain->sam_dom_handle_open;
	}
	
	DEBUG(3, ("checking domain handles for domain %s\n", domain->name));
	debug_conn_state();

	domain->last_check = t;

	/* Open sam handles if they are marked as closed */

	if (!domain->sam_handle_open || !domain->sam_dom_handle_open) {
	reopen:
		DEBUG(3, ("opening sam handles\n"));
		return open_sam_handles(domain);
	}

	/* Check sam handles are ok - the domain controller may have failed
	   and we need to move to a BDC. */

	if (!rpc_hnd_ok(&domain->sam_handle) || 
	    !rpc_hnd_ok(&domain->sam_dom_handle)) {

		/* We want to close the current connection but attempt
		   to open a new set, possibly to a new dc.  If this
		   doesn't work then return False as we have no dc
		   to talk to. */

		DEBUG(3, ("sam handles not responding\n"));

		winbindd_kill_connections(domain);
		goto reopen;
	}

	result = domain->sam_handle_open && domain->sam_dom_handle_open;

	return result;
}

/* Shut down connections to a domain controller.  If domain is NULL then
   kill all connections. */

void winbindd_kill_connections(struct winbindd_domain *domain)
{
        /* Kill all connections */

        if (!domain) {
                struct winbindd_domain *tmp;

                for (tmp = domain_list; tmp; tmp = tmp->next) {
                        winbindd_kill_connections(tmp);
                }

                return;
        }

	/* Log a level 0 message - this is probably a domain controller
	   failure */

        if (!domain->controller[0])
                return;

	DEBUG(0, ("killing connections to domain %s with controller %s\n", 
		  domain->name, domain->controller));

	debug_conn_state();

        /* Close LSA connections if we are killing connections to the dc
           that has them open. */

	if (strequal(server_state.controller, domain->controller)) {
		server_state.pwdb_initialised = False;
		server_state.lsa_handle_open = False;
		lsa_close(&server_state.lsa_handle);
	}
	
	/* Close domain sam handles but don't free them as this
	   severely traumatises the getent state.  The connections
	   will be reopened later. */

	if (domain->sam_dom_handle_open) {
		samr_close(&domain->sam_dom_handle);
		domain->sam_dom_handle_open = False;
	}
	
	if (domain->sam_handle_open) {
		samr_close(&domain->sam_handle);
		domain->sam_handle_open = False;
	}

	/* Re-lookup domain info which includes domain controller name */
	
	domain->got_domain_info = False;
}

/* Kill connections to all servers */

void winbindd_kill_all_connections(void)
{
	struct winbindd_domain *domain;

	/* Iterate over domain list */

	domain = domain_list;

	while (domain) {
		struct winbindd_domain *next;

		/* Kill conections */

		winbindd_kill_connections(domain);

		/* Remove domain from list */

		next = domain->next;
		DLIST_REMOVE(domain_list, domain);
		free(domain);

		domain = next;
	}
}

/* Attempt to connect to all domain controllers we know about */

void establish_connections(BOOL force_reestablish) 
{
	static time_t lastt;
	time_t t;

	/* Check we haven't checked too recently */

	t = time(NULL);
	if ((t - lastt < WINBINDD_ESTABLISH_LOOP) && !force_reestablish) {
		return;
	}
	lastt = t;

	DEBUG(3, ("establishing connections\n"));
	debug_conn_state();

	/* Maybe the connection died - if so then close up and restart */

	if (server_state.pwdb_initialised &&
	    server_state.lsa_handle_open &&
	    !rpc_hnd_ok(&server_state.lsa_handle)) {
		winbindd_kill_connections(NULL);
	}

	if (!server_state.pwdb_initialised) {

		/* Lookup domain controller name */

		if (!get_any_dc_name(lp_workgroup(), 
				     server_state.controller)) {
			return;
		}

		/* Initialise password database and sids */

		server_state.pwdb_initialised = pwdb_initialise(False);
		if (!server_state.pwdb_initialised) return;
	}

	/* Open lsa handle if it isn't already open */

	if (!server_state.lsa_handle_open) {

		server_state.lsa_handle_open =
			lsa_open_policy(server_state.controller, 
					&server_state.lsa_handle, 
					False, SEC_RIGHTS_MAXIMUM_ALLOWED);

		if (!server_state.lsa_handle_open) return;

		/* Now we can talk to the server we can get some info */

		get_trusted_domains();
	}

	debug_conn_state();
}

/* Connect to a domain controller using get_any_dc_name() to discover 
   the domain name and sid */

BOOL lookup_domain_sid(char *domain_name, struct winbindd_domain *domain)
{
    fstring level5_dom;
    BOOL res;
    uint32 enum_ctx = 0;
    uint32 num_doms = 0;
    char **domains = NULL;
    DOM_SID **sids = NULL;

    if (domain == NULL) {
        return False;
    }

    DEBUG(1, ("looking up sid for domain %s\n", domain_name));

    /* Get controller name for domain */

    if (!get_any_dc_name(domain_name, domain->controller)) {
	    DEBUG(0, ("Could not resolve domain controller for domain %s\n",
		      domain_name));
	    return False;
    }

    if (strequal(domain_name, lp_workgroup())) {
	    /* Do a level 5 query info policy */
	    return lsa_query_info_pol(&server_state.lsa_handle, 0x05, 
				      level5_dom, &domain->sid);
    } 

    /* Use lsaenumdomains to get sid for this domain */
    
    res = lsa_enum_trust_dom(&server_state.lsa_handle, &enum_ctx,
			     &num_doms, &domains, &sids);
    
    /* Look for domain name */
    
    if (res && domains && sids) {
            int found = False;
            int i;
	    
            for(i = 0; i < num_doms; i++) {
		    if (strequal(domain_name, domains[i])) {
			    sid_copy(&domain->sid, sids[i]);
			    found = True;
			    break;
		    }
            }
	    
            res = found;
    }
    
    /* Free memory */
    
    free_char_array(num_doms, domains);
    free_sid_array(num_doms, sids);

    return res;
}

/* Lookup domain controller and sid for a domain */

BOOL get_domain_info(struct winbindd_domain *domain)
{
    fstring sid_str;

    DEBUG(1, ("Getting domain info for domain %s\n", domain->name));

    /* Lookup domain sid */        

    if (!lookup_domain_sid(domain->name, domain)) {
	    DEBUG(0, ("could not find sid for domain %s\n", domain->name));

	    /* Could be a DC failure - shut down connections to this domain */

	    winbindd_kill_connections(domain);

	    return False;
    }
    
    /* Lookup OK */

    domain->got_domain_info = 1;

    sid_to_string(sid_str, &domain->sid);
    DEBUG(1, ("found sid %s for domain %s\n", sid_str, domain->name));

    return True;
}        

/* Store a SID in a domain indexed by name in the cache. */
 
static void store_sid_by_name_in_cache(fstring name, DOM_SID *sid, enum SID_NAME_USE type)
{
    fstring domain_str;
    char *p;
    struct winbindd_sid sid_val;

    /* Get name from domain. */
    fstrcpy( domain_str, name);
    p = strchr(domain_str, '\\');
    if (p)
        *p = '\0';
 
    sid_to_string(sid_val.sid, sid);
    sid_val.type = (int)type;
 
    DEBUG(10,("store_sid_by_name_in_cache: storing cache entry %s -> SID %s\n",
        name, sid_val.sid ));
 
    winbindd_store_sid_cache_entry(domain_str, name, &sid_val);
}

/* Lookup a SID in a domain indexed by name in the cache. */
 
static BOOL winbindd_lookup_sid_by_name_in_cache(fstring name, DOM_SID *sid, enum SID_NAME_USE *type)
{
	fstring name_domain, name_user, key_name;
	struct winbindd_sid sid_ret;
	BOOL result = False;
 
	/* Get name from domain. */
	
	if (!parse_domain_user(name, name_domain, name_user))
		goto done;
	
	strlower(name_user);	/* Username in key is lowercased */

	fstrcpy(key_name, name_domain);
	fstrcat(key_name, "\\");
	fstrcat(key_name, name_user);
	
	if (!winbindd_fetch_sid_cache_entry(name_domain, key_name, &sid_ret))
		goto done;

	string_to_sid(sid, sid_ret.sid);
	*type = (enum SID_NAME_USE)sid_ret.type;

	DEBUG(10, ("winbindd_lookup_sid_by_name_in_cache: Cache hit for name %s. SID = %s\n", name, sid_ret.sid));

	result = True;

 done:
	return result;
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
 
    DEBUG(10,("store_name_by_sid_in_cache: storing cache entry SID %s -> %s\n",
        sid_str, name_val.name ));
 
    winbindd_store_name_cache_entry(domain->name, sid_str, &name_val);
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
 
    if (!winbindd_fetch_name_cache_entry(domain->name, sid_str, &name_ret))
        return False;
 
    fstrcpy( name, name_ret.name );
    *type = (enum SID_NAME_USE)name_ret.type;
 
    DEBUG(10,("winbindd_lookup_name_by_sid_in_cache: Cache hit for SID = %s, name %s\n",
        sid_str, name ));
 
    return True;
}

/* Lookup a sid in a domain from a name */

BOOL winbindd_lookup_sid_by_name(char *name, DOM_SID *sid,
                                 enum SID_NAME_USE *type)
{
    int num_sids = 0, num_names = 1;
    DOM_SID *sids = NULL;
    uint32 *types = NULL;
    BOOL res = False;
    char **names = NULL;

    /* Don't bother with machine accounts */

    if (name[strlen(name) - 1] == '$') {
        return False;
    }

    /* First check cache. */
    if (winbindd_lookup_sid_by_name_in_cache(name, sid, type)) {
        if (*type == SID_NAME_USE_NONE)
            return False; /* Negative cache hit. */
        return True;
    }

    /* Lookup name */

    res = lsa_lookup_names(&server_state.lsa_handle, num_names, (char **)&name,
			   &sids, &types, &num_sids);

    /* Return rid and type if lookup successful */

    if (!res) {
        /* JRA. Here's where we add the -ve cache store with a name type of SID_NAME_USE_NONE. */
        DOM_SID nullsid;

        ZERO_STRUCT(nullsid);
        store_sid_by_name_in_cache(name, &nullsid, SID_NAME_USE_NONE);
        *type = SID_NAME_UNKNOWN;
	goto done;
    }

    /* Return sid */

    if ((sid != NULL) && (sids != NULL)) {
            sid_copy(sid, &sids[0]);
    }
    
    /* Return name type */
    
    if ((type != NULL) && (types != NULL)) {
            *type = types[0];
    }

    res = lsa_lookup_sids(&server_state.lsa_handle, 1, &sids,
			  &names, &types, &num_names);

    if (!res)
	    goto done;

    /* Store the forward and reverse map of this lookup in the cache. */
    store_sid_by_name_in_cache(names[0], &sids[0], types[0]);
    store_name_by_sid_in_cache(&sids[0], names[0], types[0]);

    res = True;

done:

    /* Free memory */

    if (types != NULL) free(types);
    if (sids != NULL) free(sids);
    if (names && names[0]) {
	    free(names[0]);
	    free(names);
    }

    return res;
}

/* Lookup a name in a domain from a sid */

BOOL winbindd_lookup_name_by_sid(DOM_SID *sid, fstring name,
                                 enum SID_NAME_USE *type)
{
    int num_sids = 1, num_names = 0;
    uint32 *types = NULL;
    char **names;
    BOOL res;

    /* First check cache. */
    if (winbindd_lookup_name_by_sid_in_cache(sid, name, type)) {
        if (*type == SID_NAME_USE_NONE) {
            fstrcpy(name, name_deadbeef);
            *type = SID_NAME_UNKNOWN;
            return False; /* Negative cache hit. */
        } else
            return True;
    }

    /* Lookup name */

    res = lsa_lookup_sids(&server_state.lsa_handle, num_sids, &sid, &names, 
			  &types, &num_names);

    /* Return name and type if successful */

    if (res) {

        /* Return name */

        if ((names != NULL) && (name != NULL)) {
            fstrcpy(name, names[0]);
        }

        /* Return name type */

        if ((type != NULL) && (types != NULL)) {
            *type = types[0];
        }

        store_sid_by_name_in_cache(names[0], sid, types[0]);
        store_name_by_sid_in_cache(sid, names[0], types[0]);

    } else {

        /* OK, so we tried to look up a name in this sid, and
         * didn't find it.  Therefore add a negative cache
         * entry.  */
        store_name_by_sid_in_cache(sid, "", SID_NAME_USE_NONE);
        *type = SID_NAME_UNKNOWN;
        fstrcpy(name, name_deadbeef);
    }
    /* Free memory */

    safe_free(types);
    free_char_array(num_names, names);

    return res;
}

/* Lookup user information from a rid */

BOOL winbindd_lookup_userinfo(struct winbindd_domain *domain,
                              uint32 user_rid, SAM_USERINFO_CTR *user_info)
{
	return get_samr_query_userinfo(&domain->sam_dom_handle, 0x15, 
				       user_rid, user_info);
}                                   

/* Lookup groups a user is a member of.  I wish Unix had a call like this! */

BOOL winbindd_lookup_usergroups(struct winbindd_domain *domain,
				uint32 user_rid, uint32 *num_groups,
				DOM_GID **user_groups)
{
	POLICY_HND user_pol;
	BOOL result;

        if (!samr_open_user(&domain->sam_dom_handle, 
			    SEC_RIGHTS_MAXIMUM_ALLOWED,
			    user_rid, &user_pol)) {
		return False;
	}

	if (!samr_query_usergroups(&user_pol, num_groups, user_groups)) {
		result = False;
		goto done;
	}

	result = True;
done:
	samr_close(&user_pol);
	return True;
}

/* Lookup group information from a rid */

BOOL winbindd_lookup_groupinfo(struct winbindd_domain *domain,
                              uint32 group_rid, GROUP_INFO_CTR *info)
{
	return get_samr_query_groupinfo(&domain->sam_dom_handle, 1, 
					group_rid, info);
}

/* Lookup group membership given a rid */

BOOL winbindd_lookup_groupmem(struct winbindd_domain *domain,
                              uint32 group_rid, uint32 *num_names, 
                              uint32 **rid_mem, char ***names, 
                              enum SID_NAME_USE **name_types)
{
	return sam_query_groupmem(&domain->sam_dom_handle, group_rid, 
				  num_names, rid_mem, names, name_types);
}

/* Lookup alias membership given a rid */

int winbindd_lookup_aliasmem(struct winbindd_domain *domain,
                             uint32 alias_rid, uint32 *num_names, 
                             DOM_SID ***sids, char ***names, 
                             enum SID_NAME_USE **name_types)
{
    return sam_query_aliasmem(domain->controller, 
			      &domain->sam_dom_handle, alias_rid, num_names, 
			      sids, names, name_types);
}

/* Globals for domain list stuff */

struct winbindd_domain *domain_list = NULL;

/* Given a domain name, return the struct winbindd domain info for it 
   if it is actually working. */

struct winbindd_domain *find_domain_from_name(char *domain_name)
{
	struct winbindd_domain *tmp;

	/* Search through list */

	for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
		if (strcmp(domain_name, tmp->name) == 0) {

			if (!tmp->got_domain_info) {
				get_domain_info(tmp);
			}

                        return tmp->got_domain_info ? tmp : NULL;
                }
        }

	/* Not found */

	return NULL;
}

/* Given a domain name, return the struct winbindd domain info for it */

struct winbindd_domain *find_domain_from_sid(DOM_SID *sid)
{
	struct winbindd_domain *tmp;

	/* Search through list */
	for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
		if (sid_equal(sid, &tmp->sid)) {
			if (!tmp->got_domain_info) return NULL;
                        return tmp;
                }
        }

	/* Not found */
	return NULL;
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

        safe_free(state->sam_entries);
        DLIST_REMOVE(state, state);
        next = temp->next;

        free(temp);
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
          parse_id_list(lp_winbind_gid(), False))) {
        return False;
    }

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

/* Convert a enum winbindd_cmd to a string */

struct cmdstr_table {
	enum winbindd_cmd cmd;
	char *desc;
};

static struct cmdstr_table cmdstr_table[] = {
	
	/* User functions */

	{ WINBINDD_GETPWNAM_FROM_USER, "getpwnam from user" },
	{ WINBINDD_GETPWNAM_FROM_UID, "getpwnam from uid" },
	{ WINBINDD_SETPWENT, "setpwent" },
	{ WINBINDD_ENDPWENT, "endpwent" },
	{ WINBINDD_GETPWENT, "getpwent" },
	{ WINBINDD_GETGROUPS, "getgroups" },

	/* Group functions */

	{ WINBINDD_GETGRNAM_FROM_GROUP, "getgrnam from group" },
	{ WINBINDD_GETGRNAM_FROM_GID, "getgrnam from gid" },
	{ WINBINDD_SETGRENT, "setgrent" },
	{ WINBINDD_ENDGRENT, "endgrent" },
	{ WINBINDD_GETGRENT, "getgrent" },

	/* PAM auth functions */

	{ WINBINDD_PAM_AUTH, "pam auth" },
	{ WINBINDD_PAM_AUTH_CRAP, "pam auth crap" },
	{ WINBINDD_PAM_CHAUTHTOK, "pam chauthtok" },

	/* List things */

        { WINBINDD_LIST_USERS, "list users" },
        { WINBINDD_LIST_GROUPS, "list groups" },
	{ WINBINDD_LIST_TRUSTDOM, "list trusted domains" },

	/* SID related functions */

	{ WINBINDD_LOOKUPSID, "lookup sid" },
	{ WINBINDD_LOOKUPNAME, "lookup name" },

	/* S*RS related functions */

	{ WINBINDD_SID_TO_UID, "sid to uid" },
	{ WINBINDD_SID_TO_GID, "sid to gid " },
	{ WINBINDD_GID_TO_SID, "gid to sid" },
	{ WINBINDD_UID_TO_SID, "uid to sid" },

	/* Miscellaneous other stuff */

	{ WINBINDD_CHECK_MACHACC, "check machine acct pw" },

	/* End of list */

	{ WINBINDD_NUM_CMDS, NULL }
};

char *winbindd_cmd_to_string(enum winbindd_cmd cmd)
{
	struct cmdstr_table *table = cmdstr_table;
	char *result = NULL;

	for(table = cmdstr_table; table->desc; table++) {
		if (cmd == table->cmd) {
			result = table->desc;
			break;
		}
	}
	
	if (result == NULL) {
		result = "invalid command";
	}

	return result;
};

/* find the sequence number for a domain */

uint32 domain_sequence_number(char *domain_name)
{
	struct winbindd_domain *domain;
	SAM_UNK_CTR ctr;

	domain = find_domain_from_name(domain_name);
	if (!domain) return DOM_SEQUENCE_NONE;

	/* Ensure we have open sam handles */

	if (!domain_handles_open(domain))
		return DOM_SEQUENCE_NONE;

	if (!samr_query_dom_info(&domain->sam_dom_handle, 2, &ctr)) {

		/* If this fails, something bad has gone wrong */

		winbindd_kill_connections(domain);

		DEBUG(2,("domain sequence query failed\n"));
		return DOM_SEQUENCE_NONE;
	}

	DEBUG(4,("got domain sequence number for %s of %u\n", 
		 domain_name, (unsigned)ctr.info.inf2.seq_num));
	
	return ctr.info.inf2.seq_num;
}

/* Query display info for a domain.  This returns enough information plus a
   bit extra to give an overview of domain users for the User Manager
   application. */

uint32 winbindd_query_dispinfo(struct winbindd_domain *domain,
			     uint32 *start_ndx, uint16 info_level, 
			     uint32 *num_entries, SAM_DISPINFO_CTR *ctr)
{
	uint32 status;

	status = samr_query_dispinfo(&domain->sam_dom_handle, start_ndx,
				     info_level, num_entries, ctr);

	return status;
}

/* Check if a domain is present in a comma-separated list of domains */

BOOL check_domain_env(char *domain_env, char *domain)
{
	fstring name;
	char *tmp = domain_env;

	while(next_token(&tmp, name, ",", sizeof(fstring))) {
		if (strequal(name, domain)) {
			return True;
		}
	}

	return False;
}


/* Parse a string of the form DOMAIN/user into a domain and a user */

BOOL parse_domain_user(char *domuser, fstring domain, fstring user)
{
	char *p = strchr(domuser, *lp_winbind_separator());

	if (!p)
		return False;
	
	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;

	unix_to_dos(domain, True);
	strupper(domain);
	dos_to_unix(domain, True);
	return True;
}

/* Return the uppercased workgroup name */

char *lp_uworkgroup(void)
{
	char *workgroup = lp_workgroup();

	unix_to_dos(workgroup, True);
	strupper(workgroup);
	dos_to_unix(workgroup, True);

	return workgroup;
}
