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

BOOL domain_handles_open(struct winbindd_domain *domain)
{
	return domain->sam_handle_open &&
		domain->sam_dom_handle_open;
}

static BOOL resolve_dc_name(char *domain_name, fstring domain_controller)
{
	struct in_addr ip;
	extern pstring global_myname;
	
	/* if its our primary domain and password server is not '*' then use the
	   password server parameter */
	if (strcmp(domain_name,lp_workgroup()) == 0 && 
	    strcmp(lp_passwordserver(),"*") != 0) {
		fstrcpy(domain_controller, lp_passwordserver());
		return True;
	}

	if (!resolve_name(domain_name, &ip, 0x1B)) return False;

	return lookup_pdc_name(global_myname, domain_name, &ip, domain_controller);
}


static struct winbindd_domain *add_trusted_domain(char *domain_name)
{
    struct winbindd_domain *domain;

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
		DEBUG(0, ("could not add record for domain %s\n", lp_workgroup()));
		return False;
	}
	
	/* Enumerate list of trusted domains */	
	result = lsa_enum_trust_dom(&server_state.lsa_handle, &enum_ctx,
				    &num_doms, &domains, &sids);
	
	if (!result || !domains) return False;
	
        /* Add each domain to the trusted domain list */
	for(i = 0; i < num_doms; i++) {
		if (!add_trusted_domain(domains[i])) {
			DEBUG(0, ("could not add record for domain %s\n", domains[i]));
			result = False;
		}
	}
	
	/* Free memory */	
	free_char_array(num_doms, domains);
	free_sid_array(num_doms, sids);
	
	return True;
}


/* Open sam and sam domain handles to a domain and cache the results */
static BOOL open_sam_handles(struct winbindd_domain *domain)
{
	/* Get domain info */
	if (!domain->got_domain_info) {
		domain->got_domain_info = get_domain_info(domain);
		if (!domain->got_domain_info) return False;
	}

	/* Open sam handle if it isn't already open */
	if (!domain->sam_handle_open) {
		domain->sam_handle_open = 
			samr_connect(domain->controller, SEC_RIGHTS_MAXIMUM_ALLOWED, 
				     &domain->sam_handle);
		if (!domain->sam_handle_open) return False;
	}

	/* Open sam domain handle if it isn't already open */
	if (!domain->sam_dom_handle_open) {
		domain->sam_dom_handle_open =
			samr_open_domain(&domain->sam_handle, 
					 SEC_RIGHTS_MAXIMUM_ALLOWED, &domain->sid, 
					 &domain->sam_dom_handle);
		if (!domain->sam_dom_handle_open) return False;
	}
	
	return True;
}

static void winbindd_kill_connections(void)
{
	struct winbindd_domain *domain;

	DEBUG(1,("killing winbindd connections\n"));

	server_state.pwdb_initialised = False;
	server_state.lsa_handle_open = False;
	lsa_close(&server_state.lsa_handle);
	
	for (domain=domain_list; domain; domain=domain->next) {
		if (domain->sam_dom_handle_open) {
			samr_close(&domain->sam_dom_handle);
			domain->sam_dom_handle_open = False;
		}
		if (domain->sam_handle_open) {
			samr_close(&domain->sam_handle);
			domain->sam_handle_open = False;
		}
		DLIST_REMOVE(domain_list, domain);
		free(domain);
	}
}

void establish_connections(void) 
{
	struct winbindd_domain *domain;
	static time_t lastt;
	time_t t;

	t = time(NULL);
	if (t - lastt < WINBINDD_ESTABLISH_LOOP) return;
	lastt = t;

	/* maybe the connection died - if so then close up and restart */
	if (server_state.pwdb_initialised &&
	    server_state.lsa_handle_open &&
	    !rpc_hnd_ok(&server_state.lsa_handle)) {
		winbindd_kill_connections();
	}

	if (!server_state.pwdb_initialised) {
		fstrcpy(server_state.controller, lp_passwordserver());
		if (strcmp(server_state.controller,"*") == 0) {
			if (!resolve_dc_name(lp_workgroup(), server_state.controller)) {
				return;
			}
		}

		server_state.pwdb_initialised = pwdb_initialise(False);
		if (!server_state.pwdb_initialised) return;
	}

	/* Open lsa handle if it isn't already open */
	if (!server_state.lsa_handle_open) {
		server_state.lsa_handle_open =
			lsa_open_policy(server_state.controller, &server_state.lsa_handle, 
					False, SEC_RIGHTS_MAXIMUM_ALLOWED);
		if (!server_state.lsa_handle_open) return;

		/* now we can talk to the server we can get some info */
		get_trusted_domains();
	}

	for (domain=domain_list; domain; domain=domain->next) {
		if (!domain_handles_open(domain)) {
			open_sam_handles(domain);
		}
	}
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
    if (!resolve_dc_name(domain_name, domain->controller)) {
	    return False;
    }

    if (strequal(domain->controller, server_state.controller)) {
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
	    return False;
    }
    
    /* Lookup OK */

    domain->got_domain_info = 1;

    sid_to_string(sid_str, &domain->sid);
    DEBUG(1, ("found sid %s for domain %s\n", sid_str, domain->name));

    return True;
}        

/* Lookup a sid in a domain from a name */

BOOL winbindd_lookup_sid_by_name(struct winbindd_domain *domain,
                                 char *name, DOM_SID *sid,
                                 enum SID_NAME_USE *type)
{
    int num_sids = 0, num_names = 1;
    DOM_SID *sids = NULL;
    uint32 *types = NULL;
    BOOL res;

    /* Don't bother with machine accounts */

    if (name[strlen(name) - 1] == '$') {
        return False;
    }

    /* Lookup name */

    res = lsa_lookup_names(&server_state.lsa_handle, num_names, (char **)&name,
			   &sids, &types, &num_sids);

    /* Return rid and type if lookup successful */

    if (res) {

        /* Return sid */

        if ((sid != NULL) && (sids != NULL)) {
            sid_copy(sid, &sids[0]);
        }

        /* Return name type */

        if ((type != NULL) && (types != NULL)) {
            *type = types[0];
        }
    }
    
    /* Free memory */

    if (types != NULL) free(types);
    if (sids != NULL) free(sids);

    return res;
}

/* Lookup a name in a domain from a sid */

BOOL winbindd_lookup_name_by_sid(struct winbindd_domain *domain,
                                 DOM_SID *sid, char *name,
                                 enum SID_NAME_USE *type)
{
    int num_sids = 1, num_names = 0;
    uint32 *types = NULL;
    char **names;
    BOOL res;

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
	if (!domain_handles_open(domain)) return False;

	return get_samr_query_userinfo(&domain->sam_dom_handle, 0x15, user_rid, user_info);
}                                   

/* Lookup group information from a rid */

BOOL winbindd_lookup_groupinfo(struct winbindd_domain *domain,
                              uint32 group_rid, GROUP_INFO_CTR *info)
{
	if (!domain_handles_open(domain)) return False;

	return get_samr_query_groupinfo(&domain->sam_dom_handle, 1, group_rid, info);
}

/* Lookup group membership given a rid */

BOOL winbindd_lookup_groupmem(struct winbindd_domain *domain,
                              uint32 group_rid, uint32 *num_names, 
                              uint32 **rid_mem, char ***names, 
                              enum SID_NAME_USE **name_types)
{
	if (!domain_handles_open(domain)) return False;
    
	return sam_query_groupmem(&domain->sam_dom_handle, group_rid, num_names, 
				  rid_mem, names, name_types);
}

/* Lookup alias membership given a rid */

int winbindd_lookup_aliasmem(struct winbindd_domain *domain,
                             uint32 alias_rid, uint32 *num_names, 
                             DOM_SID ***sids, char ***names, 
                             enum SID_NAME_USE **name_types)
{
    /* Open sam handles */
    if (!domain_handles_open(domain)) return False;

    return sam_query_aliasmem(domain->controller, 
			      &domain->sam_dom_handle, alias_rid, num_names, 
			      sids, names, name_types);
}

/* Globals for domain list stuff */

struct winbindd_domain *domain_list = NULL;

/* Given a domain name, return the struct winbindd domain info for it */

struct winbindd_domain *find_domain_from_name(char *domain_name)
{
	struct winbindd_domain *tmp;

	/* Search through list */
	for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
		if (strcmp(domain_name, tmp->name) == 0) {
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
        DEBUG(0, ("winbid %s parameter missing\n", is_user ? "uid" : "gid"));
        return False;
    }
    
    /* Parse entry */

    if (sscanf(paramstr, "%u-%u", &id_low, &id_high) != 2) {
        DEBUG(0, ("winbid %s parameter invalid\n", 
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
        DEBUG(0, ("gid range for invalid\n"));
        return False;
    }
    
    return True;
}

/* Convert a enum winbindd_cmd to a string */

char *winbindd_cmd_to_string(enum winbindd_cmd cmd)
{
    char *result;

    switch (cmd) {

    case WINBINDD_GETPWNAM_FROM_USER:
        result = "getpwnam from user";
        break;
            
    case WINBINDD_GETPWNAM_FROM_UID:
        result = "getpwnam from uid";
        break;

    case WINBINDD_GETGRNAM_FROM_GROUP:
        result = "getgrnam from group";
        break;

    case WINBINDD_GETGRNAM_FROM_GID:
        result = "getgrnam from gid";
        break;

    case WINBINDD_SETPWENT:
        result = "setpwent";
        break;

    case WINBINDD_ENDPWENT:
        result = "endpwent";
        break;

    case WINBINDD_GETPWENT:
        result = "getpwent";
        break;

    case WINBINDD_SETGRENT:
        result = "setgrent";
        break;

    case WINBINDD_ENDGRENT:
        result = "endgrent"; 
        break;

    case WINBINDD_GETGRENT:
        result = "getgrent";
        break;

    case WINBINDD_PAM_AUTH:
        result = "pam_auth";
        break;

    default:
        result = "invalid command";
        break;
    }

    return result;
};


/* parse a string of the form DOMAIN/user into a domain and a user */
void parse_domain_user(char *domuser, fstring domain, fstring user)
{
	char *p;
	p = strchr(domuser,'/');
	if (!p) p = strchr(domuser,'\\');
	if (!p) {
		fstrcpy(domain,"");
		fstrcpy(user, domuser);
		return;
	}
	
	fstrcpy(user, p+1);
	fstrcpy(domain, domuser);
	domain[PTR_DIFF(p, domuser)] = 0;
}

/* find the sequence number for a domain */
uint32 domain_sequence_number(char *domain_name)
{
	struct winbindd_domain *domain;
	SAM_UNK_CTR ctr;

	domain = find_domain_from_name(domain_name);
	if (!domain) return DOM_SEQUENCE_NONE;

	if (!samr_query_dom_info(&domain->sam_dom_handle, 2, &ctr)) {
		DEBUG(2,("domain sequence query failed\n"));
		return DOM_SEQUENCE_NONE;
	}

	DEBUG(4,("got domain sequence number for %s of %u\n", 
		 domain_name, (unsigned)ctr.info.inf2.seq_num));
	
	return ctr.info.inf2.seq_num;
}
