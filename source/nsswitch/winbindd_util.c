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

/* Connect to a domain controller using get_any_dc_name() to discover 
   the domain name and sid */

BOOL lookup_domain_sid(char *domain_name, struct winbindd_domain *domain)
{
    fstring level5_dom, domain_controller;
    BOOL res;

    if (domain == NULL) {
        return False;
    }

    /* Get controller name for domain */

    if (!get_any_dc_name(domain_name, domain_controller)) {
        return False;
    }

    if (strnequal("\\\\", domain_controller, 2)) {
        fstrcpy(domain->controller, &domain_controller[2]);
    } else {
        fstrcpy(domain->controller, domain_controller);
    }

    /* Lookup sid for domain.  We must call lsa_open_policy() directly to
       avoid an infinite loop with open_lsa_handle() function. */

    server_state.lsa_handle_open =
        lsa_open_policy(server_state.controller, &server_state.lsa_handle, 
                        False, SEC_RIGHTS_MAXIMUM_ALLOWED);
        
    if (strequal(domain->controller, server_state.controller)) {

        /* Do a level 5 query info policy */

        res = server_state.lsa_handle_open ? 
            lsa_query_info_pol(&server_state.lsa_handle, 0x05, level5_dom, 
                               &domain->sid) : False;
    } else {
	uint32 enum_ctx = 0;
	uint32 num_doms = 0;
	char **domains = NULL;
	DOM_SID **sids = NULL;
        int i;

        /* Use lsaenumdomains to get sid for this domain */

        res = server_state.lsa_handle_open ?
            lsa_enum_trust_dom(&server_state.lsa_handle, &enum_ctx,
                               &num_doms, &domains, &sids) : False;

        /* Look for domain name */

        if (res && domains && sids) {
            int found = False;

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

        if (domains) {

            /* Free array elements */

            for(i = 0; i < num_doms; i++) {
                safe_free(domains[i]);
            }

            /* Free array */

            safe_free(domains);
        }

        if (sids) {
            
            /* Free array elements */

            for(i = 0; i < num_doms; i++) {
                safe_free(sids[i]);
            }

            /* Free array */

            safe_free(sids);
        }
    }

    return res;
}

/* Lookup domain controller and sid for a domain */

BOOL get_domain_info(struct winbindd_domain *domain)
{
    fstring sid_str;

    /* Lookup domain sid */
        
    if (strequal(domain->name, "BUILTIN")) {
        if (!lookup_domain_sid(lp_workgroup(), domain)) {
            DEBUG(0, ("could not find sid for domain %s\n", 
                      domain->name));
            return False;
        }
        
        /* Fake up sid and domain controller */
        
        sid_copy(&domain->sid, global_sid_builtin);
        fstrcpy(domain->name, "BUILTIN");
        
    } else if (!lookup_domain_sid(domain->name, domain)) {
        DEBUG(0, ("could not find sid for domain %s\n", domain->name));
        return False;
    }
    
    domain->got_domain_info = 1;

    sid_to_string(sid_str, &domain->sid);
    DEBUG(0, ("found sid %s for domain %s\n", sid_str, domain->name));

    return True;
}        

/* Open a lsa handle to a domain and cache the result */

BOOL open_lsa_handle(struct winbindd_domain *domain)
{
    /* Get domain info */

    if (!domain->got_domain_info) {
        domain->got_domain_info = get_domain_info(domain);
    }

    /* Open lsa handle if it isn't already open */

    if (domain->got_domain_info && !server_state.lsa_handle_open) {
        server_state.lsa_handle_open =
            lsa_open_policy(server_state.controller, &server_state.lsa_handle, 
                            False, SEC_RIGHTS_MAXIMUM_ALLOWED);
    }

    return server_state.lsa_handle_open;
}

/* Open sam and sam domain handles to a domain and cache the results */

BOOL open_sam_handles(struct winbindd_domain *domain)
{
    /* Get domain info */

    if (!domain->got_domain_info) {
        domain->got_domain_info = get_domain_info(domain);
    }

    /* Open sam handle if it isn't already open */

    if (domain->got_domain_info && !domain->sam_handle_open) {
        domain->sam_handle_open = 
            samr_connect(domain->controller, SEC_RIGHTS_MAXIMUM_ALLOWED, 
                         &domain->sam_handle);
    }

    /* Open sam domain handle if it isn't already open */

    if (domain->sam_handle_open && !domain->sam_dom_handle_open) {
        domain->sam_dom_handle_open =
            samr_open_domain(&domain->sam_handle, 
                             SEC_RIGHTS_MAXIMUM_ALLOWED, &domain->sid, 
                             &domain->sam_dom_handle);
    }

    /* Open sam builtin handle if it isn't already open */

    if (domain->sam_handle_open && !domain->sam_blt_handle_open) {
        domain->sam_blt_handle_open =
            samr_open_domain(&domain->sam_handle,
                             SEC_RIGHTS_MAXIMUM_ALLOWED, global_sid_builtin,
                             &domain->sam_blt_handle);
    }

    return domain->sam_dom_handle_open && 
        domain->sam_blt_handle_open;
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

    /* Open handles */

    if (!open_lsa_handle(domain)) return False;

    /* Lookup name */

    res = server_state.lsa_handle_open ? 
        lsa_lookup_names(&server_state.lsa_handle, num_names, (char **)&name,
                         &sids, &types, &num_sids) : False;

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

    /* Open handles */

    if (!open_lsa_handle(domain)) return False;

    /* Lookup name */

    res = server_state.lsa_handle_open ? 
        lsa_lookup_sids(&server_state.lsa_handle, num_sids, &sid, &names, 
                        &types, &num_names) : False;

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

    if (types != NULL) free(types);

    if (names != NULL) { 
        int i;

        for (i = 0; i < num_names; i++) {
            if (names[i] != NULL) {
                free(names[i]);
            }
        }
        free(names); 
    }

    return res;
}

/* Lookup user information from a rid */

BOOL winbindd_lookup_userinfo(struct winbindd_domain *domain,
                              uint32 user_rid, SAM_USERINFO_CTR *user_info)
{
    BOOL res;

    /* Open handles */

    if (!open_sam_handles(domain)) return False;

    /* Get user info */

    res = domain->sam_dom_handle_open ? 
        get_samr_query_userinfo(&domain->sam_dom_handle, 0x15, user_rid, 
                                user_info) : False;

    return res;
}                                   

/* Lookup group information from a rid */

BOOL winbindd_lookup_groupinfo(struct winbindd_domain *domain,
                              uint32 group_rid, GROUP_INFO_CTR *info)
{
    BOOL res;

    /* Open pipes */

    if (!open_sam_handles(domain)) return False;

    /* Query group info */
    
    res = domain->sam_dom_handle_open ? 
        get_samr_query_groupinfo(&domain->sam_dom_handle, 1, group_rid, 
                                 info) : False;

    return res;
}

/* Lookup group membership given a rid */

BOOL winbindd_lookup_groupmem(struct winbindd_domain *domain,
                              uint32 group_rid, uint32 *num_names, 
                              uint32 **rid_mem, char ***names, 
                              enum SID_NAME_USE **name_types)
{
    BOOL res;

    /* Open pipes */

    if (!open_sam_handles(domain)) return False;

    /* Query group membership */
    
    res = domain->sam_dom_handle_open ? 
        sam_query_groupmem(&domain->sam_dom_handle, group_rid, num_names, 
                           rid_mem, names, name_types) : False;

    return res;
}

/* Lookup alias membership given a rid */

int winbindd_lookup_aliasmem(struct winbindd_domain *domain,
                             uint32 alias_rid, uint32 *num_names, 
                             DOM_SID ***sids, char ***names, 
                             enum SID_NAME_USE **name_types)
{
    POLICY_HND *pol;
    BOOL res;

    /* Open sam handles */

    if (!open_sam_handles(domain)) return False;

    if (sid_equal(global_sid_builtin, &domain->sid)) {
        pol = &domain->sam_blt_handle;
    } else {
        pol = &domain->sam_dom_handle;
    }

    /* Query alias membership */
    
    res = domain->sam_dom_handle_open ? 
        sam_query_aliasmem(domain->controller, pol, alias_rid, num_names, 
                           sids, names, name_types) : False;

    return res;
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

            /* Get domain info for this domain */

            if (!tmp->got_domain_info && !get_domain_info(tmp)) {
                return NULL;
            }

            return tmp;
        }
    }

    /* Not found */

    return NULL;
}

/* Given a uid return the domain for which the uid falls in the uid range. */

struct winbindd_domain *find_domain_from_uid(uid_t uid)
{
    struct winbindd_domain *tmp;

    for(tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        if ((uid >= tmp->uid_low) && (uid <= tmp->uid_high)) {

            /* Get domain info for this domain */

            if (!tmp->got_domain_info && !get_domain_info(tmp)) {
                return NULL;
            }

            return tmp;
        }
    }

    return NULL;
}

/* Given a gid return the domain for which the gid falls in the gid range. */

struct winbindd_domain *find_domain_from_gid(gid_t gid)
{
    struct winbindd_domain *tmp;

    for(tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        if ((gid >= tmp->gid_low) && (gid <= tmp->gid_high)) {

            /* Get domain info for this domain */

            if (!tmp->got_domain_info && !get_domain_info(tmp)) {
                return NULL;
            }

            return tmp;
        }
    }

    return NULL;
}

struct winbindd_domain *find_domain_from_sid(DOM_SID *sid)
{
    struct winbindd_domain *tmp;

    for(tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        if(sid_equal(sid, &tmp->sid)) {

            /* Get domain info for this domain */

            if (!tmp->got_domain_info && !get_domain_info(tmp)) {
                return NULL;
            }

            return tmp;
        }
    }

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
    struct winbindd_domain *domain;
    fstring domain_name;
    fstring p;

    while(next_token(&paramstr, p, LIST_SEP, sizeof(fstring) - 1)) {

        /* Parse domain entry */

        if ((sscanf(p, "%[^/]/%u-%u", domain_name, &id_low, 
                    &id_high) != 3) && 
            (sscanf(p, "%[^/]/%u", domain_name, &id_low) != 2)) {

            DEBUG(0, ("winbid %s parameter invalid\n", 
                      is_user ? "uid" : "gid"));
            return False;
        }

        /* Find domain record */
        
        if ((domain = find_domain_from_name(domain_name)) == NULL) {
            
            /* Create new domain record */
            
            if ((domain = (struct winbindd_domain *)malloc(sizeof(*domain)))
                 == NULL) {
                return False;
            }

            ZERO_STRUCTP(domain);
            fstrcpy(domain->name, domain_name);

            DLIST_ADD(domain_list, domain);
        }

        /* Store domain id info */
            
        if (is_user) {

            /* Store user info */

            domain->uid_low = id_low;

            if (id_high == 0) {
                domain->uid_high = -1;
            } else {
                domain->uid_high = id_high;
            }

        } else {

            /* Store group info */

            domain->gid_low = id_low;

            if (id_high == 0) {
                domain->gid_high = -1;
            } else {
                domain->gid_high = id_high;
            }
        }
    }

    return True;
}

/* Initialise trusted domain info */

BOOL winbindd_param_init(void)
{
    BOOL result;

    /* Parse winbind uid and winbind_gid parameters */

    result = parse_id_list(lp_winbind_uid(), True) &&
        parse_id_list(lp_winbind_gid(), False);

    /* Perform other sanity checks on results.  The only fields we have filled
       in at the moment are name and [ug]id_{low,high} */

    if (result) {
        struct winbindd_domain *temp, *temp2;

        /* Check for duplicate domain names */

        for (temp = domain_list; temp; temp = temp->next) {

            /* Check for reversed uid and gid ranges */

            if (temp->uid_low > temp->uid_high) {
                DEBUG(0, ("uid range for domain %s invalid\n", temp->name));
                return False;
            }

            if (temp->gid_low > temp->gid_high) {
                DEBUG(0, ("gid range for domain %s invalid\n", temp->name));
                return False;
            }

            for (temp2 = domain_list; temp2; temp2 = temp2->next) {
                if (temp != temp2) {
                    
                    /* Check for duplicate domain names */
                    
                    if ((temp != temp2) && strequal(temp->name, temp2->name)) {
                        DEBUG(0, ("found duplicate domain %s in winbind "
                                  "domain list\n", temp->name));
                        return False;
                    }

                    /* Check for overlapping uid ranges */

                    if (((temp->uid_low >= temp2->uid_low) &&
                         (temp->uid_low <= temp2->uid_high)) ||
                        ((temp->uid_high >= temp2->uid_low) &&
                         (temp->uid_high <= temp2->uid_high))) {
                        
                        DEBUG(0, ("uid ranges for domains %s and %s overlap\n",
                                  temp->name, temp2->name));
                        return False;
                    }

                    /* Check for overlapping gid ranges */

                    if (((temp->gid_low >= temp2->gid_low) &&
                         (temp->gid_low <= temp2->gid_high)) ||
                        ((temp->gid_high >= temp2->gid_low) &&
                         (temp->gid_high <= temp2->gid_high))) {

                        DEBUG(0, ("gid ranges for domains %s and %s overlap\n",
                                 temp->name, temp2->name));
                        return False;
                    }                    
                }
            }
        }
    }

    return result;
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

    default:
        result = "invalid command";
        break;
    }

    return result;
};
