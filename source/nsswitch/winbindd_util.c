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

BOOL lookup_domain_sid(fstring domain_name, struct winbindd_domain *domain)
{
    fstring level5_dom;
    BOOL res;

    if (domain == NULL) {
        return False;
    }

    if (!get_any_dc_name(domain_name, domain->controller)) {
        return False;
    }

    /* Get SID from domain controller.  We must call lsa_open_policy()
       directly to avoid an infinite loop with open_lsa_handle() function. */ 

    domain->lsa_handle_open =
        lsa_open_policy(domain->controller, &domain->lsa_handle, False, 
                        SEC_RIGHTS_MAXIMUM_ALLOWED);

    res = domain->lsa_handle_open ? 
        lsa_query_info_pol(&domain->lsa_handle, 0x05, level5_dom, 
                           &domain->sid) : False;

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

    if (domain->got_domain_info && !domain->lsa_handle_open) {
        domain->lsa_handle_open =
            lsa_open_policy(domain->controller, &domain->lsa_handle, False, 
                            SEC_RIGHTS_MAXIMUM_ALLOWED);
    }

    return domain->lsa_handle_open;
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
            samr_open_domain(&domain->sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                             &domain->sid, &domain->sam_dom_handle);
    }

    return domain->sam_dom_handle_open;
}

/* Lookup a sid in a domain from a name */

BOOL winbindd_lookup_sid_by_name(struct winbindd_domain *domain,
                                 fstring name, DOM_SID *sid,
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

    res = domain->lsa_handle_open ? 
        lsa_lookup_names(&domain->lsa_handle, num_names, (char **)&name,
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

    res = domain->lsa_handle_open ? 
        lsa_lookup_sids(&domain->lsa_handle, num_sids, &sid, &names, 
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
    BOOL res;

    /* Open sam handles */

    if (!open_sam_handles(domain)) return False;

    /* Query alias membership */
    
    res = domain->sam_dom_handle_open ? 
        sam_query_aliasmem(domain->controller, &domain->sam_dom_handle, 
                           alias_rid, num_names, sids, names, 
                           name_types) : False;

    return res;
}

/* Lookup alias information given a rid */

int winbindd_lookup_aliasinfo(struct winbindd_domain *domain,
                              uint32 alias_rid, ALIAS_INFO_CTR *info)
{
    BOOL res;

    /* Open pipes */

    if (!open_sam_handles(domain)) return False;

    /* Query group info */
    
    res = domain->sam_dom_handle_open ? 
        get_samr_query_aliasinfo(&domain->sam_dom_handle, 1, alias_rid, 
                                 info) : False;

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

/* Given a domain name, return the domain sid and domain controller we
   found in winbindd_surs_init(). */

struct winbindd_domain *find_domain_sid_from_name(char *domain_name)
{
    struct winbindd_domain *tmp;

    /* Search through list */

    for(tmp = domain_list; tmp != NULL; tmp = tmp->next) {
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
    /* Iterate over state list */

    while(state != NULL) {
        struct getent_state *next = state->next;

        /* Free any sam entries */

        if (state->sam_entries != NULL) free(state->sam_entries);

        /* Remove from list */

        DLIST_REMOVE(state, state);

        state = next;
    }
}

/* Parse list of arguments to winbind uid or winbind gid parameters */

static BOOL parse_id_list(char *paramstr, BOOL is_user)
{
    uid_t id_low, id_high = 0;
    struct winbindd_domain *domain;
    fstring domain_name;
    char *p;

    for (p = strtok(paramstr, LIST_SEP); p; p = strtok(NULL, LIST_SEP)) {

        /* Parse domain entry */

        if ((sscanf(p, "%[^/]/%u-%u", domain_name, &id_low, 
                    &id_high) != 3) && 
            (sscanf(p, "%[^/]/%u", domain_name, &id_low) != 2)) {

            DEBUG(0, ("surs_init(): winbid %s parameter invalid\n",
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
    /* Parse winbind uid and winbind_gid parameters */

    return (parse_id_list(lp_winbind_uid(), True) &&
            parse_id_list(lp_winbind_gid(), False));
}
