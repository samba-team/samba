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

#include "includes.h"

/* Connect to a domain controller and return the domain name and sid */

BOOL lookup_domain_sid(fstring domain_name, DOM_SID *domain_sid,
                       fstring domain_controller)
{
    POLICY_HND lsa_handle;
    DOM_SID level3_sid, level5_sid;
    fstring level3_dom, level5_dom;
    fstring system_name;
    BOOL res;

    if (!get_any_dc_name(domain_name, system_name)) {
        return False;
    }

    if (domain_controller != NULL) {
        fstrcpy(domain_controller, system_name);
    }

    /* Get SID from domain controller */

    res = lsa_open_policy(system_name, &lsa_handle, False, 
                          SEC_RIGHTS_MAXIMUM_ALLOWED);

    res = res ? lsa_query_info_pol(&lsa_handle, 0x03, level3_dom, 
                                   &level3_sid) : False;

    res = res ? lsa_query_info_pol(&lsa_handle, 0x05, level5_dom, 
                                   &level5_sid) : False;

    lsa_close(&lsa_handle);

    /* Return domain sid if successful */

    if (res && (domain_sid != NULL)) {
        sid_copy(domain_sid, &level5_sid);
        fstrcpy(domain_name, level5_dom);
    }

    return res;
}

/* Lookup a sid and type within a domain from a username */

BOOL winbindd_lookup_by_name(char *system_name, DOM_SID *level5_sid,
                             fstring name, DOM_SID *sid,
                             enum SID_NAME_USE *type)
{
    POLICY_HND lsa_handle;
    BOOL res;
    DOM_SID *sids = NULL;
    int num_sids = 0, num_names = 1;
    uint32 *types = NULL;

    if (name == NULL) {
        return 0;
    }

    res = lsa_open_policy(system_name, &lsa_handle, True, 
                          SEC_RIGHTS_MAXIMUM_ALLOWED);
    
    res = res ? lsa_lookup_names(&lsa_handle, num_names, (char **)&name,
                                 &sids, &types, &num_sids) : False;

    lsa_close(&lsa_handle);

    /* Return rid and type if lookup successful */

    if (res) {

        if ((sid != NULL) && (sids != NULL)) {
            sid_copy(sid, &sids[0]);
        }

        if ((type != NULL) && (types != NULL)) {
            *type = types[0];
        }
    }
    
    /* Free memory */

    if (types != NULL) { free(types); }
    if (sids != NULL) { free(sids); }

    return res;
}

/* Lookup a name and type within a domain from a sid */

int winbindd_lookup_by_sid(char *system_name, DOM_SID *level5_sid,
                           DOM_SID *sid, char *name,
                           enum SID_NAME_USE *type)
{
    POLICY_HND lsa_handle;
    int num_sids = 1, num_names = 0;
    uint32 *types = NULL;
    char **names;
    BOOL res;

    res = lsa_open_policy(system_name, &lsa_handle, True, 
                          SEC_RIGHTS_MAXIMUM_ALLOWED);

    res = res ? lsa_lookup_sids(&lsa_handle, num_sids, &sid,
                                &names, &types, &num_names) : False;

    lsa_close(&lsa_handle);

    /* Return name and type if successful */

    if (res) {
        if ((names != NULL) && (name != NULL)) {
            fstrcpy(name, names[0]);
        }

        if ((type != NULL) && (types != NULL)) {
            *type = types[0];
        }
    }

    /* Free memory */

    if (types != NULL) { free(types); }

    if (names != NULL) { 
        int i;

        for (i = 0; i < num_names; i++) {
            if (names[i] != NULL) {
                free(names[i]);
            }
            free(names); 
        }
    }

    return res;
}

/* Lookup user information from a rid */

int winbindd_lookup_userinfo(char *system_name, DOM_SID *dom_sid,
                             uint32 user_rid, POLICY_HND *sam_dom_handle,
                             SAM_USERINFO_CTR *user_info)
{
    POLICY_HND sam_handle, local_sam_dom_handle;
    BOOL res = True, local_handle = False;

    if (sam_dom_handle == NULL) {
        sam_dom_handle = &local_sam_dom_handle;
        local_handle = True;
    }

    /* Open connection to SAM pipe and SAM domain */

    if (local_handle) {

        res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                           &sam_handle);

        res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                     dom_sid, sam_dom_handle) : False;
    }

    /* Get user info */

    res = res ? get_samr_query_userinfo(sam_dom_handle, 0x15, 
                                        user_rid, user_info) : False;

    /* Close up shop */

    if (local_handle) {
        samr_close(sam_dom_handle);
        samr_close(&sam_handle);
    }

    return res;
}                                   

/* Lookup group information from a rid */

int winbindd_lookup_groupinfo(char *system_name, DOM_SID *dom_sid,
                              uint32 group_rid, GROUP_INFO_CTR *info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res;

    /* Open connection to SAM pipe and SAM domain */

    res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED, &sam_handle);

    res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                 dom_sid, &sam_dom_handle) : False;
    /* Query group info */
    
    res = res ? get_samr_query_groupinfo(&sam_dom_handle, 1,
                                         group_rid, info) : False;

    /* Close up shop */

    samr_close(&sam_dom_handle);
    samr_close(&sam_handle);

    return res;
}

/* Lookup group membership given a rid */

int winbindd_lookup_groupmem(char *system_name, DOM_SID *dom_sid,
                             uint32 group_rid, POLICY_HND *sam_dom_handle,
                             uint32 *num_names, uint32 **rid_mem, 
                             char ***names, uint32 **name_types)
{
    POLICY_HND sam_handle, local_sam_dom_handle;
    BOOL res = True, local_handle = False;

    if (sam_dom_handle == NULL) {
        sam_dom_handle = &local_sam_dom_handle;
        local_handle = True;
    }

    /* Open connection to SAM pipe and SAM domain */

    if (local_handle) {

        res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                           &sam_handle);

        res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                     dom_sid, sam_dom_handle) : False;
    }
    /* Query group membership */
    
    res = res ? sam_query_groupmem(sam_dom_handle, group_rid, num_names, 
                                   rid_mem, names, name_types) : False;

    /* Close up shop */

    if (local_handle) {
        samr_close(sam_dom_handle);
        samr_close(&sam_handle);
    }

    return res;
}

/* Lookup alias membership given a rid */

int winbindd_lookup_aliasmem(char *system_name, DOM_SID *dom_sid,
                             uint32 alias_rid, POLICY_HND *sam_dom_handle,
                             uint32 *num_names, DOM_SID ***sids, 
                             char ***names, uint32 **name_types)
{
    POLICY_HND sam_handle, local_sam_dom_handle;
    BOOL res = True, local_handle = False;

    if (sam_dom_handle == NULL) {
        sam_dom_handle = &local_sam_dom_handle;
        local_handle = True;
    }

    /* Open connection to SAM pipe and SAM domain */

    if (local_handle) {

        res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                           &sam_handle);

        res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                     dom_sid, sam_dom_handle) : False;
    }

    /* Query alias membership */
    
    res = res ? sam_query_aliasmem(system_name, sam_dom_handle, alias_rid,
                                   num_names, sids, names, name_types)
        : False;

    /* Close up shop */

    if (local_handle) {
        samr_close(sam_dom_handle);
        samr_close(&sam_handle);
    }

    return res;
}

/* Lookup alias information given a rid */

int winbindd_lookup_aliasinfo(char *system_name, DOM_SID *dom_sid,
                              uint32 alias_rid, ALIAS_INFO_CTR *info)
{
    POLICY_HND sam_handle, sam_dom_handle;
    BOOL res;

    /* Open connection to SAM pipe and SAM domain */

    res = samr_connect(system_name, SEC_RIGHTS_MAXIMUM_ALLOWED,
                       &sam_handle);

    res = res ? samr_open_domain(&sam_handle, SEC_RIGHTS_MAXIMUM_ALLOWED,
                                 dom_sid, &sam_dom_handle) : False;
    /* Query group info */
    
    res = res ? get_samr_query_aliasinfo(&sam_dom_handle, 1,
                                         alias_rid, info) : False;

    /* Close up shop */

    samr_close(&sam_dom_handle);
    samr_close(&sam_handle);

    return res;
}

/* Globals for domain list stuff */

struct winbindd_domain *domain_list = NULL;
struct winbindd_domain_uid *domain_uid_list = NULL;
struct winbindd_domain_gid *domain_gid_list = NULL;

/* Given a domain name, return the struct winbindd domain info for it */

struct winbindd_domain *find_domain_from_name(char *domain_name)
{
    struct winbindd_domain *tmp;

    /* Search through list */

    for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        if (strcmp(domain_name, tmp->domain_name) == 0) {
            return tmp;
        }
    }

    /* Not found */

    return NULL;
}

/* Given a domain name, return the domain sid and domain controller we
   found in winbindd_surs_init(). */

BOOL find_domain_sid_from_name(char *domain_name, DOM_SID *domain_sid, 
                               char *domain_controller)
{
    struct winbindd_domain *tmp;

    /* Search through list */

    for(tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        if (strcmp(domain_name, tmp->domain_name) == 0) {

            /* Copy domain sid */

            if (domain_sid != NULL) {
                sid_copy(domain_sid, &tmp->domain_sid);
            }
            
            /* Copy domain controller */

            if (domain_controller != NULL) {
                fstrcpy(domain_controller, tmp->domain_controller);
            }

            return True;
        }
    }

    /* Not found */

    return False;
}

/* Given a uid, return the domain sid and domain controller */

BOOL find_domain_sid_from_uid(uid_t uid, DOM_SID *domain_sid,
                              char *domain_name,
                              char *domain_controller)
{
    struct winbindd_domain_uid *tmp;

    for(tmp = domain_uid_list; tmp != NULL; tmp = tmp->next) {
        if ((uid >= tmp->uid_low) && (uid <= tmp->uid_high) &&
            (tmp->domain != NULL)) {

            /* Copy domain sid */

            if (domain_sid != NULL) {
                sid_copy(domain_sid, &tmp->domain->domain_sid);
            }
            
            /* Copy domain controller */

            if (domain_controller != NULL) {
                fstrcpy(domain_controller, tmp->domain->domain_controller);
            }

            /* Copy domain name */

            if (domain_name != NULL) {
                fstrcpy(domain_name, tmp->domain->domain_name);
            }

            return True;
        }
    }

    /* Not found */

    return False;
}

/* Given a uid, return the domain sid and domain controller */

BOOL find_domain_sid_from_gid(gid_t gid, DOM_SID *domain_sid,
                              char *domain_controller,
                              char *domain_name)
{
    struct winbindd_domain_gid *tmp;

    for(tmp = domain_gid_list; tmp != NULL; tmp = tmp->next) {
        if ((gid >= tmp->gid_low) && (gid <= tmp->gid_high) &&
            (tmp->domain != NULL)) {

            /* Copy domain sid */

            if (domain_sid != NULL) {
                sid_copy(domain_sid, &tmp->domain->domain_sid);
            }
            
            /* Copy domain controller */

            if (domain_controller != NULL) {
                fstrcpy(domain_controller, tmp->domain->domain_controller);
            }

            /* Copy domain name */

            if (domain_name != NULL) {
                fstrcpy(domain_name, tmp->domain->domain_name);
            }

            return True;
        }
    }

    /* Not found */

    return False;
}

/* Free state information held for {set,get,end}{pw,gr}ent() functions */

void free_getent_state(struct getent_state *state)
{
    /* Iterate over state list */

    while(state != NULL) {
        struct getent_state *next = state->next;

        /* Close sam handles if they are open */

        if (!state->got_sam_entries) {
            samr_close(&state->sam_dom_handle);
            samr_close(&state->sam_handle);
        }

        /* Free any sam entries */

        if (state->sam_entries != NULL) free(state->sam_entries);

        /* Remove from list */

        DLIST_REMOVE(state, state);

        state = next;
    }
}
