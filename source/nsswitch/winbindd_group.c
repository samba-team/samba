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
#include "nterr.h"
#include "sids.h"

/* Fill a grent structure from various other information */

static void winbindd_fill_grent(struct winbindd_gr *gr, char *gr_name,
                                gid_t unix_gid)
{
    /* Fill in uid/gid */

    gr->gr_gid = unix_gid;

    /* Group name and password */

    strncpy(gr->gr_name, gr_name, sizeof(gr->gr_name) - 1);
    strncpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd) - 1);
}

/* Fill in group membership */

struct grent_mem_group {
    uint32 group_rid;
    enum SID_NAME_USE group_name_type;
    fstring domain_name;
    struct grent_mem_group *prev, *next;
};

static BOOL winbindd_fill_grent_mem(struct winbindd_domain *domain,
                                    uint32 group_rid, 
                                    enum SID_NAME_USE group_name_type, 
                                    struct winbindd_gr *gr)
{
    struct grent_mem_group *done_groups = NULL, *todo_groups = NULL;
    struct grent_mem_group *temp;
    pstring groupmem_list;
    
    /* Initialise group membership information */

    gr->num_gr_mem = 0;
    pstrcpy(groupmem_list, "");

    /* Add first group to todo_groups list */

    if ((temp = (struct grent_mem_group *)malloc(sizeof(*temp))) == NULL) {
        return False;
    }

    ZERO_STRUCTP(temp);

    temp->group_rid = group_rid;
    temp->group_name_type = group_name_type;
    fstrcpy(temp->domain_name, domain->name);

    DLIST_ADD(todo_groups, temp);
            
    /* Iterate over all groups to find members of */

    while(todo_groups != NULL) {
        struct grent_mem_group *current_group = todo_groups;
        uint32 num_names = 0, num_sids = 0, *rid_mem = NULL;
        enum SID_NAME_USE *name_types = NULL;

        DOM_SID **sids = NULL;
        char **names = NULL;
        BOOL done_group;
        int i;

        /* Check we haven't looked up this group before */

        done_group = 0;

        for (temp = done_groups; temp != NULL; temp = temp->next) {
            if ((temp->group_rid == current_group->group_rid) &&
                (strcmp(temp->domain_name, current_group->domain_name) == 0)) {
                
                done_group = 1;
            }
        }

        if (done_group) goto cleanup;

        /* Lookup group membership for the current group */

        if (current_group->group_name_type == SID_NAME_DOM_GRP) {
            if (!winbindd_lookup_groupmem(domain, current_group->group_rid, 
                                          &num_names, &rid_mem, &names, 
                                          &name_types)) {

                DEBUG(1, ("fill_grent_mem(): group rid %d not a domain "
                          "group\n", current_group->group_rid));

                /* Exit if we cannot lookup the membership for the group
                   this function was called to look at */

                if (current_group->group_rid == group_rid) {
                    return False;
                } else {
                    goto cleanup;
                }
            }
        }

        if (current_group->group_name_type == SID_NAME_ALIAS) {
            if (!winbindd_lookup_aliasmem(domain, current_group->group_rid, 
                                          &num_names, &sids, &names, 
                                          &name_types)) {

                DEBUG(1, ("fill_grent_mem(): group rid %d not a local group\n",
                          group_rid));

                /* Exit if we cannot lookup the membership for the group
                   this function was called to look at */

                if (current_group->group_rid == group_rid) {
                    return False;
                } else {
                    goto cleanup;
                }
            }
        }

        /* Now for each member of the group, add it to the group list if it
           is a user, otherwise push it onto the todo_group list if it is a
           group or an alias. */
    
        for (i = 0; i < num_names; i++) {
            enum SID_NAME_USE name_type;
        
            /* Lookup name */

            if (winbindd_lookup_sid_by_name(domain, names[i], NULL, 
                                            &name_type) == WINBINDD_OK) {

                /* Check name type */

                if (name_type == SID_NAME_USER) {
        
                    /* Add to group membership list */
                
                    if (current_group->group_name_type != SID_NAME_ALIAS) {
                        pstrcat(groupmem_list, current_group->domain_name);
                        pstrcat(groupmem_list, "/");
                    }

                    pstrcat(groupmem_list, names[i]);
                    pstrcat(groupmem_list, ",");

                    gr->num_gr_mem++;

                } else {
                    struct grent_mem_group *temp2;
                    DOM_SID todo_sid;
                    uint32 todo_rid;
                    char *todo_domain;

                    /* Add group to todo list */

                    if ((winbindd_lookup_sid_by_name(domain, names[i], 
                                                     &todo_sid, &name_type)
                         == WINBINDD_OK) && 
                        (todo_domain = strtok(names[i], "/\\"))) {
                        
                        /* Fill in group entry */

                        sid_split_rid(&todo_sid, &todo_rid);

                        if ((temp2 = (struct grent_mem_group *)
                             malloc(sizeof(*temp2))) != NULL) {
                            
                            ZERO_STRUCTP(temp2);
                            temp2->group_rid = todo_rid;
                            temp2->group_name_type = name_type;
                            fstrcpy(temp2->domain_name, todo_domain);
                            
                            DLIST_ADD(todo_groups, temp2);
                        }
                    }
                }
            }
        }

        /* Remove group from todo list and add to done_groups list */

    cleanup:

        DLIST_REMOVE(todo_groups, current_group);
        DLIST_ADD(done_groups, current_group);

        /* Free memory allocated in winbindd_lookup_{alias,group}mem() */

        if (name_types != NULL) { 
            free(name_types);
            name_types = NULL;
        }

        if (rid_mem != NULL) { 
            free(rid_mem);
            rid_mem = NULL;
        }

        if (names != NULL) { 
            int j;
            
            for (j = 0; j < num_names; j++) {
                if (names[j] != NULL) {
                    free(names[j]);
                }
            }
            
            free(names); 
            names = NULL;
        }

        if (sids != NULL) {
            int j;

            for (j = 0; j < num_sids; j++) {
                if (sids[j] != NULL) {
                    free(sids[j]);
                }
            }

            free(sids);
            sids = NULL;
        }
    }
    
    /* Free done groups list */

    temp = done_groups;

    if (temp != NULL) {
        while (temp != NULL) {
            struct grent_mem_group *next;

            DLIST_REMOVE(done_groups, temp);
            next = temp->next;

            free(temp);
            temp = next;
        }
    }

    /* Phew - copy group membership list into group structure and return */

    pstrcpy(gr->gr_mem, groupmem_list);

    return True;
}

/* Return a group structure from a group name */

enum winbindd_result winbindd_getgrnam_from_group(struct winbindd_state *state)
{
    DOM_SID domain_group_sid;
    struct winbindd_domain *domain;
    enum SID_NAME_USE name_type;
    uint32 group_rid;
    fstring name_domain, name_group, temp_name;
    POSIX_ID surs_gid;

    /* Look for group domain name */

    fstrcpy(temp_name, state->request.data.groupname);
    fstrcpy(name_domain, strtok(temp_name, "/\\"));
    fstrcpy(name_group, strtok(NULL, ""));

    /* Get domain sid for the domain */

    if ((domain = find_domain_sid_from_name(name_domain)) == NULL) {
        DEBUG(0, ("getgrname_from_group(): could not get domain sid for "
                  "domain %s\n", name_domain));
        return WINBINDD_ERROR;
    }

    /* Get rid and name type from NT server */
        
    if (!winbindd_lookup_sid_by_name(domain, name_group, &domain_group_sid, 
                                 &name_type)) {
        DEBUG(1, ("group %s in domain %s does not exist\n", name_group,
                  name_domain));
        return WINBINDD_ERROR;
    }
        
    if ((name_type != SID_NAME_ALIAS) && (name_type != SID_NAME_DOM_GRP)) {
        DEBUG(1, ("from_group: name '%s' is not a local or domain group: %d\n",
                  name_group, name_type));
        return WINBINDD_ERROR;
    }

    /* Fill in group structure */

    if (!winbindd_surs_sam_sid_to_unixid(domain, &domain_group_sid, 
                                         name_type, &surs_gid)) {
        DEBUG(1, ("error sursing unix gid for sid\n"));
        return WINBINDD_ERROR;

    }

    winbindd_fill_grent(&state->response.data.gr, 
                        state->request.data.groupname, surs_gid.id);
        
    sid_split_rid(&domain_group_sid, &group_rid);
        
    if (!winbindd_fill_grent_mem(domain, group_rid, name_type,
                                 &state->response.data.gr)) {
        return WINBINDD_ERROR;
    }

    return WINBINDD_OK;
}

/* Return a group structure from a gid number */

enum winbindd_result winbindd_getgrnam_from_gid(struct winbindd_state *state)
{
    struct winbindd_domain *domain;
    DOM_SID domain_group_sid;
    enum SID_NAME_USE name_type;
    uint32 group_rid;
    fstring group_name;
    POSIX_ID surs_gid;

    /* Find domain controller and domain sid */

    if ((domain = find_domain_from_gid(state->request.data.gid)) == NULL) {
        DEBUG(0, ("Could not find domain for gid %d\n", 
                  state->request.data.gid));
        return WINBINDD_ERROR;
    }

    /* Get sid from gid */

    surs_gid.type = SURS_POSIX_GID_AS_GRP;
    surs_gid.id = state->request.data.gid;

    if (!winbindd_surs_unixid_to_sam_sid(domain, &surs_gid, 
                                         &domain_group_sid)) {
        
        surs_gid.type = SURS_POSIX_GID_AS_ALS;

        if (!winbindd_surs_unixid_to_sam_sid(domain, &surs_gid, 
                                             &domain_group_sid)) {
            DEBUG(1, ("Could not convert gid %d to domain or local sid\n",
                      state->request.data.gid));
            return WINBINDD_ERROR;
        }
    }

    /* Get name and name type from sid */

    if (!winbindd_lookup_name_by_sid(domain, &domain_group_sid, group_name, 
                                     &name_type)) {
        DEBUG(1, ("Could not lookup sid\n"));
        return WINBINDD_ERROR;
    }

    if (!((name_type == SID_NAME_ALIAS) || (name_type == SID_NAME_DOM_GRP))) {
        DEBUG(1, ("from_gid: name '%s' is not a local or domain group: %d\n", 
                  group_name, name_type));
        return WINBINDD_ERROR;
    }

    /* Fill in group structure */

    winbindd_fill_grent(&state->response.data.gr, group_name, surs_gid.id);

    sid_split_rid(&domain_group_sid, &group_rid);
        
    if (!winbindd_fill_grent_mem(domain, group_rid, name_type,
                                 &state->response.data.gr)) {
        return WINBINDD_ERROR;
    }

    return WINBINDD_OK;
}

/*
 * set/get/endgrent functions
 */

/* "Rewind" file pointer for group database enumeration */

enum winbindd_result winbindd_setgrent(struct winbindd_state *state)
{
    struct winbindd_domain *tmp;

    if (state == NULL) return WINBINDD_ERROR;

    /* Free old static data if it exists */

    if (state->getgrent_state != NULL) {
        free_getent_state(state->getgrent_state);
        state->getgrent_state = NULL;
    }

    /* Create sam pipes for each domain we know about */

    for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        struct getent_state *domain_state;

        /* Create a state record for this domain */

        if ((domain_state = (struct getent_state *)
             malloc(sizeof(struct getent_state))) == NULL) {

            return WINBINDD_ERROR;
        }

        ZERO_STRUCTP(domain_state);

        /* Add to list of open domains */

        domain_state->domain = tmp;
        DLIST_ADD(state->getgrent_state, domain_state);
    }

    return WINBINDD_OK;
}

/* Close file pointer to ntdom group database */

enum winbindd_result winbindd_endgrent(struct winbindd_state *state)
{
    if (state == NULL) return WINBINDD_ERROR;

    free_getent_state(state->getgrent_state);
    state->getgrent_state = NULL;

    return WINBINDD_OK;
}

/* Fetch next group entry from netdom database */

enum winbindd_result winbindd_getgrent(struct winbindd_state *state)
{
    if (state == NULL) return WINBINDD_ERROR;

    /* Process the current head of the getent_state list */

    while(state->getgrent_state != NULL) {
        struct getent_state *ent = state->getgrent_state;

        /* Get list of entries if we haven't already got them */

        if (!ent->got_sam_entries) {
            uint32 status, start_ndx = 0, start_ndx2 = 0;
        
            /* Get list of groups for this domain */

            if (!open_sam_handles(ent->domain)) goto cleanup;

            if (strcmp(ent->domain->name, "BUILTIN") == 0) {

                /* Enumerate aliases */

                do {
                    status =
                        samr_enum_dom_aliases(&ent->domain->sam_dom_handle,
                                              &start_ndx, 0x100000,
                                              &ent->sam_entries,
                                              &ent->num_sam_entries);
                    } while (status == STATUS_MORE_ENTRIES);

            } else {
                        
                /* Enumerate domain groups */
                        
                do {
                    status =
                        samr_enum_dom_groups(&ent->domain->sam_dom_handle,
                                             &start_ndx, 0x100000,
                                             &ent->sam_entries,
                                             &ent->num_sam_entries);
                } while (status == STATUS_MORE_ENTRIES);

                /* Enumerate domain aliases */

                do {
                    status = 
                        samr_enum_dom_aliases(&ent->domain->sam_dom_handle,
                                              &start_ndx2, 0x100000,
                                              &ent->sam_entries,
                                              &ent->num_sam_entries);
                } while (status == STATUS_MORE_ENTRIES);
            }

            ent->got_sam_entries = True;
        }

        /* Send back a group */

        while (ent->sam_entry_index < ent->num_sam_entries) {
            enum winbindd_result result;
            fstring domain_group_name;
            char *group_name = (ent->sam_entries)
                [ent->sam_entry_index].acct_name; 
   
            /* Prepend domain to name */

            fstrcpy(domain_group_name, ent->domain->name);
            fstrcat(domain_group_name, "/");
            fstrcat(domain_group_name, group_name);
   
            /* Get group entry from group name */

            fstrcpy(state->request.data.groupname, domain_group_name);
            result = winbindd_getgrnam_from_group(state);

            ent->sam_entry_index++;
                                                      
            if (result == WINBINDD_OK) {
                return result;
            }

            /* Try next group */

            DEBUG(1, ("could not getgrnam_from_group for group name %s\n",
                      domain_group_name));
        }

        /* We've exhausted all users for this pipe - close it down and
           start on the next one. */
        
    cleanup:

        if (ent->sam_entries != NULL) free(ent->sam_entries);
        ent->sam_entries = NULL;
        
        DLIST_REMOVE(state->getgrent_state, state->getgrent_state);
    }

    /* Out of pipes so we're done */

    return WINBINDD_ERROR;
}
