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

static BOOL winbindd_fill_grent_mem(char *server_name, char *domain_name, 
                                    uint32 group_rid, 
                                    enum SID_NAME_USE group_name_type, 
                                    POLICY_HND *sam_dom_handle,
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
    fstrcpy(temp->domain_name, domain_name);

    DLIST_ADD(todo_groups, temp);
            
    /* Iterate over all groups to find members of */

    while(todo_groups != NULL) {
        struct grent_mem_group *current_group = todo_groups;
        uint32 num_names = 0, num_sids = 0, *rid_mem = NULL, 
            *name_types = NULL;
        DOM_SID **sids = NULL, domain_sid;
        char **names = NULL;
        int i, done_group;

        /* Find domain sid for this group */

        if (!find_domain_sid_from_name(current_group->domain_name, 
                                       &domain_sid, NULL)) {
            DEBUG(1, ("%s:%d: could not locate domain sid for domain "
                      "%s\n", __FUNCTION__, __LINE__, 
                      current_group->domain_name));

            /* Exit if we cannot lookup the sid for the domain of the group
               this function was called to look at */

            if (fstrcpy(current_group->domain_name, domain_name) == 0) {
                return False;
            } else {
                goto cleanup;
            }
        }

        /* Check we aren't doing it recursively */

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
            if (!winbindd_lookup_groupmem(server_name, &domain_sid, 
                                          current_group->group_rid, 
                                          sam_dom_handle, &num_names, 
                                          &rid_mem, &names, &name_types)) {

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
            if (!winbindd_lookup_aliasmem(server_name, &domain_sid, 
                                          current_group->group_rid, 
                                          sam_dom_handle, &num_names, 
                                          &rid_mem, &names, &name_types) &&
                !winbindd_lookup_aliasmem(server_name, global_sid_builtin, 
                                          current_group->group_rid, 
                                          sam_dom_handle, &num_sids, 
                                          &sids, &names, &name_types)) {

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

            if (winbindd_lookup_by_name(server_name, &domain_sid, names[i],
                                        NULL, &name_type) == WINBINDD_OK) {

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

                    if ((winbindd_lookup_by_name(server_name, &domain_sid, 
                                                 names[i], &todo_sid, 
                                                 &name_type) == WINBINDD_OK) &&
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

enum winbindd_result winbindd_getgrnam_from_group(char *groupname,
                                                  POLICY_HND *sam_dom_handle,
                                                  struct winbindd_gr *gr)
{
    DOM_SID domain_sid, domain_group_sid;
    uint32 name_type;
    fstring name_domain, name_group, temp_name, domain_controller;
    POSIX_ID surs_gid;

    /* Look for group domain name */

    fstrcpy(temp_name, groupname);
    fstrcpy(name_domain, strtok(temp_name, "/\\"));
    fstrcpy(name_group, strtok(NULL, ""));

    /* Get domain sid for the domain */

    if (!find_domain_sid_from_name(name_domain, &domain_sid, 
                                     domain_controller)) {
        DEBUG(0, ("getgrname_from_group(): could not get domain sid for "
                  "domain %s\n", name_domain));
        return WINBINDD_ERROR;
    }

    /* Get rid and name type from NT server */
        
    if ((strcmp(name_domain, "BUILTIN") == 0) &&
        !winbindd_lookup_by_name(domain_controller, global_sid_builtin,
                                 name_group, &domain_group_sid,
                                 &name_type)) {
        DEBUG(1, ("builtin group name %s does not exist\n", name_group));
        return WINBINDD_ERROR;
    }
        
    if (!winbindd_lookup_by_name(domain_controller, &domain_sid, name_group, 
                                 &domain_group_sid, &name_type)) {
        DEBUG(1, ("group name %s does not exist\n", name_group));
        return WINBINDD_ERROR;
    }
    
    if ((name_type != SID_NAME_ALIAS) && (name_type != SID_NAME_DOM_GRP)) {
        DEBUG(1, ("from_group: name '%s' is not a local or domain group: %d\n",
                  name_group, name_type));
        return WINBINDD_ERROR;
    }

    /* Fill in group structure */

    if (!winbindd_surs_sam_sid_to_unixid(&domain_group_sid, name_type, 
                                         &surs_gid)) {
        DEBUG(1, ("error sursing unix gid for sid\n"));
        return WINBINDD_ERROR;

    }

    if (gr != NULL) {
        DOM_SID temp;
        uint32 group_rid;
        
        winbindd_fill_grent(gr, groupname, surs_gid.id);
        
        sid_copy(&temp, &domain_group_sid);
        sid_split_rid(&temp, &group_rid);
        
        if (!winbindd_fill_grent_mem(domain_controller, name_domain, 
                                     group_rid, name_type, NULL, gr)) {
            return WINBINDD_ERROR;
        }
    }

    return WINBINDD_OK;
}

/* Return a group structure from a gid number */

enum winbindd_result winbindd_getgrnam_from_gid(gid_t gid, 
                                                struct winbindd_gr *gr)
{
    DOM_SID domain_sid, domain_group_sid;
    uint32 name_type;
    fstring group_name, domain_controller, domain_name;
    POSIX_ID surs_gid;

    /* Get sid from gid */

    surs_gid.type = SURS_POSIX_GID_AS_GRP;
    surs_gid.id = gid;

    if (!winbindd_surs_unixid_to_sam_sid(&surs_gid, &domain_group_sid, 
                                         False)) {
        
        surs_gid.type = SURS_POSIX_GID_AS_ALS;

        if (!winbindd_surs_unixid_to_sam_sid(&surs_gid, &domain_group_sid, 
                                             False)) {
            DEBUG(1, ("Could not convert gid %d to domain or local sid\n",
                      gid));
            return WINBINDD_ERROR;
        }
    }

    /* Find domain controller and domain sid */

    if (!find_domain_sid_from_gid(gid, &domain_sid, domain_controller,
                                  domain_name)) {
        DEBUG(0, ("Could not find domain for gid %d\n", gid));
        return WINBINDD_ERROR;
    }

    /* Get name and name type from sid */

    if (!winbindd_lookup_by_sid(domain_controller, &domain_sid, 
                                &domain_group_sid, group_name, &name_type)) {
        DEBUG(1, ("Could not lookup sid\n"));
        return WINBINDD_ERROR;
    }

    if (!((name_type == SID_NAME_ALIAS) ||
          (name_type == SID_NAME_DOM_GRP))) {
        DEBUG(1, ("from_gid: name '%s' is not a local or domain group: %d\n", 
                  group_name, name_type));
        return WINBINDD_ERROR;
    }

    /* Fill in group structure */

    if (gr != NULL) {
        DOM_SID temp;
        uint32 group_rid;

        winbindd_fill_grent(gr, group_name, surs_gid.id);

        sid_copy(&temp, &domain_group_sid);
        sid_split_rid(&temp, &group_rid);
        
        if (!winbindd_fill_grent_mem(domain_controller, domain_name, 
                                     group_rid, name_type, NULL, gr)) {
            return WINBINDD_ERROR;
        }
    }

    return WINBINDD_OK;
}

/*
 * set/get/endgrent functions
 */

/* Static data for these calls */

struct winbindd_enum_grent_sam_pipes {
    BOOL valid;
    POLICY_HND sam_handle;
    POLICY_HND sam_dom_handle;
    struct acct_info *sam_entries;
    uint32 index, num_sam_entries;  
    fstring domain_name;
    BOOL got_sam_entries;
};

struct winbindd_enum_grent {
    pid_t pid;
    struct winbindd_enum_grent_sam_pipes *sam_pipes;
    int num_sam_pipes, index;
    struct winbindd_enum_grent *prev, *next;
};

static struct winbindd_enum_grent *enum_grent_list = NULL;

extern struct winbind_domain *domain_list;
extern int num_domain;

/* Return the winbindd_enum_grent structure for a given pid */

static struct winbindd_enum_grent *get_grent_static(pid_t pid)
{
    struct winbindd_enum_grent *tmp;

    for(tmp = enum_grent_list; tmp != NULL; tmp = tmp->next) {
        if (tmp->pid == pid) {
            return tmp;
        }
    }

    return NULL;
}

/* "Rewind" file pointer for group database enumeration */

enum winbindd_result winbindd_setgrent(pid_t pid)
{
    struct winbindd_enum_grent *enum_grent = get_grent_static(pid);
    struct winbind_domain *tmp;
    int i;

    /* Free old static data if it exists */

    if (enum_grent != NULL) {

        DLIST_REMOVE(enum_grent_list, enum_grent);

        if (enum_grent->sam_pipes != NULL) {
            free(enum_grent->sam_pipes);
        }

        free(enum_grent);
    }

    /* Create new static data */

    if ((enum_grent = (struct winbindd_enum_grent *)
         malloc(sizeof(*enum_grent))) == NULL) {

        return WINBINDD_ERROR;
    }

    /* Fill in fields */

    ZERO_STRUCTP(enum_grent);
    enum_grent->pid = pid;

    if ((enum_grent->sam_pipes = (struct winbindd_enum_grent_sam_pipes *)
         malloc(sizeof(*enum_grent->sam_pipes) * num_domain)) == NULL) {

        free(enum_grent);
        return WINBINDD_ERROR;
    }

    enum_grent->num_sam_pipes = num_domain;
    memset(enum_grent->sam_pipes, 0, sizeof(*enum_grent->sam_pipes) *
           num_domain);

    /* Connect to samr pipe for each domain */

    i = 0;

    for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        BOOL res;

        /* Connect to sam database */

        res = samr_connect(tmp->domain_controller, SEC_RIGHTS_MAXIMUM_ALLOWED,
                           &enum_grent->sam_pipes[i].sam_handle);

        res = res ? samr_open_domain(&enum_grent->sam_pipes[i].sam_handle, 
                                     0x304, &tmp->domain_sid, 
                                     &enum_grent->sam_pipes[i].sam_dom_handle)
            : False;

        if (res) {
            fstrcpy(enum_grent->sam_pipes[i].domain_name,
                    tmp->domain_name);
            enum_grent->sam_pipes[i].valid = True;
        } else {

            /* Close everything */

            samr_close(&enum_grent->sam_pipes[i].sam_dom_handle);
            samr_close(&enum_grent->sam_pipes[i].sam_handle);
        }

        i++;
    }

    /* Add static data to list */

    DLIST_ADD(enum_grent_list, enum_grent);

    return WINBINDD_OK;
}

enum winbindd_result winbindd_endgrent(pid_t pid)
{
    struct winbindd_enum_grent *enum_grent = get_grent_static(pid);

    /* Free handles and stuff */

    if (enum_grent != NULL) {
        int i;

        /* Close handles */

        for(i = 0; i < enum_grent->num_sam_pipes; i++) {
            if (enum_grent->sam_pipes[i].valid) {
                samr_close(&enum_grent->sam_pipes[i].sam_dom_handle);
                samr_close(&enum_grent->sam_pipes[i].sam_handle);
            }
        }

        /* Free structure */

        DLIST_REMOVE(enum_grent_list, enum_grent);

        if (enum_grent->sam_pipes != NULL) {
            free(enum_grent->sam_pipes);
        }

        free(enum_grent);
    }

    return WINBINDD_OK;
}

enum winbindd_result winbindd_getgrent(pid_t pid, struct winbindd_gr *gr)
{
    struct winbindd_enum_grent *enum_grent = get_grent_static(pid);

    /* Must have called setgrent() beforehand */

    if (enum_grent == NULL) {
        return WINBINDD_ERROR;
    }

    /* While we still have an unprocessed samr pipe */

    while (enum_grent->index < enum_grent->num_sam_pipes) {
        struct winbindd_enum_grent_sam_pipes *sam_pipe;
        
        sam_pipe = &enum_grent->sam_pipes[enum_grent->index];

        if (sam_pipe->valid) {

            /* Get list of entries if we haven't already got them */

            if (!sam_pipe->got_sam_entries) {
                uint32 status, start_ndx = 0, start_ndx2 = 0;
        
                /* Get list of groups for this domain */

                if (strcmp(sam_pipe->domain_name, "BUILTIN") == 0) {

                    /* Enumerate aliases */

                    do {
            
                        status =
                            samr_enum_dom_aliases(&sam_pipe->sam_dom_handle,
                                      &start_ndx, 0x100000,
                                      &sam_pipe->sam_entries,
                                      &sam_pipe->num_sam_entries);
                    } while (status == STATUS_MORE_ENTRIES);

                } else {
                        
                    /* Enumerate domain groups */
                        
                    do {
                        status =
                            samr_enum_dom_groups(&sam_pipe->sam_dom_handle,
                                                 &start_ndx, 0x100000,
                                                 &sam_pipe->sam_entries,
                                                 &sam_pipe->num_sam_entries);
                    } while (status == STATUS_MORE_ENTRIES);

                    /* Enumerate domain aliases */
                    
                    do {
                        status = 
                            samr_enum_dom_aliases(&sam_pipe->sam_dom_handle,
                                                  &start_ndx2, 0x100000,
                                                  &sam_pipe->sam_entries,
                                                  &sam_pipe->num_sam_entries);
                    } while (status == STATUS_MORE_ENTRIES);
                }

                sam_pipe->got_sam_entries = True;
            }

            /* Send back a group */

            while (sam_pipe->index < sam_pipe->num_sam_entries) {
                enum winbindd_result result;
                fstring domain_group_name;
                char *group_name = (sam_pipe->sam_entries)
                    [sam_pipe->index].acct_name; 
   
                /* Prepend domain to name */

                fstrcpy(domain_group_name, sam_pipe->domain_name);
                fstrcat(domain_group_name, "/");
                fstrcat(domain_group_name, group_name);
   
                /* Get group entry from group name */

                result = winbindd_getgrnam_from_group(
                    domain_group_name, &sam_pipe->sam_dom_handle, gr);
                sam_pipe->index++;
                                                      
                if (result == WINBINDD_OK) {
                    return result;
                }

                /* Try next group */

                DEBUG(1, ("could not getgrnam_from_group for group name %s\n",
                          domain_group_name));
            }
        }

        /* Try next pipe */

        enum_grent->index++;
    }

    /* Out of pipes so we're done */

    return WINBINDD_ERROR;
}
