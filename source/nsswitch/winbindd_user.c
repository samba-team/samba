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

/* Fill a pwent structure with information we have obtained from the
   PDC. */

static void winbindd_fill_pwent(struct winbindd_pw *pw, char *username,
                                uid_t unix_uid, gid_t unix_gid, 
                                SAM_USERINFO_CTR *user_info)
{
    fstring temp;

    if ((pw == NULL) || (username == NULL) || (user_info == NULL)) {
        return;
    }

    /* Fill in uid/gid */

    pw->pw_uid = unix_uid;
    pw->pw_gid = unix_gid;

    /* Username */

    strncpy(pw->pw_name, username, sizeof(pw->pw_name) - 1);

    /* Full name (gecos) */

    unistr2_to_ascii(temp, &user_info->info.id21->uni_full_name, 
                     sizeof(temp) - 1);


    strncpy(pw->pw_gecos, temp, sizeof(pw->pw_gecos) - 1);

    /* Home directory */

    unistr2_to_ascii(temp, &user_info->info.id21->uni_dir_drive, 
                     sizeof(temp));

    strncpy(pw->pw_dir, temp, sizeof(pw->pw_dir) - 1);

    /* Password */

    strncpy(pw->pw_passwd, "x", sizeof(pw->pw_passwd) - 1);

    /* Shell */

    strncpy(pw->pw_shell, "/dev/null", sizeof(pw->pw_shell) - 1);
}

/* Return a password structure from a username */

enum winbindd_result winbindd_getpwnam_from_user(char *user_name, 
                                                 struct winbindd_pw *pw)
{
    uint32 name_type, user_rid;
    SAM_USERINFO_CTR user_info;
    DOM_SID domain_sid, user_sid, group_sid, tmp_sid;
    fstring name_domain, name_user, tmp_name, domain_controller;
    POSIX_ID uid, gid;
    
    /* Look for user domain name */

    fstrcpy(tmp_name, user_name);
    fstrcpy(name_domain, strtok(tmp_name, "/\\"));
    fstrcpy(name_user, strtok(NULL, ""));

    /* Get domain sid for the domain */

    if (!find_domain_sid_from_domain(name_domain, &domain_sid,
                                     domain_controller)) {
        DEBUG(0, ("Could not get domain sid for domain %s\n", name_domain));
        return WINBINDD_ERROR;
    }

    /* Get rid and name type from name */
    
    if (!winbindd_lookup_by_name(domain_controller, &domain_sid, name_user, 
                                 &user_sid, &name_type)) {
        DEBUG(1, ("user '%s' does not exist\n", name_user));
        return WINBINDD_ERROR;
    }

    if (name_type != SID_NAME_USER) {
        DEBUG(1, ("name '%s' is not a user name: %d\n", name_user, name_type));
        return WINBINDD_ERROR;
    }

    /* Get some user info.  Split the user rid from the sid obtained from
       the winbind_lookup_by_name() call and use it in a
       winbind_lookup_userinfo() */
    
    sid_copy(&tmp_sid, &user_sid);
    sid_split_rid(&tmp_sid, &user_rid);

    if (!winbindd_lookup_userinfo(domain_controller, &domain_sid, user_rid, 
                                  &user_info)) {
        DEBUG(1, ("pwnam_from_user(): error getting user info for user '%s'\n",
                  name_user));
        return WINBINDD_ERROR;
    }
    
    /* Resolve the uid number */

    sid_copy(&user_sid, &domain_sid);
    sid_append_rid(&user_sid, user_info.info.id21->user_rid);

    if (!winbindd_surs_sam_sid_to_unixid(&user_sid, SID_NAME_USER, &uid)) {
        DEBUG(1, ("error getting user id for user\n"));
        return WINBINDD_ERROR;
    }

    /* Resolve the gid number */

    sid_copy(&group_sid, &domain_sid);
    sid_append_rid(&group_sid, user_info.info.id21->group_rid);
    
    if (!winbindd_surs_sam_sid_to_unixid(&group_sid, SID_NAME_DOM_GRP, &gid)) {
        DEBUG(1, ("error getting group id for user %s\n", name_user));
        return WINBINDD_ERROR;
    }

    /* Now take all this information and fill in a passwd structure */
            
    if (pw != NULL) {
        winbindd_fill_pwent(pw, user_name, uid.id, gid.id, &user_info);
    }
            
    /* Free user info */

    free_samr_userinfo_ctr(&user_info);

    return WINBINDD_OK;
}       

/* Return a password structure given a uid number */

enum winbindd_result winbindd_getpwnam_from_uid(uid_t uid, 
                                                struct winbindd_pw *pw)
{
    DOM_SID domain_sid, tmp_sid, domain_user_sid;
    uint32 user_rid;
    fstring username, domain_controller;
    enum SID_NAME_USE name_type;
    SAM_USERINFO_CTR user_info;
    POSIX_ID surs_uid, surs_gid;

    /* Get sid from uid */

    surs_uid.id = uid;
    surs_uid.type = SURS_POSIX_UID_AS_USR;

    if (!winbindd_surs_unixid_to_sam_sid(&surs_uid, &domain_user_sid, True)) {
        DEBUG(1, ("Could not convert uid %d to domain sid\n", uid));
        return WINBINDD_ERROR;
    }
    
    /* Find domain controller and domain sid */

    if (!find_domain_sid_from_uid(uid, &domain_sid, NULL, domain_controller)) {
        DEBUG(0, ("Could not find domain for uid %d\n", uid));
        return WINBINDD_ERROR;
    }

    /* Get name and name type from rid */

    if (!winbindd_lookup_by_sid(domain_controller, &domain_sid, 
                                &domain_user_sid, username, &name_type)) {
        fstring temp;

        sid_to_string(temp, &domain_user_sid);
        DEBUG(1, ("Could not lookup sid %s\n", temp));
        return WINBINDD_ERROR;
    }

    /* Get some user info */
    
    sid_copy(&tmp_sid, &domain_user_sid);
    sid_split_rid(&tmp_sid, &user_rid);

    if (!winbindd_lookup_userinfo(domain_controller, &domain_sid, user_rid, 
                                  &user_info)) {
        DEBUG(1, ("pwnam_from_uid(): error getting user info for user '%s'\n",
                  username));
        return WINBINDD_ERROR;
    }

    if (!winbindd_surs_sam_sid_to_unixid(&domain_user_sid, SID_NAME_USER,
                                         &surs_uid)) {
        DEBUG(1, ("error sursing unix uid\n"));
        return WINBINDD_ERROR;
    }

    /* ??? Should be domain_group_sid??? */

    if (!winbindd_surs_sam_sid_to_unixid(&domain_user_sid, SID_NAME_DOM_GRP,
                                         &surs_gid)) {
        DEBUG(1, ("error sursing gid\n"));
        return WINBINDD_ERROR;
    }

    /* Fill in password structure */

    winbindd_fill_pwent(pw, username, surs_uid.id, surs_gid.id, &user_info);

    /* Free user info */

    free_samr_userinfo_ctr(&user_info);

    return WINBINDD_OK;
}

/*
 * set/get/endpwent functions
 */

/* Static data for these calls  */

struct winbindd_enum_pwent_sam_pipes {
    BOOL valid;
    POLICY_HND sam_handle;
    POLICY_HND sam_dom_handle;
    struct acct_info *sam_entries;
    uint32 index, num_sam_entries;  
    fstring domain_name;
    BOOL got_sam_entries;
};

struct winbindd_enum_pwent {
    pid_t pid;
    struct winbindd_enum_pwent_sam_pipes *sam_pipes;
    int num_sam_pipes, index;
    struct winbindd_enum_pwent *prev, *next;
};

static struct winbindd_enum_pwent *enum_pwent_list = NULL;

extern int num_domain_uid;
extern struct winbind_domain_uid *domain_uid;

/* Get static data for getpwent() and friends */

static struct winbindd_enum_pwent *get_pwent_static(pid_t pid)
{
    struct winbindd_enum_pwent *tmp;

    /* Look through static data list for data associated with pid */

    for(tmp = enum_pwent_list; tmp != NULL; tmp = tmp->next) {
        if (tmp->pid == pid) {
            return tmp;
        }
    }

    return NULL;
}

/* Rewind file pointer for ntdom passwd database */

enum winbindd_result winbindd_setpwent(pid_t pid)
{
    struct winbindd_enum_pwent *enum_pwent = get_pwent_static(pid);
    struct winbind_domain_uid *tmp;
    int i;

    /* Free old static data if it exists */

    if (enum_pwent != NULL) {

        DLIST_REMOVE(enum_pwent_list, enum_pwent);

        if (enum_pwent->sam_pipes != NULL) {
            free(enum_pwent->sam_pipes);
        }

        free(enum_pwent);
    }

    /* Create new static data */

    if ((enum_pwent = (struct winbindd_enum_pwent *)
         malloc(sizeof(*enum_pwent))) == NULL) {

        return WINBINDD_ERROR;
    }

    /* Fill in fields */

    ZERO_STRUCTP(enum_pwent);
    enum_pwent->pid = pid;
    
    if ((enum_pwent->sam_pipes = (struct winbindd_enum_pwent_sam_pipes *)
         malloc(sizeof(*enum_pwent->sam_pipes) * num_domain_uid)) == NULL) {
        
        free(enum_pwent);
        return WINBINDD_ERROR;
    }

    enum_pwent->num_sam_pipes = num_domain_uid;
    memset(enum_pwent->sam_pipes, 0, sizeof(*enum_pwent->sam_pipes) * 
           num_domain_uid);

    /* Create sam pipes for each domain we know about */

    i = 0;

    for(tmp = domain_uid; tmp != NULL; tmp = tmp->next) {
        BOOL res;

        /* Connect to sam database */

        res = samr_connect(tmp->domain_controller, SEC_RIGHTS_MAXIMUM_ALLOWED, 
                           &enum_pwent->sam_pipes[i].sam_handle);

        res = res ? samr_open_domain(&enum_pwent->sam_pipes[i].sam_handle,
                                     0x304, &tmp->domain_sid, 
                                     &enum_pwent->sam_pipes[i].sam_dom_handle)
            : False;

        if (res) {
            fstrcpy(enum_pwent->sam_pipes[i].domain_name, tmp->domain_name);
            enum_pwent->sam_pipes[i].valid = True;
        } else {

            /* Ugh - failed for some reason */

            samr_close(&enum_pwent->sam_pipes[i].sam_dom_handle);
            samr_close(&enum_pwent->sam_pipes[i].sam_handle);
        }

        i++;
    }

    DLIST_ADD(enum_pwent_list, enum_pwent);

    return WINBINDD_OK;
}

/* Close file pointer to ntdom passwd database */

enum winbindd_result winbindd_endpwent(pid_t pid)
{
    struct winbindd_enum_pwent *enum_pwent = get_pwent_static(pid);

    /* Free handles and stuff */

    if (enum_pwent != NULL) {
        int i;

        /* Close handles */

        for(i = 0; i < enum_pwent->num_sam_pipes; i++) {
            if (enum_pwent->sam_pipes[i].valid) {
                samr_close(&enum_pwent->sam_pipes[i].sam_dom_handle);
                samr_close(&enum_pwent->sam_pipes[i].sam_handle);
            }
        }

        /* Free structure */

        DLIST_REMOVE(enum_pwent_list, enum_pwent);

        if (enum_pwent->sam_pipes != NULL) {
            free(enum_pwent->sam_pipes);
        }

        free(enum_pwent);
    }

    return WINBINDD_OK;
}

/* Fetch next passwd entry from ntdom database */

enum winbindd_result winbindd_getpwent(pid_t pid, struct winbindd_pw *pw)
{
    struct winbindd_enum_pwent *enum_pwent = get_pwent_static(pid);

    /* Must have called setpwent() beforehand */

    if (enum_pwent == NULL) {
        return WINBINDD_ERROR;
    }

    /* While we still have an unprocessed samr pipe */

    while (enum_pwent->index < enum_pwent->num_sam_pipes) {
        struct winbindd_enum_pwent_sam_pipes *sam_pipe;
        
        sam_pipe = &enum_pwent->sam_pipes[enum_pwent->index];

        if (sam_pipe->valid) {

            /* Get list of user entries for this pipe */

            if (!sam_pipe->got_sam_entries) {
                uint32 status, start_ndx = 0;
                
                do {
                    status =
                        samr_enum_dom_users(
                            &sam_pipe->sam_dom_handle,
                            &start_ndx, 0, 0, 0x10000,
                            &sam_pipe->sam_entries,
                            &sam_pipe->num_sam_entries);
                } while (status == STATUS_MORE_ENTRIES);
                
                sam_pipe->got_sam_entries = 1;
            }
   
            /* Send back a user */

            while (sam_pipe->index < sam_pipe->num_sam_entries) {
                enum winbindd_result result;
                fstring domain_user_name;
                char *user_name = (sam_pipe->sam_entries)
                    [sam_pipe->index].acct_name; 
                
                /* Prepend domain to name */
        
                fstrcpy(domain_user_name, sam_pipe->domain_name);
                fstrcat(domain_user_name, "/");
                fstrcat(domain_user_name, user_name);
                
                /* Get passwd entry from user name */
                
                result = winbindd_getpwnam_from_user(domain_user_name, pw);
                sam_pipe->index++;
                
                /* Return if user lookup worked */
                
                if (result == WINBINDD_OK) {
                    return result;
                }
                
                /* Try next user */

                DEBUG(1, ("could not getpwnam_from_user for username %s\n",
                          domain_user_name));
            }
        }

        /* Try next pipe */

        enum_pwent->index++;
    }

    /* Out of pipes so we're done */

    return WINBINDD_ERROR;
}
