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
#include "winbindd.h"

#include <nterr.h>

/* Fill a pwent structure from various other information */

static void winbindd_fill_pwent(struct winbindd_pw *pw, char *username,
                                uid_t unix_uid, gid_t unix_gid, 
                                SAM_USERINFO_CTR *user_info)
{
    fstring temp;

    /* Fill in uid/gid */

    pw->pw_uid = unix_uid;
    pw->pw_gid = unix_gid;

    /* More complicated stuff */

    strncpy(pw->pw_name, username, sizeof(pw->pw_name) - 1);

    unistr2_to_ascii(temp, &user_info->info.id21->uni_full_name, 
                     sizeof(temp) - 1);
    strncpy(pw->pw_gecos, temp, sizeof(pw->pw_gecos) - 1);

    unistr2_to_ascii(temp, &user_info->info.id21->uni_dir_drive, 
                     sizeof(temp));
    strncpy(pw->pw_dir, temp, sizeof(pw->pw_dir) - 1);

    strncpy(pw->pw_shell, "/dev/null", sizeof(pw->pw_shell) - 1);
}

/* Return a password structure from a username */

void winbindd_getpwnam_from_user(DOM_SID *domain_sid, char *domain_name,
                                 struct winbindd_request *request,
                                 struct winbindd_response *response)
{
    uint32 name_type, user_rid;
    uid_t unix_uid;
    gid_t unix_gid;
    SAM_USERINFO_CTR user_info;
    DOM_SID user_sid, group_sid, temp;
    fstring name_domain, name_user, temp_name;
    BOOL res;
    
    /* Look for user domain name */

    fstrcpy(temp_name, request->data.username);
    fstrcpy(name_domain, strtok(temp_name, "/"));
    fstrcpy(name_user, strtok(NULL, ""));

    if (!((strcmp(name_domain, domain_name) == 0) ||
          (strcmp(name_domain, "BUILTIN") == 0))) {
        DEBUG(1, ("user '%s' not builtin or in current domain\n",
                  request->data.username));
        return;
    }

    /* Get rid and name type from name */
    
    if (!winbind_lookup_by_name(SERVER, domain_sid, name_user, &user_sid, 
                                &name_type)) {
        DEBUG(1, ("user '%s' does not exist\n", name_user));
        return;
    }
    
#if 0

    /* Name type seems to return garbage )-: */

    if (name_type != SID_NAME_USER) {
        DEBUG(1, ("name '%s' is not a user name: %d\n", name_user, name_type));
        return;
    }

#endif

    /* Get some user info */
    
    sid_copy(&temp, &user_sid);
    sid_split_rid(&temp, &user_rid);

    if (!winbind_lookup_userinfo(SERVER, domain_sid, user_rid, &user_info)) {
        DEBUG(1, ("error getting user info for user '%s'\n", name_user));
        return;
    }
    
    /* Try and resolve uid and gid numbers for the name */

    sid_copy(&user_sid, domain_sid);
    sid_copy(&group_sid, domain_sid);

    sid_append_rid(&user_sid, user_info.info.id21->user_rid);
    sid_append_rid(&group_sid, user_info.info.id21->group_rid);

    res = winbindd_surs_sam_sid_to_unixid(&user_sid, request->data.username,
                                          RID_TYPE_USER, &unix_uid);

    if (!res) {
        DEBUG(1, ("error sursing unix uid for sid\n"));
    } else {

        res = res ? (winbindd_surs_sam_sid_to_unixid(&group_sid, NULL,
                                                     RID_TYPE_ALIAS, 
                                                     &unix_gid) ||
                     winbindd_surs_sam_sid_to_unixid(&group_sid, NULL,
                                                     RID_TYPE_GROUP, 
                                                     &unix_gid)) : False;
        if (!res) {
            DEBUG(1, ("error sursing unix gid for sid\n"));
        } else {
            
            /* Fill in password structure */
            
            winbindd_fill_pwent(&response->data.pw, request->data.username, 
                                unix_uid, unix_gid, &user_info);
            
            response->result = WINBINDD_OK;
        }
    }

    /* Free user info */

    free_samr_userinfo_ctr(&user_info);
}       

/* Return a password structure given a uid number */

void winbindd_getpwnam_from_uid(DOM_SID *domain_sid,
                                struct winbindd_request *request,
                                struct winbindd_response *response)
{
    DOM_SID temp, domain_user_sid;
    uint32 user_rid;
    fstring username;
    enum SID_NAME_USE name_type;
    SAM_USERINFO_CTR user_info;
    uid_t unix_uid;
    gid_t unix_gid;
    BOOL res;

    /* Get sid from uid */

    if (!winbindd_surs_unixid_to_sam_sid(request->data.uid, RID_TYPE_USER,
                                         &domain_user_sid, False)) {
        DEBUG(1, ("Could not convert uid %d to domain sid\n",
                  request->data.uid));
        return;
    }
    
    /* Get name and name type from rid */

    if (!winbind_lookup_by_sid(SERVER, domain_sid, &domain_user_sid,
                               username, &name_type)) {
        fstring temp2;

        sid_to_string(temp2, &domain_user_sid);
        DEBUG(1, ("Could not lookup sid %s\n", temp2));
        return;
    }

#if 0

    /* Name type seems to return garbage )-: */

    if (name_type != SID_NAME_USER) {
        DEBUG(1, ("name '%s' is not a user name: %d\n", username, name_type));
        return;
    }

#endif

    /* Get some user info */
    
    sid_copy(&temp, &domain_user_sid);
    sid_split_rid(&temp, &user_rid);

    if (!winbind_lookup_userinfo(SERVER, domain_sid, user_rid, &user_info)) {
        DEBUG(1, ("error getting user info for user '%s'\n",
                request->data.username));
        return;
    }

    res = winbindd_surs_sam_sid_to_unixid(&domain_user_sid, username,
                                          RID_TYPE_USER, &unix_uid);

    if (!res) {
        DEBUG(1, ("error sursing unix uid for sid\n"));
    }

    /* ??? Should be domain_group-sid??? */

    res = res ? (winbindd_surs_sam_sid_to_unixid(&domain_user_sid, NULL,
                                                 RID_TYPE_ALIAS, &unix_gid) ||
                 winbindd_surs_sam_sid_to_unixid(&domain_user_sid, NULL,
                                                 RID_TYPE_GROUP, &unix_gid))
        : False;

    /* Fill in password structure */

    if (!res) {
        DEBUG(1, ("error sursing unix gid for sid\n"));
    } else {

        winbindd_fill_pwent(&response->data.pw, username, unix_uid, 
                            unix_gid, &user_info);

        response->result = WINBINDD_OK;
    }

    /* Free user info */

    free_samr_userinfo_ctr(&user_info);
}

/* Static data for set/get/endpwent calls.  This is not supposed to be
   called in a re-entrant fashion but I don't believe it yet. */

struct winbindd_enum_pwent {
    POLICY_HND sam_handle, sam_dom_handle;
    struct acct_info *sam_entries;
    uint32 index, num_sam_entries;
    BOOL got_sam_entries;
};

static struct winbindd_enum_pwent *enum_pwent = NULL;

void winbindd_setpwent(DOM_SID *domain_sid,
                       struct winbindd_request *request,
                       struct winbindd_response *response)
{
    BOOL res;

    enum_pwent = (struct winbindd_enum_pwent *)malloc(sizeof(*enum_pwent));
    response->result = WINBINDD_ERROR;

    if (enum_pwent != NULL) {

        memset(enum_pwent, 0, sizeof(*enum_pwent));

        /* Connect to samr pipe */

        res = samr_connect(SERVER, 0x02000000, &enum_pwent->sam_handle);

        /* Open handles to domain and builtin users */

        res = res ? samr_open_domain(&enum_pwent->sam_handle, 0x304, 
                                     domain_sid, 
                                     &enum_pwent->sam_dom_handle) : False;

        if (res) {
            response->result = WINBINDD_OK;
        }
    }
}

void winbindd_endpwent(struct winbindd_request *request,
                       struct winbindd_response *response)
{
    /* Free handles and stuff */

    if (enum_pwent != NULL) {

        /* Close handles */

        samr_close(&enum_pwent->sam_dom_handle);
        samr_close(&enum_pwent->sam_handle);

        /* Free structure */

        free(enum_pwent);
        enum_pwent = NULL;
    }

    response->result = WINBINDD_OK;
}

void winbindd_getpwent(DOM_SID *domain_sid, char *domain_name,
                       struct winbindd_request *request,
                       struct winbindd_response *response)
{
    /* Must have called setpwent() beforehand */

    response->result = WINBINDD_ERROR;

    if (enum_pwent != NULL) {
        
        /* Get list of entries if we haven't already got them */

        if (!enum_pwent->got_sam_entries) {
            uint32 status, start_ndx = 0;

            do {
                status =
                    samr_enum_dom_users(&enum_pwent->sam_dom_handle,
                                        &start_ndx, 0, 0, 0x10000,
                                        &enum_pwent->sam_entries,
                                        &enum_pwent->num_sam_entries);
            } while (status == STATUS_MORE_ENTRIES);

            enum_pwent->got_sam_entries = 1;
        }

        /* Send back a user */

        while (enum_pwent->index < enum_pwent->num_sam_entries) {
            fstring domain_user_name;
            char *user_name = (enum_pwent->sam_entries)
                [enum_pwent->index].acct_name; 

            /* Convert into a getpwnam_from_user request */

            fstrcpy(domain_user_name, domain_name);
            fstrcat(domain_user_name, "/");
            fstrcat(domain_user_name, user_name);

            fstrcpy(request->data.username, domain_user_name);
            winbindd_getpwnam_from_user(domain_sid, domain_name, request, 
                                        response);
            enum_pwent->index++;

            /* Break out of loop if it actually worked */

            if (response->result == WINBINDD_OK) {
                break;
            }

            DEBUG(1, ("could not getpwnam_from_user for username %s\n",
                      user_name));
        }
    }
}

/*
Local variables:
compile-command: "make -C ~/work/nss-ntdom/samba-tng/source nsswitch"
end:
*/
