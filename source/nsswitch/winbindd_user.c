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

/* Fill a pwent structure from various other information */

static void winbindd_fill_pwent(struct winbindd_pw *pw, uid_t unix_uid, 
                                gid_t unix_gid, SAM_USERINFO_CTR *user_info)
{
    fstring temp;

    /* Fill in uid/gid */

    pw->pw_uid = unix_uid;
    pw->pw_gid = unix_gid;

    /* More complicated stuff */

    unistr2_to_ascii(temp, &user_info->info.id21->uni_full_name, 
                     sizeof(temp) - 1);
    strncpy(pw->pw_gecos, temp, sizeof(pw->pw_gecos) - 1);

    unistr2_to_ascii(temp, &user_info->info.id21->uni_dir_drive, 
                     sizeof(temp));
    strncpy(pw->pw_dir, temp, sizeof(pw->pw_dir) - 1);

    strncpy(pw->pw_shell, "/dev/null", sizeof(pw->pw_shell) - 1);
}

/* Return a password structure from a username */

void winbindd_getpwnam_from_user(DOM_SID *domain_sid,
                                 struct winbindd_request *request,
                                 struct winbindd_response *response)
{
    uint32 name_type, user_rid;
    uid_t unix_uid;
    gid_t unix_gid;
    SAM_USERINFO_CTR user_info;
    DOM_SID user_sid, group_sid, temp;
    BOOL res;
    
    /* Get rid and name type from name */
    
    if (!winbind_lookup_by_name(SERVER, domain_sid, 
                                request->data.username, &user_sid, 
                                &name_type)) {
        DEBUG(1, ("user '%s' does not exist\n", request->data.username));
        return;
    }
    
    if (name_type != SID_NAME_USER) {
        DEBUG(1, ("name '%s' is not a user name\n", request->data.username));
        return;
    }

    /* Get some user info */
    
    sid_copy(&temp, &user_sid);
    sid_split_rid(&temp, &user_rid);

    if (!winbind_lookup_userinfo(SERVER, domain_sid, user_rid, &user_info)) {
        DEBUG(1, ("error getting user info for user '%s'\n",
                request->data.username));
        return;
    }
    
    /* Try and resolve uid and gid numbers for the name */

    sid_copy(&user_sid, domain_sid);
    sid_copy(&group_sid, domain_sid);

    sid_append_rid(&user_sid, user_info.info.id21->user_rid);
    sid_append_rid(&group_sid, user_info.info.id21->group_rid);

    res = winbindd_surs_sam_sid_to_unixid(&user_sid, SID_NAME_USER, &unix_uid);

    if (!res) {
        DEBUG(1, ("error sursing unix uid for sid\n"));
    } else {

        res = res ? (winbindd_surs_sam_sid_to_unixid(&group_sid, 
                                                     SID_NAME_ALIAS, 
                                                     &unix_gid) ||
                     winbindd_surs_sam_sid_to_unixid(&group_sid, 
                                                     SID_NAME_DOM_GRP, 
                                                     &unix_gid)) : False;
        if (!res) {
            DEBUG(1, ("error sursing unix gid for sid\n"));
        } else {
            
            /* Fill in password structure */
            
            winbindd_fill_pwent(&response->data.pw, unix_uid, unix_gid, 
                                &user_info);
            
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
    DOM_SID domain_user_sid, temp;
    uint32 user_rid;
    fstring user_name;
    enum SID_NAME_USE name_type;
    SAM_USERINFO_CTR user_info;
    uid_t unix_uid;
    gid_t unix_gid;
    BOOL res;

    /* Get sid from uid */

    if (!winbindd_surs_unixid_to_sam_sid(request->data.uid, SID_NAME_USER,
                                         &domain_user_sid, False)) {
        DEBUG(1, ("Could not convert uid %d to domain sid\n",
                  request->data.uid));
        return;
    }
    
    /* Get name and name type from rid */

    if (!winbind_lookup_by_sid(SERVER, domain_sid, &domain_user_sid,
                               user_name, &name_type)) {
        DEBUG(1, ("Could not lookup sid\n"));
        return;
    }

    if (name_type != SID_NAME_USER) {
        DEBUG(1, ("name '%s' is not a user name\n", request->data.username));
        return;
    }

    /* Get some user info */
    
    sid_copy(&temp, &domain_user_sid);
    sid_split_rid(&temp, &user_rid);

    if (!winbind_lookup_userinfo(SERVER, domain_sid, user_rid, &user_info)) {
        DEBUG(1, ("error getting user info for user '%s'\n",
                request->data.username));
        return;
    }

    res = winbindd_surs_sam_sid_to_unixid(&domain_user_sid, SID_NAME_USER, 
                                          &unix_uid);

    if (!res) {
        DEBUG(1, ("error sursing unix uid for sid\n"));
    }

    res = res ? (winbindd_surs_sam_sid_to_unixid(&domain_user_sid, 
                                                 SID_NAME_ALIAS, &unix_gid) ||
                 winbindd_surs_sam_sid_to_unixid(&domain_user_sid, 
                                                 SID_NAME_DOM_GRP, &unix_gid))
        : False;

    /* Fill in password structure */

    if (!res) {
        DEBUG(1, ("error sursing unix gid for sid\n"));
    } else {

        winbindd_fill_pwent(&response->data.pw, unix_uid, unix_gid,
                            &user_info);

        response->result = WINBINDD_OK;
    }

    /* Free user info */

    free_samr_userinfo_ctr(&user_info);
}
