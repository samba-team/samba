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

/* Return a password structure from a username */

void winbindd_getpwnam_from_user(DOM_SID *domain_sid,
                                 struct winbindd_request *request,
                                 struct winbindd_response *response)
{
    uint32 user_rid, user_rid_type;
    SAM_USER_INFO_21 user_info;
    int i;
    
    /* Check well known userids */

    i = 0;

    while(wkrid_namemap[i].rid > 0) {

        if ((strcmp(wkrid_namemap[i].name, request->data.groupname) == 0) &&
            (wkrid_namemap[i].type == SID_NAME_USER)) {
            
            struct winbindd_pw *pw = &response->data.pw;

            /* Fill in pwent structure */

            strncpy(pw->pw_name, wkrid_namemap[i].name, 
                    sizeof(pw->pw_name) - 1);
            strncpy(pw->pw_passwd, "x", sizeof(pw->pw_name) - 1);

            pw->pw_uid = wkrid_namemap[i].rid + WINBINDD_UID_BASE;
            pw->pw_gid = DOMAIN_GROUP_RID_USERS + WINBINDD_UID_BASE;

            /* Return OK */

            response->result = WINBINDD_OK;
            return;
        }

        i++;
    }    

    /* Get rid and name type from name */
    
    if (!winbind_lookup_by_name(SERVER, domain_sid, 
                                request->data.username, &user_rid, 
                                &user_rid_type)) {
        DEBUG(3, ("user '%s' does not exist\n", request->data.username));
        return;
    }
    
    /* Get some user info */
    
    if (!winbind_lookup_userinfo(SERVER, domain_sid, user_rid, &user_info)) {
        DEBUG(1, ("error getting user info for user '%s'\n",
                request->data.username));
        return;
    }
    
    if (user_rid_type == SID_NAME_USER) {
        struct winbindd_pw *pw = &response->data.pw;
        DOM_SID tmp_sid;
        fstring temp;
        
        /* Fill in name, passwd field */
        
        strncpy(pw->pw_name, request->data.username, sizeof(pw->pw_name) - 1);
        strncpy(pw->pw_passwd, "x", sizeof(pw->pw_name) - 1);
        
        /* Fill in uid and gid fields */

        sid_copy(&tmp_sid, domain_sid);
        sid_append_rid(&tmp_sid, user_rid);

        if (!sursalg_sam_sid_to_unixid(&tmp_sid, user_rid_type, 
                                       &pw->pw_uid)) {
            DEBUG(1, ("Could not convert user rid %d to unix uid\n", 
                      user_rid));
            return;
        }

        /* Fill in gid field */

        if (user_info.group_rid < 1000) {
            
            /* It's a well known rid */

            pw->pw_gid = user_info.group_rid + WINBINDD_GID_BASE;

        } else {

            /* Look up UNIX gid */

            sid_copy(&tmp_sid, domain_sid);
            sid_append_rid(&tmp_sid, user_info.group_rid);
            
            if (!sursalg_sam_sid_to_unixid(&tmp_sid, SID_NAME_DOM_GRP,
                                           &pw->pw_gid)) {
                DEBUG(1, ("Could not convert group rid %d to unix gid\n",
                          user_info.group_rid));
                return;
            }
        }
            
        /* Fill in name, gecos, shell fields */

        unistr2_to_ascii(temp, &user_info.uni_full_name, sizeof(temp));
        strncpy(pw->pw_gecos, temp, sizeof(pw->pw_gecos) - 1);
        
        unistr2_to_ascii(temp, &user_info.uni_dir_drive, sizeof(temp));
        strncpy(pw->pw_dir, temp, sizeof(pw->pw_dir) - 1);
        
        strncpy(pw->pw_shell, "/dev/null", sizeof(pw->pw_shell) - 1);
        
        /* Return OK */

        response->result = WINBINDD_OK;
    }
}       

/* Return a password structure given a uid number */

void winbindd_getpwnam_from_uid(DOM_SID *domain_sid,
                                struct winbindd_request *request,
                                struct winbindd_response *response)
{
    DOM_SID domain_user_sid;
    fstring user_name;
    enum SID_NAME_USE user_name_type;
    uint32 user_rid;
    SAM_USER_INFO_21 user_info;
    int i;

    /* Check well known userids */

    i = 0;

    while(wkrid_namemap[i].rid > 0) {

        if ((strcmp(wkrid_namemap[i].name, request->data.groupname) == 0) &&
            (wkrid_namemap[i].type == SID_NAME_USER)) {
            
            struct winbindd_pw *pw = &response->data.pw;

            /* Fill in pwent structure */

            strncpy(pw->pw_name, wkrid_namemap[i].name, 
                    sizeof(pw->pw_name) - 1);
            strncpy(pw->pw_passwd, "x", sizeof(pw->pw_name) - 1);

            pw->pw_uid = wkrid_namemap[i].rid + WINBINDD_UID_BASE;
            pw->pw_gid = DOMAIN_GROUP_RID_USERS + WINBINDD_UID_BASE;

            /* Return OK */

            response->result = WINBINDD_OK;
            return;
        }

        i++;
    }    

    /* Get rid from username */

    sid_copy(&domain_user_sid, domain_sid);

    if (!sursalg_unixid_to_sam_sid(request->data.uid, SID_NAME_USER,
                                   &domain_user_sid, False)) {
        DEBUG(1, ("Could not convert uid %d to domain sid\n",
                  request->data.uid));
        return;
    }
    
    if (!sid_split_rid(&domain_user_sid, &user_rid)) {
        DEBUG(1, ("Could not split rid from domain user sid\n"));
        return;
    }

    /* Get name and name type from rid */

    if (!winbind_lookup_by_rid(SERVER, &domain_user_sid, user_rid,
                               user_name, &user_name_type)) {
        DEBUG(1, ("Could not lookup rid %d\n", user_rid));
        return;
    }

    /* Get some user info */
    
    if (!winbind_lookup_userinfo(SERVER, domain_sid, user_rid, &user_info)) {
        DEBUG(1, ("error getting user info for user '%s'\n",
                request->data.username));
        return;
    }
    
}
