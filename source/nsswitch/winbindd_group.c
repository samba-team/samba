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

/* Fill a grent structure from various other information */

static void winbindd_fill_grent(struct winbindd_gr *gr, char *gr_name,
                                gid_t unix_gid)
{
    /* Fill in uid/gid */

    gr->gr_gid = unix_gid;

    /* More complicated stuff */

    strncpy(gr->gr_name, gr_name, sizeof(gr->gr_name) - 1);
    strncpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd) - 1);
}

/* Fill in group membership */

static void winbindd_fill_grent_mem(char *server_name, DOM_SID *domain_sid, 
                                    char *domain_name, uint32 group_rid, 
                                    struct winbindd_gr *gr)
{
    int res;
    uint32 num_names = 0;
    DOM_SID **sids = NULL;
    uint32 *name_types = NULL;
    char **names;
    uint32 *rid_mem;
    
    res = winbind_lookup_groupmem(SERVER, domain_sid, group_rid, 
                                  &num_names, &rid_mem, &names, 
                                  &name_types);
    
    if (!res) {
        res = winbind_lookup_aliasmem(SERVER, domain_sid,
                                      group_rid, &num_names,
                                      &sids, &names, 
                                      &name_types);
    }
    
    /* Map each user to UNIX equivalent and append to group list */
    
    gr->num_gr_mem = 0;

    if (res) {
        fstring groupmem_list, temp_name;
        int i;
        
        fstrcpy(groupmem_list, "");
        
        for (i = 0; i < num_names; i++) {
            struct winbindd_request subsubrequest;
            struct winbindd_response subsubresponse;
            
            DEBUG(0, ("** trying name '%s'\n", names[i]));
            
            subsubrequest.cmd = WINBINDD_GETPWNAM_FROM_USER;
            fstrcpy(temp_name, domain_name);
            fstrcat(temp_name, "/");
            fstrcat(temp_name, names[i]);
            fstrcpy(subsubrequest.data.username, temp_name);
            winbindd_getpwnam_from_user(domain_sid, domain_name,
                                        &subsubrequest,
                                        &subsubresponse);
            
            if (subsubresponse.result == WINBINDD_OK) {
                
                /* Add to group membership list */
                
                fstrcat(groupmem_list, subsubresponse.data.pw.pw_name);
                fstrcat(groupmem_list, ",");

                gr->num_gr_mem++;
            }
        }

        fstrcpy(gr->gr_mem, groupmem_list);
    }
}

/* Return a group structure from a group name */

void winbindd_getgrnam_from_group(DOM_SID *domain_sid, char *domain_name,
                                  struct winbindd_request *request,
                                  struct winbindd_response *response)
{
    DOM_SID domain_group_sid;
    uint32 name_type;
    gid_t unix_gid;
    fstring name_domain, name_group, temp_name;

    /* Look for group domain name */

    fstrcpy(temp_name, request->data.groupname);
    fstrcpy(name_domain, strtok(temp_name, "/"));
    fstrcpy(name_group, strtok(NULL, ""));

    if (!((strcmp(name_domain, domain_name) == 0) ||
          (strcmp(name_domain, "BUILTIN") == 0))) {
        DEBUG(1, ("group '%s' not builtin or in current domain\n",
                  request->data.groupname));
        return;
    }

    /* Get rid and name type from NT server */
        
    if (!winbind_lookup_by_name(SERVER, domain_sid, name_group, 
                                &domain_group_sid, &name_type)) {
        DEBUG(1, ("name %s does not exist\n", request->data.groupname));
        return;
    }
    
#if 0

    /* Name type seems to return garbage )-: */

    if ((name_type != SID_NAME_ALIAS) && (name_type != SID_NAME_DOM_GRP)) {
        DEBUG(1, ("name '%s' is not a local or domain group: %d\n",
                  request->data.groupname, name_type));
        return;
    }

#endif

    /* Fill in group structure */

    if (!(winbindd_surs_sam_sid_to_unixid(&domain_group_sid, 
                                          request->data.groupname,
                                          RID_TYPE_ALIAS, &unix_gid) ||
          winbindd_surs_sam_sid_to_unixid(&domain_group_sid, 
                                          request->data.groupname,
                                          RID_TYPE_GROUP, &unix_gid))) {
        DEBUG(1, ("error sursing unix gid for sid\n"));
    } else {
        DOM_SID temp;
        uint32 group_rid;

        DEBUG(1, ("returning gid %d\n", unix_gid));

        winbindd_fill_grent(&response->data.gr, request->data.groupname, 
                            unix_gid);

        sid_copy(&temp, &domain_group_sid);
        sid_split_rid(&temp, &group_rid);

        winbindd_fill_grent_mem(SERVER, domain_sid, domain_name,
                                group_rid, &response->data.gr);
       
        response->result = WINBINDD_OK;
    }
}

/* Return a group structure from a gid number */

void winbindd_getgrnam_from_gid(DOM_SID *domain_sid, char *domain_name,
                                struct winbindd_request *request,
                                struct winbindd_response *response)
{
    DOM_SID domain_group_sid, temp;
    uint32 group_rid;
    uint32 name_type;
    fstring group_name;
    GROUP_INFO_CTR info;

    /* Get sid from gid */

    if (!(winbindd_surs_unixid_to_sam_sid(request->data.gid, RID_TYPE_ALIAS,
                                          &domain_group_sid, False) ||
          winbindd_surs_unixid_to_sam_sid(request->data.gid, RID_TYPE_GROUP,
                                          &domain_group_sid, False))) {
        DEBUG(1, ("Could not convert gid %d to domain or local sid\n",
                  request->data.gid));
        return;
    }

    /* Get name and name type from sid */

    if (!winbind_lookup_by_sid(SERVER, domain_sid, &domain_group_sid, 
                               group_name, &name_type)) {
        DEBUG(1, ("Could not lookup sid\n"));
        return;
    }

#if 0

    /* Name type seems to return garbage )-: */

    if (!((name_type == SID_NAME_ALIAS) ||
          (name_type == SID_NAME_DOM_GRP))) {
        DEBUG(1, ("name '%s' is not a local or domain group: %d\n", 
                  group_name, name_type));
        return;
    }

#endif

    /* Get some group info */

    sid_copy(&temp, &domain_group_sid);
    sid_split_rid(&temp, &group_rid);

    if (!winbind_lookup_groupinfo(SERVER, domain_sid, group_rid, &info)) {
        DEBUG(1, ("Could not lookup group info\n"));
        return;
    }

    unistr2_to_ascii(group_name, &info.group.info1.uni_acct_name, 
                     sizeof(group_name) - 1);

    DEBUG(1, ("returning group name '%s'\n", group_name));

    /* Fill in group structure */

    winbindd_fill_grent(&response->data.gr, group_name, request->data.gid);
    winbindd_fill_grent_mem(SERVER, domain_sid, domain_name, group_rid,
                            &response->data.gr);

    response->result = WINBINDD_OK;
}

/* Static data for set/get/endpwent calls.  This is not supposed to be
   called in a re-entrant fashion but I don't believe it yet. */

struct winbindd_enum_grent {
    POLICY_HND sam_handle, sam_dom_handle, sam_blt_handle;
    struct acct_info *sam_entries;
    uint32 num_sam_entries, index;
    BOOL got_sam_entries;
};

static struct winbindd_enum_grent *enum_grent = NULL;

void winbindd_setgrent(DOM_SID *domain_sid,
                       struct winbindd_request *request,
                       struct winbindd_response *response)
{
    DOM_SID sid_1_5_32;
    BOOL res;

    enum_grent = (struct winbindd_enum_grent *)malloc(sizeof(*enum_grent));
    response->result = WINBINDD_ERROR;

    if (enum_grent != NULL) {

        memset(enum_grent, 0, sizeof(*enum_grent));

        /* Connect to samr pipe */

        res = samr_connect(SERVER, 0x02000000, &enum_grent->sam_handle);

        /* Open handles to domain and builtin users */

        res = res ? samr_open_domain(&enum_grent->sam_handle, 0x304, 
                                     domain_sid, 
                                     &enum_grent->sam_dom_handle) : False;

        string_to_sid(&sid_1_5_32, "S-1-5-32");

        res = res ? samr_open_domain(&enum_grent->sam_handle, 0x304,
                                     &sid_1_5_32,
                                     &enum_grent->sam_blt_handle) : False;
                                     

        DEBUG(0, ("*********** setgrent: sam_blt_handle = 0x%08x\n",
                  &enum_grent->sam_blt_handle));

        if (res) {
            response->result = WINBINDD_OK;
        }
    }
}

void winbindd_endgrent(struct winbindd_request *request,
                       struct winbindd_response *response)
{
    /* Free handles and stuff */

    if (enum_grent != NULL) {

        /* Close handles */

        DEBUG(0, ("************ endgrent: sam_blt_handle = 0x%08x\n", 
                  &enum_grent->sam_blt_handle));

        samr_close(&enum_grent->sam_blt_handle);
        samr_close(&enum_grent->sam_dom_handle);
        samr_close(&enum_grent->sam_handle);

        /* Free structure */

        free(enum_grent);
        enum_grent = NULL;
    }

    response->result = WINBINDD_OK;
}

void winbindd_getgrent(DOM_SID *domain_sid, char *domain_name,
                       struct winbindd_request *request,
                       struct winbindd_response *response)
{
    /* Must have called setgrent() beforehand */

    response->result = WINBINDD_ERROR;

    if (enum_grent != NULL) {
        
        /* Get list of entries if we haven't already got them */

        if (!enum_grent->got_sam_entries) {
            uint32 status, start_ndx = 0;

            /* Get domain groups - do we need to query for domain
               groups using builtin handle? */

            do {

                status =
                    samr_enum_dom_groups(&enum_grent->sam_dom_handle,
                                         &start_ndx, 0x10000,
                                         &enum_grent->sam_entries,
                                         &enum_grent->num_sam_entries);
            } while (status == STATUS_MORE_ENTRIES);

            do {

                status =
                    samr_enum_dom_groups(&enum_grent->sam_blt_handle,
                                         &start_ndx, 0x10000,
                                         &enum_grent->sam_entries,
                                         &enum_grent->num_sam_entries);
            } while (status == STATUS_MORE_ENTRIES);

            /* Get local groups - do we need to query for local groups
               using domain handle? */

            do {

                status =
                    samr_enum_dom_aliases(&enum_grent->sam_dom_handle,
                                          &start_ndx, 0x10000,
                                          &enum_grent->sam_entries,
                                          &enum_grent->num_sam_entries);
            } while (status == STATUS_MORE_ENTRIES);

            do {

                status =
                    samr_enum_dom_aliases(&enum_grent->sam_blt_handle,
                                          &start_ndx, 0x10000,
                                          &enum_grent->sam_entries,
                                          &enum_grent->num_sam_entries);
            } while (status == STATUS_MORE_ENTRIES);

            enum_grent->got_sam_entries = 1;
        }

        /* Send back a group */

        while (enum_grent->index < enum_grent->num_sam_entries) {
            struct winbindd_request subrequest;
            uint32 group_rid = (enum_grent->sam_entries)
                [enum_grent->index].rid;
            fstring temp_name;
            char *group_name = (enum_grent->sam_entries)
                [enum_grent->index].acct_name; 

            /* Convert into a getpwnam_from_group request */

            subrequest.cmd = WINBINDD_GETGRNAM_FROM_GROUP;
            fstrcpy(temp_name, domain_name);
            fstrcat(temp_name, "/");
            fstrcat(temp_name, group_name);
            fstrcpy(subrequest.data.groupname, temp_name);
            winbindd_getgrnam_from_group(domain_sid, domain_name,
                                         &subrequest, response);
            enum_grent->index++;

            /* Break out of loop if it actually worked */

            if (response->result == WINBINDD_OK) {
                winbindd_fill_grent_mem(SERVER, domain_sid, domain_name,
                                        group_rid, &response->data.gr);
                response->result = WINBINDD_OK;
                break;
            }
        }
    }
}

/*
Local variables:
compile-command: "make -C ~/work/nss-ntdom/samba-tng/source nsswitch"
end:
*/
