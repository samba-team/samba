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

/* Fill a grent structure from various other information */

static void winbindd_fill_grent(struct winbindd_gr *gr)
{
    /* Fill in uid/gid */

    gr->gr_gid = 0;

    /* More complicated stuff */

    strncpy(gr->gr_name, "spamgrp", sizeof(gr->gr_name) - 1);
    strncpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd) - 1);
    strncpy(gr->gr_mem, "", sizeof(gr->gr_mem) - 1); /* ??? */
}

/* Return a group structure from a group name */

void winbindd_getgrnam_from_group(DOM_SID *domain_sid,
                                  struct winbindd_request *request,
                                  struct winbindd_response *response)
{
    DOM_SID domain_group_sid, temp;
    uint32 name_type, group_rid;
    gid_t unix_gid;
    GROUP_INFO_CTR info;

    /* Get rid and name type from NT server */
        
    if (!winbind_lookup_by_name(SERVER, domain_sid, 
                                request->data.groupname, &domain_group_sid, 
                                &name_type)) {
        DEBUG(1, ("name %s does not exist\n", request->data.groupname));
        return;
    }
    
    if ((name_type != SID_NAME_ALIAS) && (name_type != SID_NAME_DOM_GRP)) {
        DEBUG(1, ("name '%s' is not a local or domain group\n",
                  request->data.groupname));
        return;
    }

    /* Get group info */
    
    sid_copy(&temp, &domain_group_sid);
    sid_split_rid(&temp, &group_rid);

    if (!winbind_lookup_groupinfo(SERVER, domain_sid, group_rid, &info)) {
        DEBUG(1, ("Could not lookup group info\n"));
        return;
    }

    {
        fstring str;

        DEBUG(0, ("unknown_1 = %d\n", info.group.info1.unknown_1));
        DEBUG(0, ("num_members = %d\n", info.group.info1.num_members));
        
        unistr2_to_ascii(str, &info.group.info1.uni_acct_name, 
                         sizeof(str) - 1);
        DEBUG(0, ("acct_name = %s\n", str));

        unistr2_to_ascii(str, &info.group.info1.uni_acct_desc, 
                         sizeof(str) - 1);
        DEBUG(0, ("acct_desc = %s\n", str));
    }

    /* Fill in group structure */

    if (!(winbindd_surs_sam_sid_to_unixid(&domain_group_sid, SID_NAME_ALIAS, 
                                          &unix_gid) ||
          winbindd_surs_sam_sid_to_unixid(&domain_group_sid, SID_NAME_DOM_GRP, 
                                          &unix_gid))) {
        DEBUG(1, ("error sursing unix gid for sid\n"));
    } else {

        winbindd_fill_grent(&response->data.gr);
        response->result = WINBINDD_OK;
    }
}

/* Return a group structure from a gid number */

void winbindd_getgrnam_from_gid(DOM_SID *domain_sid,
                                struct winbindd_request *request,
                                struct winbindd_response *response)
{
    DOM_SID domain_group_sid, temp;
    uint32 group_rid;
    uint32 name_type;
    fstring group_name;
    GROUP_INFO_CTR info;

    /* Get sid from gid */

    if (!(winbindd_surs_unixid_to_sam_sid(request->data.gid, SID_NAME_ALIAS,
                                          &domain_group_sid, False) ||
          winbindd_surs_unixid_to_sam_sid(request->data.gid, SID_NAME_DOM_GRP,
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

    if (!((name_type == SID_NAME_ALIAS) ||
          (name_type == SID_NAME_DOM_GRP))) {
        DEBUG(1, ("name '%s' is not a local or domain group\n",
                  request->data.groupname));
        return;
    }

    /* Get some group info */

    sid_copy(&temp, &domain_group_sid);
    sid_split_rid(&temp, &group_rid);

    if (!winbind_lookup_groupinfo(SERVER, domain_sid, group_rid, &info)) {
        DEBUG(1, ("Could not lookup group info\n"));
        return;
    }

    {
        fstring str;

        DEBUG(0, ("unknown_1 = %d\n", info.group.info1.unknown_1));
        DEBUG(0, ("num_members = %d\n", info.group.info1.num_members));
        
        unistr2_to_ascii(str, &info.group.info1.uni_acct_name, 
                         sizeof(str) - 1);
        DEBUG(0, ("acct_name = %s\n", str));

        unistr2_to_ascii(str, &info.group.info1.uni_acct_desc, 
                         sizeof(str) - 1);
        DEBUG(0, ("acct_desc = %s\n", str));
    }

    /* Fill in group structure */

    winbindd_fill_grent(&response->data.gr);
    response->result = WINBINDD_OK;
}
