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

/* Return a group structure from a group name */

void winbindd_getgrnam_from_group(DOM_SID *domain_sid,
                                  struct winbindd_request *request,
                                  struct winbindd_response *response)
{
    uint32 rid, type; 
    int i;

    /* Check for well known group names */

    i = 0;

    while(wkrid_namemap[i].rid > 0) {

        if ((strcmp(wkrid_namemap[i].name, request->data.groupname) == 0) &&
            ((wkrid_namemap[i].type == SID_NAME_DOM_GRP) ||
             (wkrid_namemap[i].type == SID_NAME_ALIAS))) {

            struct winbindd_gr *gr = &response->data.gr;

            DEBUG(3, ("found well known rid 0x%x for group\n",
                      wkrid_namemap[i].rid));
            
            /* Fill in grent structure */

            strncpy(gr->gr_name, request->data.groupname, 
                    sizeof(gr->gr_passwd) - 1);
            strncpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd) - 1);

            gr->gr_gid = wkrid_namemap[i].rid + WINBINDD_GID_BASE;
            /* gr->gr_mem[0] = 0; */ /* ??? */

            /* Return OK */

            response->result = WINBINDD_OK;
            return;
        }

        i++;
    }

    /* Get rid and name type from NT server */
        
    if (!winbind_lookup_by_name(SERVER, domain_sid, 
                                request->data.groupname, &rid, &type)) {
        DEBUG(3, ("name %s does not exist\n", request->data.groupname));
        return;
    }
    
    /* Get group info */
    
    if (!winbind_lookup_groupinfo(SERVER, domain_sid, rid, NULL)) {
        DEBUG(1, ("error getting group info\n"));
        return;
    }
    
    if ((type == SID_NAME_DOM_GRP) ||
        (type == SID_NAME_ALIAS)) {
        struct winbindd_gr *gr = &response->data.gr;
        fstring temp;
        
        /* Fill in group entry */
    }
}

/* Return a group structure from a gid number */

void winbindd_getgrnam_from_gid(DOM_SID *domain_sid,
                                struct winbindd_request *request,
                                struct winbindd_response *response)
{
    /* Translate well known rids */

    if ((request->data.gid > WINBINDD_GID_BASE) &&
        ((request->data.gid - WINBINDD_GID_BASE) < 1000)) {

        uint32 rid = request->data.gid - WINBINDD_GID_BASE;
        int i = 0;

        /* Search through list of well known rids */

        while(wkrid_namemap[i].rid > 0) {

            if (wkrid_namemap[i].rid == rid) {
                struct winbindd_gr *gr = &response->data.gr;

                /* Fill in grent structure */

                strncpy(gr->gr_name, wkrid_namemap[i].name, 
                        sizeof(gr->gr_name) - 1);
                strncpy(gr->gr_passwd, "x", sizeof(gr->gr_passwd) - 1);

                gr->gr_gid = request->data.gid;
                /* gr->gr_mem[0] = 0; */ /* ??? */

                /* Return OK */

                response->result = WINBINDD_OK;
                break;
            }
            i++;
        }

    } else {

        /* Look up rid in surs database */

        DEBUG(3, ("lookup gid in surs database\n"));
    }
}
