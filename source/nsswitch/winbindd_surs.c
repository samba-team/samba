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
#include "sids.h"
#include "lib/surs.h"

/* Wrapper around "standard" surs sid to unixid function */

BOOL winbindd_surs_sam_sid_to_unixid(struct winbindd_domain *domain,
                                     DOM_SID *sid, 
                                     enum SID_NAME_USE name_type,
                                     POSIX_ID *id)
{
    DOM_SID tmp_sid;
    fstring temp;
    uint32 rid;

    sid_copy(&tmp_sid, sid);
    sid_split_rid(&tmp_sid, &rid);

    sid_to_string(temp, &tmp_sid);

    if (sid_equal(&domain->sid, &tmp_sid)) {

        /* Check users */

        if (name_type == SID_NAME_USER) {

            if ((domain->uid_low + rid) > domain->uid_high) {
                DEBUG(0, ("uid range (%d-%d) too small for rid %d\n", 
                          domain->uid_low, domain->uid_high, rid));
                return False;
            }
            
            id->id = domain->uid_low + rid;
            id->type = SURS_POSIX_UID_AS_USR;
            
            return True;
        }
        
        /* Check domain and local groups */
        
        if ((name_type == SID_NAME_DOM_GRP) || 
            (name_type == SID_NAME_ALIAS)) {
            
            if ((domain->gid_low + rid) > domain->gid_high) {
                DEBUG(0, ("gid range (%d-%d) too small for rid %d\n", 
                          domain->gid_low, domain->gid_high, rid));
                return False;
            }
            
            id->id = domain->gid_low + rid;
            id->type = SURS_POSIX_GID_AS_GRP;
            
            return True;
        }
    }

    return False;
}

/* Wrapper around "standard" surs unixd to sid function */

BOOL winbindd_surs_unixid_to_sam_sid(struct winbindd_domain *domain,
                                     POSIX_ID *id, DOM_SID *sid)
{
    /* Process user id */

    if (id->type == SURS_POSIX_UID_AS_USR) {

        if ((id->id >= domain->uid_low) && (id->id <= domain->uid_high)) {

            /* uid falls within range for this domain */
            
            if (sid != NULL) {
                sid_copy(sid, &domain->sid);
                sid_append_rid(sid, id->id - domain->uid_low);
            }
            
            return True;
        }
    }
    
    /* Process group id */
    
    if ((id->type == SURS_POSIX_GID_AS_GRP) || 
        (id->type == SURS_POSIX_GID_AS_ALS)) {
        
        if ((id->id >= domain->gid_low) && (id->id <= domain->gid_high)) {
            
            /* gid falls within range for this domain */
            
            if (sid != NULL) {
                sid_copy(sid, &domain->sid);
                sid_append_rid(sid, id->id - domain->gid_low);
            }
            
            return True;
        }
    }

    return False;
}
