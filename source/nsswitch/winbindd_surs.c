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

/* Initialise winbindd_surs database */

BOOL winbindd_surs_init(void)
{
    fstring value;
    char *p;

    /* Parse list of domains and uid ranges from "winbind uid" parameter */

    fstrcpy(value, lp_winbind_uid());

    for (p = strtok(value, LIST_SEP); p; p = strtok(NULL, LIST_SEP)) {
        struct winbindd_domain_uid *uid;
        struct winbindd_domain *domain;
        fstring domain_name;

        /* Create new domain uid entry */

        if ((uid = (struct winbindd_domain_uid *) 
             malloc(sizeof(*uid))) == NULL) {

            return False;
        }

        ZERO_STRUCTP(uid);

        /* Store info */

        if ((sscanf(p, "%[^/]/%u-%u", domain_name, &uid->uid_low,
                    &uid->uid_high) != 3) && 
            (sscanf(p, "%[^/]/%u", domain_name, &uid->uid_low) != 2)) {

            DEBUG(0, ("surs_init(): winbid uid parameter invalid\n"));
            free(uid);
            return False;
        }

        if (uid->uid_high == 0) {
            uid->uid_high = -1;
        }

        if ((domain = find_domain_from_name(domain_name)) == NULL) {
            fstring sid_str;

            /* Create new domain entry */

            if ((domain = (struct winbindd_domain *)malloc(sizeof(*domain)))
                == NULL) {
                return False;
            }
            
            fstrcpy(domain->domain_name, domain_name);

            /* Lookup domain sid */
        
            if (strequal(domain_name, "BUILTIN")) {
                sid_copy(&domain->domain_sid, global_sid_builtin);
                lookup_domain_sid(lp_workgroup(), NULL, 
                                  domain->domain_controller);
            } else if (!lookup_domain_sid(domain->domain_name, 
                                          &domain->domain_sid, 
                                          domain->domain_controller)) {
                DEBUG(0, ("surs_init(): could not find domain sid for "
                          "domain %s\n", domain->domain_name));
                return False;
            }

            sid_to_string(sid_str, &domain->domain_sid);
            DEBUG(0, ("Found sid %s for domain %s, controller %s\n",
                      sid_str, domain->domain_name, 
                      domain->domain_controller));

            DLIST_ADD(domain_list, domain);
        }

        uid->domain = domain;

        /* Add to list */

        DLIST_ADD(domain_uid_list, uid);
    }
    
    /* Parse list of domains and gid ranges from "winbind gid" parameter */

    fstrcpy(value, lp_winbind_gid());

    for (p = strtok(value, LIST_SEP); p; p = strtok(NULL, LIST_SEP)) {
        struct winbindd_domain_gid *gid;
        struct winbindd_domain *domain;
        fstring domain_name;

        /* Create new domain entry */

        if ((gid = (struct winbindd_domain_gid *)
             malloc(sizeof(*gid))) == NULL) {

            return False;
        }

        ZERO_STRUCTP(gid);

        /* Store info */

        if ((sscanf(p, "%[^/]/%u-%u", domain_name, &gid->gid_low,
                    &gid->gid_high) != 3) &&
            (sscanf(p, "%[^/]/%u", domain_name, &gid->gid_low) != 2)) {
            DEBUG(0, ("surs_init(): winbid gid parameter invalid\n"));
            free(gid);
            return False;
        }

        if (gid->gid_high == 0) {
            gid->gid_high = -1;
        }

        /* Lookup domain sid */

        if ((domain = find_domain_from_name(domain_name)) == NULL) {

            /* Create new domain entry */

            if ((domain = (struct winbindd_domain *)malloc(sizeof(*domain)))
                == NULL) {
                return False;
            }
            
            fstrcpy(domain->domain_name, domain_name);

            /* Lookup domain sid */
        
            if (strequal(domain_name, "BUILTIN")) {
                sid_copy(&domain->domain_sid, global_sid_builtin);
                lookup_domain_sid(lp_workgroup(), NULL, 
                                  domain->domain_controller);
            } else if (!lookup_domain_sid(domain->domain_name, 
                                          &domain->domain_sid, 
                                          domain->domain_controller)) {
                DEBUG(0, ("surs_init(): could not find domain sid for "
                          "domain %s\n", domain->domain_name));
                return False;
            }

            DLIST_ADD(domain_list, domain);
        }

        gid->domain = domain;

        /* Add to list */

        DLIST_ADD(domain_gid_list, gid);
    }

    return True;
}

/* Wrapper around "standard" surs sid to unixid function */

BOOL winbindd_surs_sam_sid_to_unixid(DOM_SID *sid, 
                                     enum SID_NAME_USE name_type,
                                     POSIX_ID *id)
{
    DOM_SID tmp_sid;
    fstring temp;
    uint32 rid;

    sid_copy(&tmp_sid, sid);
    sid_split_rid(&tmp_sid, &rid);

    sid_to_string(temp, &tmp_sid);

    /* User names */

    if (name_type == SID_NAME_USER) {
        struct winbindd_domain_uid *uid;

        for(uid = domain_uid_list; uid != NULL; uid = uid->next) {

            if (sid_equal(&uid->domain->domain_sid, &tmp_sid)) {

                if ((uid->uid_low + rid) > uid->uid_high) {
                    DEBUG(0, ("uid range to small for rid %d\n", rid));
                    return False;
                }

                id->id = uid->uid_low + rid;
                id->type = SURS_POSIX_UID_AS_USR;

                return True;
            }
        }
    }

    /* Domain groups */

    if ((name_type == SID_NAME_DOM_GRP) || (name_type == SID_NAME_ALIAS)) {
        struct winbindd_domain_gid *gid;
        
        for(gid = domain_gid_list; gid != NULL; gid = gid->next) {

            if (sid_equal(&gid->domain->domain_sid, &tmp_sid)) {

                if ((gid->gid_low + rid) > gid->gid_high) {
                    DEBUG(0, ("gid range too small for rid %d\n", rid));
                    return False;
                }

                id->id = gid->gid_low + rid;
                id->type = SURS_POSIX_GID_AS_GRP;
                
                return True;
            }
        }
    }

    return False;
}

/* Wrapper around "standard" surs unixd to sid function */

BOOL winbindd_surs_unixid_to_sam_sid(POSIX_ID *id, DOM_SID *sid, BOOL create)
{
    /* Process user uid */

    if (id->type == SURS_POSIX_UID_AS_USR) {
        struct winbindd_domain_uid *uid;

        for(uid = domain_uid_list; uid != NULL; uid = uid->next) {
            if ((id->id >= uid->uid_low) && (id->id <= uid->uid_high)) {

                /* uid falls within range for this domain */

                if (sid != NULL) {
                    sid_copy(sid, &uid->domain->domain_sid);
                    sid_append_rid(sid, id->id - uid->uid_low);
                }

                return True;
            }
        }
    }

    /* Process group gid */

    if ((id->type == SURS_POSIX_GID_AS_GRP) ||
        (id->type == SURS_POSIX_GID_AS_ALS)) {
        
        struct winbindd_domain_gid *gid;

        for(gid = domain_gid_list; gid != NULL; gid = gid->next) {
            if ((id->id >= gid->gid_low) && (id->id <= gid->gid_high)) {

                /* gid falls within range for this domain */

                if (sid != NULL) {
                    sid_copy(sid, &gid->domain->domain_sid);
                    sid_append_rid(sid, id->id - gid->gid_low);
                }

                return True;
            }
        }
    }

    return False;
}
