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

struct winbind_domain_uid *domain_uid_list = NULL;
struct winbind_domain_gid *domain_gid_list = NULL;
struct winbind_domain *domain_list = NULL;

int num_domain_uid = 0;
int num_domain_gid = 0;
int num_domain = 0;

/* Given a domain name, return the struct winbindd domain info for it */

struct winbind_domain *find_domain_from_name(char *domain_name)
{
    struct winbind_domain *tmp;

    /* Search through list */

    for (tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        if (strcmp(domain_name, tmp->domain_name) == 0) {
            return tmp;
        }
    }

    /* Not found */

    return NULL;
}

/* Given a domain name, return the domain sid and domain controller we
   found in winbindd_surs_init(). */

BOOL find_domain_sid_from_name(char *domain_name, DOM_SID *domain_sid, 
                               char *domain_controller)
{
    struct winbind_domain *tmp;

    /* Search through list */

    for(tmp = domain_list; tmp != NULL; tmp = tmp->next) {
        if (strcmp(domain_name, tmp->domain_name) == 0) {

            /* Copy domain sid */

            if (domain_sid != NULL) {
                sid_copy(domain_sid, &tmp->domain_sid);
            }
            
            /* Copy domain controller */

            if (domain_controller != NULL) {
                fstrcpy(domain_controller, tmp->domain_controller);
            }

            return True;
        }
    }

    /* Not found */

    return False;
}

/* Given a uid, return the domain sid and domain controller */

BOOL find_domain_sid_from_uid(uid_t uid, DOM_SID *domain_sid,
                              char *domain_name,
                              char *domain_controller)
{
    struct winbind_domain_uid *tmp;

    for(tmp = domain_uid_list; tmp != NULL; tmp = tmp->next) {
        if ((uid >= tmp->uid_low) && (uid <= tmp->uid_high) &&
            (tmp->domain != NULL)) {

            /* Copy domain sid */

            if (domain_sid != NULL) {
                sid_copy(domain_sid, &tmp->domain->domain_sid);
            }
            
            /* Copy domain controller */

            if (domain_controller != NULL) {
                fstrcpy(domain_controller, tmp->domain->domain_controller);
            }

            /* Copy domain name */

            if (domain_name != NULL) {
                fstrcpy(domain_name, tmp->domain->domain_name);
            }

            return True;
        }
    }

    /* Not found */

    return False;
}

/* Given a uid, return the domain sid and domain controller */

BOOL find_domain_sid_from_gid(gid_t gid, DOM_SID *domain_sid,
                              char *domain_controller,
                              char *domain_name)
{
    struct winbind_domain_gid *tmp;

    for(tmp = domain_gid_list; tmp != NULL; tmp = tmp->next) {
        if ((gid >= tmp->gid_low) && (gid <= tmp->gid_high) &&
            (tmp->domain != NULL)) {

            /* Copy domain sid */

            if (domain_sid != NULL) {
                sid_copy(domain_sid, &tmp->domain->domain_sid);
            }
            
            /* Copy domain controller */

            if (domain_controller != NULL) {
                fstrcpy(domain_controller, tmp->domain->domain_controller);
            }

            /* Copy domain name */

            if (domain_name != NULL) {
                fstrcpy(domain_name, tmp->domain->domain_name);
            }

            return True;
        }
    }

    /* Not found */

    return False;
}

/* Initialise winbindd_surs database */

BOOL winbindd_surs_init(void)
{
    fstring value;
    char *p;

    /* Parse list of domains and uid ranges from "winbind uid" parameter */

    fstrcpy(value, lp_winbind_uid());

    for (p = strtok(value, LIST_SEP); p; p = strtok(NULL, LIST_SEP)) {
        struct winbind_domain_uid *uid;
        struct winbind_domain *domain;
        fstring domain_name;

        /* Create new domain uid entry */

        if ((uid = (struct winbind_domain_uid *)
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

            if ((domain = (struct winbind_domain *)malloc(sizeof(*domain)))
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
            num_domain++;
        }

        uid->domain = domain;

        /* Add to list */

        DLIST_ADD(domain_uid_list, uid);
        num_domain_uid++;
    }
    
    /* Parse list of domains and gid ranges from "winbind gid" parameter */

    fstrcpy(value, lp_winbind_gid());

    for (p = strtok(value, LIST_SEP); p; p = strtok(NULL, LIST_SEP)) {
        struct winbind_domain_gid *gid;
        struct winbind_domain *domain;
        fstring domain_name;

        /* Create new domain entry */

        if ((gid = (struct winbind_domain_gid *)
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

            if ((domain = (struct winbind_domain *)malloc(sizeof(*domain)))
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
            num_domain++;
        }

        gid->domain = domain;

        /* Add to list */

        DLIST_ADD(domain_gid_list, gid);
        num_domain_gid++;
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
        struct winbind_domain_uid *uid;

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
        struct winbind_domain_gid *gid;
        
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
        struct winbind_domain_uid *uid;

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
        
        struct winbind_domain_gid *gid;

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
