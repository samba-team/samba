/* 
   Unix SMB/Netbios implementation.
   Version 2.0

   Winbind daemon - user related function

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

#include "winbindd.h"

/* High water mark keys */

#define HWM_GROUP  "GROUP HWM"
#define HWM_USER   "USER HWM"

/* Globals */

static TDB_CONTEXT *idmap_tdb;

/* Allocate either a user or group id from the pool */

static BOOL allocate_id(int *id, BOOL isgroup)
{
    int hwm;

    /* Get current high water mark */

    if ((hwm = tdb_fetch_int(idmap_tdb, 
                             isgroup ? HWM_GROUP : HWM_USER)) == -1) {
        return False;
    }

    /* Return next available uid in list */

    if ((isgroup && (hwm > server_state.gid_high)) ||
        (!isgroup && (hwm > server_state.uid_high))) {
        DEBUG(0, ("winbind %sid range full!\n", isgroup ? "g" : "u"));
        return False;
    }

    if (id) {
        *id = hwm;
    }

    hwm++;

    /* Store new high water mark */

    tdb_store_int(idmap_tdb, isgroup ? HWM_GROUP : HWM_USER, hwm);

    return True;
}

/* Get an id from a rid */

static BOOL get_id_from_rid(char *domain_name, uint32 rid, int *id,
                            BOOL isgroup)
{
    TDB_DATA data, key;
    fstring keystr;
    BOOL result;

    /* Check if rid is present in database */

    slprintf(keystr, sizeof(keystr), "%s/%d", domain_name, rid);
    
    key.dptr = keystr;
    key.dsize = strlen(keystr) + 1;

    data = tdb_fetch(idmap_tdb, key);

    if (data.dptr) {
        fstring scanstr;
        int the_id;

        /* Parse and return existing uid */

        fstrcpy(scanstr, isgroup ? "GID" : "UID");
        fstrcat(scanstr, " %d");

        if (sscanf(data.dptr, scanstr, &the_id) == 1) {

            /* Store uid */

            if (id) {
                *id = the_id;
            }

            result = True;
        }

        free(data.dptr);

    } else {

        /* Allocate a new id for this rid */

        if (id && allocate_id(id, isgroup)) {
            fstring keystr2;

            /* Store new id */
            
            slprintf(keystr2, sizeof(keystr2), "%s %d", isgroup ? "GID" :
                     "UID", *id);

            data.dptr = keystr2;
            data.dsize = strlen(keystr2) + 1;

            tdb_store(idmap_tdb, key, data, TDB_REPLACE);
            tdb_store(idmap_tdb, data, key, TDB_REPLACE);

            result = True;
        }
    }

    return result;
}

/* Get a uid from a user rid */

BOOL winbindd_idmap_get_uid_from_rid(char *domain_name, uint32 user_rid, 
                                     uid_t *uid)
{
    return get_id_from_rid(domain_name, user_rid, uid, False);
}

/* Get a gid from a group rid */

BOOL winbindd_idmap_get_gid_from_rid(char *domain_name, uint32 group_rid, 
                                     gid_t *gid)
{
    return get_id_from_rid(domain_name, group_rid, gid, True);
}

BOOL get_rid_from_id(int id, uint32 *rid, struct winbindd_domain **domain,
                     BOOL isgroup)
{
    TDB_DATA key, data;
    fstring keystr;
    BOOL result = False;

    slprintf(keystr, sizeof(keystr), "%s %d", isgroup ? "GID" : "UID", id);

    key.dptr = keystr;
    key.dsize = strlen(keystr) + 1;

    data = tdb_fetch(idmap_tdb, key);

    if (data.dptr) {
        char *p = data.dptr;
        fstring domain_name;
        uint32 the_rid;

        if (next_token(&p, domain_name, "/", sizeof(fstring))) {

            the_rid = atoi(p);

            if (rid) {
                *rid = the_rid;
            }

            if (domain) {
                *domain = find_domain_from_name(domain_name);
            }

            result = True;
        }
            
        free(data.dptr);
    }

    return result;
}

/* Get a user rid from a uid */

BOOL winbindd_idmap_get_rid_from_uid(uid_t uid, uint32 *user_rid,
                                     struct winbindd_domain **domain)
{
    return get_rid_from_id((int)uid, user_rid, domain, False);
}

/* Get a group rid from a gid */

BOOL winbindd_idmap_get_rid_from_gid(gid_t gid, uint32 *group_rid, 
                                     struct winbindd_domain **domain)
{
    return get_rid_from_id((int)gid, group_rid, domain, True);
}

/* Initialise idmap database */

BOOL winbindd_idmap_init(void)
{
    /* Open tdb cache */

    if (!(idmap_tdb = tdb_open(lock_path("winbindd_idmap.tdb"), 0,
                               TDB_NOLOCK | TDB_NOMMAP, 
                               O_RDWR | O_CREAT, 0600))) {
        DEBUG(0, ("Unable to open idmap database\n"));
        return False;
    }

     /* Create high water marks for group and user id */

    if (tdb_fetch_int(idmap_tdb, HWM_USER) == -1) {
        if (tdb_store_int(idmap_tdb, HWM_USER, server_state.uid_low) == -1) {
            DEBUG(0, ("Unable to initialise user hwm in idmap database\n"));
            return False;
        }
    }

    if (tdb_fetch_int(idmap_tdb, HWM_GROUP) == -1) {
        if (tdb_store_int(idmap_tdb, HWM_GROUP, server_state.gid_low) == -1) {
            DEBUG(0, ("Unable to initialise group hwm in idmap database\n"));
            return False;
        }
    }

    return True;   
}
