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
#include "winbindd.h"

#define WINBINDD_UID_BASE 1000
#define WINBINDD_GID_BASE 1000

struct surs_rid_acct {
    uint32 rid;
    char *name;
};

/* RIDs relative to each domain.  These live under S-1-5-21-?-?-? */

struct surs_rid_acct domain_users[] = {
    { DOMAIN_USER_RID_ADMIN, "Administrator" },
    { DOMAIN_USER_RID_GUEST, "Guest" },
    { 0, NULL}
};

struct surs_rid_acct domain_groups[] = {
    { DOMAIN_GROUP_RID_ADMINS, "Domain Admins" },
    { DOMAIN_GROUP_RID_USERS, "All Users" },
    { DOMAIN_GROUP_RID_GUESTS, "Guests" },
//    { DOMAIN_GROUP_RID_COMPUTERS, "???" },
//    { DOMAIN_GROUP_RID_CONTROLLERS, "???" },
//    { DOMAIN_GROUP_RID_CERT_ADMINS, "???" },
//    { DOMAIN_GROUP_RID_SCHEMA_ADMINS, "???" },
//    { DOMAIN_GROUP_RID_ENTERPRISE_ADMINS, "???" },
//    { DOMAIN_GROUP_RID_POLICY_ADMINS, "???" },
    { 0, NULL}
};

/* Well known RIDs.  These all live under S-1-5-32 */

struct surs_rid_acct local_users[] = {
    { 0, NULL}
};

struct surs_rid_acct local_groups[] = {
    { BUILTIN_ALIAS_RID_ADMINS, "BUILTIN/Administrators" },
    { BUILTIN_ALIAS_RID_USERS, "BUILTIN/Users" },
    { BUILTIN_ALIAS_RID_GUESTS, "BUILTIN/Guests" },
//    { BUILTIN_ALIAS_RID_POWER_USERS, "BUILTIN/00000223" },
    { BUILTIN_ALIAS_RID_ACCOUNT_OPS, "BUILTIN/Account Operators" },
    { BUILTIN_ALIAS_RID_SYSTEM_OPS, "BUILTIN/Server Operators" },
    { BUILTIN_ALIAS_RID_PRINT_OPS, "BUILTIN/Print Operators" },
    { BUILTIN_ALIAS_RID_BACKUP_OPS, "BUILTIN/Backup Operators" },
    { BUILTIN_ALIAS_RID_REPLICATOR, "BUILTIN/Replicator" },
    { 0, NULL }
};

static TDB_CONTEXT *surs_tdb_uid_by_sid = NULL;
static TDB_CONTEXT *surs_tdb_gid_by_sid = NULL;
static TDB_CONTEXT *surs_tdb_sid_by_uid = NULL;
static TDB_CONTEXT *surs_tdb_sid_by_gid = NULL;
static TDB_CONTEXT *surs_tdb_pwnam_by_sid = NULL;
static TDB_CONTEXT *surs_tdb_grnam_by_sid = NULL;

#define HWM_KEY "_HWM"

static int create_new_id(fstring sid_str, int isgroup)
{
    TDB_CONTEXT *id_by_sid = NULL;
    TDB_DATA hwm_key, hwm_value;
    TDB_DATA new_key, new_value;
    uint32 hwm_id;
    fstring temp;

    isgroup ? (id_by_sid = surs_tdb_gid_by_sid) : 
        (id_by_sid = surs_tdb_uid_by_sid);

    /* Get highest id value */

    hwm_key.dptr = HWM_KEY;
    hwm_key.dsize = strlen(HWM_KEY) + 1;

    hwm_value = tdb_fetch(id_by_sid, hwm_key);
    hwm_id = atoi(hwm_value.dptr);

    /* Add next id to database */

    new_key.dptr = sid_str;
    new_key.dsize = strlen(sid_str) + 1;

    snprintf(temp, sizeof(temp) - 1, "%d", hwm_id);
    new_value.dptr = temp;
    new_value.dsize = strlen(temp) + 1;

    /* Update hwm */

    snprintf(temp, sizeof(temp) - 1, "%d", hwm_id + 1);

    hwm_value.dptr = temp;
    hwm_value.dsize = strlen(temp) + 1;

    tdb_store(id_by_sid, hwm_key, hwm_value, TDB_REPLACE);

    return hwm_id;
}

static int create_new_uid(fstring sid_str) 
{
    return create_new_id(sid_str, False);
}

static int create_new_gid(fstring sid_str) 
{
    return create_new_id(sid_str, True);
}

/* Initialise winbindd_surs database */

int winbindd_surs_init(DOM_SID *domain_sid, char *domain_name)
{
    /* Create tdb databases */

    if ((surs_tdb_uid_by_sid = tdb_open("/tmp/uid_by_sid.tdb", 0,
                                        TDB_CLEAR_IF_FIRST, O_RDWR |
                                        O_CREAT, 0600)) == NULL) {
        DEBUG(1, ("error opening /tmp/uid_by_sid.tdb\n"));
        return False;
    }

    if ((surs_tdb_gid_by_sid = tdb_open("/tmp/gid_by_sid.tdb", 0,
                                        TDB_CLEAR_IF_FIRST, O_RDWR |
                                        O_CREAT, 0600)) == NULL) {
        DEBUG(1, ("error opening /tmp/gid_by_sid.tdb\n"));
        return False;
    }
    
    if ((surs_tdb_sid_by_uid = tdb_open("/tmp/sid_by_uid.tdb", 0,
                                        TDB_CLEAR_IF_FIRST, O_RDWR |
                                        O_CREAT, 0600)) == NULL) {
        DEBUG(1, ("error opening /tmp/sid_by_uid.tdb\n"));
        return False;
    }

    if ((surs_tdb_sid_by_gid = tdb_open("/tmp/sid_by_gid.tdb", 0,
                                        TDB_CLEAR_IF_FIRST, O_RDWR |
                                        O_CREAT, 0600)) == NULL) {
        DEBUG(1, ("error opening /tmp/sid_by_gid.tdb\n"));
        return False;
    }
    
    if ((surs_tdb_pwnam_by_sid = tdb_open("/tmp/pwnam_by_sid.tdb", 0,
                                        TDB_CLEAR_IF_FIRST, O_RDWR |
                                        O_CREAT, 0600)) == NULL) {
        DEBUG(1, ("error opening /tmp/pwnam_by_sid.tdb\n"));
        return False;
    }

    if ((surs_tdb_grnam_by_sid = tdb_open("/tmp/grnam_by_sid.tdb", 0,
                                        TDB_CLEAR_IF_FIRST, O_RDWR |
                                        O_CREAT, 0600)) == NULL) {
        DEBUG(1, ("error opening /tmp/grnam_by_sid.tdb\n"));
        return False;
    }
    
    /* Add high/low watermarks for [gu]id by sid */

    {
        TDB_DATA key, value;
        fstring temp;

        key.dptr = HWM_KEY;
        key.dsize = strlen(HWM_KEY) + 1;

        if (!tdb_exists(surs_tdb_uid_by_sid, key)) {
            snprintf(temp, sizeof(temp) - 1, "%d", WINBINDD_UID_BASE);
            value.dptr = temp;
            value.dsize = strlen(temp) + 1;

            tdb_store(surs_tdb_uid_by_sid, key, value, TDB_REPLACE);
        }

        if (!tdb_exists(surs_tdb_gid_by_sid, key)) {
            snprintf(temp, sizeof(temp) - 1, "%d", WINBINDD_GID_BASE);
            value.dptr = temp;
            value.dsize = strlen(temp) + 1;

            tdb_store(surs_tdb_gid_by_sid, key, value, TDB_REPLACE);
        }
    }

    /* Add well known users and groups */

    {
        TDB_DATA sid, id, nam;
        uint32 the_id;
        fstring sid_str, temp, temp2, temp3;
        int i;

        /* Add domain users */

        sid_to_string(sid_str, domain_sid);

        for(i = 0; domain_users[i].name != NULL; i++) {

            /* Key SID */

            snprintf(temp, sizeof(temp) - 1, "%s-%d", sid_str, 
                     domain_users[i].rid);

            sid.dptr = temp;
            sid.dsize = strlen(temp) + 1;

            /* Key uid */

            the_id = create_new_uid(sid_str);

            snprintf(temp2, sizeof(temp) - 1, "%d", the_id);

            id.dptr = temp2;
            id.dsize = strlen(temp2) + 1;

            /* Key username */

            snprintf(temp3, sizeof(temp3) - 1, "%s/%s", domain_name, 
                     domain_users[i].name);

            nam.dptr = temp3;
            nam.dsize = strlen(temp3) + 1;

            /* Store entries */

            tdb_store(surs_tdb_uid_by_sid, sid, id, TDB_REPLACE);
            tdb_store(surs_tdb_sid_by_uid, id, sid, TDB_REPLACE);
            tdb_store(surs_tdb_pwnam_by_sid, sid, nam, TDB_REPLACE);
        }

        /* Add BUILTIN users */

        sid_to_string(sid_str, &global_sid_S_1_5_20);

        for(i = 0; local_users[i].name != NULL; i++) {

            /* Key sid */

            snprintf(temp, sizeof(temp) - 1, "%s-%d", sid_str, 
                     local_users[i].rid);

            sid.dptr = temp;
            sid.dsize = strlen(temp) + 1;

            /* Key uid */

            the_id = create_new_uid(sid_str);

            snprintf(temp2, sizeof(temp) - 1, "%d", the_id);

            id.dptr = temp2;
            id.dsize = strlen(temp2) + 1;

            /* Key user name */

            nam.dptr = local_users[i].name;
            nam.dsize = strlen(local_users[i].name) + 1;

            /* Store entries */

            tdb_store(surs_tdb_uid_by_sid, sid, id, TDB_REPLACE);
            tdb_store(surs_tdb_sid_by_uid, id, sid, TDB_REPLACE);
            tdb_store(surs_tdb_pwnam_by_sid, sid, nam, TDB_REPLACE);
        }

        /* Add domain groups */

        sid_to_string(sid_str, domain_sid);

        for(i = 0; domain_groups[i].name != NULL; i++) {

            /* Key SID */

            snprintf(temp, sizeof(temp) - 1, "%s-%d", sid_str, 
                     domain_groups[i].rid);

            sid.dptr = temp;
            sid.dsize = strlen(temp) + 1;

            /* Key uid */

            the_id = create_new_gid(sid_str);

            snprintf(temp2, sizeof(temp2) - 1, "%d", the_id);

            id.dptr = temp2;
            id.dsize = strlen(temp2) + 1;

            /* Key group name */

            snprintf(temp3, sizeof(temp3) - 1, "%s/%s", domain_name,
                     domain_groups[i].name);

            nam.dptr = temp3;
            nam.dsize = strlen(temp3) + 1;

            tdb_store(surs_tdb_gid_by_sid, sid, id, TDB_REPLACE);
            tdb_store(surs_tdb_sid_by_gid, id, sid, TDB_REPLACE);
            tdb_store(surs_tdb_grnam_by_sid, sid, nam, TDB_REPLACE);
        }

        /* Add BUILTIN groups */

        sid_to_string(sid_str, &global_sid_S_1_5_20);

        for (i = 0; local_groups[i].name != NULL; i++) {

            /* Key SID */

            snprintf(temp, sizeof(temp) - 1, "%s-%d", sid_str, 
                     local_users[i].rid);

            sid.dptr = temp;
            sid.dsize = strlen(temp) + 1;

            /* Key uid */

            the_id = create_new_gid(sid_str);

            snprintf(temp2, sizeof(temp) - 1, "%d", the_id);

            id.dptr = temp2;
            id.dsize = strlen(temp2) + 1;

            /* Key group name */

            nam.dptr = local_groups[i].name;
            nam.dsize = strlen(local_groups[i].name) + 1;

            /* Store entries */

            tdb_store(surs_tdb_gid_by_sid, sid, id, TDB_REPLACE);
            tdb_store(surs_tdb_sid_by_gid, id, sid, TDB_REPLACE);
            tdb_store(surs_tdb_grnam_by_sid, sid, nam, TDB_REPLACE);
        }
    }

    return True;
}

/* Wrapper around "standard" surs sid to unixid function */

BOOL winbindd_surs_sam_sid_to_unixid(DOM_SID *sid, char *name, uint32 type, 
                                     uint32 *id)
{
    TDB_DATA key, value;
    fstring temp, temp2;

    sid_to_string(temp, sid);
    fprintf(stderr, "surs: sid %s/%s type %s ", temp, name,
              (type == SID_NAME_USER) ? "user" : (
                  (type == SID_NAME_DOM_GRP) ? "domain grp" : (
                      (type == SID_NAME_ALIAS) ? "local grp" : "?")));

    key.dptr = temp;
    key.dsize = strlen(temp) + 1;

    /* Lookup SID in user database */

    if (type == SID_NAME_USER) {

        /* Add (sid,name) to database */

        if (name != NULL) {
            value.dptr = name;
            value.dsize = strlen(name) + 1;

            tdb_store(surs_tdb_pwnam_by_sid, key, value, TDB_REPLACE);
        }

        /* Create and add (sid,uid) and (uid,sid) to databases */
            
        if (!tdb_exists(surs_tdb_uid_by_sid, key)) {
            uint32 new_uid = create_new_uid(temp);

            snprintf(temp2, sizeof(temp2) - 1, "%d", new_uid);

            value.dptr = temp2;
            value.dsize = strlen(temp2) + 1;

            tdb_store(surs_tdb_uid_by_sid, key, value, TDB_REPLACE);
            tdb_store(surs_tdb_sid_by_uid, value, key, TDB_REPLACE);
        }
        
        /* Return it */

        value = tdb_fetch(surs_tdb_uid_by_sid, key);

        if (id != NULL) {
            *id = atoi(value.dptr);
        }
        
        fprintf(stderr, "ok\n");
        return True;
    }

    /* Lookup SID in domain and local group database */

    if ((type == SID_NAME_DOM_GRP) || (type == SID_NAME_ALIAS)) {

        /* Add (sid,name) to database */

        if (name != NULL) {
            value.dptr = name;
            value.dsize = strlen(name) + 1;

            tdb_store(surs_tdb_grnam_by_sid, key, value, TDB_REPLACE);
        }

        /* Create and add (sid,gid) and (gid,sid) to databases */
            
        if (!tdb_exists(surs_tdb_gid_by_sid, key)) {
            uint32 new_gid = create_new_gid(temp);

            snprintf(temp2, sizeof(temp2) - 1, "%d", new_gid);

            value.dptr = temp2;
            value.dsize = strlen(temp2) + 1;

            tdb_store(surs_tdb_gid_by_sid, key, value, TDB_REPLACE);
            tdb_store(surs_tdb_sid_by_gid, value, key, TDB_REPLACE);
        }
        
        /* Return it */

        value = tdb_fetch(surs_tdb_gid_by_sid, key);

        if (id != NULL) {
            *id = atoi(value.dptr);
        }
        
        fprintf(stderr, "ok\n");
        return True;
    }
    
    fprintf(stderr, "not found\n");
    return False;
}

/* Wrapper around "standard" surs unixd to sid function */

BOOL winbindd_surs_unixid_to_sam_sid(uint32 id, uint32 type, DOM_SID *sid,
                                     BOOL create)
{
    TDB_DATA key, value;
    fstring temp;

    fprintf(stderr, "surs: unixid %d type %s ", id,
              (type == SID_NAME_USER) ? "user" : (
                  (type == SID_NAME_DOM_GRP) ? "domain grp" : (
                      (type == SID_NAME_ALIAS) ? "local grp" : "?")));

    snprintf(temp, sizeof(temp) - 1, "%d", id);

    key.dptr = temp;
    key.dsize = strlen(temp) + 1;

    /* Lookup sid by uid */

    if ((type == SID_NAME_USER) && tdb_exists(surs_tdb_sid_by_uid, key)) {

        /* Get sid */

        value = tdb_fetch(surs_tdb_sid_by_uid, key);
        if (sid != NULL) {
            string_to_sid(sid, value.dptr);
        }

        fprintf(stderr, "ok\n");
        return True;
    }

    /* Lookup sid by gid */

    if (((type == SID_NAME_DOM_GRP) || (type == SID_NAME_ALIAS)) &&
        tdb_exists(surs_tdb_sid_by_gid, key)) {

        /* Get sid */

        value = tdb_fetch(surs_tdb_sid_by_gid, key);
        if (sid != NULL) {
            string_to_sid(sid, value.dptr);
        }

        fprintf(stderr, "ok\n");
        return True;
    }

    fprintf(stderr, "not found\n");
    return False;
}

/*
Local variables:
compile-command: "make -C ~/work/nss-ntdom/samba-tng/source nsswitch"
end:
*/
