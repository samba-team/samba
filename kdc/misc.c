#include "kdc_locl.h"

RCSID("$Id$");

struct timeval now;

hdb_entry*
db_fetch(krb5_context context, PrincipalName *principal, char *realm)
{
    HDB *db;
    hdb_entry *ent;

    ent = malloc(sizeof(*ent));
    principalname2krb5_principal(&ent->principal, *principal, realm);
    hdb_open(context, &db, NULL, O_RDONLY, 0);
    db->fetch(context, db, ent);
    db->close(context, db);
    return ent;
}

/* this should move someplace else */
krb5_error_code
mk_des_keyblock(EncryptionKey *kb)
{
    kb->keytype = KEYTYPE_DES;
    kb->keyvalue.data = malloc(sizeof(des_cblock));
    kb->keyvalue.length = sizeof(des_cblock);
    des_new_random_key(kb->keyvalue.data);
    return 0;
}



