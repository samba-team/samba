#include "kdc_locl.h"

RCSID("$Id$");

struct timeval now;

hdb_entry*
db_fetch(krb5_context context, krb5_principal principal)
{
    HDB *db;
    hdb_entry *ent;
    krb5_error_code ret;

    ent = malloc(sizeof(*ent));
    krb5_copy_principal(context, principal, &ent->principal);
    hdb_open(context, &db, NULL, O_RDONLY, 0);
    ret = db->fetch(context, db, ent);
    db->close(context, db);
    if(ret){
	krb5_free_principal(context, ent->principal);
	free(ent);
	return NULL;
    }
    return ent;
}
