/* $Id$ */

#ifndef __HDB_H__
#define __HDB_H__

#include <hdb_err.h>

typedef struct hdb_entry{
    krb5_principal principal;
    krb5_keyblock keyblock;
    int kvno;
    time_t max_life;
    time_t max_renew;
}hdb_entry;

typedef struct HDB{
    void *db;

    krb5_error_code (*close)(krb5_context, struct HDB*);
    krb5_error_code (*fetch)(krb5_context, struct HDB*, hdb_entry*);
    krb5_error_code (*store)(krb5_context, struct HDB*, hdb_entry*);
    krb5_error_code (*delete)(krb5_context, struct HDB*, hdb_entry*);
    krb5_error_code (*firstkey)(krb5_context, struct HDB*, hdb_entry*);
    krb5_error_code (*nextkey)(krb5_context, struct HDB*, hdb_entry*);
}HDB;

krb5_error_code hdb_db_open(krb5_context, HDB**, const char*, int, mode_t);
krb5_error_code hdb_ndbm_open(krb5_context, HDB**, const char*, int, mode_t);
krb5_error_code hdb_open(krb5_context, HDB**, const char*, int, mode_t);

#define HDB_DEFAULT_DB "heimdal"

#endif /* __HDB_H__ */
