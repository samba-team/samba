#include "hdb_locl.h"

RCSID("$Id$");

#ifdef HAVE_DB_H

krb5_error_code
DB_close(krb5_context context, HDB *db)
{
    DB *d = (DB*)db->db;
    d->close(d);
    free(db);
    return 0;
}

static krb5_error_code
DB_fetch(krb5_context context, HDB *db, hdb_entry *entry)
{
    DB *d = (DB*)db->db;
    DBT key, value;
    krb5_data data;
    int err;

    hdb_principal2key(context, entry->principal, &data);

    key.data = data.data;
    key.size = data.length;
    err = d->get(d, &key, &value, 0);
    krb5_data_free(&data);
    if(err < 0)
	return errno;
    if(err == 1)
	return KRB5_HDB_NOENTRY;

    data.data = value.data;
    data.length = value.size;
    
    hdb_value2entry(context, &data, entry);
    return 0;
}

static krb5_error_code
DB_store(krb5_context context, HDB *db, hdb_entry *entry)
{
    DB *d = (DB*)db->db;
    krb5_data data;
    int err;
    DBT key, value;
    hdb_principal2key(context, entry->principal, &data);
    key.data = data.data;
    key.size = data.length;
    hdb_entry2value(context, entry, &data);
    value.data = data.data;
    value.size = data.length;
    err = d->put(d, &key, &value, 0);
    free(key.data);
    free(value.data);
    if(err == -1)
	return errno;
    return 0;
}

static krb5_error_code
DB_delete(krb5_context context, HDB *db, hdb_entry *entry)
{
    DB *d = (DB*)db->db;
    DBT key;
    krb5_data data;
    int err;

    hdb_principal2key(context, entry->principal, &data);

    key.data = data.data;
    key.size = data.length;
    err = d->del(d, &key, 0);
    krb5_data_free(&data);
    if(err < 0)
	return errno;
    if(err == 1)
	return KRB5_HDB_NOENTRY;
    return 0;
}

static krb5_error_code
DB_seq(krb5_context context, HDB *db, hdb_entry *entry, int flag)

{
    DB *d = (DB*)db->db;
    DBT key, value;
    krb5_data data;
    int err;

    err = d->seq(d, &key, &value, flag);
    if(err == -1)
	return errno;
    if(err == 1)
	return KRB5_HDB_NOENTRY;

    data.data = key.data;
    data.length = key.size;
    hdb_key2principal(context, &data, &entry->principal);
    krb5_data_free(&data);
    data.data = value.data;
    data.length = value.size;
    hdb_value2entry(context, &data, entry);
    krb5_data_free(&data);
    return 0;
}


static krb5_error_code
DB_firstkey(krb5_context context, HDB *db, hdb_entry *entry)
{
    return DB_seq(context, db, entry, R_FIRST);
}


static krb5_error_code
DB_nextkey(krb5_context context, HDB *db, hdb_entry *entry)
{
    return DB_seq(context, db, entry, R_NEXT);
}

krb5_error_code
hdb_db_open(krb5_context context, HDB **db, 
	    const char *filename, int flags, mode_t mode)
{
    DB *d;
    char *fn = malloc(strlen(filename) + 4);
    sprintf(fn, "%s.db", filename);
    d = dbopen(fn, flags, mode, DB_BTREE, NULL);
    free(fn);
    if(d == NULL)
	return errno;
    *db = malloc(sizeof(**db));
    (*db)->db = d;
    (*db)->close = DB_close;
    (*db)->fetch = DB_fetch;
    (*db)->store = DB_store;
    (*db)->delete = DB_delete;
    (*db)->firstkey = DB_firstkey;
    (*db)->nextkey= DB_nextkey;
    return 0;
}


#endif
