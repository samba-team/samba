#include "hdb_locl.h"

RCSID("$Id$");

void
hdb_principal2key(krb5_context context, krb5_principal p, krb5_data *key)
{
    krb5_storage *sp;
    krb5_principal new;

    krb5_copy_principal(context, p, &new);
#ifdef USE_ASN1_PRINCIPAL
    new->name.name_type = 0;
#else
    new->type = 0;
#endif
    sp = krb5_storage_emem();
    krb5_store_principal(sp, new);
    krb5_storage_to_data(sp, key);
    krb5_storage_free(sp);
    krb5_free_principal(context, new);
}

void
hdb_key2principal(krb5_context context, krb5_data *key, krb5_principal *p)
{
    krb5_storage *sp;
    sp = krb5_storage_from_mem(key->data, key->length);
    krb5_ret_principal(sp, p);
    krb5_storage_free(sp);
}

void
hdb_entry2value(krb5_context context, hdb_entry *ent, krb5_data *value)
{
    krb5_storage *sp;
    sp = krb5_storage_emem();
    krb5_store_int32(sp, ent->kvno);
    krb5_store_keyblock(sp, ent->keyblock);
    krb5_store_int32(sp, ent->max_life);
    krb5_store_int32(sp, ent->max_renew);
    krb5_store_int32(sp, ent->last_change);
    krb5_store_principal(sp, ent->changed_by);
    krb5_store_int32(sp, ent->expires);
    krb5_store_int32(sp, ent->u.flags);
    krb5_storage_to_data(sp, value);
    krb5_storage_free(sp);
}

void
hdb_value2entry(krb5_context context, krb5_data *value, hdb_entry *ent)
{
    /* XXX must check return values */
    krb5_storage *sp;
    int32_t tmp;
    sp = krb5_storage_from_mem(value->data, value->length);
    krb5_ret_int32(sp, &tmp);
    ent->kvno = tmp;
    krb5_ret_keyblock(sp, &ent->keyblock);
    krb5_ret_int32(sp, &tmp);
    ent->max_life = tmp;
    krb5_ret_int32(sp, &tmp);
    ent->max_renew = tmp;
    krb5_ret_int32(sp, &tmp);
    ent->last_change = tmp;
    krb5_ret_principal(sp, &ent->changed_by);
    krb5_ret_int32(sp, &tmp);
    ent->expires = tmp;
    krb5_ret_int32(sp, &tmp);
    ent->u.flags = tmp;
    krb5_storage_free(sp);
}



krb5_error_code
hdb_etype2key(krb5_context context, 
	      hdb_entry *e, 
	      krb5_enctype etype, 
	      krb5_keyblock **key)
{
    krb5_keytype keytype;
    krb5_error_code ret;
    ret = krb5_etype2keytype(context, etype, &keytype);
    if(ret)
	return ret;
    if(keytype == e->keyblock.keytype){
	*key = &e->keyblock;
	return 0;
    }
    return KRB5_PROG_ETYPE_NOSUPP;
}

void
hdb_free_entry(krb5_context context, hdb_entry *ent)
{
    krb5_free_principal(context, ent->principal);
    krb5_free_keyblock(context, &ent->keyblock);
    krb5_free_principal(context, ent->changed_by);
}
	       


krb5_error_code
hdb_open(krb5_context context, HDB **db, 
	 const char *filename, int flags, mode_t mode)
{
    if(filename == NULL)
	filename = HDB_DEFAULT_DB;
#ifdef HAVE_DB_H
    return hdb_db_open(context, db, filename, flags, mode);
#elif HAVE_NDBM_H
    return hdb_ndbm_open(context, db, filename, flags, mode);
#else
#error No suitable database library
#endif
}
