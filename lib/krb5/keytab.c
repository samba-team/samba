#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_kt_resolve(krb5_context context,
		const char *name,
		krb5_keytab *id)
{
  krb5_keytab k;

  if (strncmp (name, "FILE:", 5) != 0)
    return -1;

  k = ALLOC(1, krb5_keytab_data);
  if (k == NULL)
    return ENOMEM;
  k->filename = strdup(name + 5);
  if (k->filename == NULL)
    return ENOMEM;
  *id = k;
  return 0;
}

#define KEYTAB_DEFAULT "FILE:/etc/v5srvtab"

krb5_error_code
krb5_kt_default_name(krb5_context context,
		     char *name,
		     int namesize)
{
  strncpy (name, KEYTAB_DEFAULT, namesize);
  return 0;
}

krb5_error_code
krb5_kt_default(krb5_context context,
		krb5_keytab *id)
{
  return krb5_kt_resolve (context, KEYTAB_DEFAULT, id);
}

krb5_error_code
krb5_kt_read_service_key(krb5_context context,
			 krb5_pointer keyprocarg,
			 krb5_principal principal,
			 krb5_kvno vno,
			 krb5_keytype keytype,
			 krb5_keyblock **key)
{
  krb5_keytab keytab;
  krb5_keytab_entry entry;
  krb5_error_code r;

  if (keyprocarg)
    r = krb5_kt_resolve (context, keyprocarg, &keytab);
  else
    r = krb5_kt_default (context, &keytab);

  if (r)
    return r;

  r = krb5_kt_get_entry (context, keytab, principal, vno, keytype, &entry);
  if (r)
    return r;
  *key = malloc(sizeof(**key));
  (*key)->keytype = entry.keyblock.keytype;
  (*key)->contents.length = 0;
  (*key)->contents.data = NULL;
  krb5_data_copy(&(*key)->contents, entry.keyblock.contents.data,
		 entry.keyblock.contents.length);

  krb5_kt_close (context, keytab);
  return r;
}

krb5_error_code
krb5_kt_add_entry(krb5_context context,
		  krb5_keytab id,
		  krb5_keytab_entry *entry)
{
  abort ();
}

krb5_error_code
krb5_kt_remove_entry(krb5_context context,
		     krb5_keytab id,
		     krb5_keytab_entry *entry)
{
  abort ();
}

krb5_error_code
krb5_kt_get_name(krb5_context context,
		 krb5_keytab keytab,
		 char *name,
		 int namesize)
{
  strncpy (name, keytab->filename, namesize);
  return 0;
}

krb5_error_code
krb5_kt_close(krb5_context context,
	      krb5_keytab id)
{
  free (id->filename);
  free (id);
  return 0;
}

krb5_error_code
krb5_kt_get_entry(krb5_context context,
		  krb5_keytab id,
		  krb5_principal principal,
		  krb5_kvno kvno,
		  krb5_keytype keytype,
		  krb5_keytab_entry *entry)
{
  krb5_error_code r;
  krb5_kt_cursor cursor;

  r = krb5_kt_start_seq_get (context, id, &cursor);
  while (krb5_kt_next_entry(context, id, entry, &cursor) == 0) {
    if ((principal == NULL || krb5_principal_compare(context,
						     principal,
						     entry->principal)) &&
	(kvno == 0 || kvno == entry->vno)) {
      krb5_kt_end_seq_get (context, id, &cursor);
      return 0;
    }
  }
  krb5_kt_end_seq_get (context, id, &cursor);
  return KRB5_KT_NOTFOUND;
}

krb5_error_code
krb5_kt_free_entry(krb5_context context,
		   krb5_keytab_entry *entry)
{
  free (entry);
  return 0;
}

krb5_error_code
krb5_kt_start_seq_get(krb5_context context,
		      krb5_keytab id,
		      krb5_kt_cursor *cursor)
{
  int16_t tag;
  int ret;
  krb5_storage *sp;

  cursor->fd = open (id->filename, O_RDONLY);
  if (cursor->fd < 0)
    return -1;
  cursor->sp = krb5_storage_from_fd(cursor->fd);
  ret = krb5_ret_int16(cursor->sp, &tag);
  if (ret)
    return ret;
  if (tag != 0x0502)
    return KRB5_KT_UNKNOWN_TYPE;
  return 0;
}

static krb5_error_code
krb5_kt_store_data(krb5_storage *sp,
		   krb5_data data)
{
    int ret;
    ret = krb5_store_int16(sp, data.length);
    if(ret < 0)
	return ret;
    ret = sp->store(sp, data.data, data.length);
    if(ret != data.length){
	if(ret < 0)
	    return errno;
	return KRB5_CC_END;
    }
    return 0;
}

static krb5_error_code
krb5_kt_ret_data(krb5_storage *sp,
		 krb5_data *data)
{
    int ret;
    int16_t size;
    ret = krb5_ret_int16(sp, &size);
    if(ret)
	return ret;
    data->length = size;
    data->data = malloc(size);
    ret = sp->fetch(sp, data->data, size);
    if(ret != size)
	return (ret < 0)? errno : KRB5_CC_END;
    return 0;
}

static krb5_error_code
krb5_kt_ret_principal(krb5_storage *sp,
		      krb5_principal *princ)
{
    int i;
    int ret;
    krb5_principal p;
    int16_t tmp;
    
    p = ALLOC(1, krb5_principal_data);
    if(p == NULL)
	return ENOMEM;


    p->type = KRB5_NT_SRV_HST;
    ret = krb5_ret_int16(sp, &tmp);
    if(ret) return ret;
    p->ncomp = tmp;
    ret = krb5_kt_ret_data(sp, &p->realm);
    if(ret) return ret;
    p->comp = ALLOC(p->ncomp, krb5_data);
    if(p->comp == NULL){
	return ENOMEM;
    }
    for(i = 0; i < p->ncomp; i++){
	ret = krb5_kt_ret_data(sp, &p->comp[i]);
	if(ret) return ret;
    }
    *princ = p;
    return 0;
}

static krb5_error_code
krb5_kt_ret_keyblock(krb5_storage *sp, krb5_keyblock *p)
{
    int ret;
    int16_t tmp;

    ret = krb5_ret_int16(sp, &tmp); /* keytype + etype */
    if(ret) return ret;
    p->keytype = tmp;
    ret = krb5_kt_ret_data(sp, &p->contents);
    return ret;
}

krb5_error_code
krb5_kt_next_entry(krb5_context context,
		   krb5_keytab id,
		   krb5_keytab_entry *entry,
		   krb5_kt_cursor *cursor)
{
  u_int32_t len;
  u_int32_t timestamp;
  int ret;
  int8_t tmp;

  ret = krb5_ret_int32(cursor->sp, &len);
  if (ret)
    return ret;
  ret = krb5_kt_ret_principal (cursor->sp, &entry->principal);
  if (ret)
    return ret;
  ret = krb5_ret_int32(cursor->sp, &entry->principal->type);
  if (ret)
    return ret;
  ret = krb5_ret_int32(cursor->sp, &timestamp);
  if (ret)
    return ret;
  ret = krb5_ret_int8(cursor->sp, &tmp);
  if (ret)
    return ret;
  entry->vno = tmp;
  ret = krb5_kt_ret_keyblock (cursor->sp, &entry->keyblock);
  if (ret)
    return ret;
  return 0;
}

krb5_error_code
krb5_kt_end_seq_get(krb5_context context,
		    krb5_keytab id,
		    krb5_kt_cursor *cursor)
{
    krb5_storage_free(cursor->sp);
    close (cursor->fd);
    return 0;
}
