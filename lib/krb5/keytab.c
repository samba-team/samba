#include "krb5_locl.h"

krb5_error_code
krb5_kt_resolve(krb5_context context,
		const char *name,
		krb5_keytab *id)
{
  krb5_keytab k;

  if (strncmp (name, "FILE:", 5) != 0)
    return -1;

  k = ALLOC(1, krb5_keytab);
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

  r = krb5_kt_get_entry (context, keytab, principal, vno, keytype, &entry);

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
  
}

krb5_error_code
krb5_kt_get_entry(krb5_context,
		  krb5_keytab,
		  krb5_principal,
		  krb5_kvno,
		  krb5_keytype,
		  krb5_keytab_entry *);

krb5_error_code
krb5_kt_free_entry(krb5_context,
		   krb5_keytab_entry *);

krb5_error_code
krb5_kt_start_seq_get(krb5_context,
		      krb5_keytab id,
		      krb5_kt_cursor *);

krb5_error_code
krb5_kt_next_entry(krb5_context,
		   krb5_keytab,
		   krb5_keytab_entry *,
		   krb5_kt_cursor *);

krb5_error_code
krb5_kt_end_seq_get(krb5_context,
		    krb5_keytab,
		    krb5_kt_cursor *);

