#ifndef __KEYTAB_H__
#define __KEYTAB_H__

#if 0
krb5_error_code
krb5_kt_register(krb5_context, krb5_kt_ops *);
#endif

krb5_error_code
krb5_kt_resolve(krb5_context, const char *, krb5_keytab *id);

krb5_error_code
krb5_kt_default_name(krb5_context, char *name, int namesize);

krb5_error_code
krb5_kt_default(krb5_context, krb5_keytab *id);

krb5_error_code
krb5_kt_read_service_key(krb5_context,
			 krb5_pointer keyprocarg,
			 krb5_principal principal,
			 krb5_kvno vno,
			 krb5_keytype keytype,
			 krb5_keyblock **key);

krb5_error_code
krb5_kt_add_entry(krb5_context,
		  krb5_keytab id,
		  krb5_keytab_entry *entry);

krb5_error_code
krb5_kt_remove_entry(krb5_context,
		     krb5_keytab id,
		     krb5_keytab_entry *entry);

krb5_error_code
krb5_kt_get_name(krb5_context,
		 krb5_keytab,
		 char *name,
		 int namesize);

krb5_error_code
krb5_kt_close(krb5_context,
	      krb5_keytab id);

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

#endif /* __KEYTAB_H__ */
