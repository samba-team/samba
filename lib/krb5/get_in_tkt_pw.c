#include "krb5_locl.h"

RCSID("$Id$");

static krb5_error_code
key_proc (krb5_context context,
	  krb5_keytype type,
	  krb5_data *salt,
	  krb5_const_pointer keyseed,
	  krb5_keyblock **key)
{
     krb5_error_code err;
     char *password = (char *)keyseed;
     char buf[BUFSIZ];
     
     *key = malloc (sizeof (**key));
     if (*key == NULL)
	  return ENOMEM;
     (*key)->keytype = type;
     (*key)->contents.length = 0;
     (*key)->contents.data   = NULL;
     if (password == NULL) {
	  des_read_pw_string (buf, sizeof(buf), "Password: ", 0);
	  password = buf;
     }
     err = krb5_string_to_key (password, salt, *key);
     memset (buf, 0, sizeof(buf));
     return err;
}

krb5_error_code
krb5_get_in_tkt_with_password (krb5_context context,
			       krb5_flags options,
			       krb5_address *const *addrs,
			       const krb5_enctype *etypes,
			       const krb5_preauthtype *pre_auth_types,
			       const char *password,
			       krb5_ccache ccache,
			       krb5_creds *creds,
			       krb5_kdc_rep **ret_as_reply)
{
     return krb5_get_in_tkt (context, options, addrs, etypes,
			     pre_auth_types, key_proc, password,
			     NULL, NULL, creds, ccache, ret_as_reply);
}
