#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_generate_subkey(krb5_context context,
		     const krb5_keyblock *key,
		     krb5_keyblock **subkey)
{
    krb5_error_code ret;
    krb5_keyblock *k;

    if (key->keytype != KEYTYPE_DES)
	abort ();
    k = malloc(sizeof(**subkey));
    if (k == NULL)
	return ENOMEM;
    k->keytype = key->keytype;
    k->contents.length = 0;
    ret = krb5_data_copy (&k->contents,
			  key->contents.data,
			  key->contents.length);
    if (ret) {
	free(k);
	return ret;
    }
    des_new_random_key ((des_cblock *)k->contents.data);
    *subkey = k;
    return 0;
}
