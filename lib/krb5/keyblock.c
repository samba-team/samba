#include "krb5_locl.h"

krb5_error_code
krb5_generate_random_des_key(krb5_context context,
			     krb5_keyblock *keyblock)
{
    des_new_random_key(keyblock->keyvalue.data);
    return 0;
}

static struct key_type {
    int keytype;
    int keysize;
    krb5_error_code (*func)(krb5_context, krb5_keyblock*);
} key_types[] = {
    { KEYTYPE_DES, 8, krb5_generate_random_des_key },
};

static const int num_key_types = sizeof(key_types) / sizeof(key_types[0]);

krb5_error_code
krb5_generate_random_keyblock(krb5_context context,
			      int keytype,
			      krb5_keyblock *keyblock)
{
    struct key_type *k;
    for(k = key_types; k < key_types + num_key_types; k++)
	if(keytype == k->keytype){
	    keyblock->keytype = keytype;
	    keyblock->keyvalue.length = k->keysize;
	    keyblock->keyvalue.data = malloc(keyblock->keyvalue.length);
	    return (*k->func)(context, keyblock);
	}
    return KRB5_PROG_KEYTYPE_NOSUPP;
}
