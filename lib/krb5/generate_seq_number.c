#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_generate_seq_number(krb5_context context,
			 const krb5_keyblock *key,
			 int32_t *seqno)
{
    des_cblock c;
    int32_t q;
    u_char *p;
    int i;

    if (key->keytype != KEYTYPE_DES)
	abort ();
    memmove (c, key->keyvalue.data, sizeof(c));
    des_new_random_key(&c);
    q = 0;
    for (p = (u_char *)c, i = 0; i < sizeof(c); ++i, ++p)
	q = (q << 8) | *p;
    q &= 0xffffffff;
    *seqno = q;
    return 0;
}
