#include "kdc_locl.h"

RCSID("$Id$");

int main(int argc, char **argv)
{
    krb5_context context;
    krb5_principal princ;
    krb5_data salt;
    krb5_keyblock key;
    int i;
    krb5_init_context(&context);
    krb5_parse_name(context, argv[1], &princ);
    salt.length = 0;
    salt.data = NULL;
    krb5_get_salt(princ, &salt);
    krb5_string_to_key(argv[2], &salt, &key);
    for(i = 0; i < key.keyvalue.length; i++)
	printf("%02x", ((unsigned char*)key.keyvalue.data)[i]);
    printf("\n");
}
