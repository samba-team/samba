#include "kuser_locl.h"

RCSID("$Id$");

#if 1
main(int argc, char **argv)
{
    krb5_context context;
    krb5_ccache cache;
    krb5_creds in, *out;
    int ret;

    if (argc != 2) {
      printf ("argc != 2\n");
      return 1;
    }

    krb5_init_context(&context);
    krb5_cc_default(context, &cache);
    memset(&in, 0, sizeof(in));
    krb5_cc_get_principal(context, cache, &in.client);
    krb5_parse_name(context, argv[1], &in.server);
    in.times.endtime = time(NULL) + 4711;
    ret = krb5_get_credentials(context, 0, cache, &in, &out);
    
    printf("%s\n", krb5_get_err_text(context, ret));
}
#endif

#if 0
int
main(int argc, char **argv)
{
    int ret;
    krb5_context context;
    krb5_principal principal;
    krb5_keyblock *key;
    krb5_creds in, *out;


    krb5_init_context(&context);
    krb5_build_principal(context, &principal, strlen("FOO.SE"), "FOO.SE",
			 "host", "emma.pdc.kth.se", NULL);
    krb5_kt_read_service_key(context,
			     NULL,
			     principal,
			     3,
			     KEYTYPE_DES,
			     &key);
    return 0;
}
#endif
