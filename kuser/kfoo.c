#include "kuser_locl.h"

RCSID("$Id$");

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
    in.times.endtime = 0;
    ret = krb5_get_credentials(context, 0, cache, &in, &out);
    
    if(ret){
	printf("%s\n", krb5_get_err_text(context, ret));
	exit(1);
    }
    exit(0);
}
