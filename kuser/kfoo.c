#include <krb5.h>

main(int argc, char **argv)
{
    int ret;
    krb5_context context;
    krb5_ccache cache;
    krb5_creds in, *out;
    krb5_init_context(&context);
    krb5_cc_default(context, &cache);
    memset(&in, 0, sizeof(in));
    krb5_cc_get_principal(context, cache, &in.client);
    krb5_parse_name(context, "hosts/farbrorn@pdc.kth.se", &in.server);
    in.times.endtime = time(NULL) + 4711;
    ret = krb5_get_credentials(context, 0, cache, &in, &out);
    
    printf("%d\n", ret);
}
