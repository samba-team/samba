#include "kdc_locl.h"

RCSID("$Id$");

static RETSIGTYPE
sigterm(int sig)
{
    exit(0);
}

int
main(int argc, char **argv)
{
    krb5_context context;
    des_cblock key;
    des_new_random_key(&key);
    memset(&key, 0, sizeof(key));
    signal(SIGINT, sigterm);
    krb5_init_context(&context);
    loop(context);
}
