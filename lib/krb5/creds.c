#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_free_creds(krb5_context context, krb5_creds *c)
{
    krb5_free_principal (context, c->client);
    c->client = NULL;
    krb5_free_principal (context, c->server);
    c->server = NULL;
    krb5_free_keyblock (context, &c->session);
    krb5_data_free (&c->ticket);
    krb5_data_free (&c->second_ticket);
    krb5_data_free (&c->authdata);
    krb5_free_addresses (context, &c->addresses);
    return 0;
}
