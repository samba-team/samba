#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_get_default_realm(krb5_context context,
		       char **realm)
{
    char *res;

    res = strdup (context->default_realm);
    if (res == NULL)
	return ENOMEM;
    *realm = res;
    return 0;
}
