#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_set_default_realm(krb5_context context,
		       char *realm)
{
    const char *foo;
    char *tmp;

    if (realm == NULL)
	foo = krb5_config_get_string (context->cf,
				      "libdefaults",
				      "default_realm",
				      NULL);
    else
	foo = realm;

    tmp = strdup (foo);
    if (tmp == NULL)
	return ENOMEM;
    context->default_realm = tmp;
    return 0;
}
