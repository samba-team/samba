#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_set_default_realm(krb5_context context,
		       char *realm)
{
    const char *foo;
    char *tmp;
    char **realms = NULL;

    if (realm == NULL){
	foo = krb5_config_get_string (context->cf,
				      "libdefaults",
				      "default_realm",
				      NULL);
	if(foo == NULL){
	    krb5_error_code ret;
	    ret = krb5_get_host_realm(context, NULL, &realms);
	    if(ret)
		return ret;
	    foo = realms[0];
	}
    } else
	foo = realm;

    tmp = strdup (foo);
    if(realms){
	char **q;
	for(q = realms; *q; q++)
	    free(*q);
	free(realms);
    }
	
    if (tmp == NULL)
	return ENOMEM;
    context->default_realm = tmp;
    return 0;
}
