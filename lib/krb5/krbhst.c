#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_get_krbhst (krb5_context context,
		 const krb5_realm *realm,
		 char ***hostlist)
{
     char *r;
     const char *val;

#ifdef USE_ASN1_PRINCIPAL
     r = *realm;
#else
     r = malloc (realm->length + 1);
     strncpy (r, realm->data, realm->length);
     r[realm->length] = '\0';
#endif

     val = krb5_config_get_string (context->cf,
				   "realms",
				   r,
				   "kdc",
				   NULL);
#ifndef USE_ASN1_PRINCIPAL
     free (r);
#endif
     if (val == NULL)
	 return KRB5_REALM_UNKNOWN;

     *hostlist = malloc (2 * sizeof (char *));
     (*hostlist)[0] = val;
     (*hostlist)[1] = NULL;
     return 0;
}

krb5_error_code
krb5_free_krbhst (krb5_context context,
		  char *const *hostlist)
{
    free ((void *)hostlist);
    return 0;
}
