/*
 *
 */

#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_principal2principalname (PrincipalName *p,
			      const krb5_principal from)
{
    copy_PrincipalName(&from->name, p);
    return 0;
}

krb5_error_code
principalname2krb5_principal (krb5_principal *principal,
			      const PrincipalName from,
			      const Realm realm)
{
    krb5_principal p = malloc(sizeof(*p));
    copy_PrincipalName(&from, &p->name);
    p->realm = strdup(realm);
    *principal = p;
    return 0;
}
