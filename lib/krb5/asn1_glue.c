/*
 *
 */

#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_principal2principalname (PrincipalName *p,
			      krb5_principal from)
{
    int i;

    p->name_type = from->type;
    p->name_string.len = from->ncomp;
    p->name_string.val = malloc(from->ncomp * sizeof(*p->name_string.val));
    for (i = 0; i < from->ncomp; ++i) {
	int len = from->comp[i].length;
	p->name_string.val[i] = malloc(len + 1);
	strncpy (p->name_string.val[i], from->comp[i].data, len);
	p->name_string.val[i][len] = '\0';
    }
    return 0;
}

krb5_error_code
principalname2krb5_principal (krb5_principal *principal,
			      PrincipalName from,
			      char *realm)
{
    int i;
    krb5_principal p;
    p = malloc (sizeof(*p));
    p->type = from.name_type;
    p->ncomp = from.name_string.len;
    p->comp = malloc (p->ncomp * sizeof(*p->comp));
    for (i = 0; i < p->ncomp; ++i) {
	int len = strlen(from.name_string.val[i]);
	p->comp[i].length = len;
	p->comp[i].data = strdup(from.name_string.val[i]);
    }
    p->realm.data = strdup(realm);
    p->realm.length = strlen(realm);
    *principal = p;
    return 0;
}
