#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_principal_alloc(krb5_principal *p)
{
  krb5_principal tmp;
  tmp = ALLOC(1, krb5_principal_data);
  if(!tmp)
    return ENOMEM;
  memset(tmp, 0, sizeof(krb5_principal_data));
  *p = tmp;
  return 0;
}

void
krb5_principal_free(krb5_principal principal)
{
  int i;
  for(i = 0; i < principal->ncomp; i++)
    krb5_data_free(&principal->comp[i]);
  free(principal->comp);
  krb5_data_free(&principal->realm);
  free(principal);
}
