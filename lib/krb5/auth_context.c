#include "krb5_locl.h"

krb5_error_code
krb5_auth_con_init(krb5_context context,
		   krb5_auth_context **auth_context)
{
  krb5_auth_context *p;
  p = ALLOC(1, krb5_auth_context);;
  if(!p)
    return ENOMEM;
  memset(p, 0, sizeof(p));
  p->authenticator = ALLOC(1, krb5_authenticator);
  if (!p->authenticator)
    return ENOMEM;
  *auth_context = p;
  return 0;
}

krb5_error_code
krb5_auth_con_free(krb5_context context,
		   krb5_auth_context *auth_context,
		   krb5_flags flags)
{
  free (auth_context->authenticator);
  free (auth_context);
  return 0;
}
