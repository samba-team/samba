#include "krb5_locl.h"

RCSID("$Id$");

/* XXX */

#ifdef sun
#define memmove(a,b,c) bcopy(b,a,c)
#endif

void
krb5_data_free(krb5_data *p)
{
  if(p->length && p->data)
    free(p->data);
  p->length = 0;
}

krb5_error_code
krb5_data_alloc(krb5_data *p, int len)
{
  krb5_data_free(p);
  p->data = (krb5_pointer)malloc(len);
  if(!p->data)
    return ENOMEM;
  p->length = len; 
  return 0;
}

krb5_error_code
krb5_data_realloc(krb5_data *p, int len)
{
  void *tmp;
  tmp = realloc(p->data, len);
  if(!tmp)
    return ENOMEM;
  p->data = tmp;
  p->length = len;
  return 0;
}

krb5_error_code
krb5_data_copy(krb5_data *p, void *data, size_t len)
{
  krb5_data_free(p);
  p->data = (krb5_pointer)malloc(len);
  if(!p->data)
    return ENOMEM;
  memmove(p->data, data, len);
  p->length = len;
  return 0;
}

