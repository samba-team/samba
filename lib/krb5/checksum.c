#include <krb5_locl.h>
#include <krb5_error.h>
#include "md4.h"

krb5_error_code
krb5_create_checksum (krb5_context context,
		      krb5_cksumtype type,
		      void *ptr,
		      size_t len,
		      Checksum *result)
{
  struct md4 m;

  if (type != CKSUMTYPE_RSA_MD4)
    abort ();

  result->cksumtype = CKSUMTYPE_RSA_MD4;
  result->checksum.length = 16;
  result->checksum.data   = malloc(16);
  if (result->checksum.data == NULL)
    return ENOMEM;

  md4_init(&m);
  md4_update(&m, ptr, len);
  md4_finito (&m, result->checksum.data);
  return 0;
}
