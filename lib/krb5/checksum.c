#include <krb5_locl.h>
#include "md4.h"

RCSID("$Id$");

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

krb5_error_code
krb5_verify_checksum (krb5_context context,
		      void *ptr,
		      size_t len,
		      Checksum *cksum)
{
  struct md4 m;
  u_char csum[16];

  if (cksum->cksumtype != CKSUMTYPE_RSA_MD4)
    return KRB5KRB_AP_ERR_INAPP_CKSUM;
  if (cksum->checksum.length != 16)
    return KRB5KRB_AP_ERR_MODIFIED;

  md4_init (&m);
  md4_update (&m, ptr, len);
  md4_finito (&m, csum);
  if (memcmp (cksum->checksum.data, csum, 16) == 0)
    return 0;
  else
    return KRB5KRB_AP_ERR_MODIFIED;
}
