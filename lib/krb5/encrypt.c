#include <krb5_locl.h>
#include "crc.h"

RCSID("$Id$");

krb5_error_code
krb5_encrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      krb5_keyblock *keyblock,
	      krb5_data *result)
{
  u_char *p;
  u_long crc;
  size_t sz;
  des_cblock key;
  des_key_schedule schedule;

  sz = len + 12;
  sz = (sz + 7) & ~7;
  p = malloc (sz);
  if (p == NULL)
    return ENOMEM;
  memset (p, 0, sz);
  des_new_random_key((des_cblock*)p);
#if 0
  des_rand_data ((des_cblock*)p, 8);
#endif
  memcpy (p + 12, ptr, len);
  crc_init_table ();
  crc = crc_update (p, sz, 0);
  p[8]  = crc & 0xff;
  p[9]  = (crc >> 8)  & 0xff;
  p[10] = (crc >> 16) & 0xff;
  p[11] = (crc >> 24) & 0xff;
  
  memcpy (&key, keyblock->keyvalue.data, sizeof(key));
  des_set_key (&key, schedule);
  des_cbc_encrypt ((des_cblock *)p, (des_cblock *)p, sz, schedule, &key, DES_ENCRYPT);

  result->data = p;
  result->length = sz;
  return 0;
}
