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
  des_rand_data (p, 8);
  memcpy (p + 12, ptr, len);
  crc_init_table ();
  crc = crc_update (p, sz, 0);
  p[8]  = crc & 0xff;
  p[9]  = (crc >> 8)  & 0xff;
  p[10] = (crc >> 16) & 0xff;
  p[11] = (crc >> 24) & 0xff;
  
  memcpy (&key, keyblock->contents.data, sizeof(key));
  des_set_key (&key, schedule);
  des_cbc_encrypt ((des_cblock *)p, (des_cblock *)p, sz, schedule, &key, DES_ENCRYPT);

  result->data = p;
  result->length = sz;
  return 0;
}

krb5_error_code
krb5_decrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      krb5_keyblock *keyblock,
	      krb5_data *result)
{
  u_char *p = (u_char *)ptr;
  u_long my_crc, her_crc;
  des_cblock key;
  des_key_schedule schedule;

  memcpy (&key, keyblock->contents.data, sizeof(key));
  des_set_key (&key, schedule);
  des_cbc_encrypt ((des_cblock *)ptr, (des_cblock *)ptr, len, schedule, &key, DES_DECRYPT);

  her_crc = (p[11] << 24) | (p[10] << 16) | (p[9] << 8) | (p[8] << 0);
  memset (p + 8, 0, sizeof(her_crc));
  crc_init_table ();
  my_crc = crc_update (ptr, len, 0);
  if (my_crc != her_crc)
    return KRB5KRB_AP_ERR_BAD_INTEGRITY;
  result->length = len - 12;
  result->data = malloc(result->length);
  if (result->data == NULL)
    return ENOMEM;
  memcpy (result->data, (u_char *)ptr + 12, result->length);
  return 0;
}
