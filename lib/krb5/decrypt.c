#include <krb5_locl.h>
#include "crc.h"

RCSID("$Id$");

krb5_error_code
krb5_decrypt (krb5_context context,
	      void *ptr,
	      size_t len,
	      const krb5_keyblock *keyblock,
	      krb5_data *result)
{
  u_char *p = (u_char *)ptr;
  u_int32_t my_crc, her_crc;
  des_cblock key;
  des_key_schedule schedule;

  memcpy (&key, keyblock->contents.data, sizeof(key));
  des_set_key (&key, schedule);
  des_cbc_encrypt ((des_cblock *)ptr, (des_cblock *)ptr, len, 
		   schedule, &key, DES_DECRYPT);

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
