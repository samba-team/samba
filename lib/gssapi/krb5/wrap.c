#include "gssapi_locl.h"

RCSID("$Id$");

OM_uint32 gss_wrap
           (OM_uint32 * minor_status,
            const gss_ctx_id_t context_handle,
            int conf_req_flag,
            gss_qop_t qop_req,
            const gss_buffer_t input_message_buffer,
            int * conf_state,
            gss_buffer_t output_message_buffer
           )
{
  u_char *p;
  size_t len;
  struct md5 md5;
  u_char hash[16];
  des_key_schedule schedule;
  des_cblock key;
  des_cblock zero;
  size_t padlength;
  int i;
  int32_t seq_number;

  padlength = 8 - (input_message_buffer->length % 8);

  len = input_message_buffer->length + 8 + padlength + 28
    + GSS_KRB5_MECHANISM->length;
  output_message_buffer->length = len;
  output_message_buffer->value  = malloc (len);
  if (output_message_buffer->value == NULL)
    return GSS_S_FAILURE;

  p = output_message_buffer->value;
  memcpy (p, "\x60\x07\x06\x05", 4);
  p += 4;
  memcpy (p, GSS_KRB5_MECHANISM->elements, GSS_KRB5_MECHANISM->length);
  p += GSS_KRB5_MECHANISM->length;
  /* TOK_ID */
  memcpy (p, "\x02\x01", 2);
  p += 2;
  /* SGN_ALG */
  memcpy (p, "\x00\x00", 2);
  p += 2;
  /* SEAL_ALG */
  memcpy (p, "\x00\x00", 2);
  p += 2;
  /* Filler */
  memcpy (p, "\xff\xff", 2);
  p += 2;

  /* fill in later */
  memset (p, 0, 16);
  p += 16;

  /* confounder + data + pad */
  des_new_random_key((des_cblock*)p);
  memcpy (p + 8, input_message_buffer->value,
	  input_message_buffer->length);
  memset (p + 8 + input_message_buffer->length, padlength, padlength);

  /* checksum */
  md5_init (&md5);
  md5_update (&md5, p - 24, 8);
  md5_update (&md5, p + 8, input_message_buffer->length + padlength);
  md5_finito (&md5, hash);

  memset (&zero, 0, sizeof(zero));
  memcpy (&key, context_handle->auth_context->key.keyvalue.data,
	  sizeof(key));
  des_set_key (&key, schedule);
  des_cbc_cksum ((des_cblock *)hash,
		 (des_cblock *)hash, sizeof(hash), schedule, &zero);
  memcpy (p - 8, hash, 8);

  /* sequence number */
  krb5_auth_getlocalseqnumber (gssapi_krb5_context,
			       context_handle->auth_context,
			       &seq_number);

  p -= 16;
  p[0] = (seq_number >> 0)  & 0xFF;
  p[1] = (seq_number >> 8)  & 0xFF;
  p[2] = (seq_number >> 16) & 0xFF;
  p[3] = (seq_number >> 24) & 0xFF;
  memset (p + 4,
	  (context_handle->more_flags & LOCAL) ? 0 : 0xFF,
	  4);

  des_set_key (&key, schedule);
  des_cbc_encrypt ((des_cblock *)p, (des_cblock *)p, 8,
		   schedule, (des_cblock *)(p + 16), DES_ENCRYPT);

  krb5_auth_setlocalseqnumber (gssapi_krb5_context,
			       context_handle->auth_context,
			       ++seq_number);

  /* encrypt the data */
  p += 16;

  memset (&zero, 0, sizeof(zero));
  memcpy (&key, context_handle->auth_context->key.keyvalue.data,
	  sizeof(key));
  for (i = 0; i < sizeof(key); ++i)
    key[i] ^= 0xf0;
  des_set_key (&key, schedule);
  des_cbc_encrypt ((des_cblock *)p,
		   (des_cblock *)p,
		   8 + input_message_buffer->length + padlength,
		   schedule,
		   &zero,
		   DES_ENCRYPT);

  memset (key, 0, sizeof(key));
  memset (schedule, 0, sizeof(schedule));

  return GSS_S_COMPLETE;
}
