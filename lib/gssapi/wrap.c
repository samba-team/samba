#include "gssapi_locl.h"
#include <des.h>
#include <md5.h>

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

  len = input_message_buffer->length + 28 + GSS_KRB5_MECHANISM->length;
  output_message_buffer->length = len;
  output_message_buffer->value  = malloc (len);
  if (output_message_buffer->value == NULL)
    return GSS_S_FAILURE;

  p = output_message_buffer->value;
  memcpy (p, "\x60\x07\x06\x05", 4);
  p += 4;
  memcpy (p, GSS_KRB5_MECHANISM->elements, GSS_KRB5_MECHANISM->length);
  p += GSS_KRB5_MECHANISM->length;
  memcpy (p, "\x02\x01", 2);
  p += 2;
  memcpy (p, "\x00\x00", 2);
  p += 2;
  memcpy (p, "\xff\xff", 2);
  p += 2;
  memcpy (p, "\xff\xff", 2);
  p += 2;

  memset (p, 0, 16);
  p += 16;
  memcpy (p, input_message_buffer->value,
	  input_message_buffer->length);
  
  md5_init (&md5);
  md5_update (&md5, p - 24, 8);
  md5_update (&md5, p, input_message_buffer->length);
  md5_finito (&md5, hash);

  memset (&zero, 0, sizeof(zero));
  memcpy (&key, context_handle->auth_context->key.contents.data,
	  sizeof(key));
  des_set_key (&key, schedule);
  des_cbc_cksum ((des_cblock *)hash,
		 (des_cblock *)hash, sizeof(hash), schedule, &zero);
  memcpy (p - 8, hash, 8);
  return GSS_S_COMPLETE;
}
