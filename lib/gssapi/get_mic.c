#include "gssapi_locl.h"
#include <des.h>
#include <md5.h>

RCSID("$Id$");

OM_uint32 gss_get_mic
           (OM_uint32 * minor_status,
            const gss_ctx_id_t context_handle,
            gss_qop_t qop_req,
            const gss_buffer_t message_buffer,
            gss_buffer_t message_token
           )
{
  u_char *p;
  size_t len;
  struct md5 md5;
  u_char hash[16];
  des_key_schedule schedule;
  des_cblock key;
  des_cblock zero;

  len = 28 + GSS_KRB5_MECHANISM->length;
  message_token->length = len;
  message_token->value  = malloc (len);
  if (message_token->value == NULL)
    return GSS_S_FAILURE;

  p = message_token->value;
  memcpy (p, "\x60\x07\x06\x05", 4);
  p += 4;
  memcpy (p, GSS_KRB5_MECHANISM->elements, GSS_KRB5_MECHANISM->length);
  p += GSS_KRB5_MECHANISM->length;
  memcpy (p, "\x01\x01", 2);
  p += 2;
  memcpy (p, "\x00\x00", 2);
  p += 2;
  memcpy (p, "\xff\xff\xff\xff", 4);
  p += 4;

  memset (p, 0, 16);
  p += 16;
  
  md5_init (&md5);
  md5_update (&md5, p - 24, 8);
  md5_update (&md5, message_buffer->value,
	      message_buffer->length);
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
