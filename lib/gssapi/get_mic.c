#include "gssapi_locl.h"

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
  struct md5 md5;
  u_char hash[16];
  des_key_schedule schedule;
  des_cblock key;
  des_cblock zero;
  int32_t seq_number;
  size_t len, total_len;

  gssapi_krb5_encap_length (22, &len, &total_len);

  message_token->length = total_len;
  message_token->value  = malloc (total_len);
  if (message_token->value == NULL)
    return GSS_S_FAILURE;

  p = gssapi_krb5_make_header(message_token->value,
			      len,
			      "\x01\x01");

  memcpy (p, "\x00\x00", 2);
  p += 2;
  memcpy (p, "\xff\xff\xff\xff", 4);
  p += 4;

  /* Fill in later */
  memset (p, 0, 16);
  p += 16;

  /* checksum */
  md5_init (&md5);
  md5_update (&md5, p - 24, 8);
  md5_update (&md5, message_buffer->value,
	      message_buffer->length);
  md5_finito (&md5, hash);

  memset (&zero, 0, sizeof(zero));
#if 0
  memcpy (&key, context_handle->auth_context->key.keyvalue.data,
	  sizeof(key));
#endif
  memcpy (&key, context_handle->auth_context->local_subkey.keyvalue.data,
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
		   schedule, (des_cblock *)(p + 8), DES_ENCRYPT);

  krb5_auth_setlocalseqnumber (gssapi_krb5_context,
			       context_handle->auth_context,
			       ++seq_number);
  
  memset (key, 0, sizeof(key));
  memset (schedule, 0, sizeof(schedule));
  
  return GSS_S_COMPLETE;
}
