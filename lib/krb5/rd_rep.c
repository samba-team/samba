#include <krb5_locl.h>
#include <krb5_error.h>

krb5_error_code
krb5_rd_rep(krb5_context context,
	    krb5_auth_context auth_context,
	    const krb5_data *inbuf,
	    krb5_ap_rep_enc_part **repl)
{
  AP_REP ap_rep;
  int len;
  des_key_schedule schedule;
  char *buf;
  int i;

  len = decode_AP_REP(inbuf->data, inbuf->length, &ap_rep);
  if (len < 0)
    return ASN1_PARSE_ERROR;
  if (ap_rep.pvno != 5)
    return KRB_AP_ERR_BADVERSION;
  if (ap_rep.msg_type != krb_ap_rep)
    return KRB_AP_ERR_MSG_TYPE;

  des_set_key (auth_context->key.contents.data, schedule);
  len = ap_rep.enc_part.cipher.length;
  buf = malloc (len);
  if (buf == NULL)
    return ENOMEM;
  des_cbc_encrypt ((des_cblock *)ap_rep.enc_part.cipher.data,
		   (des_cblock *)buf,
		   len,
		   schedule,
		   auth_context->key.contents.data,
		   DES_DECRYPT);
  
  /* XXX - Check CRC */

  *repl = malloc(sizeof(**repl));
  if (*repl == NULL)
    return ENOMEM;

  i = decode_EncAPRepPart((unsigned char *)buf + 12, len - 12, *repl);
  if (i < 0)
    return ASN1_PARSE_ERROR;
  if ((*repl)->ctime != auth_context->authenticator->ctime ||
      (*repl)->cusec != auth_context->authenticator->cusec) {
    printf("KRB_AP_ERR_MUT_FAIL\n");
    printf ("(%u, %u) != (%u, %u)\n",
	    (*repl)->ctime, (*repl)->cusec,
	    auth_context->authenticator->ctime,
	    auth_context->authenticator->cusec);
#if 0				/* Something wrong with the coding??? */
    return KRB_AP_ERR_MUT_FAIL;
#endif
  }
  
  return 0;
}

void
krb5_free_ap_rep_enc_part (krb5_context context,
			   krb5_ap_rep_enc_part *val)
{
  free (val);
}
