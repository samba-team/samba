#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_rd_rep(krb5_context context,
	    krb5_auth_context auth_context,
	    const krb5_data *inbuf,
	    krb5_ap_rep_enc_part **repl)
{
  krb5_error_code ret;
  AP_REP ap_rep;
  int len;
  des_key_schedule schedule;
  char *buf;
  int i;
  krb5_data data;

  len = decode_AP_REP(inbuf->data, inbuf->length, &ap_rep);
  if (len < 0)
    return ASN1_PARSE_ERROR;
  if (ap_rep.pvno != 5)
    return KRB5KRB_AP_ERR_BADVERSION;
  if (ap_rep.msg_type != krb_ap_rep)
    return KRB5KRB_AP_ERR_MSG_TYPE;

  ret = krb5_decrypt (context,
		      ap_rep.enc_part.cipher.data,
		      ap_rep.enc_part.cipher.length,
		      &auth_context->key,
		      &data);
  if (ret)
    return ret;

  *repl = malloc(sizeof(**repl));
  if (*repl == NULL)
    return ENOMEM;
  i = decode_EncAPRepPart(data.data,
			  data.length,
			  *repl);
  if (i < 0)
    return ASN1_PARSE_ERROR;
  if ((*repl)->ctime != auth_context->authenticator->ctime ||
      (*repl)->cusec != auth_context->authenticator->cusec) {
    printf("KRB5KRB_AP_ERR_MUT_FAIL\n");
    printf ("(%u, %u) != (%u, %u)\n",
	    (*repl)->ctime, (*repl)->cusec,
	    auth_context->authenticator->ctime,
	    auth_context->authenticator->cusec);
#if 0				/* Something wrong with the coding??? */
    return KRB5KRB_AP_ERR_MUT_FAIL;
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
