#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_build_ap_req (krb5_context context,
		   krb5_creds *cred,
		   krb5_flags ap_options,
		   krb5_data authenticator,
		   krb5_data *ret)
{
  AP_REQ ap;
  Ticket t;
  size_t len;
  
  ap.pvno = 5;
  ap.msg_type = krb_ap_req;
  memset(&ap.ap_options, 0, sizeof(ap.ap_options));
  ap.ap_options.use_session_key = (ap_options & AP_OPTS_USE_SESSION_KEY) > 0;
  ap.ap_options.mutual_required = (ap_options & AP_OPTS_MUTUAL_REQUIRED) > 0;
  
  ap.ticket.tkt_vno = 5;
  copy_Realm(&cred->server->realm, &ap.ticket.realm);
  copy_PrincipalName(&cred->server->name, &ap.ticket.sname);

  decode_Ticket(cred->ticket.data, cred->ticket.length, &t, &len);
  copy_EncryptedData(&t.enc_part, &ap.ticket.enc_part);
  free_Ticket(&t);

  ap.authenticator.etype = ap.ticket.enc_part.etype;
  ap.authenticator.kvno  = NULL;
  ap.authenticator.cipher = authenticator;

  ret->length = length_AP_REQ(&ap);
  ret->data = malloc(ret->length);
  encode_AP_REQ((char *)ret->data + ret->length - 1, ret->length, &ap, &len);
  free_AP_REQ(&ap);
  
  return 0;
}
