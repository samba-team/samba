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
  unsigned char buf[1024];
  int len;

  ap.pvno = 5;
  ap.msg_type = krb_ap_req;
  memset(&ap.ap_options, 0, sizeof(ap.ap_options));
  if (ap_options & AP_OPTS_USE_SESSION_KEY)
    ap.ap_options.use_session_key = 1;
  if (ap_options & AP_OPTS_MUTUAL_REQUIRED)
    ap.ap_options.mutual_required = 1;
  
  ap.ticket.tkt_vno = 5;
  ap.ticket.realm = malloc(cred->server->realm.length + 1);
  strncpy(ap.ticket.realm, cred->server->realm.data,
	  cred->server->realm.length);
  ap.ticket.realm[cred->server->realm.length] = '\0';
  krb5_principal2principalname(&ap.ticket.sname, cred->server);

  decode_Ticket(cred->ticket.data, cred->ticket.length, &t);

  ap.ticket.enc_part = t.enc_part;

  ap.authenticator.etype = ap.ticket.enc_part.etype;
  ap.authenticator.kvno  = NULL;
  ap.authenticator.cipher = authenticator;

  ret->length = encode_AP_REQ(buf + sizeof(buf) - 1, sizeof(buf), &ap);

  ret->data = malloc(ret->length);
  memcpy (ret->data, buf + sizeof(buf) - ret->length, ret->length);

  return 0;
}
