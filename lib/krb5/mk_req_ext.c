#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_mk_req_extended(krb5_context context,
		     krb5_auth_context *auth_context,
		     const krb5_flags ap_req_options,
		     krb5_data *in_data,
		     krb5_creds *in_creds,
		     krb5_data *outbuf)
{
  krb5_error_code r;
  Authenticator *auth;
  krb5_data authenticator;
  Checksum c;

  if (*auth_context == NULL) {
      r = krb5_auth_con_init(context, auth_context);
      if (r)
	  return r;
  }

  (*auth_context)->key.keytype = in_creds->session.keytype;
  krb5_data_copy (&(*auth_context)->key.keyvalue,
		  in_creds->session.keyvalue.data,
		  in_creds->session.keyvalue.length);

  r = krb5_create_checksum (context,
			    CKSUMTYPE_RSA_MD4,
			    in_data->data,
			    in_data->length,
			    &c);
  
  r = krb5_build_authenticator (context,
				*auth_context,
				in_creds,
				&c,
				&auth,
				&authenticator);
  if (r)
    return r;

  r = krb5_build_ap_req (context, in_creds, ap_req_options,
			 authenticator, outbuf);
  krb5_data_free (&authenticator);
  return r;
}
