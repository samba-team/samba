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
  Checksum *c_opt;

  if (*auth_context == NULL) {
      r = krb5_auth_con_init(context, auth_context);
      if (r)
	  return r;
  }

  copy_EncryptionKey(&in_creds->session,
		     &(*auth_context)->key);

  if (in_data) {

      r = krb5_create_checksum (context,
				(*auth_context)->cksumtype,
				in_data->data,
				in_data->length,
				&(*auth_context)->key,
				&c);
      c_opt = &c;
  } else {
      c_opt = NULL;
  }
  
  r = krb5_build_authenticator (context,
				*auth_context,
				in_creds,
				c_opt,
				&auth,
				&authenticator);
  if (r)
    return r;

  r = krb5_build_ap_req (context, in_creds, ap_req_options,
			 authenticator, outbuf);
  return r;
}
