#include <krb5_locl.h>

RCSID("$Id$");

krb5_error_code
krb5_mk_req(krb5_context context,
	    krb5_auth_context *auth_context,
	    const krb5_flags ap_req_options,
	    char *service,
	    char *hostname,
	    krb5_data *in_data,
	    krb5_ccache ccache,
	    krb5_data *outbuf)
{
  krb5_error_code r;
  krb5_creds this_cred, *cred;
  char **realms;
  Authenticator *auth;
  krb5_data realm_data, authenticator;
  Checksum c;

  if (*auth_context == NULL) {
      r = krb5_auth_con_init(context, auth_context);
      if (r)
	  return r;
  }

  r = krb5_get_host_realm(context, hostname, &realms);
  if (r)
    return r;
  realm_data.length = strlen(*realms);
  realm_data.data   = *realms;

  r = krb5_cc_get_principal(context, ccache, &this_cred.client);
  
  if(r)
      return r;

  r = krb5_build_principal (context, &this_cred.server,
			    strlen(*realms),
			    *realms,
			    service,
			    hostname,
			    NULL);
  if (r)
    return r;
  this_cred.times.endtime = 0;

  r = krb5_get_credentials (context, 0, ccache, &this_cred, &cred);
  if (r)
    return r;

  (*auth_context)->key.keytype = cred->session.keytype;
  krb5_data_copy (&(*auth_context)->key.contents,
		  cred->session.contents.data,
		  cred->session.contents.length);

  r = krb5_create_checksum (context,
			    CKSUMTYPE_RSA_MD4,
			    in_data->data,
			    in_data->length,
			    &c);
  
  r = krb5_build_authenticator (context,
				*auth_context,
				cred,
				&c,
				&auth,
				&authenticator);
  if (r)
    return r;

  r = krb5_build_ap_req (context, cred, ap_req_options,
			 authenticator, outbuf);
  krb5_data_free (&authenticator);
  return r;
}
