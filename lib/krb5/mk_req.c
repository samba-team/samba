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
  krb5_data realm_data;

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

  return krb5_mk_req_extended (context,
			       auth_context,
			       ap_req_options,
			       in_data,
			       cred,
			       outbuf);
}
