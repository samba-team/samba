#include "krb5_locl.h"

RCSID("$Id$");

/*
 * The format seems to be:
 * client -> server
 *
 * 4 bytes - length
 * KRB5_SENDAUTH_V1.0 (including zero)
 * 4 bytes - length
 * protocol string (with terminating zero)
 *
 * server -> client
 * 4 bytes - length (0 = OK, else length of error)
 * (error)
 *
 * client -> server
 * 4 bytes - length
 * AP-REQ
 *
 * server -> client
 * 4 bytes - length
 * AP-REP
 */

krb5_error_code
krb5_sendauth(krb5_context context,
	      krb5_auth_context *auth_context,
	      krb5_pointer p_fd,
	      char *appl_version,
	      krb5_principal client,
	      krb5_principal server,
	      krb5_flags ap_req_options,
	      krb5_data *in_data,
	      krb5_creds *in_creds,
	      krb5_ccache ccache,
	      /*krb5_error*/ void **error,
	      krb5_ap_rep_enc_part **rep_result,
	      krb5_creds **out_creds)
{
  krb5_error_code ret;
  int fd = *((int *)p_fd);
  u_int32_t len, net_len;
  const char *version = KRB5_SENDAUTH_VERSION;
  u_char repl;
  krb5_data ap_req;
  krb5_creds this_cred;
  krb5_creds *creds;

  len = strlen(version) + 1;
  net_len = htonl(len);
  if (krb5_net_write (context, fd, &net_len, 4) != 4
      || krb5_net_write (context, fd, version, len) != len)
    return errno;

  len = strlen(appl_version) + 1;
  net_len = htonl(len);
  if (krb5_net_write (context, fd, &net_len, 4) != 4
      || krb5_net_write (context, fd, appl_version, len) != len)
    return errno;

  if (krb5_net_read (context, fd, &repl, sizeof(repl)) != sizeof(repl))
    return errno;

  if (repl != 0)
    return KRB5_SENDAUTH_BADRESPONSE; /* XXX */

  if (in_creds == NULL) {
    if (client == NULL) {
      ret = krb5_cc_get_principal (context, ccache, &client);
      if (ret)
	return ret;
    }
    this_cred.client = client;
    this_cred.server = server;
    this_cred.times.endtime = 0;
    this_cred.ticket.length = 0;
    in_creds = &this_cred;
  }
  if (in_creds->ticket.length == 0) {
    ret = krb5_get_credentials (context, 0, ccache, in_creds, &creds);
    if (ret)
      return ret;
  } else {
    creds = in_creds;
  }
  if (out_creds)
    *out_creds = creds;

  ret = krb5_mk_req_extended (context,
			      auth_context,
			      ap_req_options,
			      in_data,
			      creds,
			      &ap_req);
  if (ret)
    return ret;

  ret = krb5_write_message (context,
			    p_fd,
			    &ap_req);
  if (ret)
      return ret;

  krb5_data_free (&ap_req);

  if (krb5_net_read (context, fd, &len, 4) != 4)
    return errno;

  if (len != 0)
    return KRB5_SENDAUTH_REJECTED;

  if (ap_req_options & AP_OPTS_MUTUAL_REQUIRED) {
    krb5_data ap_rep;
    krb5_ap_rep_enc_part *ignore;

    krb5_data_zero (&ap_rep);
    ret = krb5_read_message (context,
			     p_fd,
			     &ap_rep);
    if (ret)
	return ret;

    ret = krb5_rd_rep (context, *auth_context, &ap_rep,
		       rep_result ? rep_result : &ignore);
    if (ret)
      return ret;
    if (rep_result == NULL)
      krb5_free_ap_rep_enc_part (context, ignore);
    krb5_data_free (&ap_rep);
  }
  return 0;
}
