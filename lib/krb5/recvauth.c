#include "krb5_locl.h"

RCSID("$Id$");

krb5_error_code
krb5_recvauth(krb5_context context,
	      krb5_auth_context *auth_context,
	      krb5_pointer p_fd,
	      char *appl_version,
	      krb5_principal server,
	      int32_t flags,
	      krb5_keytab keytab,
	      krb5_ticket **ticket)
{
  krb5_error_code ret;
  const char *version = "KRB5_SENDAUTH_V1.0";
  char her_version[19];		/* Size ^ */
  char *her_appl_version;
  int fd = *((int *)p_fd);
  u_int32_t len;
  u_char repl;
  krb5_data data;
  krb5_flags ap_options;

  if (krb5_net_read (context, fd, &len, 4) != 4)
    return errno;
  len = ntohl(len);
  if (len != sizeof(her_version)
      || krb5_net_read (context, fd, her_version, len) != len
      || strcmp (version, her_version)) {
    repl = 1;
    krb5_net_write (context, fd, &repl, 1);
    return KRB5_SENDAUTH_BADAUTHVERS;
  }

  if (krb5_net_read (context, fd, &len, 4) != 4)
    return errno;
  len = ntohl(len);
  if (len != strlen(appl_version) + 1) {
    repl = 2;
    krb5_net_write (context, fd, &repl, 1);
    return KRB5_SENDAUTH_BADAPPLVERS;
  }
  her_appl_version = malloc (len);
  if (her_appl_version == NULL) {
    repl = 2;
    krb5_net_write (context, fd, &repl, 1);
    return ENOMEM;
  }
  if (krb5_net_read (context, fd, her_appl_version, len) != len
      || strcmp (appl_version, her_appl_version)) {
    repl = 2;
    krb5_net_write (context, fd, &repl, 1);
    free (her_appl_version);
    return KRB5_SENDAUTH_BADAPPLVERS;
  }
  free (her_appl_version);

  repl = 0;
  if (krb5_net_write (context, fd, &repl, 1) != 1)
    return errno;

  if (krb5_net_read (context, fd, &len, 4) != 4)
    return errno;

  len = ntohl(len);
  data.length = len;
  data.data = malloc (len);
  if (data.data == NULL)
    return ENOMEM;

  if (krb5_net_read (context, fd, data.data, len) != len)
    return errno;

  ret = krb5_rd_req (context,
		     auth_context,
		     &data,
		     server,
		     keytab,
		     &ap_options,
		     ticket);
  krb5_data_free (&data);
  if (ret)
    return ret;

  len = 0;
  if (krb5_net_write (context, fd, &len, 4) != 4)
    return errno;

  if (ap_options & AP_OPTS_MUTUAL_REQUIRED) {
    ret = krb5_mk_rep (context, auth_context, &data);
    if (ret)
      return ret;

    len = htonl(data.length);
    if (krb5_net_write (context, fd, &len, 4) != 4
	|| krb5_net_write (context, fd, data.data, data.length) != data.length)
      return errno;
    krb5_data_free (&data);
  }
  return 0;
}
