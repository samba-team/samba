#include "kuser_locl.h"
RCSID("$Id$");

static void
usage (void)
{
    errx (1, "Usage: %s", __progname);
}

int
main (int argc, char **argv)
{
  krb5_error_code err;
  krb5_context context;
  krb5_ccache  ccache;
  krb5_principal principal;
  krb5_principal server;
  krb5_creds cred;

  set_progname (argv[0]);

  err = krb5_init_context (&context);
  if (err)
      errx (1, "krb5_init_context: %s", krb5_get_err_text(context, err));
  
  err = krb5_cc_default (context, &ccache);
  if (err)
      errx (1, "krb5_cc_default: %s", krb5_get_err_text(context, err));

  err = krb5_cc_destroy (context, ccache);
  if (err)
      errx (1, "krb5_cc_destroy: %s", krb5_get_err_text(context, err));
  krb5_free_context (context);
  return 0;
}
