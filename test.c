#include <stdio.h>
#include "krb5.h"
#include "config_file.h"

int main(int argc, char **argv)
{
  krb5_error_code err;
  krb5_context context;
  krb5_ccache  ccache;
  krb5_creds   cred, out_cred;
#if 0
  k5_cfile *cf;
  char *p;
  krb5_parse_config_file(&cf, "krb5.conf");
  krb5_get_config_tag(cf, "realms ATHENA.MIT.EDU v4_instance_convert mit", &p);
#endif

  err = krb5_init_context (&context);
  if (err)
    abort ();

  err = krb5_cc_default (context, &ccache);
  if (err)
    abort ();

  err = krb5_build_principal (context,
			      &cred.server,
			      strlen("x-dce.pdc.kth.se"),
			      "x-dce.pdc.kth.se",
			      "host",
			      "sisyphus.pdc.kth.se",
			      NULL);
  if (err)
    abort ();
  cred.server->type = KRB5_NT_SRV_HST;
  cred.times.endtime = time (NULL) + 4711;

  err = krb5_get_credentials (context,
			      0,
			      ccache,
			      &cred,
			      &out_cred);
  if (err)
    abort ();

  krb5_free_context ();

  return 0;
}
