#include <stdio.h>
#include <string.h>
#include <krb5.h>

int
main (int argc, char **argv)
{
  krb5_error_code err;
  krb5_context context;
  krb5_ccache  ccache;
  krb5_principal principal;
  krb5_principal server;
  krb5_creds cred;

  err = krb5_init_context (&context);
  if (err)
    abort ();

  err = krb5_cc_default (context, &ccache);
  if (err)
    abort ();

  err = krb5_parse_name (context, argv[1], &principal);
  if (err)
    abort ();

  err = krb5_cc_initialize (context, ccache, principal);
  if (err)
    abort ();

  cred.client = principal;
  cred.times.endtime = time (NULL) + 4711;

  err = krb5_build_principal_ext (context,
				  &cred.server,
				  principal->realm.length,
				  principal->realm.data,
				  strlen("krbtgt"),
				  "krbtgt",
				  principal->realm.length, 
				  principal->realm.data,
				  NULL);
  if (err)
    abort ();
  cred.server->type = KRB5_NT_SRV_INST;

  err = krb5_get_in_tkt_with_password (context,
				       0,
				       NULL,
				       NULL,
				       NULL,
				       NULL,
				       ccache,
				       &cred,
				       NULL);
  if (err)
      abort ();
  
  krb5_free_context (context);
  return 0;
}
