#include "kuser_locl.h"


int
main (int argc, char **argv)
{
  krb5_error_code err;
  krb5_context context;
  krb5_ccache  ccache;
  krb5_principal principal;
  krb5_principal server;
  krb5_creds cred;
  krb5_preauthtype pre_auth[] = {KRB5_PADATA_ENC_TIMESTAMP};

  err = krb5_init_context (&context);
  if (err){
      fprintf(stderr, "%s\n", krb5_get_err_text(context, err));;
      abort();
  }				  
  
  err = krb5_cc_default (context, &ccache);
  if (err){
      fprintf(stderr, "%s\n", krb5_get_err_text(context, err));;
      abort();
  }				  

  
  if(argv[1]){
      err = krb5_parse_name (context, argv[1], &principal);
      if (err){
	  fprintf(stderr, "%s\n", krb5_get_err_text(context, err));;
	  abort();
      }				  
      
  }else{
      char *realm;
      struct passwd *pw;
      krb5_get_lrealm(&realm);
      pw = getpwuid(getuid());
      krb5_build_principal(context, &principal, strlen(realm), realm,
			   pw->pw_name, NULL);

      free(realm);
  }

  err = krb5_cc_initialize (context, ccache, principal);
  if (err){
      fprintf(stderr, "%s\n", krb5_get_err_text(context, err));;
      abort();
  }				  

  cred.client = principal;
  cred.times.endtime = 0;

  err = krb5_build_principal_ext (context,
				  &cred.server,
				  principal->realm.length,
				  principal->realm.data,
				  strlen("krbtgt"),
				  "krbtgt",
				  principal->realm.length, 
				  principal->realm.data,
				  NULL);
  if (err){
      fprintf(stderr, "%s\n", krb5_get_err_text(context, err));;
      abort();
  }				  
  cred.server->type = KRB5_NT_SRV_INST;

  err = krb5_get_in_tkt_with_password (context,
				       0,
				       NULL,
				       NULL,
				       /*NULL*/ pre_auth,
				       NULL,
				       ccache,
				       &cred,
				       NULL);
  if (err){
      fprintf(stderr, "%s\n", krb5_get_err_text(context, err));;
      abort();
  }				  
  
  krb5_free_context (context);
  return 0;
}
