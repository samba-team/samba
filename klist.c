#include <stdio.h>
#include <krb5.h>

int
main (int argc, char **argv)
{
     krb5_error_code err;
     krb5_context context;
     krb5_ccache ccache;
     krb5_principal principal;
     krb5_cc_cursor cursor;
     krb5_creds creds;
     char *str;

     err = krb5_init_context (&context);
     if (err)
	  abort ();

     err = krb5_cc_default (context, &ccache);
     if (err)
	  abort ();

     err = krb5_cc_get_principal (context, ccache, &principal);
     if (err)
	  abort ();

     err = krb5_unparse_name (context, principal, &str);
     if (err)
	  abort ();

     printf ("Principal: %s\n", str);
     free (str);

     err = krb5_cc_start_seq_get (context, ccache, &cursor);
     if (err)
	  abort ();

     while (krb5_cc_next_cred (context,
			       ccache,
			       &creds,
			       &cursor) == 0) {
	  err = krb5_unparse_name (context, creds.server, &str);
	  if (err)
	       abort ();
	  printf ("%s\t", str);
	  free (str);
	  printf ("%s\t", ctime(&creds.times.starttime));
	  printf ("%s\n", ctime(&creds.times.endtime));
     }
     err = krb5_cc_end_seq_get (context, ccache, &cursor);
     if (err)
	  return err;

     err = krb5_cc_close (context, ccache);
     if (err)
	  abort ();


     krb5_free_principal (principal);

     krb5_free_context (context);
     return 0;
}
