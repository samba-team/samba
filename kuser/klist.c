#include "kuser_locl.h"

static char*
printable_time(time_t t)
{
    static char s[128];
    strcpy(s, ctime(&t)+ 4);
    s[15] = 0;
    return s;
}


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
    struct timeval now;

    err = krb5_init_context (&context);
    if (err)
	errx (1, "krb5_init_context: %s", krb5_get_err_text(context,err));

    err = krb5_cc_default (context, &ccache);
    if (err)
	errx (1, "krb5_cc_default: %s", krb5_get_err_text(context,err));

    err = krb5_cc_get_principal (context, ccache, &principal);
    if (err)
	errx (1, "krb5_cc_get_principal: %s", krb5_get_err_text(context,err));

    err = krb5_unparse_name (context, principal, &str);
    if (err)
	errx (1, "krb5_unparse_name: %s", krb5_get_err_text(context,err));

    printf ("Credentials cache: %s\n", krb5_cc_get_name(context, ccache));
    printf ("\tPrincipal: %s\n\n", str);
    free (str);

    err = krb5_cc_start_seq_get (context, ccache, &cursor);
    if (err)
	errx (1, "krb5_cc_start_seq_get: %s", krb5_get_err_text(context,err));

    printf("  %-15s  %-15s  %s\n", "Issued", "Expires", "Principal");

    gettimeofday(&now, NULL);

    while (krb5_cc_next_cred (context,
			      ccache,
			      &creds,
			      &cursor) == 0) {
	printf ("%s  ", printable_time(creds.times.authtime));
	if(creds.times.endtime > now.tv_sec)
	    printf ("%s  ", printable_time(creds.times.endtime));
	else
	    printf ("%-15s  ", ">>>Expired<<<");
	err = krb5_unparse_name (context, creds.server, &str);
	if (err)
	    errx (1, "krb5_unparse_name: %s", krb5_get_err_text(context,err));
	printf ("%s\n", str);
	free (str);
    }
    err = krb5_cc_end_seq_get (context, ccache, &cursor);
    if (err)
	errx (1, "krb5_cc_end_seq_get: %s", krb5_get_err_text(context,err));

    err = krb5_cc_close (context, ccache);
    if (err)
	errx (1, "krb5_cc_close: %s", krb5_get_err_text(context,err));

    krb5_free_principal (context, principal);

    krb5_free_context (context);
    return 0;
}
