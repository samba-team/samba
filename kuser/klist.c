#include "kuser_locl.h"

static char*
printable_time(time_t t)
{
    static char s[128];
    strcpy(s, ctime(&t)+ 4);
    s[15] = 0;
    return s;
}

void usage()
{
    fprintf(stderr, "Usage: %s [-v]\n", __progname);
    exit(1);
}

void
print_cred(krb5_context context, krb5_creds *cred)
{
    char *str;
    struct timeval now;
    krb5_error_code ret;

    gettimeofday(&now, NULL);

    printf ("%s  ", printable_time(cred->times.authtime));
    if(cred->times.endtime > now.tv_sec)
	printf ("%s  ", printable_time(cred->times.endtime));
    else
	printf ("%-15s  ", ">>>Expired<<<");
    ret = krb5_unparse_name (context, cred->server, &str);
    if (ret)
	errx (1, "krb5_unparse_name: %s", 
	      krb5_get_err_text(context,ret));
    printf ("%s\n", str);
    free (str);
}

void
print_cred_verbose(krb5_context context, krb5_creds *cred)
{
    int j;
    char *str;
    krb5_error_code ret;
    int first_flag;
    struct timeval now;

    gettimeofday(&now, NULL);

    ret = krb5_unparse_name(context, cred->server, &str);
    if(ret)
	exit(1);
    printf("Server: %s\n", str);
    printf("Session key: type = %d, length = %d\n", 
	   cred->session.keytype, 
	   cred->session.keyvalue.length);
    printf("Auth time:  %s\n", printable_time(cred->times.authtime));
    if(cred->times.authtime != cred->times.starttime)
	printf("Start time: %s\n", printable_time(cred->times.starttime));
    printf("End time:   %s", printable_time(cred->times.endtime));
    if(now.tv_sec > cred->times.endtime)
	printf(" (expired)");
    printf("\n");
    if(cred->flags.b.renewable)
	printf("Renew till: %s\n", 
	       printable_time(cred->times.renew_till));
    printf("Ticket flags: ");
#define PRINT_FLAG(f) if(cred->flags.b. ##f) { if(!first_flag) printf(", "); printf("%s", #f); first_flag = 0; }
    first_flag = 1;
    PRINT_FLAG(forwardable);
    PRINT_FLAG(forwarded);
    PRINT_FLAG(proxiable);
    PRINT_FLAG(proxy);
    PRINT_FLAG(may_postdate);
    PRINT_FLAG(postdated);
    PRINT_FLAG(invalid);
    PRINT_FLAG(renewable);
    PRINT_FLAG(initial);
    PRINT_FLAG(pre_authent);
    PRINT_FLAG(hw_authent);
    printf("\n");
    printf("Addresses: ");
    for(j = 0; j < cred->addresses.len; j++){
	if(j) printf(", ");
	switch(cred->addresses.val[j].addr_type){
	case AF_INET:
	    printf("%s", inet_ntoa(*(struct in_addr*)cred->addresses.val[j].address.data));
	    break;
	default:
	    printf("{ %d %d }", cred->addresses.val[j].addr_type,
		   cred->addresses.val[j].address.length);
	}
    }
    printf("\n\n");
}

int
main (int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    krb5_ccache ccache;
    krb5_principal principal;
    krb5_cc_cursor cursor;
    krb5_creds creds;
    char *str;
    int verbose = 0;
    int c;

    while((c = getopt(argc, argv, "v")) != -1){
	switch(c){
	case 'v':
	    verbose = 1;
	    break;
	default:
	    usage();
	}
    }
    argc -= optind;
    argv += optind;
	

    ret = krb5_init_context (&context);
    if (ret)
	errx (1, "krb5_init_context: %s", krb5_get_err_text(context,ret));

    ret = krb5_cc_default (context, &ccache);
    if (ret)
	errx (1, "krb5_cc_default: %s", krb5_get_err_text(context,ret));

    ret = krb5_cc_get_principal (context, ccache, &principal);
    if (ret)
	errx (1, "krb5_cc_get_principal: %s", krb5_get_err_text(context,ret));

    ret = krb5_unparse_name (context, principal, &str);
    if (ret)
	errx (1, "krb5_unparse_name: %s", krb5_get_err_text(context,ret));

    printf ("Credentials cache: %s\n", krb5_cc_get_name(context, ccache));
    printf ("\tPrincipal: %s\n\n", str);
    free (str);

    ret = krb5_cc_start_seq_get (context, ccache, &cursor);
    if (ret)
	errx (1, "krb5_cc_start_seq_get: %s", krb5_get_err_text(context,ret));

    if(!verbose)
	printf("  %-15s  %-15s  %s\n", "Issued", "Expires", "Principal");

    while (krb5_cc_next_cred (context,
			      ccache,
			      &creds,
			      &cursor) == 0) {
	if(verbose){
	    print_cred_verbose(context, &creds);
	}else{
	    print_cred(context, &creds);
	}
    }
    ret = krb5_cc_end_seq_get (context, ccache, &cursor);
    if (ret)
	errx (1, "krb5_cc_end_seq_get: %s", krb5_get_err_text(context,ret));

    ret = krb5_cc_close (context, ccache);
    if (ret)
	errx (1, "krb5_cc_close: %s", krb5_get_err_text(context,ret));

    krb5_free_principal (context, principal);

    krb5_free_context (context);
    return 0;
}
