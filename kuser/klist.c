/*
 * Copyright (c) 1997, 1998 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 * All rights reserved. 
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions 
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright 
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright 
 *    notice, this list of conditions and the following disclaimer in the 
 *    documentation and/or other materials provided with the distribution. 
 *
 * 3. All advertising materials mentioning features or use of this software 
 *    must display the following acknowledgement: 
 *      This product includes software developed by Kungliga Tekniska 
 *      Högskolan and its contributors. 
 *
 * 4. Neither the name of the Institute nor the names of its contributors 
 *    may be used to endorse or promote products derived from this software 
 *    without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE 
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS 
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT 
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY 
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF 
 * SUCH DAMAGE. 
 */

#include "kuser_locl.h"

RCSID("$Id$");

static char*
printable_time(time_t t)
{
    static char s[128];
    strcpy(s, ctime(&t)+ 4);
    s[15] = 0;
    return s;
}

static char*
printable_time_long(time_t t)
{
    static char s[128];
    strcpy(s, ctime(&t)+ 4);
    s[20] = 0;
    return s;
}

static void
print_cred(krb5_context context, krb5_creds *cred)
{
    char *str;
    krb5_error_code ret;
    int32_t sec;

    krb5_timeofday (context, &sec);

    if(cred->times.starttime)
	printf ("%s  ", printable_time(cred->times.starttime));
    else
	printf ("%s  ", printable_time(cred->times.authtime));
    
    if(cred->times.endtime > sec)
	printf ("%s  ", printable_time(cred->times.endtime));
    else
	printf ("%-15s  ", ">>>Expired<<<");
    ret = krb5_unparse_name (context, cred->server, &str);
    if (ret)
	krb5_err(context, 1, ret, "krb5_unparse_name");
    printf ("%s\n", str);
    free (str);
}

static void
print_cred_verbose(krb5_context context, krb5_creds *cred)
{
    int j;
    char *str;
    krb5_error_code ret;
    int first_flag;
    int32_t sec;

    krb5_timeofday (context, &sec);

    ret = krb5_unparse_name(context, cred->server, &str);
    if(ret)
	exit(1);
    printf("Server: %s\n", str);
    free (str);
    {
	Ticket t;
	size_t len;
	char *s;
	decode_Ticket(cred->ticket.data, cred->ticket.length, &t, &len);
	krb5_etype_to_string(context, t.enc_part.etype, &s);
	printf("Ticket etype: %s", s);
	free(s);
	if(t.enc_part.kvno)
	    printf(", kvno %d", *t.enc_part.kvno);
	printf("\n");
	free_Ticket(&t);
    }
    krb5_keytype_to_string(context, cred->session.keytype, &str);
    printf("Session key: %s\n", str);
    free(str);
    printf("Auth time:  %s\n", printable_time_long(cred->times.authtime));
    if(cred->times.authtime != cred->times.starttime)
	printf("Start time: %s\n", printable_time_long(cred->times.starttime));
    printf("End time:   %s", printable_time_long(cred->times.endtime));
    if(sec > cred->times.endtime)
	printf(" (expired)");
    printf("\n");
    if(cred->flags.b.renewable)
	printf("Renew till: %s\n", 
	       printable_time_long(cred->times.renew_till));
    printf("Ticket flags: ");
#define PRINT_FLAG2(f, s) if(cred->flags.b.f) { if(!first_flag) printf(", "); printf("%s", #s); first_flag = 0; }
#define PRINT_FLAG(f) PRINT_FLAG2(f, f)
    first_flag = 1;
    PRINT_FLAG(forwardable);
    PRINT_FLAG(forwarded);
    PRINT_FLAG(proxiable);
    PRINT_FLAG(proxy);
    PRINT_FLAG2(may_postdate, may-postdate);
    PRINT_FLAG(postdated);
    PRINT_FLAG(invalid);
    PRINT_FLAG(renewable);
    PRINT_FLAG(initial);
    PRINT_FLAG2(pre_authent, pre-authenticated);
    PRINT_FLAG2(hw_authent, hw-authenticated);
    PRINT_FLAG2(transited_policy_checked, transited-policy-checked);
    PRINT_FLAG2(ok_as_delegate, ok-as-delegate);
    PRINT_FLAG(anonymous);
    printf("\n");
    printf("Addresses: ");
    for(j = 0; j < cred->addresses.len; j++){
	if(j) printf(", ");
	switch(cred->addresses.val[j].addr_type){
	case KRB5_ADDRESS_INET : {
	    struct in_addr a;
	    unsigned long foo;

	    k_get_int (cred->addresses.val[j].address.data,
		       &foo, 4);
	    a.s_addr = htonl(foo);
	    
	    printf("IPv4: %s", inet_ntoa(a));
	    break;
	}
#if defined(AF_INET6) && defined(HAVE_INET_NTOP) && defined(INET6_ADDRSTRLEN)
	case KRB5_ADDRESS_INET6: {
	    char foo[INET6_ADDRSTRLEN];

	    printf("IPv6: %s", inet_ntop(AF_INET6,
					 cred->addresses.val[j].address.data,
					 foo, sizeof(foo)));
	    break;
	}
#endif
	default:{
	    char *s;
	    int i;
	    krb5_address *a = &cred->addresses.val[j];
	    s = malloc(a->address.length * 2 + 1);
	    for(i = 0; i < a->address.length; i++)
		sprintf(s + 2*i, "%02x", ((char*)a->address.data)[i]);
	    printf("%d/%s", cred->addresses.val[j].addr_type, s);
	    free(s);
	}
	}
    }
    printf("\n\n");
}

static int version_flag = 0;
static int help_flag = 0;
static int do_verbose = 0;

static struct getargs args[] = {
    { "verbose",		'v', arg_flag, &do_verbose,
      "Verbose output", NULL },
    { "version", 		0,   arg_flag, &version_flag, 
      "print version", NULL },
    { "help",			0,   arg_flag, &help_flag, 
      NULL, NULL}
};

static void
usage (int ret)
{
    arg_printusage (args,
		    sizeof(args)/sizeof(*args),
		    NULL,
		    "");
    exit (ret);
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
    int optind = 0;

    set_progname (argv[0]);

    if(getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optind))
	usage(1);
    
    if (help_flag)
	usage (0);

    if(version_flag){
	printf("%s (%s-%s)\n", __progname, PACKAGE, VERSION);
	exit(0);
    }

    argc -= optind;
    argv += optind;

    if (argc != 0)
	usage (1);

    ret = krb5_init_context (&context);
    if (ret)
	krb5_err(context, 1, ret, "krb5_init_context");

    ret = krb5_cc_default (context, &ccache);
    if (ret)
	krb5_err (context, 1, ret, "krb5_cc_default");

    ret = krb5_cc_get_principal (context, ccache, &principal);
    if(ret == ENOENT)
	krb5_errx(context, 1, "No ticket file: %s", 
		  krb5_cc_get_name(context, ccache));
    if (ret)
	krb5_err (context, 1, ret, "krb5_cc_get_principal");

    ret = krb5_unparse_name (context, principal, &str);
    if (ret)
	krb5_err (context, 1, ret, "krb5_unparse_name");

    printf ("Credentials cache: %s\n", krb5_cc_get_name(context, ccache));
    printf ("\tPrincipal: %s\n\n", str);
    free (str);

    if (do_verbose && context->kdc_sec_offset) {
	char buf[BUFSIZ];
	int val;
	int sig;

	val = context->kdc_sec_offset;
	sig = 1;
	if (val < 0) {
	    sig = -1;
	    val = -val;
	}

	unparse_time (val, buf, sizeof(buf));

	printf ("\tKDC time offset: %s%s\n",
		sig == -1 ? "-" : "", buf);
    }

    ret = krb5_cc_start_seq_get (context, ccache, &cursor);
    if (ret)
	krb5_err(context, 1, ret, "krb5_cc_start_seq_get");

    if(!do_verbose)
	printf("  %-15s  %-15s  %s\n", "Issued", "Expires", "Principal");

    while (krb5_cc_next_cred (context,
			      ccache,
			      &creds,
			      &cursor) == 0) {
	if(do_verbose){
	    print_cred_verbose(context, &creds);
	}else{
	    print_cred(context, &creds);
	}
	krb5_free_creds_contents (context, &creds);
    }
    ret = krb5_cc_end_seq_get (context, ccache, &cursor);
    if (ret)
	krb5_err (context, 1, ret, "krb5_cc_end_seq_get");

    ret = krb5_cc_close (context, ccache);
    if (ret)
	krb5_err (context, 1, ret, "krb5_cc_close");

    krb5_free_principal (context, principal);
    krb5_free_context (context);
    return 0;
}
