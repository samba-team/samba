/*
 * Copyright (c) 2004 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of the Institute nor the names of its contributors
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

#ifdef HAVE_CONFIG_H
#include <config.h>
RCSID("$Id$");
#endif

#include <stdlib.h>
#include <krb5.h>
#include <roken.h>
#include <getarg.h>
#include <parse_units.h>
#include <parse_time.h>

static int krbtgt_only_flag;
static char *service_string;
static char *enctype_string;
static char *flags_string;
static char *valid_string;
static int fcache_version;
static int help_flag;
static int version_flag;

static struct getargs args[] = {
    { "krbtgt-only", 0, arg_flag, &krbtgt_only_flag,
      "only copy local krbtgt" },
    { "service", 0, arg_string, &service_string,
      "limit to this service", "principal" },
    { "enctype", 0, arg_string, &enctype_string,
      "limit to this enctype", "enctype" },
    { "flags", 0, arg_string, &flags_string,
      "limit to these flags", "ticketflags" },
    { "valid-for", 0, arg_string, &valid_string, 
      "limit to creds valid for at least this long", "time" },
    { "fcache-version", 0, arg_integer, &fcache_version,
      "file cache version to create" },
    { "version", 0, arg_flag, &version_flag },
    { "help", 'h', arg_flag, &help_flag }
};

static void
usage(int ret)
{
    arg_printusage(args,
		   sizeof(args) / sizeof(*args),
		   NULL,
		   "[from-cache] to-cache");
    exit(ret);
}


#define KRB5_TC_MATCH_SRV_NAMEONLY	(1 << 29)
#define KRB5_TC_MATCH_FLAGS_EXACT	(1 << 28)
#define KRB5_TC_MATCH_FLAGS		(1 << 27)
#define KRB5_TC_MATCH_TIMES_EXACT	(1 << 26)
#define KRB5_TC_MATCH_TIMES		(1 << 25)
#define KRB5_TC_MATCH_AUTHDATA		(1 << 24)
#define KRB5_TC_MATCH_2ND_TKT		(1 << 23)
#define KRB5_TC_MATCH_IS_SKEY		(1 << 22)

static krb5_boolean
krb5_data_equal(const krb5_data *a, const krb5_data *b)
{
    if(a->length != b->length)
	return FALSE;
    return memcmp(a->data, b->data, a->length) == 0;
}

static krb5_boolean
krb5_times_equal(const krb5_times *a, const krb5_times *b)
{
    return a->starttime == b->starttime &&
	a->authtime == b->authtime &&
	a->endtime == b->endtime &&
	a->renew_till == b->renew_till;
}

static krb5_boolean
krb5_compare_creds2(krb5_context context, krb5_flags whichfields,
		    const krb5_creds * mcreds, const krb5_creds * creds)
{
    krb5_boolean match = TRUE;

    if (match && mcreds->server) {
	if (whichfields & (KRB5_TC_DONT_MATCH_REALM | KRB5_TC_MATCH_SRV_NAMEONLY)) 
	    match = krb5_principal_compare_any_realm (context, mcreds->server, 
						      creds->server);
	else
	    match = krb5_principal_compare (context, mcreds->server, 
					    creds->server);
    }

    if (match && mcreds->client) {
	if(whichfields & KRB5_TC_DONT_MATCH_REALM)
	    match = krb5_principal_compare_any_realm (context, mcreds->client, 
						      creds->client);
	else
	    match = krb5_principal_compare (context, mcreds->client, 
					    creds->client);
    }
	    
    if (match && (whichfields & KRB5_TC_MATCH_KEYTYPE))
	match = krb5_enctypes_compatible_keys(context,
					      mcreds->session.keytype,
					      creds->session.keytype);

    if (match && (whichfields & KRB5_TC_MATCH_FLAGS_EXACT))
	match = mcreds->flags.i == creds->flags.i;

    if (match && (whichfields & KRB5_TC_MATCH_FLAGS))
	match = (creds->flags.i & mcreds->flags.i) == mcreds->flags.i;

    if (match && (whichfields & KRB5_TC_MATCH_TIMES_EXACT))
	match = krb5_times_equal(&mcreds->times, &creds->times);
    
    if (match && (whichfields & KRB5_TC_MATCH_TIMES))
	/* compare only expiration times */
	match = (mcreds->times.renew_till <= creds->times.renew_till) &&
	    (mcreds->times.endtime <= creds->times.endtime);

    if (match && (whichfields & KRB5_TC_MATCH_AUTHDATA)) {
	unsigned int i;
	if(mcreds->authdata.len != creds->authdata.len)
	    match = FALSE;
	else
	    for(i = 0; match && i < mcreds->authdata.len; i++)
		match = (mcreds->authdata.val[i].ad_type == 
			 creds->authdata.val[i].ad_type) &&
		    krb5_data_equal(&mcreds->authdata.val[i].ad_data,
				    &creds->authdata.val[i].ad_data);
    }
    if (match && (whichfields & KRB5_TC_MATCH_2ND_TKT))
	match = krb5_data_equal(&mcreds->second_ticket, &creds->second_ticket);

    if (match && (whichfields & KRB5_TC_MATCH_IS_SKEY))
	match = ((mcreds->second_ticket.length == 0) == 
		 (creds->second_ticket.length == 0));

    return match;
}

static krb5_error_code
krb5_cc_next_cred_match(krb5_context context,
			const krb5_ccache id,
			krb5_cc_cursor * cursor,
			krb5_creds * creds,
			krb5_flags whichfields,
			const krb5_creds * mcreds)
{
    krb5_error_code ret;
    while (1) {
	ret = krb5_cc_next_cred(context, id, cursor, creds);
	if (ret)
	    return ret;
	if (mcreds == NULL || krb5_compare_creds2(context, whichfields, mcreds, creds))
	    return 0;
	krb5_free_creds_contents(context, creds);
    }
}

static krb5_error_code
krb5_cc_copy_cache_match(krb5_context context,
			 const krb5_ccache from,
			 krb5_ccache to,
			 krb5_flags whichfields,
			 const krb5_creds * mcreds,
			 unsigned int *matched)
{
    krb5_error_code ret;
    krb5_cc_cursor cursor;
    krb5_creds cred;
    krb5_principal princ;

    ret = krb5_cc_get_principal(context, from, &princ);
    if (ret)
	return ret;
    ret = krb5_cc_initialize(context, to, princ);
    if (ret) {
	krb5_free_principal(context, princ);
	return ret;
    }
    ret = krb5_cc_start_seq_get(context, from, &cursor);
    if (ret) {
	krb5_free_principal(context, princ);
	return ret;
    }
    if (matched)
	*matched = 0;
    while (ret == 0 &&
	   krb5_cc_next_cred_match(context, from, &cursor, &cred,
				   whichfields, mcreds) == 0) {
	if (matched)
	    (*matched)++;
	ret = krb5_cc_store_cred(context, to, &cred);
	krb5_free_creds_contents(context, &cred);
    }
    krb5_cc_end_seq_get(context, from, &cursor);
    krb5_free_principal(context, princ);
    return ret;
}

static int32_t
bitswap32(int32_t b)
{
    int32_t r = 0;
    int i;
    for (i = 0; i < 32; i++) {
	r = r << 1 | (b & 1);
	b = b >> 1;
    }
    return r;
}

static void
parse_ticket_flags(krb5_context context,
		   const char *flags_string, krb5_ticket_flags *ret_flags)
{
    TicketFlags ff;
    int flags = parse_flags(flags_string, TicketFlags_units, 0);
    if (flags == -1)	/* XXX */
	krb5_errx(context, 1, "bad flags specified: \"%s\"", flags_string);

    memset(&ff, 0, sizeof(ff));
    ff.proxy = 1;
    if (parse_flags("proxy", TicketFlags_units, 0) == TicketFlags2int(ff))
	ret_flags->i = flags;
    else
	ret_flags->i = bitswap32(flags);
}

int
main(int argc, char **argv)
{
    krb5_error_code ret;
    krb5_context context;
    int optind = 0;
    const char *from_name, *to_name;
    krb5_ccache from_ccache, to_ccache;
    krb5_flags whichfields = 0;
    krb5_creds mcreds;
    unsigned int matched;

    setprogname(argv[0]);

    memset(&mcreds, 0, sizeof(mcreds));

    if (getarg(args, sizeof(args) / sizeof(args[0]), argc, argv, &optind))
	usage(1);

    if (help_flag)
	usage(0);

    if (version_flag) {
	print_version(NULL);
	exit(0);
    }
    argc -= optind;
    argv += optind;

    if (argc < 1 || argc > 2)
	usage(1);

    if (krb5_init_context(&context))
	errx(1, "krb5_init_context failed");

    if (service_string) {
	ret = krb5_parse_name(context, service_string, &mcreds.server);
	if (ret)
	    krb5_err(context, 1, ret, "%s", service_string);
    }
    if (enctype_string) {
	krb5_enctype enctype;
	ret = krb5_string_to_enctype(context, enctype_string, &enctype);
	if (ret)
	    krb5_err(context, 1, ret, "%s", enctype_string);
	whichfields |= KRB5_TC_MATCH_KEYTYPE;
	mcreds.session.keytype = enctype;
    }
    if (flags_string) {
	parse_ticket_flags(context, flags_string, &mcreds.flags);
	whichfields |= KRB5_TC_MATCH_FLAGS;
    }
    if (valid_string) {
	time_t t = parse_time(valid_string, "s");
	if(t < 0)
	    errx(1, "unknown time \"%s\"", valid_string);
	mcreds.times.endtime = time(NULL) + t;
	whichfields |= KRB5_TC_MATCH_TIMES;
    }
    if (fcache_version)
	krb5_set_fcache_version(context, fcache_version);

    if (argc == 1) {
	from_name = krb5_cc_default_name(context);
	to_name = argv[0];
    } else {
	from_name = argv[0];
	to_name = argv[1];
    }

    ret = krb5_cc_resolve(context, from_name, &from_ccache);
    if (ret)
	krb5_err(context, 1, ret, "%s", from_name);

    if (krbtgt_only_flag) {
	krb5_principal client;
	ret = krb5_cc_get_principal(context, from_ccache, &client);
	if (ret)
	    krb5_err(context, 1, ret, "getting default principal");
	ret = krb5_make_principal(context, &mcreds.server,
				  krb5_principal_get_realm(context, client),
				  KRB5_TGS_NAME,
				  krb5_principal_get_realm(context, client),
				  NULL);
	if (ret)
	    krb5_err(context, 1, ret, "constructing krbtgt principal");
	krb5_free_principal(context, client);
    }
    ret = krb5_cc_resolve(context, to_name, &to_ccache);
    if (ret)
	krb5_err(context, 1, ret, "%s", to_name);

    ret = krb5_cc_copy_cache_match(context, from_ccache, to_ccache,
				   whichfields, &mcreds, &matched);
    if (ret)
	krb5_err(context, 1, ret, "copying cred cache");

    krb5_cc_close(context, from_ccache);
    if(matched == 0)
	krb5_cc_destroy(context, to_ccache);
    else
	krb5_cc_close(context, to_ccache);
    krb5_free_context(context);
    return matched == 0;
}
