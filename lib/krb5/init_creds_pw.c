/*
 * Copyright (c) 1997 Kungliga Tekniska Högskolan
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

#include "krb5_locl.h"

RCSID("$Id$");

static const char *
get_config_string (krb5_context context,
		   char *realm,
		   char *name,
		   const char *def)
{
    const char *ret;

    ret = krb5_config_get_string (context->cf,
				  "libdefaults",
				  realm,
				  name,
				  NULL);
    if (ret)
	return ret;
    ret = krb5_config_get_string (context->cf,
				  "libdefaults",
				  name,
				  NULL);
    if (ret)
	return ret;
    return def;
}

static int
ison (const char *s)
{
    return strcasecmp (s, "y") == 0
	|| strcasecmp (s, "yes") == 0
	|| strcasecmp (s, "t") == 0
	|| strcasecmp (s, "true") == 0
	|| strcasecmp (s, "1") == 0
	|| strcasecmp (s, "on") == 0;
}

static krb5_error_code
init_cred (krb5_context context,
	   krb5_creds *cred,
	   krb5_principal client,
	   krb5_deltat start_time,
	   char *in_tkt_service,
	   krb5_get_init_creds_opt *options)
{
    krb5_error_code ret;
    krb5_realm *client_realm;
    int tmp;

    memset (cred, 0, sizeof(*cred));
    
    if (client)
	cred->client = client;
    else {			/* XXX -> get_default_principal */
	char *p;

	p = getenv ("USER");
	if (p) {
	    ret = krb5_parse_name (context, p, &cred->client);
	    if (ret)
		goto out;
	} else {
	    struct passwd *pw;
	    char *realm;

	    pw = getpwuid (getuid ());
	    if (pw == NULL) {
		ret = ENOTTY;	/* XXX */
		goto out;
	    }
	    ret = krb5_get_default_realm (context, &realm);
	    if (ret)
		goto out;
	    ret = krb5_build_principal (context, &cred->client,
					strlen(realm), realm,
					pw->pw_name, NULL);
	    free (realm);
	    if (ret)
		goto out;
	}
    }

    client_realm = krb5_princ_realm (context, cred->client);

    if (start_time)
	cred->times.starttime  = time(NULL) + start_time;

    if (options->flags & KRB5_GET_INIT_CREDS_OPT_TKT_LIFE)
	tmp = options->tkt_life;
    else
	tmp = parse_time(get_config_string (context,
					    *client_realm,
					    "ticket_lifetime",
					    "36000"),
			 NULL);
    cred->times.endtime = time(NULL) + tmp;

    tmp = 0;
    if (options->flags & KRB5_GET_INIT_CREDS_OPT_RENEW_LIFE)
	tmp = options->renew_life;
    else
	tmp = parse_time(get_config_string (context,
					    *client_realm,
					    "renew_lifetime",
					    "0"),
			 NULL);
    if (tmp)
	cred->times.renew_till = time(NULL) + tmp;

    if (in_tkt_service) {
	ret = krb5_parse_name (context, in_tkt_service, &cred->server);
	if (ret)
	    goto out;
	krb5_princ_set_realm (context, cred->server, client_realm);
    } else {
	ret = krb5_build_principal_ext (context,
					&cred->server,
					strlen(*client_realm),
					*client_realm,
					strlen("krbtgt"),
					"krbtgt",
					strlen(*client_realm),
					*client_realm,
					NULL);
	if (ret)
	    goto out;
    }
    return 0;

out:
    krb5_free_creds_contents (context, cred);
    return ret;
}

krb5_error_code
krb5_get_init_creds_password(krb5_context context,
			     krb5_creds *creds,
			     krb5_principal client,
			     char *password,
			     krb5_prompter_fct prompter,
			     void *data,
			     krb5_deltat start_time,
			     char *in_tkt_service,
			     krb5_get_init_creds_opt *options)
{
    krb5_error_code ret;
    krb5_kdc_flags flags;
    krb5_addresses *addrs = NULL;
    krb5_enctype *etypes = NULL;
    krb5_preauthtype *pre_auth_types = NULL;
    krb5_creds this_cred;
    krb5_kdc_rep kdc_reply;
    char buf[BUFSIZ];
    krb5_data password_data;
    const char *tmp_str;
    krb5_realm *client_realm;

    ret = init_cred (context, &this_cred, client, start_time,
		     in_tkt_service, options);
    if (ret)
	return ret;

    client_realm = krb5_princ_realm (context, this_cred.client);

    flags.i = 0;

    if (options->flags & KRB5_GET_INIT_CREDS_OPT_FORWARDABLE)
	flags.b.forwardable = 1;
    else
	flags.b.forwardable = ison(get_config_string (context,
						      *client_realm,
						      "forwardable",
						      "no"));

    if (options->flags & KRB5_GET_INIT_CREDS_OPT_PROXIABLE)
	flags.b.proxiable = 1;
    else
	flags.b.proxiable = ison(get_config_string (context,
						    *client_realm,
						    "proxiable",
						    "no"));

    if (this_cred.times.renew_till)
	flags.b.renewable = 1;
    if (options->flags & KRB5_GET_INIT_CREDS_OPT_ADDRESS_LIST)
	addrs = options->address_list;
    if (options->flags & KRB5_GET_INIT_CREDS_OPT_ETYPE_LIST) {
	etypes = malloc((options->etype_list_length + 1)
			* sizeof(krb5_enctype));
	if (etypes == NULL) {
	    ret = ENOMEM;
	    goto out;
	}
	memcpy (etypes, options->etype_list,
		options->etype_list_length * sizeof(krb5_enctype));
	etypes[options->etype_list_length] = 0;
    }
    if (options->flags & KRB5_GET_INIT_CREDS_OPT_PREAUTH_LIST) {
	pre_auth_types = malloc((options->preauth_list_length + 1)
				* sizeof(krb5_preauthtype));
	if (pre_auth_types == NULL) {
	    ret = ENOMEM;
	    goto out;
	}
	memcpy (pre_auth_types, options->preauth_list,
		options->preauth_list_length * sizeof(krb5_preauthtype));
	pre_auth_types[options->preauth_list_length] = 0;
    }
    if (options->flags & KRB5_GET_INIT_CREDS_OPT_SALT)
	;			/* XXX */

    if (password == NULL) {
	krb5_prompt prompt;
	char *p;

	krb5_unparse_name (context, this_cred.client, &p);
	asprintf (&prompt.prompt, "%s's Password: ", p);
	free (p);
	password_data.data   = buf;
	password_data.length = sizeof(buf);
	prompt.hidden = 1;
	prompt.reply  = &password_data;

	ret = (*prompter) (context, data, NULL, 1, &prompt);
	if (ret) {
	    memset (buf, 0, sizeof(buf));
	    goto out;
	}
	password = password_data.data;
    }

    ret = krb5_get_in_cred (context,
			    flags.i,
			    addrs,
			    etypes,
			    pre_auth_types,
			    krb5_password_key_proc,
			    password,
			    NULL,
			    NULL,
			    &this_cred,
			    NULL /* &kdc_reply */);
    memset (buf, 0, sizeof(buf));
    if (ret)
	goto out;
    free (pre_auth_types);
    free (etypes);
    if (creds)
	*creds = this_cred;
    else
	krb5_free_creds_contents (context, &this_cred);
    return 0;

out:
    free (pre_auth_types);
    free (etypes);
    krb5_free_creds_contents (context, &this_cred);
    return ret;
}
