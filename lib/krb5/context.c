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

#include "krb5_locl.h"

RCSID("$Id$");

int issuid(void); /* XXX */

krb5_error_code
krb5_init_context(krb5_context *context)
{
    krb5_context p;
    int val;
    const char *config_file = NULL;
    const char * tmp;
    krb5_config_section *tmp_cf;
    krb5_error_code ret;

    ALLOC(p, 1);
    if(!p)
	return ENOMEM;
    memset(p, 0, sizeof(krb5_context_data));

    /* init error tables */
    krb5_init_ets(p);

    if(!issuid())
	config_file = getenv("KRB5_CONFIG");
    if (config_file == NULL)
	config_file = krb5_config_file;

    ret = krb5_config_parse_file (config_file, &tmp_cf);

    if (ret == 0)
	p->cf = tmp_cf;
    else
	krb5_warnx (p, "Unable to parse config file %s.  Ignoring.",
		    config_file); /* XXX */

    p->max_skew = 5 * 60;
    val = krb5_config_get_time (p, NULL, "libdefaults", "clockskew", NULL);
    if (val >= 0)
	p->max_skew = val;

    p->kdc_timeout = 3;
    val = krb5_config_get_time (p, NULL, "libdefaults", "kdc_timeout", NULL);
    if(val >= 0) 
	p->kdc_timeout = val;

    p->max_retries = 3;
    val = krb5_config_get_int (p, NULL, "libdefaults", "max_retries", NULL);
    if (val >= 0)
	p->max_retries = val;

    p->http_proxy = krb5_config_get_string(p, NULL, "libdefaults", 
					   "http_proxy", NULL);

    {
	char **etypes;
	etypes = krb5_config_get_strings(p, NULL, "libdefaults", 
					 "default_etypes", NULL);
	if(etypes){
	    int i, j, k;
	    for(i = 0; etypes[i]; i++);
	    p->etypes = malloc((i+1) * sizeof(*p->etypes));
	    for(j = 0, k = 0; j < i; j++) {
		if(krb5_string_to_enctype(p, etypes[j], &p->etypes[k]) == 0)
		    k++;
	    }
	    p->etypes[k] = ETYPE_NULL;
	    krb5_config_free_strings(etypes);
	}
    }
    /* default keytab name */
    p->default_keytab = krb5_config_get_string(p, NULL, 
					       "libdefaults", 
					       "default_keytab_name", 
					       NULL);
    if(p->default_keytab == NULL)
	p->default_keytab = KEYTAB_DEFAULT;

    p->time_fmt = krb5_config_get_string(p, NULL, "libdefaults", 
					 "time_format", NULL);
    if(p->time_fmt == NULL)
	p->time_fmt = "%d-%b-%Y %H:%M:%S";
    p->log_utc = krb5_config_get_bool(p, NULL, "libdefaults", "log_utc", NULL);

    /* init dns-proxy slime */
    tmp = krb5_config_get_string(p, NULL, "libdefaults", 
				 "dns_proxy", NULL);
    if(tmp) 
	roken_gethostby_setup(p->http_proxy, tmp);
    krb5_set_default_realm(p, NULL);
    *context = p;
    return 0;
}

void
krb5_free_context(krb5_context context)
{
  int i;

  free(context->etypes);
  free(context->default_realm);
  krb5_config_file_free (context->cf);
  free_error_table (context->et_list);
  for(i = 0; i < context->num_ops; ++i)
    free(context->cc_ops[i].prefix);
  free(context->cc_ops);
  free(context);
}

static krb5_error_code
default_etypes(krb5_enctype **etype)
{
    krb5_enctype p[] = {
	ETYPE_DES3_CBC_SHA1,
	ETYPE_DES3_CBC_MD5,
	ETYPE_DES_CBC_MD5,
	ETYPE_DES_CBC_MD4,
	ETYPE_DES_CBC_CRC,
	ETYPE_NULL
    };
    *etype = malloc(sizeof(p));
    if(*etype == NULL)
	return ENOMEM;
    memcpy(*etype, p, sizeof(p));
    return 0;
}

krb5_error_code
krb5_set_default_in_tkt_etypes(krb5_context context, 
			       const krb5_enctype *etypes)
{
    int i;
    krb5_enctype *p = NULL;

    if(etypes) {
	i = 0;
	while(etypes[i])
	    if(!krb5_enctype_valid(context, etypes[i++]))
		return KRB5_PROG_ETYPE_NOSUPP;
	++i;
	ALLOC(p, i);
	if(!p)
	    return ENOMEM;
	memmove(p, etypes, i * sizeof(krb5_enctype));
    }
    if(context->etypes)
	free(context->etypes);
    context->etypes = p;
    return 0;
}



krb5_error_code
krb5_get_default_in_tkt_etypes(krb5_context context,
			       krb5_enctype **etypes)
{
  krb5_enctype *p;
  int i;

  if(context->etypes) {
    for(i = 0; context->etypes[i]; i++);
    ++i;
    ALLOC(p, i);
    if(!p)
      return ENOMEM;
    memmove(p, context->etypes, i * sizeof(krb5_enctype));
  } else
    if(default_etypes(&p))
      return ENOMEM;
  *etypes = p;
  return 0;
}

const char *
krb5_get_err_text(krb5_context context, long code)
{
    const char *p = com_right(context->et_list, code);
    if(p == NULL)
	p = strerror(code);
    return p;
}

void
krb5_init_ets(krb5_context context)
{
    if(context->et_list == NULL){
	initialize_krb5_error_table_r(&context->et_list);
	initialize_asn1_error_table_r(&context->et_list);
	initialize_heim_error_table_r(&context->et_list);
    }
}

void
krb5_set_use_admin_kdc (krb5_context context, krb5_boolean flag)
{
    context->use_admin_kdc = flag;
}

krb5_boolean
krb5_get_use_admin_kdc (krb5_context context)
{
    return context->use_admin_kdc;
}
