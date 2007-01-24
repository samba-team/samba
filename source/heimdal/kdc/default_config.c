/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden). 
 *
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

#include "kdc_locl.h"

int require_preauth = -1; /* 1 == require preauth for all principals */

const char *trpolicy_str;

int disable_des = -1;
int enable_v4 = -1;
int enable_kaserver = -1;
int enable_524 = -1;
int enable_v4_cross_realm = -1;
int detach_from_console = -1;

char *v4_realm;

/* 
 * Setup some of the defaults for the KDC configuration.
 * 
 * Note: Caller must also fill in:
 * - db
 * - num_db
 * - logf
 *
*/

void
krb5_kdc_default_config(krb5_kdc_configuration *config)
{
    memset(config, 0, sizeof(*config));
    config->require_preauth = TRUE;
    config->kdc_warn_pwexpire = 0;
    config->encode_as_rep_as_tgs_rep = FALSE; /* bug compatibility */
    config->check_ticket_addresses = TRUE;
    config->allow_null_ticket_addresses = TRUE;
    config->allow_anonymous = FALSE;
    config->trpolicy = TRPOLICY_ALWAYS_CHECK;
    config->enable_v4 = FALSE;
    config->enable_kaserver = FALSE;
    config->enable_524 = FALSE; /* overriden by enable_v4 in configure()) */
    config->enable_v4_cross_realm = FALSE;
    config->enable_pkinit = FALSE;
    config->enable_pkinit_princ_in_cert = TRUE;
    config->db = NULL;
    config->num_db = 0;
    config->logf = NULL;
}


/* 
 * Setup some valudes for the KDC configuration, from the config file
 * 
 * Note: Caller must also fill in:
 * - db
 * - num_db
 * - logf
 *
*/

void krb5_kdc_configure(krb5_context context, krb5_kdc_configuration *config)
{
    const char *p;
    if(require_preauth == -1) {
	config->require_preauth = krb5_config_get_bool_default(context, NULL, 
							       config->require_preauth,
							       "kdc", 
							       "require-preauth", NULL);
    } else {
	config->require_preauth = require_preauth;
    }

    if(enable_v4 == -1) {
	config->enable_v4 = krb5_config_get_bool_default(context, NULL, 
							 config->enable_v4, 
							 "kdc", 
							 "enable-kerberos4", 
							 NULL);
    } else {
	config->enable_v4 = enable_v4;
    }

    if(enable_v4_cross_realm == -1) {
	config->enable_v4_cross_realm =
	    krb5_config_get_bool_default(context, NULL,
					 config->enable_v4_cross_realm, 
					 "kdc", 
					 "enable-kerberos4-cross-realm",
					 NULL);
    } else {
	config->enable_v4_cross_realm = enable_v4_cross_realm;
    }

    if(enable_524 == -1) {
	config->enable_524 = krb5_config_get_bool_default(context, NULL, 
							  config->enable_v4, 
							  "kdc", "enable-524", 
							  NULL);
    } else {
	config->enable_524 = enable_524;
    }

    config->enable_digest = 
	krb5_config_get_bool_default(context, NULL, 
				     FALSE, 
				     "kdc", 
				     "enable-digest", NULL);

    {
	const char *digests;

	digests = krb5_config_get_string(context, NULL, 
					 "kdc", 
					 "digests_allowed", NULL);
	if (digests == NULL)
	    digests = "ntlm-v2";
	config->digests_allowed = parse_flags(digests,
					      _kdc_digestunits,
					      0);
	if (config->digests_allowed == -1) {
	    kdc_log(context, config, 0,
		    "unparsable digest units (%s), turning off digest",
		    digests);
	    config->enable_digest = 0;
	} else if (config->digests_allowed == 0) {
	    kdc_log(context, config, 0,
		    "no digest enable, turning digest off",
		    digests);
	    config->enable_digest = 0;
	}
    }

    config->enable_kx509 = 
	krb5_config_get_bool_default(context, NULL, 
				     FALSE, 
				     "kdc", 
				     "enable-kx509", NULL);

    config->check_ticket_addresses = 
	krb5_config_get_bool_default(context, NULL, 
				     config->check_ticket_addresses, 
				     "kdc", 
				     "check-ticket-addresses", NULL);
    config->allow_null_ticket_addresses = 
	krb5_config_get_bool_default(context, NULL, 
				     config->allow_null_ticket_addresses, 
				     "kdc", 
				     "allow-null-ticket-addresses", NULL);

    config->allow_anonymous = 
	krb5_config_get_bool_default(context, NULL, 
				     config->allow_anonymous,
				     "kdc", 
				     "allow-anonymous", NULL);

    config->max_datagram_reply_length =
	krb5_config_get_int_default(context, 
				    NULL, 
				    1400,
				    "kdc",
				    "max-kdc-datagram-reply-length",
				    NULL);

    trpolicy_str = 
	krb5_config_get_string_default(context, NULL, "DEFAULT", "kdc", 
				       "transited-policy", NULL);
    if(strcasecmp(trpolicy_str, "always-check") == 0) {
	config->trpolicy = TRPOLICY_ALWAYS_CHECK;
    } else if(strcasecmp(trpolicy_str, "allow-per-principal") == 0) {
	config->trpolicy = TRPOLICY_ALLOW_PER_PRINCIPAL;
    } else if(strcasecmp(trpolicy_str, "always-honour-request") == 0) {
	config->trpolicy = TRPOLICY_ALWAYS_HONOUR_REQUEST;
    } else if(strcasecmp(trpolicy_str, "DEFAULT") == 0) { 
	/* default */
    } else {
	kdc_log(context, config, 
		0, "unknown transited-policy: %s, reverting to default (always-check)", 
		trpolicy_str);
    }
	
    if (krb5_config_get_string(context, NULL, "kdc", 
			       "enforce-transited-policy", NULL))
	krb5_errx(context, 1, "enforce-transited-policy deprecated, "
		  "use [kdc]transited-policy instead");

    if(v4_realm == NULL){
	p = krb5_config_get_string (context, NULL, 
				    "kdc",
				    "v4-realm",
				    NULL);
	if(p != NULL) {
	    config->v4_realm = strdup(p);
	    if (config->v4_realm == NULL)
		krb5_errx(context, 1, "out of memory");
	} else {
	    config->v4_realm = NULL;
	}
    } else {
	config->v4_realm = v4_realm;
    }

    if (enable_kaserver == -1) {
	config->enable_kaserver = 
	    krb5_config_get_bool_default(context, 
					 NULL, 
					 config->enable_kaserver,
					 "kdc",
					 "enable-kaserver",
					 NULL);
    } else {
	config->enable_kaserver = enable_kaserver;
    }

    config->encode_as_rep_as_tgs_rep =
	krb5_config_get_bool_default(context, NULL, 
				     config->encode_as_rep_as_tgs_rep, 
				     "kdc", 
				     "encode_as_rep_as_tgs_rep", 
				     NULL);

    config->kdc_warn_pwexpire =
	krb5_config_get_time_default (context, NULL,
				      config->kdc_warn_pwexpire,
				      "kdc",
				      "kdc_warn_pwexpire",
				      NULL);

    if(detach_from_console == -1) 
	detach_from_console = krb5_config_get_bool_default(context, NULL, 
							   DETACH_IS_DEFAULT,
							   "kdc",
							   "detach", NULL);

#ifdef PKINIT
    config->enable_pkinit = 
	krb5_config_get_bool_default(context, 
				     NULL, 
				     config->enable_pkinit,
				     "kdc",
				     "enable-pkinit",
				     NULL);
    if (config->enable_pkinit) {
	const char *user_id, *anchors, *ocsp_file;
	char **pool_list, **revoke_list;

	user_id = krb5_config_get_string(context, NULL,
					 "kdc",
					 "pkinit_identity",
					 NULL);
	if (user_id == NULL)
	    krb5_errx(context, 1, "pkinit enabled but no identity");

	anchors = krb5_config_get_string(context, NULL,
					 "kdc",
					 "pkinit_anchors",
					 NULL);
	if (anchors == NULL)
	    krb5_errx(context, 1, "pkinit enabled but no X509 anchors");

	pool_list = krb5_config_get_strings(context, NULL,
					    "kdc",
					    "pkinit_pool",
					    NULL);

	revoke_list = krb5_config_get_strings(context, NULL,
					      "kdc",
					      "pkinit_revoke",
					      NULL);

	ocsp_file = 
	    krb5_config_get_string(context, NULL,
				   "kdc",
				   "pkinit_kdc_ocsp",
				   NULL);
	if (ocsp_file) {
	    config->pkinit_kdc_ocsp_file = strdup(ocsp_file);
	    if (config->pkinit_kdc_ocsp_file == NULL)
		krb5_errx(context, 1, "out of memory");
	}
	_kdc_pk_initialize(context, config, user_id, anchors, 
			   pool_list, revoke_list);

	krb5_config_free_strings(pool_list);
	krb5_config_free_strings(revoke_list);

	config->enable_pkinit_princ_in_cert = 
	    krb5_config_get_bool_default(context, 
					 NULL,
					 config->enable_pkinit_princ_in_cert,
					 "kdc",
					 "pkinit_principal_in_certificate",
					 NULL);
    }

    config->pkinit_dh_min_bits =
	krb5_config_get_int_default(context, 
				    NULL, 
				    0,
				    "kdc",
				    "pkinit_dh_min_bits",
				    NULL);

#endif

    if(config->v4_realm == NULL && (config->enable_kaserver || config->enable_v4)){
#ifdef KRB4
	config->v4_realm = malloc(40); /* REALM_SZ */
	if (config->v4_realm == NULL)
	    krb5_errx(context, 1, "out of memory");
	krb_get_lrealm(config->v4_realm, 1);
#else
	krb5_errx(context, 1, "No Kerberos 4 realm configured");
#endif
    }
    if(disable_des == -1)
	disable_des = krb5_config_get_bool_default(context, NULL, 
						   FALSE,
						   "kdc",
						   "disable-des", NULL);
    if(disable_des) {
	krb5_enctype_disable(context, ETYPE_DES_CBC_CRC);
	krb5_enctype_disable(context, ETYPE_DES_CBC_MD4);
	krb5_enctype_disable(context, ETYPE_DES_CBC_MD5);
	krb5_enctype_disable(context, ETYPE_DES_CBC_NONE);
	krb5_enctype_disable(context, ETYPE_DES_CFB64_NONE);
	krb5_enctype_disable(context, ETYPE_DES_PCBC_NONE);

	kdc_log(context, config, 
		0, "DES was disabled, turned off Kerberos V4, 524 "
		"and kaserver");
	config->enable_v4 = 0;
	config->enable_524 = 0;
	config->enable_kaserver = 0;
    }

    _kdc_windc_init(context);
}

