/*
 * Copyright (c) 1997-2007 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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
#include <getarg.h>
#include <parse_bytes.h>

static const char *sysplugin_dirs[] =  {
#ifdef _WIN32
    "$ORIGIN",
#else
    "$ORIGIN/../lib/plugin/kdc",
#endif
#ifdef __APPLE__
    LIBDIR "/plugin/kdc",
#endif
    NULL
};

static void
load_kdc_plugins_once(void *ctx)
{
    krb5_context context = ctx;
    const char * const *dirs = sysplugin_dirs;
#ifndef _WIN32
    char **cfdirs;

    cfdirs = krb5_config_get_strings(context, NULL, "kdc", "plugin_dir", NULL);
    if (cfdirs)
        dirs = (const char * const *)cfdirs;
#endif

    _krb5_load_plugins(context, "kdc", (const char **)dirs);

#ifndef _WIN32
    krb5_config_free_strings(cfdirs);
#endif
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
krb5_kdc_get_config(krb5_context context, krb5_kdc_configuration **config)
{
    static heim_base_once_t load_kdc_plugins = HEIM_BASE_ONCE_INIT;
    krb5_kdc_configuration *c;
    krb5_error_code ret;

    heim_base_once_f(&load_kdc_plugins, context, load_kdc_plugins_once);

    c = calloc(1, sizeof(*c));
    if (c == NULL) {
	krb5_set_error_message(context, ENOMEM, "malloc: out of memory");
	return ENOMEM;
    }

    c->app = "kdc";
    c->num_kdc_processes = -1;
    c->require_preauth = TRUE;
    c->kdc_warn_pwexpire = 0;
    c->encode_as_rep_as_tgs_rep = FALSE;
    c->tgt_use_strongest_session_key = FALSE;
    c->preauth_use_strongest_session_key = FALSE;
    c->svc_use_strongest_session_key = FALSE;
    c->use_strongest_server_key = TRUE;
    c->check_ticket_addresses = TRUE;
    c->warn_ticket_addresses = FALSE;
    c->allow_null_ticket_addresses = TRUE;
    c->allow_anonymous = FALSE;
    c->historical_anon_realm = FALSE;
    c->strict_nametypes = FALSE;
    c->trpolicy = TRPOLICY_ALWAYS_CHECK;
    c->require_pac = FALSE;
    c->disable_pac = FALSE;
    c->enable_fast = TRUE;
    c->enable_fast_cookie = TRUE;
    c->enable_armored_pa_enc_timestamp = TRUE;
    c->enable_unarmored_pa_enc_timestamp = TRUE;
    c->enable_pkinit = FALSE;
    c->require_pkinit_freshness = FALSE;
    c->pkinit_princ_in_cert = TRUE;
    c->pkinit_require_binding = TRUE;
    c->synthetic_clients = FALSE;
    c->pkinit_max_life_from_cert_extension = FALSE;
    c->pkinit_max_life_bound = 0;
    c->synthetic_clients_max_life = 300;
    c->synthetic_clients_max_renew = 300;
    c->pkinit_dh_min_bits = 1024;
    c->db = NULL;
    c->num_db = 0;
    c->logf = NULL;

    c->num_kdc_processes =
        krb5_config_get_int_default(context, NULL, c->num_kdc_processes,
				    "kdc", "num-kdc-processes", NULL);

    c->require_preauth =
	krb5_config_get_bool_default(context, NULL,
				     c->require_preauth,
				     "kdc", "require-preauth", NULL);
#ifdef DIGEST
    c->enable_digest =
	krb5_config_get_bool_default(context, NULL,
				     FALSE,
				     "kdc", "enable-digest", NULL);

    {
	const char *digests;

	digests = krb5_config_get_string(context, NULL,
					 "kdc",
					 "digests_allowed", NULL);
	if (digests == NULL)
	    digests = "ntlm-v2";
	c->digests_allowed = parse_flags(digests,_kdc_digestunits, 0);
	if (c->digests_allowed == -1) {
	    kdc_log(context, c, 0,
		    "unparsable digest units (%s), turning off digest",
		    digests);
	    c->enable_digest = 0;
	} else if (c->digests_allowed == 0) {
	    kdc_log(context, c, 0, "no digest enable, turning digest off");
	    c->enable_digest = 0;
	}
    }
#endif

#ifdef KX509
    c->enable_kx509 =
	krb5_config_get_bool_default(context, NULL,
				     FALSE,
				     "kdc", "enable_kx509", NULL);
#endif

    c->tgt_use_strongest_session_key =
	krb5_config_get_bool_default(context, NULL,
				     c->tgt_use_strongest_session_key,
				     "kdc",
				     "tgt-use-strongest-session-key", NULL);
    c->preauth_use_strongest_session_key =
	krb5_config_get_bool_default(context, NULL,
				     c->preauth_use_strongest_session_key,
				     "kdc",
				     "preauth-use-strongest-session-key", NULL);
    c->svc_use_strongest_session_key =
	krb5_config_get_bool_default(context, NULL,
				     c->svc_use_strongest_session_key,
				     "kdc",
				     "svc-use-strongest-session-key", NULL);
    c->use_strongest_server_key =
	krb5_config_get_bool_default(context, NULL,
				     c->use_strongest_server_key,
				     "kdc",
				     "use-strongest-server-key", NULL);

    c->check_ticket_addresses =
	krb5_config_get_bool_default(context, NULL,
				     c->check_ticket_addresses,
				     "kdc",
				     "check-ticket-addresses", NULL);
    c->warn_ticket_addresses =
	krb5_config_get_bool_default(context, NULL,
				     c->warn_ticket_addresses,
				     "kdc",
				     "warn_ticket_addresses", NULL);
    c->allow_null_ticket_addresses =
	krb5_config_get_bool_default(context, NULL,
				     c->allow_null_ticket_addresses,
				     "kdc",
				     "allow-null-ticket-addresses", NULL);

    c->allow_anonymous =
	krb5_config_get_bool_default(context, NULL,
				     c->allow_anonymous,
				     "kdc",
				     "allow-anonymous", NULL);

    c->historical_anon_realm =
	krb5_config_get_bool_default(context, NULL,
				     c->historical_anon_realm,
				     "kdc",
				     "historical_anon_realm", NULL);

    c->strict_nametypes =
	krb5_config_get_bool_default(context, NULL,
				     c->strict_nametypes,
				     "kdc",
				     "strict-nametypes", NULL);

    c->max_datagram_reply_length =
	krb5_config_get_int_default(context,
				    NULL,
				    1400,
				    "kdc",
				    "max-kdc-datagram-reply-length",
				    NULL);

    {
	const char *trpolicy_str;

	trpolicy_str =
	    krb5_config_get_string_default(context, NULL, "DEFAULT", "kdc",
					   "transited-policy", NULL);
	if(strcasecmp(trpolicy_str, "always-check") == 0) {
	    c->trpolicy = TRPOLICY_ALWAYS_CHECK;
	} else if(strcasecmp(trpolicy_str, "allow-per-principal") == 0) {
	    c->trpolicy = TRPOLICY_ALLOW_PER_PRINCIPAL;
	} else if(strcasecmp(trpolicy_str, "always-honour-request") == 0) {
	    c->trpolicy = TRPOLICY_ALWAYS_HONOUR_REQUEST;
	} else if(strcasecmp(trpolicy_str, "DEFAULT") == 0) {
	    /* default */
	} else {
	    kdc_log(context, c, 0,
		    "unknown transited-policy: %s, "
		    "reverting to default (always-check)",
		    trpolicy_str);
	}
    }

    c->encode_as_rep_as_tgs_rep =
	krb5_config_get_bool_default(context, NULL,
				     c->encode_as_rep_as_tgs_rep,
				     "kdc",
				     "encode_as_rep_as_tgs_rep", NULL);

    c->kdc_warn_pwexpire =
	krb5_config_get_time_default (context, NULL,
				      c->kdc_warn_pwexpire,
				      "kdc", "kdc_warn_pwexpire", NULL);

    c->require_pac =
	krb5_config_get_bool_default(context,
				     NULL,
				     c->require_pac,
				     "kdc",
				     "require_pac",
				     NULL);

    c->disable_pac =
	krb5_config_get_bool_default(context,
				     NULL,
				     c->disable_pac,
				     "kdc",
				     "disable_pac",
				     NULL);

    c->enable_fast =
	krb5_config_get_bool_default(context,
				     NULL,
				     c->enable_fast,
				     "kdc",
				     "enable_fast",
				     NULL);

    c->enable_fast_cookie =
	krb5_config_get_bool_default(context,
				     NULL,
				     c->enable_fast_cookie,
				     "kdc",
				     "enable_fast_cookie",
				     NULL);

    c->enable_armored_pa_enc_timestamp =
	krb5_config_get_bool_default(context,
				     NULL,
				     c->enable_armored_pa_enc_timestamp,
				     "kdc",
				     "enable_armored_pa_enc_timestamp",
				     NULL);

    c->enable_unarmored_pa_enc_timestamp =
	krb5_config_get_bool_default(context,
				     NULL,
				     c->enable_unarmored_pa_enc_timestamp,
				     "kdc",
				     "enable_unarmored_pa_enc_timestamp",
				     NULL);

    c->enable_pkinit =
	krb5_config_get_bool_default(context,
				     NULL,
				     c->enable_pkinit,
				     "kdc",
				     "enable-pkinit",
				     NULL);

    c->require_pkinit_freshness =
	krb5_config_get_bool_default(context,
				     NULL,
				     c->require_pkinit_freshness,
				     "kdc",
				     "require-pkinit-freshness",
				     NULL);

    c->pkinit_kdc_identity =
	krb5_config_get_string(context, NULL,
			       "kdc", "pkinit_identity", NULL);
    c->pkinit_kdc_anchors =
	krb5_config_get_string(context, NULL,
			       "kdc", "pkinit_anchors", NULL);
    c->pkinit_kdc_cert_pool =
	krb5_config_get_strings(context, NULL,
				"kdc", "pkinit_pool", NULL);
    c->pkinit_kdc_revoke =
	krb5_config_get_strings(context, NULL,
				"kdc", "pkinit_revoke", NULL);
    c->pkinit_kdc_ocsp_file =
	krb5_config_get_string(context, NULL,
			       "kdc", "pkinit_kdc_ocsp", NULL);
    c->pkinit_kdc_friendly_name =
	krb5_config_get_string(context, NULL,
			       "kdc", "pkinit_kdc_friendly_name", NULL);
    c->pkinit_princ_in_cert =
	krb5_config_get_bool_default(context, NULL,
				     c->pkinit_princ_in_cert,
				     "kdc",
				     "pkinit_principal_in_certificate",
				     NULL);
    c->pkinit_require_binding =
	krb5_config_get_bool_default(context, NULL,
				     c->pkinit_require_binding,
				     "kdc",
				     "pkinit_win2k_require_binding",
				     NULL);
    c->pkinit_dh_min_bits =
	krb5_config_get_int_default(context, NULL,
				    0,
				    "kdc", "pkinit_dh_min_bits", NULL);

    c->pkinit_max_life_from_cert_extension =
        krb5_config_get_bool_default(context, NULL,
                                     c->pkinit_max_life_from_cert_extension,
                                     "kdc",
                                     "pkinit_max_life_from_cert_extension",
                                     NULL);

    c->synthetic_clients =
	krb5_config_get_bool_default(context, NULL,
				     c->synthetic_clients,
				     "kdc",
				     "synthetic_clients",
				     NULL);

    c->pkinit_max_life_bound =
         krb5_config_get_time_default(context, NULL, 0, "kdc",
                                      "pkinit_max_life_bound",
                                      NULL);

    c->pkinit_max_life_from_cert =
         krb5_config_get_time_default(context, NULL, 0, "kdc",
                                      "pkinit_max_life_from_cert",
                                      NULL);

    c->synthetic_clients_max_life =
         krb5_config_get_time_default(context, NULL, 300, "kdc",
                                      "synthetic_clients_max_life",
                                      NULL);

    c->synthetic_clients_max_renew =
         krb5_config_get_time_default(context, NULL, 300, "kdc",
                                      "synthetic_clients_max_renew",
                                      NULL);

    c->enable_gss_preauth =
	krb5_config_get_bool_default(context, NULL,
				     c->enable_gss_preauth,
				     "kdc",
				     "enable_gss_preauth", NULL);

    c->enable_gss_auth_data =
	krb5_config_get_bool_default(context, NULL,
				     c->enable_gss_auth_data,
				     "kdc",
				     "enable_gss_auth_data", NULL);

    ret = _kdc_gss_get_mechanism_config(context, "kdc",
					"gss_mechanisms_allowed",
					&c->gss_mechanisms_allowed);
    if (ret) {
	free(c);
	return ret;
    }

    ret = _kdc_gss_get_mechanism_config(context, "kdc",
					"gss_cross_realm_mechanisms_allowed",
					&c->gss_cross_realm_mechanisms_allowed);
    if (ret) {
	OM_uint32 minor;
	gss_release_oid_set(&minor, &c->gss_mechanisms_allowed);
	free(c);
	return ret;
    }

    *config = c;

    return 0;
}

KDC_LIB_FUNCTION krb5_error_code KDC_LIB_CALL
krb5_kdc_pkinit_config(krb5_context context, krb5_kdc_configuration *config)
{
#ifdef PKINIT
    if (config->enable_pkinit) {
#ifdef __APPLE__
	if (config->pkinit_kdc_identity == NULL) {
	    if (config->pkinit_kdc_friendly_name == NULL)
		config->pkinit_kdc_friendly_name =
		    strdup("O=System Identity,CN=com.apple.kerberos.kdc");
	    config->pkinit_kdc_identity = strdup("KEYCHAIN:");
	}
	if (config->pkinit_kdc_anchors == NULL)
	    config->pkinit_kdc_anchors = strdup("KEYCHAIN:");
#endif /* __APPLE__ */

	if (config->pkinit_kdc_identity == NULL)
	    krb5_errx(context, 1, "pkinit enabled but no identity");

	if (config->pkinit_kdc_anchors == NULL)
	    krb5_errx(context, 1, "pkinit enabled but no X509 anchors");

	krb5_kdc_pk_initialize(context, config,
			       config->pkinit_kdc_identity,
			       config->pkinit_kdc_anchors,
			       config->pkinit_kdc_cert_pool,
			       config->pkinit_kdc_revoke);

    }

    return 0;
#endif /* PKINIT */
}
