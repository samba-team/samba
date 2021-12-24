/*
 * Copyright (c) 1997-2003 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 *
 * Copyright (c) 2005 Andrew Bartlett <abartlet@samba.org>
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

/*
 * $Id$
 */

#ifndef __KDC_H__
#define __KDC_H__

#include <hdb.h>
#include <krb5.h>
#include <kx509_asn1.h>
#include <gssapi/gssapi.h>

#define heim_pcontext krb5_context
#define heim_pconfig krb5_kdc_configuration *
#include <heimbase-svc.h>

enum krb5_kdc_trpolicy {
    TRPOLICY_ALWAYS_CHECK,
    TRPOLICY_ALLOW_PER_PRINCIPAL,
    TRPOLICY_ALWAYS_HONOUR_REQUEST
};

typedef struct krb5_kdc_configuration {
    krb5_boolean require_preauth; /* require preauth for all principals */
    time_t kdc_warn_pwexpire; /* time before expiration to print a warning */

    struct HDB **db;
    int num_db;

    int num_kdc_processes;

    krb5_boolean encode_as_rep_as_tgs_rep; /* bug compatibility */

    /*
     * Windows 2019 (and earlier versions) always sends the salt
     * and Samba has testsuites that check this behaviour, so a
     * Samba AD DC will set this flag to match the AS-REP packet
     * exactly.
     */
    krb5_boolean force_include_pa_etype_salt;

    krb5_boolean tgt_use_strongest_session_key;
    krb5_boolean preauth_use_strongest_session_key;
    krb5_boolean svc_use_strongest_session_key;
    krb5_boolean use_strongest_server_key;

    krb5_boolean check_ticket_addresses;
    krb5_boolean warn_ticket_addresses;
    krb5_boolean allow_null_ticket_addresses;
    krb5_boolean allow_anonymous;
    krb5_boolean historical_anon_realm;
    krb5_boolean strict_nametypes;
    enum krb5_kdc_trpolicy trpolicy;

    krb5_boolean require_pac;
    krb5_boolean enable_armored_pa_enc_timestamp;
    krb5_boolean enable_unarmored_pa_enc_timestamp;

    krb5_boolean autodetect_referrals;

    krb5_boolean enable_pkinit;
    krb5_boolean pkinit_princ_in_cert;
    const char *pkinit_kdc_identity;
    const char *pkinit_kdc_anchors;
    const char *pkinit_kdc_friendly_name;
    const char *pkinit_kdc_ocsp_file;
    char **pkinit_kdc_cert_pool;
    char **pkinit_kdc_revoke;
    int pkinit_dh_min_bits;
    /* XXX Turn these into bit-fields */
    int pkinit_require_binding;
    int pkinit_allow_proxy_certs;
    int synthetic_clients;
    int pkinit_max_life_from_cert_extension;
    krb5_timestamp pkinit_max_life_from_cert;
    krb5_timestamp pkinit_max_life_bound;
    krb5_timestamp synthetic_clients_max_life;
    krb5_timestamp synthetic_clients_max_renew;

    krb5_log_facility *logf;

    int enable_digest;
    int digests_allowed;

    int enable_gss_preauth;
    int enable_gss_auth_data;
    gss_OID_set gss_mechanisms_allowed;
    gss_OID_set gss_cross_realm_mechanisms_allowed;

    size_t max_datagram_reply_length;

    int enable_kx509;

    const char *app;
} krb5_kdc_configuration;

#define ASTGS_REQUEST_DESC_COMMON_ELEMENTS			\
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;			\
								\
    KDC_REQ req;						\
								\
    KDC_REP rep;						\
    EncTicketPart et;						\
    EncKDCRepPart ek;						\
								\
    /* princ requested by client (AS) or canon princ (TGT) */	\
    krb5_principal client_princ;				\
    hdb_entry_ex *client;					\
    HDB *clientdb;						\
								\
    krb5_principal server_princ;				\
    hdb_entry_ex *server;					\
								\
    krb5_keyblock reply_key;					\
								\
    krb5_pac pac;						\
    uint64_t pac_attributes;

#ifndef __KDC_LOCL_H__
struct astgs_request_desc {
    ASTGS_REQUEST_DESC_COMMON_ELEMENTS
};
#endif

typedef struct kdc_request_desc *kdc_request_t;
typedef struct astgs_request_desc *astgs_request_t;
typedef struct kx509_req_context_desc *kx509_req_context;

struct krb5_kdc_service {
    unsigned int flags;
#define KS_KRB5		1
#define KS_NO_LENGTH	2
    const char *name;
    krb5_error_code (*process)(kdc_request_t *, int *claim);
};

#include <kdc-protos.h>

#undef heim_pcontext
#undef heim_pconfig

#endif
