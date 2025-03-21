/*
 * Copyright (c) 1997-2005 Kungliga Tekniska Högskolan
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

/*
 * $Id$
 */

#ifndef __KDC_LOCL_H__
#define __KDC_LOCL_H__

#include "headers.h"

typedef struct pk_client_params pk_client_params;
typedef struct gss_client_params gss_client_params;

#include <kdc-private.h>

#define FAST_EXPIRATION_TIME (3 * 60)

/* KFE == KDC_FIND_ETYPE */
#define KFE_IS_TGS	0x1
#define KFE_IS_PREAUTH	0x2
#define KFE_USE_CLIENT	0x4

#define heim_pcontext krb5_context
#define heim_pconfig krb5_kdc_configuration *
#include <heimbase-svc.h>

#define KDC_AUDIT_EATWHITE      HEIM_SVC_AUDIT_EATWHITE
#define KDC_AUDIT_VIS           HEIM_SVC_AUDIT_VIS
#define KDC_AUDIT_VISLAST       HEIM_SVC_AUDIT_VISLAST

struct kdc_request_desc {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;
};

struct kdc_patypes;

struct krb5_kdc_configuration {
    KRB5_KDC_CONFIGURATION_COMMON_ELEMENTS;

    int num_kdc_processes;

    size_t max_datagram_reply_length;

    time_t kdc_warn_pwexpire; /* time before expiration to print a warning */

    unsigned int require_preauth : 1; /* require preauth for all principals */
    unsigned int encode_as_rep_as_tgs_rep : 1; /* bug compatibility */

    unsigned int check_ticket_addresses : 1;
    unsigned int warn_ticket_addresses : 1;
    unsigned int allow_null_ticket_addresses : 1;
    unsigned int allow_anonymous : 1;
    unsigned int historical_anon_realm : 1;
    unsigned int strict_nametypes : 1;

    unsigned int disable_pac : 1;
    unsigned int enable_unarmored_pa_enc_timestamp : 1;

    unsigned int enable_pkinit : 1;
    unsigned int require_pkinit_freshness : 1;
    unsigned int pkinit_princ_in_cert : 1;
    const char *pkinit_kdc_identity;
    const char *pkinit_kdc_anchors;
    const char *pkinit_kdc_friendly_name;
    const char *pkinit_kdc_ocsp_file;
    char **pkinit_kdc_cert_pool;
    char **pkinit_kdc_revoke;
    int pkinit_dh_min_bits;
    unsigned int pkinit_require_binding : 1;
    unsigned int pkinit_allow_proxy_certs : 1;
    unsigned int synthetic_clients : 1;
    unsigned int pkinit_max_life_from_cert_extension : 1;
    krb5_timestamp pkinit_max_life_from_cert;
    krb5_timestamp pkinit_max_life_bound;
    krb5_timestamp synthetic_clients_max_life;
    krb5_timestamp synthetic_clients_max_renew;

    int digests_allowed;
    unsigned int enable_digest : 1;

    unsigned int enable_kx509 : 1;

    unsigned int enable_gss_preauth : 1;
    unsigned int enable_gss_auth_data : 1;
    gss_OID_set gss_mechanisms_allowed;
    gss_OID_set gss_cross_realm_mechanisms_allowed;

};

struct astgs_request_desc {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;

    /* AS-REQ or TGS-REQ */
    KDC_REQ req;

    /* AS-REP or TGS-REP */
    KDC_REP rep;
    EncTicketPart et;
    EncKDCRepPart ek;

    /* client principal (AS) or TGT/S4U principal (TGS) */
    krb5_principal client_princ;
    hdb_entry *client;
    HDB *clientdb;
    krb5_principal canon_client_princ;

    /* server principal */
    krb5_principal server_princ;
    HDB *serverdb;
    hdb_entry *server;

    /* presented ticket in TGS-REQ (unused by AS) */
    krb5_principal krbtgt_princ;
    hdb_entry *krbtgt;
    HDB *krbtgtdb;
    krb5_ticket *ticket;

    krb5_keyblock reply_key;

    krb5_pac pac;
    uint64_t pac_attributes;

    /* Only AS */
    const struct kdc_patypes *pa_used;
    unsigned int pkinit_freshness_used : 1;

    /* PA methods can affect both the reply key and the session key (pkinit) */
    krb5_enctype sessionetype;
    krb5_keyblock session_key;

    krb5_timestamp pa_endtime;
    krb5_timestamp pa_max_life;

    krb5_keyblock strengthen_key;
    const Key *ticket_key;

    /* only valid for tgs-req */
    unsigned int rk_is_subkey : 1;
    unsigned int fast_asserted : 1;
    unsigned int explicit_armor_present : 1;
    krb5_keyblock enc_ad_key;

    krb5_crypto armor_crypto;
    hdb_entry *armor_server;
    HDB *armor_serverdb;
    krb5_ticket *armor_ticket;
    Key *armor_key;

    krb5_principal armor_client_principal;
    hdb_entry *armor_client;
    HDB *armor_clientdb;
    krb5_pac armor_pac;

    KDCFastState fast;
};

typedef struct kx509_req_context_desc {
    HEIM_SVC_REQUEST_DESC_COMMON_ELEMENTS;

    struct Kx509Request req;
    Kx509CSRPlus csr_plus;
    krb5_auth_context ac;
    const char *realm; /* XXX Confusion: is this crealm or srealm? */
    krb5_keyblock *key;
    hx509_request csr;
    krb5_times ticket_times;
    unsigned int send_chain:1;          /* Client expects a full chain */
    unsigned int have_csr:1;            /* Client sent a CSR */
} *kx509_req_context;

#undef heim_pconfig
#undef heim_pcontext

extern sig_atomic_t exit_flag;
extern size_t max_request_udp;
extern size_t max_request_tcp;
extern const char *request_log;
extern const char *port_str;
extern krb5_addresses explicit_addresses;

extern int enable_http;

extern int detach_from_console;
extern int daemon_child;
extern int do_bonjour;

extern int testing_flag;

extern const struct units _kdc_digestunits[];

#define KDC_LOG_FILE		"kdc.log"

extern struct timeval _kdc_now;
#define kdc_time (_kdc_now.tv_sec)

extern char *runas_string;
extern char *chroot_string;

void
start_kdc(krb5_context context, krb5_kdc_configuration *config, const char *argv0);

krb5_kdc_configuration *
configure(krb5_context context, int argc, char **argv, int *optidx);

#ifdef __APPLE__
void bonjour_announce(krb5_context, krb5_kdc_configuration *);
#endif

/* no-copy setters */

#undef _KDC_REQUEST_GET_ACCESSOR
#undef _KDC_REQUEST_SET_ACCESSOR

#undef _KDC_REQUEST_GET_ACCESSOR_PTR
#undef _KDC_REQUEST_SET_ACCESSOR_PTR
#define _KDC_REQUEST_SET_ACCESSOR_PTR(R, T, t, f)	    \
    void						    \
    _kdc_request_set_ ## f ## _nocopy(R r, T *v);

#undef _KDC_REQUEST_GET_ACCESSOR_STRUCT
#undef _KDC_REQUEST_SET_ACCESSOR_STRUCT
#define _KDC_REQUEST_SET_ACCESSOR_STRUCT(R, T, t, f)	    \
    void						    \
    _kdc_request_set_ ## f ## _nocopy(R r, T *v);

#undef HEIMDAL_KDC_KDC_ACCESSORS_H
#include "kdc-accessors.h"

#endif /* __KDC_LOCL_H__ */
