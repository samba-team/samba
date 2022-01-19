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

struct as_request_pa_state;
struct kdc_patypes;

struct astgs_request_desc {
    ASTGS_REQUEST_DESC_COMMON_ELEMENTS;

    /* Only AS */
    const struct kdc_patypes *pa_used;
    struct as_request_pa_state *pa_state;

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

    krb5_crypto armor_crypto;
    hdb_entry_ex *armor_server;
    krb5_ticket *armor_ticket;
    Key *armor_key;

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

#endif /* __KDC_LOCL_H__ */
