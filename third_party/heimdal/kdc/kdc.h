/*
 * Copyright (c) 1997-2022 Kungliga Tekniska Högskolan
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

enum krb5_kdc_trpolicy {
    TRPOLICY_ALWAYS_CHECK,
    TRPOLICY_ALLOW_PER_PRINCIPAL,
    TRPOLICY_ALWAYS_HONOUR_REQUEST,
    TRPOLICY_NEVER_CHECK,
};

struct krb5_kdc_configuration;
typedef struct krb5_kdc_configuration krb5_kdc_configuration;

/*
 * Access to request fields by plugins and other out-of-tree
 * consumers should be via the functions in kdc-accessors.h.
 */

struct kdc_request_desc;
typedef struct kdc_request_desc *kdc_request_t;

struct astgs_request_desc;
typedef struct astgs_request_desc *astgs_request_t;

struct kx509_req_context_desc;
typedef struct kx509_req_context_desc *kx509_req_context;

struct krb5_kdc_service {
    unsigned int flags;
#define KS_KRB5		1
#define KS_NO_LENGTH	2
    const char *name;
    krb5_error_code (*process)(kdc_request_t *, int *claim);
};

/*
 * The following fields are guaranteed stable within a major
 * release of Heimdal and can be manipulated by applications
 * that manage KDC requests themselves using libkdc.
 *
 * Applications can make custom KDC configuration available
 * to libkdc by using krb5_set_config().
 */

#define KRB5_KDC_CONFIGURATION_COMMON_ELEMENTS			\
    krb5_log_facility *logf;					\
    struct HDB **db;						\
    size_t num_db;						\
    const char *app;						\
								\
    /*
     * If non-null, contains static dummy data to include in
     * place of the FAST cookie when it is disabled.
     */								\
    krb5_data dummy_fast_cookie;				\
								\
    /*								\
     * Windows 2019 (and earlier versions) always sends the salt\
     * and Samba has testsuites that check this behaviour, so a \
     * Samba AD DC will set this flag to match the AS-REP packet\
     * exactly.						\
     */							\
    unsigned int force_include_pa_etype_salt : 1;		\
								\
    unsigned int tgt_use_strongest_session_key : 1;		\
    unsigned int preauth_use_strongest_session_key : 1;	\
    unsigned int svc_use_strongest_session_key : 1;		\
    unsigned int use_strongest_server_key : 1;			\
								\
    unsigned int require_pac : 1;				\
    unsigned int enable_fast : 1;				\
    unsigned int enable_fast_cookie : 1;			\
    unsigned int enable_armored_pa_enc_timestamp : 1;		\
    enum krb5_kdc_trpolicy trpolicy

#ifndef __KDC_LOCL_H__
struct krb5_kdc_configuration {
    KRB5_KDC_CONFIGURATION_COMMON_ELEMENTS;
};
#endif

typedef void *kdc_object_t;
typedef struct kdc_array_data *kdc_array_t;
typedef struct kdc_dict_data *kdc_dict_t;
typedef struct kdc_string_data *kdc_string_t;
typedef struct kdc_data_data *kdc_data_t;
typedef struct kdc_number_data *kdc_number_t;

typedef void (KRB5_CALLCONV *kdc_array_iterator_t)(kdc_object_t, void *, int *);

typedef void (KRB5_CALLCONV *kdc_type_dealloc)(kdc_object_t);

#include <kdc-protos.h>

#endif /* __KDC_H__ */
