/*
 * Copyright (c) 2006 Kungliga Tekniska Högskolan
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

/* $Id$ */

#ifndef HEIMDAL_KDC_KDC_PLUGIN_H
#define HEIMDAL_KDC_KDC_PLUGIN_H 1

#include <krb5.h>
#include <kdc.h>
#include <kdc-accessors.h>
#include <hdb.h>

/*
 * Allocate a PAC for the given client with krb5_pac_init(),
 * and fill its contents in with krb5_pac_add_buffer().
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_pac_generate)(void *,
					     astgs_request_t,
					     hdb_entry *, /* client */
					     hdb_entry *, /* server */
					     const krb5_keyblock *, /* pk_replykey */
					     uint64_t,	      /* pac_attributes */
					     krb5_pac *);

/*
 * Verify the PAC KDC signatures by fetching the appropriate TGS key
 * and calling krb5_pac_verify() with that key. Optionally update the
 * PAC buffers on success.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_pac_verify)(void *,
					   astgs_request_t,
					   const krb5_principal, /* new ticket client */
					   const krb5_principal, /* delegation proxy */
					   hdb_entry *,/* client */
					   hdb_entry *,/* server */
					   hdb_entry *,/* krbtgt */
					   krb5_pac *);

/*
 * Authorize the client principal's access to the Authentication Service (AS).
 * This function is called after any pre-authentication has completed.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_client_access)(void *, astgs_request_t);

/*
 * A referral policy plugin can either rewrite the server principal
 * by resetting priv->server_princ, or it can disable referral
 * processing entirely by returning an error.
 *
 * The error code from the previous server lookup is available as r->ret.
 *
 * If the function returns KRB5_PLUGIN_NO_HANDLE, the TGS will continue
 * with its default referral handling.
 *
 * Note well: the plugin should free priv->server_princ is replacing.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_referral_policy)(void *, astgs_request_t);

/*
 * Update the AS or TGS reply immediately prior to encoding.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_finalize_reply)(void *, astgs_request_t);

/*
 * Audit an AS or TGS request. This function is called after encoding the
 * reply (on success), or before encoding the error message. If a HDB audit
 * function is also present, it is called after this one.
 *
 * The request should not be modified by the plugin.
 */

typedef krb5_error_code
(KRB5_CALLCONV *krb5plugin_kdc_audit)(void *, astgs_request_t);

/*
 * Plugins should carefully check API contract notes for changes
 * between plugin API versions.
 */
#define KRB5_PLUGIN_KDC_VERSION_10	10

typedef struct krb5plugin_kdc_ftable {
    HEIM_PLUGIN_FTABLE_COMMON_ELEMENTS(krb5_context);
    krb5plugin_kdc_pac_generate		pac_generate;
    krb5plugin_kdc_pac_verify		pac_verify;
    krb5plugin_kdc_client_access	client_access;
    krb5plugin_kdc_referral_policy	referral_policy;
    krb5plugin_kdc_finalize_reply	finalize_reply;
    krb5plugin_kdc_audit		audit;
} krb5plugin_kdc_ftable;

#endif /* HEIMDAL_KDC_KDC_PLUGIN_H */
