/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Portions Copyright (c) 2019 Kungliga Tekniska Högskolan
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
 * 3. Neither the name of PADL Software nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY PADL SOFTWARE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL PADL SOFTWARE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "kdc_locl.h"

#include <gssapi/gssapi.h>
#include <gssapi_mech.h>

#include <gss-preauth-protos.h>
#include <gss-preauth-private.h>

#include "gss_preauth_authorizer_plugin.h"

struct gss_client_params {
    OM_uint32 major, minor;
    gss_ctx_id_t context_handle;
    gss_name_t initiator_name;
    gss_OID mech_type;
    gss_buffer_desc output_token;
    OM_uint32 flags;
    OM_uint32 lifetime;
    krb5_checksum req_body_checksum;
};

static void
pa_gss_display_status(astgs_request_t r,
                      OM_uint32 major,
                      OM_uint32 minor,
                      gss_client_params *gcp,
                      const char *msg);

static void
pa_gss_display_name(gss_name_t name,
                    gss_buffer_t namebuf,
                    gss_const_buffer_t *namebuf_p);

static void HEIM_CALLCONV
pa_gss_dealloc_client_params(void *ptr);

/*
 * Create a checksum over KDC-REQ-BODY (without the nonce), used to
 * assert the request is invariant within the preauth conversation.
 */
static krb5_error_code
pa_gss_create_req_body_checksum(astgs_request_t r,
                                krb5_checksum *checksum)
{
    krb5_error_code ret;
    KDC_REQ_BODY b = r->req.req_body;
    krb5_data data;
    size_t size;

    b.nonce = 0;

    ASN1_MALLOC_ENCODE(KDC_REQ_BODY, data.data, data.length, &b, &size, ret);
    heim_assert(ret || data.length,
                "internal asn1 encoder error");

    ret = krb5_create_checksum(r->context, NULL, 0, CKSUMTYPE_SHA256,
                               data.data, data.length, checksum);
    krb5_data_free(&data);

    return ret;
}

/*
 * Verify a checksum over KDC-REQ-BODY (without the nonce), used to
 * assert the request is invariant within the preauth conversation.
 */
static krb5_error_code
pa_gss_verify_req_body_checksum(astgs_request_t r,
                                krb5_checksum *checksum)
{
    krb5_error_code ret;
    KDC_REQ_BODY b = r->req.req_body;
    krb5_data data;
    size_t size;

    b.nonce = 0;

    ASN1_MALLOC_ENCODE(KDC_REQ_BODY, data.data, data.length, &b, &size, ret);
    heim_assert(ret || data.length,
                "internal asn1 encoder error");

    ret = _kdc_verify_checksum(r->context, NULL, 0, &data, checksum);
    krb5_data_free(&data);

    return ret;
}

/*
 * Decode the FX-COOKIE context state, consisting of the exported
 * GSS context token concatenated with the checksum of the initial
 * KDC-REQ-BODY.
 */
static krb5_error_code
pa_gss_decode_context_state(astgs_request_t r,
                            const krb5_data *state,
                            gss_buffer_t sec_context_token,
                            krb5_checksum *req_body_checksum)
{
    krb5_error_code ret;
    krb5_storage *sp;
    size_t cksumsize;
    krb5_data data;
    int32_t cksumtype;

    memset(req_body_checksum, 0, sizeof(*req_body_checksum));
    sec_context_token->length = 0;
    sec_context_token->value = NULL;

    krb5_data_zero(&data);

    sp = krb5_storage_from_readonly_mem(state->data, state->length);
    if (sp == NULL) {
        ret = krb5_enomem(r->context);
	goto out;
    }

    krb5_storage_set_eof_code(sp, KRB5_BAD_MSIZE);
    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_PACKED);

    ret = krb5_ret_data(sp, &data);
    if (ret)
        goto out;

    ret = krb5_ret_int32(sp, &cksumtype);
    if (ret)
        goto out;

    req_body_checksum->cksumtype = (CKSUMTYPE)cksumtype;

    if (req_body_checksum->cksumtype == CKSUMTYPE_NONE ||
	krb5_checksum_is_keyed(r->context, req_body_checksum->cksumtype)) {
	ret = KRB5KDC_ERR_SUMTYPE_NOSUPP;
	goto out;
    }

    ret = krb5_checksumsize(r->context, req_body_checksum->cksumtype,
			    &cksumsize);
    if (ret)
        goto out;

    req_body_checksum->checksum.data = malloc(cksumsize);
    if (req_body_checksum->checksum.data == NULL) {
        ret = krb5_enomem(r->context);
        goto out;
    }

    if (krb5_storage_read(sp, req_body_checksum->checksum.data,
                          cksumsize) != cksumsize) {
        ret = KRB5_BAD_MSIZE;
        goto out;
    }

    req_body_checksum->checksum.length = cksumsize;

    _krb5_gss_data_to_buffer(&data, sec_context_token);

out:
    if (ret) {
        krb5_data_free(&data);
        free_Checksum(req_body_checksum);
        memset(req_body_checksum, 0, sizeof(*req_body_checksum));
    }
    krb5_storage_free(sp);

    return ret;
}

/*
 * Deserialize a GSS-API security context from the FAST cookie.
 */
static krb5_error_code
pa_gss_get_context_state(astgs_request_t r,
                         gss_client_params *gcp)
{
    int idx = 0;
    PA_DATA *fast_pa;
    krb5_error_code ret;

    OM_uint32 major, minor;
    gss_buffer_desc sec_context_token;

    fast_pa = krb5_find_padata(r->fast.fast_state.val,
                               r->fast.fast_state.len,
                               KRB5_PADATA_GSS, &idx);
    if (fast_pa == NULL)
        return 0;

    ret = pa_gss_decode_context_state(r, &fast_pa->padata_value,
                                      &sec_context_token,
                                      &gcp->req_body_checksum);
    if (ret)
        return ret;

    ret = pa_gss_verify_req_body_checksum(r, &gcp->req_body_checksum);
    if (ret) {
        gss_release_buffer(&minor, &sec_context_token);
        return ret;
    }

    major = gss_import_sec_context(&minor, &sec_context_token,
                                   &gcp->context_handle);
    if (GSS_ERROR(major)) {
        pa_gss_display_status(r, major, minor, gcp,
                              "Failed to import GSS pre-authentication context");
	ret = _krb5_gss_map_error(major, minor);
    } else
	ret = 0;

    gss_release_buffer(&minor, &sec_context_token);

    return ret;
}

/*
 * Encode the FX-COOKIE context state, consisting of the exported
 * GSS context token concatenated with the checksum of the initial
 * KDC-REQ-BODY.
 */
static krb5_error_code
pa_gss_encode_context_state(astgs_request_t r,
                            gss_const_buffer_t sec_context_token,
                            const krb5_checksum *req_body_checksum,
                            krb5_data *state)
{
    krb5_error_code ret;
    krb5_storage *sp;
    krb5_data data;

    krb5_data_zero(state);

    sp = krb5_storage_emem();
    if (sp == NULL) {
        ret = krb5_enomem(r->context);
	goto out;
    }

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_PACKED);

    _krb5_gss_buffer_to_data(sec_context_token, &data);

    ret = krb5_store_data(sp, data);
    if (ret)
        goto out;

    ret = krb5_store_int32(sp, (int32_t)req_body_checksum->cksumtype);
    if (ret)
        goto out;

    ret = krb5_store_bytes(sp, req_body_checksum->checksum.data,
                           req_body_checksum->checksum.length);
    if (ret)
        goto out;

    ret = krb5_storage_to_data(sp, state);
    if (ret)
        goto out;

out:
    krb5_storage_free(sp);

    return ret;
}

/*
 * Serialize a GSS-API security context into a FAST cookie.
 */
static krb5_error_code
pa_gss_set_context_state(astgs_request_t r,
                         gss_client_params *gcp)
{
    krb5_error_code ret;
    PA_DATA *fast_pa;
    int idx = 0;
    krb5_data state;

    OM_uint32 major, minor;
    gss_buffer_desc sec_context_token = GSS_C_EMPTY_BUFFER;

    /*
     * On second and subsequent responses, we can recycle the checksum
     * from the request as it is validated and invariant. This saves
     * re-encoding the request body again.
     */
    if (gcp->req_body_checksum.cksumtype == CKSUMTYPE_NONE) {
        ret = pa_gss_create_req_body_checksum(r, &gcp->req_body_checksum);
        if (ret)
            return ret;
    }

    major = gss_export_sec_context(&minor, &gcp->context_handle,
                                   &sec_context_token);
    if (GSS_ERROR(major)) {
        pa_gss_display_status(r, major, minor, gcp,
                              "Failed to export GSS pre-authentication context");
        return _krb5_gss_map_error(major, minor);
    }

    ret = pa_gss_encode_context_state(r, &sec_context_token,
                                      &gcp->req_body_checksum, &state);
    gss_release_buffer(&minor, &sec_context_token);
    if (ret)
        return ret;

    fast_pa = krb5_find_padata(r->fast.fast_state.val,
                               r->fast.fast_state.len,
                               KRB5_PADATA_GSS, &idx);
    if (fast_pa) {
        krb5_data_free(&fast_pa->padata_value);
        fast_pa->padata_value = state;
    } else {
        ret = krb5_padata_add(r->context, &r->fast.fast_state,
                              KRB5_PADATA_GSS,
                              state.data, state.length);
        if (ret)
            krb5_data_free(&state);
    }

    return ret;
}

static krb5_error_code
pa_gss_acquire_acceptor_cred(astgs_request_t r,
                             gss_client_params *gcp,
                             gss_cred_id_t *cred)
{
    krb5_error_code ret;
    krb5_principal tgs_name;

    OM_uint32 major, minor;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_buffer_desc display_name = GSS_C_EMPTY_BUFFER;
    gss_const_buffer_t display_name_p;

    *cred = GSS_C_NO_CREDENTIAL;

    ret = krb5_make_principal(r->context, &tgs_name, r->req.req_body.realm,
                              KRB5_TGS_NAME, r->req.req_body.realm, NULL);
    if (ret)
        return ret;

    ret = _krb5_gss_pa_unparse_name(r->context, tgs_name, &target_name);
    krb5_free_principal(r->context, tgs_name);
    if (ret)
        return ret;

    pa_gss_display_name(target_name, &display_name, &display_name_p);

    kdc_log(r->context, r->config, 4,
            "Acquiring GSS acceptor credential for %.*s",
            (int)display_name_p->length, (char *)display_name_p->value);

    major = gss_acquire_cred(&minor, target_name, GSS_C_INDEFINITE,
                             r->config->gss_mechanisms_allowed,
                             GSS_C_ACCEPT, cred, NULL, NULL);
    ret = _krb5_gss_map_error(major, minor);

    if (ret)
        pa_gss_display_status(r, major, minor, gcp,
                              "Failed to acquire GSS acceptor credential");

    gss_release_buffer(&minor, &display_name);
    gss_release_name(&minor, &target_name);

    return ret;
}

krb5_error_code
_kdc_gss_rd_padata(astgs_request_t r,
                   const PA_DATA *pa,
                   gss_client_params **pgcp,
                   int *open)
{
    krb5_error_code ret;

    OM_uint32 minor;
    gss_client_params *gcp = NULL;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    struct gss_channel_bindings_struct cb;

    memset(&cb, 0, sizeof(cb));

    *pgcp = NULL;

    if (!r->config->enable_gss_preauth) {
        ret = KRB5KDC_ERR_POLICY;
        goto out;
    }

    if (pa->padata_value.length == 0) {
        ret = KRB5KDC_ERR_PREAUTH_FAILED;
        goto out;
    }

    gcp = kdc_object_alloc(sizeof(*gcp), "pa-gss-client-params", pa_gss_dealloc_client_params);
    if (gcp == NULL) {
        ret = krb5_enomem(r->context);
        goto out;
    }

    /* errors are fast fail until gss_accept_sec_context() is called */
    gcp->major = GSS_S_NO_CONTEXT;

    ret = pa_gss_get_context_state(r, gcp);
    if (ret)
        goto out;

    ret = pa_gss_acquire_acceptor_cred(r, gcp, &cred);
    if (ret)
        goto out;

    _krb5_gss_data_to_buffer(&pa->padata_value, &input_token);
    _krb5_gss_data_to_buffer(&r->req.req_body._save, &cb.application_data);

    gcp->major = gss_accept_sec_context(&gcp->minor,
                                        &gcp->context_handle,
                                        cred,
                                        &input_token,
                                        &cb,
                                        &gcp->initiator_name,
                                        &gcp->mech_type,
                                        &gcp->output_token,
                                        &gcp->flags,
                                        &gcp->lifetime,
                                        NULL); /* delegated_cred_handle */

    ret = _krb5_gss_map_error(gcp->major, gcp->minor);

    if (GSS_ERROR(gcp->major)) {
        pa_gss_display_status(r, gcp->major, gcp->minor, gcp,
                              "Failed to accept GSS security context");
    } else if ((gcp->flags & GSS_C_ANON_FLAG) && !_kdc_is_anon_request(&r->req)) {
        kdc_log(r->context, r->config, 2,
                "Anonymous GSS pre-authentication request w/o anonymous flag");
        ret = KRB5KDC_ERR_BADOPTION;
    } else
        *open = (gcp->major == GSS_S_COMPLETE);

out:
    gss_release_cred(&minor, &cred);

    if (gcp && gcp->major != GSS_S_NO_CONTEXT)
        *pgcp = gcp;
    else
        kdc_object_release(gcp);

    return ret;
}

krb5_timestamp
_kdc_gss_endtime(astgs_request_t r,
                 gss_client_params *gcp)
{
    krb5_timestamp endtime;

    if (gcp->lifetime == GSS_C_INDEFINITE)
        endtime = 0;
    else
        endtime = kdc_time + gcp->lifetime;

    kdc_log(r->context, r->config, 10,
            "GSS pre-authentication endtime is %ld", (long)endtime);

    return endtime;
}

struct pa_gss_authorize_plugin_ctx {
    astgs_request_t r;
    struct gss_client_params *gcp;
    krb5_boolean authorized;
    krb5_principal initiator_princ;
};

static krb5_error_code KRB5_LIB_CALL
pa_gss_authorize_cb(krb5_context context,
                    const void *plug,
                    void *plugctx,
                    void *userctx)
{
    const krb5plugin_gss_preauth_authorizer_ftable *authorizer = plug;
    struct pa_gss_authorize_plugin_ctx *pa_gss_authorize_plugin_ctx = userctx;

    return authorizer->authorize(plugctx,
                                 pa_gss_authorize_plugin_ctx->r,
                                 pa_gss_authorize_plugin_ctx->gcp->initiator_name,
                                 pa_gss_authorize_plugin_ctx->gcp->mech_type,
                                 pa_gss_authorize_plugin_ctx->gcp->flags,
                                 &pa_gss_authorize_plugin_ctx->authorized,
                                 &pa_gss_authorize_plugin_ctx->initiator_princ);
}

static const char *plugin_deps[] = {
    "kdc",
    "hdb",
    "gssapi",
    "krb5",
    NULL
};

static struct heim_plugin_data
gss_preauth_authorizer_data = {
    "kdc",
    KDC_GSS_PREAUTH_AUTHORIZER,
    KDC_GSS_PREAUTH_AUTHORIZER_VERSION_1,
    plugin_deps,
    kdc_get_instance
};

static krb5_error_code
pa_gss_authorize_plugin(astgs_request_t r,
                        struct gss_client_params *gcp,
                        gss_const_buffer_t display_name,
                        krb5_boolean *authorized,
                        krb5_principal *initiator_princ)
{
    krb5_error_code ret;
    struct pa_gss_authorize_plugin_ctx ctx;

    ctx.r = r;
    ctx.gcp = gcp;
    ctx.authorized = 0;
    ctx.initiator_princ = NULL;

    krb5_clear_error_message(r->context);
    ret = _krb5_plugin_run_f(r->context, &gss_preauth_authorizer_data,
                             0, &ctx, pa_gss_authorize_cb);

    if (ret != KRB5_PLUGIN_NO_HANDLE) {
        const char *msg = krb5_get_error_message(r->context, ret);

        kdc_log(r->context, r->config, 7,
                "GSS authz plugin %sauthorize%s %s initiator %.*s: %s",
                ctx.authorized ? "" : "did not " ,
                ctx.authorized ? "d" : "",
                gss_oid_to_name(gcp->mech_type),
                (int)display_name->length, (char *)display_name->value,
                msg);
        krb5_free_error_message(r->context, msg);
    }

    *authorized = ctx.authorized;
    *initiator_princ = ctx.initiator_princ;

    return ret;
}

static krb5_error_code
pa_gss_authorize_default(astgs_request_t r,
                         struct gss_client_params *gcp,
                         gss_const_buffer_t display_name,
                         krb5_boolean *authorized,
                         krb5_principal *initiator_princ)
{
    krb5_error_code ret;
    krb5_principal principal;
    krb5_const_realm realm = r->server->principal->realm;
    int flags = 0, cross_realm_allowed = 0, unauth_anon;

    /*
     * gss_cross_realm_mechanisms_allowed is a list of GSS-API mechanisms
     * that are allowed to map directly to Kerberos principals in any
     * realm. If the authenticating mechanism is not on the list, then
     * the initiator will be mapped to an enterprise principal in the
     * service realm. This is useful to stop synthetic principals in
     * foreign realms being conflated with true cross-realm principals.
     */
    if (r->config->gss_cross_realm_mechanisms_allowed) {
        OM_uint32 minor;

        gss_test_oid_set_member(&minor, gcp->mech_type,
                                r->config->gss_cross_realm_mechanisms_allowed,
                                &cross_realm_allowed);
    }

    kdc_log(r->context, r->config, 10,
            "Initiator %.*s will be mapped to %s",
            (int)display_name->length, (char *)display_name->value,
            cross_realm_allowed ? "nt-principal" : "nt-enterprise-principal");

    if (!cross_realm_allowed)
        flags |= KRB5_PRINCIPAL_PARSE_ENTERPRISE | KRB5_PRINCIPAL_PARSE_NO_REALM;

    ret = _krb5_gss_pa_parse_name(r->context, gcp->initiator_name,
                                  flags, &principal);
    if (ret) {
        const char *msg = krb5_get_error_message(r->context, ret);

        kdc_log(r->context, r->config, 2,
                "Failed to parse %s initiator name %.*s: %s",
                gss_oid_to_name(gcp->mech_type),
                (int)display_name->length, (char *)display_name->value, msg);
        krb5_free_error_message(r->context, msg);

        return ret;
    }

    /*
     * GSS_C_ANON_FLAG indicates the client requested anonymous authentication
     * (it is validated against the request-anonymous flag).
     *
     * _kdc_is_anonymous_pkinit() returns TRUE if the principal contains both
     * the well known anonymous name and realm.
     */
    unauth_anon = (gcp->flags & GSS_C_ANON_FLAG) &&
        _kdc_is_anonymous_pkinit(r->context, principal);

    /*
     * Always use the anonymous entry created in our HDB, i.e. with the local
     * realm, for authorizing anonymous requests. This matches PKINIT behavior
     * as anonymous PKINIT requests include the KDC realm in the request.
     */
    if (unauth_anon || (flags & KRB5_PRINCIPAL_PARSE_ENTERPRISE)) {
        ret = krb5_principal_set_realm(r->context, principal, realm);
        if (ret) {
            krb5_free_principal(r->context, principal);
            return ret;
        }
    }

    if (unauth_anon) {
        /*
         * Special case to avoid changing _kdc_as_rep(). If the initiator is
         * the unauthenticated anonymous principal, r->client_princ also needs
         * to be set in order to force the AS-REP realm to be set to the well-
         * known anonymous identity. This is because (unlike anonymous PKINIT)
         * we only require the anonymous flag, not the anonymous name, in the
         * client AS-REQ.
         */
        krb5_principal anon_princ;

        ret = krb5_copy_principal(r->context, principal, &anon_princ);
        if (ret)
            return ret;

        krb5_free_principal(r->context, r->client_princ);
        r->client_princ = anon_princ;
    }

    *authorized = TRUE;
    *initiator_princ = principal;

    return 0;
}

krb5_error_code
_kdc_gss_check_client(astgs_request_t r,
                      gss_client_params *gcp,
                      char **client_name)
{
    krb5_error_code ret;
    krb5_principal initiator_princ = NULL;
    hdb_entry *initiator = NULL;
    krb5_boolean authorized = FALSE;
    HDB *clientdb = r->clientdb;

    OM_uint32 minor;
    gss_buffer_desc display_name = GSS_C_EMPTY_BUFFER;
    gss_const_buffer_t display_name_p;

    *client_name = NULL;

    pa_gss_display_name(gcp->initiator_name, &display_name, &display_name_p);

    /*
     * If no plugins handled the authorization request, then all clients
     * are authorized as the directly corresponding Kerberos principal.
     */
    ret = pa_gss_authorize_plugin(r, gcp, display_name_p,
                                  &authorized, &initiator_princ);
    if (ret == KRB5_PLUGIN_NO_HANDLE)
        ret = pa_gss_authorize_default(r, gcp, display_name_p,
                                       &authorized, &initiator_princ);
    if (ret == 0 && !authorized)
        ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
    if (ret)
        goto out;

    ret = krb5_unparse_name(r->context, initiator_princ, client_name);
    if (ret)
        goto out;

    kdc_log(r->context, r->config, 4,
            "Mapped GSS %s initiator %.*s to principal %s",
            gss_oid_to_name(gcp->mech_type),
            (int)display_name_p->length, (char *)display_name_p->value,
            *client_name);

    ret = _kdc_db_fetch(r->context,
                        r->config,
                        initiator_princ,
                        HDB_F_FOR_AS_REQ | HDB_F_GET_CLIENT |
                             HDB_F_CANON | HDB_F_SYNTHETIC_OK,
                        NULL,
                        &r->clientdb,
                        &initiator);
    if (ret) {
        const char *msg = krb5_get_error_message(r->context, ret);

        kdc_log(r->context, r->config, 4, "UNKNOWN -- %s: %s",
                *client_name, msg);
        krb5_free_error_message(r->context, msg);

        goto out;
    }

    /*
     * If the AS-REQ client name was the well-known federated name, then
     * replace the client name with the initiator name. Otherwise, the
     * two principals must match, noting that GSS pre-authentication is
     * for authentication, not general purpose impersonation.
     */
    if (krb5_principal_is_federated(r->context, r->client->principal)) {
        initiator->flags.force_canonicalize = 1;

        _kdc_free_ent(r->context, clientdb, r->client);
        r->client = initiator;
        initiator = NULL;
    } else if (!krb5_principal_compare(r->context,
                                       r->client->principal,
                                       initiator->principal)) {
        kdc_log(r->context, r->config, 2,
                "GSS %s initiator %.*s does not match principal %s",
                gss_oid_to_name(gcp->mech_type),
                (int)display_name_p->length, (char *)display_name_p->value,
                r->cname);
        ret = KRB5_KDC_ERR_CLIENT_NAME_MISMATCH;
        goto out;
    }

out:
    krb5_free_principal(r->context, initiator_princ);
    if (initiator)
        _kdc_free_ent(r->context, r->clientdb, initiator);
    gss_release_buffer(&minor, &display_name);

    return ret;
}

krb5_error_code
_kdc_gss_mk_pa_reply(astgs_request_t r,
                     gss_client_params *gcp)
{
    krb5_error_code ret;
    const KDC_REQ *req = &r->req;

    if (gcp->major == GSS_S_COMPLETE) {
        krb5_enctype enctype;
        uint32_t kfe = 0;
        krb5_keyblock *reply_key = NULL;

        if (krb5_principal_is_krbtgt(r->context, r->server_princ))
            kfe |= KFE_IS_TGS;

        ret = _kdc_find_etype(r, kfe, req->req_body.etype.val,
                              req->req_body.etype.len, &enctype, NULL, NULL);
        if (ret)
            return ret;

        ret = _krb5_gss_pa_derive_key(r->context, gcp->context_handle,
                                      req->req_body.nonce,
                                      enctype, &reply_key);
        if (ret) {
            kdc_log(r->context, r->config, 10,
                    "Failed to derive GSS reply key: %d", ret);
            return ret;
        }

        krb5_free_keyblock_contents(r->context, &r->reply_key);
        r->reply_key = *reply_key;
        free(reply_key);
    } else if (gcp->major == GSS_S_CONTINUE_NEEDED) {
        ret = pa_gss_set_context_state(r, gcp);
        if (ret)
            return ret;
    }

    /* only return padata in error case if we have an error token */
    if (!GSS_ERROR(gcp->major) || gcp->output_token.length) {
        ret = krb5_padata_add(r->context, r->rep.padata, KRB5_PADATA_GSS,
                              gcp->output_token.value, gcp->output_token.length);
        if (ret)
            return ret;

        /* token is now owned by r->rep.padata */
        gcp->output_token.length = 0;
        gcp->output_token.value = NULL;
    }

    if (gcp->major == GSS_S_CONTINUE_NEEDED)
        ret = KRB5_KDC_ERR_MORE_PREAUTH_DATA_REQUIRED;
    else
        ret = _krb5_gss_map_error(gcp->major, gcp->minor);

    return ret;
}

krb5_error_code
_kdc_gss_mk_composite_name_ad(astgs_request_t r,
                              gss_client_params *gcp)
{
    krb5_error_code ret;
    krb5_data data;

    OM_uint32 major, minor;
    gss_buffer_desc namebuf = GSS_C_EMPTY_BUFFER;

    if (!r->config->enable_gss_auth_data || (gcp->flags & GSS_C_ANON_FLAG))
        return 0;

    major = gss_export_name_composite(&minor, gcp->initiator_name, &namebuf);
    if (major == GSS_S_COMPLETE) {
        _krb5_gss_buffer_to_data(&namebuf, &data);

        ret = _kdc_tkt_add_if_relevant_ad(r->context, &r->et,
                                          KRB5_AUTHDATA_GSS_COMPOSITE_NAME,
                                          &data);
    } else if (major != GSS_S_UNAVAILABLE)
        ret = _krb5_gss_map_error(major, minor);
    else
        ret = 0;

    gss_release_buffer(&minor, &namebuf);

    return ret;
}

static void HEIM_CALLCONV
pa_gss_dealloc_client_params(void *ptr)
{
    gss_client_params *gcp = ptr;
    OM_uint32 minor;

    if (gcp == NULL)
        return;

    gss_delete_sec_context(&minor, &gcp->context_handle, GSS_C_NO_BUFFER);
    gss_release_name(&minor, &gcp->initiator_name);
    gss_release_buffer(&minor, &gcp->output_token);
    free_Checksum(&gcp->req_body_checksum);
    memset(gcp, 0, sizeof(*gcp));
}

krb5_error_code
_kdc_gss_get_mechanism_config(krb5_context context,
                              const char *section,
                              const char *key,
                              gss_OID_set *oidsp)
{
    krb5_error_code ret;
    char **mechs, **mechp;

    gss_OID_set oids = GSS_C_NO_OID_SET;
    OM_uint32 major, minor;

    mechs = krb5_config_get_strings(context, NULL, section, key, NULL);
    if (mechs == NULL)
        return 0;

    major = gss_create_empty_oid_set(&minor, &oids);
    if (GSS_ERROR(major)) {
        krb5_config_free_strings(mechs);
        return _krb5_gss_map_error(major, minor);
    }

    for (mechp = mechs; *mechp; mechp++) {
        gss_OID oid = gss_name_to_oid(*mechp);
        if (oid == GSS_C_NO_OID)
            continue;

        major = gss_add_oid_set_member(&minor, oid, &oids);
        if (GSS_ERROR(major))
            break;
    }

    ret = _krb5_gss_map_error(major, minor);
    if (ret == 0)
        *oidsp = oids;
    else
        gss_release_oid_set(&minor, &oids);

    krb5_config_free_strings(mechs);

    return ret;
}

static void
pa_gss_display_status(astgs_request_t r,
                      OM_uint32 major,
                      OM_uint32 minor,
                      gss_client_params *gcp,
                      const char *msg)
{
    krb5_error_code ret = _krb5_gss_map_error(major, minor);
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    OM_uint32 dmaj, dmin;
    OM_uint32 more = 0;
    char *gmmsg = NULL;
    char *gmsg = NULL;
    char *s = NULL;

    do {
        gss_release_buffer(&dmin, &buf);
        dmaj = gss_display_status(&dmin, major, GSS_C_GSS_CODE, GSS_C_NO_OID,
                                  &more, &buf);
        if (GSS_ERROR(dmaj) ||
            buf.length >= INT_MAX ||
            asprintf(&s, "%s%s%.*s", gmsg ? gmsg : "", gmsg ? ": " : "",
                     (int)buf.length, (char *)buf.value) == -1 ||
            s == NULL) {
            free(gmsg);
            gmsg = NULL;
            break;
        }
        gmsg = s;
        s = NULL;
    } while (!GSS_ERROR(dmaj) && more);

    if (gcp->mech_type != GSS_C_NO_OID) {
        do {
            gss_release_buffer(&dmin, &buf);
            dmaj = gss_display_status(&dmin, major, GSS_C_MECH_CODE,
                                      gcp->mech_type, &more, &buf);
            if (GSS_ERROR(dmaj) ||
                asprintf(&s, "%s%s%.*s", gmmsg ? gmmsg : "", gmmsg ? ": " : "",
                         (int)buf.length, (char *)buf.value) == -1 ||
                s == NULL) {
                free(gmmsg);
                gmmsg = NULL;
                break;
            }
            gmmsg = s;
            s = NULL;
        } while (!GSS_ERROR(dmaj) && more);
    }

    if (gmsg == NULL)
        krb5_set_error_message(r->context, ENOMEM,
                               "Error displaying GSS-API status");
    else
        krb5_set_error_message(r->context, ret, "%s%s%s%s", gmsg,
                               gmmsg ? " (" : "", gmmsg ? gmmsg : "",
                               gmmsg ? ")" : "");
    krb5_prepend_error_message(r->context, ret, "%s", msg);

    kdc_log(r->context, r->config, 1,
            "%s: %s%s%s%s",
            msg, gmsg, gmmsg ? " (" : "", gmmsg ? gmmsg : "",
            gmmsg ? ")" : "");

    free(gmmsg);
    free(gmsg);
}

static const gss_buffer_desc
gss_pa_unknown_display_name = {
    sizeof("<unknown name>") - 1,
    "<unknown name>"
};

static void
pa_gss_display_name(gss_name_t name,
                    gss_buffer_t namebuf,
                    gss_const_buffer_t *namebuf_p)
{
    OM_uint32 major, minor;

    major = gss_display_name(&minor, name, namebuf, NULL);
    if (GSS_ERROR(major))
        *namebuf_p = &gss_pa_unknown_display_name;
    else
        *namebuf_p = namebuf;
}

static krb5_error_code KRB5_LIB_CALL
pa_gss_finalize_pac_cb(krb5_context context,
		        const void *plug,
		        void *plugctx,
		        void *userctx)
{
    const krb5plugin_gss_preauth_authorizer_ftable *authorizer = plug;

    return authorizer->finalize_pac(plugctx, userctx);
}


krb5_error_code
_kdc_gss_finalize_pac(astgs_request_t r,
		      gss_client_params *gcp)
{
    krb5_error_code ret;

    krb5_clear_error_message(r->context);
    ret = _krb5_plugin_run_f(r->context, &gss_preauth_authorizer_data,
                             0, r, pa_gss_finalize_pac_cb);

    if (ret == KRB5_PLUGIN_NO_HANDLE)
	ret = 0;

    return ret;
}
