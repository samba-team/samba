/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
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

#include <krb5_locl.h>
#include <mech_locl.h>

#include "gss-preauth-protos.h"
#include "gss-preauth-private.h"

static krb5_error_code
pa_gss_acquire_initiator_cred(krb5_context context,
                              krb5_gss_init_ctx gssic,
                              const krb5_creds *kcred,
                              gss_cred_id_t *cred)
{
    krb5_error_code ret;

    OM_uint32 major, minor;
    gss_const_OID mech;
    gss_OID_set_desc mechs;
    gss_name_t initiator_name = GSS_C_NO_NAME;
    OM_uint32 time_req;
    krb5_timestamp now;

    *cred = GSS_C_NO_CREDENTIAL;

    mech = _krb5_init_creds_get_gss_mechanism(context, gssic);

    mechs.count = 1;
    mechs.elements = (gss_OID)mech;

    ret = _krb5_gss_pa_unparse_name(context, kcred->client, &initiator_name);
    if (ret)
        return ret;

    krb5_timeofday(context, &now);
    if (kcred->times.endtime && kcred->times.endtime > now)
        time_req = kcred->times.endtime - now;
    else
        time_req = GSS_C_INDEFINITE;

    major = gss_acquire_cred(&minor, initiator_name, time_req, &mechs,
                             GSS_C_INITIATE, cred, NULL, NULL);
    ret = _krb5_gss_map_error(major, minor);

    gss_release_name(&major, &initiator_name);

    return ret;
}

static krb5_error_code KRB5_LIB_CALL
pa_gss_step(krb5_context context,
            krb5_gss_init_ctx gssic,
            const krb5_creds *kcred,
            gss_ctx_id_t *ctx,
            KDCOptions flags,
            krb5_data *enc_as_req,
            krb5_data *in,
            krb5_data *out)
{
    krb5_error_code ret;
    krb5_principal tgs_name = NULL;

    OM_uint32 major, minor;
    gss_cred_id_t cred;
    gss_name_t target_name = GSS_C_NO_NAME;
    OM_uint32 req_flags = GSS_C_MUTUAL_FLAG;
    OM_uint32 ret_flags;
    struct gss_channel_bindings_struct cb;
    gss_buffer_desc input_token, output_token = GSS_C_EMPTY_BUFFER;

    memset(&cb, 0, sizeof(cb));
    krb5_data_zero(out);

    if (flags.request_anonymous)
        req_flags |= GSS_C_ANON_FLAG;

    cred = (gss_cred_id_t)_krb5_init_creds_get_gss_cred(context, gssic);

    if (cred == GSS_C_NO_CREDENTIAL) {
        ret = pa_gss_acquire_initiator_cred(context, gssic, kcred, &cred);
        if (ret)
            goto out;

        _krb5_init_creds_set_gss_cred(context, gssic, cred);
    }

    ret = krb5_make_principal(context, &tgs_name, kcred->server->realm,
                              KRB5_TGS_NAME, kcred->server->realm, NULL);
    if (ret)
        goto out;

    ret = _krb5_gss_pa_unparse_name(context, tgs_name, &target_name);
    if (ret)
        goto out;

    _krb5_gss_data_to_buffer(enc_as_req, &cb.application_data);
    _krb5_gss_data_to_buffer(in, &input_token);

    major = gss_init_sec_context(&minor,
                                 cred,
                                 ctx,
                                 target_name,
                                 (gss_OID)_krb5_init_creds_get_gss_mechanism(context, gssic),
                                 req_flags,
                                 GSS_C_INDEFINITE,
                                 &cb,
                                 &input_token,
                                 NULL,
                                 &output_token,
                                 &ret_flags,
                                 NULL);

    _krb5_gss_buffer_to_data(&output_token, out);

    if (major == GSS_S_COMPLETE) {
        if ((ret_flags & GSS_C_MUTUAL_FLAG) == 0)
            ret = KRB5_MUTUAL_FAILED;
        else if ((ret_flags & req_flags) != req_flags)
            ret = KRB5KDC_ERR_BADOPTION;
        else
            ret = 0;
    } else
        ret = _krb5_gss_map_error(major, minor);

out:
    gss_release_name(&minor, &target_name);
    krb5_free_principal(context, tgs_name);

    return ret;
}

static krb5_error_code KRB5_LIB_CALL
pa_gss_finish(krb5_context context,
              krb5_gss_init_ctx gssic,
              const krb5_creds *kcred,
              gss_ctx_id_t ctx,
              krb5int32 nonce,
              krb5_enctype enctype,
              krb5_principal *client_p,
              krb5_keyblock **reply_key_p)
{
    krb5_error_code ret;
    krb5_principal client = NULL;
    krb5_keyblock *reply_key = NULL;

    OM_uint32 major, minor;
    gss_name_t initiator_name = GSS_C_NO_NAME;

    *client_p = NULL;
    *reply_key_p = NULL;

    major = gss_inquire_context(&minor,
                                ctx,
                                &initiator_name,
                                NULL, /* target_name */
                                NULL, /* lifetime_req */
                                NULL, /* mech_type */
                                NULL, /* ctx_flags */
                                NULL, /* locally_initiated */
                                NULL); /* open */

    if (GSS_ERROR(major))
        return _krb5_gss_map_error(major, minor);

    ret = _krb5_gss_pa_parse_name(context, initiator_name, 0, &client);
    if (ret)
        goto out;

    ret = _krb5_gss_pa_derive_key(context, ctx, nonce, enctype, &reply_key);
    if (ret)
        goto out;

    *client_p = client;
    client = NULL;

    *reply_key_p = reply_key;
    reply_key = NULL;

out:
    krb5_free_principal(context, client);
    if (reply_key)
        krb5_free_keyblock(context, reply_key);
    gss_release_name(&minor, &initiator_name);

    return ret;
}

static void KRB5_LIB_CALL
pa_gss_delete_sec_context(krb5_context context,
                          krb5_gss_init_ctx gssic,
                          gss_ctx_id_t ctx)
{
    OM_uint32 minor;

    gss_delete_sec_context(&minor, &ctx, GSS_C_NO_BUFFER);
}

static void KRB5_LIB_CALL
pa_gss_release_cred(krb5_context context,
                    krb5_gss_init_ctx gssic,
                    gss_cred_id_t cred)
{
    OM_uint32 minor;

    gss_release_cred(&minor, &cred);
}

krb5_error_code
krb5_gss_set_init_creds(krb5_context context,
                        krb5_init_creds_context ctx,
                        gss_const_cred_id_t gss_cred,
                        gss_const_OID gss_mech)
{
    return _krb5_init_creds_init_gss(context,ctx,
                                     pa_gss_step,
                                     pa_gss_finish,
                                     pa_gss_release_cred,
                                     pa_gss_delete_sec_context,
                                     gss_cred,
                                     gss_mech,
                                     0);
}
