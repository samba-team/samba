/*
 * Copyright (C) 2021, PADL Software Pty Ltd.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "spnego_locl.h"

#define SC_MECH_TYPES               0x0001
#define SC_PREFERRED_MECH_TYPE      0x0002
#define SC_SELECTED_MECH_TYPE       0x0004
#define SC_NEGOTIATED_MECH_TYPE     0x0008
#define SC_NEGOTIATED_CTX_ID        0x0010
#define SC_MECH_FLAGS               0x0020
#define SC_MECH_TIME_REC            0x0040
#define SC_MECH_SRC_NAME            0x0080
#define SC_TARGET_NAME              0x0100
#define SC_NEGOEX                   0x0200

#define SNC_OID                     0x01
#define SNC_MECH_CONTEXT            0x02
#define SNC_METADATA                0x04

static krb5_error_code
ret_spnego_context(krb5_storage *sp, gssspnego_ctx *ctxp);
static krb5_error_code
store_spnego_context(krb5_storage *sp, gssspnego_ctx ctx);

static krb5_error_code
ret_negoex_auth_mech(krb5_storage *sp, struct negoex_auth_mech **mechp);
static krb5_error_code
store_negoex_auth_mech(krb5_storage *sp, struct negoex_auth_mech *mech);

#ifdef sc_flags
#undef sc_flags
#endif

static uint16_t
spnego_flags_to_int(struct spnego_flags flags);
static struct spnego_flags
int_to_spnego_flags(uint16_t f);

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_import_sec_context_internal(OM_uint32 *minor,
                                        gss_const_buffer_t buffer,
                                        gssspnego_ctx *ctxp)
{
    krb5_error_code ret;
    krb5_storage *sp;

    sp = krb5_storage_from_readonly_mem(buffer->value, buffer->length);
    if (sp == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_PACKED);

    ret = ret_spnego_context(sp, ctxp);

    krb5_storage_free(sp);

    *minor = ret;
    return ret ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

OM_uint32 GSSAPI_CALLCONV
_gss_spnego_export_sec_context_internal(OM_uint32 *minor,
                                        gssspnego_ctx ctx,
                                        gss_buffer_t buffer)
{
    krb5_error_code ret;
    krb5_storage *sp;
    krb5_data data;

    sp = krb5_storage_emem();
    if (sp == NULL) {
        *minor = ENOMEM;
        return GSS_S_FAILURE;
    }

    krb5_data_zero(&data);

    krb5_storage_set_byteorder(sp, KRB5_STORAGE_BYTEORDER_PACKED);

    ret = store_spnego_context(sp, ctx);
    if (ret == 0)
        ret = krb5_storage_to_data(sp, &data);
    if (ret == 0) {
        buffer->length = data.length;
        buffer->value = data.data;
    }

    krb5_storage_free(sp);

    *minor = ret;
    return ret ? GSS_S_FAILURE : GSS_S_COMPLETE;
}

static krb5_error_code
ret_spnego_context(krb5_storage *sp, gssspnego_ctx *ctxp)
{
    OM_uint32 major = GSS_S_COMPLETE, minor;
    gssspnego_ctx ctx = NULL;
    krb5_error_code ret = 0;
    krb5_data data;
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    uint16_t sc_flags, spnego_flags;

    *ctxp = NULL;
    krb5_data_zero(&data);

    CHECK(major, _gss_spnego_alloc_sec_context(&minor, (gss_ctx_id_t *)&ctx));

    CHECK(ret, krb5_ret_uint16(sp, &sc_flags));
    CHECK(ret, krb5_ret_uint16(sp, &spnego_flags));
    ctx->flags = int_to_spnego_flags(spnego_flags);

    if (sc_flags & SC_MECH_TYPES)
        CHECK(major, _gss_mg_ret_buffer(&minor, sp, &ctx->NegTokenInit_mech_types));
    if (sc_flags & SC_PREFERRED_MECH_TYPE)
        CHECK(major, _gss_mg_ret_oid(&minor, sp, &ctx->preferred_mech_type));
    if (sc_flags & SC_SELECTED_MECH_TYPE)
        CHECK(major, _gss_mg_ret_oid(&minor, sp, &ctx->selected_mech_type));
    if (sc_flags & SC_NEGOTIATED_MECH_TYPE)
        CHECK(major, _gss_mg_ret_oid(&minor, sp, &ctx->negotiated_mech_type));

    if (sc_flags & SC_NEGOTIATED_CTX_ID) {
        CHECK(major, _gss_mg_ret_buffer(&minor, sp, &buf));
        CHECK(major, gss_import_sec_context(&minor, &buf,
              &ctx->negotiated_ctx_id));
        gss_release_buffer(&minor, &buf);
    }

    if (sc_flags & SC_MECH_FLAGS)
        CHECK(ret, krb5_ret_uint32(sp, &ctx->mech_flags));
    if (sc_flags & SC_MECH_TIME_REC)
        CHECK(ret, krb5_ret_uint32(sp, &ctx->mech_time_rec));
    else
        ctx->mech_time_rec = GSS_C_INDEFINITE;

    if (sc_flags & SC_MECH_SRC_NAME) {
        CHECK(major, _gss_mg_ret_buffer(&minor, sp, &buf));
        CHECK(major, gss_import_name(&minor, &buf, GSS_C_NT_EXPORT_NAME,
                                     &ctx->mech_src_name));
        gss_release_buffer(&minor, &buf);
    }

    if (sc_flags & SC_TARGET_NAME) {
        CHECK(major, _gss_mg_ret_buffer(&minor, sp, &buf));
        CHECK(major, gss_import_name(&minor, &buf, GSS_C_NT_EXPORT_NAME,
                                     &ctx->target_name));
        gss_release_buffer(&minor, &buf);
    }

    if (sc_flags & SC_NEGOEX) {
        uint8_t i, nschemes;

        CHECK(ret, krb5_ret_uint8(sp, &ctx->negoex_step));

        CHECK(ret, krb5_ret_data(sp, &data));
        ctx->negoex_transcript = krb5_storage_emem();
        if (ctx->negoex_transcript == NULL) {
            ret = ENOMEM;
            goto fail;
        }

        krb5_storage_set_byteorder(ctx->negoex_transcript,
                                   KRB5_STORAGE_BYTEORDER_LE);
        if (krb5_storage_write(ctx->negoex_transcript,
                               data.data, data.length) != data.length) {
            ret = ENOMEM;
            goto fail;
        }
        krb5_data_free(&data);

        CHECK(ret, krb5_ret_uint32(sp, &ctx->negoex_seqnum));

        if (krb5_storage_read(sp, ctx->negoex_conv_id,
                              GUID_LENGTH) != GUID_LENGTH) {
            ret = KRB5_BAD_MSIZE;
            goto fail;
        }

        CHECK(ret, krb5_ret_uint8(sp, &nschemes));
        for (i = 0; i < nschemes; i++) {
            struct negoex_auth_mech *mech;

            CHECK(ret, ret_negoex_auth_mech(sp, &mech));
            /* `mech' will not be NULL here, but quiet scan-build */
            if (mech)
                HEIM_TAILQ_INSERT_TAIL(&ctx->negoex_mechs, mech, links);
        }
    }

    *ctxp = ctx;

fail:
    if (ret == 0 && GSS_ERROR(major))
        ret = minor ? minor : KRB5_BAD_MSIZE;
    if (ret)
        _gss_spnego_delete_sec_context(&minor, (gss_ctx_id_t *)&ctx,
                                       GSS_C_NO_BUFFER);
    krb5_data_free(&data);
    gss_release_buffer(&minor, &buf);

    return ret;
}

static krb5_error_code
store_spnego_context(krb5_storage *sp, gssspnego_ctx ctx)
{
    OM_uint32 major = GSS_S_COMPLETE, minor;
    krb5_error_code ret = 0;
    krb5_data data;
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    uint16_t sc_flags = 0, spnego_flags;

    krb5_data_zero(&data);

    if (ctx->NegTokenInit_mech_types.length)
        sc_flags |= SC_MECH_TYPES;
    if (ctx->preferred_mech_type)
        sc_flags |= SC_PREFERRED_MECH_TYPE;
    if (ctx->selected_mech_type)
        sc_flags |= SC_SELECTED_MECH_TYPE;
    if (ctx->negotiated_mech_type)
        sc_flags |= SC_NEGOTIATED_MECH_TYPE;
    if (ctx->negotiated_ctx_id)
        sc_flags |= SC_NEGOTIATED_CTX_ID;
    if (ctx->mech_flags)
        sc_flags |= SC_MECH_FLAGS;
    if (ctx->mech_time_rec != GSS_C_INDEFINITE)
        sc_flags |= SC_MECH_TIME_REC;
    if (ctx->mech_src_name)
        sc_flags |= SC_MECH_SRC_NAME;
    if (ctx->target_name)
        sc_flags |= SC_TARGET_NAME;
    if (ctx->negoex_step)
        sc_flags |= SC_NEGOEX;

    CHECK(ret, krb5_store_uint16(sp, sc_flags));
    spnego_flags = spnego_flags_to_int(ctx->flags);
    CHECK(ret, krb5_store_uint16(sp, spnego_flags));

    if (sc_flags & SC_MECH_TYPES)
        CHECK(major, _gss_mg_store_buffer(&minor, sp, &ctx->NegTokenInit_mech_types));
    if (sc_flags & SC_PREFERRED_MECH_TYPE)
        CHECK(major, _gss_mg_store_oid(&minor, sp, ctx->preferred_mech_type));
    if (sc_flags & SC_SELECTED_MECH_TYPE)
        CHECK(major, _gss_mg_store_oid(&minor, sp, ctx->selected_mech_type));
    if (sc_flags & SC_NEGOTIATED_MECH_TYPE)
        CHECK(major, _gss_mg_store_oid(&minor, sp, ctx->negotiated_mech_type));
    if (sc_flags & SC_NEGOTIATED_CTX_ID) {
        CHECK(major, gss_export_sec_context(&minor, &ctx->negotiated_ctx_id,
                                            &buf));
        CHECK(major, _gss_mg_store_buffer(&minor, sp, &buf));
        gss_release_buffer(&minor, &buf);
    }
    if (sc_flags & SC_MECH_FLAGS)
        CHECK(ret, krb5_store_uint32(sp, ctx->mech_flags));
    if (sc_flags & SC_MECH_TIME_REC)
        CHECK(ret, krb5_store_uint32(sp, ctx->mech_time_rec));
    if (sc_flags & SC_MECH_SRC_NAME) {
        CHECK(major, gss_export_name(&minor, ctx->mech_src_name, &buf));
        CHECK(major, _gss_mg_store_buffer(&minor, sp, &buf));
        gss_release_buffer(&minor, &buf);
    }

    if (sc_flags & SC_TARGET_NAME) {
        CHECK(major, gss_export_name(&minor, ctx->target_name, &buf));
        CHECK(major, _gss_mg_store_buffer(&minor, sp, &buf));
        gss_release_buffer(&minor, &buf);
    }

    if (sc_flags & SC_NEGOEX) {
        uint32_t nschemes;
        struct negoex_auth_mech *mech;

        CHECK(ret, krb5_store_uint8(sp, ctx->negoex_step));

        if (ctx->negoex_transcript) {
            CHECK(ret, krb5_storage_to_data(ctx->negoex_transcript, &data));
        }
        CHECK(ret, krb5_store_data(sp, data));
        krb5_data_free(&data);

        CHECK(ret, krb5_store_uint32(sp, ctx->negoex_seqnum));
        CHECK(ret, krb5_store_bytes(sp, ctx->negoex_conv_id, GUID_LENGTH));

        nschemes = 0;
        HEIM_TAILQ_FOREACH(mech, &ctx->negoex_mechs, links)
            nschemes++;

        if (nschemes > 0xff) {
            ret = ERANGE;
            goto fail;
        }
        CHECK(ret, krb5_store_uint8(sp, nschemes));

        HEIM_TAILQ_FOREACH(mech, &ctx->negoex_mechs, links)
            CHECK(ret, store_negoex_auth_mech(sp, mech));
    }

fail:
    if (ret == 0 && GSS_ERROR(major))
        ret = minor ? minor : KRB5_BAD_MSIZE;
    krb5_data_free(&data);
    gss_release_buffer(&minor, &buf);

    return ret;
}

static krb5_error_code
ret_negoex_auth_mech(krb5_storage *sp, struct negoex_auth_mech **mechp)
{
    krb5_error_code ret;
    OM_uint32 major = GSS_S_COMPLETE, minor;
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    struct negoex_auth_mech *mech;
    krb5_context context = _gss_mg_krb5_context();
    uint8_t snc_flags, negoex_flags;

    *mechp = NULL;

    mech = calloc(1, sizeof(*mech));
    if (mech == NULL) {
        ret = ENOMEM;
        goto fail;
    }

    CHECK(ret, krb5_ret_uint8(sp, &snc_flags));
    CHECK(ret, krb5_ret_uint8(sp, &negoex_flags));
    if (negoex_flags & (1 << 0))
        mech->complete = 1;
    if (negoex_flags & (1 << 1))
        mech->sent_checksum = 1;
    if (negoex_flags & (1 << 2))
        mech->verified_checksum = 1;

    if (snc_flags & SNC_OID)
        CHECK(major, _gss_mg_ret_oid(&minor, sp, &mech->oid));

    if (krb5_storage_read(sp, mech->scheme, GUID_LENGTH) != GUID_LENGTH) {
        ret = KRB5_BAD_MSIZE;
        goto fail;
    }

    if (snc_flags & SNC_MECH_CONTEXT) {
        CHECK(major, _gss_mg_ret_buffer(&minor, sp, &buf));
        CHECK(major, gss_import_sec_context(&minor, &buf,
                                            &mech->mech_context));
        gss_release_buffer(&minor, &buf);
    }

    if (snc_flags & SNC_METADATA)
        CHECK(major, _gss_mg_ret_buffer(&minor, sp, &mech->metadata));

fail:
    if (ret == 0 && GSS_ERROR(major))
        ret = minor ? minor : KRB5_BAD_MSIZE;
    if (ret)
        _gss_negoex_release_auth_mech(context, mech);
    else
        *mechp = mech;

    gss_release_buffer(&minor, &buf);
    return ret;
}

static krb5_error_code
store_negoex_auth_mech(krb5_storage *sp, struct negoex_auth_mech *mech)
{
    krb5_error_code ret;
    OM_uint32 major = GSS_S_COMPLETE, minor;
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    uint8_t negoex_flags = 0, snc_flags = 0;

    negoex_flags = 0;
    if (mech->complete)
        negoex_flags |= (1 << 0);
    if (mech->sent_checksum)
        negoex_flags |= (1 << 1);
    if (mech->verified_checksum)
        negoex_flags |= (1 << 2);

    if (mech->oid)
        snc_flags |= SNC_OID;
    if (mech->mech_context)
        snc_flags |= SNC_MECH_CONTEXT;
    if (mech->metadata.length)
        snc_flags |= SNC_METADATA;

    CHECK(ret, krb5_store_uint8(sp, snc_flags));
    CHECK(ret, krb5_store_uint8(sp, negoex_flags));

    if (snc_flags & SNC_OID)
        CHECK(major, _gss_mg_store_oid(&minor, sp, mech->oid));

    CHECK(ret, krb5_store_bytes(sp, mech->scheme, GUID_LENGTH));

    if (snc_flags & SNC_MECH_CONTEXT) {
        CHECK(major, gss_export_sec_context(&minor, &mech->mech_context,
                                            &buf));
        CHECK(major, _gss_mg_store_buffer(&minor, sp, &buf));
        gss_release_buffer(&minor, &buf);
    }

    if (snc_flags & SNC_METADATA)
        CHECK(major, _gss_mg_store_buffer(&minor, sp, &mech->metadata));

fail:
    if (ret == 0 && GSS_ERROR(major))
        ret = minor ? minor : KRB5_BAD_MSIZE;
    gss_release_buffer(&minor, &buf);

    return ret;
}

static uint16_t
spnego_flags_to_int(struct spnego_flags flags)
{
    uint16_t f = 0;

    if (flags.open)
        f |= (1 << 0);
    if (flags.local)
        f |= (1 << 1);
    if (flags.require_mic)
        f |= (1 << 2);
    if (flags.peer_require_mic)
        f |= (1 << 3);
    if (flags.sent_mic)
        f |= (1 << 4);
    if (flags.verified_mic)
        f |= (1 << 5);
    if (flags.safe_omit)
        f |= (1 << 6);
    if (flags.maybe_open)
        f |= (1 << 7);
    if (flags.seen_supported_mech)
        f |= (1 << 8);

    return f;
}

static struct spnego_flags
int_to_spnego_flags(uint16_t f)
{
    struct spnego_flags flags;

    memset(&flags, 0, sizeof(flags));

    if (f & (1 << 0))
        flags.open = 1;
    if (f & (1 << 1))
        flags.local = 1;
    if (f & (1 << 2))
        flags.require_mic = 1;
    if (f & (1 << 3))
        flags.peer_require_mic = 1;
    if (f & (1 << 4))
        flags.sent_mic = 1;
    if (f & (1 << 5))
        flags.verified_mic = 1;
    if (f & (1 << 6))
        flags.safe_omit = 1;
    if (f & (1 << 7))
        flags.maybe_open = 1;
    if (f & (1 << 8))
        flags.seen_supported_mech = 1;

    return flags;
}
