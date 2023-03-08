/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	$FreeBSD: src/lib/libgssapi/gss_accept_sec_context.c,v 1.1 2005/12/29 14:40:20 dfr Exp $
 */

#include "mech_locl.h"

/*
 * accumulate_token() tries to assemble a complete GSS token which may
 * be fed to it in pieces.  Microsoft does this when tokens are too large
 * in CIFS, e.g.  It may occur in other places as well.  It is specified in:
 *
 *      [MS-SPNG]: Simple and Protected GSS-API Negotiation
 *                 Mechanism (SPNEGO) Extension
 *
 *      https://winprotocoldoc.blob.core.windows.net/
 *      productionwindowsarchives/MS-SPNG/%5bMS-SPNG%5d.pdf
 *
 * Sections 3.1.5.4 to 3.1.5.9.
 *
 * We only accumulate if we see the appropriate application tag in the
 * first byte of 0x60 because in the absence of this, we cannot interpret
 * the following bytes as a DER length.
 *
 * We only allocate an accumulating buffer if we detect that the token
 * is split between multiple packets as this is the uncommon case and
 * we want to optimise for the common case.  If we aren't accumulating,
 * we simply return success.
 *
 * Our return value is GSS_S_CONTINUE_NEEDED if we need more input.
 * We return GSS_S_COMPLETE if we are either finished accumulating or
 * if we decide that we do not understand this token.  We only return
 * an error if we think that we should understand the token and still
 * fail to understand it.
 */

static OM_uint32
accumulate_token(struct _gss_context *ctx, gss_buffer_t input_token)
{
	unsigned char *p = input_token->value;
	size_t len = input_token->length;
        gss_buffer_t gci;
        size_t l;

	/*
	 * Token must start with [APPLICATION 0] SEQUENCE.
	 * But if it doesn't assume it is DCE-STYLE Kerberos!
	 */
        if (!ctx->gc_target_len) {
                free(ctx->gc_free_this);
                ctx->gc_free_this = NULL;
                _mg_buffer_zero(&ctx->gc_input);

                /*
                 * Let's prepare gc_input for the case where
                 * we aren't accumulating.
                 */

                ctx->gc_input.length = len;
                ctx->gc_input.value  = p;

                if (len == 0)
                        return GSS_S_COMPLETE;

                /* Not our DER w/ a length */
                if (*p != 0x60)
                        return GSS_S_COMPLETE;

                if (der_get_length(p+1, len-1, &ctx->gc_target_len, &l) != 0)
                        return GSS_S_DEFECTIVE_TOKEN;

                _gss_mg_log(10, "gss-asc: DER length: %zu",
                    ctx->gc_target_len);

                ctx->gc_oid_offset  = l + 1;
                ctx->gc_target_len += ctx->gc_oid_offset;

                _gss_mg_log(10, "gss-asc: total length: %zu",
                    ctx->gc_target_len);

                if (ctx->gc_target_len == ASN1_INDEFINITE ||
                    ctx->gc_target_len < len)
                        return GSS_S_DEFECTIVE_TOKEN;

                /* We've got it all, short-circuit the accumulating */
                if (ctx->gc_target_len == len)
                        goto done;

                _gss_mg_log(10, "gss-asc: accumulating partial token");

                ctx->gc_input.length = 0;
                ctx->gc_input.value  = calloc(ctx->gc_target_len, 1);
                if (!ctx->gc_input.value)
                        return GSS_S_FAILURE;
                ctx->gc_free_this = ctx->gc_input.value;
        }

	if (len == 0)
                return GSS_S_DEFECTIVE_TOKEN;

        gci = &ctx->gc_input;

        if (ctx->gc_target_len > gci->length) {
                if (gci->length + len > ctx->gc_target_len) {
                        _gss_mg_log(10, "gss-asc: accumulation exceeded "
                            "target length: bailing");
                        return GSS_S_DEFECTIVE_TOKEN;
                }
                memcpy((char *)gci->value + gci->length, p, len);
                gci->length += len;
        }

        if (gci->length != ctx->gc_target_len) {
                _gss_mg_log(10, "gss-asc: collected %zu/%zu bytes",
                    gci->length, ctx->gc_target_len);
                return GSS_S_CONTINUE_NEEDED;
        }

done:
        _gss_mg_log(10, "gss-asc: received complete %zu byte token",
            ctx->gc_target_len);
        ctx->gc_target_len = 0;

	return GSS_S_COMPLETE;
}

static void
log_oid(const char *str, gss_OID mech)
{
        OM_uint32        maj, min;
        gss_buffer_desc  buf;

        maj = gss_oid_to_str(&min, mech, &buf);
        if (maj == GSS_S_COMPLETE) {
                _gss_mg_log(10, "%s: %.*s", str, (int)buf.length,
                    (char *)buf.value);
                gss_release_buffer(&min, &buf);
        }
}

static OM_uint32
choose_mech(struct _gss_context *ctx)
{
        gss_OID_desc     mech;
        gss_OID          mech_oid;
        unsigned char   *p = ctx->gc_input.value;
        size_t           len = ctx->gc_input.length;

        if (len == 0) {
		/*
		 * There is the a wierd mode of SPNEGO (in CIFS and
		 * SASL GSS-SPENGO) where the first token is zero
		 * length and the acceptor returns a mech_list, lets
		 * hope that is what is happening now.
		 *
		 * http://msdn.microsoft.com/en-us/library/cc213114.aspx
		 * "NegTokenInit2 Variation for Server-Initiation"
		 */
                mech_oid = &__gss_spnego_mechanism_oid_desc;
                goto gss_get_mechanism;
	}

        p   += ctx->gc_oid_offset;
        len -= ctx->gc_oid_offset;

        /*
         * Decode the OID for the mechanism. Simplify life by
         * assuming that the OID length is less than 128 bytes.
         */
        if (len < 2 || *p != 0x06) {
            _gss_mg_log(10, "initial context token appears to be for non-standard mechanism");
            return GSS_S_COMPLETE;
        }
        len -= 2;
        if ((p[1] & 0x80) || p[1] > len) {
                _gss_mg_log(10, "mechanism oid in initial context token is too long");
                return GSS_S_COMPLETE;
        }
        mech.length = p[1];
        p += 2;
        mech.elements = p;

        mech_oid = _gss_mg_support_mechanism(&mech);
        if (mech_oid == GSS_C_NO_OID)
                return GSS_S_COMPLETE;

gss_get_mechanism:
        /*
         * If mech_oid == GSS_C_NO_OID then the mech is non-standard
         * and we have to try all mechs (that we have a cred element
         * for, if we have a cred).
         */
        log_oid("mech oid", mech_oid);
        ctx->gc_mech = __gss_get_mechanism(mech_oid);
        if (!ctx->gc_mech) {
            _gss_mg_log(10, "mechanism client used is unknown");
            return (GSS_S_BAD_MECH);
        }
        _gss_mg_log(10, "using mech \"%s\"", ctx->gc_mech->gm_name);
        return GSS_S_COMPLETE;
}

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_accept_sec_context(OM_uint32 *minor_status,
    gss_ctx_id_t *context_handle,
    gss_const_cred_id_t acceptor_cred_handle,
    const gss_buffer_t input_token,
    const gss_channel_bindings_t input_chan_bindings,
    gss_name_t *src_name,
    gss_OID *mech_type,
    gss_buffer_t output_token,
    OM_uint32 *ret_flags,
    OM_uint32 *time_rec,
    gss_cred_id_t *delegated_cred_handle)
{
	OM_uint32 major_status, mech_ret_flags, junk;
	gssapi_mech_interface m = NULL;
	struct _gss_context *ctx = (struct _gss_context *) *context_handle;
	struct _gss_cred *cred = (struct _gss_cred *) acceptor_cred_handle;
	struct _gss_mechanism_cred *mc;
        gss_buffer_desc defective_token_error;
	gss_const_cred_id_t acceptor_mc;
	gss_cred_id_t delegated_mc = GSS_C_NO_CREDENTIAL;
	gss_name_t src_mn = GSS_C_NO_NAME;
	gss_OID mech_ret_type = GSS_C_NO_OID;
        int initial;

        defective_token_error.length = 0;
        defective_token_error.value = NULL;

	*minor_status = 0;
	if (src_name)
	    *src_name = GSS_C_NO_NAME;
	if (mech_type)
	    *mech_type = GSS_C_NO_OID;
	if (ret_flags)
	    *ret_flags = 0;
	if (time_rec)
	    *time_rec = 0;
	if (delegated_cred_handle)
	    *delegated_cred_handle = GSS_C_NO_CREDENTIAL;
	_mg_buffer_zero(output_token);

        if (!*context_handle) {
                ctx = calloc(sizeof(*ctx), 1);
		if (!ctx) {
			*minor_status = ENOMEM;
			return (GSS_S_DEFECTIVE_TOKEN);
		}
                *context_handle = (gss_ctx_id_t)ctx;
                ctx->gc_initial = 1;
        }

        major_status = accumulate_token(ctx, input_token);
        if (major_status != GSS_S_COMPLETE)
                return major_status;

        /*
         * If we get here, then we have a complete token.  Please note
         * that we may have a major_status of GSS_S_DEFECTIVE_TOKEN.  This
         * 
         */

        initial = ctx->gc_initial;
        ctx->gc_initial = 0;

        if (major_status == GSS_S_COMPLETE && initial) {
                major_status = choose_mech(ctx);
                if (major_status != GSS_S_COMPLETE)
                        return major_status;
        }
        m = ctx->gc_mech;

        if (initial && !m && acceptor_cred_handle == GSS_C_NO_CREDENTIAL) {
                /*
                 * No header, not a standard mechanism.  Try all the mechanisms
                 * (because default credential).
                 */
                struct _gss_mech_switch *ms;

                _gss_load_mech();
                acceptor_mc = GSS_C_NO_CREDENTIAL;
                HEIM_TAILQ_FOREACH(ms, &_gss_mechs, gm_link) {
                        m = &ms->gm_mech;
                        mech_ret_flags = 0;
                        major_status = m->gm_accept_sec_context(minor_status,
                            &ctx->gc_ctx,
                            acceptor_mc,
                            &ctx->gc_input,
                            input_chan_bindings,
                            &src_mn,
                            &mech_ret_type,
                            output_token,
                            &mech_ret_flags,
                            time_rec,
                            &delegated_mc);
                        if (major_status == GSS_S_DEFECTIVE_TOKEN) {
                                /*
                                 * Try to retain and output one error token for
                                 * GSS_S_DEFECTIVE_TOKEN.  The first one.
                                 */
                                if (output_token->length &&
                                    defective_token_error.length == 0) {
                                    defective_token_error = *output_token;
                                    output_token->length = 0;
                                    output_token->value = NULL;
                                }
                                gss_release_buffer(&junk, output_token);
                                continue;
                        }
                        gss_release_buffer(&junk, &defective_token_error);
                        ctx->gc_mech = m;
                        goto got_one;
                }
                m = NULL;
                acceptor_mc = GSS_C_NO_CREDENTIAL;
        } else if (initial && !m) {
                /*
                 * No header, not a standard mechanism.  Try all the mechanisms
                 * that we have a credential element for if we have a
                 * non-default credential.
                 */
		HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link) {
                        m = mc->gmc_mech;
                        acceptor_mc = (m->gm_flags & GM_USE_MG_CRED) ?
                            acceptor_cred_handle : mc->gmc_cred;
                        mech_ret_flags = 0;
                        major_status = m->gm_accept_sec_context(minor_status,
                            &ctx->gc_ctx,
                            acceptor_mc,
                            &ctx->gc_input,
                            input_chan_bindings,
                            &src_mn,
                            &mech_ret_type,
                            output_token,
                            &mech_ret_flags,
                            time_rec,
                            &delegated_mc);
                        if (major_status == GSS_S_DEFECTIVE_TOKEN) {
                                if (output_token->length &&
                                    defective_token_error.length == 0) {
                                    defective_token_error = *output_token;
                                    output_token->length = 0;
                                    output_token->value = NULL;
                                }
                                gss_release_buffer(&junk, output_token);
                                continue;
                        }
                        gss_release_buffer(&junk, &defective_token_error);
                        ctx->gc_mech = m;
                        goto got_one;
                }
                m = NULL;
                acceptor_mc = GSS_C_NO_CREDENTIAL;
        }

        if (m == NULL) {
                gss_delete_sec_context(&junk, context_handle, NULL);
                _gss_mg_log(10, "No mechanism accepted the non-standard initial security context token");
                *output_token = defective_token_error;
                return GSS_S_BAD_MECH;
        }

	if (m->gm_flags & GM_USE_MG_CRED) {
		acceptor_mc = acceptor_cred_handle;
	} else if (cred) {
		HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link)
			if (mc->gmc_mech == m)
				break;
		if (!mc) {
		        gss_delete_sec_context(&junk, context_handle, NULL);
			_gss_mg_log(10, "gss-asc: client sent mech %s "
				    "but no credential was matching",
				    m->gm_name);
			HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link)
				_gss_mg_log(10, "gss-asc: available creds were %s", mc->gmc_mech->gm_name);
			return (GSS_S_BAD_MECH);
		}
		acceptor_mc = mc->gmc_cred;
	} else {
		acceptor_mc = GSS_C_NO_CREDENTIAL;
	}

	mech_ret_flags = 0;
	major_status = m->gm_accept_sec_context(minor_status,
	    &ctx->gc_ctx,
	    acceptor_mc,
	    &ctx->gc_input,
	    input_chan_bindings,
	    &src_mn,
	    &mech_ret_type,
	    output_token,
	    &mech_ret_flags,
	    time_rec,
	    &delegated_mc);

got_one:
	if (major_status != GSS_S_COMPLETE &&
	    major_status != GSS_S_CONTINUE_NEEDED)
	{
		_gss_mg_error(m, *minor_status);
		gss_delete_sec_context(&junk, context_handle, NULL);
		return (major_status);
	}

	if (mech_type)
		*mech_type = mech_ret_type;

	if (src_name && src_mn) {
		if (ctx->gc_mech->gm_flags & GM_USE_MG_NAME) {
			/* Negotiation mechanisms use mechglue names as names */
			*src_name = src_mn;
			src_mn = GSS_C_NO_NAME;
		} else {
			/*
			 * Make a new name and mark it as an MN.
			 *
			 * Note that _gss_create_name() consumes `src_mn' but doesn't
			 * take a pointer, so it can't set it to GSS_C_NO_NAME.
			 */
			struct _gss_name *name = _gss_create_name(src_mn, m);

			if (!name) {
				m->gm_release_name(minor_status, &src_mn);
				gss_delete_sec_context(&junk, context_handle, NULL);
				return (GSS_S_FAILURE);
			}
			*src_name = (gss_name_t) name;
			src_mn = GSS_C_NO_NAME;
		}
	} else if (src_mn) {
		if (ctx->gc_mech->gm_flags & GM_USE_MG_NAME) {
			_gss_mg_release_name((struct _gss_name *)src_mn);
			src_mn = GSS_C_NO_NAME;
		} else {
			m->gm_release_name(minor_status, &src_mn);
		}
	}

	if (mech_ret_flags & GSS_C_DELEG_FLAG) {
		if (!delegated_cred_handle) {
			if (m->gm_flags	 & GM_USE_MG_CRED)
				gss_release_cred(minor_status, &delegated_mc);
			else
				m->gm_release_cred(minor_status, &delegated_mc);
			mech_ret_flags &=
			    ~(GSS_C_DELEG_FLAG|GSS_C_DELEG_POLICY_FLAG);
		} else if ((m->gm_flags & GM_USE_MG_CRED) != 0) {
			/* 
			 * If credential is uses mechglue cred, assume it
			 * returns one too.
			 */
			*delegated_cred_handle = delegated_mc;
		} else if (gss_oid_equal(mech_ret_type, &m->gm_mech_oid) == 0) {
			/*
			 * If the returned mech_type is not the same
			 * as the mech, assume its pseudo mech type
			 * and the returned type is already a
			 * mech-glue object
			 */
			*delegated_cred_handle = delegated_mc;

		} else if (delegated_mc) {
			struct _gss_cred *dcred;
			struct _gss_mechanism_cred *dmc;

			dcred = _gss_mg_alloc_cred();
			if (!dcred) {
				*minor_status = ENOMEM;
				gss_delete_sec_context(&junk, context_handle, NULL);
				return (GSS_S_FAILURE);
			}
			dmc = malloc(sizeof(struct _gss_mechanism_cred));
			if (!dmc) {
				free(dcred);
				*minor_status = ENOMEM;
				gss_delete_sec_context(&junk, context_handle, NULL);
				return (GSS_S_FAILURE);
			}
			dmc->gmc_mech = m;
			dmc->gmc_mech_oid = &m->gm_mech_oid;
			dmc->gmc_cred = delegated_mc;
			HEIM_TAILQ_INSERT_TAIL(&dcred->gc_mc, dmc, gmc_link);

			*delegated_cred_handle = (gss_cred_id_t) dcred;
		}
	}

	_gss_mg_log(10, "gss-asc: return %d/%d", (int)major_status, (int)*minor_status);

	if (ret_flags)
	    *ret_flags = mech_ret_flags;
	return (major_status);
}
