/*
 * Copyright (c) 2004, PADL Software Pty Ltd.
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

#include "spnego/spnego_locl.h"

RCSID("$Id: compat.c,v 1.6 2006/10/07 22:26:59 lha Exp $");

/*
 * Apparently Microsoft got the OID wrong, and used
 * 1.2.840.48018.1.2.2 instead. We need both this and
 * the correct Kerberos OID here in order to deal with
 * this. Because this is manifest in SPNEGO only I'd
 * prefer to deal with this here rather than inside the
 * Kerberos mechanism.
 */
static gss_OID_desc gss_mskrb_mechanism_oid_desc =
	{9, (void *)"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"};

static gss_OID_desc gss_krb5_mechanism_oid_desc =
	{9, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};

/*
 * Allocate a SPNEGO context handle
 */
OM_uint32 _gss_spnego_alloc_sec_context (OM_uint32 * minor_status,
					 gss_ctx_id_t *context_handle)
{
    gssspnego_ctx ctx;

    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
	*minor_status = ENOMEM;
	return GSS_S_FAILURE;
    }

    ctx->initiator_mech_types.len = 0;
    ctx->initiator_mech_types.val = NULL;
    ctx->preferred_mech_type = GSS_C_NO_OID;
    ctx->negotiated_mech_type = GSS_C_NO_OID;
    ctx->negotiated_ctx_id = GSS_C_NO_CONTEXT;

    /*
     * Cache these so we can return them before returning
     * GSS_S_COMPLETE, even if the mechanism has itself
     * completed earlier
     */
    ctx->mech_flags = 0;
    ctx->mech_time_rec = 0;
    ctx->mech_src_name = GSS_C_NO_NAME;
    ctx->delegated_cred_id = GSS_C_NO_CREDENTIAL;

    ctx->open = 0;
    ctx->local = 0;
    ctx->require_mic = 0;
    ctx->verified_mic = 0;

    HEIMDAL_MUTEX_init(&ctx->ctx_id_mutex);

    *context_handle = (gss_ctx_id_t)ctx;

    return GSS_S_COMPLETE;
}

/*
 * Free a SPNEGO context handle. The caller must have acquired
 * the lock before this is called.
 */
OM_uint32 _gss_spnego_internal_delete_sec_context
           (OM_uint32 *minor_status,
            gss_ctx_id_t *context_handle,
            gss_buffer_t output_token
           )
{
    gssspnego_ctx ctx;
    OM_uint32 ret, minor;

    *minor_status = 0;

    if (context_handle == NULL) {
	return GSS_S_NO_CONTEXT;
    }

    if (output_token != GSS_C_NO_BUFFER) {
	output_token->length = 0;
	output_token->value = NULL;
    }

    ctx = (gssspnego_ctx)*context_handle;
    *context_handle = GSS_C_NO_CONTEXT;

    if (ctx == NULL) {
	return GSS_S_NO_CONTEXT;
    }

    if (ctx->initiator_mech_types.val != NULL)
	free_MechTypeList(&ctx->initiator_mech_types);

    _gss_spnego_release_cred(&minor, &ctx->delegated_cred_id);

    gss_release_oid(&minor, &ctx->preferred_mech_type);
    ctx->negotiated_mech_type = GSS_C_NO_OID;

    gss_release_name(&minor, &ctx->mech_src_name);

    if (ctx->negotiated_ctx_id != GSS_C_NO_CONTEXT) {
	ret = gss_delete_sec_context(minor_status,
				     &ctx->negotiated_ctx_id,
				     output_token);
	ctx->negotiated_ctx_id = GSS_C_NO_CONTEXT;
    } else {
	ret = GSS_S_COMPLETE;
    }

    HEIMDAL_MUTEX_unlock(&ctx->ctx_id_mutex);
    HEIMDAL_MUTEX_destroy(&ctx->ctx_id_mutex);

    free(ctx);
    *context_handle = NULL;

    return ret;
}

/*
 * For compatability with the Windows SPNEGO implementation, the
 * default is to ignore the mechListMIC unless CFX is used and
 * a non-preferred mechanism was negotiated
 */

OM_uint32
_gss_spnego_require_mechlist_mic(OM_uint32 *minor_status,
				 gssspnego_ctx ctx,
				 int *require_mic)
{
    gss_buffer_set_t buffer_set = GSS_C_NO_BUFFER_SET;
    OM_uint32 minor;

    *minor_status = 0;
    *require_mic = 0;

    if (ctx == NULL) {
	return GSS_S_COMPLETE;
    }

    if (ctx->require_mic) {
	/* Acceptor requested it: mandatory to honour */
	*require_mic = 1;
	return GSS_S_COMPLETE;
    }

    /*
     * Check whether peer indicated implicit support for updated SPNEGO
     * (eg. in the Kerberos case by using CFX)
     */
    if (gss_inquire_sec_context_by_oid(&minor, ctx->negotiated_ctx_id,
				       GSS_C_PEER_HAS_UPDATED_SPNEGO,
				       &buffer_set) == GSS_S_COMPLETE) {
	*require_mic = 1;
	gss_release_buffer_set(&minor, &buffer_set);
    }

    /* Safe-to-omit MIC rules follow */
    if (*require_mic) {
	if (gss_oid_equal(ctx->negotiated_mech_type, ctx->preferred_mech_type)) {
	    *require_mic = 0;
	} else if (gss_oid_equal(ctx->negotiated_mech_type, &gss_krb5_mechanism_oid_desc) &&
		   gss_oid_equal(ctx->preferred_mech_type, &gss_mskrb_mechanism_oid_desc)) {
	    *require_mic = 0;
	}
    }

    return GSS_S_COMPLETE;
}

int _gss_spnego_add_mech_type(gss_OID mech_type,
			      int includeMSCompatOID,
			      MechTypeList *mechtypelist)
{
    int ret;

    if (gss_oid_equal(mech_type, GSS_SPNEGO_MECHANISM))
	return 0;

    if (includeMSCompatOID &&
	gss_oid_equal(mech_type, &gss_krb5_mechanism_oid_desc)) {
	ret = der_get_oid(gss_mskrb_mechanism_oid_desc.elements,
			  gss_mskrb_mechanism_oid_desc.length,
			  &mechtypelist->val[mechtypelist->len],
			  NULL);
	if (ret)
	    return ret;
	mechtypelist->len++;
    }
    ret = der_get_oid(mech_type->elements,
		      mech_type->length,
		      &mechtypelist->val[mechtypelist->len],
		      NULL);
    if (ret)
	return ret;
    mechtypelist->len++;

    return 0;
}

OM_uint32
_gss_spnego_select_mech(OM_uint32 *minor_status,
			MechType *mechType,
			gss_OID *mech_p)
{
    char mechbuf[64];
    size_t mech_len;
    gss_OID_desc oid;
    OM_uint32 ret;

    ret = der_put_oid ((unsigned char *)mechbuf + sizeof(mechbuf) - 1,
		       sizeof(mechbuf),
		       mechType,
		       &mech_len);
    if (ret) {
	return GSS_S_DEFECTIVE_TOKEN;
    }

    oid.length   = mech_len;
    oid.elements = mechbuf + sizeof(mechbuf) - mech_len;

    if (gss_oid_equal(&oid, GSS_SPNEGO_MECHANISM)) {
	return GSS_S_BAD_MECH;
    }

    *minor_status = 0;

    /* Translate broken MS Kebreros OID */
    if (gss_oid_equal(&oid, &gss_mskrb_mechanism_oid_desc)) {
	gssapi_mech_interface mech;

	mech = __gss_get_mechanism(&gss_krb5_mechanism_oid_desc);
	if (mech == NULL)
	    return GSS_S_BAD_MECH;

	ret = gss_duplicate_oid(minor_status,
				&gss_mskrb_mechanism_oid_desc,
				mech_p);
    } else {
	gssapi_mech_interface mech;

	mech = __gss_get_mechanism(&oid);
	if (mech == NULL)
	    return GSS_S_BAD_MECH;

	ret = gss_duplicate_oid(minor_status,
				&mech->gm_mech_oid,
				mech_p);
    }

    return ret;
}

