/*
 * AEAD support
 */ 

#include "mech_locl.h"
RCSID("$Id$");

OM_uint32 GSSAPI_LIB_FUNCTION
gss_wrap_iov(OM_uint32 * minor_status,
	     gss_ctx_id_t  context_handle,
	     int conf_req_flag,
	     gss_qop_t qop_req,
	     int * conf_state,
	     int iov_count,
	     gss_iov_buffer_desc *iov)
{
	struct _gss_context *ctx = (struct _gss_context *) context_handle;
	gssapi_mech_interface m;

	if (conf_state)
	    *conf_state = 0;
	if (ctx == NULL) {
	    *minor_status = 0;
	    return GSS_S_NO_CONTEXT;
	}

	m = ctx->gc_mech;

	if (m->gm_wrap_iov == NULL) {
	    *minor_status = 0;
	    return GSS_S_UNAVAILABLE;
	}

	return (m->gm_wrap_iov)(minor_status, ctx->gc_ctx,
				conf_req_flag, qop_req, conf_state, iov_count, iov);
}

OM_uint32 GSSAPI_LIB_FUNCTION
gss_unwrap_iov(OM_uint32 *minor_status,
	       gss_ctx_id_t context_handle,
	       int *conf_state,
	       gss_qop_t *qop_state,
	       int iov_count,
	       gss_iov_buffer_desc *iov)
{
	struct _gss_context *ctx = (struct _gss_context *) context_handle;
	gssapi_mech_interface m;	  

	if (conf_state)
	    *conf_state = 0;
	if (qop_state)
	    *qop_state = 0;
	if (ctx == NULL) {
	    *minor_status = 0;
	    return GSS_S_NO_CONTEXT;
	}

	m = ctx->gc_mech;

	if (m->gm_unwrap_iov == NULL) {
	    *minor_status = 0;
	    return GSS_S_UNAVAILABLE;
	}

	return (m->gm_unwrap_iov)(minor_status, ctx->gc_ctx,
				conf_state, qop_state, iov_count, iov);
}

OM_uint32  GSSAPI_LIB_FUNCTION
gss_wrap_iov_length(OM_uint32 * minor_status,
		    gss_ctx_id_t context_handle,
		    int conf_req_flag,
		    gss_qop_t qop_req,
		    int iov_count,
		    gss_iov_buffer_desc *iov)
{
	struct _gss_context *ctx = (struct _gss_context *) context_handle;
	gssapi_mech_interface m;

	if (ctx == NULL) {
	    *minor_status = 0;
	    return GSS_S_NO_CONTEXT;
	}

	m = ctx->gc_mech;

	if (m->gm_wrap_iov == NULL) {
	    *minor_status = 0;
	    return GSS_S_UNAVAILABLE;
	}

	return (m->gm_wrap_iov_length)(minor_status, ctx->gc_ctx,
				       conf_req_flag, qop_req, iov_count, iov);
}

OM_uint32 GSSAPI_LIB_FUNCTION
gss_release_iov_buffer(OM_uint32 *minor_status,
		       int iov_count,
		       gss_iov_buffer_desc *iov)
{
    OM_uint32 junk;
    size_t i;

    for (i = 0; i < iov_count; i++) {
	if ((iov[i].flags & GSS_IOV_BUFFER_FLAG_ALLOCATED) == 0)
	    continue;
	gss_release_buffer(&junk, &iov[i].buffer);
    }
    *minor_status = 0;
    return GSS_S_COMPLETE;
}

