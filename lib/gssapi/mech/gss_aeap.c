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
	     gss_iov_buffer_desc *iov,
	     int iov_count)
{
	struct _gss_context *ctx = (struct _gss_context *) context_handle;
	gssapi_mech_interface m;

	if (minor_status)
	    *minor_status = 0;
	if (conf_state)
	    *conf_state = 0;
	if (ctx == NULL)
	    return GSS_S_NO_CONTEXT;
	if (iov == NULL && iov_count != 0)
	    return GSS_S_CALL_INACCESSIBLE_READ;

	m = ctx->gc_mech;

	if (m->gm_wrap_iov == NULL) {
	    *minor_status = 0;
	    return GSS_S_UNAVAILABLE;
	}

	return (m->gm_wrap_iov)(minor_status, ctx->gc_ctx,
				conf_req_flag, qop_req, conf_state,
				iov, iov_count);
}

OM_uint32 GSSAPI_LIB_FUNCTION
gss_unwrap_iov(OM_uint32 *minor_status,
	       gss_ctx_id_t context_handle,
	       int *conf_state,
	       gss_qop_t *qop_state,
	       gss_iov_buffer_desc *iov,
	       int iov_count)
{
	struct _gss_context *ctx = (struct _gss_context *) context_handle;
	gssapi_mech_interface m;	  

	if (minor_status)
	    *minor_status = 0;
	if (conf_state)
	    *conf_state = 0;
	if (qop_state)
	    *qop_state = 0;
	if (ctx == NULL)
	    return GSS_S_NO_CONTEXT;
	if (iov == NULL && iov_count != 0)
	    return GSS_S_CALL_INACCESSIBLE_READ;

	m = ctx->gc_mech;

	if (m->gm_unwrap_iov == NULL) {
	    *minor_status = 0;
	    return GSS_S_UNAVAILABLE;
	}

	return (m->gm_unwrap_iov)(minor_status, ctx->gc_ctx,
				  conf_state, qop_state,
				  iov, iov_count);
}

OM_uint32  GSSAPI_LIB_FUNCTION
gss_wrap_iov_length(OM_uint32 * minor_status,
		    gss_ctx_id_t context_handle,
		    int conf_req_flag,
		    gss_qop_t qop_req,
		    gss_iov_buffer_desc *iov,
		    int iov_count)
{
	struct _gss_context *ctx = (struct _gss_context *) context_handle;
	gssapi_mech_interface m;

	if (minor_status)
	    *minor_status = 0;
	if (ctx == NULL)
	    return GSS_S_NO_CONTEXT;
	if (iov == NULL && iov_count != 0)
	    return GSS_S_CALL_INACCESSIBLE_READ;

	m = ctx->gc_mech;

	if (m->gm_wrap_iov == NULL) {
	    *minor_status = 0;
	    return GSS_S_UNAVAILABLE;
	}

	return (m->gm_wrap_iov_length)(minor_status, ctx->gc_ctx,
				       conf_req_flag, qop_req,
				       iov, iov_count);
}

OM_uint32 GSSAPI_LIB_FUNCTION
gss_release_iov_buffer(OM_uint32 *minor_status,
		       gss_iov_buffer_desc *iov,
		       int iov_count)
{
    OM_uint32 junk;
    size_t i;

    if (minor_status)
	*minor_status = 0;
    if (iov == NULL && iov_count != 0)
	return GSS_S_CALL_INACCESSIBLE_READ;

    for (i = 0; i < iov_count; i++) {
	if (iov[i].type & GSS_IOV_BUFFER_TYPE_FLAG_ALLOCATED)
	    continue;
	gss_release_buffer(&junk, &iov[i].buffer);
    }
    return GSS_S_COMPLETE;
}

