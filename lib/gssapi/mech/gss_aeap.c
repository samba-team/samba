/*
 * AEAD support
 */ 

#include "mech_locl.h"
RCSID("$Id$");

/**
 * Encrypts or sign the data.
 *
 * There can only be one GSS_IOV_BUFFER_TYPE_DATA buffer.
 * There can be as 0 or more GSS_IOV_BUFFER_TYPE_SIGN_ONLY buffers.
 *
 * The caller needs provide either:
 *
 * - one GSS_IOV_BUFFER_TYPE_HEADER, one GSS_IOV_BUFFER_TYPE_PADDING, andd one GSS_IOV_BUFFER_TYPE_TRAILER
 * - on DCE-RPC mode, only one GSS_IOV_BUFFER_TYPE_HEADER may be given
 *
 * To generate gss_wrap() comptaible headers, use: HEADER | DATA | PADDING | TRAILER
 *
 * The input sizes of HEADER, PADDING and TRAILER can be fetched using gss_wrap_iov_length() or
 * gss_context_query_attributes().
 *
 * @ingroup gssapi
 */


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

typedef struct gss_context_stream_sizes_desc {
    size_t header; /**< size of header */
    size_t trailer; /**< size of trailer */
    size_t max_msg_size; /**< maximum message size */
    size_t buffers; /**< extra GSS_IOV_BUFFER_TYPE_EMPTY buffer to pass */
    size_t blocksize; /**< Specificed optimal size of messages, also
			 is the maximum padding size
			 (GSS_IOV_BUFFER_TYPE_PADDING) */
} gss_context_stream_sizes; 

/**
 * Query the context for parameters.
 *
 * - GSS_OID_ATTR_STREAM_SIZES data is a gss_context_stream_sizes.
 */


OM_uint32 GSSAPI_LIB_FUNCTION
gss_context_query_attributes(OM_uint32 *minor_status,
			     gss_OID attribute,
			     void *data,
			     size_t len)
{
    *minor_status = 0;
    
    return GSS_S_COMPLETE;
}
			     
