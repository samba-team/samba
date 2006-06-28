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

#include "gsskrb5_locl.h"

RCSID("$Id$");

OM_uint32 _gsskrb5_inquire_cred_by_oid
	   (OM_uint32 * minor_status,
	    const gss_cred_id_t cred_handle,
	    const gss_OID desired_object,
	    gss_buffer_set_t *data_set)
{
    gsskrb5_cred cred = (gsskrb5_cred)cred_handle;
    krb5_error_code kret;
    krb5_ccache_data ccache;
    gss_buffer_desc ccache_ops_buf;
    gss_buffer_desc ccache_data_buf;
    OM_uint32 ret;

    if (gss_oid_equal(desired_object, GSS_KRB5_COPY_CCACHE_X) == 0) {
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    HEIMDAL_MUTEX_lock(&cred->cred_id_mutex);

    if (cred->ccache == NULL) {
	HEIMDAL_MUTEX_unlock(&cred->cred_id_mutex);
	*minor_status = EINVAL;
	return GSS_S_FAILURE;
    }

    kret = krb5_cc_copy_cache(_gsskrb5_context, cred->ccache, &ccache);
    HEIMDAL_MUTEX_unlock(&cred->cred_id_mutex);
    if (kret) {
	*minor_status = kret;
	_gsskrb5_set_error_string ();
	return GSS_S_FAILURE;
    }

    ccache_ops_buf.value = (void *)ccache.ops->prefix;
    ccache_ops_buf.length = strlen(ccache.ops->prefix);

    ccache_data_buf.value = ccache.data.data;
    ccache_data_buf.length = ccache.data.length;

    ret = gss_add_buffer_set_member(minor_status,
				    &ccache_ops_buf,
				    data_set);
    if (ret == 0) {
	ret = gss_add_buffer_set_member(minor_status,
					&ccache_data_buf,
					data_set);
    }

    krb5_cc_close(_gsskrb5_context, &ccache);

    return GSS_S_COMPLETE;
}

