/*
 * Copyright (c) 2018, PADL Software Pty Ltd.
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

#include "mech_locl.h"

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_set_neg_mechs(OM_uint32 *minor_status,
		  gss_cred_id_t cred_handle,
		  const gss_OID_set mechs)
{
    struct _gss_cred *cred = (struct _gss_cred *)cred_handle;
    OM_uint32 major_status, junk;
    gss_OID_set tmp_mechs;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;

    *minor_status = 0;

    if (cred_handle == GSS_C_NO_CREDENTIAL || mechs == GSS_C_NO_OID_SET)
	return GSS_S_CALL_INACCESSIBLE_READ;

    major_status = gss_duplicate_oid_set(minor_status, mechs, &tmp_mechs);
    if (major_status != GSS_S_COMPLETE)
	return major_status;

    gss_release_oid_set(&junk, &cred->gc_neg_mechs);
    cred->gc_neg_mechs = tmp_mechs;

    return GSS_S_COMPLETE;
}
