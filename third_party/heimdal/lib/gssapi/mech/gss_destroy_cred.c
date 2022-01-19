/*-
 * Copyright (c) 2005 Doug Rabson
 * All rights reserved.
 *
 * Portions Copyright (c) 2009 Apple Inc. All rights reserved.
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
 */

#include "mech_locl.h"
#include <heim_threads.h>

/**
 * Destroy a credential 
 *
 * gss_release_cred() frees the memory, gss_destroy_cred() removes the credentials from memory/disk and then call gss_release_cred() on the credential.
 *
 * @param min_stat minor status code
 * @param cred_handle credentail to destory
 *
 * @returns a gss_error code, see gss_display_status() about printing
 *          the error code.
 * 
 * @ingroup gssapi
 */

GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_destroy_cred(OM_uint32 *minor_status,
		 gss_cred_id_t *cred_handle)
{
    struct _gss_cred *cred;
    struct _gss_mechanism_cred *mc, *next;

    OM_uint32 junk;

    if (cred_handle == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ;
    if (*cred_handle == GSS_C_NO_CREDENTIAL)
	return GSS_S_COMPLETE;

    cred = (struct _gss_cred *)*cred_handle;
    *cred_handle = GSS_C_NO_CREDENTIAL;

    HEIM_TAILQ_FOREACH_SAFE(mc, &cred->gc_mc, gmc_link, next) {
	HEIM_TAILQ_REMOVE(&cred->gc_mc, mc, gmc_link);
	if (mc->gmc_mech->gm_destroy_cred)
	    mc->gmc_mech->gm_destroy_cred(&junk, &mc->gmc_cred);
	else
	    mc->gmc_mech->gm_release_cred(&junk, &mc->gmc_cred);
	free(mc);
    }
    free(cred);

    return GSS_S_COMPLETE;
}
