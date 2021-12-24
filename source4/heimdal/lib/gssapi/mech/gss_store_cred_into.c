/*
 * Copyright (c) 2009 Kungliga Tekniska Högskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "mech_locl.h"

static OM_uint32
store_mech_cred(OM_uint32 *minor_status,
		gssapi_mech_interface m,
		const struct _gss_mechanism_cred *mc,
		gss_cred_usage_t input_usage,
		OM_uint32 store_cred_flags,
		gss_const_key_value_set_t cred_store,
		gss_cred_usage_t *usage_stored,
                gss_buffer_set_t *env)
{
    OM_uint32 major_status;
    OM_uint32 overwrite_cred =
        !!(store_cred_flags & GSS_C_STORE_CRED_OVERWRITE);
    OM_uint32 default_cred = !!(store_cred_flags & GSS_C_STORE_CRED_DEFAULT);

    if (m->gm_store_cred_into2)
	major_status = m->gm_store_cred_into2(minor_status, mc->gmc_cred,
					      input_usage, &m->gm_mech_oid,
                                              store_cred_flags, cred_store,
                                              NULL, usage_stored,
                                              env);
    else if (m->gm_store_cred_into)
	major_status = m->gm_store_cred_into(minor_status, mc->gmc_cred,
					     input_usage, &m->gm_mech_oid,
					     overwrite_cred, default_cred,
					     cred_store, NULL, usage_stored);
    else if (cred_store == GSS_C_NO_CRED_STORE && m->gm_store_cred)
	major_status = m->gm_store_cred(minor_status, mc->gmc_cred,
					input_usage, &m->gm_mech_oid,
					overwrite_cred, default_cred,
					NULL, usage_stored);
    else
	major_status = GSS_S_UNAVAILABLE;

    return major_status;
}

/*
 * See RFC5588 for gss_store_cred().  This function is a variant that takes a
 * const key/value hashmap-like thing that specifies a credential store in a
 * mechanism- and implementation-specific way, though Heimdal and MIT agree on
 * at least the following keys for the Kerberos mechanism: ccache, keytab, and
 * client_keytab.  A set of environment variables may be output as well
 */
GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_store_cred_into2(OM_uint32 *minor_status,
                     gss_const_cred_id_t input_cred_handle,
                     gss_cred_usage_t input_usage,
                     const gss_OID desired_mech,
                     OM_uint32 store_cred_flags,
                     gss_const_key_value_set_t cred_store,
                     gss_OID_set *elements_stored,
                     gss_cred_usage_t *cred_usage_stored,
                     gss_buffer_set_t *env)
{
    struct _gss_cred *cred = (struct _gss_cred *)input_cred_handle;
    struct _gss_mechanism_cred *mc;
    OM_uint32 major_status;
    OM_uint32 minor;
    size_t successes;

    if (env != NULL)
        *env = NULL;

    if (input_cred_handle == NULL)
	return GSS_S_CALL_INACCESSIBLE_READ;

    if (minor_status == NULL)
	return GSS_S_CALL_INACCESSIBLE_WRITE;
    *minor_status = 0;

    if (cred_usage_stored)
	*cred_usage_stored = 0;

    if (elements_stored) {
	*elements_stored = GSS_C_NO_OID_SET;

	major_status = gss_create_empty_oid_set(minor_status,
						elements_stored);
	if (major_status != GSS_S_COMPLETE)
	    return major_status;
    }

    major_status = GSS_S_NO_CRED;
    successes = 0;

    HEIM_TAILQ_FOREACH(mc, &cred->gc_mc, gmc_link) {
	gssapi_mech_interface m = mc->gmc_mech;

	if (m == NULL || (m->gm_flags & GM_USE_MG_CRED) != 0)
	    continue;

        if (desired_mech != GSS_C_NO_OID &&
            !gss_oid_equal(&m->gm_mech_oid, desired_mech))
            continue;

        major_status = store_mech_cred(minor_status, m, mc, input_usage,
                                       store_cred_flags, cred_store,
                                       cred_usage_stored, env);
	if (major_status == GSS_S_COMPLETE) {
            if (elements_stored && desired_mech != GSS_C_NO_OID)
                gss_add_oid_set_member(&minor, desired_mech, elements_stored);
            successes++;
	} else if (desired_mech != GSS_C_NO_OID) {
	    _gss_mg_error(m, *minor_status);
	    gss_release_oid_set(&minor, elements_stored);
	    return major_status;
        }
    }

    if (successes > 0) {
	*minor_status = 0;
	major_status = GSS_S_COMPLETE;
    }

    heim_assert(successes || major_status != GSS_S_COMPLETE,
		"cred storage failed, but no error raised");

    return major_status;
}

/*
 * See RFC5588 for gss_store_cred().  This function is a variant that takes a
 * const key/value hashmap-like thing that specifies a credential store in a
 * mechanism- and implementation-specific way, though Heimdal and MIT agree on
 * at least the following keys for the Kerberos mechanism: ccache, keytab, and
 * client_keytab.
 */
GSSAPI_LIB_FUNCTION OM_uint32 GSSAPI_LIB_CALL
gss_store_cred_into(OM_uint32 *minor_status,
		    gss_const_cred_id_t input_cred_handle,
		    gss_cred_usage_t input_usage,
		    const gss_OID desired_mech,
		    OM_uint32 overwrite_cred,
		    OM_uint32 default_cred,
		    gss_const_key_value_set_t cred_store,
		    gss_OID_set *elements_stored,
		    gss_cred_usage_t *cred_usage_stored)
{
    OM_uint32 store_cred_flags =
        (overwrite_cred ? GSS_C_STORE_CRED_OVERWRITE : 0) |
        (default_cred ? GSS_C_STORE_CRED_DEFAULT : 0);
    return gss_store_cred_into2(minor_status, input_cred_handle, input_usage,
                                desired_mech, store_cred_flags, cred_store,
                                elements_stored, cred_usage_stored, NULL);
}
