/*
 * Copyright (c) 2018 Kungliga Tekniska Högskolan
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

#include "gsskrb5_locl.h"

OM_uint32 GSSAPI_CALLCONV _gsskrb5_duplicate_cred (
     OM_uint32           *minor_status,
     gss_const_cred_id_t input_cred_handle,
     gss_cred_id_t       *output_cred_handle)
{
    krb5_context context;
    gsskrb5_cred cred, dup;
    OM_uint32 major, junk;

    dup = NULL;

    if (output_cred_handle == NULL) {
        *minor_status = EINVAL;
        return GSS_S_CALL_INACCESSIBLE_WRITE;
    }

    GSSAPI_KRB5_INIT (&context);

    if (input_cred_handle == GSS_C_NO_CREDENTIAL) {
        /* Duplicate the default credential */
        return _gsskrb5_acquire_cred_from(minor_status, GSS_C_NO_NAME,
					  GSS_C_INDEFINITE,
					  GSS_C_NO_OID_SET,
					  GSS_C_BOTH,
					  GSS_C_NO_CRED_STORE,
					  output_cred_handle,
					  NULL, NULL);
    }

    /* Duplicate the input credential */

    dup = calloc(1, sizeof(*dup));
    if (dup == NULL) {
        *minor_status = krb5_enomem(context);
        return (GSS_S_FAILURE);
    }

    *output_cred_handle = (gss_cred_id_t)dup; /* making sure to release on error */

    cred = (gsskrb5_cred)input_cred_handle;
    HEIMDAL_MUTEX_lock(&cred->cred_id_mutex);

    dup->destination_realm = NULL;
    dup->usage = cred->usage;
    dup->endtime = cred->endtime;
    dup->principal = NULL;
    dup->keytab = NULL;
    dup->ccache = NULL;
    dup->mechanisms = NULL;

    major = GSS_S_FAILURE;

    HEIMDAL_MUTEX_init(&dup->cred_id_mutex);
    if (cred->destination_realm &&
        (dup->destination_realm = strdup(cred->destination_realm)) == NULL) {
        *minor_status = krb5_enomem(context);
        goto fail;
    }
    *minor_status = krb5_copy_principal(context, cred->principal,
                                        &dup->principal);
    if (*minor_status)
        goto fail;

    if (cred->keytab) {
        char *name = NULL;

        *minor_status = krb5_kt_get_full_name(context, cred->keytab, &name);
        if (*minor_status)
            goto fail;
        *minor_status = krb5_kt_resolve(context, name, &dup->keytab);
        krb5_xfree(name);
        if (*minor_status)
            goto fail;
    }

    if (cred->ccache) {
        const char *type, *name;
        char *type_name = NULL;

        type = krb5_cc_get_type(context, cred->ccache); /* can't fail */
        if (strcmp(type, "MEMORY") == 0) {
            *minor_status = krb5_cc_new_unique(context, type, NULL,
                                               &dup->ccache);
            if (*minor_status)
                goto fail;

            *minor_status = krb5_cc_copy_cache(context, cred->ccache,
                                               dup->ccache);
            if (*minor_status)
                goto fail;

        } else {
            name = krb5_cc_get_name(context, cred->ccache);
            if (name == NULL) {
                *minor_status = ENOMEM;
                goto fail;
            }

            if (asprintf(&type_name, "%s:%s", type, name) == -1 ||
                type_name == NULL) {
                *minor_status = ENOMEM;
                goto fail;
            }

            *minor_status = krb5_cc_resolve(context, type_name,
                                            &dup->ccache);
            free(type_name);
            if (*minor_status)
                goto fail;
        }
    }

    major = gss_create_empty_oid_set(minor_status, &dup->mechanisms);
    if (major != GSS_S_COMPLETE)
        goto fail;

    major = gss_add_oid_set_member(minor_status, GSS_KRB5_MECHANISM,
                                   &dup->mechanisms);
    if (major != GSS_S_COMPLETE)
        goto fail;

    HEIMDAL_MUTEX_unlock(&cred->cred_id_mutex);
    *output_cred_handle = (gss_cred_id_t)dup;
    *minor_status = 0;
    return major;

fail:
    HEIMDAL_MUTEX_unlock(&cred->cred_id_mutex);
    *output_cred_handle = (gss_cred_id_t)dup;
    _gsskrb5_release_cred(&junk, output_cred_handle);
    return major;
}
