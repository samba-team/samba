/*
 * Copyright (c) 2021, PADL Software Pty Ltd.
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

#include <krb5_locl.h>
#include <mech_locl.h>
#include <heimntlm.h>

#include "gss-preauth-protos.h"
#include "gss-preauth-private.h"

krb5_error_code
_krb5_gss_map_error(OM_uint32 major, OM_uint32 minor)
{
    krb5_error_code ret;

    if (minor != 0)
        return (krb5_error_code)minor;

    switch (major) {
    case GSS_S_COMPLETE:
        ret = 0;
        break;
    case GSS_S_CONTINUE_NEEDED:
        ret = HEIM_ERR_PA_CONTINUE_NEEDED;
        break;
    case GSS_S_BAD_NAME:
    case GSS_S_BAD_NAMETYPE:
        ret = KRB5_PRINC_NOMATCH;
        break;
    case GSS_S_NO_CRED:
        ret = KRB5_CC_NOTFOUND;
        break;
    case GSS_S_BAD_MIC:
    case GSS_S_DEFECTIVE_CREDENTIAL:
        ret = KRB5KRB_AP_ERR_BAD_INTEGRITY;
        break;
    case GSS_S_FAILURE:
    default:
        ret = KRB5KDC_ERR_PREAUTH_FAILED;
        break;
    }

    return ret;
}

krb5_error_code
_krb5_gss_pa_derive_key(krb5_context context,
                        gss_ctx_id_t ctx,
                        krb5int32 nonce,
                        krb5_enctype enctype,
                        krb5_keyblock **keyblock)
{
    krb5_error_code ret;
    u_char saltdata[12] = "KRB-GSS";
    krb5_keyblock kdkey;
    size_t keysize;

    OM_uint32 major, minor;
    gss_buffer_desc salt, dkey = GSS_C_EMPTY_BUFFER;

    *keyblock = NULL;

    ret = krb5_enctype_keysize(context, enctype, &keysize);
    if (ret)
        return ret;

    saltdata[ 8] = (nonce >> 0 ) & 0xFF;
    saltdata[ 9] = (nonce >> 8 ) & 0xFF;
    saltdata[10] = (nonce >> 16) & 0xFF;
    saltdata[11] = (nonce >> 24) & 0xFF;

    salt.value = saltdata;
    salt.length = sizeof(saltdata);

    major = gss_pseudo_random(&minor, ctx, GSS_C_PRF_KEY_FULL,
                              &salt, keysize, &dkey);
    if (GSS_ERROR(major))
        return KRB5_PREAUTH_NO_KEY;

    kdkey.keytype = enctype;
    kdkey.keyvalue.data = dkey.value;
    kdkey.keyvalue.length = dkey.length;

    ret = krb5_copy_keyblock(context, &kdkey, keyblock);

    if (dkey.value) {
        memset_s(dkey.value, dkey.length, 0, dkey.length);
        gss_release_buffer(&minor, &dkey);
    }

    return ret;
}

krb5_error_code
_krb5_gss_pa_unparse_name(krb5_context context,
                          krb5_const_principal principal,
                          gss_name_t *namep)
{
    krb5_error_code ret;
    char *name = NULL;

    OM_uint32 major, minor;
    gss_buffer_desc name_buf;

    *namep = GSS_C_NO_NAME;

    if (principal->name.name_type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
        if (principal->name.name_string.len != 1)
            return EINVAL;

        name = principal->name.name_string.val[0];
    } else {
        ret = krb5_unparse_name(context, principal, &name);
        if (ret)
            return ret;
    }

    name_buf.length = strlen(name);
    name_buf.value = name;

    major = gss_import_name(&minor, &name_buf,
                            GSS_KRB5_NT_PRINCIPAL_NAME, namep);
    if (major == GSS_S_BAD_NAMETYPE) {
        gss_OID name_type = GSS_C_NO_OID;
        int flags = 0;

        if (principal->name.name_type == KRB5_NT_ENTERPRISE_PRINCIPAL) {
            name_type = GSS_C_NT_USER_NAME;
        } else if (principal->name.name_type == KRB5_NT_PRINCIPAL) {
            flags = KRB5_PRINCIPAL_UNPARSE_SHORT;
            name_type = GSS_C_NT_USER_NAME;
        } else if ((principal->name.name_type == KRB5_NT_SRV_HST ||
                    principal->name.name_type == KRB5_NT_SRV_INST) &&
            principal->name.name_string.len == 2) {
            flags = KRB5_PRINCIPAL_UNPARSE_NO_REALM;
            name_type = GSS_C_NT_HOSTBASED_SERVICE;
        }

        if (flags) {
            krb5_xfree(name);

            ret = krb5_unparse_name_flags(context, principal, flags, &name);
            if (ret)
                return ret;

            if (gss_oid_equal(name_type, GSS_C_NT_HOSTBASED_SERVICE)) {
                char *inst = strchr(name, '/');
                if (inst)
                    *inst = '@';
            }

            name_buf.length = strlen(name);
            name_buf.value = name;
        }

        if (name_type)
            major = gss_import_name(&minor, &name_buf, name_type, namep);
    }

    if (name != principal->name.name_string.val[0])
        krb5_xfree(name);

    return _krb5_gss_map_error(major, minor);
}

krb5_error_code
_krb5_gss_pa_parse_name(krb5_context context,
                        gss_const_name_t name,
                        int flags,
                        krb5_principal *principal)
{
    krb5_error_code ret;
    char *displayed_name0;

    OM_uint32 major, minor;
    gss_OID name_type = GSS_C_NO_OID;
    gss_buffer_desc displayed_name = GSS_C_EMPTY_BUFFER;

    major = gss_display_name(&minor, name, &displayed_name, &name_type);
    if (GSS_ERROR(major))
        return _krb5_gss_map_error(major, minor);

    if (gss_oid_equal(name_type, GSS_C_NT_ANONYMOUS)) {
        ret = krb5_make_principal(context, principal, KRB5_ANON_REALM,
                                  KRB5_WELLKNOWN_NAME, KRB5_ANON_NAME, NULL);
        if (ret == 0)
            (*principal)->name.name_type = KRB5_NT_WELLKNOWN;
    } else {
        displayed_name0 = malloc(displayed_name.length + 1);
            if (displayed_name0 == NULL)
                return krb5_enomem(context);

        memcpy(displayed_name0, displayed_name.value, displayed_name.length);
        displayed_name0[displayed_name.length] = '\0';

        ret = krb5_parse_name_flags(context, displayed_name0, flags, principal);
                                    gss_release_buffer(&minor, &displayed_name);
        free(displayed_name0);
    }

    gss_release_buffer(&minor, &displayed_name);

    return ret;
}

void
_krb5_gss_data_to_buffer(const krb5_data *data, gss_buffer_t buffer)
{
    if (data) {
        buffer->length = data->length;
        buffer->value = data->data;
    } else {
        _mg_buffer_zero(buffer);
    }
}

void
_krb5_gss_buffer_to_data(gss_const_buffer_t buffer, krb5_data *data)
{
    if (buffer) {
        data->length = buffer->length;
        data->data = buffer->value;
    } else {
        krb5_data_zero(data);
    }
}
