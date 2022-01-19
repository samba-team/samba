/*
 * Copyright (c) 2004, PADL Software Pty Ltd.
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

#include "spnego_locl.h"
#include <gssapi_mech.h>

/*
 * RFC2478, SPNEGO:
 *  The security mechanism of the initial
 *  negotiation token is identified by the Object Identifier
 *  iso.org.dod.internet.security.mechanism.snego (1.3.6.1.5.5.2).
 */
static gss_mo_desc spnego_mo[] = {
    {
	GSS_C_MA_SASL_MECH_NAME,
	GSS_MO_MA,
	"SASL mech name",
	rk_UNCONST("SPNEGO"),
	_gss_mo_get_ctx_as_string,
	NULL
    },
    {
	GSS_C_MA_MECH_NAME,
	GSS_MO_MA,
	"Mechanism name",
	rk_UNCONST("SPNEGO"),
	_gss_mo_get_ctx_as_string,
	NULL
    },
    {
	GSS_C_MA_MECH_DESCRIPTION,
	GSS_MO_MA,
	"Mechanism description",
	rk_UNCONST("Heimdal SPNEGO Mechanism"),
	_gss_mo_get_ctx_as_string,
	NULL
    },
    {
	GSS_C_MA_MECH_NEGO,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_MECH_PSEUDO,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    }
};

static gssapi_mech_interface_desc spnego_mech = {
    GMI_VERSION,
    "spnego",
    {6, rk_UNCONST("\x2b\x06\x01\x05\x05\x02") },
    GM_USE_MG_CRED | GM_USE_MG_NAME,
    NULL, /* gm_acquire_cred */
    NULL, /* gm_release_cred */
    _gss_spnego_init_sec_context,
    _gss_spnego_accept_sec_context,
    _gss_spnego_process_context_token,
    _gss_spnego_delete_sec_context,
    _gss_spnego_context_time,
    _gss_spnego_get_mic,
    _gss_spnego_verify_mic,
    _gss_spnego_wrap,
    _gss_spnego_unwrap,
    NULL, /* gm_display_status */
    NULL, /* gm_indicate_mechs */
    NULL, /* gm_compare_name */
    NULL, /* gm_display_name */
    NULL, /* gm_import_name */
    NULL, /* gm_export_name */
    NULL, /* gm_release_name */
    NULL, /* gm_inquire_cred */
    _gss_spnego_inquire_context,
    _gss_spnego_wrap_size_limit,
    NULL, /* gm_add_cred */
    NULL, /* gm_inquire_cred_by_mech */
    _gss_spnego_export_sec_context,
    _gss_spnego_import_sec_context,
    NULL, /* gm_spnego_inquire_names_for_mech */
    NULL, /* gm_spnego_inquire_mechs_for_name */
    NULL, /* gm_spnego_canonicalize_name */
    NULL, /* gm_spnego_duplicate_name */
    _gss_spnego_inquire_sec_context_by_oid,
    NULL, /* gm_inquire_cred_by_oid */
    _gss_spnego_set_sec_context_option,
    NULL, /* gm_set_cred_option */
    _gss_spnego_pseudo_random,
    _gss_spnego_wrap_iov,
    _gss_spnego_unwrap_iov,
    _gss_spnego_wrap_iov_length,
    NULL,
    NULL, /* gm_export_cred */
    NULL, /* gm_import_cred */
    NULL, /* gm_acquire_cred_from */
    NULL, /* gm_acquire_cred_impersonate_name */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    spnego_mo,
    sizeof(spnego_mo) / sizeof(spnego_mo[0]),
    NULL, /* gm_localname */
    NULL, /* gm_authorize_localname */
    NULL, /* gm_display_name_ext */
    NULL, /* gm_inquire_name */
    NULL, /* gm_get_name_attribute */
    NULL, /* gm_set_name_attribute */
    NULL, /* gm_delete_name_attribute */
    NULL, /* gm_export_name_composite */
    NULL, /* gm_duplicate_cred */
    NULL, /* gm_add_cred_from */
    NULL, /* gm_store_cred_into */
    NULL, /* gm_query_mechanism_info */
    NULL, /* gm_query_meta_data */
    NULL, /* gm_exchange_meta_data */
    NULL, /* gm_store_cred_into2 */
    NULL  /* gm_compat */
};

gssapi_mech_interface
__gss_spnego_initialize(void)
{
	return &spnego_mech;
}

