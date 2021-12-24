/*
 * Copyright (c) 2006-2020 Kungliga Tekniska Högskolan
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

#include "sanon_locl.h"

static uint8_t anonymous_identity;
gss_name_t
_gss_sanon_anonymous_identity = (gss_name_t)&anonymous_identity;
gss_cred_id_t
_gss_sanon_anonymous_cred = (gss_cred_id_t)&anonymous_identity;

static uint8_t non_anonymous_identity;
gss_name_t
_gss_sanon_non_anonymous_identity = (gss_name_t)&non_anonymous_identity;
gss_cred_id_t
_gss_sanon_non_anonymous_cred = (gss_cred_id_t)&non_anonymous_identity;

static gss_buffer_desc wellknown_user_name = {
    SANON_WELLKNOWN_USER_NAME_LEN,
    SANON_WELLKNOWN_USER_NAME
};
gss_buffer_t
_gss_sanon_wellknown_user_name = &wellknown_user_name;

static gss_buffer_desc wellknown_service_name = {
    SANON_WELLKNOWN_SERVICE_NAME_LEN,
    SANON_WELLKNOWN_SERVICE_NAME
};
gss_buffer_t
_gss_sanon_wellknown_service_name = &wellknown_service_name;

static gss_mo_desc sanon_mo[] = {
    {
	GSS_C_MA_MECH_NAME,
	GSS_MO_MA,
	"Mechanism name",
	rk_UNCONST("SANON-X25519"),
	_gss_mo_get_ctx_as_string,
	NULL
    },
    {
	GSS_C_MA_MECH_DESCRIPTION,
	GSS_MO_MA,
	"Mechanism description",
	rk_UNCONST("Heimdal Simple Anonymous (X25519) Mechanism"),
	_gss_mo_get_ctx_as_string,
	NULL
    },
    {
	GSS_C_MA_MECH_CONCRETE,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_ITOK_FRAMED,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_AUTH_INIT_ANON,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_AUTH_TARG_ANON,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_INTEG_PROT,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_CONF_PROT,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_MIC,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_WRAP,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_REPLAY_DET,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_OOS_DET,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_CBINDINGS,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_PFS,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_CTX_TRANS,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    },
    {
	GSS_C_MA_NEGOEX_AND_SPNEGO,
	GSS_MO_MA,
	NULL,
	NULL,
	NULL,
	NULL
    }
};

static gssapi_mech_interface_desc sanon_mech = {
    GMI_VERSION,
    "sanon-x25519",
    { 10, rk_UNCONST("\x2b\x06\x01\x04\x01\xa9\x4a\x1a\x01\x6e") },
    0,
    NULL,
    _gss_sanon_release_cred,
    _gss_sanon_init_sec_context,
    _gss_sanon_accept_sec_context,
    _gss_sanon_process_context_token,
    _gss_sanon_delete_sec_context,
    _gss_sanon_context_time,
    _gss_sanon_get_mic,
    _gss_sanon_verify_mic,
    _gss_sanon_wrap,
    _gss_sanon_unwrap,
    _gss_sanon_display_status,
    NULL, /* gm_indicate_mechs */
    _gss_sanon_compare_name,
    _gss_sanon_display_name,
    _gss_sanon_import_name,
    _gss_sanon_export_name,
    _gss_sanon_release_name,
    _gss_sanon_inquire_cred,
    _gss_sanon_inquire_context,
    _gss_sanon_wrap_size_limit,
    NULL, /* gm_add_cred */
    _gss_sanon_inquire_cred_by_mech,
    _gss_sanon_export_sec_context,
    _gss_sanon_import_sec_context,
    _gss_sanon_inquire_names_for_mech,
    _gss_sanon_inquire_mechs_for_name,
    _gss_sanon_canonicalize_name,
    _gss_sanon_duplicate_name,
    _gss_sanon_inquire_sec_context_by_oid,
    NULL, /* gm_inquire_cred_by_oid */
    NULL, /* gm_set_sec_context_option */
    NULL, /* gm_set_cred_option */
    _gss_sanon_pseudo_random,
    _gss_sanon_wrap_iov,
    _gss_sanon_unwrap_iov,
    _gss_sanon_wrap_iov_length,
    NULL, /* gm_store_cred */
    _gss_sanon_export_cred,
    _gss_sanon_import_cred,
    _gss_sanon_acquire_cred_from,
    NULL, /* gm_acquire_cred_impersonate_name */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    sanon_mo,
    sizeof(sanon_mo) / sizeof(sanon_mo[0]),
    NULL, /* gm_localname */
    NULL, /* gm_authorize_localname */
    NULL, /* gm_display_name_ext */
    NULL, /* gm_inquire_name */
    NULL, /* gm_get_name_attribute */
    NULL, /* gm_set_name_attribute */
    NULL, /* gm_delete_name_attribute */
    NULL, /* gm_export_name_composite */
    _gss_sanon_duplicate_cred,
    _gss_sanon_add_cred_from,
    NULL, /* gm_store_cred_into */
    _gssspi_sanon_query_mechanism_info,
    _gssspi_sanon_query_meta_data,
    _gssspi_sanon_exchange_meta_data,
    NULL, /* gm_store_cred_into2 */
    NULL, /* gm_compat */
};

gssapi_mech_interface
__gss_sanon_initialize(void)
{
    return &sanon_mech;
}
