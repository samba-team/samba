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

#include "spnego_locl.h"

RCSID("$Id$");

/*
 * RFC2478, SPNEGO:
 *  The security mechanism of the initial
 *  negotiation token is identified by the Object Identifier
 *  iso.org.dod.internet.security.mechanism.snego (1.3.6.1.5.5.2).
 */

static struct gss_config spnego_mech = {
	{6, (void *)"\x2b\x06\x01\x05\x05\x02"},
	NULL,
	gss_spnego_acquire_cred,
	gss_spnego_release_cred,
	gss_spnego_init_sec_context,
	gss_spnego_accept_sec_context,
	gss_spnego_process_context_token,
	gss_spnego_delete_sec_context,
	gss_spnego_context_time,
	gss_spnego_sign,
	gss_spnego_verify,
	gss_spnego_seal,
	gss_spnego_unseal,
	NULL, /*gss_spnego_display_status,*/
	gss_spnego_indicate_mechs,
	gss_spnego_compare_name,
	gss_spnego_display_name,
	gss_spnego_import_name,
	gss_spnego_release_name,
	gss_spnego_inquire_cred,
	gss_spnego_add_cred,
	gss_spnego_export_sec_context,
	gss_spnego_import_sec_context,
	gss_spnego_inquire_cred_by_mech,
	gss_spnego_inquire_names_for_mech,
	gss_spnego_inquire_context,
	gss_spnego_internal_release_oid,
	gss_spnego_wrap_size_limit,
	NULL, /*gss_spnego_pname_to_uid,*/
	gss_spnego_duplicate_name,
	NULL, /*gss_spnego_set_allowable_enctypes */
	gss_spnego_verify_mic,
	gss_spnego_get_mic,
	gss_spnego_wrap,
	gss_spnego_unwrap,
	gss_spnego_canonicalize_name,
	gss_spnego_export_name,
	gss_spnego_wrap_ex,
	gss_spnego_unwrap_ex,
	gss_spnego_complete_auth_token,
	NULL, /*gss_spnego_set_neg_mechs*/
	NULL, /*gss_spnego_get_neg_mechs*/
	gss_spnego_inquire_sec_context_by_oid,
	gss_spnego_inquire_cred_by_oid,
	gss_spnego_set_sec_context_option,
	NULL /*gss_spnego_userok*/
};

gss_OID GSS_SPNEGO_MECHANISM = &spnego_mech.mech_type;

gss_mechanism gss_spnego_initialize(void)
{
	return &spnego_mech;
}

