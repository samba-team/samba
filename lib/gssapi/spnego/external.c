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
#include <gssapi_mech.h>

RCSID("$Id$");

/*
 * RFC2478, SPNEGO:
 *  The security mechanism of the initial
 *  negotiation token is identified by the Object Identifier
 *  iso.org.dod.internet.security.mechanism.snego (1.3.6.1.5.5.2).
 */

static gssapi_mech_interface_desc spnego_mech = {
    GMI_VERSION,
    "spnego",
    {6, (void *)"\x2b\x06\x01\x05\x05\x02"},
    gss_spnego_acquire_cred,
    gss_spnego_release_cred,
    gss_spnego_init_sec_context,
    gss_spnego_accept_sec_context,
    gss_spnego_process_context_token,
    gss_spnego_delete_sec_context,
    gss_spnego_context_time,
    gss_spnego_get_mic,
    gss_spnego_verify_mic,
    gss_spnego_wrap,
    gss_spnego_unwrap,
    gss_spnego_display_status,
    gss_spnego_indicate_mechs,
    gss_spnego_compare_name,
    gss_spnego_display_name,
    gss_spnego_import_name,
    gss_spnego_export_name,
    gss_spnego_release_name,
    gss_spnego_inquire_cred,
    gss_spnego_inquire_context,
    gss_spnego_wrap_size_limit,
    gss_spnego_add_cred,
    gss_spnego_inquire_cred_by_mech,
    gss_spnego_export_sec_context,
    gss_spnego_import_sec_context,
    NULL,
    gss_spnego_inquire_mechs_for_name,
    gss_spnego_canonicalize_name,
    gss_spnego_duplicate_name
};

gssapi_mech_interface
__gss_spnego_initialize(void)
{
	return &spnego_mech;
}

static gss_OID_desc gss_spnego_mechanism_desc = 
    {6, (void *)"\x2b\x06\x01\x05\x05\x02"};

gss_OID GSS_SPNEGO_MECHANISM = &gss_spnego_mechanism_desc;
