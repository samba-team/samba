/*
 * Copyright (c) 2005 Andrew Bartlett <abartlet@samba.org>
 * 
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

#include "kdc_locl.h"

/* 
 * Setup some of the defaults for the KDC configuration.
 * 
 * Note: Caller must also fill in:
 * - db
 * - num_db
 * - logf
 *
*/

void
krb5_kdc_default_config(krb5_kdc_configuration *config)
{
    memset(config, 0, sizeof(*config));
    config->require_preauth = TRUE;
    config->kdc_warn_pwexpire = 0;
    config->encode_as_rep_as_tgs_rep = FALSE; /* bug compatibility */
    config->check_ticket_addresses = TRUE;
    config->allow_null_ticket_addresses = TRUE;
    config->allow_anonymous = FALSE;
    config->trpolicy = TRPOLICY_ALWAYS_CHECK;
    config->enable_v4 = FALSE;
    config->enable_kaserver = FALSE;
    config->enable_524 = FALSE; /* overriden by enable_v4 in configure()) */
    config->enable_v4_cross_realm = FALSE;
    config->enable_pkinit = FALSE;
    config->enable_pkinit_princ_in_cert = TRUE;
    config->db = NULL;
    config->num_db = 0;
    config->logf = NULL;
}
