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

#include "mech_locl.h"
RCSID("$Id$");

OM_uint32
gss_set_cred_option (OM_uint32 *minor_status,
		     gss_cred_id_t *cred_handle,
		     const gss_OID object,
		     const gss_buffer_t value)
{
	struct _gss_cred *cred = (struct _gss_cred *) cred_handle;
	OM_uint32		major_status = GSS_S_COMPLETE;
	struct _gss_mechanism_cred *mc;
	gssapi_mech_interface	m;
	int one_ok = 0;

	*minor_status = 0;

	if (cred == NULL)
		return GSS_S_NO_CRED;

	SLIST_FOREACH(mc, &cred->gc_mc, gmc_link) {

		m = mc->gmc_mech;

		if (m == NULL)
			return GSS_S_BAD_MECH;

		if (m->gm_set_cred_option == NULL)
			continue;

		major_status = m->gm_set_cred_option(minor_status,
		    &mc->gmc_cred, object, value);
		if (major_status == GSS_S_BAD_MECH)
			one_ok = 1;
	}
	if (one_ok) {
		*minor_status = 0;
		return GSS_S_COMPLETE;
	}
	return major_status;
}

