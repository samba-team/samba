/* 
   Unix SMB/CIFS implementation.
 
   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"

static const struct gensec_security_ops gensec_ntlmssp_security_ops = {
	.name		= "ntlmssp",
	.sasl_name	= "NTLM",
	.auth_type	= DCERPC_AUTH_TYPE_NTLMSSP,
	.oid            = OID_NTLMSSP,
	.client_start   = gensec_ntlmssp_client_start,
	.update 	= gensec_ntlmssp_update,
	.seal 		= gensec_ntlmssp_seal_packet,
	.sign		= gensec_ntlmssp_sign_packet,
	.check_sig	= gensec_ntlmssp_check_packet,
	.unseal		= gensec_ntlmssp_unseal_packet,
	.session_key	= gensec_ntlmssp_session_key,
	.end		= gensec_ntlmssp_end
};


static const struct gensec_security_ops gensec_spnego_security_ops = {
	.name		= "spnego",
	.sasl_name	= "GSS-SPNEGO",
	.oid            = OID_SPNEGO,
	.client_start   = gensec_spnego_client_start,
	.update 	= gensec_spnego_update,
	.seal 		= gensec_spnego_seal_packet,
	.sign		= gensec_spnego_sign_packet,
	.check_sig	= gensec_spnego_check_packet,
	.unseal		= gensec_spnego_unseal_packet,
	.session_key	= gensec_spnego_session_key,
	.end		= gensec_spnego_end
};

static const struct gensec_security_ops *generic_security_ops[] = {
	&gensec_ntlmssp_security_ops,
	&gensec_spnego_security_ops,
	NULL
};

const struct gensec_security_ops *gensec_security_by_authtype(uint8_t auth_type)
{
	int i;
	for (i=0; generic_security_ops[i]; i++) {
		if (generic_security_ops[i]->auth_type == auth_type) {
			return generic_security_ops[i];
		}
	}

	return NULL;
}

const struct gensec_security_ops *gensec_security_by_oid(const char *oid)
{
	int i;
	for (i=0; generic_security_ops[i]; i++) {
		if (generic_security_ops[i]->oid &&
		    (strcmp(generic_security_ops[i]->oid, oid) == 0)) {
			return generic_security_ops[i];
		}
	}

	return NULL;
}

const struct gensec_security_ops *gensec_security_by_sasl_name(const char *sasl_name)
{
	int i;
	for (i=0; generic_security_ops[i]; i++) {
		if (generic_security_ops[i]->sasl_name 
		    && (strcmp(generic_security_ops[i]->sasl_name, sasl_name) == 0)) {
			return generic_security_ops[i];
		}
	}

	return NULL;
}

const struct gensec_security_ops **gensec_security_all(void)
{
	return generic_security_ops;
}

