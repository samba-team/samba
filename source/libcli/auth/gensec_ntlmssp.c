/* 
   Unix SMB/CIFS implementation.

   dcerpc authentication operations

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


NTSTATUS gensec_ntlmssp_client_start(struct gensec_security *gensec_security)
{
	struct ntlmssp_state *ntlmssp_state = NULL;
	NTSTATUS status;

	status = ntlmssp_client_start(&ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = ntlmssp_set_domain(ntlmssp_state, gensec_security->user.domain);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	status = ntlmssp_set_username(ntlmssp_state, gensec_security->user.name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = ntlmssp_set_password(ntlmssp_state, gensec_security->user.password);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	gensec_security->private_data = ntlmssp_state;

	return status;
}

/*
  wrappers for the ntlmssp_*() functions
*/
NTSTATUS gensec_ntlmssp_unseal_packet(struct gensec_security *gensec_security, 
				      TALLOC_CTX *mem_ctx, 
				      uint8_t *data, size_t length, DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = gensec_security->private_data;

	return ntlmssp_unseal_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

NTSTATUS gensec_ntlmssp_check_packet(struct gensec_security *gensec_security, 
				     TALLOC_CTX *mem_ctx, 
				     const uint8_t *data, size_t length, 
				     const DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = gensec_security->private_data;

	return ntlmssp_check_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

NTSTATUS gensec_ntlmssp_seal_packet(struct gensec_security *gensec_security, 
				    TALLOC_CTX *mem_ctx, 
				    uint8_t *data, size_t length, 
				    DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = gensec_security->private_data;

	return ntlmssp_seal_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

NTSTATUS gensec_ntlmssp_sign_packet(struct gensec_security *gensec_security, 
				    TALLOC_CTX *mem_ctx, 
				    const uint8_t *data, size_t length, 
				    DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = gensec_security->private_data;

	return ntlmssp_sign_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

NTSTATUS gensec_ntlmssp_session_key(struct gensec_security *gensec_security, 
				    DATA_BLOB *session_key)
{
	struct ntlmssp_state *ntlmssp_state = gensec_security->private_data;

	return ntlmssp_session_key(ntlmssp_state, session_key);
}

NTSTATUS gensec_ntlmssp_update(struct gensec_security *gensec_security, TALLOC_CTX *out_mem_ctx, 
			       const DATA_BLOB in, DATA_BLOB *out) 
{
	struct ntlmssp_state *ntlmssp_state = gensec_security->private_data;

	return ntlmssp_update(ntlmssp_state, out_mem_ctx, in, out);
}

void gensec_ntlmssp_end(struct gensec_security *gensec_security)
{
	struct ntlmssp_state *ntlmssp_state = gensec_security->private_data;

	ntlmssp_end(&ntlmssp_state);

	gensec_security->private_data = NULL;
}
