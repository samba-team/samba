/* 
   Unix SMB/CIFS implementation.

   dcerpc authentication operations

   Copyright (C) Andrew Tridgell 2003
   
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

/*
  wrappers for the ntlmssp_*() functions
*/
static NTSTATUS ntlm_unseal_packet(struct dcerpc_security *dcerpc_security, 
				   TALLOC_CTX *mem_ctx, 
				   uchar *data, size_t length, DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private;
	return ntlmssp_unseal_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

static NTSTATUS ntlm_check_packet(struct dcerpc_security *dcerpc_security, 
				  TALLOC_CTX *mem_ctx, 
				  const uchar *data, size_t length, 
				  const DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private;
	return ntlmssp_check_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

static NTSTATUS ntlm_seal_packet(struct dcerpc_security *dcerpc_security, 
				 TALLOC_CTX *mem_ctx, 
				 uchar *data, size_t length, 
				 DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private;
	return ntlmssp_seal_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

static NTSTATUS ntlm_sign_packet(struct dcerpc_security *dcerpc_security, 
				 TALLOC_CTX *mem_ctx, 
				 const uchar *data, size_t length, 
				 DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private;
	return ntlmssp_sign_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

static NTSTATUS ntlm_session_key(struct dcerpc_security *dcerpc_security, 
				 DATA_BLOB *session_key)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private;
	if (!ntlmssp_state->session_key.data) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}
	*session_key = ntlmssp_state->session_key;
	return NT_STATUS_OK;
}

static void ntlm_security_end(struct dcerpc_security *dcerpc_security)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private;
	ntlmssp_end(&ntlmssp_state);
}



/*
  do ntlm style authentication on a dcerpc pipe
*/
NTSTATUS dcerpc_bind_auth_ntlm(struct dcerpc_pipe *p,
			       const char *uuid, unsigned version,
			       const char *domain,
			       const char *username,
			       const char *password)
{
	NTSTATUS status;
	struct ntlmssp_state *state;
	TALLOC_CTX *mem_ctx;
	DATA_BLOB credentials;

	mem_ctx = talloc_init("dcerpc_bind_auth_ntlm");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	status = ntlmssp_client_start(&state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = ntlmssp_set_domain(state, domain);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}
	
	status = ntlmssp_set_username(state, username);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = ntlmssp_set_password(state, password);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	p->auth_info = talloc(p->mem_ctx, sizeof(*p->auth_info));
	if (!p->auth_info) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	p->auth_info->auth_type = DCERPC_AUTH_TYPE_NTLMSSP;
	
	if (p->flags & DCERPC_SEAL) {
		p->auth_info->auth_level = DCERPC_AUTH_LEVEL_PRIVACY;
		state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN | NTLMSSP_NEGOTIATE_SEAL;
	} else {
		/* ntlmssp does not work on dcerpc with
		   AUTH_LEVEL_NONE */
		state->neg_flags |= NTLMSSP_NEGOTIATE_SIGN;
		p->auth_info->auth_level = DCERPC_AUTH_LEVEL_INTEGRITY;
	}
	p->auth_info->auth_pad_length = 0;
	p->auth_info->auth_reserved = 0;
	p->auth_info->auth_context_id = random();
	p->auth_info->credentials = data_blob(NULL, 0);
	p->security_state = NULL;

	status = ntlmssp_update(state, mem_ctx,
				p->auth_info->credentials,
				&credentials);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto done;
	}

	p->auth_info->credentials = credentials;

	status = dcerpc_bind_byuuid(p, mem_ctx, uuid, version);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = ntlmssp_update(state, mem_ctx,
				p->auth_info->credentials, 
				&credentials);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto done;
	}

	p->auth_info->credentials = credentials;

	status = dcerpc_auth3(p, mem_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	p->security_state = talloc_p(p->mem_ctx, struct dcerpc_security);
	if (!p->security_state) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	p->security_state->private = state;
	p->security_state->unseal_packet = ntlm_unseal_packet;
	p->security_state->check_packet = ntlm_check_packet;
	p->security_state->seal_packet = ntlm_seal_packet;
	p->security_state->sign_packet = ntlm_sign_packet;
	p->security_state->session_key = ntlm_session_key;
	p->security_state->security_end = ntlm_security_end;

done:
	talloc_destroy(mem_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		p->security_state = NULL;
		p->auth_info = NULL;
	}

	return status;
}


