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
static NTSTATUS dcerpc_ntlmssp_unseal(struct dcerpc_security *dcerpc_security, 
				   TALLOC_CTX *mem_ctx, 
				   uint8_t *data, size_t length, DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private_data;

	return ntlmssp_unseal_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

static NTSTATUS dcerpc_ntlmssp_check_sig(struct dcerpc_security *dcerpc_security, 
				  TALLOC_CTX *mem_ctx, 
				  const uint8_t *data, size_t length, 
				  const DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private_data;

	return ntlmssp_check_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

static NTSTATUS dcerpc_ntlmssp_seal(struct dcerpc_security *dcerpc_security, 
				 TALLOC_CTX *mem_ctx, 
				 uint8_t *data, size_t length, 
				 DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private_data;

	return ntlmssp_seal_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

static NTSTATUS dcerpc_ntlmssp_sign(struct dcerpc_security *dcerpc_security, 
				 TALLOC_CTX *mem_ctx, 
				 const uint8_t *data, size_t length, 
				 DATA_BLOB *sig)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private_data;

	return ntlmssp_sign_packet(ntlmssp_state, mem_ctx, data, length, sig);
}

static NTSTATUS dcerpc_ntlmssp_session_key(struct dcerpc_security *dcerpc_security, 
				 DATA_BLOB *session_key)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private_data;

	if (!ntlmssp_state->session_key.data) {
		return NT_STATUS_NO_USER_SESSION_KEY;
	}
	*session_key = ntlmssp_state->session_key;

	return NT_STATUS_OK;
}

static NTSTATUS dcerpc_ntlmssp_start(struct dcerpc_pipe *dce_pipe, struct dcerpc_security *dcerpc_security)
{
	struct ntlmssp_state *ntlmssp_state = NULL;
	NTSTATUS status;

	status = ntlmssp_client_start(&ntlmssp_state);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = ntlmssp_set_domain(ntlmssp_state, dcerpc_security->user.domain);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	status = ntlmssp_set_username(ntlmssp_state, dcerpc_security->user.name);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = ntlmssp_set_password(ntlmssp_state, dcerpc_security->user.password);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	
	dcerpc_security->private_data = ntlmssp_state;

	return status;
}

static NTSTATUS dcerpc_ntlmssp_update(struct dcerpc_security *dcerpc_security, TALLOC_CTX *out_mem_ctx, 
						const DATA_BLOB in, DATA_BLOB *out) 
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private_data;

	return ntlmssp_update(ntlmssp_state, out_mem_ctx, in, out);
}

static void dcerpc_ntlmssp_end(struct dcerpc_security *dcerpc_security)
{
	struct ntlmssp_state *ntlmssp_state = dcerpc_security->private_data;

	ntlmssp_end(&ntlmssp_state);

	dcerpc_security->private_data = NULL;
}

static const struct dcesrv_security_ops dcerpc_ntlmssp_security_ops = {
	.name		= "ntlmssp",
	.auth_type	= DCERPC_AUTH_TYPE_NTLMSSP,
	.start 		= dcerpc_ntlmssp_start,
	.update 	= dcerpc_ntlmssp_update,
	.seal 		= dcerpc_ntlmssp_seal,
	.sign		= dcerpc_ntlmssp_sign,
	.check_sig	= dcerpc_ntlmssp_check_sig,
	.unseal		= dcerpc_ntlmssp_unseal,
	.session_key	= dcerpc_ntlmssp_session_key,
	.end		= dcerpc_ntlmssp_end
};

const struct dcesrv_security_ops *dcerpc_ntlmssp_security_get_ops(void)
{
	return &dcerpc_ntlmssp_security_ops;
}

/*
  do ntlm style authentication on a dcerpc pipe
*/
NTSTATUS dcerpc_bind_auth_ntlm(struct dcerpc_pipe *p,
			       const char *uuid, uint_t version,
			       const char *domain,
			       const char *username,
			       const char *password)
{
	NTSTATUS status;

	status = dcerpc_bind_auth(p, DCERPC_AUTH_TYPE_NTLMSSP,
				uuid, version,
				domain, username, 
				password);

	return status;
}


