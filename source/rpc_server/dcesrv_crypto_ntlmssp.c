/* 
   Unix SMB/CIFS implementation.

   server side dcerpc authentication code - NTLMSSP auth/crypto code

   Copyright (C) Andrew Tridgell 2004
   Copyright (C) Stefan (metze) Metzmacher 2004

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

/*
  this provides the NTLMSSP backend for server side rpc
*/

#include "includes.h"


/*
  start crypto state
*/
static NTSTATUS dcesrv_crypto_ntlmssp_start(struct dcesrv_auth *auth, DATA_BLOB *auth_blob)
{
	struct auth_ntlmssp_state *ntlmssp = NULL;
	NTSTATUS status;

	/* TODO: we should parse the auth_blob and remember the client
	   hostname and target domain, then check against the auth3
	   bind packet */
	
	status = auth_ntlmssp_start(&ntlmssp);

	auth->crypto_ctx.private_data = ntlmssp;

	return status;
}

/*
  update crypto state
*/
static NTSTATUS dcesrv_crypto_ntlmssp_update(struct dcesrv_auth *auth, TALLOC_CTX *out_mem_ctx, 
						const DATA_BLOB in, DATA_BLOB *out) 
{
	struct auth_ntlmssp_state *auth_ntlmssp_state = auth->crypto_ctx.private_data;

	return auth_ntlmssp_update(auth_ntlmssp_state, out_mem_ctx, in, out);
}

/*
  get auth_session_info state
*/
static NTSTATUS dcesrv_crypto_ntlmssp_session_info(struct dcesrv_auth *auth, struct auth_session_info **session_info) 
{
	struct auth_ntlmssp_state *auth_ntlmssp_state = auth->crypto_ctx.private_data;

	return auth_ntlmssp_get_session_info(auth_ntlmssp_state, session_info);
}

/*
  seal a packet
*/
static NTSTATUS dcesrv_crypto_ntlmssp_seal(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
						uint8_t *data, size_t length, DATA_BLOB *sig)
{
	struct auth_ntlmssp_state *auth_ntlmssp_state = auth->crypto_ctx.private_data;

	return ntlmssp_seal_packet(auth_ntlmssp_state->ntlmssp_state, sig_mem_ctx, data, length, sig);
}

/*
  sign a packet
*/
static NTSTATUS dcesrv_crypto_ntlmssp_sign(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
						const uint8_t *data, size_t length, DATA_BLOB *sig) 
{
	struct auth_ntlmssp_state *auth_ntlmssp_state = auth->crypto_ctx.private_data;

	return ntlmssp_sign_packet(auth_ntlmssp_state->ntlmssp_state, sig_mem_ctx, data, length, sig);
}

/*
  check a packet signature
*/
static NTSTATUS dcesrv_crypto_ntlmssp_check_sig(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
						const uint8_t *data, size_t length, const DATA_BLOB *sig)
{
	struct auth_ntlmssp_state *auth_ntlmssp_state = auth->crypto_ctx.private_data;

	return ntlmssp_check_packet(auth_ntlmssp_state->ntlmssp_state, sig_mem_ctx, data, length, sig);
}

/*
  unseal a packet
*/
static NTSTATUS dcesrv_crypto_ntlmssp_unseal(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
						uint8_t *data, size_t length, DATA_BLOB *sig)
{
	struct auth_ntlmssp_state *auth_ntlmssp_state = auth->crypto_ctx.private_data;

	return ntlmssp_unseal_packet(auth_ntlmssp_state->ntlmssp_state, sig_mem_ctx, data, length, sig);
}

/*
  end crypto state
*/
static void dcesrv_crypto_ntlmssp_end(struct dcesrv_auth *auth)
{
	struct auth_ntlmssp_state *auth_ntlmssp_state = auth->crypto_ctx.private_data;

	auth->crypto_ctx.private_data = NULL;

	auth_ntlmssp_end(&auth_ntlmssp_state);

	return;
}

static const struct dcesrv_crypto_ops dcesrv_crypto_ntlmssp_ops = {
	.name		= "ntlmssp",
	.auth_type	= DCERPC_AUTH_TYPE_NTLMSSP,
	.start 		= dcesrv_crypto_ntlmssp_start,
	.update 	= dcesrv_crypto_ntlmssp_update,
	.session_info 	= dcesrv_crypto_ntlmssp_session_info,
	.seal 		= dcesrv_crypto_ntlmssp_seal,
	.sign		= dcesrv_crypto_ntlmssp_sign,
	.check_sig	= dcesrv_crypto_ntlmssp_check_sig,
	.unseal		= dcesrv_crypto_ntlmssp_unseal,
	.end		= dcesrv_crypto_ntlmssp_end
};

/*
  startup the cryptographic side of an authenticated dcerpc server
*/
const struct dcesrv_crypto_ops *dcesrv_crypto_ntlmssp_get_ops(void)
{
	return &dcesrv_crypto_ntlmssp_ops;
}
