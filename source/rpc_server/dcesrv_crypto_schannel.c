/* 
   Unix SMB/CIFS implementation.

   server side dcerpc authentication code - schannel auth/crypto code

   Copyright (C) Andrew Tridgell 2004

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

struct srv_schannel_state {
	TALLOC_CTX *mem_ctx;
	struct schannel_bind bind_info;
	struct schannel_state *state;
};

/*
  start crypto state
*/
static NTSTATUS dcesrv_crypto_schannel_start(struct dcesrv_auth *auth, DATA_BLOB *auth_blob)
{
	struct srv_schannel_state *schannel = NULL;
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	uint8_t session_key[16];
	const char *account_name;
	struct schannel_bind_ack ack;

	mem_ctx = talloc_init("schannel_start");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	schannel = talloc_p(mem_ctx, struct srv_schannel_state);
	if (!schannel) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	schannel->mem_ctx = mem_ctx;

	/* parse the schannel startup blob */
	status = ndr_pull_struct_blob(auth_blob, mem_ctx, &schannel->bind_info, 
				      (ndr_pull_flags_fn_t)ndr_pull_schannel_bind);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (schannel->bind_info.bind_type == 23) {
		account_name = schannel->bind_info.u.info23.account_name;
	} else {
		account_name = schannel->bind_info.u.info3.account_name;
	}

	/* pull the session key for this client */
	status = schannel_fetch_session_key(mem_ctx, account_name, session_key);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_INVALID_HANDLE;
	}
	
	/* start up the schannel server code */
	status = schannel_start(&schannel->state, session_key, False);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_INVALID_HANDLE;
	}

	auth->crypto_ctx.private_data = schannel;

	ack.unknown1 = 1;
	ack.unknown2 = 0;
	ack.unknown3 = 0x6c0000;

	status = ndr_push_struct_blob(auth_blob, mem_ctx, &ack, 
				      (ndr_push_flags_fn_t)ndr_push_schannel_bind_ack);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_destroy(mem_ctx);
		return NT_STATUS_INVALID_PARAMETER;
	}

	return status;
}

/*
  update crypto state
*/
static NTSTATUS dcesrv_crypto_schannel_update(struct dcesrv_auth *auth, TALLOC_CTX *out_mem_ctx, 
						const DATA_BLOB in, DATA_BLOB *out) 
{
	return NT_STATUS_OK;
}

/*
  get auth_session_info state
*/
static NTSTATUS dcesrv_crypto_schannel_session_info(struct dcesrv_auth *auth, struct auth_session_info **session_info) 
{
	struct srv_schannel_state *srv_schannel_state = auth->crypto_ctx.private_data;

	return NT_STATUS_NOT_IMPLEMENTED;
}

/*
  seal a packet
*/
static NTSTATUS dcesrv_crypto_schannel_seal(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
						uint8_t *data, size_t length, DATA_BLOB *sig)
{
	struct srv_schannel_state *srv_schannel_state = auth->crypto_ctx.private_data;

	return schannel_seal_packet(srv_schannel_state->state, sig_mem_ctx, data, length, sig);
}

/*
  sign a packet
*/
static NTSTATUS dcesrv_crypto_schannel_sign(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
					    const uint8_t *data, size_t length, DATA_BLOB *sig) 
{
	struct srv_schannel_state *srv_schannel_state = auth->crypto_ctx.private_data;

	return schannel_sign_packet(srv_schannel_state->state, sig_mem_ctx, data, length, sig);
}

/*
  check a packet signature
*/
static NTSTATUS dcesrv_crypto_schannel_check_sig(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
						const uint8_t *data, size_t length, const DATA_BLOB *sig)
{
	struct srv_schannel_state *srv_schannel_state = auth->crypto_ctx.private_data;

	return schannel_check_packet(srv_schannel_state->state, data, length, sig);
}

/*
  unseal a packet
*/
static NTSTATUS dcesrv_crypto_schannel_unseal(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
						uint8_t *data, size_t length, DATA_BLOB *sig)
{
	struct srv_schannel_state *srv_schannel_state = auth->crypto_ctx.private_data;

	return schannel_unseal_packet(srv_schannel_state->state, sig_mem_ctx, data, length, sig);
}

/*
  end crypto state
*/
static void dcesrv_crypto_schannel_end(struct dcesrv_auth *auth)
{
	struct srv_schannel_state *srv_schannel_state = auth->crypto_ctx.private_data;

	if (srv_schannel_state == NULL) {
		return;
	}

	schannel_end(&srv_schannel_state->state);

	talloc_destroy(srv_schannel_state->mem_ctx);

	auth->crypto_ctx.private_data = NULL;
}

static const struct dcesrv_crypto_ops dcesrv_crypto_schannel_ops = {
	.name		= "schannel",
	.auth_type	= DCERPC_AUTH_TYPE_SCHANNEL,
	.start 		= dcesrv_crypto_schannel_start,
	.update 	= dcesrv_crypto_schannel_update,
	.session_info 	= dcesrv_crypto_schannel_session_info,
	.seal 		= dcesrv_crypto_schannel_seal,
	.sign		= dcesrv_crypto_schannel_sign,
	.check_sig	= dcesrv_crypto_schannel_check_sig,
	.unseal		= dcesrv_crypto_schannel_unseal,
	.end		= dcesrv_crypto_schannel_end
};

/*
  startup the cryptographic side of an authenticated dcerpc server
*/
const struct dcesrv_crypto_ops *dcesrv_crypto_schannel_get_ops(void)
{
	return &dcesrv_crypto_schannel_ops;
}
