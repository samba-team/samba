/* 
   Unix SMB/CIFS implementation.

   server side dcerpc authentication code - crypto support

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
  this provides a crypto interface to the various backends (such as
  NTLMSSP and SCHANNEL) for the rpc server code
*/

#include "includes.h"

/*
  startup the cryptographic side of an authenticated dcerpc server
*/
NTSTATUS dcesrv_crypto_select_type(struct dcesrv_connection *dce_conn,
			       struct dcesrv_auth *auth)
{
	if (auth->auth_info->auth_level != DCERPC_AUTH_LEVEL_INTEGRITY &&
	    auth->auth_info->auth_level != DCERPC_AUTH_LEVEL_PRIVACY) {
		DEBUG(2,("auth_level %d not supported in dcesrv auth\n", 
			 auth->auth_info->auth_level));
		return NT_STATUS_INVALID_PARAMETER;
	}

	if (auth->crypto_ctx.ops != NULL) {
		/* TODO:
		 * this this function should not be called
		 * twice per dcesrv_connection!
		 * 
		 * so we need to find out the right
		 * dcerpc error to return
		 */
	}

	/*
	 * TODO:
	 * maybe a dcesrv_crypto_find_backend_by_type() whould be better here
	 * to make thinks more generic
	 */
	auth->crypto_ctx.ops = dcesrv_crypto_backend_bytype(auth->auth_info->auth_type);
	if (auth->crypto_ctx.ops == NULL) {
		DEBUG(2,("dcesrv auth_type %d not supported\n", auth->auth_info->auth_type));
		return NT_STATUS_INVALID_PARAMETER;
	}

	return NT_STATUS_OK;
}

/*
  start crypto state
*/
NTSTATUS dcesrv_crypto_start(struct dcesrv_auth *auth, DATA_BLOB *auth_blob) 
{
	return auth->crypto_ctx.ops->start(auth, auth_blob);
}

/*
  update crypto state
*/
NTSTATUS dcesrv_crypto_update(struct dcesrv_auth *auth, 
			      TALLOC_CTX *out_mem_ctx, 
			      const DATA_BLOB in, DATA_BLOB *out) 
{
	return auth->crypto_ctx.ops->update(auth, out_mem_ctx, in, out);
}

/*
  seal a packet
*/
NTSTATUS dcesrv_crypto_seal(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
				uint8_t *data, size_t length, DATA_BLOB *sig)
{
	return auth->crypto_ctx.ops->seal(auth, sig_mem_ctx, data, length, sig);
}

/*
  sign a packet
*/
NTSTATUS dcesrv_crypto_sign(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
				const uint8_t *data, size_t length, DATA_BLOB *sig) 
{
	return auth->crypto_ctx.ops->sign(auth, sig_mem_ctx, data, length, sig);
}

/*
  check a packet signature
*/
NTSTATUS dcesrv_crypto_check_sig(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
				const uint8_t *data, size_t length, const DATA_BLOB *sig)
{
	return auth->crypto_ctx.ops->check_sig(auth, sig_mem_ctx, data, length, sig);
}

/*
  unseal a packet
*/
NTSTATUS dcesrv_crypto_unseal(struct dcesrv_auth *auth, TALLOC_CTX *sig_mem_ctx,
				uint8_t *data, size_t length, DATA_BLOB *sig)
{
	return auth->crypto_ctx.ops->unseal(auth, sig_mem_ctx, data, length, sig);
}

/*
  end crypto state
*/
void dcesrv_crypto_end(struct dcesrv_auth *auth) 
{
	auth->crypto_ctx.ops->end(auth);
}

const struct dcesrv_crypto_ops *dcesrv_crypto_backend_bytype(uint8_t auth_type)
{
	switch (auth_type) {
		case DCERPC_AUTH_TYPE_SCHANNEL:
			return dcesrv_crypto_schannel_get_ops();
		case DCERPC_AUTH_TYPE_NTLMSSP:
			return dcesrv_crypto_ntlmssp_get_ops();
	}

	return NULL;
}
