/* 
   Unix SMB/CIFS implementation.

   server side dcerpc authentication code - crypto support

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

/*
  this provides a crypto interface to the various backends (such as
  NTLMSSP and SCHANNEL) for the rpc server code
*/

#include "includes.h"

/*
  startup the cryptographic side of an authenticated dcerpc server
*/
NTSTATUS dcesrv_crypto_startup(struct dcesrv_connection *dce_conn,
			       struct dcesrv_auth *auth)
{
	struct auth_ntlmssp_state *ntlmssp = NULL;
	NTSTATUS status;

	if (auth->auth_info->auth_level != DCERPC_AUTH_LEVEL_INTEGRITY &&
	    auth->auth_info->auth_level != DCERPC_AUTH_LEVEL_PRIVACY) {
		DEBUG(2,("auth_level %d not supported in dcesrv auth\n", 
			 auth->auth_info->auth_level));
		return NT_STATUS_INVALID_PARAMETER;
	}

	switch (auth->auth_info->auth_type) {
/*
	case DCERPC_AUTH_TYPE_SCHANNEL:
		return auth_schannel_start();
*/

	case DCERPC_AUTH_TYPE_NTLMSSP:
		status = auth_ntlmssp_start(&ntlmssp);
		auth->crypto_state = ntlmssp;
		break;

	default:
		DEBUG(2,("dcesrv auth_type %d not supported\n", auth->auth_info->auth_type));
		status = NT_STATUS_INVALID_PARAMETER;
	}

	DEBUG(4,("dcesrv_crypto_startup: %s\n", nt_errstr(status)));

	return status;
}

/*
  update crypto state
*/
NTSTATUS dcesrv_crypto_update(struct dcesrv_auth *auth, 
			      TALLOC_CTX *out_mem_ctx, 
			      const DATA_BLOB in, DATA_BLOB *out) 
{
	AUTH_NTLMSSP_STATE *ntlmssp = auth->crypto_state;

	return ntlmssp_update(ntlmssp->ntlmssp_state, out_mem_ctx, in, out);
}


/*
  seal a packet
*/
NTSTATUS dcesrv_crypto_seal(struct dcesrv_auth *auth, 
			    TALLOC_CTX *sig_mem_ctx, uint8_t *data, size_t length, DATA_BLOB *sig)
{
	AUTH_NTLMSSP_STATE *ntlmssp = auth->crypto_state;

	return ntlmssp_seal_packet(ntlmssp->ntlmssp_state, sig_mem_ctx, data, length, sig);
}

/*
  sign a packet
*/
NTSTATUS dcesrv_crypto_sign(struct dcesrv_auth *auth, 
			    TALLOC_CTX *sig_mem_ctx, const uint8_t *data, size_t length, DATA_BLOB *sig) 
{
	AUTH_NTLMSSP_STATE *ntlmssp = auth->crypto_state;

	return ntlmssp_sign_packet(ntlmssp->ntlmssp_state, sig_mem_ctx, data, length, sig);
}

/*
  check a packet signature
*/
NTSTATUS dcesrv_crypto_check_sig(struct dcesrv_auth *auth, 
				 TALLOC_CTX *sig_mem_ctx, const uint8_t *data, size_t length, const DATA_BLOB *sig)
{
	AUTH_NTLMSSP_STATE *ntlmssp = auth->crypto_state;

	return ntlmssp_check_packet(ntlmssp->ntlmssp_state, sig_mem_ctx, data, length, sig);
}

/*
  unseal a packet
*/
NTSTATUS dcesrv_crypto_unseal(struct dcesrv_auth *auth, 
			       TALLOC_CTX *sig_mem_ctx, uint8_t *data, size_t length, DATA_BLOB *sig)
{
	AUTH_NTLMSSP_STATE *ntlmssp = auth->crypto_state;

	return ntlmssp_unseal_packet(ntlmssp->ntlmssp_state, sig_mem_ctx, data, length, sig);
}
