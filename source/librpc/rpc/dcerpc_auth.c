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

/*
  do a non-athenticated dcerpc bind
*/
NTSTATUS dcerpc_bind_auth_none(struct dcerpc_pipe *p,
			       const char *uuid, uint_t version)
{
	TALLOC_CTX *mem_ctx;
	NTSTATUS status;

	mem_ctx = talloc_init("dcerpc_bind_auth_ntlm");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}

	status = dcerpc_bind_byuuid(p, mem_ctx, uuid, version);
	talloc_destroy(mem_ctx);

	return status;
}

NTSTATUS dcerpc_bind_auth3(struct dcerpc_pipe *p, uint8_t auth_type, uint8_t auth_level,
			   const char *uuid, uint_t version)
{
	NTSTATUS status;
	TALLOC_CTX *mem_ctx;
	DATA_BLOB credentials;
	DATA_BLOB null_data_blob = data_blob(NULL, 0);

	mem_ctx = talloc_init("dcerpc_bind_auth");
	if (!mem_ctx) {
		return NT_STATUS_NO_MEMORY;
	}
	
	if (!p->conn->security_state.generic_state) {
		status = gensec_client_start(p, &p->conn->security_state.generic_state);
		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}

		status = gensec_start_mech_by_authtype(p->conn->security_state.generic_state, 
						       auth_type, auth_level);

		if (!NT_STATUS_IS_OK(status)) {
			return status;
		}
	}

	p->conn->security_state.auth_info = talloc(p, struct dcerpc_auth);
	if (!p->conn->security_state.auth_info) {
		status = NT_STATUS_NO_MEMORY;
		goto done;
	}

	p->conn->security_state.auth_info->auth_type = auth_type;
	p->conn->security_state.auth_info->auth_level = auth_level;
	p->conn->security_state.auth_info->auth_pad_length = 0;
	p->conn->security_state.auth_info->auth_reserved = 0;
	p->conn->security_state.auth_info->auth_context_id = random();
	p->conn->security_state.auth_info->credentials = null_data_blob;

	status = gensec_update(p->conn->security_state.generic_state, mem_ctx,
			       null_data_blob,
			       &credentials);
	
	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto done;
	}

	p->conn->security_state.auth_info->credentials = credentials;

	status = dcerpc_bind_byuuid(p, mem_ctx, uuid, version);
	if (!NT_STATUS_IS_OK(status)) {
		goto done;
	}

	status = gensec_update(p->conn->security_state.generic_state, mem_ctx,
			       p->conn->security_state.auth_info->credentials,
			       &credentials);

	if (!NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
		goto done;
	}

	p->conn->security_state.auth_info->credentials = credentials;
	
	status = dcerpc_auth3(p->conn, mem_ctx);
done:
	talloc_destroy(mem_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(p->conn->security_state.generic_state);
		ZERO_STRUCT(p->conn->security_state);
	} else {
		/* Authenticated connections use the generic session key */
		p->conn->security_state.session_key = dcerpc_generic_session_key;
	}

	return status;
}
