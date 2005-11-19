/* 
   Unix SMB/CIFS implementation.

   Generic Authentication Interface

   Copyright (C) Andrew Tridgell 2003
   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2004-2005
   Copyright (C) Stefan Metzmacher 2004
   
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
#include "libcli/composite/composite.h"

/*
  do a non-athenticated dcerpc bind
*/

struct composite_context *dcerpc_bind_auth_none_send(TALLOC_CTX *mem_ctx,
						     struct dcerpc_pipe *p,
						     const char *uuid,
						     uint_t version)
{
	struct dcerpc_syntax_id syntax;
	struct dcerpc_syntax_id transfer_syntax;

	struct composite_context *c;

	c = talloc_zero(mem_ctx, struct composite_context);
	if (c == NULL) return NULL;

	c->status = dcerpc_init_syntaxes(uuid, &syntax, &transfer_syntax,
					 version);
	if (!NT_STATUS_IS_OK(c->status)) {
		DEBUG(2,("Invalid uuid string in "
			 "dcerpc_bind_auth_none_send\n"));
		goto failed;
	}

	/* c was only allocated as a container for a possible error */
	talloc_free(c);

	return dcerpc_bind_send(p, mem_ctx, &syntax, &transfer_syntax);

 failed:
	composite_trigger_error(c);
	return c;
}

NTSTATUS dcerpc_bind_auth_none_recv(struct composite_context *ctx)
{
	return dcerpc_bind_recv(ctx);
}

NTSTATUS dcerpc_bind_auth_none(struct dcerpc_pipe *p,
			       const char *uuid, uint_t version)
{
	struct composite_context *ctx;
	ctx = dcerpc_bind_auth_none_send(p, p, uuid, version);
	return dcerpc_bind_auth_none_recv(ctx);
}

/*
  perform a multi-part authenticated bind
*/
static NTSTATUS dcerpc_bind_auth(struct dcerpc_pipe *p, uint8_t auth_type, uint8_t auth_level,
				 const char *uuid, uint_t version)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(p);
	DATA_BLOB credentials;
	DATA_BLOB null_data_blob = data_blob(NULL, 0);

	int num_passes = 0;

	if (!p->conn->security_state.generic_state) {
		status = gensec_client_start(p, &p->conn->security_state.generic_state,
					     p->conn->event_ctx);
		if (!NT_STATUS_IS_OK(status)) goto done;

		status = gensec_start_mech_by_authtype(p->conn->security_state.generic_state, 
						       auth_type, auth_level);
		if (!NT_STATUS_IS_OK(status)) goto done;
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

	while (1) {
		num_passes++;
		status = gensec_update(p->conn->security_state.generic_state, tmp_ctx,
				       p->conn->security_state.auth_info->credentials,
				       &credentials);

		/* The status value here, from GENSEC is vital to the security
		 * of the system.  Even if the other end accepts, if GENSEC
		 * claims 'MORE_PROCESSING_REQUIRED' then you must keep
		 * feeding it blobs, or else the remote host/attacker might
		 * avoid mutal authentication requirements.
		 *
		 * Likewise, you must not feed GENSEC too much (after the OK),
		 * it doesn't like that either
		 */

		if (!NT_STATUS_IS_OK(status) 
		    && !NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			DEBUG(1, ("Failed DCERPC client gensec_update with mechanism %s: %s\n",
				  gensec_get_name_by_authtype(auth_type), nt_errstr(status)));

			break;
		}

		if (!credentials.length) {
			break;
		}

		p->conn->security_state.auth_info->credentials = credentials;
		
		if (NT_STATUS_EQUAL(status, NT_STATUS_MORE_PROCESSING_REQUIRED)) {
			if (num_passes == 1) {
				status = dcerpc_bind_byuuid(p, tmp_ctx, uuid, version);
			} else {
				/* We are demanding a reply, so use a request that will get us one */
				status = dcerpc_alter_context(p, tmp_ctx, &p->syntax, &p->transfer_syntax);
			}
			if (!NT_STATUS_IS_OK(status)) {
				break;
			}
		} else if (NT_STATUS_IS_OK(status)) {
			/* NO reply expected, so just send it */
			if (num_passes == 1) {
				status = dcerpc_bind_byuuid(p, tmp_ctx, uuid, version);
			} else {
				status = dcerpc_auth3(p->conn, tmp_ctx);
			}
			break;
		} else {
			break;
		}
	};

done:
	talloc_free(tmp_ctx);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(p->conn->security_state.generic_state);
		ZERO_STRUCT(p->conn->security_state);
	} else {
		/* Authenticated connections use the generic session key */
		p->conn->security_state.session_key = dcerpc_generic_session_key;
	}

	return status;
}

/*
  setup GENSEC on a DCE-RPC pipe
*/
NTSTATUS dcerpc_bind_auth_password(struct dcerpc_pipe *p,
				   const char *uuid, uint_t version,
				   struct cli_credentials *credentials,
				   uint8_t auth_type,
				   const char *service)
{
	NTSTATUS status;

	if (!(p->conn->flags & (DCERPC_SIGN | DCERPC_SEAL))) {
		p->conn->flags |= DCERPC_CONNECT;
	}

	status = gensec_client_start(p, &p->conn->security_state.generic_state,
				     p->conn->event_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start GENSEC client mode: %s\n", nt_errstr(status)));
		return status;
	}

	status = gensec_set_credentials(p->conn->security_state.generic_state, 
					credentials);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client credentails: %s\n", 
			  nt_errstr(status)));
		return status;
	}

	status = gensec_set_target_hostname(p->conn->security_state.generic_state, 
					    p->conn->transport.peer_name(p->conn));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC target hostname: %s\n", 
			  nt_errstr(status)));
		return status;
	}

	if (service) {
		status = gensec_set_target_service(p->conn->security_state.generic_state, service);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start set GENSEC target service: %s\n", 
				  nt_errstr(status)));
			return status;
		}
	}

	status = gensec_start_mech_by_authtype(p->conn->security_state.generic_state, 
					       auth_type,
					       dcerpc_auth_level(p->conn));
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(1, ("Failed to start set GENSEC client mechanism %s: %s\n",
			  gensec_get_name_by_authtype(auth_type), nt_errstr(status)));
		return status;
	}
	
	status = dcerpc_bind_auth(p, auth_type,
				  dcerpc_auth_level(p->conn),
				  uuid, version);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2, ("Failed to bind to pipe with %s: %s\n", 
			  gensec_get_name_by_authtype(auth_type), nt_errstr(status)));
		return status;
	}

	return status;
}
