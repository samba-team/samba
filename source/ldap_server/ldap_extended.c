/* 
   Unix SMB/CIFS implementation.
   LDAP server
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
#include "ldap_server/ldap_server.h"
#include "dlinklist.h"
#include "libcli/ldap/ldap.h"
#include "lib/tls/tls.h"
#include "smbd/service_stream.h"

struct ldapsrv_starttls_context {
	struct ldapsrv_connection *conn;
	struct socket_context *tls_socket;
};

static void ldapsrv_start_tls(void *private) 
{
	struct ldapsrv_starttls_context *ctx = talloc_get_type(private, struct ldapsrv_starttls_context);
	talloc_steal(ctx->conn->connection, ctx->tls_socket);
	talloc_unlink(ctx->conn->connection, ctx->conn->connection->socket);

	ctx->conn->sockets.tls = ctx->tls_socket;
	ctx->conn->connection->socket = ctx->tls_socket;
	packet_set_socket(ctx->conn->packet, ctx->conn->connection->socket);
}

NTSTATUS ldapsrv_ExtendedRequest(struct ldapsrv_call *call)
{
	struct ldap_ExtendedRequest *req = &call->request->r.ExtendedRequest;
	struct ldapsrv_reply *reply;

	DEBUG(10, ("Extended\n"));

	reply = ldapsrv_init_reply(call, LDAP_TAG_ExtendedResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}

	ZERO_STRUCT(reply->msg->r);

	/* check if we have a START_TLS call */
	if (strcmp(req->oid, LDB_EXTENDED_START_TLS_OID) == 0) {
		struct ldapsrv_starttls_context *ctx;
		int result = 0;
		const char *errstr;
		ctx = talloc(call, struct ldapsrv_starttls_context); 

		if (ctx) {
			ctx->conn = call->conn;
			ctx->tls_socket = tls_init_server(call->conn->service->tls_params,
						 call->conn->connection->socket,
						 call->conn->connection->event.fde, 
						 NULL);
		} 

		if (!ctx || !ctx->tls_socket) {
			result = LDAP_OPERATIONS_ERROR;
			errstr = talloc_asprintf(reply, 
						 "START-TLS: Failed to setup TLS socket");
		} else {
			result = LDAP_SUCCESS;
			errstr = NULL;
			call->send_callback = ldapsrv_start_tls;
			call->send_private  = ctx;
		}

		reply->msg->r.ExtendedResponse.response.resultcode = result;
		reply->msg->r.ExtendedResponse.response.errormessage = errstr;
		reply->msg->r.ExtendedResponse.oid = talloc_strdup(reply, req->oid);
		if (!reply->msg->r.ExtendedResponse.oid) {
			return NT_STATUS_NO_MEMORY;
		}
	}

	/* TODO: OID not recognized, return a protocol error */

	ldapsrv_queue_reply(call, reply);
	return NT_STATUS_OK;
}
