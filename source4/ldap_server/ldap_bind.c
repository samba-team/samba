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
#include "auth/auth.h"
#include "libcli/ldap/ldap.h"
#include "smbd/service_stream.h"

static NTSTATUS ldapsrv_BindSimple(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request->r.BindRequest;
	struct ldapsrv_reply *reply;
	struct ldap_BindResponse *resp;

	int result;
	const char *errstr;
	const char *nt4_domain, *nt4_account;

	struct auth_session_info *session_info;

	NTSTATUS status;

	DEBUG(10, ("BindSimple dn: %s\n",req->dn));

	status = crack_dn_to_nt4_name(call, req->dn, &nt4_domain, &nt4_account);
	if (NT_STATUS_IS_OK(status)) {
		status = authenticate_username_pw(call, nt4_domain, nt4_account, 
						  req->creds.password, &session_info);
	}

	/* When we add authentication here, we also need to handle telling the backends */

	reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}

	if (NT_STATUS_IS_OK(status)) {
		struct ldapsrv_partition *part;
		result = LDAP_SUCCESS;
		errstr = NULL;

		talloc_free(call->conn->session_info);
		call->conn->session_info = session_info;
		for (part = call->conn->partitions; part; part = part->next) {
			if (!part->ops->Bind) {
				continue;
			}
			status = part->ops->Bind(part, call->conn);
			if (!NT_STATUS_IS_OK(status)) {
				result = LDAP_OPERATIONS_ERROR;
				errstr = talloc_asprintf(reply, "Simple Bind: Failed to advise partition %s of new credentials: %s", part->base_dn, nt_errstr(status));
			}
		}
	} else {
		status = auth_nt_status_squash(status);

		result = LDAP_INVALID_CREDENTIALS;
		errstr = talloc_asprintf(reply, "Simple Bind Failed: %s", nt_errstr(status));
	}

	resp = &reply->msg->r.BindResponse;
	resp->response.resultcode = result;
	resp->response.errormessage = errstr;
	resp->response.dn = NULL;
	resp->response.referral = NULL;

	/* This looks wrong... */
	resp->SASL.secblob = data_blob(NULL, 0);

	ldapsrv_queue_reply(call, reply);
	return NT_STATUS_OK;
}

static NTSTATUS ldapsrv_BindSASL(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request->r.BindRequest;
	struct ldapsrv_reply *reply;
	struct ldap_BindResponse *resp;
	struct ldapsrv_connection *conn;
	int result;
	const char *errstr;
	NTSTATUS status = NT_STATUS_OK;

	DEBUG(10, ("BindSASL dn: %s\n",req->dn));

	if (!call->conn->gensec) {
		struct cli_credentials *server_credentials;
		call->conn->session_info = NULL;

		status = gensec_server_start(call->conn, &call->conn->gensec,
					     call->conn->connection->event.ctx);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC server code: %s\n", nt_errstr(status)));
			return status;
		}
		
		gensec_set_target_service(call->conn->gensec, "ldap");

		server_credentials 
			= cli_credentials_init(call);
		if (!server_credentials) {
			DEBUG(1, ("Failed to init server credentials\n"));
			return NT_STATUS_NO_MEMORY;
		}
		
		cli_credentials_set_conf(server_credentials);
		status = cli_credentials_set_machine_account(server_credentials);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(10, ("Failed to obtain server credentials, perhaps a standalone server?: %s\n", nt_errstr(status)));
			talloc_free(server_credentials);
			server_credentials = NULL;
		}
		
		gensec_set_credentials(call->conn->gensec, server_credentials);

		gensec_want_feature(call->conn->gensec, GENSEC_FEATURE_SIGN);
		gensec_want_feature(call->conn->gensec, GENSEC_FEATURE_SEAL);
		gensec_want_feature(call->conn->gensec, GENSEC_FEATURE_ASYNC_REPLIES);

		status = gensec_start_mech_by_sasl_name(call->conn->gensec, req->creds.SASL.mechanism);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC SASL[%s] server code: %s\n", 
				req->creds.SASL.mechanism, nt_errstr(status)));
		}
	}

	reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}
	resp = &reply->msg->r.BindResponse;
	
	conn = call->conn;

	if (NT_STATUS_IS_OK(status)) {
		status = gensec_update(call->conn->gensec, reply,
				       req->creds.SASL.secblob, &resp->SASL.secblob);
	}

	if (NT_STATUS_EQUAL(NT_STATUS_MORE_PROCESSING_REQUIRED, status)) {
		result = LDAP_SASL_BIND_IN_PROGRESS;
		errstr = NULL;
	} else if (NT_STATUS_IS_OK(status)) {
		struct ldapsrv_partition *part;
		struct auth_session_info *old_session_info;

		result = LDAP_SUCCESS;
		errstr = NULL;
		if (gensec_have_feature(call->conn->gensec, GENSEC_FEATURE_SEAL) ||
		    gensec_have_feature(call->conn->gensec, GENSEC_FEATURE_SIGN)) {
			call->conn->enable_wrap = True;
		}
		old_session_info = call->conn->session_info;
		call->conn->session_info = NULL;
		status = gensec_session_info(call->conn->gensec, &call->conn->session_info);
		if (!NT_STATUS_IS_OK(status)) {
			call->conn->session_info = old_session_info;
			result = LDAP_OPERATIONS_ERROR;
			errstr = talloc_asprintf(reply, "SASL:[%s]: Failed to get session info: %s", req->creds.SASL.mechanism, nt_errstr(status));
		} else {
			talloc_free(old_session_info);
			for (part = call->conn->partitions; part; part = part->next) {
				if (!part->ops->Bind) {
					continue;
				}
				status = part->ops->Bind(part, conn);
				if (!NT_STATUS_IS_OK(status)) {
					result = LDAP_OPERATIONS_ERROR;
					errstr = talloc_asprintf(reply, "SASL:[%s]: Failed to advise partition %s of new credentials: %s", req->creds.SASL.mechanism, part->base_dn, nt_errstr(status));
				}
			}
		}
	} else {
		status = auth_nt_status_squash(status);
		result = LDAP_INVALID_CREDENTIALS;
		errstr = talloc_asprintf(reply, "SASL:[%s]: %s", req->creds.SASL.mechanism, nt_errstr(status));
	}

	resp->response.resultcode = result;
	resp->response.dn = NULL;
	resp->response.errormessage = errstr;
	resp->response.referral = NULL;

	ldapsrv_queue_reply(call, reply);
	return NT_STATUS_OK;
}

NTSTATUS ldapsrv_BindRequest(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request->r.BindRequest;
	struct ldapsrv_reply *reply;
	struct ldap_BindResponse *resp;

	switch (req->mechanism) {
		case LDAP_AUTH_MECH_SIMPLE:
			return ldapsrv_BindSimple(call);
		case LDAP_AUTH_MECH_SASL:
			return ldapsrv_BindSASL(call);
	}

	reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}

	resp = &reply->msg->r.BindResponse;
	resp->response.resultcode = 7;
	resp->response.dn = NULL;
	resp->response.errormessage = talloc_asprintf(reply, "Bad AuthenticationChoice [%d]", req->mechanism);
	resp->response.referral = NULL;
	resp->SASL.secblob = data_blob(NULL, 0);

	ldapsrv_queue_reply(call, reply);
	return NT_STATUS_OK;
}

NTSTATUS ldapsrv_UnbindRequest(struct ldapsrv_call *call)
{
	DEBUG(10, ("UnbindRequest\n"));
	return NT_STATUS_OK;
}
