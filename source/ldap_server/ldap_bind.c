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


static NTSTATUS ldapsrv_BindSimple(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request.r.BindRequest;
	struct ldapsrv_reply *reply;
	struct ldap_BindResponse *resp;

	DEBUG(10, ("BindSimple dn: %s\n",req->dn));

	reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}

	resp = &reply->msg.r.BindResponse;
	resp->response.resultcode = 0;
	resp->response.dn = NULL;
	resp->response.errormessage = NULL;
	resp->response.referral = NULL;
	resp->SASL.secblob = data_blob(NULL, 0);

	return ldapsrv_queue_reply(call, reply);
}

static NTSTATUS ldapsrv_BindSASL(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request.r.BindRequest;
	struct ldapsrv_reply *reply;
	struct ldap_BindResponse *resp;
	int result;
	const char *errstr;
	NTSTATUS status = NT_STATUS_OK;
	NTSTATUS sasl_status;
	BOOL ret;

	DEBUG(10, ("BindSASL dn: %s\n",req->dn));

	if (!call->conn->gensec) {
		call->conn->session_info = NULL;

		status = gensec_server_start(call->conn, &call->conn->gensec);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC server code: %s\n", nt_errstr(status)));
			return status;
		}

		/*gensec_want_feature(call->conn->gensec, GENSEC_WANT_SIGN|GENSEC_WANT_SEAL);*/

		status = gensec_start_mech_by_sasl_name(call->conn->gensec, req->creds.SASL.mechanism);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC SASL[%s] server code: %s\n", 
				req->creds.SASL.mechanism, nt_errstr(status)));
			goto reply;
		}
	}

reply:
	reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}
	resp = &reply->msg.r.BindResponse;

	if (NT_STATUS_IS_OK(status)) {
		status = gensec_update(call->conn->gensec, reply,
					req->creds.SASL.secblob, &resp->SASL.secblob);
	}

	if (NT_STATUS_EQUAL(NT_STATUS_MORE_PROCESSING_REQUIRED, status)) {
		result = LDAP_SASL_BIND_IN_PROGRESS;
		errstr = NULL;
	} else if (NT_STATUS_IS_OK(status)) {
		result = LDAP_SUCCESS;
		errstr = NULL;
	} else {
		result = 49;
		errstr = talloc_asprintf(reply, "SASL:[%s]: %s", req->creds.SASL.mechanism, nt_errstr(status));
	}

	resp->response.resultcode = result;
	resp->response.dn = NULL;
	resp->response.errormessage = errstr;
	resp->response.referral = NULL;

	sasl_status = status;
	status = ldapsrv_queue_reply(call, reply);
	if (!NT_STATUS_IS_OK(sasl_status) || !NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = ldapsrv_do_responses(call->conn);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	ret = ldapsrv_append_to_buf(&call->conn->sasl_out_buffer, call->conn->out_buffer.data, call->conn->out_buffer.length);
	if (!ret) {
		return NT_STATUS_NO_MEMORY;
	}
	ldapsrv_consumed_from_buf(&call->conn->out_buffer, call->conn->out_buffer.length);

	status = gensec_session_info(call->conn->gensec, &call->conn->session_info);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	//debug_session_info(0, 0, call->conn->session_info);

	return status;
}

NTSTATUS ldapsrv_BindRequest(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request.r.BindRequest;
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

	resp = &reply->msg.r.BindResponse;
	resp->response.resultcode = 7;
	resp->response.dn = NULL;
	resp->response.errormessage = talloc_asprintf(reply, "Bad AuthenticationChoice [%d]", req->mechanism);
	resp->response.referral = NULL;
	resp->SASL.secblob = data_blob(NULL, 0);

	return ldapsrv_queue_reply(call, reply);
}

NTSTATUS ldapsrv_UnbindRequest(struct ldapsrv_call *call)
{
	DEBUG(10, ("UnbindRequest\n"));
	return NT_STATUS_OK;
}
