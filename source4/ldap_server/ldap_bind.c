/* 
   Unix SMB/CIFS implementation.
   LDAP server
   Copyright (C) Stefan Metzmacher 2004
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "includes.h"
#include "ldap_server/ldap_server.h"
#include "auth/auth.h"
#include "smbd/service.h"
#include <ldb.h>
#include <ldb_errors.h>
#include "../lib/util/dlinklist.h"
#include "dsdb/samdb/samdb.h"
#include "auth/gensec/gensec.h"
#include "auth/gensec/gensec_tstream.h"
#include "param/param.h"
#include "../lib/util/tevent_ntstatus.h"
#include "lib/util/time_basic.h"

static char *ldapsrv_bind_error_msg(TALLOC_CTX *mem_ctx,
				    HRESULT hresult,
				    uint32_t DSID,
				    NTSTATUS status)
{
	WERROR werr;
	char *msg = NULL;

	status = nt_status_squash(status);
	werr = ntstatus_to_werror(status);

	/*
	 * There are 4 lower case hex digits following 'v' at the end,
	 * but different Windows Versions return different values:
	 *
	 * Windows 2008R2 uses 'v1db1'
	 * Windows 2012R2 uses 'v2580'
	 *
	 * We just match Windows 2008R2 as that's what was referenced
	 * in https://bugzilla.samba.org/show_bug.cgi?id=9048
	 */
	msg = talloc_asprintf(mem_ctx, "%08X: LdapErr: DSID-%08X, comment: "
			      "AcceptSecurityContext error, data %x, v1db1",
			      (unsigned)HRES_ERROR_V(hresult),
			      (unsigned)DSID,
			      (unsigned)W_ERROR_V(werr));

	return msg;
}

struct ldapsrv_bind_wait_context {
	struct ldapsrv_reply *reply;
	struct tevent_req *req;
	NTSTATUS status;
	bool done;
};

struct ldapsrv_bind_wait_state {
	uint8_t dummy;
};

static struct tevent_req *ldapsrv_bind_wait_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 void *private_data)
{
	struct ldapsrv_bind_wait_context *bind_wait =
		talloc_get_type_abort(private_data,
		struct ldapsrv_bind_wait_context);
	struct tevent_req *req;
	struct ldapsrv_bind_wait_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ldapsrv_bind_wait_state);
	if (req == NULL) {
		return NULL;
	}
	bind_wait->req = req;

	tevent_req_defer_callback(req, ev);

	if (!bind_wait->done) {
		return req;
	}

	if (tevent_req_nterror(req, bind_wait->status)) {
		return tevent_req_post(req, ev);
	}

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS ldapsrv_bind_wait_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS ldapsrv_bind_wait_setup(struct ldapsrv_call *call,
					struct ldapsrv_reply *reply)
{
	struct ldapsrv_bind_wait_context *bind_wait = NULL;

	if (call->wait_private != NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	bind_wait = talloc_zero(call, struct ldapsrv_bind_wait_context);
	if (bind_wait == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	bind_wait->reply = reply;

	call->wait_private = bind_wait;
	call->wait_send = ldapsrv_bind_wait_send;
	call->wait_recv = ldapsrv_bind_wait_recv;
	return NT_STATUS_OK;
}

static void ldapsrv_bind_wait_finished(struct ldapsrv_call *call,
				       NTSTATUS status)
{
	struct ldapsrv_bind_wait_context *bind_wait =
		talloc_get_type_abort(call->wait_private,
		struct ldapsrv_bind_wait_context);

	bind_wait->done = true;
	bind_wait->status = status;

	if (bind_wait->req == NULL) {
		return;
	}

	if (tevent_req_nterror(bind_wait->req, status)) {
		return;
	}

	tevent_req_done(bind_wait->req);
}

static void ldapsrv_BindSimple_done(struct tevent_req *subreq);

static NTSTATUS ldapsrv_BindSimple(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request->r.BindRequest;
	struct ldapsrv_reply *reply = NULL;
	struct ldap_BindResponse *resp = NULL;
	int result;
	const char *errstr = NULL;
	NTSTATUS status;
	bool using_tls = call->conn->sockets.active == call->conn->sockets.tls;
	struct tevent_req *subreq = NULL;

	DEBUG(10, ("BindSimple dn: %s\n",req->dn));

	reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}

	if (req->dn != NULL &&
	    strlen(req->dn) != 0 &&
	    call->conn->require_strong_auth > LDAP_SERVER_REQUIRE_STRONG_AUTH_NO &&
	    !using_tls)
	{
		status = NT_STATUS_NETWORK_ACCESS_DENIED;
		result = LDAP_STRONG_AUTH_REQUIRED;
		errstr = talloc_asprintf(reply,
					 "BindSimple: Transport encryption required.");
		goto do_reply;
	}

	subreq = authenticate_ldap_simple_bind_send(call,
					call->conn->connection->event.ctx,
					call->conn->connection->msg_ctx,
					call->conn->lp_ctx,
					call->conn->connection->remote_address,
					call->conn->connection->local_address,
					using_tls,
					req->dn,
					req->creds.password);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, ldapsrv_BindSimple_done, call);

	status = ldapsrv_bind_wait_setup(call, reply);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(subreq);
		return status;
	}

	/*
	 * The rest will be async.
	 */
	return NT_STATUS_OK;

do_reply:
	resp = &reply->msg->r.BindResponse;
	resp->response.resultcode = result;
	resp->response.errormessage = errstr;
	resp->response.dn = NULL;
	resp->response.referral = NULL;
	resp->SASL.secblob = NULL;

	ldapsrv_queue_reply(call, reply);
	return NT_STATUS_OK;
}

static void ldapsrv_BindSimple_done(struct tevent_req *subreq)
{
	struct ldapsrv_call *call =
		tevent_req_callback_data(subreq,
		struct ldapsrv_call);
	struct ldapsrv_bind_wait_context *bind_wait =
		talloc_get_type_abort(call->wait_private,
		struct ldapsrv_bind_wait_context);
	struct ldapsrv_reply *reply = bind_wait->reply;
	struct auth_session_info *session_info = NULL;
	NTSTATUS status;
	struct ldap_BindResponse *resp = NULL;
	int result;
	const char *errstr = NULL;

	status = authenticate_ldap_simple_bind_recv(subreq,
						    call,
						    &session_info);
	if (NT_STATUS_IS_OK(status)) {
		char *ldb_errstring = NULL;
		result = LDAP_SUCCESS;
		errstr = NULL;

		talloc_unlink(call->conn, call->conn->session_info);
		call->conn->session_info = talloc_steal(call->conn, session_info);

		call->conn->authz_logged = true;

		/* don't leak the old LDB */
		talloc_unlink(call->conn, call->conn->ldb);

		result = ldapsrv_backend_Init(call->conn, &ldb_errstring);

		if (result != LDB_SUCCESS) {
			/* Only put the detailed error in DEBUG() */
			DBG_ERR("ldapsrv_backend_Init failed: %s: %s",
				ldb_errstring, ldb_strerror(result));
			errstr = talloc_strdup(reply,
					       "Simple Bind: Failed to advise "
					       "ldb new credentials");
			result = LDB_ERR_OPERATIONS_ERROR;
		}
	} else {
		status = nt_status_squash(status);

		result = LDAP_INVALID_CREDENTIALS;
		errstr = ldapsrv_bind_error_msg(reply, HRES_SEC_E_INVALID_TOKEN,
						0x0C0903A9, status);
	}

	resp = &reply->msg->r.BindResponse;
	resp->response.resultcode = result;
	resp->response.errormessage = errstr;
	resp->response.dn = NULL;
	resp->response.referral = NULL;
	resp->SASL.secblob = NULL;

	ldapsrv_queue_reply(call, reply);
	ldapsrv_bind_wait_finished(call, NT_STATUS_OK);
}

struct ldapsrv_sasl_postprocess_context {
	struct ldapsrv_connection *conn;
	struct tstream_context *sasl;
};

struct ldapsrv_sasl_postprocess_state {
	uint8_t dummy;
};

static struct tevent_req *ldapsrv_sasl_postprocess_send(TALLOC_CTX *mem_ctx,
						struct tevent_context *ev,
						void *private_data)
{
	struct ldapsrv_sasl_postprocess_context *context =
		talloc_get_type_abort(private_data,
		struct ldapsrv_sasl_postprocess_context);
	struct tevent_req *req;
	struct ldapsrv_sasl_postprocess_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ldapsrv_sasl_postprocess_state);
	if (req == NULL) {
		return NULL;
	}

	TALLOC_FREE(context->conn->sockets.sasl);
	context->conn->sockets.sasl = talloc_move(context->conn, &context->sasl);
	context->conn->sockets.active = context->conn->sockets.sasl;

	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static NTSTATUS ldapsrv_sasl_postprocess_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS ldapsrv_setup_gensec(struct ldapsrv_connection *conn,
				     const char *sasl_mech,
				     struct gensec_security **_gensec_security)
{
	NTSTATUS status;

	struct gensec_security *gensec_security;

	status = samba_server_gensec_start(conn,
					   conn->connection->event.ctx,
					   conn->connection->msg_ctx,
					   conn->lp_ctx,
					   conn->server_credentials,
					   "ldap",
					   &gensec_security);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = gensec_set_target_service_description(gensec_security,
						       "LDAP");
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = gensec_set_remote_address(gensec_security,
					   conn->connection->remote_address);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	status = gensec_set_local_address(gensec_security,
					  conn->connection->local_address);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	gensec_want_feature(gensec_security, GENSEC_FEATURE_ASYNC_REPLIES);
	gensec_want_feature(gensec_security, GENSEC_FEATURE_LDAP_STYLE);

	if (conn->sockets.active == conn->sockets.tls) {
		gensec_want_feature(gensec_security, GENSEC_FEATURE_LDAPS_TRANSPORT);
	}

	status = gensec_start_mech_by_sasl_name(gensec_security, sasl_mech);

	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}

	*_gensec_security = gensec_security;
	return status;
}

static void ldapsrv_BindSASL_done(struct tevent_req *subreq);

static NTSTATUS ldapsrv_BindSASL(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request->r.BindRequest;
	struct ldapsrv_reply *reply;
	struct ldap_BindResponse *resp;
	struct ldapsrv_connection *conn;
	int result = 0;
	const char *errstr=NULL;
	NTSTATUS status = NT_STATUS_OK;
	DATA_BLOB input = data_blob_null;
	struct tevent_req *subreq = NULL;

	DEBUG(10, ("BindSASL dn: %s\n",req->dn));

	reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
	if (!reply) {
		return NT_STATUS_NO_MEMORY;
	}
	resp = &reply->msg->r.BindResponse;
	/* Windows 2000 mmc doesn't like secblob == NULL and reports a decoding error */
	resp->SASL.secblob = talloc_zero(reply, DATA_BLOB);
	if (resp->SASL.secblob == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	conn = call->conn;

	/* 
	 * TODO: a SASL bind with a different mechanism
	 *       should cancel an inprogress SASL bind.
	 *       (see RFC 4513)
	 */

	if (!conn->gensec) {
		status = ldapsrv_setup_gensec(conn, req->creds.SASL.mechanism,
					      &conn->gensec);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(1, ("Failed to start GENSEC server for [%s] code: %s\n",
				  ldb_binary_encode_string(call, req->creds.SASL.mechanism),
				  nt_errstr(status)));
			result = LDAP_OPERATIONS_ERROR;
			errstr = talloc_asprintf(reply, "SASL: Failed to start authentication system: %s", 
						 nt_errstr(status));
			goto do_reply;
		}
	}

	if (req->creds.SASL.secblob) {
		input = *req->creds.SASL.secblob;
	}

	subreq = gensec_update_send(call, conn->connection->event.ctx,
				    conn->gensec, input);
	if (subreq == NULL) {
		return NT_STATUS_NO_MEMORY;
	}
	tevent_req_set_callback(subreq, ldapsrv_BindSASL_done, call);

	status = ldapsrv_bind_wait_setup(call, reply);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(subreq);
		return status;
	}

	/*
	 * The rest will be async.
	 */
	return NT_STATUS_OK;

do_reply:
	if (result != LDAP_SASL_BIND_IN_PROGRESS) {
		/*
		 * We should destroy the gensec context
		 * when we hit a fatal error.
		 *
		 * Note: conn->gensec is already cleared
		 * for the LDAP_SUCCESS case.
		 */
		talloc_unlink(conn, conn->gensec);
		conn->gensec = NULL;
	}

	resp->response.resultcode = result;
	resp->response.dn = NULL;
	resp->response.errormessage = errstr;
	resp->response.referral = NULL;

	ldapsrv_queue_reply(call, reply);
	return NT_STATUS_OK;
}

static void ldapsrv_BindSASL_done(struct tevent_req *subreq)
{
	struct ldapsrv_call *call =
		tevent_req_callback_data(subreq,
		struct ldapsrv_call);
	struct ldapsrv_bind_wait_context *bind_wait =
		talloc_get_type_abort(call->wait_private,
		struct ldapsrv_bind_wait_context);
	struct ldap_BindRequest *req = &call->request->r.BindRequest;
	struct ldapsrv_reply *reply = bind_wait->reply;
	struct ldap_BindResponse *resp = &reply->msg->r.BindResponse;
	struct ldapsrv_connection *conn = call->conn;
	struct auth_session_info *session_info = NULL;
	struct ldapsrv_sasl_postprocess_context *context = NULL;
	NTSTATUS status;
	int result;
	const char *errstr = NULL;
	char *ldb_errstring = NULL;
	DATA_BLOB output = data_blob_null;
	NTTIME expire_time_nt;

	status = gensec_update_recv(subreq, call, &output);
	TALLOC_FREE(subreq);

	if (NT_STATUS_EQUAL(NT_STATUS_MORE_PROCESSING_REQUIRED, status)) {
		*resp->SASL.secblob = output;
		result = LDAP_SASL_BIND_IN_PROGRESS;
		errstr = NULL;
		goto do_reply;
	}

	if (!NT_STATUS_IS_OK(status)) {
		status = nt_status_squash(status);
		result = LDAP_INVALID_CREDENTIALS;
		errstr = ldapsrv_bind_error_msg(reply, HRES_SEC_E_LOGON_DENIED,
						0x0C0904DC, status);
		goto do_reply;
	}

	if (gensec_have_feature(conn->gensec, GENSEC_FEATURE_SIGN) ||
	    gensec_have_feature(conn->gensec, GENSEC_FEATURE_SEAL)) {

		context = talloc_zero(call, struct ldapsrv_sasl_postprocess_context);
		if (context == NULL) {
			ldapsrv_bind_wait_finished(call, NT_STATUS_NO_MEMORY);
			return;
		}
	}

	if (context && conn->sockets.tls) {
		TALLOC_FREE(context);
		status = NT_STATUS_NOT_SUPPORTED;
		result = LDAP_UNWILLING_TO_PERFORM;
		errstr = talloc_asprintf(reply,
					 "SASL:[%s]: Sign or Seal are not allowed if TLS is used",
					 req->creds.SASL.mechanism);
		goto do_reply;
	}

	if (context && conn->sockets.sasl) {
		TALLOC_FREE(context);
		status = NT_STATUS_NOT_SUPPORTED;
		result = LDAP_UNWILLING_TO_PERFORM;
		errstr = talloc_asprintf(reply,
					 "SASL:[%s]: Sign or Seal are not allowed if SASL encryption has already been set up",
					 req->creds.SASL.mechanism);
		goto do_reply;
	}

	if (context == NULL) {
		switch (call->conn->require_strong_auth) {
		case LDAP_SERVER_REQUIRE_STRONG_AUTH_NO:
			break;
		case LDAP_SERVER_REQUIRE_STRONG_AUTH_ALLOW_SASL_OVER_TLS:
			if (call->conn->sockets.active == call->conn->sockets.tls) {
				break;
			}
			status = NT_STATUS_NETWORK_ACCESS_DENIED;
			result = LDAP_STRONG_AUTH_REQUIRED;
			errstr = talloc_asprintf(reply,
					"SASL:[%s]: not allowed if TLS is used.",
					 req->creds.SASL.mechanism);
			goto do_reply;

		case LDAP_SERVER_REQUIRE_STRONG_AUTH_YES:
			status = NT_STATUS_NETWORK_ACCESS_DENIED;
			result = LDAP_STRONG_AUTH_REQUIRED;
			errstr = talloc_asprintf(reply,
					 "SASL:[%s]: Sign or Seal are required.",
					 req->creds.SASL.mechanism);
			goto do_reply;
		}
	}

	if (context != NULL) {
		context->conn = conn;
		status = gensec_create_tstream(context,
					       context->conn->gensec,
					       context->conn->sockets.raw,
					       &context->sasl);
		if (!NT_STATUS_IS_OK(status)) {
			result = LDAP_OPERATIONS_ERROR;
			errstr = talloc_asprintf(reply,
					 "SASL:[%s]: Failed to setup SASL socket: %s",
					 req->creds.SASL.mechanism, nt_errstr(status));
			goto do_reply;
		}
	}

	status = gensec_session_info(conn->gensec, call, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		result = LDAP_OPERATIONS_ERROR;
		errstr = talloc_asprintf(reply,
					 "SASL:[%s]: Failed to get session info: %s",
					 req->creds.SASL.mechanism, nt_errstr(status));
		goto do_reply;
	}

	talloc_unlink(conn, conn->session_info);
	conn->session_info = talloc_steal(conn, session_info);

	/* don't leak the old LDB */
	talloc_unlink(conn, conn->ldb);

	call->conn->authz_logged = true;

	result = ldapsrv_backend_Init(call->conn, &ldb_errstring);

	if (result != LDB_SUCCESS) {
		/* Only put the detailed error in DEBUG() */
		DBG_ERR("ldapsrv_backend_Init failed: %s: %s",
			ldb_errstring, ldb_strerror(result));
		errstr = talloc_strdup(reply,
				       "SASL Bind: Failed to advise "
				       "ldb new credentials");
		result = LDB_ERR_OPERATIONS_ERROR;
		goto do_reply;
	}

	expire_time_nt = gensec_expire_time(conn->gensec);
	if (expire_time_nt != GENSEC_EXPIRE_TIME_INFINITY) {
		struct timeval_buf buf;

		nttime_to_timeval(&conn->limits.expire_time, expire_time_nt);

		DBG_DEBUG("Setting connection expire_time to %s\n",
			  timeval_str_buf(&conn->limits.expire_time,
					  false,
					  true,
					  &buf));
	}

	if (context != NULL) {
		const void *ptr = NULL;

		ptr = talloc_reparent(conn, context->sasl, conn->gensec);
		if (ptr == NULL) {
			ldapsrv_bind_wait_finished(call, NT_STATUS_NO_MEMORY);
			return;
		}

		call->postprocess_send = ldapsrv_sasl_postprocess_send;
		call->postprocess_recv = ldapsrv_sasl_postprocess_recv;
		call->postprocess_private = context;
	} else {
		talloc_unlink(conn, conn->gensec);
	}
	conn->gensec = NULL;

	*resp->SASL.secblob = output;
	result = LDAP_SUCCESS;
	errstr = NULL;

do_reply:
	if (result != LDAP_SASL_BIND_IN_PROGRESS) {
		/*
		 * We should destroy the gensec context
		 * when we hit a fatal error.
		 *
		 * Note: conn->gensec is already cleared
		 * for the LDAP_SUCCESS case.
		 */
		talloc_unlink(conn, conn->gensec);
		conn->gensec = NULL;
	}

	resp->response.resultcode = result;
	resp->response.dn = NULL;
	resp->response.errormessage = errstr;
	resp->response.referral = NULL;

	ldapsrv_queue_reply(call, reply);
	ldapsrv_bind_wait_finished(call, NT_STATUS_OK);
}

NTSTATUS ldapsrv_BindRequest(struct ldapsrv_call *call)
{
	struct ldap_BindRequest *req = &call->request->r.BindRequest;
	struct ldapsrv_reply *reply;
	struct ldap_BindResponse *resp;

	if (call->conn->pending_calls != NULL) {
		reply = ldapsrv_init_reply(call, LDAP_TAG_BindResponse);
		if (!reply) {
			return NT_STATUS_NO_MEMORY;
		}

		resp = &reply->msg->r.BindResponse;
		resp->response.resultcode = LDAP_BUSY;
		resp->response.dn = NULL;
		resp->response.errormessage = talloc_asprintf(reply, "Pending requests on this LDAP session");
		resp->response.referral = NULL;
		resp->SASL.secblob = NULL;

		ldapsrv_queue_reply(call, reply);
		return NT_STATUS_OK;
	}

	/* 
	 * TODO: a simple bind should cancel an
	 *       inprogress SASL bind.
	 *       (see RFC 4513)
	 */
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
	resp->response.resultcode = LDAP_AUTH_METHOD_NOT_SUPPORTED;
	resp->response.dn = NULL;
	resp->response.errormessage = talloc_asprintf(reply, "Bad AuthenticationChoice [%d]", req->mechanism);
	resp->response.referral = NULL;
	resp->SASL.secblob = NULL;

	ldapsrv_queue_reply(call, reply);
	return NT_STATUS_OK;
}

struct ldapsrv_unbind_wait_context {
	uint8_t dummy;
};

struct ldapsrv_unbind_wait_state {
	uint8_t dummy;
};

static struct tevent_req *ldapsrv_unbind_wait_send(TALLOC_CTX *mem_ctx,
						 struct tevent_context *ev,
						 void *private_data)
{
	struct ldapsrv_unbind_wait_context *unbind_wait =
		talloc_get_type_abort(private_data,
		struct ldapsrv_unbind_wait_context);
	struct tevent_req *req;
	struct ldapsrv_unbind_wait_state *state;

	req = tevent_req_create(mem_ctx, &state,
				struct ldapsrv_unbind_wait_state);
	if (req == NULL) {
		return NULL;
	}

	(void)unbind_wait;

	tevent_req_nterror(req, NT_STATUS_LOCAL_DISCONNECT);
	return tevent_req_post(req, ev);
}

static NTSTATUS ldapsrv_unbind_wait_recv(struct tevent_req *req)
{
	return tevent_req_simple_recv_ntstatus(req);
}

static NTSTATUS ldapsrv_unbind_wait_setup(struct ldapsrv_call *call)
{
	struct ldapsrv_unbind_wait_context *unbind_wait = NULL;

	if (call->wait_private != NULL) {
		return NT_STATUS_INTERNAL_ERROR;
	}

	unbind_wait = talloc_zero(call, struct ldapsrv_unbind_wait_context);
	if (unbind_wait == NULL) {
		return NT_STATUS_NO_MEMORY;
	}

	call->wait_private = unbind_wait;
	call->wait_send = ldapsrv_unbind_wait_send;
	call->wait_recv = ldapsrv_unbind_wait_recv;
	return NT_STATUS_OK;
}

NTSTATUS ldapsrv_UnbindRequest(struct ldapsrv_call *call)
{
	struct ldapsrv_call *c = NULL;
	struct ldapsrv_call *n = NULL;

	DEBUG(10, ("UnbindRequest\n"));

	for (c = call->conn->pending_calls; c != NULL; c = n) {
		n = c->next;

		DLIST_REMOVE(call->conn->pending_calls, c);
		TALLOC_FREE(c);
	}

	return ldapsrv_unbind_wait_setup(call);
}
