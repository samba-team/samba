/* 
   Unix SMB/CIFS implementation.

   LDAP server

   Copyright (C) Andrew Tridgell 2005
   Copyright (C) Volker Lendecke 2004
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
#include "system/network.h"
#include "lib/events/events.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"
#include "librpc/gen_ndr/ndr_samr.h"
#include "../lib/util/dlinklist.h"
#include "../lib/util/asn1.h"
#include "ldap_server/ldap_server.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "smbd/service.h"
#include "smbd/process_model.h"
#include "lib/tls/tls.h"
#include "lib/messaging/irpc.h"
#include <ldb.h>
#include <ldb_errors.h>
#include "libcli/ldap/ldap_proto.h"
#include "system/network.h"
#include "lib/socket/netif.h"
#include "dsdb/samdb/samdb.h"
#include "param/param.h"
#include "../lib/tsocket/tsocket.h"
#include "../lib/util/tevent_ntstatus.h"
#include "../libcli/util/tstream.h"
#include "libds/common/roles.h"
#include "lib/util/time.h"

static void ldapsrv_terminate_connection_done(struct tevent_req *subreq);

/*
  close the socket and shutdown a server_context
*/
static void ldapsrv_terminate_connection(struct ldapsrv_connection *conn,
					 const char *reason)
{
	struct tevent_req *subreq;

	if (conn->limits.reason) {
		return;
	}

	DLIST_REMOVE(conn->service->connections, conn);

	conn->limits.endtime = timeval_current_ofs(0, 500);

	tevent_queue_stop(conn->sockets.send_queue);
	TALLOC_FREE(conn->sockets.read_req);
	TALLOC_FREE(conn->deferred_expire_disconnect);
	if (conn->active_call) {
		tevent_req_cancel(conn->active_call);
		conn->active_call = NULL;
	}

	conn->limits.reason = talloc_strdup(conn, reason);
	if (conn->limits.reason == NULL) {
		TALLOC_FREE(conn->sockets.tls);
		TALLOC_FREE(conn->sockets.sasl);
		TALLOC_FREE(conn->sockets.raw);
		stream_terminate_connection(conn->connection, reason);
		return;
	}

	subreq = tstream_disconnect_send(conn,
					 conn->connection->event.ctx,
					 conn->sockets.active);
	if (subreq == NULL) {
		TALLOC_FREE(conn->sockets.tls);
		TALLOC_FREE(conn->sockets.sasl);
		TALLOC_FREE(conn->sockets.raw);
		stream_terminate_connection(conn->connection, reason);
		return;
	}
	tevent_req_set_endtime(subreq,
			       conn->connection->event.ctx,
			       conn->limits.endtime);
	tevent_req_set_callback(subreq, ldapsrv_terminate_connection_done, conn);
}

static void ldapsrv_terminate_connection_done(struct tevent_req *subreq)
{
	struct ldapsrv_connection *conn =
		tevent_req_callback_data(subreq,
		struct ldapsrv_connection);
	int sys_errno;
	bool ok;

	tstream_disconnect_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);

	if (conn->sockets.active == conn->sockets.raw) {
		TALLOC_FREE(conn->sockets.tls);
		TALLOC_FREE(conn->sockets.sasl);
		TALLOC_FREE(conn->sockets.raw);
		stream_terminate_connection(conn->connection,
					    conn->limits.reason);
		return;
	}

	TALLOC_FREE(conn->sockets.tls);
	TALLOC_FREE(conn->sockets.sasl);
	conn->sockets.active = conn->sockets.raw;

	subreq = tstream_disconnect_send(conn,
					 conn->connection->event.ctx,
					 conn->sockets.active);
	if (subreq == NULL) {
		TALLOC_FREE(conn->sockets.raw);
		stream_terminate_connection(conn->connection,
					    conn->limits.reason);
		return;
	}
	ok = tevent_req_set_endtime(subreq,
				    conn->connection->event.ctx,
				    conn->limits.endtime);
	if (!ok) {
		TALLOC_FREE(conn->sockets.raw);
		stream_terminate_connection(conn->connection,
					    conn->limits.reason);
		return;
	}
	tevent_req_set_callback(subreq, ldapsrv_terminate_connection_done, conn);
}

/*
  called when a LDAP socket becomes readable
*/
void ldapsrv_recv(struct stream_connection *c, uint16_t flags)
{
	smb_panic(__location__);
}

/*
  called when a LDAP socket becomes writable
*/
static void ldapsrv_send(struct stream_connection *c, uint16_t flags)
{
	smb_panic(__location__);
}

static int ldapsrv_load_limits(struct ldapsrv_connection *conn)
{
	TALLOC_CTX *tmp_ctx;
	const char *attrs[] = { "configurationNamingContext", NULL };
	const char *attrs2[] = { "lDAPAdminLimits", NULL };
	struct ldb_message_element *el;
	struct ldb_result *res = NULL;
	struct ldb_dn *basedn;
	struct ldb_dn *conf_dn;
	struct ldb_dn *policy_dn;
	unsigned int i;
	int ret;

	/* set defaults limits in case of failure */
	conn->limits.initial_timeout = 120;
	conn->limits.conn_idle_time = 900;
	conn->limits.max_page_size = 1000;
	conn->limits.max_notifications = 5;
	conn->limits.search_timeout = 120;
	conn->limits.expire_time = (struct timeval) {
		.tv_sec = get_time_t_max(),
	};


	tmp_ctx = talloc_new(conn);
	if (tmp_ctx == NULL) {
		return -1;
	}

	basedn = ldb_dn_new(tmp_ctx, conn->ldb, NULL);
	if (basedn == NULL) {
		goto failed;
	}

	ret = ldb_search(conn->ldb, tmp_ctx, &res, basedn, LDB_SCOPE_BASE, attrs, NULL);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	if (res->count != 1) {
		goto failed;
	}

	conf_dn = ldb_msg_find_attr_as_dn(conn->ldb, tmp_ctx, res->msgs[0], "configurationNamingContext");
	if (conf_dn == NULL) {
		goto failed;
	}

	policy_dn = ldb_dn_copy(tmp_ctx, conf_dn);
	ldb_dn_add_child_fmt(policy_dn, "CN=Default Query Policy,CN=Query-Policies,CN=Directory Service,CN=Windows NT,CN=Services");
	if (policy_dn == NULL) {
		goto failed;
	}

	ret = ldb_search(conn->ldb, tmp_ctx, &res, policy_dn, LDB_SCOPE_BASE, attrs2, NULL);
	if (ret != LDB_SUCCESS) {
		goto failed;
	}

	if (res->count != 1) {
		goto failed;
	}

	el = ldb_msg_find_element(res->msgs[0], "lDAPAdminLimits");
	if (el == NULL) {
		goto failed;
	}

	for (i = 0; i < el->num_values; i++) {
		char policy_name[256];
		int policy_value, s;

		s = sscanf((const char *)el->values[i].data, "%255[^=]=%d", policy_name, &policy_value);
		if (s != 2 || policy_value == 0)
			continue;
		if (strcasecmp("InitRecvTimeout", policy_name) == 0) {
			conn->limits.initial_timeout = policy_value;
			continue;
		}
		if (strcasecmp("MaxConnIdleTime", policy_name) == 0) {
			conn->limits.conn_idle_time = policy_value;
			continue;
		}
		if (strcasecmp("MaxPageSize", policy_name) == 0) {
			conn->limits.max_page_size = policy_value;
			continue;
		}
		if (strcasecmp("MaxNotificationPerConn", policy_name) == 0) {
			conn->limits.max_notifications = policy_value;
			continue;
		}
		if (strcasecmp("MaxQueryDuration", policy_name) == 0) {
			conn->limits.search_timeout = policy_value;
			continue;
		}
	}

	return 0;

failed:
	DBG_ERR("Failed to load ldap server query policies\n");
	talloc_free(tmp_ctx);
	return -1;
}

static int ldapsrv_call_destructor(struct ldapsrv_call *call)
{
	if (call->conn == NULL) {
		return 0;
	}

	DLIST_REMOVE(call->conn->pending_calls, call);

	call->conn = NULL;
	return 0;
}

static struct tevent_req *ldapsrv_process_call_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct tevent_queue *call_queue,
						    struct ldapsrv_call *call);
static NTSTATUS ldapsrv_process_call_recv(struct tevent_req *req);

static bool ldapsrv_call_read_next(struct ldapsrv_connection *conn);
static void ldapsrv_accept_tls_done(struct tevent_req *subreq);

/*
  initialise a server_context from a open socket and register a event handler
  for reading from that socket
*/
static void ldapsrv_accept(struct stream_connection *c,
			   struct auth_session_info *session_info,
			   bool is_privileged)
{
	struct ldapsrv_service *ldapsrv_service = 
		talloc_get_type(c->private_data, struct ldapsrv_service);
	struct ldapsrv_connection *conn;
	struct cli_credentials *server_credentials;
	struct socket_address *socket_address;
	NTSTATUS status;
	int port;
	int ret;
	struct tevent_req *subreq;
	struct timeval endtime;
	char *errstring = NULL;

	conn = talloc_zero(c, struct ldapsrv_connection);
	if (!conn) {
		stream_terminate_connection(c, "ldapsrv_accept: out of memory");
		return;
	}
	conn->is_privileged = is_privileged;

	conn->sockets.send_queue = tevent_queue_create(conn, "ldapsev send queue");
	if (conn->sockets.send_queue == NULL) {
		stream_terminate_connection(c,
					    "ldapsrv_accept: tevent_queue_create failed");
		return;
	}

	TALLOC_FREE(c->event.fde);

	ret = tstream_bsd_existing_socket(conn,
					  socket_get_fd(c->socket),
					  &conn->sockets.raw);
	if (ret == -1) {
		stream_terminate_connection(c,
					    "ldapsrv_accept: out of memory");
		return;
	}
	socket_set_flags(c->socket, SOCKET_FLAG_NOCLOSE);

	conn->connection  = c;
	conn->service     = ldapsrv_service;
	conn->lp_ctx      = ldapsrv_service->task->lp_ctx;

	c->private_data   = conn;

	socket_address = socket_get_my_addr(c->socket, conn);
	if (!socket_address) {
		ldapsrv_terminate_connection(conn, "ldapsrv_accept: failed to obtain local socket address!");
		return;
	}
	port = socket_address->port;
	talloc_free(socket_address);
	if (port == 3268 || port == 3269) /* Global catalog */ {
		conn->global_catalog = true;
	}

	server_credentials = cli_credentials_init(conn);
	if (!server_credentials) {
		stream_terminate_connection(c, "Failed to init server credentials\n");
		return;
	}

	cli_credentials_set_conf(server_credentials, conn->lp_ctx);
	status = cli_credentials_set_machine_account(server_credentials, conn->lp_ctx);
	if (!NT_STATUS_IS_OK(status)) {
		stream_terminate_connection(c, talloc_asprintf(conn, "Failed to obtain server credentials, perhaps a standalone server?: %s\n", nt_errstr(status)));
		return;
	}
	conn->server_credentials = server_credentials;

	conn->session_info = session_info;

	conn->sockets.active = conn->sockets.raw;

	if (conn->is_privileged) {
		conn->require_strong_auth = LDAP_SERVER_REQUIRE_STRONG_AUTH_NO;
	} else {
		conn->require_strong_auth = lpcfg_ldap_server_require_strong_auth(conn->lp_ctx);
	}

	ret = ldapsrv_backend_Init(conn, &errstring);
	if (ret != LDB_SUCCESS) {
		char *reason = talloc_asprintf(conn,
					       "LDB backend for LDAP Init "
					       "failed: %s: %s",
					       errstring, ldb_strerror(ret));
		ldapsrv_terminate_connection(conn, reason);
		return;
	}

	/* load limits from the conf partition */
	ldapsrv_load_limits(conn); /* should we fail on error ? */

	/* register the server */	
	irpc_add_name(c->msg_ctx, "ldap_server");

	DLIST_ADD_END(ldapsrv_service->connections, conn);

	if (port != 636 && port != 3269) {
		ldapsrv_call_read_next(conn);
		return;
	}

	endtime = timeval_current_ofs(conn->limits.conn_idle_time, 0);

	subreq = tstream_tls_accept_send(conn,
					 conn->connection->event.ctx,
					 conn->sockets.raw,
					 conn->service->tls_params);
	if (subreq == NULL) {
		ldapsrv_terminate_connection(conn, "ldapsrv_accept: "
				"no memory for tstream_tls_accept_send");
		return;
	}
	tevent_req_set_endtime(subreq,
			       conn->connection->event.ctx,
			       endtime);
	tevent_req_set_callback(subreq, ldapsrv_accept_tls_done, conn);
}

static void ldapsrv_accept_tls_done(struct tevent_req *subreq)
{
	struct ldapsrv_connection *conn =
		tevent_req_callback_data(subreq,
		struct ldapsrv_connection);
	int ret;
	int sys_errno;

	ret = tstream_tls_accept_recv(subreq, &sys_errno,
				      conn, &conn->sockets.tls);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		const char *reason;

		reason = talloc_asprintf(conn, "ldapsrv_accept_tls_loop: "
					 "tstream_tls_accept_recv() - %d:%s",
					 sys_errno, strerror(sys_errno));
		if (!reason) {
			reason = "ldapsrv_accept_tls_loop: "
				 "tstream_tls_accept_recv() - failed";
		}

		ldapsrv_terminate_connection(conn, reason);
		return;
	}

	conn->sockets.active = conn->sockets.tls;
	conn->referral_scheme = LDAP_REFERRAL_SCHEME_LDAPS;
	ldapsrv_call_read_next(conn);
}

static void ldapsrv_call_read_done(struct tevent_req *subreq);
static NTSTATUS ldapsrv_packet_check(
	void *private_data,
	DATA_BLOB blob,
	size_t *packet_size);

static bool ldapsrv_call_read_next(struct ldapsrv_connection *conn)
{
	struct tevent_req *subreq;

	if (conn->pending_calls != NULL) {
		conn->limits.endtime = timeval_zero();

		ldapsrv_notification_retry_setup(conn->service, false);
	} else if (timeval_is_zero(&conn->limits.endtime)) {
		conn->limits.endtime =
			timeval_current_ofs(conn->limits.initial_timeout, 0);
	} else {
		conn->limits.endtime =
			timeval_current_ofs(conn->limits.conn_idle_time, 0);
	}

	if (conn->sockets.read_req != NULL) {
		return true;
	}

	/*
	 * The minimum size of a LDAP pdu is 7 bytes
	 *
	 * dumpasn1 -hh ldap-unbind-min.dat
	 *
	 *     <30 05 02 01 09 42 00>
	 *    0    5: SEQUENCE {
	 *     <02 01 09>
	 *    2    1:   INTEGER 9
	 *     <42 00>
	 *    5    0:   [APPLICATION 2]
	 *          :     Error: Object has zero length.
	 *          :   }
	 *
	 * dumpasn1 -hh ldap-unbind-windows.dat
	 *
	 *     <30 84 00 00 00 05 02 01 09 42 00>
	 *    0    5: SEQUENCE {
	 *     <02 01 09>
	 *    6    1:   INTEGER 9
	 *     <42 00>
	 *    9    0:   [APPLICATION 2]
	 *          :     Error: Object has zero length.
	 *          :   }
	 *
	 * This means using an initial read size
	 * of 7 is ok.
	 */
	subreq = tstream_read_pdu_blob_send(conn,
					    conn->connection->event.ctx,
					    conn->sockets.active,
					    7, /* initial_read_size */
					    ldapsrv_packet_check,
					    conn);
	if (subreq == NULL) {
		ldapsrv_terminate_connection(conn, "ldapsrv_call_read_next: "
				"no memory for tstream_read_pdu_blob_send");
		return false;
	}
	if (!timeval_is_zero(&conn->limits.endtime)) {
		bool ok;
		ok = tevent_req_set_endtime(subreq,
					    conn->connection->event.ctx,
					    conn->limits.endtime);
		if (!ok) {
			ldapsrv_terminate_connection(
				conn,
				"ldapsrv_call_read_next: "
				"no memory for tevent_req_set_endtime");
			return false;
		}
	}
	tevent_req_set_callback(subreq, ldapsrv_call_read_done, conn);
	conn->sockets.read_req = subreq;
	return true;
}

static void ldapsrv_call_process_done(struct tevent_req *subreq);
static int ldapsrv_check_packet_size(
	struct ldapsrv_connection *conn,
	size_t size);

static void ldapsrv_call_read_done(struct tevent_req *subreq)
{
	struct ldapsrv_connection *conn =
		tevent_req_callback_data(subreq,
		struct ldapsrv_connection);
	NTSTATUS status;
	struct ldapsrv_call *call;
	struct asn1_data *asn1;
	DATA_BLOB blob;
	int ret = LDAP_SUCCESS;
	struct ldap_request_limits limits = {0};

	conn->sockets.read_req = NULL;

	call = talloc_zero(conn, struct ldapsrv_call);
	if (!call) {
		ldapsrv_terminate_connection(conn, "no memory");
		return;
	}
	talloc_set_destructor(call, ldapsrv_call_destructor);

	call->conn = conn;

	status = tstream_read_pdu_blob_recv(subreq,
					    call,
					    &blob);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		const char *reason;

		reason = talloc_asprintf(call, "ldapsrv_call_loop: "
					 "tstream_read_pdu_blob_recv() - %s",
					 nt_errstr(status));
		if (!reason) {
			reason = nt_errstr(status);
		}

		ldapsrv_terminate_connection(conn, reason);
		return;
	}

	ret = ldapsrv_check_packet_size(conn, blob.length);
	if (ret != LDAP_SUCCESS) {
		ldapsrv_terminate_connection(
			conn,
			"Request packet too large");
		return;
	}

	asn1 = asn1_init(call, ASN1_MAX_TREE_DEPTH);
	if (asn1 == NULL) {
		ldapsrv_terminate_connection(conn, "no memory");
		return;
	}

	call->request = talloc(call, struct ldap_message);
	if (call->request == NULL) {
		ldapsrv_terminate_connection(conn, "no memory");
		return;
	}

	if (!asn1_load(asn1, blob)) {
		ldapsrv_terminate_connection(conn, "asn1_load failed");
		return;
	}

	limits.max_search_size =
		lpcfg_ldap_max_search_request_size(conn->lp_ctx);
	status = ldap_decode(
		asn1,
		&limits,
		samba_ldap_control_handlers(),
		call->request);
	if (!NT_STATUS_IS_OK(status)) {
		ldapsrv_terminate_connection(conn, nt_errstr(status));
		return;
	}

	data_blob_free(&blob);


	/* queue the call in the global queue */
	subreq = ldapsrv_process_call_send(call,
					   conn->connection->event.ctx,
					   conn->service->call_queue,
					   call);
	if (subreq == NULL) {
		ldapsrv_terminate_connection(conn, "ldapsrv_process_call_send failed");
		return;
	}
	tevent_req_set_callback(subreq, ldapsrv_call_process_done, call);
	conn->active_call = subreq;
}

static void ldapsrv_call_wait_done(struct tevent_req *subreq);
static void ldapsrv_call_writev_start(struct ldapsrv_call *call);
static void ldapsrv_call_writev_done(struct tevent_req *subreq);

static void ldapsrv_call_process_done(struct tevent_req *subreq)
{
	struct ldapsrv_call *call =
		tevent_req_callback_data(subreq,
		struct ldapsrv_call);
	struct ldapsrv_connection *conn = call->conn;
	NTSTATUS status;

	conn->active_call = NULL;

	status = ldapsrv_process_call_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		ldapsrv_terminate_connection(conn, nt_errstr(status));
		return;
	}

	if (call->wait_send != NULL) {
		subreq = call->wait_send(call,
					 conn->connection->event.ctx,
					 call->wait_private);
		if (subreq == NULL) {
			ldapsrv_terminate_connection(conn,
					"ldapsrv_call_process_done: "
					"call->wait_send - no memory");
			return;
		}
		tevent_req_set_callback(subreq,
					ldapsrv_call_wait_done,
					call);
		conn->active_call = subreq;
		return;
	}

	ldapsrv_call_writev_start(call);
}

static void ldapsrv_call_wait_done(struct tevent_req *subreq)
{
	struct ldapsrv_call *call =
		tevent_req_callback_data(subreq,
		struct ldapsrv_call);
	struct ldapsrv_connection *conn = call->conn;
	NTSTATUS status;

	conn->active_call = NULL;

	status = call->wait_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		const char *reason;

		reason = talloc_asprintf(call, "ldapsrv_call_wait_done: "
					 "call->wait_recv() - %s",
					 nt_errstr(status));
		if (reason == NULL) {
			reason = nt_errstr(status);
		}

		ldapsrv_terminate_connection(conn, reason);
		return;
	}

	ldapsrv_call_writev_start(call);
}

static void ldapsrv_call_writev_start(struct ldapsrv_call *call)
{
	struct ldapsrv_connection *conn = call->conn;
	struct ldapsrv_reply *reply = NULL;
	struct tevent_req *subreq = NULL;
	size_t length = 0;
	size_t i;

	call->iov_count = 0;

	/* build all the replies into an IOV (no copy) */
	for (reply = call->replies;
	     reply != NULL;
	     reply = reply->next) {

		/* Cap output at 25MB per writev() */
		if (length > length + reply->blob.length
		    || length + reply->blob.length > LDAP_SERVER_MAX_CHUNK_SIZE) {
			break;
		}

		/*
		 * Overflow is harmless here, just used below to
		 * decide if to read or write, but checkd above anyway
		 */
		length += reply->blob.length;

		/*
		 * At worst an overflow would mean we send less
		 * replies
		 */
		call->iov_count++;
	}

	if (length == 0) {
		if (!call->notification.busy) {
			TALLOC_FREE(call);
		}

		ldapsrv_call_read_next(conn);
		return;
	}

	/* Cap call->iov_count at IOV_MAX */
	call->iov_count = MIN(call->iov_count, IOV_MAX);

	call->out_iov = talloc_array(call,
				     struct iovec,
				     call->iov_count);
	if (!call->out_iov) {
		/* This is not ideal */
		ldapsrv_terminate_connection(conn,
					     "failed to allocate "
					     "iovec array");
		return;
	}

	/* We may have had to cap the number of replies at IOV_MAX */
	for (i = 0;
	     i < call->iov_count && call->replies != NULL;
	     i++) {
		reply = call->replies;
		call->out_iov[i].iov_base = reply->blob.data;
		call->out_iov[i].iov_len = reply->blob.length;

		/* Keep only the ASN.1 encoded data */
		talloc_steal(call->out_iov, reply->blob.data);

		DLIST_REMOVE(call->replies, reply);
		TALLOC_FREE(reply);
	}

	if (i > call->iov_count) {
		/* This is not ideal, but also (essentially) impossible */
		ldapsrv_terminate_connection(conn,
					     "call list ended"
					     "before iov_count");
		return;
	}

	subreq = tstream_writev_queue_send(call,
					   conn->connection->event.ctx,
					   conn->sockets.active,
					   conn->sockets.send_queue,
					   call->out_iov, call->iov_count);
	if (subreq == NULL) {
		ldapsrv_terminate_connection(conn, "stream_writev_queue_send failed");
		return;
	}
	tevent_req_set_callback(subreq, ldapsrv_call_writev_done, call);
}

static void ldapsrv_call_postprocess_done(struct tevent_req *subreq);

static void ldapsrv_call_writev_done(struct tevent_req *subreq)
{
	struct ldapsrv_call *call =
		tevent_req_callback_data(subreq,
		struct ldapsrv_call);
	struct ldapsrv_connection *conn = call->conn;
	int sys_errno;
	int rc;

	rc = tstream_writev_queue_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);

	/* This releases the ASN.1 encoded packets from memory */
	TALLOC_FREE(call->out_iov);
	if (rc == -1) {
		const char *reason;

		reason = talloc_asprintf(call, "ldapsrv_call_writev_done: "
					 "tstream_writev_queue_recv() - %d:%s",
					 sys_errno, strerror(sys_errno));
		if (reason == NULL) {
			reason = "ldapsrv_call_writev_done: "
				 "tstream_writev_queue_recv() failed";
		}

		ldapsrv_terminate_connection(conn, reason);
		return;
	}

	if (call->postprocess_send) {
		subreq = call->postprocess_send(call,
						conn->connection->event.ctx,
						call->postprocess_private);
		if (subreq == NULL) {
			ldapsrv_terminate_connection(conn, "ldapsrv_call_writev_done: "
					"call->postprocess_send - no memory");
			return;
		}
		tevent_req_set_callback(subreq,
					ldapsrv_call_postprocess_done,
					call);
		return;
	}

	/* Perhaps still some more to send */
	if (call->replies != NULL) {
		ldapsrv_call_writev_start(call);
		return;
	}

	if (!call->notification.busy) {
		TALLOC_FREE(call);
	}

	ldapsrv_call_read_next(conn);
}

static void ldapsrv_call_postprocess_done(struct tevent_req *subreq)
{
	struct ldapsrv_call *call =
		tevent_req_callback_data(subreq,
		struct ldapsrv_call);
	struct ldapsrv_connection *conn = call->conn;
	NTSTATUS status;

	status = call->postprocess_recv(subreq);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		const char *reason;

		reason = talloc_asprintf(call, "ldapsrv_call_postprocess_done: "
					 "call->postprocess_recv() - %s",
					 nt_errstr(status));
		if (reason == NULL) {
			reason = nt_errstr(status);
		}

		ldapsrv_terminate_connection(conn, reason);
		return;
	}

	TALLOC_FREE(call);

	ldapsrv_call_read_next(conn);
}

static void ldapsrv_notification_retry_done(struct tevent_req *subreq);

void ldapsrv_notification_retry_setup(struct ldapsrv_service *service, bool force)
{
	struct ldapsrv_connection *conn = NULL;
	struct timeval retry;
	size_t num_pending = 0;
	size_t num_active = 0;

	if (force) {
		TALLOC_FREE(service->notification.retry);
		service->notification.generation += 1;
	}

	if (service->notification.retry != NULL) {
		return;
	}

	for (conn = service->connections; conn != NULL; conn = conn->next) {
		if (conn->pending_calls == NULL) {
			continue;
		}

		num_pending += 1;

		if (conn->pending_calls->notification.generation !=
		    service->notification.generation)
		{
			num_active += 1;
		}
	}

	if (num_pending == 0) {
		return;
	}

	if (num_active != 0) {
		retry = timeval_current_ofs(0, 100);
	} else {
		retry = timeval_current_ofs(5, 0);
	}

	service->notification.retry = tevent_wakeup_send(service,
							 service->task->event_ctx,
							 retry);
	if (service->notification.retry == NULL) {
		/* retry later */
		return;
	}

	tevent_req_set_callback(service->notification.retry,
				ldapsrv_notification_retry_done,
				service);
}

static void ldapsrv_notification_retry_done(struct tevent_req *subreq)
{
	struct ldapsrv_service *service =
		tevent_req_callback_data(subreq,
		struct ldapsrv_service);
	struct ldapsrv_connection *conn = NULL;
	struct ldapsrv_connection *conn_next = NULL;
	bool ok;

	service->notification.retry = NULL;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		/* ignore */
	}

	for (conn = service->connections; conn != NULL; conn = conn_next) {
		struct ldapsrv_call *call = conn->pending_calls;

		conn_next = conn->next;

		if (conn->pending_calls == NULL) {
			continue;
		}

		if (conn->active_call != NULL) {
			continue;
		}

		DLIST_DEMOTE(conn->pending_calls, call);
		call->notification.generation =
				service->notification.generation;

		/* queue the call in the global queue */
		subreq = ldapsrv_process_call_send(call,
						   conn->connection->event.ctx,
						   conn->service->call_queue,
						   call);
		if (subreq == NULL) {
			ldapsrv_terminate_connection(conn,
					"ldapsrv_process_call_send failed");
			continue;
		}
		tevent_req_set_callback(subreq, ldapsrv_call_process_done, call);
		conn->active_call = subreq;
	}

	ldapsrv_notification_retry_setup(service, false);
}

struct ldapsrv_process_call_state {
	struct ldapsrv_call *call;
};

static void ldapsrv_process_call_trigger(struct tevent_req *req,
					 void *private_data);

static struct tevent_req *ldapsrv_process_call_send(TALLOC_CTX *mem_ctx,
						    struct tevent_context *ev,
						    struct tevent_queue *call_queue,
						    struct ldapsrv_call *call)
{
	struct tevent_req *req;
	struct ldapsrv_process_call_state *state;
	bool ok;

	req = tevent_req_create(mem_ctx, &state,
				struct ldapsrv_process_call_state);
	if (req == NULL) {
		return req;
	}

	state->call = call;

	ok = tevent_queue_add(call_queue, ev, req,
			      ldapsrv_process_call_trigger, NULL);
	if (!ok) {
		tevent_req_oom(req);
		return tevent_req_post(req, ev);
	}

	return req;
}

static void ldapsrv_disconnect_ticket_expired(struct tevent_req *subreq);

static void ldapsrv_process_call_trigger(struct tevent_req *req,
					 void *private_data)
{
	struct ldapsrv_process_call_state *state =
		tevent_req_data(req,
		struct ldapsrv_process_call_state);
	struct ldapsrv_connection *conn = state->call->conn;
	NTSTATUS status;

	if (conn->deferred_expire_disconnect != NULL) {
		/*
		 * Just drop this on the floor
		 */
		tevent_req_done(req);
		return;
	}

	/* make the call */
	status = ldapsrv_do_call(state->call);

	if (NT_STATUS_EQUAL(status, NT_STATUS_NETWORK_SESSION_EXPIRED)) {
		/*
		 * For testing purposes, defer the TCP disconnect
		 * after having sent the msgid 0
		 * 1.3.6.1.4.1.1466.20036 exop response. LDAP clients
		 * should not wait for the TCP connection to close but
		 * handle this packet equivalent to a TCP
		 * disconnect. This delay enables testing both cases
		 * in LDAP client libraries.
		 */

		int defer_msec = lpcfg_parm_int(
			conn->lp_ctx,
			NULL,
			"ldap_server",
			"delay_expire_disconnect",
			0);

		conn->deferred_expire_disconnect = tevent_wakeup_send(
			conn,
			conn->connection->event.ctx,
			timeval_current_ofs_msec(defer_msec));
		if (tevent_req_nomem(conn->deferred_expire_disconnect, req)) {
			return;
		}
		tevent_req_set_callback(
			conn->deferred_expire_disconnect,
			ldapsrv_disconnect_ticket_expired,
			conn);

		tevent_req_done(req);
		return;
	}

	if (!NT_STATUS_IS_OK(status)) {
		tevent_req_nterror(req, status);
		return;
	}

	tevent_req_done(req);
}

static void ldapsrv_disconnect_ticket_expired(struct tevent_req *subreq)
{
	struct ldapsrv_connection *conn = tevent_req_callback_data(
		subreq, struct ldapsrv_connection);
	bool ok;

	ok = tevent_wakeup_recv(subreq);
	TALLOC_FREE(subreq);
	if (!ok) {
		DBG_WARNING("tevent_wakeup_recv failed\n");
	}
	conn->deferred_expire_disconnect = NULL;
	ldapsrv_terminate_connection(conn, "network session expired");
}

static NTSTATUS ldapsrv_process_call_recv(struct tevent_req *req)
{
	NTSTATUS status;

	if (tevent_req_is_nterror(req, &status)) {
		tevent_req_received(req);
		return status;
	}

	tevent_req_received(req);
	return NT_STATUS_OK;
}

static void ldapsrv_accept_nonpriv(struct stream_connection *c)
{
	struct ldapsrv_service *ldapsrv_service = talloc_get_type_abort(
		c->private_data, struct ldapsrv_service);
	struct auth_session_info *session_info;
	NTSTATUS status;

	status = auth_anonymous_session_info(
		c, ldapsrv_service->task->lp_ctx, &session_info);
	if (!NT_STATUS_IS_OK(status)) {
		stream_terminate_connection(c, "failed to setup anonymous "
					    "session info");
		return;
	}
	ldapsrv_accept(c, session_info, false);
}

static const struct stream_server_ops ldap_stream_nonpriv_ops = {
	.name			= "ldap",
	.accept_connection	= ldapsrv_accept_nonpriv,
	.recv_handler		= ldapsrv_recv,
	.send_handler		= ldapsrv_send,
};

/* The feature removed behind an #ifdef until we can do it properly
 * with an EXTERNAL bind. */

#define WITH_LDAPI_PRIV_SOCKET

#ifdef WITH_LDAPI_PRIV_SOCKET
static void ldapsrv_accept_priv(struct stream_connection *c)
{
	struct ldapsrv_service *ldapsrv_service = talloc_get_type_abort(
		c->private_data, struct ldapsrv_service);
	struct auth_session_info *session_info;

	session_info = system_session(ldapsrv_service->task->lp_ctx);
	if (!session_info) {
		stream_terminate_connection(c, "failed to setup system "
					    "session info");
		return;
	}
	ldapsrv_accept(c, session_info, true);
}

static const struct stream_server_ops ldap_stream_priv_ops = {
	.name			= "ldap",
	.accept_connection	= ldapsrv_accept_priv,
	.recv_handler		= ldapsrv_recv,
	.send_handler		= ldapsrv_send,
};

#endif


/*
  add a socket address to the list of events, one event per port
*/
static NTSTATUS add_socket(struct task_server *task,
			   struct loadparm_context *lp_ctx,
			   const struct model_ops *model_ops,
			   const char *address, struct ldapsrv_service *ldap_service)
{
	uint16_t port = 389;
	NTSTATUS status;
	struct ldb_context *ldb;

	status = stream_setup_socket(task, task->event_ctx, lp_ctx,
				     model_ops, &ldap_stream_nonpriv_ops,
				     "ip", address, &port,
				     lpcfg_socket_options(lp_ctx),
				     ldap_service, task->process_context);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("ldapsrv failed to bind to %s:%u - %s\n",
			address, port, nt_errstr(status));
		return status;
	}

	if (tstream_tls_params_enabled(ldap_service->tls_params)) {
		/* add ldaps server */
		port = 636;
		status = stream_setup_socket(task, task->event_ctx, lp_ctx,
					     model_ops,
					     &ldap_stream_nonpriv_ops,
					     "ip", address, &port,
					     lpcfg_socket_options(lp_ctx),
					     ldap_service,
					     task->process_context);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("ldapsrv failed to bind to %s:%u - %s\n",
				address, port, nt_errstr(status));
			return status;
		}
	}

	/* Load LDAP database, but only to read our settings */
	ldb = samdb_connect(ldap_service,
			    ldap_service->task->event_ctx,
			    lp_ctx,
			    system_session(lp_ctx),
			    NULL,
			    0);
	if (!ldb) {
		return NT_STATUS_INTERNAL_DB_CORRUPTION;
	}

	if (samdb_is_gc(ldb)) {
		port = 3268;
		status = stream_setup_socket(task, task->event_ctx, lp_ctx,
					     model_ops,
					     &ldap_stream_nonpriv_ops,
					     "ip", address, &port,
					     lpcfg_socket_options(lp_ctx),
					     ldap_service,
					     task->process_context);
		if (!NT_STATUS_IS_OK(status)) {
			DBG_ERR("ldapsrv failed to bind to %s:%u - %s\n",
				address, port, nt_errstr(status));
			return status;
		}
		if (tstream_tls_params_enabled(ldap_service->tls_params)) {
			/* add ldaps server for the global catalog */
			port = 3269;
			status = stream_setup_socket(task, task->event_ctx, lp_ctx,
						     model_ops,
						     &ldap_stream_nonpriv_ops,
						     "ip", address, &port,
						     lpcfg_socket_options(lp_ctx),
						     ldap_service,
						     task->process_context);
			if (!NT_STATUS_IS_OK(status)) {
				DBG_ERR("ldapsrv failed to bind to %s:%u - %s\n",
					address, port, nt_errstr(status));
				return status;
			}
		}
	}

	/* And once we are bound, free the temporary ldb, it will
	 * connect again on each incoming LDAP connection */
	talloc_unlink(ldap_service, ldb);

	return NT_STATUS_OK;
}

/*
  open the ldap server sockets
*/
static NTSTATUS ldapsrv_task_init(struct task_server *task)
{	
	char *ldapi_path;
#ifdef WITH_LDAPI_PRIV_SOCKET
	char *priv_dir;
#endif
	const char *dns_host_name;
	struct ldapsrv_service *ldap_service;
	NTSTATUS status;

	switch (lpcfg_server_role(task->lp_ctx)) {
	case ROLE_STANDALONE:
		task_server_terminate(task, "ldap_server: no LDAP server required in standalone configuration", 
				      false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task, "ldap_server: no LDAP server required in member server configuration", 
				      false);
		return NT_STATUS_INVALID_DOMAIN_ROLE;
	case ROLE_ACTIVE_DIRECTORY_DC:
		/* Yes, we want an LDAP server */
		break;
	}

	task_server_set_title(task, "task[ldapsrv]");

	ldap_service = talloc_zero(task, struct ldapsrv_service);
	if (ldap_service == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	ldap_service->task = task;

	dns_host_name = talloc_asprintf(ldap_service, "%s.%s",
					lpcfg_netbios_name(task->lp_ctx),
					lpcfg_dnsdomain(task->lp_ctx));
	if (dns_host_name == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	status = tstream_tls_params_server(ldap_service,
					   dns_host_name,
					   lpcfg_tls_enabled(task->lp_ctx),
					   lpcfg_tls_keyfile(ldap_service, task->lp_ctx),
					   lpcfg_tls_certfile(ldap_service, task->lp_ctx),
					   lpcfg_tls_cafile(ldap_service, task->lp_ctx),
					   lpcfg_tls_crlfile(ldap_service, task->lp_ctx),
					   lpcfg_tls_dhpfile(ldap_service, task->lp_ctx),
					   lpcfg_tls_priority(task->lp_ctx),
					   &ldap_service->tls_params);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("ldapsrv failed tstream_tls_params_server - %s\n",
			nt_errstr(status));
		goto failed;
	}

	ldap_service->call_queue = tevent_queue_create(ldap_service, "ldapsrv_call_queue");
	if (ldap_service->call_queue == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	if (lpcfg_interfaces(task->lp_ctx) && lpcfg_bind_interfaces_only(task->lp_ctx)) {
		struct interface *ifaces;
		int num_interfaces;
		int i;

		load_interface_list(task, task->lp_ctx, &ifaces);
		num_interfaces = iface_list_count(ifaces);

		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		for(i = 0; i < num_interfaces; i++) {
			const char *address = iface_list_n_ip(ifaces, i);
			status = add_socket(task, task->lp_ctx, task->model_ops,
					    address, ldap_service);
			if (!NT_STATUS_IS_OK(status)) goto failed;
		}
	} else {
		char **wcard;
		size_t i;
		size_t num_binds = 0;
		wcard = iface_list_wildcard(task);
		if (wcard == NULL) {
			DBG_ERR("No wildcard addresses available\n");
			status = NT_STATUS_UNSUCCESSFUL;
			goto failed;
		}
		for (i=0; wcard[i]; i++) {
			status = add_socket(task, task->lp_ctx, task->model_ops,
					    wcard[i], ldap_service);
			if (NT_STATUS_IS_OK(status)) {
				num_binds++;
			}
		}
		talloc_free(wcard);
		if (num_binds == 0) {
			status = NT_STATUS_UNSUCCESSFUL;
			goto failed;
		}
	}

	ldapi_path = lpcfg_private_path(ldap_service, task->lp_ctx, "ldapi");
	if (!ldapi_path) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto failed;
	}

	status = stream_setup_socket(task, task->event_ctx, task->lp_ctx,
				     task->model_ops, &ldap_stream_nonpriv_ops,
				     "unix", ldapi_path, NULL, 
				     lpcfg_socket_options(task->lp_ctx),
				     ldap_service, task->process_context);
	talloc_free(ldapi_path);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("ldapsrv failed to bind to %s - %s\n",
			ldapi_path, nt_errstr(status));
	}

#ifdef WITH_LDAPI_PRIV_SOCKET
	priv_dir = lpcfg_private_path(ldap_service, task->lp_ctx, "ldap_priv");
	if (priv_dir == NULL) {
		status = NT_STATUS_UNSUCCESSFUL;
		goto failed;
	}
	/*
	 * Make sure the directory for the privileged ldapi socket exists, and
	 * is of the correct permissions
	 */
	if (!directory_create_or_exist(priv_dir, 0750)) {
		task_server_terminate(task, "Cannot create ldap "
				      "privileged ldapi directory", true);
		return NT_STATUS_UNSUCCESSFUL;
	}
	ldapi_path = talloc_asprintf(ldap_service, "%s/ldapi", priv_dir);
	talloc_free(priv_dir);
	if (ldapi_path == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	status = stream_setup_socket(task, task->event_ctx, task->lp_ctx,
				     task->model_ops, &ldap_stream_priv_ops,
				     "unix", ldapi_path, NULL,
				     lpcfg_socket_options(task->lp_ctx),
				     ldap_service,
				     task->process_context);
	talloc_free(ldapi_path);
	if (!NT_STATUS_IS_OK(status)) {
		DBG_ERR("ldapsrv failed to bind to %s - %s\n",
			ldapi_path, nt_errstr(status));
	}

#endif

	/* register the server */
	irpc_add_name(task->msg_ctx, "ldap_server");

	task->private_data = ldap_service;

	return NT_STATUS_OK;

failed:
	task_server_terminate(task, "Failed to startup ldap server task", true);
	return status;
}

/*
 * Open a database to be later used by LDB wrap code (although it should be
 * plumbed through correctly eventually).
 */
static void ldapsrv_post_fork(struct task_server *task, struct process_details *pd)
{
	struct ldapsrv_service *ldap_service =
		talloc_get_type_abort(task->private_data, struct ldapsrv_service);

	ldap_service->sam_ctx = samdb_connect(ldap_service,
					      ldap_service->task->event_ctx,
					      ldap_service->task->lp_ctx,
					      system_session(ldap_service->task->lp_ctx),
					      NULL,
					      0);
	if (ldap_service->sam_ctx == NULL) {
		task_server_terminate(task, "Cannot open system session LDB",
				      true);
		return;
	}
}

/*
 * Check the size of an ldap request packet.
 *
 * For authenticated connections the maximum packet size is controlled by
 * the smb.conf parameter "ldap max authenticated request size"
 *
 * For anonymous connections the maximum packet size is controlled by
 * the smb.conf parameter "ldap max anonymous request size"
 */
static int ldapsrv_check_packet_size(
	struct ldapsrv_connection *conn,
	size_t size)
{
	bool is_anonymous = false;
	size_t max_size = 0;

	max_size = lpcfg_ldap_max_anonymous_request_size(conn->lp_ctx);
	if (size <= max_size) {
		return LDAP_SUCCESS;
	}

	/*
	 * Request is larger than the maximum unauthenticated request size.
	 * As this code is called frequently we avoid calling
	 * security_token_is_anonymous if possible
	 */
	if (conn->session_info != NULL &&
		conn->session_info->security_token != NULL) {
		is_anonymous = security_token_is_anonymous(
			conn->session_info->security_token);
	}

	if (is_anonymous) {
		DBG_WARNING(
			"LDAP request size (%zu) exceeds (%zu)\n",
			size,
			max_size);
		return LDAP_UNWILLING_TO_PERFORM;
	}

	max_size = lpcfg_ldap_max_authenticated_request_size(conn->lp_ctx);
	if (size > max_size) {
		DBG_WARNING(
			"LDAP request size (%zu) exceeds (%zu)\n",
			size,
			max_size);
		return LDAP_UNWILLING_TO_PERFORM;
	}
	return LDAP_SUCCESS;

}

/*
 * Check that the blob contains enough data to be a valid packet
 * If there is a packet header check the size to ensure that it does not
 * exceed the maximum sizes.
 *
 */
static NTSTATUS ldapsrv_packet_check(
	void *private_data,
	DATA_BLOB blob,
	size_t *packet_size)
{
	NTSTATUS ret;
	struct ldapsrv_connection *conn = private_data;
	int result = LDB_SUCCESS;

	ret = ldap_full_packet(private_data, blob, packet_size);
	if (!NT_STATUS_IS_OK(ret)) {
		return ret;
	}
	result = ldapsrv_check_packet_size(conn, *packet_size);
	if (result != LDAP_SUCCESS) {
		return NT_STATUS_LDAP(result);
	}
	return NT_STATUS_OK;
}

NTSTATUS server_service_ldap_init(TALLOC_CTX *ctx)
{
	static const struct service_details details = {
		.inhibit_fork_on_accept = false,
		.inhibit_pre_fork = false,
		.task_init = ldapsrv_task_init,
		.post_fork = ldapsrv_post_fork,
	};
	return register_server_service(ctx, "ldap", &details);
}
