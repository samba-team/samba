/* 
   Unix SMB/CIFS implementation.
   LDAP protocol helper functions for SAMBA
   
   Copyright (C) Andrew Tridgell  2004
   Copyright (C) Volker Lendecke 2004
   Copyright (C) Stefan Metzmacher 2004
   Copyright (C) Simo Sorce 2004
    
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
#include <tevent.h>
#include "lib/socket/socket.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/util/tstream.h"
#include "../lib/util/asn1.h"
#include "../lib/util/dlinklist.h"
#include "libcli/ldap/libcli_ldap.h"
#include "libcli/ldap/ldap_proto.h"
#include "libcli/ldap/ldap_client.h"
#include "libcli/composite/composite.h"
#include "lib/tls/tls.h"
#include "auth/gensec/gensec.h"
#include "system/time.h"
#include "param/param.h"
#include "libcli/resolve/resolve.h"

static void ldap_connection_dead(struct ldap_connection *conn, NTSTATUS status);

static int ldap_connection_destructor(struct ldap_connection *conn)
{
	/*
	 * NT_STATUS_OK means that callbacks of pending requests are not
	 * triggered
	 */
	ldap_connection_dead(conn, NT_STATUS_OK);
	return 0;
}

/**
  create a new ldap_connection stucture. The event context is optional
*/

_PUBLIC_ struct ldap_connection *ldap4_new_connection(TALLOC_CTX *mem_ctx, 
					     struct loadparm_context *lp_ctx,
					     struct tevent_context *ev)
{
	struct ldap_connection *conn;

	if (ev == NULL) {
		return NULL;
	}

	conn = talloc_zero(mem_ctx, struct ldap_connection);
	if (conn == NULL) {
		return NULL;
	}

	conn->next_messageid  = 1;
	conn->event.event_ctx = ev;

	conn->sockets.send_queue = tevent_queue_create(conn,
					"ldap_connection send_queue");
	if (conn->sockets.send_queue == NULL) {
		TALLOC_FREE(conn);
		return NULL;
	}

	conn->lp_ctx = lp_ctx;

	/* set a reasonable request timeout */
	conn->timeout = 60;

	/* explicitly avoid reconnections by default */
	conn->reconnect.max_retries = 0;

	talloc_set_destructor(conn, ldap_connection_destructor);
	return conn;
}

/*
  the connection is dead
*/
static void ldap_connection_dead(struct ldap_connection *conn, NTSTATUS status)
{
	struct ldap_request *req;

	tevent_queue_stop(conn->sockets.send_queue);
	TALLOC_FREE(conn->sockets.recv_subreq);
	conn->sockets.active = NULL;
	TALLOC_FREE(conn->sockets.sasl);
	TALLOC_FREE(conn->sockets.tls);
	TALLOC_FREE(conn->sockets.raw);

	/* return an error for any pending request ... */
	while (conn->pending) {
		req = conn->pending;
		DLIST_REMOVE(req->conn->pending, req);
		req->conn = NULL;
		req->state = LDAP_REQUEST_DONE;
		if (NT_STATUS_IS_OK(status)) {
			continue;
		}
		req->status = status;
		if (req->async.fn) {
			req->async.fn(req);
		}
	}
}

static void ldap_reconnect(struct ldap_connection *conn);

/*
  handle packet errors
*/
static void ldap_error_handler(struct ldap_connection *conn, NTSTATUS status)
{
	ldap_connection_dead(conn, status);

	/* but try to reconnect so that the ldb client can go on */
	ldap_reconnect(conn);
}


/*
  match up with a pending message, adding to the replies list
*/
static void ldap_match_message(struct ldap_connection *conn, struct ldap_message *msg)
{
	struct ldap_request *req;
	int i;

	for (req=conn->pending; req; req=req->next) {
		if (req->messageid == msg->messageid) break;
	}
	/* match a zero message id to the last request sent.
	   It seems that servers send 0 if unable to parse */
	if (req == NULL && msg->messageid == 0) {
		req = conn->pending;
	}
	if (req == NULL) {
		DEBUG(0,("ldap: no matching message id for %u\n",
			 msg->messageid));
		TALLOC_FREE(msg);
		return;
	}

	/* Check for undecoded critical extensions */
	for (i=0; msg->controls && msg->controls[i]; i++) {
		if (!msg->controls_decoded[i] && 
		    msg->controls[i]->critical) {
			TALLOC_FREE(msg);
			req->status = NT_STATUS_LDAP(LDAP_UNAVAILABLE_CRITICAL_EXTENSION);
			req->state = LDAP_REQUEST_DONE;
			DLIST_REMOVE(conn->pending, req);
			if (req->async.fn) {
				req->async.fn(req);
			}
			return;
		}
	}

	/* add to the list of replies received */
	req->replies = talloc_realloc(req, req->replies, 
				      struct ldap_message *, req->num_replies+1);
	if (req->replies == NULL) {
		TALLOC_FREE(msg);
		req->status = NT_STATUS_NO_MEMORY;
		req->state = LDAP_REQUEST_DONE;
		DLIST_REMOVE(conn->pending, req);
		if (req->async.fn) {
			req->async.fn(req);
		}
		return;
	}

	req->replies[req->num_replies] = talloc_steal(req->replies, msg);
	req->num_replies++;

	if (msg->type != LDAP_TAG_SearchResultEntry &&
	    msg->type != LDAP_TAG_SearchResultReference) {
		/* currently only search results expect multiple
		   replies */
		req->state = LDAP_REQUEST_DONE;
		DLIST_REMOVE(conn->pending, req);
	}

	if (req->async.fn) {
		req->async.fn(req);
	}
}

static void ldap_connection_recv_done(struct tevent_req *subreq);

static void ldap_connection_recv_next(struct ldap_connection *conn)
{
	struct tevent_req *subreq = NULL;

	if (conn->sockets.recv_subreq != NULL) {
		return;
	}

	if (conn->sockets.active == NULL) {
		return;
	}

	if (conn->pending == NULL) {
		return;
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
					    conn->event.event_ctx,
					    conn->sockets.active,
					    7, /* initial_read_size */
					    ldap_full_packet,
					    conn);
	if (subreq == NULL) {
		ldap_error_handler(conn, NT_STATUS_NO_MEMORY);
		return;
	}
	tevent_req_set_callback(subreq, ldap_connection_recv_done, conn);
	conn->sockets.recv_subreq = subreq;
	return;
}

/*
  decode/process LDAP data
*/
static void ldap_connection_recv_done(struct tevent_req *subreq)
{
	NTSTATUS status;
	struct ldap_connection *conn =
		tevent_req_callback_data(subreq,
		struct ldap_connection);
	struct ldap_message *msg;
	struct asn1_data *asn1;
	DATA_BLOB blob;
	struct ldap_request_limits limits = {0};

	msg = talloc_zero(conn, struct ldap_message);
	if (msg == NULL) {
		ldap_error_handler(conn, NT_STATUS_NO_MEMORY);
		return;
	}

	asn1 = asn1_init(conn, ASN1_MAX_TREE_DEPTH);
	if (asn1 == NULL) {
		TALLOC_FREE(msg);
		ldap_error_handler(conn, NT_STATUS_NO_MEMORY);
		return;
	}

	conn->sockets.recv_subreq = NULL;

	status = tstream_read_pdu_blob_recv(subreq,
					    asn1,
					    &blob);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(msg);
		asn1_free(asn1);
		ldap_error_handler(conn, status);
		return;
	}

	asn1_load_nocopy(asn1, blob.data, blob.length);

	status = ldap_decode(asn1, &limits, samba_ldap_control_handlers(), msg);
	asn1_free(asn1);
	if (!NT_STATUS_IS_OK(status)) {
		TALLOC_FREE(msg);
		ldap_error_handler(conn, status);
		return;
	}

	ldap_match_message(conn, msg);
	ldap_connection_recv_next(conn);

	return;
}

enum ldap_proto {
	LDAP_PROTO_NONE,
	LDAP_PROTO_LDAP,
	LDAP_PROTO_LDAPS,
	LDAP_PROTO_LDAPI
};

static int ldap_parse_basic_url(
	const char *url,
	enum ldap_proto *pproto,
	TALLOC_CTX *mem_ctx,
	char **pdest,		/* path for ldapi, host for ldap[s] */
	uint16_t *pport)	/* Not set for ldapi */
{
	enum ldap_proto proto = LDAP_PROTO_NONE;
	char *host = NULL;
	int ret, port;

	if (url == NULL) {
		return EINVAL;
	}

	if (strncasecmp_m(url, "ldapi://", strlen("ldapi://")) == 0) {
		char *path = NULL, *end = NULL;

		path = talloc_strdup(mem_ctx, url+8);
		if (path == NULL) {
			return ENOMEM;
		}
		end = rfc1738_unescape(path);
		if (end == NULL) {
			TALLOC_FREE(path);
			return EINVAL;
		}

		*pproto = LDAP_PROTO_LDAPI;
		*pdest = path;
		return 0;
	}

	if (strncasecmp_m(url, "ldap://", strlen("ldap://")) == 0) {
		url += 7;
		proto = LDAP_PROTO_LDAP;
		port = 389;
	}
	if (strncasecmp_m(url, "ldaps://", strlen("ldaps://")) == 0) {
		url += 8;
		port = 636;
		proto = LDAP_PROTO_LDAPS;
	}

	if (proto == LDAP_PROTO_NONE) {
		return EPROTONOSUPPORT;
	}

	if (url[0] == '[') {
		/*
		 * IPv6 with [aa:bb:cc..]:port
		 */
		const char *end = NULL;

		url +=1;

		end = strchr(url, ']');
		if (end == NULL) {
			return EINVAL;
		}

		ret = sscanf(end+1, ":%d", &port);
		if (ret < 0) {
			return EINVAL;
		}

		*pdest = talloc_strndup(mem_ctx, url, end-url);
		if (*pdest == NULL) {
			return ENOMEM;
		}
		*pproto = proto;
		*pport = port;
		return 0;
	}

	ret = sscanf(url, "%m[^:/]:%d", &host, &port);
	if (ret < 1) {
		return EINVAL;
	}

	*pdest = talloc_strdup(mem_ctx, host);
	SAFE_FREE(host);
	if (*pdest == NULL) {
		return ENOMEM;
	}
	*pproto = proto;
	*pport = port;

	return 0;
}

/*
  connect to a ldap server
*/

struct ldap_connect_state {
	struct composite_context *ctx;
	struct ldap_connection *conn;
	struct socket_context *sock;
	struct tstream_context *raw;
	struct tstream_tls_params *tls_params;
	struct tstream_context *tls;
};

static void ldap_connect_recv_unix_conn(struct composite_context *ctx);
static void ldap_connect_recv_tcp_conn(struct composite_context *ctx);

_PUBLIC_ struct composite_context *ldap_connect_send(struct ldap_connection *conn,
					    const char *url)
{
	struct composite_context *result, *ctx;
	struct ldap_connect_state *state;
	enum ldap_proto proto;
	char *dest = NULL;
	uint16_t port;
	int ret;

	result = talloc_zero(conn, struct composite_context);
	if (result == NULL) goto failed;
	result->state = COMPOSITE_STATE_IN_PROGRESS;
	result->async.fn = NULL;
	result->event_ctx = conn->event.event_ctx;

	state = talloc(result, struct ldap_connect_state);
	if (state == NULL) goto failed;
	state->ctx = result;
	result->private_data = state;

	state->conn = conn;

	if (conn->reconnect.url == NULL) {
		conn->reconnect.url = talloc_strdup(conn, url);
		if (conn->reconnect.url == NULL) goto failed;
	}

	ret = ldap_parse_basic_url(url, &proto, conn, &dest, &port);
	if (ret != 0) {
		composite_error(result, map_nt_error_from_unix_common(ret));
		return result;
	}

	if (proto == LDAP_PROTO_LDAPI) {
		struct socket_address *unix_addr;
		NTSTATUS status = socket_create(state, "unix",
						SOCKET_TYPE_STREAM,
						&state->sock, 0);
		if (!NT_STATUS_IS_OK(status)) {
			return NULL;
		}

		conn->host = talloc_asprintf(conn, "%s.%s",
					     lpcfg_netbios_name(conn->lp_ctx),
					     lpcfg_dnsdomain(conn->lp_ctx));
		if (composite_nomem(conn->host, state->ctx)) {
			return result;
		}

		unix_addr = socket_address_from_strings(state, state->sock->backend_name,
							dest, 0);
		if (composite_nomem(unix_addr, result)) {
			return result;
		}

		ctx = socket_connect_send(state->sock, NULL, unix_addr,
					  0, result->event_ctx);
		ctx->async.fn = ldap_connect_recv_unix_conn;
		ctx->async.private_data = state;
		return result;
	}

	if ((proto == LDAP_PROTO_LDAP) || (proto == LDAP_PROTO_LDAPS)) {

		conn->ldaps = (proto == LDAP_PROTO_LDAPS);

		conn->host = talloc_move(conn, &dest);
		conn->port = port;

		if (conn->ldaps) {
			char *ca_file = lpcfg_tls_cafile(state, conn->lp_ctx);
			char *crl_file = lpcfg_tls_crlfile(state, conn->lp_ctx);
			const char *tls_priority = lpcfg_tls_priority(conn->lp_ctx);
			enum tls_verify_peer_state verify_peer =
				lpcfg_tls_verify_peer(conn->lp_ctx);
			NTSTATUS status;

			status = tstream_tls_params_client(state,
							   ca_file,
							   crl_file,
							   tls_priority,
							   verify_peer,
							   conn->host,
							   &state->tls_params);
			if (!NT_STATUS_IS_OK(status)) {
				composite_error(result, status);
				return result;
			}
		}

		ctx = socket_connect_multi_send(state, conn->host, 1, &conn->port,
						lpcfg_resolve_context(conn->lp_ctx),
						result->event_ctx);
		if (composite_nomem(ctx, result)) {
			return result;
		}

		ctx->async.fn = ldap_connect_recv_tcp_conn;
		ctx->async.private_data = state;
		return result;
	}
 failed:
	talloc_free(result);
	return NULL;
}

static void ldap_connect_got_tls(struct tevent_req *subreq);

static void ldap_connect_got_sock(struct composite_context *ctx, 
				  struct ldap_connection *conn)
{
	struct ldap_connect_state *state =
		talloc_get_type_abort(ctx->private_data,
		struct ldap_connect_state);
	struct tevent_req *subreq = NULL;
	int fd;
	int ret;

	socket_set_flags(state->sock, SOCKET_FLAG_NOCLOSE);
	fd = socket_get_fd(state->sock);
	TALLOC_FREE(state->sock);

	smb_set_close_on_exec(fd);

	ret = set_blocking(fd, false);
	if (ret == -1) {
		NTSTATUS status = map_nt_error_from_unix_common(errno);
		composite_error(state->ctx, status);
		return;
	}

	ret = tstream_bsd_existing_socket(state, fd, &state->raw);
	if (ret == -1) {
		NTSTATUS status = map_nt_error_from_unix_common(errno);
		composite_error(state->ctx, status);
		return;
	}

	if (!conn->ldaps) {
		conn->sockets.raw = talloc_move(conn, &state->raw);
		conn->sockets.active = conn->sockets.raw;
		composite_done(state->ctx);
		return;
	}

	subreq = tstream_tls_connect_send(state, state->ctx->event_ctx,
					  state->raw, state->tls_params);
	if (composite_nomem(subreq, state->ctx)) {
		return;
	}
	tevent_req_set_callback(subreq, ldap_connect_got_tls, state);
}

static void ldap_connect_got_tls(struct tevent_req *subreq)
{
	struct ldap_connect_state *state =
		tevent_req_callback_data(subreq,
		struct ldap_connect_state);
	int err;
	int ret;

	ret = tstream_tls_connect_recv(subreq, &err, state, &state->tls);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		NTSTATUS status = map_nt_error_from_unix_common(err);
		composite_error(state->ctx, status);
		return;
	}

	talloc_steal(state->tls, state->tls_params);

	state->conn->sockets.raw = talloc_move(state->conn, &state->raw);
	state->conn->sockets.tls = talloc_move(state->conn->sockets.raw,
					       &state->tls);
	state->conn->sockets.active = state->conn->sockets.tls;
	composite_done(state->ctx);
}

static void ldap_connect_recv_tcp_conn(struct composite_context *ctx)
{
	struct ldap_connect_state *state =
		talloc_get_type_abort(ctx->async.private_data,
		struct ldap_connect_state);
	struct ldap_connection *conn = state->conn;
	uint16_t port;
	NTSTATUS status = socket_connect_multi_recv(ctx, state, &state->sock,
						       &port);
	if (!NT_STATUS_IS_OK(status)) {
		composite_error(state->ctx, status);
		return;
	}

	ldap_connect_got_sock(state->ctx, conn);
}

static void ldap_connect_recv_unix_conn(struct composite_context *ctx)
{
	struct ldap_connect_state *state =
		talloc_get_type_abort(ctx->async.private_data,
		struct ldap_connect_state);
	struct ldap_connection *conn = state->conn;

	NTSTATUS status = socket_connect_recv(ctx);

	if (!NT_STATUS_IS_OK(state->ctx->status)) {
		composite_error(state->ctx, status);
		return;
	}

	ldap_connect_got_sock(state->ctx, conn);
}

_PUBLIC_ NTSTATUS ldap_connect_recv(struct composite_context *ctx)
{
	NTSTATUS status = composite_wait(ctx);
	talloc_free(ctx);
	return status;
}

_PUBLIC_ NTSTATUS ldap_connect(struct ldap_connection *conn, const char *url)
{
	struct composite_context *ctx = ldap_connect_send(conn, url);
	return ldap_connect_recv(ctx);
}

/* set reconnect parameters */

_PUBLIC_ void ldap_set_reconn_params(struct ldap_connection *conn, int max_retries)
{
	if (conn) {
		conn->reconnect.max_retries = max_retries;
		conn->reconnect.retries = 0;
		conn->reconnect.previous = time_mono(NULL);
	}
}

/* Actually this function is NOT ASYNC safe, FIXME? */
static void ldap_reconnect(struct ldap_connection *conn)
{
	NTSTATUS status;
	time_t now = time_mono(NULL);

	/* do we have set up reconnect ? */
	if (conn->reconnect.max_retries == 0) return;

	/* is the retry time expired ? */
	if (now > conn->reconnect.previous + 30) {
		conn->reconnect.retries = 0;
		conn->reconnect.previous = now;
	}

	/* are we reconnectind too often and too fast? */
	if (conn->reconnect.retries > conn->reconnect.max_retries) return;

	/* keep track of the number of reconnections */
	conn->reconnect.retries++;

	/* reconnect */
	status = ldap_connect(conn, conn->reconnect.url);
	if ( ! NT_STATUS_IS_OK(status)) {
		return;
	}

	/* rebind */
	status = ldap_rebind(conn);
	if ( ! NT_STATUS_IS_OK(status)) {
		ldap_connection_dead(conn, status);
	}
}

static void ldap_request_destructor_abandon(struct ldap_request *abandon)
{
	TALLOC_FREE(abandon);
}

/* destroy an open ldap request */
static int ldap_request_destructor(struct ldap_request *req)
{
	if (req->state == LDAP_REQUEST_PENDING) {
		struct ldap_message msg = {
			.type = LDAP_TAG_AbandonRequest,
			.r.AbandonRequest.messageid = req->messageid,
		};
		struct ldap_request *abandon = NULL;

		DLIST_REMOVE(req->conn->pending, req);

		abandon = ldap_request_send(req->conn, &msg);
		if (abandon == NULL) {
			ldap_error_handler(req->conn, NT_STATUS_NO_MEMORY);
			return 0;
		}
		abandon->async.fn = ldap_request_destructor_abandon;
		abandon->async.private_data = NULL;
	}

	return 0;
}

static void ldap_request_timeout_abandon(struct ldap_request *abandon)
{
	struct ldap_request *req =
		talloc_get_type_abort(abandon->async.private_data,
		struct ldap_request);

	if (req->state == LDAP_REQUEST_PENDING) {
		DLIST_REMOVE(req->conn->pending, req);
	}
	req->state = LDAP_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
}

/*
  called on timeout of a ldap request
*/
static void ldap_request_timeout(struct tevent_context *ev, struct tevent_timer *te, 
				      struct timeval t, void *private_data)
{
	struct ldap_request *req =
		talloc_get_type_abort(private_data,
		struct ldap_request);

	req->status = NT_STATUS_IO_TIMEOUT;
	if (req->state == LDAP_REQUEST_PENDING) {
		struct ldap_message msg = {
			.type = LDAP_TAG_AbandonRequest,
			.r.AbandonRequest.messageid = req->messageid,
		};
		struct ldap_request *abandon = NULL;

		abandon = ldap_request_send(req->conn, &msg);
		if (abandon == NULL) {
			ldap_error_handler(req->conn, NT_STATUS_NO_MEMORY);
			return;
		}
		talloc_reparent(req->conn, req, abandon);
		abandon->async.fn = ldap_request_timeout_abandon;
		abandon->async.private_data = req;
		DLIST_REMOVE(req->conn->pending, req);
		return;
	}
	req->state = LDAP_REQUEST_DONE;
	if (req->async.fn) {
		req->async.fn(req);
	}
}


/*
  called on completion of a failed ldap request
*/
static void ldap_request_failed_complete(struct tevent_context *ev, struct tevent_timer *te,
				      struct timeval t, void *private_data)
{
	struct ldap_request *req =
		talloc_get_type_abort(private_data,
		struct ldap_request);

	if (req->async.fn) {
		req->async.fn(req);
	}
}

static void ldap_request_written(struct tevent_req *subreq);

/*
  send a ldap message - async interface
*/
_PUBLIC_ struct ldap_request *ldap_request_send(struct ldap_connection *conn,
				       struct ldap_message *msg)
{
	struct ldap_request *req;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	struct tevent_req *subreq = NULL;

	req = talloc_zero(conn, struct ldap_request);
	if (req == NULL) return NULL;

	if (conn->sockets.active == NULL) {
		status = NT_STATUS_INVALID_CONNECTION;
		goto failed;
	}

	req->state       = LDAP_REQUEST_SEND;
	req->conn        = conn;
	req->messageid   = conn->next_messageid++;
	if (conn->next_messageid == 0) {
		conn->next_messageid = 1;
	}
	req->type        = msg->type;
	if (req->messageid == -1) {
		goto failed;
	}

	talloc_set_destructor(req, ldap_request_destructor);

	msg->messageid = req->messageid;

	if (!ldap_encode(msg, samba_ldap_control_handlers(), &req->data, req)) {
		status = NT_STATUS_INTERNAL_ERROR;
		goto failed;		
	}

	/* put a timeout on the request */
	req->time_event = tevent_add_timer(conn->event.event_ctx, req,
					   timeval_current_ofs(conn->timeout, 0),
					   ldap_request_timeout, req);
	if (req->time_event == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	req->write_iov.iov_base = req->data.data;
	req->write_iov.iov_len = req->data.length;

	subreq = tstream_writev_queue_send(req, conn->event.event_ctx,
					   conn->sockets.active,
					   conn->sockets.send_queue,
					   &req->write_iov, 1);
	if (subreq == NULL) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}
	tevent_req_set_callback(subreq, ldap_request_written, req);

	req->state = LDAP_REQUEST_PENDING;
	DLIST_ADD(conn->pending, req);

	return req;

failed:
	req->status = status;
	req->state = LDAP_REQUEST_ERROR;
	tevent_add_timer(conn->event.event_ctx, req, timeval_zero(),
			 ldap_request_failed_complete, req);

	return req;
}

static void ldap_request_written(struct tevent_req *subreq)
{
	struct ldap_request *req =
		tevent_req_callback_data(subreq,
		struct ldap_request);
	int err;
	ssize_t ret;

	ret = tstream_writev_queue_recv(subreq, &err);
	TALLOC_FREE(subreq);
	if (ret == -1) {
		NTSTATUS error = map_nt_error_from_unix_common(err);
		ldap_error_handler(req->conn, error);
		return;
	}

	if (req->type == LDAP_TAG_AbandonRequest ||
	    req->type == LDAP_TAG_UnbindRequest)
	{
		if (req->state == LDAP_REQUEST_PENDING) {
			DLIST_REMOVE(req->conn->pending, req);
		}
		req->state = LDAP_REQUEST_DONE;
		if (req->async.fn) {
			req->async.fn(req);
		}
		return;
	}

	ldap_connection_recv_next(req->conn);
}


/*
  wait for a request to complete
  note that this does not destroy the request
*/
_PUBLIC_ NTSTATUS ldap_request_wait(struct ldap_request *req)
{
	while (req->state < LDAP_REQUEST_DONE) {
		if (tevent_loop_once(req->conn->event.event_ctx) != 0) {
			req->state = LDAP_REQUEST_ERROR;
			req->status = NT_STATUS_UNEXPECTED_NETWORK_ERROR;
			break;
		}
	}
	return req->status;
}


/*
  a mapping of ldap response code to strings
*/
static const struct {
	enum ldap_result_code code;
	const char *str;
} ldap_code_map[] = {
#define _LDAP_MAP_CODE(c) { c, #c }
	_LDAP_MAP_CODE(LDAP_SUCCESS),
	_LDAP_MAP_CODE(LDAP_OPERATIONS_ERROR),
	_LDAP_MAP_CODE(LDAP_PROTOCOL_ERROR),
	_LDAP_MAP_CODE(LDAP_TIME_LIMIT_EXCEEDED),
	_LDAP_MAP_CODE(LDAP_SIZE_LIMIT_EXCEEDED),
	_LDAP_MAP_CODE(LDAP_COMPARE_FALSE),
	_LDAP_MAP_CODE(LDAP_COMPARE_TRUE),
	_LDAP_MAP_CODE(LDAP_AUTH_METHOD_NOT_SUPPORTED),
	_LDAP_MAP_CODE(LDAP_STRONG_AUTH_REQUIRED),
	_LDAP_MAP_CODE(LDAP_REFERRAL),
	_LDAP_MAP_CODE(LDAP_ADMIN_LIMIT_EXCEEDED),
	_LDAP_MAP_CODE(LDAP_UNAVAILABLE_CRITICAL_EXTENSION),
	_LDAP_MAP_CODE(LDAP_CONFIDENTIALITY_REQUIRED),
	_LDAP_MAP_CODE(LDAP_SASL_BIND_IN_PROGRESS),
	_LDAP_MAP_CODE(LDAP_NO_SUCH_ATTRIBUTE),
	_LDAP_MAP_CODE(LDAP_UNDEFINED_ATTRIBUTE_TYPE),
	_LDAP_MAP_CODE(LDAP_INAPPROPRIATE_MATCHING),
	_LDAP_MAP_CODE(LDAP_CONSTRAINT_VIOLATION),
	_LDAP_MAP_CODE(LDAP_ATTRIBUTE_OR_VALUE_EXISTS),
	_LDAP_MAP_CODE(LDAP_INVALID_ATTRIBUTE_SYNTAX),
	_LDAP_MAP_CODE(LDAP_NO_SUCH_OBJECT),
	_LDAP_MAP_CODE(LDAP_ALIAS_PROBLEM),
	_LDAP_MAP_CODE(LDAP_INVALID_DN_SYNTAX),
	_LDAP_MAP_CODE(LDAP_ALIAS_DEREFERENCING_PROBLEM),
	_LDAP_MAP_CODE(LDAP_INAPPROPRIATE_AUTHENTICATION),
	_LDAP_MAP_CODE(LDAP_INVALID_CREDENTIALS),
	_LDAP_MAP_CODE(LDAP_INSUFFICIENT_ACCESS_RIGHTS),
	_LDAP_MAP_CODE(LDAP_BUSY),
	_LDAP_MAP_CODE(LDAP_UNAVAILABLE),
	_LDAP_MAP_CODE(LDAP_UNWILLING_TO_PERFORM),
	_LDAP_MAP_CODE(LDAP_LOOP_DETECT),
	_LDAP_MAP_CODE(LDAP_NAMING_VIOLATION),
	_LDAP_MAP_CODE(LDAP_OBJECT_CLASS_VIOLATION),
	_LDAP_MAP_CODE(LDAP_NOT_ALLOWED_ON_NON_LEAF),
	_LDAP_MAP_CODE(LDAP_NOT_ALLOWED_ON_RDN),
	_LDAP_MAP_CODE(LDAP_ENTRY_ALREADY_EXISTS),
	_LDAP_MAP_CODE(LDAP_OBJECT_CLASS_MODS_PROHIBITED),
	_LDAP_MAP_CODE(LDAP_AFFECTS_MULTIPLE_DSAS),
	_LDAP_MAP_CODE(LDAP_OTHER)
};

/*
  used to setup the status code from a ldap response
*/
_PUBLIC_ NTSTATUS ldap_check_response(struct ldap_connection *conn, struct ldap_Result *r)
{
	size_t i;
	const char *codename = "unknown";

	if (r->resultcode == LDAP_SUCCESS) {
		return NT_STATUS_OK;
	}

	if (conn->last_error) {
		talloc_free(conn->last_error);
	}

	for (i=0;i<ARRAY_SIZE(ldap_code_map);i++) {
		if ((enum ldap_result_code)r->resultcode == ldap_code_map[i].code) {
			codename = ldap_code_map[i].str;
			break;
		}
	}

	conn->last_error = talloc_asprintf(conn, "LDAP error %u %s - %s <%s> <%s>", 
					   r->resultcode,
					   codename,
					   r->dn?r->dn:"(NULL)", 
					   r->errormessage?r->errormessage:"", 
					   r->referral?r->referral:"");
	
	return NT_STATUS_LDAP(r->resultcode);
}

/*
  return error string representing the last error
*/
_PUBLIC_ const char *ldap_errstr(struct ldap_connection *conn, 
			TALLOC_CTX *mem_ctx, 
			NTSTATUS status)
{
	if (NT_STATUS_IS_LDAP(status) && conn->last_error != NULL) {
		return talloc_strdup(mem_ctx, conn->last_error);
	}
	return talloc_asprintf(mem_ctx, "LDAP client internal error: %s", nt_errstr(status));
}


/*
  return the Nth result message, waiting if necessary
*/
_PUBLIC_ NTSTATUS ldap_result_n(struct ldap_request *req, int n, struct ldap_message **msg)
{
	*msg = NULL;

	NT_STATUS_HAVE_NO_MEMORY(req);

	while (req->state < LDAP_REQUEST_DONE && n >= req->num_replies) {
		if (tevent_loop_once(req->conn->event.event_ctx) != 0) {
			return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
		}
	}

	if (n < req->num_replies) {
		*msg = req->replies[n];
		return NT_STATUS_OK;
	}

	if (!NT_STATUS_IS_OK(req->status)) {
		return req->status;
	}

	return NT_STATUS_NO_MORE_ENTRIES;
}


/*
  return a single result message, checking if it is of the expected LDAP type
*/
_PUBLIC_ NTSTATUS ldap_result_one(struct ldap_request *req, struct ldap_message **msg, int type)
{
	NTSTATUS status;
	status = ldap_result_n(req, 0, msg);
	if (!NT_STATUS_IS_OK(status)) {
		return status;
	}
	if ((*msg) != NULL && (*msg)->type != (enum ldap_request_tag)type) {
		*msg = NULL;
		return NT_STATUS_UNEXPECTED_NETWORK_ERROR;
	}
	return status;
}
