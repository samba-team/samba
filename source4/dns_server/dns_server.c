/*
   Unix SMB/CIFS implementation.

   DNS server startup

   Copyright (C) 2010 Kai Blin  <kai@samba.org>

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
#include "smbd/service_task.h"
#include "smbd/service.h"
#include "smbd/service_stream.h"
#include "smbd/process_model.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/util/tstream.h"
#include "libcli/util/ntstatus.h"
#include "system/network.h"
#include "lib/stream/packet.h"
#include "lib/socket/netif.h"
#include "dns_server/dns_server.h"
#include "param/param.h"
#include "librpc/ndr/libndr.h"
#include "librpc/gen_ndr/ndr_dns.h"
#include "librpc/gen_ndr/ndr_dnsp.h"
#include <ldb.h>
#include "dsdb/samdb/samdb.h"
#include "dsdb/common/util.h"
#include "auth/session.h"
#include "lib/util/dlinklist.h"
#include "lib/util/tevent_werror.h"
#include "auth/auth.h"
#include "auth/credentials/credentials.h"

#undef DBGC_CLASS
#define DBGC_CLASS DBGC_DNS

NTSTATUS server_service_dns_init(void);

/* hold information about one dns socket */
struct dns_socket {
	struct dns_server *dns;
	struct tsocket_address *local_address;
};

struct dns_udp_socket {
	struct dns_socket *dns_socket;
	struct tdgram_context *dgram;
	struct tevent_queue *send_queue;
};

/*
  state of an open tcp connection
*/
struct dns_tcp_connection {
	/* stream connection we belong to */
	struct stream_connection *conn;

	/* the dns_server the connection belongs to */
	struct dns_socket *dns_socket;

	struct tstream_context *tstream;

	struct tevent_queue *send_queue;
};

static void dns_tcp_terminate_connection(struct dns_tcp_connection *dnsconn, const char *reason)
{
	stream_terminate_connection(dnsconn->conn, reason);
}

static void dns_tcp_recv(struct stream_connection *conn, uint16_t flags)
{
	struct dns_tcp_connection *dnsconn = talloc_get_type(conn->private_data,
							     struct dns_tcp_connection);
	/* this should never be triggered! */
	dns_tcp_terminate_connection(dnsconn, "dns_tcp_recv: called");
}

static void dns_tcp_send(struct stream_connection *conn, uint16_t flags)
{
	struct dns_tcp_connection *dnsconn = talloc_get_type(conn->private_data,
							     struct dns_tcp_connection);
	/* this should never be triggered! */
	dns_tcp_terminate_connection(dnsconn, "dns_tcp_send: called");
}

struct dns_process_state {
	DATA_BLOB *in;
	struct dns_server *dns;
	struct dns_name_packet in_packet;
	struct dns_request_state state;
	uint16_t dns_err;
	struct dns_name_packet out_packet;
	DATA_BLOB out;
};

static void dns_process_done(struct tevent_req *subreq);

static struct tevent_req *dns_process_send(TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct dns_server *dns,
					   DATA_BLOB *in)
{
	struct tevent_req *req, *subreq;
	struct dns_process_state *state;
	enum ndr_err_code ndr_err;
	WERROR ret;
	const char *forwarder = lpcfg_dns_forwarder(dns->task->lp_ctx);
	req = tevent_req_create(mem_ctx, &state, struct dns_process_state);
	if (req == NULL) {
		return NULL;
	}
	state->in = in;

	state->dns = dns;

	if (in->length < 12) {
		tevent_req_werror(req, WERR_INVALID_PARAM);
		return tevent_req_post(req, ev);
	}
	dump_data_dbgc(DBGC_DNS, 8, in->data, in->length);

	ndr_err = ndr_pull_struct_blob(
		in, state, &state->in_packet,
		(ndr_pull_flags_fn_t)ndr_pull_dns_name_packet);

	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		state->dns_err = DNS_RCODE_FORMERR;
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}
	if (DEBUGLVLC(DBGC_DNS, 8)) {
		NDR_PRINT_DEBUGC(DBGC_DNS, dns_name_packet, &state->in_packet);
	}

	ret = dns_verify_tsig(dns, state, &state->state, &state->in_packet, in);
	if (!W_ERROR_IS_OK(ret)) {
		DEBUG(1, ("Failed to verify TSIG!\n"));
		state->dns_err = werr_to_dns_err(ret);
		tevent_req_done(req);
		return tevent_req_post(req, ev);
	}

	if (state->in_packet.operation & DNS_FLAG_REPLY) {
		DEBUG(1, ("Won't reply to replies.\n"));
		tevent_req_werror(req, WERR_INVALID_PARAM);
		return tevent_req_post(req, ev);
	}

	state->state.flags = state->in_packet.operation;
	state->state.flags |= DNS_FLAG_REPLY;

	
	if (forwarder && *forwarder) {
		state->state.flags |= DNS_FLAG_RECURSION_AVAIL;
	}

	state->out_packet = state->in_packet;

	switch (state->in_packet.operation & DNS_OPCODE) {
	case DNS_OPCODE_QUERY:
		subreq = dns_server_process_query_send(
			state, ev, dns, &state->state, &state->in_packet);
		if (tevent_req_nomem(subreq, req)) {
			return tevent_req_post(req, ev);
		}
		tevent_req_set_callback(subreq, dns_process_done, req);
		return req;
	case DNS_OPCODE_UPDATE:
		ret = dns_server_process_update(
			dns, &state->state, state, &state->in_packet,
			&state->out_packet.answers, &state->out_packet.ancount,
			&state->out_packet.nsrecs,  &state->out_packet.nscount,
			&state->out_packet.additional,
			&state->out_packet.arcount);
		break;
	default:
		ret = WERR_DNS_ERROR_RCODE_NOT_IMPLEMENTED;
	}
	if (!W_ERROR_IS_OK(ret)) {
		state->dns_err = werr_to_dns_err(ret);
	}
	tevent_req_done(req);
	return tevent_req_post(req, ev);
}

static void dns_process_done(struct tevent_req *subreq)
{
	struct tevent_req *req = tevent_req_callback_data(
		subreq, struct tevent_req);
	struct dns_process_state *state = tevent_req_data(
		req, struct dns_process_state);
	WERROR ret;

	ret = dns_server_process_query_recv(
		subreq, state,
		&state->out_packet.answers, &state->out_packet.ancount,
		&state->out_packet.nsrecs,  &state->out_packet.nscount,
		&state->out_packet.additional, &state->out_packet.arcount);
	TALLOC_FREE(subreq);

	if (!W_ERROR_IS_OK(ret)) {
		state->dns_err = werr_to_dns_err(ret);
	}
	tevent_req_done(req);
}

static WERROR dns_process_recv(struct tevent_req *req, TALLOC_CTX *mem_ctx,
			       DATA_BLOB *out)
{
	struct dns_process_state *state = tevent_req_data(
		req, struct dns_process_state);
	enum ndr_err_code ndr_err;
	WERROR ret;

	if (tevent_req_is_werror(req, &ret)) {
		return ret;
	}
	if (state->dns_err != DNS_RCODE_OK) {
		goto drop;
	}
	state->out_packet.operation |= state->state.flags;

	if (state->state.sign) {
		ret = dns_sign_tsig(state->dns, mem_ctx, &state->state,
				    &state->out_packet, 0);
		if (!W_ERROR_IS_OK(ret)) {
			state->dns_err = DNS_RCODE_SERVFAIL;
			goto drop;
		}
	}

	if (DEBUGLVLC(DBGC_DNS, 8)) {
		NDR_PRINT_DEBUGC(DBGC_DNS, dns_name_packet, &state->out_packet);
	}

	ndr_err = ndr_push_struct_blob(
		out, mem_ctx, &state->out_packet,
		(ndr_push_flags_fn_t)ndr_push_dns_name_packet);
	if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
		DEBUG(1, ("Failed to push packet: %s!\n",
			  ndr_errstr(ndr_err)));
		state->dns_err = DNS_RCODE_SERVFAIL;
		goto drop;
	}
	return WERR_OK;

drop:
	*out = data_blob_talloc(mem_ctx, state->in->data, state->in->length);
	if (out->data == NULL) {
		return WERR_NOMEM;
	}
	out->data[2] |= 0x80; /* Toggle DNS_FLAG_REPLY */
	out->data[3] |= state->dns_err;
	return WERR_OK;
}

struct dns_tcp_call {
	struct dns_tcp_connection *dns_conn;
	DATA_BLOB in;
	DATA_BLOB out;
	uint8_t out_hdr[4];
	struct iovec out_iov[2];
};

static void dns_tcp_call_process_done(struct tevent_req *subreq);
static void dns_tcp_call_writev_done(struct tevent_req *subreq);

static void dns_tcp_call_loop(struct tevent_req *subreq)
{
	struct dns_tcp_connection *dns_conn = tevent_req_callback_data(subreq,
				      struct dns_tcp_connection);
	struct dns_server *dns = dns_conn->dns_socket->dns;
	struct dns_tcp_call *call;
	NTSTATUS status;

	call = talloc(dns_conn, struct dns_tcp_call);
	if (call == NULL) {
		dns_tcp_terminate_connection(dns_conn, "dns_tcp_call_loop: "
				"no memory for dns_tcp_call");
		return;
	}
	call->dns_conn = dns_conn;

	status = tstream_read_pdu_blob_recv(subreq,
					    call,
					    &call->in);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		const char *reason;

		reason = talloc_asprintf(call, "dns_tcp_call_loop: "
					 "tstream_read_pdu_blob_recv() - %s",
					 nt_errstr(status));
		if (!reason) {
			reason = nt_errstr(status);
		}

		dns_tcp_terminate_connection(dns_conn, reason);
		return;
	}

	DEBUG(10,("Received DNS TCP packet of length %lu from %s\n",
		 (long) call->in.length,
		 tsocket_address_string(dns_conn->conn->remote_address, call)));

	/* skip length header */
	call->in.data += 2;
	call->in.length -= 2;

	subreq = dns_process_send(call, dns->task->event_ctx, dns,
				  &call->in);
	if (subreq == NULL) {
		dns_tcp_terminate_connection(
			dns_conn, "dns_tcp_call_loop: dns_process_send "
			"failed\n");
		return;
	}
	tevent_req_set_callback(subreq, dns_tcp_call_process_done, call);

	/*
	 * The dns tcp pdu's has the length as 2 byte (initial_read_size),
	 * packet_full_request_u16 provides the pdu length then.
	 */
	subreq = tstream_read_pdu_blob_send(dns_conn,
					    dns_conn->conn->event.ctx,
					    dns_conn->tstream,
					    2, /* initial_read_size */
					    packet_full_request_u16,
					    dns_conn);
	if (subreq == NULL) {
		dns_tcp_terminate_connection(dns_conn, "dns_tcp_call_loop: "
				"no memory for tstream_read_pdu_blob_send");
		return;
	}
	tevent_req_set_callback(subreq, dns_tcp_call_loop, dns_conn);
}

static void dns_tcp_call_process_done(struct tevent_req *subreq)
{
	struct dns_tcp_call *call = tevent_req_callback_data(subreq,
			struct dns_tcp_call);
	struct dns_tcp_connection *dns_conn = call->dns_conn;
	WERROR err;

	err = dns_process_recv(subreq, call, &call->out);
	TALLOC_FREE(subreq);
	if (!W_ERROR_IS_OK(err)) {
		DEBUG(1, ("dns_process returned %s\n", win_errstr(err)));
		dns_tcp_terminate_connection(dns_conn,
				"dns_tcp_call_loop: process function failed");
		return;
	}

	/* First add the length of the out buffer */
	RSSVAL(call->out_hdr, 0, call->out.length);
	call->out_iov[0].iov_base = (char *) call->out_hdr;
	call->out_iov[0].iov_len = 2;

	call->out_iov[1].iov_base = (char *) call->out.data;
	call->out_iov[1].iov_len = call->out.length;

	subreq = tstream_writev_queue_send(call,
					   dns_conn->conn->event.ctx,
					   dns_conn->tstream,
					   dns_conn->send_queue,
					   call->out_iov, 2);
	if (subreq == NULL) {
		dns_tcp_terminate_connection(dns_conn, "dns_tcp_call_loop: "
				"no memory for tstream_writev_queue_send");
		return;
	}
	tevent_req_set_callback(subreq, dns_tcp_call_writev_done, call);
}

static void dns_tcp_call_writev_done(struct tevent_req *subreq)
{
	struct dns_tcp_call *call = tevent_req_callback_data(subreq,
			struct dns_tcp_call);
	int sys_errno;
	int rc;

	rc = tstream_writev_queue_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (rc == -1) {
		const char *reason;

		reason = talloc_asprintf(call, "dns_tcp_call_writev_done: "
					 "tstream_writev_queue_recv() - %d:%s",
					 sys_errno, strerror(sys_errno));
		if (!reason) {
			reason = "dns_tcp_call_writev_done: tstream_writev_queue_recv() failed";
		}

		dns_tcp_terminate_connection(call->dns_conn, reason);
		return;
	}

	/* We don't care about errors */

	talloc_free(call);
}

/*
  called when we get a new connection
*/
static void dns_tcp_accept(struct stream_connection *conn)
{
	struct dns_socket *dns_socket;
	struct dns_tcp_connection *dns_conn;
	struct tevent_req *subreq;
	int rc;

	dns_conn = talloc_zero(conn, struct dns_tcp_connection);
	if (dns_conn == NULL) {
		stream_terminate_connection(conn,
				"dns_tcp_accept: out of memory");
		return;
	}

	dns_conn->send_queue = tevent_queue_create(conn, "dns_tcp_accept");
	if (dns_conn->send_queue == NULL) {
		stream_terminate_connection(conn,
				"dns_tcp_accept: out of memory");
		return;
	}

	dns_socket = talloc_get_type(conn->private_data, struct dns_socket);

	TALLOC_FREE(conn->event.fde);

	rc = tstream_bsd_existing_socket(dns_conn,
			socket_get_fd(conn->socket),
			&dns_conn->tstream);
	if (rc < 0) {
		stream_terminate_connection(conn,
				"dns_tcp_accept: out of memory");
		return;
	}

	dns_conn->conn = conn;
	dns_conn->dns_socket = dns_socket;
	conn->private_data = dns_conn;

	/*
	 * The dns tcp pdu's has the length as 2 byte (initial_read_size),
	 * packet_full_request_u16 provides the pdu length then.
	 */
	subreq = tstream_read_pdu_blob_send(dns_conn,
					    dns_conn->conn->event.ctx,
					    dns_conn->tstream,
					    2, /* initial_read_size */
					    packet_full_request_u16,
					    dns_conn);
	if (subreq == NULL) {
		dns_tcp_terminate_connection(dns_conn, "dns_tcp_accept: "
				"no memory for tstream_read_pdu_blob_send");
		return;
	}
	tevent_req_set_callback(subreq, dns_tcp_call_loop, dns_conn);
}

static const struct stream_server_ops dns_tcp_stream_ops = {
	.name			= "dns_tcp",
	.accept_connection	= dns_tcp_accept,
	.recv_handler		= dns_tcp_recv,
	.send_handler		= dns_tcp_send
};

struct dns_udp_call {
	struct dns_udp_socket *sock;
	struct tsocket_address *src;
	DATA_BLOB in;
	DATA_BLOB out;
};

static void dns_udp_call_process_done(struct tevent_req *subreq);
static void dns_udp_call_sendto_done(struct tevent_req *subreq);

static void dns_udp_call_loop(struct tevent_req *subreq)
{
	struct dns_udp_socket *sock = tevent_req_callback_data(subreq,
				      struct dns_udp_socket);
	struct dns_server *dns = sock->dns_socket->dns;
	struct dns_udp_call *call;
	uint8_t *buf;
	ssize_t len;
	int sys_errno;

	call = talloc(sock, struct dns_udp_call);
	if (call == NULL) {
		talloc_free(call);
		goto done;
	}
	call->sock = sock;

	len = tdgram_recvfrom_recv(subreq, &sys_errno,
				   call, &buf, &call->src);
	TALLOC_FREE(subreq);
	if (len == -1) {
		talloc_free(call);
		goto done;
	}

	call->in.data = buf;
	call->in.length = len;

	DEBUG(10,("Received DNS UDP packet of length %lu from %s\n",
		 (long)call->in.length,
		 tsocket_address_string(call->src, call)));

	subreq = dns_process_send(call, dns->task->event_ctx, dns,
				  &call->in);
	if (subreq == NULL) {
		TALLOC_FREE(call);
		goto done;
	}
	tevent_req_set_callback(subreq, dns_udp_call_process_done, call);

done:
	subreq = tdgram_recvfrom_send(sock,
				      sock->dns_socket->dns->task->event_ctx,
				      sock->dgram);
	if (subreq == NULL) {
		task_server_terminate(sock->dns_socket->dns->task,
				      "no memory for tdgram_recvfrom_send",
				      true);
		return;
	}
	tevent_req_set_callback(subreq, dns_udp_call_loop, sock);
}

static void dns_udp_call_process_done(struct tevent_req *subreq)
{
	struct dns_udp_call *call = tevent_req_callback_data(
		subreq, struct dns_udp_call);
	struct dns_udp_socket *sock = call->sock;
	struct dns_server *dns = sock->dns_socket->dns;
	WERROR err;

	err = dns_process_recv(subreq, call, &call->out);
	TALLOC_FREE(subreq);
	if (!W_ERROR_IS_OK(err)) {
		DEBUG(1, ("dns_process returned %s\n", win_errstr(err)));
		TALLOC_FREE(call);
		return;
	}

	subreq = tdgram_sendto_queue_send(call,
					  dns->task->event_ctx,
					  sock->dgram,
					  sock->send_queue,
					  call->out.data,
					  call->out.length,
					  call->src);
	if (subreq == NULL) {
		talloc_free(call);
		return;
	}
	tevent_req_set_callback(subreq, dns_udp_call_sendto_done, call);

}
static void dns_udp_call_sendto_done(struct tevent_req *subreq)
{
	struct dns_udp_call *call = tevent_req_callback_data(subreq,
				       struct dns_udp_call);
	int sys_errno;

	tdgram_sendto_queue_recv(subreq, &sys_errno);

	/* We don't care about errors */

	talloc_free(call);
}

/*
  start listening on the given address
*/
static NTSTATUS dns_add_socket(struct dns_server *dns,
			       const struct model_ops *model_ops,
			       const char *name,
			       const char *address,
			       uint16_t port)
{
	struct dns_socket *dns_socket;
	struct dns_udp_socket *dns_udp_socket;
	struct tevent_req *udpsubreq;
	NTSTATUS status;
	int ret;

	dns_socket = talloc(dns, struct dns_socket);
	NT_STATUS_HAVE_NO_MEMORY(dns_socket);

	dns_socket->dns = dns;

	ret = tsocket_address_inet_from_strings(dns_socket, "ip",
						address, port,
						&dns_socket->local_address);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(errno);
		return status;
	}

	status = stream_setup_socket(dns->task,
				     dns->task->event_ctx,
				     dns->task->lp_ctx,
				     model_ops,
				     &dns_tcp_stream_ops,
				     "ip", address, &port,
				     lpcfg_socket_options(dns->task->lp_ctx),
				     dns_socket);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%u TCP - %s\n",
			 address, port, nt_errstr(status)));
		talloc_free(dns_socket);
		return status;
	}

	dns_udp_socket = talloc(dns_socket, struct dns_udp_socket);
	NT_STATUS_HAVE_NO_MEMORY(dns_udp_socket);

	dns_udp_socket->dns_socket = dns_socket;

	ret = tdgram_inet_udp_socket(dns_socket->local_address,
				     NULL,
				     dns_udp_socket,
				     &dns_udp_socket->dgram);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(0,("Failed to bind to %s:%u UDP - %s\n",
			 address, port, nt_errstr(status)));
		return status;
	}

	dns_udp_socket->send_queue = tevent_queue_create(dns_udp_socket,
							 "dns_udp_send_queue");
	NT_STATUS_HAVE_NO_MEMORY(dns_udp_socket->send_queue);

	udpsubreq = tdgram_recvfrom_send(dns_udp_socket,
					 dns->task->event_ctx,
					 dns_udp_socket->dgram);
	NT_STATUS_HAVE_NO_MEMORY(udpsubreq);
	tevent_req_set_callback(udpsubreq, dns_udp_call_loop, dns_udp_socket);

	return NT_STATUS_OK;
}

/*
  setup our listening sockets on the configured network interfaces
*/
static NTSTATUS dns_startup_interfaces(struct dns_server *dns,
				       struct interface *ifaces)
{
	const struct model_ops *model_ops;
	int num_interfaces;
	TALLOC_CTX *tmp_ctx = talloc_new(dns);
	NTSTATUS status;
	int i;

	/* within the dns task we want to be a single process, so
	   ask for the single process model ops and pass these to the
	   stream_setup_socket() call. */
	model_ops = process_model_startup("single");
	if (!model_ops) {
		DEBUG(0,("Can't find 'single' process model_ops\n"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (ifaces != NULL) {
		num_interfaces = iface_list_count(ifaces);

		for (i=0; i<num_interfaces; i++) {
			const char *address = talloc_strdup(tmp_ctx,
							    iface_list_n_ip(ifaces, i));

			status = dns_add_socket(dns, model_ops, "dns", address,
						DNS_SERVICE_PORT);
			NT_STATUS_NOT_OK_RETURN(status);
		}
	} else {
		int num_binds = 0;
		char **wcard;
		wcard = iface_list_wildcard(tmp_ctx);
		if (wcard == NULL) {
			DEBUG(0, ("No wildcard address available\n"));
			return NT_STATUS_INTERNAL_ERROR;
		}
		for (i = 0; wcard[i] != NULL; i++) {
			status = dns_add_socket(dns, model_ops, "dns", wcard[i],
						DNS_SERVICE_PORT);
			if (NT_STATUS_IS_OK(status)) {
				num_binds++;
			}
		}
		if (num_binds == 0) {
			talloc_free(tmp_ctx);
			return NT_STATUS_INVALID_PARAMETER_MIX;
		}
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

static int dns_server_sort_zones(struct ldb_message **m1, struct ldb_message **m2)
{
	const char *n1, *n2;
	size_t l1, l2;

	n1 = ldb_msg_find_attr_as_string(*m1, "name", NULL);
	n2 = ldb_msg_find_attr_as_string(*m2, "name", NULL);

	l1 = strlen(n1);
	l2 = strlen(n2);

	/* If the string lengths are not equal just sort by length */
	if (l1 != l2) {
		/* If m1 is the larger zone name, return it first */
		return l2 - l1;
	}

	/*TODO: We need to compare DNs here, we want the DomainDNSZones first */
	return 0;
}

static struct dns_server_tkey_store *tkey_store_init(TALLOC_CTX *mem_ctx,
						     uint16_t size)
{
	struct dns_server_tkey_store *buffer = talloc_zero(mem_ctx,
						struct dns_server_tkey_store);

	if (buffer == NULL) {
		return NULL;
	}

	buffer->size = size;
	buffer->next_idx = 0;

	buffer->tkeys = talloc_zero_array(buffer, struct dns_server_tkey *, size);
	if (buffer->tkeys == NULL) {
		TALLOC_FREE(buffer);
	}

	return buffer;
}

static void dns_task_init(struct task_server *task)
{
	struct dns_server *dns;
	NTSTATUS status;
	struct interface *ifaces = NULL;
	int ret;
	struct ldb_result *res;
	static const char * const attrs[] = { "name", NULL};
	static const char * const attrs_none[] = { NULL};
	unsigned int i;
	struct ldb_message *dns_acc;
	char *hostname_lower;
	char *dns_spn;

	switch (lpcfg_server_role(task->lp_ctx)) {
	case ROLE_STANDALONE:
		task_server_terminate(task, "dns: no DNS required in standalone configuration", false);
		return;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task, "dns: no DNS required in member server configuration", false);
		return;
	case ROLE_ACTIVE_DIRECTORY_DC:
		/* Yes, we want a DNS */
		break;
	}

	if (lpcfg_interfaces(task->lp_ctx) && lpcfg_bind_interfaces_only(task->lp_ctx)) {
		load_interface_list(task, task->lp_ctx, &ifaces);

		if (iface_list_count(ifaces) == 0) {
			task_server_terminate(task, "dns: no network interfaces configured", false);
			return;
		}
	}

	task_server_set_title(task, "task[dns]");

	dns = talloc_zero(task, struct dns_server);
	if (dns == NULL) {
		task_server_terminate(task, "dns: out of memory", true);
		return;
	}

	dns->task = task;
	/*FIXME: Make this a configurable option */
	dns->max_payload = 4096;

	dns->server_credentials = cli_credentials_init(dns);
	if (!dns->server_credentials) {
		task_server_terminate(task, "Failed to init server credentials\n", true);
		return;
	}

	dns->samdb = samdb_connect(dns, dns->task->event_ctx, dns->task->lp_ctx,
			      system_session(dns->task->lp_ctx), 0);
	if (!dns->samdb) {
		task_server_terminate(task, "dns: samdb_connect failed", true);
		return;
	}

	cli_credentials_set_conf(dns->server_credentials, task->lp_ctx);

	hostname_lower = strlower_talloc(dns, lpcfg_netbios_name(task->lp_ctx));
	dns_spn = talloc_asprintf(dns, "DNS/%s.%s",
				  hostname_lower,
				  lpcfg_dnsdomain(task->lp_ctx));
	TALLOC_FREE(hostname_lower);

	ret = dsdb_search_one(dns->samdb, dns, &dns_acc,
			      ldb_get_default_basedn(dns->samdb), LDB_SCOPE_SUBTREE,
			      attrs_none, 0, "(servicePrincipalName=%s)",
			      dns_spn);
	if (ret == LDB_SUCCESS) {
		TALLOC_FREE(dns_acc);
		if (!dns_spn) {
			task_server_terminate(task, "dns: talloc_asprintf failed", true);
			return;
		}
		status = cli_credentials_set_stored_principal(dns->server_credentials, task->lp_ctx, dns_spn);
		if (!NT_STATUS_IS_OK(status)) {
			task_server_terminate(task,
					      talloc_asprintf(task, "Failed to obtain server credentials for DNS, "
							      "despite finding it in the samdb! %s\n",
							      nt_errstr(status)),
					      true);
			return;
		}
	} else {
		TALLOC_FREE(dns_spn);
		status = cli_credentials_set_machine_account(dns->server_credentials, task->lp_ctx);
		if (!NT_STATUS_IS_OK(status)) {
			task_server_terminate(task,
					      talloc_asprintf(task, "Failed to obtain server credentials, perhaps a standalone server?: %s\n",
							      nt_errstr(status)),
					      true);
			return;
		}
	}

	dns->tkeys = tkey_store_init(dns, TKEY_BUFFER_SIZE);
	if (!dns->tkeys) {
		task_server_terminate(task, "Failed to allocate tkey storage\n", true);
		return;
	}

	// TODO: this search does not work against windows
	ret = dsdb_search(dns->samdb, dns, &res, NULL, LDB_SCOPE_SUBTREE,
			  attrs, DSDB_SEARCH_SEARCH_ALL_PARTITIONS, "(objectClass=dnsZone)");
	if (ret != LDB_SUCCESS) {
		task_server_terminate(task,
				      "dns: failed to look up root DNS zones",
				      true);
		return;
	}

	TYPESAFE_QSORT(res->msgs, res->count, dns_server_sort_zones);

	for (i=0; i < res->count; i++) {
		struct dns_server_zone *z;

		z = talloc_zero(dns, struct dns_server_zone);
		if (z == NULL) {
			task_server_terminate(task, "dns failed to allocate memory", true);
		}

		z->name = ldb_msg_find_attr_as_string(res->msgs[i], "name", NULL);
		z->dn = talloc_move(z, &res->msgs[i]->dn);
		/*
		 * Ignore the RootDNSServers zone and zones that we don't support yet
		 * RootDNSServers should never be returned (Windows DNS server don't)
		 * ..TrustAnchors should never be returned as is, (Windows returns
		 * TrustAnchors) and for the moment we don't support DNSSEC so we'd better
		 * not return this zone.
		 */
		if ((strcmp(z->name, "RootDNSServers") == 0) ||
		    (strcmp(z->name, "..TrustAnchors") == 0))
		{
			DEBUG(10, ("Ignoring zone %s\n", z->name));
			talloc_free(z);
			continue;
		}
		DLIST_ADD_END(dns->zones, z, NULL);
	}

	status = dns_startup_interfaces(dns, ifaces);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "dns failed to setup interfaces", true);
		return;
	}
}

NTSTATUS server_service_dns_init(void)
{
	return register_server_service("dns", dns_task_init);
}
