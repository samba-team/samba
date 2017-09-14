/*
   Unix SMB/CIFS implementation.

   KDC related functions

   Copyright (c) 2005-2008 Andrew Bartlett <abartlet@samba.org>
   Copyright (c) 2005      Andrew Tridgell <tridge@samba.org>
   Copyright (c) 2005      Stefan Metzmacher <metze@samba.org>

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
#include "param/param.h"
#include "smbd/process_model.h"
#include "lib/tsocket/tsocket.h"
#include "libcli/util/tstream.h"
#include "kdc/kdc-server.h"
#include "kdc/kdc-proxy.h"
#include "lib/stream/packet.h"

/*
 * State of an open tcp connection
 */
struct kdc_tcp_connection {
	/* stream connection we belong to */
	struct stream_connection *conn;

	/* the kdc_server the connection belongs to */
	struct kdc_socket *kdc_socket;

	struct tstream_context *tstream;

	struct tevent_queue *send_queue;
};

struct kdc_tcp_call {
	struct kdc_tcp_connection *kdc_conn;
	DATA_BLOB in;
	DATA_BLOB out;
	uint8_t out_hdr[4];
	struct iovec out_iov[2];
};

struct kdc_udp_call {
	struct kdc_udp_socket *sock;
	struct tsocket_address *src;
	DATA_BLOB in;
	DATA_BLOB out;
};

static void kdc_udp_call_proxy_done(struct tevent_req *subreq);
static void kdc_udp_call_sendto_done(struct tevent_req *subreq);

static void kdc_tcp_call_writev_done(struct tevent_req *subreq);
static void kdc_tcp_call_proxy_done(struct tevent_req *subreq);

static void kdc_tcp_terminate_connection(struct kdc_tcp_connection *kdc_conn,
					 const char *reason)
{
	stream_terminate_connection(kdc_conn->conn, reason);
}

static NTSTATUS kdc_proxy_unavailable_error(struct kdc_server *kdc,
					    TALLOC_CTX *mem_ctx,
					    DATA_BLOB *out)
{
	krb5_error_code code;
	krb5_data enc_error;

	code = smb_krb5_mk_error(kdc->smb_krb5_context->krb5_context,
				 KRB5KDC_ERR_SVC_UNAVAILABLE,
				 NULL,
				 NULL,
				 NULL,
				 NULL,
				 &enc_error);
	if (code != 0) {
		DBG_WARNING("Unable to form krb5 error reply\n");
		return NT_STATUS_INTERNAL_ERROR;
	}

	*out = data_blob_talloc(mem_ctx, enc_error.data, enc_error.length);
	smb_krb5_free_data_contents(kdc->smb_krb5_context->krb5_context,
				    &enc_error);
	if (!out->data) {
		return NT_STATUS_NO_MEMORY;
	}

	return NT_STATUS_OK;
}

static void kdc_udp_call_loop(struct tevent_req *subreq)
{
	struct kdc_udp_socket *sock = tevent_req_callback_data(subreq,
				      struct kdc_udp_socket);
	struct kdc_udp_call *call;
	uint8_t *buf;
	ssize_t len;
	int sys_errno;
	kdc_code ret;

	call = talloc(sock, struct kdc_udp_call);
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

	DEBUG(10,("Received krb5 UDP packet of length %lu from %s\n",
		 (long)call->in.length,
		 tsocket_address_string(call->src, call)));

	/* Call krb5 */
	ret = sock->kdc_socket->process(sock->kdc_socket->kdc,
				       call,
				       &call->in,
				       &call->out,
				       call->src,
				       sock->kdc_socket->local_address,
				       1 /* Datagram */);
	if (ret == KDC_ERROR) {
		talloc_free(call);
		goto done;
	}

	if (ret == KDC_PROXY_REQUEST) {
		uint16_t port;

		if (!sock->kdc_socket->kdc->am_rodc) {
			DEBUG(0,("kdc_udp_call_loop: proxying requested when not RODC"));
			talloc_free(call);
			goto done;
		}

		port = tsocket_address_inet_port(sock->kdc_socket->local_address);

		subreq = kdc_udp_proxy_send(call,
					    sock->kdc_socket->kdc->task->event_ctx,
					    sock->kdc_socket->kdc,
					    port,
					    call->in);
		if (subreq == NULL) {
			talloc_free(call);
			goto done;
		}
		tevent_req_set_callback(subreq, kdc_udp_call_proxy_done, call);
		goto done;
	}

	subreq = tdgram_sendto_queue_send(call,
					  sock->kdc_socket->kdc->task->event_ctx,
					  sock->dgram,
					  sock->send_queue,
					  call->out.data,
					  call->out.length,
					  call->src);
	if (subreq == NULL) {
		talloc_free(call);
		goto done;
	}
	tevent_req_set_callback(subreq, kdc_udp_call_sendto_done, call);

done:
	subreq = tdgram_recvfrom_send(sock,
				      sock->kdc_socket->kdc->task->event_ctx,
				      sock->dgram);
	if (subreq == NULL) {
		task_server_terminate(sock->kdc_socket->kdc->task,
				      "no memory for tdgram_recvfrom_send",
				      true);
		return;
	}
	tevent_req_set_callback(subreq, kdc_udp_call_loop, sock);
}

static void kdc_udp_call_proxy_done(struct tevent_req *subreq)
{
	struct kdc_udp_call *call =
		tevent_req_callback_data(subreq,
		struct kdc_udp_call);
	NTSTATUS status;

	status = kdc_udp_proxy_recv(subreq, call, &call->out);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		/* generate an error packet */
		status = kdc_proxy_unavailable_error(call->sock->kdc_socket->kdc,
						     call, &call->out);
	}

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(call);
		return;
	}

	subreq = tdgram_sendto_queue_send(call,
					  call->sock->kdc_socket->kdc->task->event_ctx,
					  call->sock->dgram,
					  call->sock->send_queue,
					  call->out.data,
					  call->out.length,
					  call->src);
	if (subreq == NULL) {
		talloc_free(call);
		return;
	}

	tevent_req_set_callback(subreq, kdc_udp_call_sendto_done, call);
}

static void kdc_udp_call_sendto_done(struct tevent_req *subreq)
{
	struct kdc_udp_call *call = tevent_req_callback_data(subreq,
				       struct kdc_udp_call);
	int sys_errno;

	tdgram_sendto_queue_recv(subreq, &sys_errno);

	/* We don't care about errors */

	talloc_free(call);
}

static void kdc_tcp_call_loop(struct tevent_req *subreq)
{
	struct kdc_tcp_connection *kdc_conn = tevent_req_callback_data(subreq,
				      struct kdc_tcp_connection);
	struct kdc_tcp_call *call;
	NTSTATUS status;
	kdc_code ret;

	call = talloc(kdc_conn, struct kdc_tcp_call);
	if (call == NULL) {
		kdc_tcp_terminate_connection(kdc_conn, "kdc_tcp_call_loop: "
				"no memory for kdc_tcp_call");
		return;
	}
	call->kdc_conn = kdc_conn;

	status = tstream_read_pdu_blob_recv(subreq,
					    call,
					    &call->in);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		const char *reason;

		reason = talloc_asprintf(call, "kdc_tcp_call_loop: "
					 "tstream_read_pdu_blob_recv() - %s",
					 nt_errstr(status));
		if (!reason) {
			reason = nt_errstr(status);
		}

		kdc_tcp_terminate_connection(kdc_conn, reason);
		return;
	}

	DEBUG(10,("Received krb5 TCP packet of length %lu from %s\n",
		 (long) call->in.length,
		 tsocket_address_string(kdc_conn->conn->remote_address, call)));

	/* skip length header */
	call->in.data +=4;
	call->in.length -= 4;

	/* Call krb5 */
	ret = kdc_conn->kdc_socket->process(kdc_conn->kdc_socket->kdc,
					   call,
					   &call->in,
					   &call->out,
					   kdc_conn->conn->remote_address,
					   kdc_conn->conn->local_address,
					   0 /* Stream */);
	if (ret == KDC_ERROR) {
		kdc_tcp_terminate_connection(kdc_conn,
				"kdc_tcp_call_loop: process function failed");
		return;
	}

	if (ret == KDC_PROXY_REQUEST) {
		uint16_t port;

		if (!kdc_conn->kdc_socket->kdc->am_rodc) {
			kdc_tcp_terminate_connection(kdc_conn,
						     "kdc_tcp_call_loop: proxying requested when not RODC");
			return;
		}
		port = tsocket_address_inet_port(kdc_conn->conn->local_address);

		subreq = kdc_tcp_proxy_send(call,
					    kdc_conn->conn->event.ctx,
					    kdc_conn->kdc_socket->kdc,
					    port,
					    call->in);
		if (subreq == NULL) {
			kdc_tcp_terminate_connection(kdc_conn,
				"kdc_tcp_call_loop: kdc_tcp_proxy_send failed");
			return;
		}
		tevent_req_set_callback(subreq, kdc_tcp_call_proxy_done, call);
		return;
	}

	/* First add the length of the out buffer */
	RSIVAL(call->out_hdr, 0, call->out.length);
	call->out_iov[0].iov_base = (char *) call->out_hdr;
	call->out_iov[0].iov_len = 4;

	call->out_iov[1].iov_base = (char *) call->out.data;
	call->out_iov[1].iov_len = call->out.length;

	subreq = tstream_writev_queue_send(call,
					   kdc_conn->conn->event.ctx,
					   kdc_conn->tstream,
					   kdc_conn->send_queue,
					   call->out_iov, 2);
	if (subreq == NULL) {
		kdc_tcp_terminate_connection(kdc_conn, "kdc_tcp_call_loop: "
				"no memory for tstream_writev_queue_send");
		return;
	}
	tevent_req_set_callback(subreq, kdc_tcp_call_writev_done, call);

	/*
	 * The krb5 tcp pdu's has the length as 4 byte (initial_read_size),
	 * packet_full_request_u32 provides the pdu length then.
	 */
	subreq = tstream_read_pdu_blob_send(kdc_conn,
					    kdc_conn->conn->event.ctx,
					    kdc_conn->tstream,
					    4, /* initial_read_size */
					    packet_full_request_u32,
					    kdc_conn);
	if (subreq == NULL) {
		kdc_tcp_terminate_connection(kdc_conn, "kdc_tcp_call_loop: "
				"no memory for tstream_read_pdu_blob_send");
		return;
	}
	tevent_req_set_callback(subreq, kdc_tcp_call_loop, kdc_conn);
}

static void kdc_tcp_call_proxy_done(struct tevent_req *subreq)
{
	struct kdc_tcp_call *call = tevent_req_callback_data(subreq,
			struct kdc_tcp_call);
	struct kdc_tcp_connection *kdc_conn = call->kdc_conn;
	NTSTATUS status;

	status = kdc_tcp_proxy_recv(subreq, call, &call->out);
	TALLOC_FREE(subreq);
	if (!NT_STATUS_IS_OK(status)) {
		/* generate an error packet */
		status = kdc_proxy_unavailable_error(kdc_conn->kdc_socket->kdc,
						     call, &call->out);
	}

	if (!NT_STATUS_IS_OK(status)) {
		const char *reason;

		reason = talloc_asprintf(call, "kdc_tcp_call_proxy_done: "
					 "kdc_proxy_unavailable_error - %s",
					 nt_errstr(status));
		if (!reason) {
			reason = "kdc_tcp_call_proxy_done: kdc_proxy_unavailable_error() failed";
		}

		kdc_tcp_terminate_connection(call->kdc_conn, reason);
		return;
	}

	/* First add the length of the out buffer */
	RSIVAL(call->out_hdr, 0, call->out.length);
	call->out_iov[0].iov_base = (char *) call->out_hdr;
	call->out_iov[0].iov_len = 4;

	call->out_iov[1].iov_base = (char *) call->out.data;
	call->out_iov[1].iov_len = call->out.length;

	subreq = tstream_writev_queue_send(call,
					   kdc_conn->conn->event.ctx,
					   kdc_conn->tstream,
					   kdc_conn->send_queue,
					   call->out_iov, 2);
	if (subreq == NULL) {
		kdc_tcp_terminate_connection(kdc_conn, "kdc_tcp_call_loop: "
				"no memory for tstream_writev_queue_send");
		return;
	}
	tevent_req_set_callback(subreq, kdc_tcp_call_writev_done, call);

	/*
	 * The krb5 tcp pdu's has the length as 4 byte (initial_read_size),
	 * packet_full_request_u32 provides the pdu length then.
	 */
	subreq = tstream_read_pdu_blob_send(kdc_conn,
					    kdc_conn->conn->event.ctx,
					    kdc_conn->tstream,
					    4, /* initial_read_size */
					    packet_full_request_u32,
					    kdc_conn);
	if (subreq == NULL) {
		kdc_tcp_terminate_connection(kdc_conn, "kdc_tcp_call_loop: "
				"no memory for tstream_read_pdu_blob_send");
		return;
	}
	tevent_req_set_callback(subreq, kdc_tcp_call_loop, kdc_conn);
}

static void kdc_tcp_call_writev_done(struct tevent_req *subreq)
{
	struct kdc_tcp_call *call = tevent_req_callback_data(subreq,
			struct kdc_tcp_call);
	int sys_errno;
	int rc;

	rc = tstream_writev_queue_recv(subreq, &sys_errno);
	TALLOC_FREE(subreq);
	if (rc == -1) {
		const char *reason;

		reason = talloc_asprintf(call, "kdc_tcp_call_writev_done: "
					 "tstream_writev_queue_recv() - %d:%s",
					 sys_errno, strerror(sys_errno));
		if (!reason) {
			reason = "kdc_tcp_call_writev_done: tstream_writev_queue_recv() failed";
		}

		kdc_tcp_terminate_connection(call->kdc_conn, reason);
		return;
	}

	/* We don't care about errors */

	talloc_free(call);
}

/*
  called when we get a new connection
*/
static void kdc_tcp_accept(struct stream_connection *conn)
{
	struct kdc_socket *kdc_socket;
	struct kdc_tcp_connection *kdc_conn;
	struct tevent_req *subreq;
	int rc;

	kdc_conn = talloc_zero(conn, struct kdc_tcp_connection);
	if (kdc_conn == NULL) {
		stream_terminate_connection(conn,
				"kdc_tcp_accept: out of memory");
		return;
	}

	kdc_conn->send_queue = tevent_queue_create(conn, "kdc_tcp_accept");
	if (kdc_conn->send_queue == NULL) {
		stream_terminate_connection(conn,
				"kdc_tcp_accept: out of memory");
		return;
	}

	kdc_socket = talloc_get_type(conn->private_data, struct kdc_socket);

	TALLOC_FREE(conn->event.fde);

	rc = tstream_bsd_existing_socket(kdc_conn,
			socket_get_fd(conn->socket),
			&kdc_conn->tstream);
	if (rc < 0) {
		stream_terminate_connection(conn,
				"kdc_tcp_accept: out of memory");
		return;
	}

	kdc_conn->conn = conn;
	kdc_conn->kdc_socket = kdc_socket;
	conn->private_data = kdc_conn;

	/*
	 * The krb5 tcp pdu's has the length as 4 byte (initial_read_size),
	 * packet_full_request_u32 provides the pdu length then.
	 */
	subreq = tstream_read_pdu_blob_send(kdc_conn,
					    kdc_conn->conn->event.ctx,
					    kdc_conn->tstream,
					    4, /* initial_read_size */
					    packet_full_request_u32,
					    kdc_conn);
	if (subreq == NULL) {
		kdc_tcp_terminate_connection(kdc_conn, "kdc_tcp_accept: "
				"no memory for tstream_read_pdu_blob_send");
		return;
	}
	tevent_req_set_callback(subreq, kdc_tcp_call_loop, kdc_conn);
}

static void kdc_tcp_recv(struct stream_connection *conn, uint16_t flags)
{
	struct kdc_tcp_connection *kdcconn = talloc_get_type(conn->private_data,
							     struct kdc_tcp_connection);
	/* this should never be triggered! */
	kdc_tcp_terminate_connection(kdcconn, "kdc_tcp_recv: called");
}

static void kdc_tcp_send(struct stream_connection *conn, uint16_t flags)
{
	struct kdc_tcp_connection *kdcconn = talloc_get_type(conn->private_data,
							     struct kdc_tcp_connection);
	/* this should never be triggered! */
	kdc_tcp_terminate_connection(kdcconn, "kdc_tcp_send: called");
}

static const struct stream_server_ops kdc_tcp_stream_ops = {
	.name			= "kdc_tcp",
	.accept_connection	= kdc_tcp_accept,
	.recv_handler		= kdc_tcp_recv,
	.send_handler		= kdc_tcp_send
};

/*
 * Start listening on the given address
 */
NTSTATUS kdc_add_socket(struct kdc_server *kdc,
			const struct model_ops *model_ops,
			const char *name,
			const char *address,
			uint16_t port,
			kdc_process_fn_t process,
			bool udp_only)
{
	struct kdc_socket *kdc_socket;
	struct kdc_udp_socket *kdc_udp_socket;
	struct tevent_req *udpsubreq;
	NTSTATUS status;
	int ret;

	kdc_socket = talloc(kdc, struct kdc_socket);
	NT_STATUS_HAVE_NO_MEMORY(kdc_socket);

	kdc_socket->kdc = kdc;
	kdc_socket->process = process;

	ret = tsocket_address_inet_from_strings(kdc_socket, "ip",
						address, port,
						&kdc_socket->local_address);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(errno);
		return status;
	}

	if (!udp_only) {
		status = stream_setup_socket(kdc->task,
					     kdc->task->event_ctx,
					     kdc->task->lp_ctx,
					     model_ops,
					     &kdc_tcp_stream_ops,
					     "ip", address, &port,
					     lpcfg_socket_options(kdc->task->lp_ctx),
					     kdc_socket,
					     kdc->task->process_context);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("Failed to bind to %s:%u TCP - %s\n",
				 address, port, nt_errstr(status)));
			talloc_free(kdc_socket);
			return status;
		}
	}

	kdc_udp_socket = talloc(kdc_socket, struct kdc_udp_socket);
	NT_STATUS_HAVE_NO_MEMORY(kdc_udp_socket);

	kdc_udp_socket->kdc_socket = kdc_socket;

	ret = tdgram_inet_udp_socket(kdc_socket->local_address,
				     NULL,
				     kdc_udp_socket,
				     &kdc_udp_socket->dgram);
	if (ret != 0) {
		status = map_nt_error_from_unix_common(errno);
		DEBUG(0,("Failed to bind to %s:%u UDP - %s\n",
			 address, port, nt_errstr(status)));
		return status;
	}

	kdc_udp_socket->send_queue = tevent_queue_create(kdc_udp_socket,
							 "kdc_udp_send_queue");
	NT_STATUS_HAVE_NO_MEMORY(kdc_udp_socket->send_queue);

	udpsubreq = tdgram_recvfrom_send(kdc_udp_socket,
					 kdc->task->event_ctx,
					 kdc_udp_socket->dgram);
	NT_STATUS_HAVE_NO_MEMORY(udpsubreq);
	tevent_req_set_callback(udpsubreq, kdc_udp_call_loop, kdc_udp_socket);

	return NT_STATUS_OK;
}
