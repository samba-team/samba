/* 
   Unix SMB/CIFS implementation.
   
   WINS Replication server
   
   Copyright (C) Stefan Metzmacher	2005
   
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
#include "dlinklist.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "lib/messaging/irpc.h"
#include "librpc/gen_ndr/ndr_winsrepl.h"
#include "wrepl_server/wrepl_server.h"

void wreplsrv_terminate_connection(struct wreplsrv_in_connection *wreplconn, const char *reason)
{
	stream_terminate_connection(wreplconn->conn, reason);
}

/*
  called when we get a new connection
*/
static void wreplsrv_accept(struct stream_connection *conn)
{
	struct wreplsrv_service *service = talloc_get_type(conn->private, struct wreplsrv_service);
	struct wreplsrv_in_connection *wreplconn;

	wreplconn = talloc_zero(conn, struct wreplsrv_in_connection);
	if (!wreplconn) {
		stream_terminate_connection(conn, "wreplsrv_accept: out of memory");
		return;
	}

	wreplconn->conn		= conn;
	wreplconn->service	= service;
	wreplconn->our_ip	= socket_get_my_addr(conn->socket, wreplconn);
	if (!wreplconn->our_ip) {
		wreplsrv_terminate_connection(wreplconn, "wreplsrv_accept: out of memory");
		return;
	}

	/* TODO: find out if it's a partner */

	conn->private = wreplconn;

	irpc_add_name(conn->msg_ctx, "wreplsrv_connection");
}

/*
  receive some data on a WREPL connection
*/
static void wreplsrv_recv(struct stream_connection *conn, uint16_t flags)
{
	struct wreplsrv_in_connection *wreplconn = talloc_get_type(conn->private, struct wreplsrv_in_connection);
	struct wreplsrv_in_call *call;
	DATA_BLOB packet_in_blob;
	DATA_BLOB packet_out_blob;
	struct wrepl_wrap packet_out_wrap;
	struct data_blob_list_item *rep;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	size_t nread;

	/* avoid recursion, because of half async code */
	if (wreplconn->processing) {
		EVENT_FD_NOT_READABLE(conn->event.fde);
		return;
	}

	if (wreplconn->partial.length == 0) {
		wreplconn->partial = data_blob_talloc(wreplconn, NULL, 4);
		if (wreplconn->partial.data == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto failed;
		}
		wreplconn->partial_read = 0;
	}

	/* read in the packet length */
	if (wreplconn->partial_read < 4) {
		uint32_t packet_length;

		status = socket_recv(conn->socket, 
				     wreplconn->partial.data + wreplconn->partial_read,
				     4 - wreplconn->partial_read,
				     &nread, 0);
		if (NT_STATUS_IS_ERR(status)) goto failed;
		if (!NT_STATUS_IS_OK(status)) return;

		wreplconn->partial_read += nread;
		if (wreplconn->partial_read != 4) return;

		packet_length = RIVAL(wreplconn->partial.data, 0) + 4;

		wreplconn->partial.data = talloc_realloc(wreplconn, wreplconn->partial.data, 
							 uint8_t, packet_length);
		if (wreplconn->partial.data == NULL) {
			status = NT_STATUS_NO_MEMORY;
			goto failed;
		}
		wreplconn->partial.length = packet_length;
	}

	/* read in the body */
	status = socket_recv(conn->socket, 
			     wreplconn->partial.data + wreplconn->partial_read,
			     wreplconn->partial.length - wreplconn->partial_read,
			     &nread, 0);
	if (NT_STATUS_IS_ERR(status)) goto failed;
	if (!NT_STATUS_IS_OK(status)) return;

	wreplconn->partial_read += nread;
	if (wreplconn->partial_read != wreplconn->partial.length) return;

	packet_in_blob.data = wreplconn->partial.data + 4;
	packet_in_blob.length = wreplconn->partial.length - 4;

	call = talloc_zero(wreplconn, struct wreplsrv_in_call);
	if (!call) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}
	call->wreplconn = wreplconn;

	/* we have a full request - parse it */
	status = ndr_pull_struct_blob(&packet_in_blob,
				      call, &call->req_packet,
				      (ndr_pull_flags_fn_t)ndr_pull_wrepl_packet);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(2,("Failed to parse incoming WINS-Replication packet - %s\n",
			 nt_errstr(status)));
		DEBUG(10,("packet length %u\n", wreplconn->partial.length));
		NDR_PRINT_DEBUG(wrepl_packet, &call->req_packet);
		goto failed;
	}

	/*
	 * we have parsed the request, so we can reset the wreplconn->partial_read,
	 * maybe we could also free wreplconn->partial, but for now we keep it,
	 * and overwrite it the next time
	 */
	wreplconn->partial_read = 0;

	if (DEBUGLVL(10)) {
		DEBUG(10,("Received WINS-Replication packet of length %u\n", wreplconn->partial.length));
		NDR_PRINT_DEBUG(wrepl_packet, &call->req_packet);
	}

	/* actually process the request */
	wreplconn->processing = True;
	status = wreplsrv_in_call(call);
	wreplconn->processing = False;
	if (NT_STATUS_IS_ERR(status)) goto failed;
	if (!NT_STATUS_IS_OK(status)) {
		/* w2k just ignores invalid packets, so we do */
		DEBUG(10,("Received WINS-Replication packet was invalid, we just ignore it\n"));
		talloc_free(call);
		return;
	}

	/* and now encode the reply */
	packet_out_wrap.packet = call->rep_packet;
	status = ndr_push_struct_blob(&packet_out_blob, call, &packet_out_wrap,
				      (ndr_push_flags_fn_t)ndr_push_wrepl_wrap);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	if (DEBUGLVL(10)) {
		DEBUG(10,("Sending WINS-Replication packet of length %d\n", (int)packet_out_blob.length));
		NDR_PRINT_DEBUG(wrepl_packet, &call->rep_packet);
	}

	rep = talloc(wreplconn, struct data_blob_list_item);
	if (!rep) {
		status = NT_STATUS_NO_MEMORY;
		goto failed;
	}

	rep->blob = packet_out_blob;
	talloc_steal(rep, packet_out_blob.data);
	/* we don't need the call anymore */
	talloc_free(call);

	if (!wreplconn->send_queue) {
		EVENT_FD_WRITEABLE(conn->event.fde);
	}
	DLIST_ADD_END(wreplconn->send_queue, rep, struct data_blob_list_item *);

	if (wreplconn->terminate) {
		EVENT_FD_NOT_READABLE(conn->event.fde);
	} else {
		EVENT_FD_READABLE(conn->event.fde);
	}
	return;

failed:
	wreplsrv_terminate_connection(wreplconn, nt_errstr(status));
}

/*
  called when we can write to a connection
*/
static void wreplsrv_send(struct stream_connection *conn, uint16_t flags)
{
	struct wreplsrv_in_connection *wreplconn = talloc_get_type(conn->private, struct wreplsrv_in_connection);
	NTSTATUS status;

	while (wreplconn->send_queue) {
		struct data_blob_list_item *rep = wreplconn->send_queue;
		size_t sendlen;

		status = socket_send(conn->socket, &rep->blob, &sendlen, 0);
		if (NT_STATUS_IS_ERR(status)) goto failed;
		if (!NT_STATUS_IS_OK(status)) return;

		rep->blob.length -= sendlen;
		rep->blob.data   += sendlen;

		if (rep->blob.length == 0) {
			DLIST_REMOVE(wreplconn->send_queue, rep);
			talloc_free(rep);
		}
	}

	if (wreplconn->terminate) {
		wreplsrv_terminate_connection(wreplconn, "connection terminated after all pending packets are send");
		return;
	}

	EVENT_FD_NOT_WRITEABLE(conn->event.fde);
	return;

failed:
	wreplsrv_terminate_connection(wreplconn, nt_errstr(status));
}

static const struct stream_server_ops wreplsrv_stream_ops = {
	.name			= "wreplsrv",
	.accept_connection	= wreplsrv_accept,
	.recv_handler		= wreplsrv_recv,
	.send_handler		= wreplsrv_send,
};

/*
  startup the wrepl port 42 server sockets
*/
static NTSTATUS wreplsrv_setup_sockets(struct wreplsrv_service *service)
{
	NTSTATUS status;
	struct task_server *task = service->task;
	const struct model_ops *model_ops;
	const char *address;
	uint16_t port = WINS_REPLICATION_PORT;

	/* within the wrepl task we want to be a single process, so
	   ask for the single process model ops and pass these to the
	   stream_setup_socket() call. */
	model_ops = process_model_byname("single");
	if (!model_ops) {
		DEBUG(0,("Can't find 'single' process model_ops"));
		return NT_STATUS_INTERNAL_ERROR;
	}

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;

		/* We have been given an interfaces line, and been 
		   told to only bind to those interfaces. Create a
		   socket per interface and bind to only these.
		*/
		for(i = 0; i < num_interfaces; i++) {
			address = iface_n_ip(i);
			status = stream_setup_socket(task->event_ctx, model_ops, &wreplsrv_stream_ops,
						     "ipv4", address, &port, NULL);
			if (!NT_STATUS_IS_OK(status)) {
				DEBUG(0,("stream_setup_socket(address=%s,port=%u) failed - %s\n",
					 address, port, nt_errstr(status)));
				return status;
			}
		}
	} else {
		address = lp_socket_address();
		status = stream_setup_socket(task->event_ctx, model_ops, &wreplsrv_stream_ops,
					     "ipv4", address, &port, NULL);
		if (!NT_STATUS_IS_OK(status)) {
			DEBUG(0,("stream_setup_socket(address=%s,port=%u) failed - %s\n",
				 address, port, nt_errstr(status)));
			return status;
		}
	}

	return NT_STATUS_OK;
}

/*
  startup the wrepl task
*/
static void wreplsrv_task_init(struct task_server *task)
{
	NTSTATUS status;
	struct wreplsrv_service *service;

	service = talloc_zero(task, struct wreplsrv_service);
	if (!service) {
		task_server_terminate(task, "wreplsrv_task_init: out of memory");
		return;
	}
	service->task = task;
	task->private = service;

	/*
	 * TODO: setup up all partners, and open the winsdb
	 */

	/* 
	 * setup listen sockets, so we can anwser requests from our partners,
	 * which pull from us
	 */
	status = wreplsrv_setup_sockets(service);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "wreplsrv_task_init: wreplsrv_setup_sockets() failed");
		return;
	}

	/*
	 * TODO: setup timed events for each partner we want to pull from
	 */

	irpc_add_name(task->msg_ctx, "wrepl_server");
}

/*
  initialise the WREPL server
 */
static NTSTATUS wreplsrv_init(struct event_context *event_ctx, const struct model_ops *model_ops)
{
	return task_server_startup(event_ctx, model_ops, wreplsrv_task_init);
}

/*
  register ourselves as a available server
*/
NTSTATUS server_service_wrepl_init(void)
{
	return register_server_service("wrepl", wreplsrv_init);
}
