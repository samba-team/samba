/* 
   Unix SMB/CIFS implementation.
   Main winbindd server routines

   Copyright (C) Stefan Metzmacher	2005
   Copyright (C) Andrew Tridgell	2005
   
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
#include "lib/socket/socket.h"
#include "system/dir.h"
#include "system/filesys.h"
#include "dlinklist.h"
#include "lib/events/events.h"
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "nsswitch/winbind_nss_config.h"
#include "nsswitch/winbindd_nss.h"
#include "winbind/wb_server.h"

void wbsrv_terminate_connection(struct wbsrv_connection *wbconn, const char *reason)
{
	stream_terminate_connection(wbconn->conn, reason);
}

/*
  called when we get a new connection
*/
static void wbsrv_accept(struct stream_connection *conn)
{
	struct wbsrv_listen_socket *listen_socket =
		talloc_get_type(conn->private, struct wbsrv_listen_socket);
	struct wbsrv_connection *wbconn;

	wbconn = talloc_zero(conn, struct wbsrv_connection);
	if (!wbconn) {
		stream_terminate_connection(conn,
					    "wbsrv_accept: out of memory");
		return;
	}
	wbconn->conn		= conn;
	wbconn->listen_socket	= listen_socket;
	conn->private = wbconn;
}

/*
  receive some data on a winbind connection
*/
static void wbsrv_recv(struct stream_connection *conn, uint16_t flags)
{
	struct wbsrv_connection *wbconn =
		talloc_get_type(conn->private, struct wbsrv_connection);
	const struct wbsrv_protocol_ops *ops = wbconn->listen_socket->ops;
	struct wbsrv_call *call;
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	size_t nread;

	/* avoid recursion, because of half async code */
	if (wbconn->processing) {
		EVENT_FD_NOT_READABLE(conn->event.fde);
		return;
	}

	/* if the used protocol doesn't support pending requests disallow
	 * them */
	if (wbconn->pending_calls && !ops->allow_pending_calls) {
		EVENT_FD_NOT_READABLE(conn->event.fde);
		return;
	}

	if (wbconn->partial.length == 0) {
		wbconn->partial = data_blob_talloc(wbconn, NULL, 4);
		if (!wbconn->partial.data) goto nomem;

		wbconn->partial_read = 0;
	}

	/* read in the packet length */
	if (wbconn->partial_read < 4) {
		uint32_t packet_length;

		status = socket_recv(conn->socket, 
				     wbconn->partial.data+wbconn->partial_read,
				     4 - wbconn->partial_read,
				     &nread, 0);
		if (NT_STATUS_IS_ERR(status)) goto failed;
		if (!NT_STATUS_IS_OK(status)) return;

		wbconn->partial_read += nread;
		if (wbconn->partial_read != 4) return;

		packet_length = ops->packet_length(wbconn->partial);

		wbconn->partial.data =
			talloc_realloc(wbconn, wbconn->partial.data, uint8_t,
				       packet_length);
		if (!wbconn->partial.data) goto nomem;

		wbconn->partial.length = packet_length;
	}

	/* read in the body */
	status = socket_recv(conn->socket, 
			     wbconn->partial.data + wbconn->partial_read,
			     wbconn->partial.length - wbconn->partial_read,
			     &nread, 0);
	if (NT_STATUS_IS_ERR(status)) goto failed;
	if (!NT_STATUS_IS_OK(status)) return;

	wbconn->partial_read += nread;
	if (wbconn->partial_read != wbconn->partial.length) return;

	/* we have a full request - parse it */
	status = ops->pull_request(wbconn->partial, wbconn, &call);
	if (!NT_STATUS_IS_OK(status)) goto failed;
	call->wbconn	= wbconn;
	call->event_ctx	= conn->event.ctx;

	/*
	 * we have parsed the request, so we can reset the
	 * wbconn->partial_read, maybe we could also free wbconn->partial, but
	 * for now we keep it, and overwrite it the next time
	 */
	wbconn->partial_read = 0;

	/* actually process the request */
	wbconn->pending_calls++;
	wbconn->processing = True;
	status = ops->handle_call(call);
	wbconn->processing = False;
	if (!NT_STATUS_IS_OK(status)) goto failed;

	/* if the backend want to reply later just return here */
	if (call->flags & WBSRV_CALL_FLAGS_REPLY_ASYNC) {
		return;
	}

	/*
	 * and queue the reply, this implies talloc_free(call),
	 * and set the socket to readable again
	 */
	status = wbsrv_send_reply(call);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	return;
nomem:
	status = NT_STATUS_NO_MEMORY;
failed:
	wbsrv_terminate_connection(wbconn, nt_errstr(status));
}

/*
 * queue a wbsrv_call reply on a wbsrv_connection
 * NOTE: that this implies talloc_free(call),
 *       use talloc_reference(call) if you need it after
 *       calling wbsrv_queue_reply
 * NOTE: if this function desn't return NT_STATUS_OK,
 *       the caller needs to call
 *           wbsrv_terminate_connection(call->wbconn, "reason...");
 *           return;
 *       to drop the connection
 */
NTSTATUS wbsrv_send_reply(struct wbsrv_call *call)
{
	struct wbsrv_connection *wbconn = call->wbconn;
	const struct wbsrv_protocol_ops *ops = wbconn->listen_socket->ops;
	struct data_blob_list_item *rep;
	NTSTATUS status;

	/* and now encode the reply */
	rep = talloc(wbconn, struct data_blob_list_item);
	NT_STATUS_HAVE_NO_MEMORY(rep);

	status = ops->push_reply(call, rep, &rep->blob);
	NT_STATUS_NOT_OK_RETURN(status);

	if (!wbconn->send_queue) {
		EVENT_FD_WRITEABLE(wbconn->conn->event.fde);
	}
	DLIST_ADD_END(wbconn->send_queue, rep, struct data_blob_list_item *);

	EVENT_FD_READABLE(wbconn->conn->event.fde);

	/* the call isn't needed any more */
	wbconn->pending_calls--;
	talloc_free(call);
	return NT_STATUS_OK;
}

/*
  called when we can write to a connection
*/
static void wbsrv_send(struct stream_connection *conn, uint16_t flags)
{
	struct wbsrv_connection *wbconn = talloc_get_type(conn->private, struct wbsrv_connection);
	NTSTATUS status;

	while (wbconn->send_queue) {
		struct data_blob_list_item *q = wbconn->send_queue;
		size_t sendlen;

		status = socket_send(conn->socket, &q->blob, &sendlen, 0);
		if (NT_STATUS_IS_ERR(status)) goto failed;
		if (!NT_STATUS_IS_OK(status)) return;

		q->blob.length -= sendlen;
		q->blob.data   += sendlen;

		if (q->blob.length == 0) {
			DLIST_REMOVE(wbconn->send_queue, q);
			talloc_free(q);
		}
	}

	EVENT_FD_NOT_WRITEABLE(conn->event.fde);
	return;
failed:
	wbsrv_terminate_connection(wbconn, nt_errstr(status));
}

static const struct stream_server_ops wbsrv_ops = {
	.name			= "winbind",
	.accept_connection	= wbsrv_accept,
	.recv_handler		= wbsrv_recv,
	.send_handler		= wbsrv_send
};

static const struct wbsrv_protocol_ops wbsrv_samba3_protocol_ops = {
	.name			= "winbind samba3 protocol",
	.allow_pending_calls	= False,
	.packet_length		= wbsrv_samba3_packet_length,
	.pull_request		= wbsrv_samba3_pull_request,
	.handle_call		= wbsrv_samba3_handle_call,
	.push_reply		= wbsrv_samba3_push_reply
};

/*
  startup the winbind task
*/
static void winbind_task_init(struct task_server *task)
{
	uint16_t port = 1;
	const struct model_ops *model_ops;
	NTSTATUS status;
	struct wbsrv_service *service;
	struct wbsrv_listen_socket *listen_socket;

	/* within the winbind task we want to be a single process, so
	   ask for the single process model ops and pass these to the
	   stream_setup_socket() call. */
	model_ops = process_model_byname("single");
	if (!model_ops) {
		task_server_terminate(task,
				      "Can't find 'single' process model_ops");
		return;
	}

	/* Make sure the directory for NCALRPC exists */
	if (!directory_exist(WINBINDD_DIR)) {
		mkdir(WINBINDD_DIR, 0755);
	}

	service = talloc_zero(task, struct wbsrv_service);
	if (!service) goto nomem;
	service->task	= task;

	service->primary_sid = secrets_get_domain_sid(service,
						      lp_workgroup());
	if (service->primary_sid == NULL) {
		task_server_terminate(
			task, nt_errstr(NT_STATUS_CANT_ACCESS_DOMAIN_INFO));
		return;
	}

	/* setup the unprivileged samba3 socket */
	listen_socket = talloc(service, struct wbsrv_listen_socket);
	if (!listen_socket) goto nomem;
	listen_socket->socket_path	= WINBINDD_SAMBA3_SOCKET;
	if (!listen_socket->socket_path) goto nomem;
	listen_socket->service		= service;
	listen_socket->privileged	= False;
	listen_socket->ops		= &wbsrv_samba3_protocol_ops;
	status = stream_setup_socket(task->event_ctx, model_ops,
				     &wbsrv_ops, "unix",
				     listen_socket->socket_path, &port,
				     listen_socket);
	if (!NT_STATUS_IS_OK(status)) goto listen_failed;

	/* setup the privileged samba3 socket */
	listen_socket = talloc(service, struct wbsrv_listen_socket);
	if (!listen_socket) goto nomem;
	listen_socket->socket_path	=
		smbd_tmp_path(listen_socket,
			      WINBINDD_SAMBA3_PRIVILEGED_SOCKET);
	if (!listen_socket->socket_path) goto nomem;
	listen_socket->service		= service;
	listen_socket->privileged	= True;
	listen_socket->ops		= &wbsrv_samba3_protocol_ops;
	status = stream_setup_socket(task->event_ctx, model_ops,
				     &wbsrv_ops, "unix",
				     listen_socket->socket_path, &port,
				     listen_socket);
	if (!NT_STATUS_IS_OK(status)) goto listen_failed;

	return;

listen_failed:
	DEBUG(0,("stream_setup_socket(path=%s) failed - %s\n",
		 listen_socket->socket_path, nt_errstr(status)));
	task_server_terminate(task, nt_errstr(status));
	return;
nomem:
	task_server_terminate(task, nt_errstr(NT_STATUS_NO_MEMORY));
	return;
}

/*
  initialise the winbind server
 */
static NTSTATUS winbind_init(struct event_context *event_ctx,
			     const struct model_ops *model_ops)
{
	return task_server_startup(event_ctx, model_ops, winbind_task_init);
}

/*
  register ourselves as a available server
*/
NTSTATUS server_service_winbind_init(void)
{
	return register_server_service("winbind", winbind_init);
}
