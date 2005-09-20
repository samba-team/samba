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
#include "winbind/winbindd_nss.h"

#define WINBINDD_DIR "/tmp/.winbindd/"
#define WINBINDD_ECHO_SOCKET  WINBINDD_DIR"echo"
#define WINBINDD_ADDR_PREFIX "127.0.255."
#define WINBINDD_ECHO_ADDR WINBINDD_ADDR_PREFIX"1"
#define WINBINDD_ECHO_PORT 55555
#define WINBINDD_SAMBA3_SOCKET WINBINDD_DIR"pipe"

/*
  state of an open winbind connection
*/
struct wbserver_connection {
	DATA_BLOB input;
	struct data_blob_list_item *send_queue;
};


/*
  called when we get a new connection
*/
static void winbind_accept(struct stream_connection *conn)
{
	struct wbserver_connection *wbconn;

	wbconn = talloc_zero(conn, struct wbserver_connection);
	wbconn->input = data_blob_talloc(wbconn, NULL, 1024);
	
	conn->private = wbconn;
}

/*
  receive some data on a winbind connection
*/
static void winbind_recv(struct stream_connection *conn, uint16_t flags)
{
	struct wbserver_connection *wbconn = talloc_get_type(conn->private, struct wbserver_connection);
	NTSTATUS status;
	size_t nread;
	struct data_blob_list_item *q;

	status = socket_recv(conn->socket, wbconn->input.data, wbconn->input.length, &nread, 0);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(10,("socket_recv: %s\n",nt_errstr(status)));
		stream_terminate_connection(conn, "socket_recv: failed\n");
		return;
	}

	/* just reflect the data back down the socket */
	q = talloc(wbconn, struct data_blob_list_item);
	if (q == NULL) {
		stream_terminate_connection(conn, "winbind_recv: out of memory\n");
		return;
	}

	q->blob = data_blob_talloc(q, wbconn->input.data, nread);
	if (q->blob.data == NULL) {
		stream_terminate_connection(conn, "winbind_recv: out of memory\n");
		return;
	}

	DLIST_ADD_END(wbconn->send_queue, q, struct data_blob_list_item *);

	EVENT_FD_WRITEABLE(conn->event.fde);
}

/*
  called when we can write to a connection
*/
static void winbind_send(struct stream_connection *conn, uint16_t flags)
{
	struct wbserver_connection *wbconn = talloc_get_type(conn->private, struct wbserver_connection);

	while (wbconn->send_queue) {
		struct data_blob_list_item *q = wbconn->send_queue;
		NTSTATUS status;
		size_t sendlen;

		status = socket_send(conn->socket, &q->blob, &sendlen, 0);
		if (NT_STATUS_IS_ERR(status)) {
			DEBUG(10,("socket_send() %s\n",nt_errstr(status)));
			stream_terminate_connection(conn, "socket_send: failed\n");
			return;
		}
		if (!NT_STATUS_IS_OK(status)) {
			return;
		}

		q->blob.length -= sendlen;
		q->blob.data   += sendlen;

		if (q->blob.length == 0) {
			DLIST_REMOVE(wbconn->send_queue, q);
			talloc_free(q);
		}
	}

	EVENT_FD_NOT_WRITEABLE(conn->event.fde);
}

static const struct stream_server_ops winbind_echo_ops = {
	.name			= "winbind_echo",
	.accept_connection	= winbind_accept,
	.recv_handler		= winbind_recv,
	.send_handler		= winbind_send,
};

struct winbind3_connection {
	struct winbindd_request *request;
	struct winbindd_response *response;
	DATA_BLOB partial;
	size_t nsent;
};

static void winbind_samba3_accept(struct stream_connection *conn)
{
	struct winbind3_connection *wbconn;

	wbconn = talloc(conn, struct winbind3_connection);
	if (wbconn == NULL) {
		DEBUG(0, ("talloc failed\n"));
		stream_terminate_connection(conn, "talloc failed");
		return;
	}

	wbconn->request = NULL;
	wbconn->response = NULL;
	ZERO_STRUCT(wbconn->partial);
	conn->private = wbconn;
}

static void winbind_samba3_recv(struct stream_connection *conn, uint16_t flags)
{
	struct winbind3_connection *wbconn =
		talloc_get_type(conn->private, struct winbind3_connection);
	size_t npending, received;
	NTSTATUS res;

	if (!NT_STATUS_IS_OK(socket_pending(conn->socket, &npending))) {
		stream_terminate_connection(conn, "socket_pending() failed");
		return;
	}

	if (npending == 0) {
		stream_terminate_connection(conn, "EOF from client");
		return;
	}

	if (wbconn->partial.length + npending >
	    sizeof(struct winbindd_request)) {
		npending = sizeof(struct winbindd_request) -
			wbconn->partial.length;
	}

	wbconn->partial.data =
		talloc_realloc_size(wbconn, wbconn->partial.data,
				    wbconn->partial.length + npending);
	if (wbconn->partial.data == NULL) {
		stream_terminate_connection(conn, "talloc_realloc failed");
		return;
	}

	res = socket_recv(conn->socket,
			  &wbconn->partial.data[wbconn->partial.length],
			  npending, &received, 0);

	if (!NT_STATUS_IS_OK(res)) {
		DEBUG(5, ("sock_recv failed: %s\n", nt_errstr(res)));
		stream_terminate_connection(conn, "talloc_realloc failed");
		return;
	}

	wbconn->partial.length += received;

	if (wbconn->partial.length < sizeof(struct winbindd_request)) {
		return;
	}

	wbconn->request = (struct winbindd_request *)wbconn->partial.data;

	SMB_ASSERT(wbconn->response == NULL);

	wbconn->response = talloc_zero(wbconn, struct winbindd_response);
	if (wbconn->response == NULL) {
		stream_terminate_connection(conn, "talloc_zero failed");
		return;
	}

	wbconn->response->length = sizeof(struct winbindd_response);
	wbconn->response->result = WINBINDD_ERROR;

	if (wbconn->request->length != sizeof(struct winbindd_request)) {
		DEBUG(10, ("Got invalid request length %d\n",
			   wbconn->request->length));
		goto done;
	}

	DEBUG(10, ("Got winbind request %d\n", wbconn->request->cmd));

	switch(wbconn->request->cmd) {
	case WINBINDD_INTERFACE_VERSION:
		wbconn->response->result = WINBINDD_OK;
		wbconn->response->data.interface_version =
			WINBIND_INTERFACE_VERSION;
		break;
	case WINBINDD_PRIV_PIPE_DIR:
		wbconn->response->result = WINBINDD_OK;
		wbconn->response->extra_data =
			smbd_tmp_path(wbconn->response, "winbind_priv/pipe");
		if (wbconn->response->extra_data == NULL) {
			stream_terminate_connection(conn,
						    "smbd_tmp_path failed");
			return;
		}
		wbconn->response->length +=
			strlen(wbconn->response->extra_data) + 1;
		break;
	case WINBINDD_PING:
		wbconn->response->result = WINBINDD_OK;
		break;
	default:
		break;
	}

 done:
	talloc_free(wbconn->partial.data);
	wbconn->partial.data = NULL;
	wbconn->nsent = 0;

	wbconn->partial.data = (char *)wbconn->response;
	wbconn->partial.length = sizeof(struct winbindd_response);

	EVENT_FD_NOT_READABLE(conn->event.fde);
	EVENT_FD_WRITEABLE(conn->event.fde);
}

static void winbind_samba3_send(struct stream_connection *conn, uint16_t flags)
{
	struct winbind3_connection *wbconn =
		talloc_get_type(conn->private, struct winbind3_connection);
	size_t nsent;
	NTSTATUS res;

	res = socket_send(conn->socket, &wbconn->partial, &nsent, 0);
	if (!NT_STATUS_IS_OK(res)) {
		stream_terminate_connection(conn, "socket_send() failed");
		return;
	}

	wbconn->partial.data += nsent;
	wbconn->partial.length -= nsent;

	if (wbconn->partial.length != 0) {
		return;
	}

	if (wbconn->response->extra_data != NULL) {
		wbconn->partial.data = wbconn->response->extra_data;
		wbconn->partial.length = wbconn->response->length -
			sizeof(struct winbindd_response);
		wbconn->response->extra_data = NULL;
		return;
	}

	talloc_free(wbconn->response);
	wbconn->response = NULL;
	wbconn->partial.data = NULL;
	EVENT_FD_NOT_WRITEABLE(conn->event.fde);
	EVENT_FD_READABLE(conn->event.fde);
}

static const struct stream_server_ops winbind_samba3_ops = {
	.name			= "winbind_samba3",
	.accept_connection	= winbind_samba3_accept,
	.recv_handler		= winbind_samba3_recv,
	.send_handler		= winbind_samba3_send,
};

/*
  startup the winbind task
*/
static void winbind_task_init(struct task_server *task)
{
	uint16_t port = 1;
	const struct model_ops *model_ops;
	NTSTATUS status;

	/* within the winbind task we want to be a single process, so
	   ask for the single process model ops and pass these to the
	   stream_setup_socket() call. */
	model_ops = process_model_byname("single");
	if (!model_ops) {
		task_server_terminate(task, "Can't find 'single' process model_ops");
		return;
	}

	/* Make sure the directory for NCALRPC exists */
	if (!directory_exist(WINBINDD_DIR)) {
		mkdir(WINBINDD_DIR, 0755);
	}

	status = stream_setup_socket(task->event_ctx, model_ops, &winbind_echo_ops, 
				     "unix", WINBINDD_ECHO_SOCKET, &port, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(path=%s) failed - %s\n",
			 WINBINDD_ECHO_SOCKET, nt_errstr(status)));
		task_server_terminate(task, "winbind Failed to find to ECHO unix socket");
		return;
	}

	status = stream_setup_socket(task->event_ctx, model_ops,
				     &winbind_samba3_ops, "unix",
				     WINBINDD_SAMBA3_SOCKET, &port, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(path=%s) failed - %s\n",
			 WINBINDD_ECHO_SOCKET, nt_errstr(status)));
		task_server_terminate(task, "winbind Failed to find to "
				      "SAMBA3 unix socket");
		return;
	}

	port = WINBINDD_ECHO_PORT;

	status = stream_setup_socket(task->event_ctx, model_ops, &winbind_echo_ops,
				     "ipv4", WINBINDD_ECHO_ADDR, &port, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(address=%s,port=%u) failed - %s\n",
			 WINBINDD_ECHO_ADDR, port, nt_errstr(status)));
		task_server_terminate(task, "winbind Failed to find to ECHO tcp socket");
		return;
	}
}

/*
  initialise the winbind server
 */
static NTSTATUS winbind_init(struct event_context *event_ctx, const struct model_ops *model_ops)
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
