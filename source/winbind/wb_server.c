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

#define WINBINDD_DIR "/tmp/.winbindd/"
#define WINBINDD_ECHO_SOCKET  WINBINDD_DIR"echo"
#define WINBINDD_ADDR_PREFIX "127.0.255."
#define WINBINDD_ECHO_ADDR WINBINDD_ADDR_PREFIX"1"
#define WINBINDD_ECHO_PORT 55555

/*
  state of an open winbind connection
*/
struct wbserver_connection {
	DATA_BLOB blob;
	struct send_queue {
		struct send_queue *next, *prev;
		DATA_BLOB blob;
	} *queue;
};


/*
  called when we get a new connection
*/
static void winbind_accept(struct stream_connection *conn)
{
	struct wbserver_connection *wbconn;

	wbconn = talloc_zero(conn, struct wbserver_connection);
	wbconn->blob = data_blob_talloc(wbconn, NULL, 1024);
	
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
	struct send_queue *q;

	status = socket_recv(conn->socket, wbconn->blob.data, wbconn->blob.length, &nread, 0);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(10,("socket_recv: %s\n",nt_errstr(status)));
		stream_terminate_connection(conn, "socket_recv: failed\n");
		return;
	}

	/* just reflect the data back down the socket */
	q = talloc(wbconn, struct send_queue);
	if (q == NULL) {
		stream_terminate_connection(conn, "winbind_recv: out of memory\n");
		return;
	}

	q->blob = data_blob_talloc(q, wbconn->blob.data, nread);
	if (q->blob.data == NULL) {
		stream_terminate_connection(conn, "winbind_recv: out of memory\n");
		return;
	}

	DLIST_ADD_END(wbconn->queue, q, struct send_queue *);

	EVENT_FD_WRITEABLE(conn->event.fde);
}

/*
  called when we can write to a connection
*/
static void winbind_send(struct stream_connection *conn, uint16_t flags)
{
	struct wbserver_connection *wbconn = talloc_get_type(conn->private, struct wbserver_connection);

	while (wbconn->queue) {
		struct send_queue *q = wbconn->queue;
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
			DLIST_REMOVE(wbconn->queue, q);
			talloc_free(q);
		}
	}

	EVENT_FD_NOT_WRITEABLE(conn->event.fde);
}

static const struct stream_server_ops winbind_stream_ops = {
	.name			= "winbind_echo",
	.accept_connection	= winbind_accept,
	.recv_handler		= winbind_recv,
	.send_handler		= winbind_send,
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
		task_terminate(task, "Can't find 'single' process model_ops");
		return;
	}

	/* Make sure the directory for NCALRPC exists */
	if (!directory_exist(WINBINDD_DIR)) {
		mkdir(WINBINDD_DIR, 0755);
	}

	status = stream_setup_socket(task->event_ctx, model_ops, &winbind_stream_ops, 
				     "unix", WINBINDD_ECHO_SOCKET, &port, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(path=%s) failed - %s\n",
			 WINBINDD_ECHO_SOCKET, nt_errstr(status)));
		task_terminate(task, "winbind Failed to find to ECHO unix socket");
		return;
	}

	port = WINBINDD_ECHO_PORT;

	status = stream_setup_socket(task->event_ctx, model_ops, &winbind_stream_ops,
				     "ipv4", WINBINDD_ECHO_ADDR, &port, NULL);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("service_setup_stream_socket(address=%s,port=%u) failed - %s\n",
			 WINBINDD_ECHO_ADDR, port, nt_errstr(status)));
		task_terminate(task, "winbind Failed to find to ECHO tcp socket");
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
