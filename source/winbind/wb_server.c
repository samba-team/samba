/* 
   Unix SMB/CIFS implementation.
   Main winbindd server routines

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
#include "events.h"
#include "system/time.h"

#define WINBINDD_DIR "/tmp/.winbindd/"
#define WINBINDD_ECHO_SOCKET  WINBINDD_DIR"echo"
#define WINBINDD_ADDR_PREFIX "127.0.255."
#define WINBINDD_ECHO_ADDR WINBINDD_ADDR_PREFIX"1"
#define WINBINDD_ECHO_PORT 55555

static void winbind_accept(struct server_connection *conn)
{
	DEBUG(10,("winbind_accept:\n"));
}

static DATA_BLOB tmp_blob;

static void winbind_recv(struct server_connection *conn, struct timeval t, uint16_t flags)
{


	NTSTATUS status;
	size_t nread;

if (!tmp_blob.data) {
	tmp_blob = data_blob_talloc(conn, NULL, 1024);
	if (tmp_blob.data == NULL) {
		return;
	}
}
	tmp_blob.length = 1024;
	status = socket_recv(conn->socket, tmp_blob.data, tmp_blob.length, &nread, 0);
	if (NT_STATUS_IS_ERR(status)) {
		DEBUG(10,("socket_recv: %s\n",nt_errstr(status)));
		talloc_free(tmp_blob.data);
		server_terminate_connection(conn, "socket_recv: failed\n");
		return;
	}
	tmp_blob.length = nread;
#if 0
DEBUG(0,("winbind_recv:\n"));
dump_data(0, tmp_blob.data, tmp_blob.length);
#endif
	conn->event.fde->flags |= EVENT_FD_WRITE;
}

static void winbind_send(struct server_connection *conn, struct timeval t, uint16_t flags)
{
	NTSTATUS status;
	size_t sendlen;

	if (tmp_blob.length > 1 && tmp_blob.data[0] == (uint8_t)'q') {

	}

	status = socket_send(conn->socket, &tmp_blob, &sendlen, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(10,("socket_send() %s\n",nt_errstr(status)));
		server_terminate_connection(conn, "socket_send: failed\n");
		return;
	}

	if (tmp_blob.length > 1 && tmp_blob.data[0] == (uint8_t)'q') {
		server_terminate_connection(conn, "winbind_send: user quit\n");
		return;
	}
#if 0
DEBUG(0,("winbind_send:\n"));
dump_data(0, tmp_blob.data, tmp_blob.length);
#endif
	tmp_blob.length -= sendlen;

	if (tmp_blob.length == 0) {
		conn->event.fde->flags &= ~EVENT_FD_WRITE;
	}
}

static void winbind_idle(struct server_connection *conn, struct timeval t)
{
	DEBUG(1,("winbind_idle: not implemented!\n"));
	return;
}

static void winbind_close(struct server_connection *conn, const char *reason)
{
	DEBUG(10,("winbind_close: %s\n", reason));
}



static int winbind_task_server_contect_destructor(void *ptr)
{
	struct server_context *server = ptr;

	server_service_shutdown(server, "exit");

	return 0;	
}

static void winbind_server_task_init(struct server_task *task)
{
	const char *wb_task_service[] = { "winbind_task", NULL };
	struct server_context *server;

	DEBUG(1,("winbindsrv_task_init\n"));
	server = server_service_startup("single", wb_task_service);
	if (!server) {
		DEBUG(0,("Starting Services (winbind_task) failed.\n"));
		return;
	}

	task->task.private_data = talloc_steal(task, server);

	task->event.ctx = event_context_merge(task->event.ctx, server->event.ctx);
	server->event.ctx = talloc_reference(server, task->event.ctx);

	talloc_set_destructor(server, winbind_task_server_contect_destructor);

	/* wait for events */
	event_loop_wait(task->event.ctx);
}

static const struct server_task_ops winbind_srver_task_ops = {
	.name		= "winbind_server_task",
	.task_init	= winbind_server_task_init
};

static const struct server_task_ops *winbind_srver_task_get_ops(void)
{
	return &winbind_srver_task_ops;
}

static const struct server_stream_ops winbind_stream_ops = {
	.name			= "winbind",
	.socket_init		= NULL,
	.accept_connection	= winbind_accept,
	.recv_handler		= winbind_recv,
	.send_handler		= winbind_send,
	.idle_handler		= winbind_idle,
	.close_connection	= winbind_close
};

static const struct server_stream_ops *winbind_get_stream_ops(void)
{
	return &winbind_stream_ops;
}

static void winbind_task_init(struct server_service *service)
{
	struct server_stream_socket *stream_socket;
	uint16_t port = 1;

	DEBUG(1,("winbind_task_init\n"));

	/* Make sure the directory for NCALRPC exists */
	if (!directory_exist(WINBINDD_DIR, NULL)) {
		mkdir(WINBINDD_DIR, 0755);
	}

	stream_socket = service_setup_stream_socket(service, winbind_get_stream_ops(), "unix", WINBINDD_ECHO_SOCKET, &port);
	if (!stream_socket) {
		DEBUG(0,("service_setup_stream_socket(path=%s) failed\n",WINBINDD_ECHO_SOCKET));
		return;
	}

	port = WINBINDD_ECHO_PORT;
	stream_socket = service_setup_stream_socket(service, winbind_get_stream_ops(), "ipv4", WINBINDD_ECHO_ADDR, &port);
	if (!stream_socket) {
		DEBUG(0,("service_setup_stream_socket(address=%s,port=%u) failed\n",WINBINDD_ECHO_ADDR, port));
		return;
	}

	return;
}

static const struct server_service_ops winbind_task_ops = {
	.name			= "winbind_task",
	.service_init		= winbind_task_init,
};

const struct server_service_ops *winbind_task_get_ops(void)
{
	return &winbind_task_ops;
}

static void winbind_init(struct server_service *service)
{
	DEBUG(1,("winbind_init\n"));

	server_run_task(service, winbind_srver_task_get_ops());

	return;
}

static const struct server_service_ops winbind_ops = {
	.name			= "winbind",
	.service_init		= winbind_init,
};

const struct server_service_ops *winbind_get_ops(void)
{
	return &winbind_ops;
}

NTSTATUS server_service_winbind_init(void)
{
	return NT_STATUS_OK;	
}
