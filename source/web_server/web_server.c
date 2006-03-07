/* 
   Unix SMB/CIFS implementation.

   web server startup

   Copyright (C) Andrew Tridgell 2005
   
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
#include "smbd/service_task.h"
#include "smbd/service_stream.h"
#include "smbd/service.h"
#include "web_server/web_server.h"
#include "lib/events/events.h"
#include "system/filesys.h"
#include "system/network.h"
#include "netif/netif.h"
#include "lib/tls/tls.h"

/* don't allow connections to hang around forever */
#define HTTP_TIMEOUT 30

/*
  destroy a web connection
*/
static int websrv_destructor(void *ptr)
{
	struct websrv_context *web = talloc_get_type(ptr, struct websrv_context);
	if (web->output.fd != -1) {
		close(web->output.fd);
	}
	return 0;
}

/*
  called when a connection times out. This prevents a stuck connection
  from hanging around forever
*/
static void websrv_timeout(struct event_context *event_context, 
			   struct timed_event *te, 
			   struct timeval t, void *private)
{
	struct websrv_context *web = talloc_get_type(private, struct websrv_context);
	struct stream_connection *conn = web->conn;
	web->conn = NULL;
	/* TODO: send a message to any running esp context on this connection
	   to stop running */
	stream_terminate_connection(conn, "websrv_timeout: timed out");	
}

/*
  called when a web connection becomes readable
*/
static void websrv_recv(struct stream_connection *conn, uint16_t flags)
{
	struct websrv_context *web = talloc_get_type(conn->private, 
						     struct websrv_context);
	NTSTATUS status;
	uint8_t buf[1024];
	size_t nread;
	uint8_t *p;
	DATA_BLOB b;

	/* not the most efficient http parser ever, but good enough for us */
	status = tls_socket_recv(web->tls, buf, sizeof(buf), &nread);
	if (NT_STATUS_IS_ERR(status)) goto failed;
	if (!NT_STATUS_IS_OK(status)) return;

	status = data_blob_append(web, &web->input.partial, buf, nread);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	/* parse any lines that are available */
	b = web->input.partial;
	while (!web->input.end_of_headers &&
	       (p=memchr(b.data, '\n', b.length))) {
		const char *line = (const char *)b.data;
		*p = 0;
		if (p != b.data && p[-1] == '\r') {
			p[-1] = 0;
		}
		status = http_parse_header(web, line);
		if (!NT_STATUS_IS_OK(status)) return;
		b.length -= (p - b.data) + 1;
		b.data = p+1;
	}

	/* keep any remaining bytes in web->input.partial */
	if (b.length == 0) {
		b.data = NULL;
	}
	b = data_blob_talloc(web, b.data, b.length);
	data_blob_free(&web->input.partial);
	web->input.partial = b;

	/* we finish when we have both the full headers (terminated by
	   a blank line) and any post data, as indicated by the
	   content_length */
	if (web->input.end_of_headers &&
	    web->input.partial.length >= web->input.content_length) {
		if (web->input.partial.length > web->input.content_length) {
			web->input.partial.data[web->input.content_length] = 0;
		}
		EVENT_FD_NOT_READABLE(web->conn->event.fde);

		/* the reference/unlink code here is quite subtle. It
		 is needed because the rendering of the web-pages, and
		 in particular the esp/ejs backend, is semi-async.  So
		 we could well end up in the connection timeout code
		 while inside http_process_input(), but we must not
		 destroy the stack variables being used by that
		 rendering process when we handle the timeout. */
		talloc_reference(web->task, web);
		http_process_input(web);
		talloc_unlink(web->task, web);
	}
	return;

failed:
	stream_terminate_connection(conn, "websrv_recv: failed");
}


/*
  called when a web connection becomes writable
*/
static void websrv_send(struct stream_connection *conn, uint16_t flags)
{
	struct websrv_context *web = talloc_get_type(conn->private, 
						     struct websrv_context);
	NTSTATUS status;
	size_t nsent;
	DATA_BLOB b;

	b = web->output.content;
	b.data += web->output.nsent;
	b.length -= web->output.nsent;

	status = tls_socket_send(web->tls, &b, &nsent);
	if (NT_STATUS_IS_ERR(status)) {
		stream_terminate_connection(web->conn, "socket_send: failed");
		return;
	}
	if (!NT_STATUS_IS_OK(status)) {
		return;
	}

	web->output.nsent += nsent;

	/* possibly read some more raw data from a file */
	if (web->output.content.length == web->output.nsent && 
	    web->output.fd != -1) {
		uint8_t buf[2048];
		ssize_t nread;

		data_blob_free(&web->output.content);
		web->output.nsent = 0;

		nread = read(web->output.fd, buf, sizeof(buf));
		if (nread == -1 && errno == EINTR) {
			return;
		}
		if (nread <= 0) {
			close(web->output.fd);
			web->output.fd = -1;
			nread = 0;
		}
		web->output.content = data_blob_talloc(web, buf, nread);
	}

	if (web->output.content.length == web->output.nsent && 
	    web->output.fd == -1) {
		talloc_free(web->tls);
		web->tls = NULL;
		stream_terminate_connection(web->conn, "websrv_send: finished sending");
	}
}

/*
  establish a new connection to the web server
*/
static void websrv_accept(struct stream_connection *conn)
{
	struct task_server *task = talloc_get_type(conn->private, struct task_server);
	struct esp_data *edata = talloc_get_type(task->private, struct esp_data);
	struct websrv_context *web;

	web = talloc_zero(conn, struct websrv_context);
	if (web == NULL) goto failed;

	web->task = task;
	web->conn = conn;
	conn->private = web;
	web->output.fd = -1;
	talloc_set_destructor(web, websrv_destructor);

	event_add_timed(conn->event.ctx, web, 
			timeval_current_ofs(HTTP_TIMEOUT, 0),
			websrv_timeout, web);

	web->tls = tls_init_server(edata->tls_params, conn->socket, 
				   conn->event.fde, "GPHO", True);
	if (web->tls == NULL) goto failed;

	return;

failed:
	talloc_free(conn);
}


static const struct stream_server_ops web_stream_ops = {
	.name			= "web",
	.accept_connection	= websrv_accept,
	.recv_handler		= websrv_recv,
	.send_handler		= websrv_send,
};

/*
  startup the web server task
*/
static void websrv_task_init(struct task_server *task)
{
	NTSTATUS status;
	uint16_t port = lp_web_port();
	const struct model_ops *model_ops;

	/* run the web server as a single process */
	model_ops = process_model_byname("single");
	if (!model_ops) goto failed;

	if (lp_interfaces() && lp_bind_interfaces_only()) {
		int num_interfaces = iface_count();
		int i;
		for(i = 0; i < num_interfaces; i++) {
			const char *address = iface_n_ip(i);
			status = stream_setup_socket(task->event_ctx, model_ops, 
						     &web_stream_ops, 
						     "ipv4", address, 
						     &port, task);
			if (!NT_STATUS_IS_OK(status)) goto failed;
		}
	} else {
		status = stream_setup_socket(task->event_ctx, model_ops, 
					     &web_stream_ops, 
					     "ipv4", lp_socket_address(), 
					     &port, task);
		if (!NT_STATUS_IS_OK(status)) goto failed;
	}

	/* startup the esp processor - unfortunately we can't do this
	   per connection as that wouldn't allow for session variables */
	status = http_setup_esp(task);
	if (!NT_STATUS_IS_OK(status)) goto failed;

	return;

failed:
	task_server_terminate(task, "websrv_task_init: failed to startup web server task");
}


/*
  called on startup of the web server service It's job is to start
  listening on all configured sockets
*/
static NTSTATUS websrv_init(struct event_context *event_context, 
			    const struct model_ops *model_ops)
{	
	return task_server_startup(event_context, model_ops, websrv_task_init);
}

/* called at smbd startup - register ourselves as a server service */
NTSTATUS server_service_web_init(void)
{
	return register_server_service("web", websrv_init);
}
