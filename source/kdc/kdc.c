/* 
   Unix SMB/CIFS implementation.

   KDC Server startup

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
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
#include "smbd/service_task.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "kdc/kdc.h"


/*
  handle fd events on a cldap_socket
*/
static void kdc_socket_handler(struct event_context *ev, struct fd_event *fde,
			       uint16_t flags, void *private)
{
	NTSTATUS status;
	struct kdc_socket *kdc_socket = talloc_get_type(private, struct kdc_socket);
	if (flags & EVENT_FD_WRITE) {
		/* this should not happen */
	} else if (flags & EVENT_FD_READ) {
		TALLOC_CTX *tmp_ctx = talloc_new(kdc_socket);
		DATA_BLOB blob = data_blob_talloc(tmp_ctx, NULL, 64 * 1024);
		size_t nread;
		const char *src_addr;
		int src_port;

		DEBUG(0, ("incoming!\n"));

		status = socket_recvfrom(kdc_socket->sock, blob.data, blob.length, &nread, 0,
					 &src_addr, &src_port);
		if (!NT_STATUS_IS_OK(status)) {
			talloc_free(tmp_ctx);
			return;
		}
		talloc_steal(tmp_ctx, src_addr);
		blob.length = nread;
		
		DEBUG(2,("Received krb5 packet of length %d from %s:%d\n", 
			 blob.length, src_addr, src_port));
		

	}
}

/*
  start listening on the given address
*/
static NTSTATUS kdc_add_socket(struct kdc_server *kdc, const char *address)
{
	struct kdc_socket *kdc_socket;
	NTSTATUS status;

	kdc_socket = talloc(kdc, struct kdc_socket);
	NT_STATUS_HAVE_NO_MEMORY(kdc_socket);

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &kdc_socket->sock, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(kdc_socket);
		return status;
	}

	kdc_socket->kdc = kdc;

	talloc_steal(kdc_socket, kdc_socket->sock);

	kdc_socket->fde = event_add_fd(kdc->task->event_ctx, kdc, 
				       socket_get_fd(kdc_socket->sock), 0,
				       kdc_socket_handler, kdc_socket);

	status = socket_listen(kdc_socket->sock, address, lp_krb5_port(), 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d - %s\n", 
			 address, lp_krb5_port(), nt_errstr(status)));
		talloc_free(kdc_socket);
		return status;
	}

	return NT_STATUS_OK;
}


/*
  setup our listening sockets on the configured network interfaces
*/
NTSTATUS kdc_startup_interfaces(struct kdc_server *kdc)
{
	int num_interfaces = iface_count();
	TALLOC_CTX *tmp_ctx = talloc_new(kdc);
	NTSTATUS status;

	/* if we are allowing incoming packets from any address, then
	   we need to bind to the wildcard address */
	if (!lp_bind_interfaces_only()) {
		status = kdc_add_socket(kdc, "0.0.0.0");
		NT_STATUS_NOT_OK_RETURN(status);
	} else {
		int i;

		for (i=0; i<num_interfaces; i++) {
			const char *address = talloc_strdup(tmp_ctx, iface_n_ip(i));
			status = kdc_add_socket(kdc, address);
			NT_STATUS_NOT_OK_RETURN(status);
		}
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

/*
  startup the kdc task
*/
static void kdc_task_init(struct task_server *task)
{
	struct kdc_server *kdc;
	NTSTATUS status;

	if (iface_count() == 0) {
		task_terminate(task, "kdc: no network interfaces configured");
		return;
	}

	kdc = talloc(task, struct kdc_server);
	if (kdc == NULL) {
		task_terminate(task, "kdc: out of memory");
		return;
	}

	kdc->task = task;

	/* Setup the KDC configuration */
	kdc->config = talloc(kdc, struct krb5_kdc_configuration);
	if (!kdc->config) {
		task_terminate(task, "kdc: out of memory");
		return;
	}
	krb5_kdc_default_config(kdc->config);

	/* TODO: Fill in the hdb and logging details */

	/* start listening on the configured network interfaces */
	status = kdc_startup_interfaces(kdc);
	if (!NT_STATUS_IS_OK(status)) {
		task_terminate(task, "kdc failed to setup interfaces");
		return;
	}

	DEBUG(0, ("When I grow up, I want to be a KDC!\n"));
}


/*
  called on startup of the KDC service 
*/
static NTSTATUS kdc_init(struct event_context *event_ctx, 
			 const struct model_ops *model_ops)
{	
	return task_server_startup(event_ctx, model_ops, kdc_task_init);
}

/* called at smbd startup - register ourselves as a server service */
NTSTATUS server_service_kdc_init(void)
{
	return register_server_service("kdc", kdc_init);
}
