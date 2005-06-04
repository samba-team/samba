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
#include "system/network.h"

/* 
 */

static void kdc_recv_handler(struct event_context *ev, struct fd_event *fde,
			     struct kdc_socket *kdc_socket)
{
	TALLOC_CTX *tmp_ctx = talloc_new(kdc_socket);
	NTSTATUS status;
	DATA_BLOB blob;
	krb5_data reply;
	size_t nread, dsize;
	const char *src_addr;
	int src_port;
	struct sockaddr_in src_sock_addr;
	struct ipv4_addr addr;
	
	status = socket_pending(kdc_socket->sock, &dsize);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}
	
	blob = data_blob_talloc(tmp_ctx, NULL, dsize);
	if (blob.data == NULL) {
		talloc_free(tmp_ctx);
		return;
	}
	
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
	
	/* TODO:  This really should be in a utility function somewhere */
	ZERO_STRUCT(src_sock_addr);
#ifdef HAVE_SOCK_SIN_LEN
	src_sock_addr.sin_len         = sizeof(src_sock_addr);
#endif
	addr                     = interpret_addr2(src_addr);
	src_sock_addr.sin_addr.s_addr = addr.addr;
	src_sock_addr.sin_port        = htons(src_port);
	src_sock_addr.sin_family      = PF_INET;
	
	/* Call krb5 */
	if (krb5_kdc_process_krb5_request(kdc_socket->kdc->krb5_context, 
					  kdc_socket->kdc->config,
					  blob.data, blob.length, 
					  &reply,
					  src_addr,
					  &src_sock_addr) != -1) {
		size_t sendlen = reply.length;
		DATA_BLOB reply_blob;
		reply_blob.data = reply.data;
		reply_blob.length = reply.length;

		/* Send the reply on it's way */
		socket_sendto(kdc_socket->sock, &reply_blob, &sendlen, 0,
			      src_addr, src_port);

		krb5_data_free(&reply);
	}
	talloc_free(tmp_ctx);
}

/*
  handle fd events on a KDC socket
*/
static void kdc_socket_handler(struct event_context *ev, struct fd_event *fde,
			       uint16_t flags, void *private)
{
	struct kdc_socket *kdc_socket = talloc_get_type(private, struct kdc_socket);
	if (flags & EVENT_FD_WRITE) {
		/* not sure on write events yet */
	} else if (flags & EVENT_FD_READ) {
		kdc_recv_handler(ev, fde, kdc_socket);
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

	EVENT_FD_READABLE(kdc_socket->fde);

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
	krb5_error_code ret;

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

	initialize_krb5_error_table();

	ret = krb5_init_context(&kdc->krb5_context);
	if (ret) {
		DEBUG(1,("kdc_task_init: krb5_init_context failed (%s)\n", 
			 error_message(ret)));
		task_terminate(task, "kdc: krb5_init_context failed");
		return; 
	}

	/* TODO: Fill in the hdb and logging details */
	kdc_openlog(kdc->krb5_context, kdc->config);
	
	kdc->config->db = talloc(kdc->config, struct HDB *);
	if (!kdc->config->db) {
		task_terminate(task, "kdc: out of memory");
		return;
	}
	kdc->config->num_db = 1;
		
	ret = hdb_ldb_create(kdc->krb5_context, &kdc->config->db[0], lp_sam_url());
	if (ret != 0) {
		DEBUG(1, ("kdc_task_init: hdb_ldb_create fails: %s\n", 
			  smb_get_krb5_error_message(kdc->krb5_context, ret, kdc))); 
		task_terminate(task, "kdc: hdb_ldb_create failed");
		return; 
	}

	/* start listening on the configured network interfaces */
	status = kdc_startup_interfaces(kdc);
	if (!NT_STATUS_IS_OK(status)) {
		task_terminate(task, "kdc failed to setup interfaces");
		return;
	}
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
