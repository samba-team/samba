/* 
   Unix SMB/CIFS implementation.

   KDC Server startup

   Copyright (C) Andrew Bartlett <abartlet@samba.org> 2005
   Copyright (C) Andrew Tridgell	2005
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
#include "smbd/service_task.h"
#include "smbd/service.h"
#include "smbd/service_stream.h"
#include "smbd/process_model.h"
#include "lib/events/events.h"
#include "lib/socket/socket.h"
#include "kdc/kdc.h"
#include "system/network.h"
#include "lib/util/dlinklist.h"
#include "lib/messaging/irpc.h"
#include "lib/stream/packet.h"
#include "librpc/gen_ndr/samr.h"
#include "lib/socket/netif.h"
#include "heimdal/kdc/windc_plugin.h"
#include "heimdal/lib/krb5/krb5_locl.h"
#include "heimdal/kdc/kdc_locl.h"


/* Disgusting hack to get a mem_ctx into the hdb plugin, when used as a keytab */
TALLOC_CTX *kdc_mem_ctx;

/* hold all the info needed to send a reply */
struct kdc_reply {
	struct kdc_reply *next, *prev;
	struct socket_address *dest;
	DATA_BLOB packet;
};

typedef BOOL (*kdc_process_fn_t)(struct kdc_server *kdc,
				 TALLOC_CTX *mem_ctx, 
				 DATA_BLOB *input, 
				 DATA_BLOB *reply,
				 struct socket_address *peer_addr, 
				 struct socket_address *my_addr, 
				 int datagram);

/* hold information about one kdc socket */
struct kdc_socket {
	struct socket_context *sock;
	struct kdc_server *kdc;
	struct fd_event *fde;

	/* a queue of outgoing replies that have been deferred */
	struct kdc_reply *send_queue;

	kdc_process_fn_t process;
};
/*
  state of an open tcp connection
*/
struct kdc_tcp_connection {
	/* stream connection we belong to */
	struct stream_connection *conn;

	/* the kdc_server the connection belongs to */
	struct kdc_server *kdc;

	struct packet_context *packet;

	kdc_process_fn_t process;
};

/*
  handle fd send events on a KDC socket
*/
static void kdc_send_handler(struct kdc_socket *kdc_socket)
{
	while (kdc_socket->send_queue) {
		struct kdc_reply *rep = kdc_socket->send_queue;
		NTSTATUS status;
		size_t sendlen;

		status = socket_sendto(kdc_socket->sock, &rep->packet, &sendlen,
				       rep->dest);
		if (NT_STATUS_EQUAL(status, STATUS_MORE_ENTRIES)) {
			break;
		}
		if (NT_STATUS_EQUAL(status, NT_STATUS_INVALID_BUFFER_SIZE)) {
			/* Replace with a krb err, response to big */
		}
		
		DLIST_REMOVE(kdc_socket->send_queue, rep);
		talloc_free(rep);
	}

	if (kdc_socket->send_queue == NULL) {
		EVENT_FD_NOT_WRITEABLE(kdc_socket->fde);
	}
}


/*
  handle fd recv events on a KDC socket
*/
static void kdc_recv_handler(struct kdc_socket *kdc_socket)
{
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx = talloc_new(kdc_socket);
	DATA_BLOB blob;
	struct kdc_reply *rep;
	DATA_BLOB reply;
	size_t nread, dsize;
	struct socket_address *src;
	struct socket_address *my_addr;
	int ret;

	status = socket_pending(kdc_socket->sock, &dsize);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}

	blob = data_blob_talloc(tmp_ctx, NULL, dsize);
	if (blob.data == NULL) {
		/* hope this is a temporary low memory condition */
		talloc_free(tmp_ctx);
		return;
	}

	status = socket_recvfrom(kdc_socket->sock, blob.data, blob.length, &nread,
				 tmp_ctx, &src);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return;
	}
	blob.length = nread;
	
	DEBUG(10,("Received krb5 UDP packet of length %lu from %s:%u\n", 
		 (long)blob.length, src->addr, (uint16_t)src->port));
	
	my_addr = socket_get_my_addr(kdc_socket->sock, tmp_ctx);
	if (!my_addr) {
		talloc_free(tmp_ctx);
		return;
	}


	/* Call krb5 */
	ret = kdc_socket->process(kdc_socket->kdc, 
				  tmp_ctx, 
				  &blob,  
				  &reply,
				  src, my_addr,
				  1 /* Datagram */);
	if (!ret) {
		talloc_free(tmp_ctx);
		return;
	}

	/* queue a pending reply */
	rep = talloc(kdc_socket, struct kdc_reply);
	if (rep == NULL) {
		talloc_free(tmp_ctx);
		return;
	}
	rep->dest         = talloc_steal(rep, src);
	rep->packet       = reply;
	talloc_steal(rep, reply.data);

	if (rep->packet.data == NULL) {
		talloc_free(rep);
		talloc_free(tmp_ctx);
		return;
	}

	DLIST_ADD_END(kdc_socket->send_queue, rep, struct kdc_reply *);
	EVENT_FD_WRITEABLE(kdc_socket->fde);
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
		kdc_send_handler(kdc_socket);
	} 
	if (flags & EVENT_FD_READ) {
		kdc_recv_handler(kdc_socket);
	}
}

static void kdc_tcp_terminate_connection(struct kdc_tcp_connection *kdcconn, const char *reason)
{
	stream_terminate_connection(kdcconn->conn, reason);
}

/*
  receive a full packet on a KDC connection
*/
static NTSTATUS kdc_tcp_recv(void *private, DATA_BLOB blob)
{
	struct kdc_tcp_connection *kdcconn = talloc_get_type(private, 
							     struct kdc_tcp_connection);
	NTSTATUS status = NT_STATUS_UNSUCCESSFUL;
	TALLOC_CTX *tmp_ctx = talloc_new(kdcconn);
	int ret;
	DATA_BLOB input, reply;
	struct socket_address *src_addr;
	struct socket_address *my_addr;

	talloc_steal(tmp_ctx, blob.data);

	src_addr = socket_get_peer_addr(kdcconn->conn->socket, tmp_ctx);
	if (!src_addr) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	my_addr = socket_get_my_addr(kdcconn->conn->socket, tmp_ctx);
	if (!my_addr) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	/* Call krb5 */
	input = data_blob_const(blob.data + 4, blob.length - 4); 

	ret = kdcconn->process(kdcconn->kdc, 
			       tmp_ctx,
			       &input,
			       &reply,
			       src_addr,
			       my_addr,
			       0 /* Not datagram */);
	if (!ret) {
		talloc_free(tmp_ctx);
		return NT_STATUS_INTERNAL_ERROR;
	}

	/* and now encode the reply */
	blob = data_blob_talloc(kdcconn, NULL, reply.length + 4);
	if (!blob.data) {
		talloc_free(tmp_ctx);
		return NT_STATUS_NO_MEMORY;
	}

	RSIVAL(blob.data, 0, reply.length);
	memcpy(blob.data + 4, reply.data, reply.length);	

	status = packet_send(kdcconn->packet, blob);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(tmp_ctx);
		return status;
	}

	/* the call isn't needed any more */
	talloc_free(tmp_ctx);
	return NT_STATUS_OK;
}

/*
  receive some data on a KDC connection
*/
static void kdc_tcp_recv_handler(struct stream_connection *conn, uint16_t flags)
{
	struct kdc_tcp_connection *kdcconn = talloc_get_type(conn->private, 
							     struct kdc_tcp_connection);
	packet_recv(kdcconn->packet);
}

/*
  called on a tcp recv error
*/
static void kdc_tcp_recv_error(void *private, NTSTATUS status)
{
	struct kdc_tcp_connection *kdcconn = talloc_get_type(private, struct kdc_tcp_connection);
	kdc_tcp_terminate_connection(kdcconn, nt_errstr(status));
}

/*
  called when we can write to a connection
*/
static void kdc_tcp_send(struct stream_connection *conn, uint16_t flags)
{
	struct kdc_tcp_connection *kdcconn = talloc_get_type(conn->private, 
							     struct kdc_tcp_connection);
	packet_queue_run(kdcconn->packet);
}

/**
   Wrapper for krb5_kdc_process_krb5_request, converting to/from Samba
   calling conventions
*/

static BOOL kdc_process(struct kdc_server *kdc,
			TALLOC_CTX *mem_ctx, 
			DATA_BLOB *input, 
			DATA_BLOB *reply,
			struct socket_address *peer_addr, 
			struct socket_address *my_addr,
			int datagram_reply)
{
	int ret;	
	krb5_data k5_reply;
	krb5_data_zero(&k5_reply);

	DEBUG(10,("Received KDC packet of length %lu from %s:%d\n", 
		  (long)input->length - 4, peer_addr->addr, peer_addr->port));

	ret = krb5_kdc_process_krb5_request(kdc->smb_krb5_context->krb5_context, 
					    kdc->config,
					    input->data, input->length,
					    &k5_reply,
					    peer_addr->addr,
					    peer_addr->sockaddr,
					    datagram_reply);
	if (ret == -1) {
		*reply = data_blob(NULL, 0);
		return False;
	}
	if (k5_reply.length) {
		*reply = data_blob_talloc(mem_ctx, k5_reply.data, k5_reply.length);
		krb5_free_data_contents(kdc->smb_krb5_context->krb5_context, &k5_reply);
	} else {
		*reply = data_blob(NULL, 0);	
	}
	return True;
}

/*
  called when we get a new connection
*/
static void kdc_tcp_generic_accept(struct stream_connection *conn, kdc_process_fn_t process_fn)
{
	struct kdc_server *kdc = talloc_get_type(conn->private, struct kdc_server);
	struct kdc_tcp_connection *kdcconn;

	kdcconn = talloc_zero(conn, struct kdc_tcp_connection);
	if (!kdcconn) {
		stream_terminate_connection(conn, "kdc_tcp_accept: out of memory");
		return;
	}
	kdcconn->conn	 = conn;
	kdcconn->kdc	 = kdc;
	kdcconn->process = process_fn;
	conn->private    = kdcconn;

	kdcconn->packet = packet_init(kdcconn);
	if (kdcconn->packet == NULL) {
		kdc_tcp_terminate_connection(kdcconn, "kdc_tcp_accept: out of memory");
		return;
	}
	packet_set_private(kdcconn->packet, kdcconn);
	packet_set_socket(kdcconn->packet, conn->socket);
	packet_set_callback(kdcconn->packet, kdc_tcp_recv);
	packet_set_full_request(kdcconn->packet, packet_full_request_u32);
	packet_set_error_handler(kdcconn->packet, kdc_tcp_recv_error);
	packet_set_event_context(kdcconn->packet, conn->event.ctx);
	packet_set_fde(kdcconn->packet, conn->event.fde);
	packet_set_serialise(kdcconn->packet);
}

static void kdc_tcp_accept(struct stream_connection *conn)
{
	kdc_tcp_generic_accept(conn, kdc_process);
}

static const struct stream_server_ops kdc_tcp_stream_ops = {
	.name			= "kdc_tcp",
	.accept_connection	= kdc_tcp_accept,
	.recv_handler		= kdc_tcp_recv_handler,
	.send_handler		= kdc_tcp_send
};

static void kpasswdd_tcp_accept(struct stream_connection *conn)
{
	kdc_tcp_generic_accept(conn, kpasswdd_process);
}

static const struct stream_server_ops kpasswdd_tcp_stream_ops = {
	.name			= "kpasswdd_tcp",
	.accept_connection	= kpasswdd_tcp_accept,
	.recv_handler		= kdc_tcp_recv_handler,
	.send_handler		= kdc_tcp_send
};

/*
  start listening on the given address
*/
static NTSTATUS kdc_add_socket(struct kdc_server *kdc, const char *address)
{
	const struct model_ops *model_ops;
 	struct kdc_socket *kdc_socket;
 	struct kdc_socket *kpasswd_socket;
	struct socket_address *kdc_address, *kpasswd_address;
	NTSTATUS status;
	uint16_t kdc_port = lp_krb5_port();
	uint16_t kpasswd_port = lp_kpasswd_port();

	kdc_socket = talloc(kdc, struct kdc_socket);
	NT_STATUS_HAVE_NO_MEMORY(kdc_socket);

	kpasswd_socket = talloc(kdc, struct kdc_socket);
	NT_STATUS_HAVE_NO_MEMORY(kpasswd_socket);

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &kdc_socket->sock, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(kdc_socket);
		return status;
	}

	status = socket_create("ip", SOCKET_TYPE_DGRAM, &kpasswd_socket->sock, 0);
	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(kpasswd_socket);
		return status;
	}

	kdc_socket->kdc = kdc;
	kdc_socket->send_queue = NULL;
	kdc_socket->process = kdc_process;

	talloc_steal(kdc_socket, kdc_socket->sock);

	kdc_socket->fde = event_add_fd(kdc->task->event_ctx, kdc, 
				       socket_get_fd(kdc_socket->sock), EVENT_FD_READ,
				       kdc_socket_handler, kdc_socket);

	kdc_address = socket_address_from_strings(kdc_socket, kdc_socket->sock->backend_name, 
						  address, kdc_port);
	NT_STATUS_HAVE_NO_MEMORY(kdc_address);

	status = socket_listen(kdc_socket->sock, kdc_address, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d UDP for kdc - %s\n", 
			 address, kdc_port, nt_errstr(status)));
		talloc_free(kdc_socket);
		return status;
	}

	kpasswd_socket->kdc = kdc;
	kpasswd_socket->send_queue = NULL;
	kpasswd_socket->process = kpasswdd_process;

	talloc_steal(kpasswd_socket, kpasswd_socket->sock);

	kpasswd_socket->fde = event_add_fd(kdc->task->event_ctx, kdc, 
					   socket_get_fd(kpasswd_socket->sock), EVENT_FD_READ,
					   kdc_socket_handler, kpasswd_socket);
	
	kpasswd_address = socket_address_from_strings(kpasswd_socket, kpasswd_socket->sock->backend_name, 
						      address, kpasswd_port);
	NT_STATUS_HAVE_NO_MEMORY(kpasswd_address);

	status = socket_listen(kpasswd_socket->sock, kpasswd_address, 0, 0);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%d UDP for kpasswd - %s\n", 
			 address, kpasswd_port, nt_errstr(status)));
		talloc_free(kpasswd_socket);
		return status;
	}

	/* within the kdc task we want to be a single process, so
	   ask for the single process model ops and pass these to the
	   stream_setup_socket() call. */
	model_ops = process_model_byname("single");
	if (!model_ops) {
		DEBUG(0,("Can't find 'single' process model_ops\n"));
		talloc_free(kdc_socket);
		return NT_STATUS_INTERNAL_ERROR;
	}

	status = stream_setup_socket(kdc->task->event_ctx, model_ops, 
				     &kdc_tcp_stream_ops, 
				     "ip", address, &kdc_port, kdc);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%u TCP - %s\n",
			 address, kdc_port, nt_errstr(status)));
		talloc_free(kdc_socket);
		return status;
	}

	status = stream_setup_socket(kdc->task->event_ctx, model_ops, 
				     &kpasswdd_tcp_stream_ops, 
				     "ip", address, &kpasswd_port, kdc);
	if (!NT_STATUS_IS_OK(status)) {
		DEBUG(0,("Failed to bind to %s:%u TCP - %s\n",
			 address, kpasswd_port, nt_errstr(status)));
		talloc_free(kdc_socket);
		return status;
	}

	return NT_STATUS_OK;
}


/*
  setup our listening sockets on the configured network interfaces
*/
static NTSTATUS kdc_startup_interfaces(struct kdc_server *kdc)
{
	int num_interfaces = iface_count();
	TALLOC_CTX *tmp_ctx = talloc_new(kdc);
	NTSTATUS status;
	
	int i;
	
	for (i=0; i<num_interfaces; i++) {
		const char *address = talloc_strdup(tmp_ctx, iface_n_ip(i));
		status = kdc_add_socket(kdc, address);
		NT_STATUS_NOT_OK_RETURN(status);
	}

	talloc_free(tmp_ctx);

	return NT_STATUS_OK;
}

static struct krb5plugin_windc_ftable windc_plugin_table = {
	.minor_version = KRB5_WINDC_PLUGING_MINOR,
	.init = samba_kdc_plugin_init,
	.fini = samba_kdc_plugin_fini,
	.pac_generate = samba_kdc_get_pac,
	.pac_verify = samba_kdc_reget_pac,
	.client_access = samba_kdc_check_client_access,
};


/*
  startup the kdc task
*/
static void kdc_task_init(struct task_server *task)
{
	struct kdc_server *kdc;
	NTSTATUS status;
	krb5_error_code ret;

	switch (lp_server_role()) {
	case ROLE_STANDALONE:
		task_server_terminate(task, "kdc: no KDC required in standalone configuration");
		return;
	case ROLE_DOMAIN_MEMBER:
		task_server_terminate(task, "kdc: no KDC required in member server configuration");
		return;
	case ROLE_DOMAIN_CONTROLLER:
		/* Yes, we want a KDC */
		break;
	}

	if (iface_count() == 0) {
		task_server_terminate(task, "kdc: no network interfaces configured");
		return;
	}

	task_server_set_title(task, "task[kdc]");

	kdc = talloc(task, struct kdc_server);
	if (kdc == NULL) {
		task_server_terminate(task, "kdc: out of memory");
		return;
	}

	kdc->task = task;

	initialize_krb5_error_table();

	ret = smb_krb5_init_context(kdc, task->event_ctx, &kdc->smb_krb5_context);
	if (ret) {
		DEBUG(1,("kdc_task_init: krb5_init_context failed (%s)\n", 
			 error_message(ret)));
		task_server_terminate(task, "kdc: krb5_init_context failed");
		return; 
	}

	krb5_add_et_list(kdc->smb_krb5_context->krb5_context, initialize_hdb_error_table_r);

	/* Registar WinDC hooks */
	ret = _krb5_plugin_register(kdc->smb_krb5_context->krb5_context, 
				    PLUGIN_TYPE_DATA, "windc",
				    &windc_plugin_table);
	if(ret) {
		task_server_terminate(task, "kdc: failed to register hdb keytab");
		return;
	}

	/* Setup the KDC configuration */
	kdc->config = talloc(kdc, krb5_kdc_configuration);
	if (!kdc->config) {
		task_server_terminate(task, "kdc: out of memory");
		return;
	}
	krb5_kdc_default_config(kdc->config);

	kdc->config->logf = kdc->smb_krb5_context->logf;
	kdc->config->db = talloc(kdc->config, struct HDB *);
	if (!kdc->config->db) {
		task_server_terminate(task, "kdc: out of memory");
		return;
	}
	kdc->config->num_db = 1;
		
	status = kdc_hdb_ldb_create(kdc, kdc->smb_krb5_context->krb5_context, 
				    &kdc->config->db[0], NULL);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "kdc: hdb_ldb_create (setup KDC database) failed");
		return; 
	}

	ret = krb5_kt_register(kdc->smb_krb5_context->krb5_context, &hdb_kt_ops);
	if(ret) {
		task_server_terminate(task, "kdc: failed to register hdb keytab");
		return;
	}

	krb5_kdc_configure(kdc->smb_krb5_context->krb5_context, kdc->config);

	kdc_mem_ctx = kdc->smb_krb5_context;

	/* start listening on the configured network interfaces */
	status = kdc_startup_interfaces(kdc);
	if (!NT_STATUS_IS_OK(status)) {
		task_server_terminate(task, "kdc failed to setup interfaces");
		return;
	}

	irpc_add_name(task->msg_ctx, "kdc_server");
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
